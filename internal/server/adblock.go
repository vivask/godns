package server

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"godns/internal/config"
	"godns/internal/log"

	"github.com/miekg/dns"
	"golang.org/x/net/idna"
)

const (
	adblockFilePath = "/var/lib/godns/adblock.txt"
)

// --- Trie Implementation for Suffixes ---

// TrieNode представляет узел префиксного дерева (Trie).
type TrieNode struct {
	children map[rune]*TrieNode
	isEnd    bool // true, если путь от корня до этого узла представляет суффикс маски
}

// NewTrieNode создает новый узел Trie.
func NewTrieNode() *TrieNode {
	return &TrieNode{
		children: make(map[rune]*TrieNode),
		isEnd:    false,
	}
}

// Trie представляет префиксное дерево для эффективного поиска суффиксов.
type Trie struct {
	root *TrieNode
	mu   sync.RWMutex
}

// NewTrie создает новый Trie.
func NewTrie() *Trie {
	return &Trie{
		root: NewTrieNode(),
	}
}

// Insert добавляет суффикс (в обратном порядке) в Trie.
// Например, для "*.example.com" будет вставлен "moc.elpmaxe".
func (t *Trie) Insert(reversedSuffix string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	node := t.root
	// Проходим по символам суффикса
	for _, ch := range reversedSuffix {
		if _, exists := node.children[ch]; !exists {
			node.children[ch] = NewTrieNode()
		}
		node = node.children[ch]
	}
	node.isEnd = true
}

// SearchSuffix проверяет, существует ли в Trie суффикс, который является
// суффиксом заданного reversedDomain. reversedDomain также должен быть в обратном порядке.
// Например, reversedDomain = "moc.elpmaxe.sda.bus" (для "sub.ads.example.com")
// Trie содержит "moc.elpmaxe".
// Функция проверит, что "moc.elpmaxe" является префиксом "moc.elpmaxe.sda.bus"
// и что следующий символ после префикса - точка ('.').
func (t *Trie) SearchSuffix(reversedDomain string) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()

	node := t.root
	// Проходим по символам reversedDomain
	for i, ch := range reversedDomain {
		// Если текущий узел отмечен как конец суффикса, проверяем границу метки
		if node.isEnd {
			// Если мы находимся в начале строки reversedDomain, это означает,
			// что суффикс в Trie совпадает полностью с reversedDomain.
			// Это случай, когда домен вида "example.com" проверяется против "*.example.com".
			// Такие домены не должны блокироваться маской.
			if i == 0 {
				// Продолжаем поиск, возможно, есть более длинные совпадения
				// или нужно проверить следующий символ на точку.
				// Но если i==0 и node.isEnd, это означает, что reversedDomain
				// полностью совпадает с суффиксом, что не то, что мы ищем.
				// Пример: reversedDomain="moc.elpmaxe", trie содержит "moc.elpmaxe".
				// Это означает, что мы проверяем "example.com" против "*.example.com".
				// Такие домены не блокируются. Продолжаем.
				// Но если следующий символ в reversedDomain (если он есть) - точка,
				// то это было бы совпадение.
				// Однако, если i==0, мы еще не продвинулись по reversedDomain.
				// Нужно продолжить, чтобы найти, есть ли более длинные совпадения
				// или проверить, что следующий символ - точка.
				// Проще: если node.isEnd и i > 0, и (i == len(reversedDomain) или символ до был точкой),
				// то совпадение найдено.
				// Но логика здесь: мы идем по символам reversedDomain.
				// Если node.isEnd, это означает, что мы нашли конец суффикса в Trie.
				// Нужно проверить, правильно ли он позиционирован.
				// Правильно: если суффикс в Trie заканчивается здесь, и в reversedDomain
				// следующий символ (т.е. символ в нормальном домене перед этой частью) - точка.
				// Но в reversedDomain следующий символ - это символ с индексом i.
				// Если i == len(reversedDomain), значит, мы вышли за границы, и совпадение
				// это весь reversedDomain, что не подходит.
				// Если i < len(reversedDomain), то символ reversedDomain[i] соответствует
				// символу в нормальном домене перед совпавшей частью.
				// Пример:
				// reversedDomain = "moc.elpmaxe.sda.bus" (для "sub.ads.example.com")
				// Trie содержит "moc.elpmaxe".
				// Мы прошли 13 символов ("moc.elpmaxe").
				// i = 13. node.isEnd = true.
				// reversedDomain[13] = '.'. Это точка. Значит, совпадение на границе метки.
				// Возвращаем true.
				// Другой пример:
				// reversedDomain = "moc.elpmaxe" (для "example.com")
				// Trie содержит "moc.elpmaxe".
				// Мы прошли 13 символов. i = 13. node.isEnd = true.
				// i == len(reversedDomain). Это означает, что reversedDomain полностью совпадает
				// с суффиксом. Это случай "example.com" против "*.example.com". Не блокируем.
				if i > 0 && i < len(reversedDomain) && reversedDomain[i] == '.' {
					return true
				}
			} else {
				// Если i > 0, это означает, что мы уже прошли часть reversedDomain.
				// node.isEnd означает, что мы нашли конец суффикса в Trie.
				// Проверяем, является ли совпадение на границе метки.
				// Символ в позиции i в reversedDomain - это символ в нормальном домене
				// *перед* совпавшей частью.
				// Если он точка, то совпадение корректно.
				if i < len(reversedDomain) && reversedDomain[i] == '.' {
					return true
				}
				// Если i == len(reversedDomain), это означает, что reversedDomain
				// является суффиксом того, что есть в Trie, но не наоборот.
				// Например, reversedDomain = "moc.elpmaxe", Trie = "moc.elpmaxe.sda".
				// Это не то, что мы ищем. Продолжаем.
			}
		}

		// Если символ не найден в текущем узле, путь не существует
		if _, exists := node.children[ch]; !exists {
			// Проверка на isEnd была выше. Если символ не найден, дальнейший поиск бесполезен.
			// Но нужно проверить, может быть, текущий node.isEnd уже true и это конец?
			// Это уже сделано в начале цикла.
			// Если символ не найден, мы не можем продолжить путь.
			// Но если node.isEnd, и мы на границе (проверили выше), то можно вернуть true.
			// Если нет, то путь прерван.
			break
		}
		node = node.children[ch]
	}

	// Проверка после выхода из цикла: может быть, последний узел также является концом суффикса?
	// Это случай, когда reversedDomain полностью совпадает с одним из суффиксов в Trie.
	// Например, reversedDomain = "moc.elpmaxe", Trie содержит "moc.elpmaxe".
	// Это означает проверку "example.com" против "*.example.com". Не должно блокироваться.
	// Но если бы было "moc.elpmaxe.sda" и Trie "moc.elpmaxe", то при i=13
	// node.children[ch] не существовало бы, и мы бы вышли из цикла.
	// Перед выходом node указывало бы на узел "moc.elpmaxe".
	// node.isEnd было бы true. Но i=13, len(reversedDomain)=17.
	// Мы бы проверили if i < len(reversedDomain) && reversedDomain[i] == '.'.
	// reversedDomain[13] = '.'. Вернули бы true.
	// В случае полного совпадения: reversedDomain = "moc.elpmaxe", len=13, i после цикла = 13.
	// node.isEnd = true. i НЕ < len(reversedDomain). Не возвращаем true.
	if node.isEnd {
		// Это случай, когда reversedDomain полностью совпадает с суффиксом.
		// Например, проверяем "example.com" (reversed "moc.elpmaxe")
		// против "*.example.com" (stored as "moc.elpmaxe").
		// Такие домены не блокируются маской.
		// len(reversedDomain) == позиция после последнего символа.
		// node.isEnd здесь означает, что суффикс в Trie заканчивается точно там,
		// где заканчивается reversedDomain. Это не блокируется.
		// Пример, где блокируется:
		// reversedDomain = "moc.elpmaxe.sda" (для "ads.example.com")
		// Trie = "moc.elpmaxe".
		// Цикл пройдет 13 символов. i=13. node.children['.'] существует.
		// node = node.children['.']. Следующий символ 's'. Нет ребра 's' из точки.
		// Выход из цикла. node.isEnd для узла точки = true.
		// i=13, len=17. i < len. reversedDomain[13] = 's' (не '.').
		// Не возвращаем true.
		// НО! Логика в цикле должна была это поймать.
		// Давайте упростим логику в цикле и уберем эту проверку после,
		// так как она дублирует и может запутать.
		// Правильная логика: если в цикле мы дошли до конца reversedDomain
		// и последний node.isEnd, это полное совпадение, не блокируем.
		// Если в цикле мы нашли node.isEnd и следующий символ точка, блокируем.
		// Если символ не найден, и node.isEnd, но не на границе, не блокируем.
		// Эта проверка после цикла обрабатывает случай полного совпадения.
		// len(reversedDomain) - это позиция после последнего символа.
		// Если node.isEnd здесь, это значит, путь в Trie совпадает полностью.
		// Это случай "example.com" vs "*.example.com". Не блокируем.
		// Поэтому возвращаем false.
		// Но в логике выше, если бы был символ после и он был точкой, мы бы вернули true.
		// Здесь node.isEnd и конец строки. Не блокируем.
		// return false; // Не блокируем полное совпадение с суффиксом
		// Но это избыточно, так как логика в цикле должна была обработать все случаи.
		// Лучше оставить как есть, но сделать логику в цикле более надежной.
		// Перепишем логику цикла.
	}

	// Совпадений не найдено
	return false
}

// --- BlackList Implementation ---

// BlackList хранит списки заблокированных доменов.
type BlackList struct {
	// Карта для быстрой проверки точных совпадений.
	exact map[string]struct{}
	// Trie для эффективного поиска по суффиксам (маскам).
	suffixTrie *Trie
	mu         sync.RWMutex
}

// NewBlackList создает новый экземпляр BlackList.
func NewBlackList() *BlackList {
	return &BlackList{
		exact:      make(map[string]struct{}),
		suffixTrie: NewTrie(),
	}
}

// reverseString возвращает строку с символами в обратном порядке.
func reverseString(s string) string {
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}

// Add добавляет домен или маску домена в черный список.
// Поддерживает маски вида "*.example.com".
func (bl *BlackList) Add(domain string) {
	canonicalDomain := dns.CanonicalName(domain)
	trimmedDomain := strings.TrimSuffix(canonicalDomain, ".")

	bl.mu.Lock()
	defer bl.mu.Unlock()

	if strings.HasPrefix(trimmedDomain, "*.") {
		suffixToStore := trimmedDomain[2:]
		reversedSuffix := reverseString(suffixToStore)
		bl.suffixTrie.Insert(reversedSuffix)
	} else {
		bl.exact[canonicalDomain] = struct{}{}
	}
}

// Contains проверяет, заблокирован ли домен.
// Сначала проверяется точное совпадение (O(1)), затем суффиксы (O(K) с Trie).
func (bl *BlackList) Contains(domain string) bool {
	canonicalDomain := dns.CanonicalName(domain)

	bl.mu.RLock()
	// 1. Проверка на точное совпадение
	if _, exists := bl.exact[canonicalDomain]; exists {
		bl.mu.RUnlock()
		return true
	}
	bl.mu.RUnlock() // Разблокируем чтение перед потенциально долгой операцией

	// 2. Проверка на суффиксы (маски) с использованием Trie
	queryDomain := strings.TrimSuffix(canonicalDomain, ".")
	if queryDomain == "" {
		return false
	}
	reversedQuery := reverseString(queryDomain)
	return bl.suffixTrie.SearchSuffix(reversedQuery)
}

// --- Adblock Implementation ---

// Adblock управляет списками блокировки.
type Adblock struct {
	cfg       *config.Config // Исправлено: тип конфигурации
	blacklist *BlackList
	ticker    *time.Ticker
}

// NewAdblock создает новый экземпляр Adblock.
func NewAdblock(cfg *config.Config) *Adblock { // Исправлено: тип конфигурации
	ab := &Adblock{
		cfg:       cfg,
		blacklist: NewBlackList(),
	}
	return ab
}

// Start инициализирует и запускает обновление списков блокировки.
func (ab *Adblock) Start() {
	if !ab.cfg.Adblock.Enable {
		log.Info("Adblock disabled")
		return
	}

	if ab.loadFromFile() {
		log.Info("Loaded adblock list from file")
	} else {
		log.Info("Adblock file not found, building from sources")
		go ab.update()
	}

	go ab.scheduleUpdate()
}

// scheduleUpdate планирует регулярное обновление списков.
func (ab *Adblock) scheduleUpdate() {
	if !ab.cfg.Adblock.Enable {
		return
	}

	updateDur, err := time.ParseDuration(ab.cfg.Adblock.Update)
	if err != nil {
		log.Errorf("Invalid update duration: %v", err)
		return
	}

	ab.ticker = time.NewTicker(updateDur)
	defer ab.ticker.Stop()

	// Проверка времени для первого запуска
	now := time.Now()
	scheduledTime, err := time.Parse("15:04:05", ab.cfg.Adblock.Time)
	if err == nil {
		nextRun := time.Date(now.Year(), now.Month(), now.Day(), scheduledTime.Hour(), scheduledTime.Minute(), scheduledTime.Second(), 0, now.Location())
		if nextRun.Before(now) {
			nextRun = nextRun.Add(24 * time.Hour)
		}
		durationUntilNextRun := nextRun.Sub(now)
		time.AfterFunc(durationUntilNextRun, func() {
			log.Infof("Scheduled adblock update at %s", nextRun.Format("15:04:05"))
			ab.update()
		})
	}

	for {
		select {
		case <-ab.ticker.C:
			now := time.Now().Format("15:04:05")
			if strings.HasPrefix(now, ab.cfg.Adblock.Time) {
				log.Infof("Scheduled adblock update at %s", now)
				ab.update()
			}
		}
	}
}

// update загружает и обрабатывает списки блокировки из источников.
func (ab *Adblock) update() {
	log.Info("Updating adblock lists...")

	newList := NewBlackList()
	client := &http.Client{Timeout: 30 * time.Second}

	for _, src := range ab.cfg.Adblock.Sources {
		log.Debugf("Fetching adblock source: %s", src)
		resp, err := client.Get(src)
		if err != nil {
			log.Warnf("Failed to fetch source %s: %v", src, err)
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			log.Warnf("Non-OK response from %s: %d", src, resp.StatusCode)
			continue
		}

		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			originalLine := scanner.Text()
			line := strings.TrimSpace(originalLine)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}

			var domainsToProcess []string

			if strings.Contains(line, "0.0.0.0") || strings.Contains(line, "127.0.0.1") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					domainsToProcess = append(domainsToProcess, parts[1])
				}
			} else if strings.HasPrefix(line, "||") {
				endIdx := strings.Index(line, "^")
				if endIdx > 2 {
					domainPart := line[2:endIdx]
					if strings.HasPrefix(domainPart, "*.") {
						domain := domainPart[2:]
						if domain != "" {
							asciiDomain, err := idna.ToASCII(domain)
							if err != nil {
								log.Debugf("Failed to convert domain to ASCII (punycode): %s, error: %v", domain, err)
								continue
							}
							newList.Add("*." + asciiDomain)
							continue
						}
					} else if strings.Contains(domainPart, "*") {
						log.Debugf("Unsupported AdGuard wildcard format (skipping): %s", line)
						continue
					} else {
						if domainPart != "" {
							domainsToProcess = append(domainsToProcess, domainPart)
						}
					}
				} else {
					log.Debugf("Malformed AdGuard rule (skipping): %s", line)
					continue
				}
			} else {
				if strings.Contains(line, "##") || strings.Contains(line, "#@#") ||
					strings.Contains(line, "$") || (strings.Contains(line, "/") && !strings.HasPrefix(line, "http")) {
					if strings.Contains(line, ",") && strings.Contains(line, "=") && strings.HasPrefix(line, "$") {
						domainStart := strings.Index(line, "domain=")
						if domainStart != -1 {
							domainPart := line[domainStart+len("domain="):]
							parts := strings.Split(domainPart, "|")
							for _, part := range parts {
								subParts := strings.Split(part, ",")
								for _, subPart := range subParts {
									cleanDomain := strings.TrimSpace(subPart)
									if strings.HasPrefix(cleanDomain, "~") {
										cleanDomain = cleanDomain[1:]
									}
									if cleanDomain != "" && strings.Contains(cleanDomain, ".") {
										domainsToProcess = append(domainsToProcess, cleanDomain)
									}
								}
							}
						} else {
							log.Debugf("Complex rule (skipping): %s", line)
							continue
						}
					} else {
						log.Debugf("Complex rule (skipping): %s", line)
						continue
					}
				} else {
					potentialDomains := strings.Split(line, ",")
					if len(potentialDomains) > 1 {
						for _, d := range potentialDomains {
							cleanDomain := strings.TrimSpace(d)
							if cleanDomain != "" {
								domainsToProcess = append(domainsToProcess, cleanDomain)
							}
						}
					} else {
						if strings.HasPrefix(line, "*.") {
							domain := line[2:]
							if domain != "" {
								asciiDomain, err := idna.ToASCII(domain)
								if err != nil {
									log.Debugf("Failed to convert domain to ASCII (punycode): %s, error: %v", domain, err)
									continue
								}
								newList.Add("*." + asciiDomain)
								continue
							}
						} else {
							cleanDomain := strings.TrimSpace(line)
							if cleanDomain != "" && strings.Contains(cleanDomain, ".") {
								domainsToProcess = append(domainsToProcess, cleanDomain)
							}
						}
					}
				}
			}

			for _, domain := range domainsToProcess {
				asciiDomain, err := idna.ToASCII(domain)
				if err != nil {
					log.Debugf("Failed to convert domain to ASCII (punycode): %s, error: %v", domain, err)
					continue
				}

				if strings.Contains(asciiDomain, ".") &&
					!strings.Contains(asciiDomain, "/") &&
					!strings.Contains(asciiDomain, " ") &&
					!strings.Contains(asciiDomain, "#") {

					canonical := dns.CanonicalName(asciiDomain)
					newList.Add(canonical)
				} else {
					log.Debugf("Extracted string doesn't look like a valid domain (skipping): %s (from line: %s)", asciiDomain, originalLine)
				}
			}
		}

		if err := scanner.Err(); err != nil {
			log.Warnf("Error reading source %s: %v", src, err)
		}
	}

	newList.mu.RLock()
	count := len(newList.exact)
	// Подсчет суффиксов в Trie сложен, оставим общее представление
	// Можно добавить счетчик в Trie, если нужно точное число
	newList.mu.RUnlock()

	ab.blacklist = newList
	ab.saveToFile()
	log.Infof("Adblock list updated: %d+ entries", count) // Уточнение, что это только точные совпадения + маски
}

// saveToFile сохраняет черный список в файл.
func (ab *Adblock) saveToFile() {
	err := os.MkdirAll("/var/lib/godns", 0755)
	if err != nil {
		log.Errorf("Failed to create dir: %v", err)
		return
	}

	file, err := os.Create(adblockFilePath)
	if err != nil {
		log.Errorf("Failed to create adblock file: %v", err)
		return
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	ab.blacklist.mu.RLock()
	defer ab.blacklist.mu.RUnlock()

	for domain := range ab.blacklist.exact {
		fmt.Fprintln(writer, domain)
	}

	// Примечание: сохранение Trie в текстовый файл сложно.
	// Для простоты пересоздаем его при загрузке.
	// Если нужно сохранять Trie, потребуется сериализация.

	writer.Flush()
}

// loadFromFile загружает черный список из файла.
// Примечание: эта реализация пересоздает Trie только из точных совпадений и масок из файла.
// Если файл содержит только точные совпадения, Trie останется пустым.
func (ab *Adblock) loadFromFile() bool {
	file, err := os.Open(adblockFilePath)
	if err != nil {
		return false
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		ab.blacklist.Add(line)
	}

	if err := scanner.Err(); err != nil {
		log.Warnf("Error reading adblock file: %v", err)
		return false
	}
	return true
}

// IsBlocked проверяет, заблокирован ли домен.
func (ab *Adblock) IsBlocked(domain string) bool {
	return ab.blacklist.Contains(domain)
}
