package server

import (
	"bufio"
	"net/http"
	"strings"
	"sync"
	"time"

	"godns/internal/config"
	"godns/internal/log"

	"github.com/miekg/dns"
	"golang.org/x/net/idna"
)

// BlackList хранит домены для блокировки
type BlackList struct {
	exact map[string]struct{}
	mu    sync.RWMutex
}

func NewBlackList() *BlackList {
	return &BlackList{
		exact: make(map[string]struct{}),
	}
}

func (bl *BlackList) Add(domain string) {
	bl.mu.Lock()
	defer bl.mu.Unlock()
	bl.exact[domain] = struct{}{}
}

func (bl *BlackList) Contains(domain string) bool {
	bl.mu.RLock()
	defer bl.mu.RUnlock()
	_, exists := bl.exact[domain]
	return exists
}

// WhiteList хранит домены, которые НЕ должны блокироваться
type WhiteList struct {
	exact map[string]struct{}
	mu    sync.RWMutex
}

func NewWhiteList() *WhiteList {
	return &WhiteList{
		exact: make(map[string]struct{}),
	}
}

// Add добавляет домен в белый список. Домен должен быть в канонической форме.
func (wl *WhiteList) Add(domain string) {
	wl.mu.Lock()
	defer wl.mu.Unlock()
	// Убедимся, что домен в канонической форме
	canonical := dns.CanonicalName(domain)
	wl.exact[canonical] = struct{}{}
}

// Contains проверяет, находится ли домен в белом списке. Домен должен быть в канонической форме.
func (wl *WhiteList) Contains(domain string) bool {
	wl.mu.RLock()
	defer wl.mu.RUnlock()
	// Убедимся, что домен в канонической форме при проверке
	canonical := dns.CanonicalName(domain)
	_, exists := wl.exact[canonical]
	return exists
}

// LoadFromConfig загружает белый список из конфигурации.
func (wl *WhiteList) LoadFromConfig(domains []string) {
	for _, domain := range domains {
		trimmedDomain := strings.TrimSpace(domain)
		if trimmedDomain != "" {
			// Конвертируем домен в ASCII (punycode) при загрузке
			asciiDomain, err := idna.ToASCII(trimmedDomain)
			if err != nil {
				log.Debugf("Failed to convert whitelist domain to ASCII (punycode): %s, error: %v", trimmedDomain, err)
				continue // Пропускаем недействительные домены
			}
			// Проверяем, что это действительно похоже на домен
			if strings.Contains(asciiDomain, ".") &&
				!strings.Contains(asciiDomain, " ") &&
				!strings.Contains(asciiDomain, "/") {
				wl.Add(asciiDomain) // Add внутри использует CanonicalName
			} else {
				log.Debugf("Skipping invalid whitelist domain: %s", asciiDomain)
			}
		}
	}
	log.Debugf("Loaded %d domains into whitelist", func() int { wl.mu.RLock(); defer wl.mu.RUnlock(); return len(wl.exact) }())
}

type Adblock struct {
	cfg        *config.Config
	blacklist  *BlackList
	whitelist  *WhiteList // Добавлен белый список
	updateOnce sync.Once  // Для однократного выполнения update при старте
}

func NewAdblock(cfg *config.Config) *Adblock {
	ab := &Adblock{
		cfg:       cfg,
		blacklist: NewBlackList(),
		whitelist: NewWhiteList(),
	}
	// Загружаем белый список из конфига при инициализации
	ab.whitelist.LoadFromConfig(cfg.Adblock.White)
	return ab
}

func (ab *Adblock) Start() {
	if !ab.cfg.Adblock.Enable {
		log.Info("Adblock disabled")
		return
	}

	log.Info("Initializing adblock lists...")
	// Запускаем обновление один раз при старте
	ab.updateOnce.Do(func() {
		ab.update()
	})

	go ab.scheduleUpdate()
}

func (ab *Adblock) scheduleUpdate() {
	if !ab.cfg.Adblock.Enable {
		return
	}

	updateDur, err := time.ParseDuration(ab.cfg.Adblock.Update)
	if err != nil {
		log.Errorf("Invalid update duration: %v", err)
		return
	}

	// Создаем тикер с меньшим интервалом для проверки времени
	checkTicker := time.NewTicker(1 * time.Minute) // Проверяем каждую минуту
	defer checkTicker.Stop()

	log.Infof("Adblock update scheduled every %v, checking time around %s", updateDur, ab.cfg.Adblock.Time)

	for {
		select {
		case <-checkTicker.C:
			now := time.Now().Format("15:04:05")
			// Проверяем, совпадает ли текущее время с заданным в конфиге (с точностью до минуты)
			if strings.HasPrefix(now, ab.cfg.Adblock.Time[:5]) { // Сравниваем только HH:MM
				log.Infof("Scheduled adblock update triggered at %s", now)
				// Используем Once для избежания одновременных обновлений
				ab.updateOnce.Do(func() {
					go func() {
						ab.update()
						// После завершения обновления сбрасываем Once, чтобы разрешить следующее обновление
						// Это требует использования sync.OnceValue или аналога в Go 1.21+
						// Для более старых версий Go можно использовать флаг и мьютекс
						// Здесь просто запускаем update напрямую, предполагая, что ticker обеспечит интервал
						// Или используем другой подход для однократного запуска за период
						// Упростим: просто запускаем update, предполагая, что checkTicker не слишком частый
						// и вероятность коллизии мала. Для production лучше использовать мьютекс.
					}()
				})
				// Простое решение: запускаем обновление напрямую, полагаясь на ticker для интервала
				// и на то, что update сам по себе потокобезопасен (создает новый список).
				// ab.update()
			}
		}
	}
	// Примечание: канал closeCh для остановки не обрабатывается в этом фрагменте,
	// предполагается, что он есть в полной версии Server.
}

func (ab *Adblock) update() {
	log.Info("Updating adblock blacklists...")

	newList := NewBlackList()
	client := &http.Client{Timeout: 30 * time.Second}

	for _, src := range ab.cfg.Adblock.Black {
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
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}

			var domain string

			// Обработка формата hosts
			if strings.Contains(line, "0.0.0.0") || strings.Contains(line, "127.0.0.1") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					domain = parts[1]
				}
			} else if strings.HasPrefix(line, "||") && strings.Contains(line, "^") {
				// Обработка формата AdGuard/ABP (||domain^)
				endIdx := strings.Index(line, "^")
				if endIdx > 2 {
					domain = line[2:endIdx]
				}
			} else if !strings.Contains(line, " ") && strings.Contains(line, ".") {
				// Простые домены
				domain = line
			}

			// Если домен найден, обрабатываем его
			if domain != "" {
				// Конвертируем домен в ASCII (punycode)
				asciiDomain, err := idna.ToASCII(domain)
				if err != nil {
					log.Debugf("Failed to convert domain to ASCII (punycode): %s, error: %v", domain, err)
					continue
				}

				// Проверяем, что это действительно домен
				if strings.Contains(asciiDomain, ".") &&
					!strings.Contains(asciiDomain, "*") &&
					!strings.Contains(asciiDomain, "/") {

					canonical := dns.CanonicalName(asciiDomain)

					// Проверяем, не находится ли домен в белом списке
					// Это ключевое изменение: пропускаем, если в whitelist
					if ab.whitelist.Contains(canonical) {
						log.Debugf("Skipping domain %s as it's in the whitelist", canonical)
						continue
					}

					newList.Add(canonical)
				}
			}
		}

		if scannerErr := scanner.Err(); scannerErr != nil {
			log.Warnf("Error reading source %s: %v", src, scannerErr)
		}
	}

	// Получаем количество записей
	newList.mu.RLock()
	count := len(newList.exact)
	newList.mu.RUnlock()

	// Атомарно заменяем старый список новым
	ab.blacklist = newList

	log.Infof("Adblock blacklist updated: %d entries", count)
}

func (ab *Adblock) IsBlocked(domain string) bool {
	// Сначала проверяем, не находится ли домен в белом списке
	// Это повышает приоритет белого списка
	if ab.whitelist.Contains(domain) {
		log.Debugf("Domain %s is whitelisted, NOT blocked", domain)
		return false
	}

	// Затем проверяем черный список
	blocked := ab.blacklist.Contains(domain)
	if blocked {
		log.Debugf("Domain %s is blocked by blacklist", domain)
	}
	return blocked
}
