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

type Adblock struct {
	cfg       *config.Config
	blacklist *BlackList
	ticker    *time.Ticker
	once      sync.Once
}

func NewAdblock(cfg *config.Config) *Adblock {
	ab := &Adblock{
		cfg:       cfg,
		blacklist: NewBlackList(),
	}
	return ab
}

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
				// Простые домены (phishing_army_blocklist.txt)
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

				// Проверяем, что это действительно домен (содержит точку и не содержит недопустимых символов)
				if strings.Contains(asciiDomain, ".") &&
					!strings.Contains(asciiDomain, "*") &&
					!strings.Contains(asciiDomain, "/") {
					canonical := dns.CanonicalName(asciiDomain)
					newList.Add(canonical)
				}
			}
		}

		if err := scanner.Err(); err != nil {
			log.Warnf("Error reading source %s: %v", src, err)
		}
	}

	// Получаем количество записей
	newList.mu.RLock()
	count := len(newList.exact)
	newList.mu.RUnlock()

	ab.blacklist = newList
	ab.saveToFile()
	log.Infof("Adblock list updated: %d entries", count)
}

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
	writer.Flush()
}

func (ab *Adblock) loadFromFile() bool {
	file, err := os.Open(adblockFilePath)
	if err != nil {
		return false
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		domain := dns.CanonicalName(scanner.Text())
		ab.blacklist.Add(domain)
	}

	if err := scanner.Err(); err != nil {
		log.Warnf("Error reading adblock file: %v", err)
		return false
	}

	return true
}

func (ab *Adblock) IsBlocked(domain string) bool {
	return ab.blacklist.Contains(domain)
}
