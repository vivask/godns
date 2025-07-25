package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"godns/internal/config"
	"godns/internal/log"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go/http3"
)

type upstream struct {
	url        string
	client     *http.Client
	certPool   *x509.CertPool
	lastUpdate time.Time
	mu         sync.RWMutex
}

type Server struct {
	cfg     *config.Config
	cache   *Cache
	ups     []*upstream
	conn    *net.UDPConn
	wg      sync.WaitGroup
	closeCh chan struct{}
}

func New(cfg *config.Config) (*Server, error) {
	s := &Server{
		cfg:     cfg,
		cache:   NewCache(cfg.CacheSize),
		closeCh: make(chan struct{}),
	}
	// инициализируем upstream-ы
	for _, u := range []string{cfg.UP1, cfg.UP2, cfg.UP3} {
		ups := &upstream{url: u}
		if err := ups.refreshCert(); err != nil {
			log.Warnf("initial cert refresh for %s: %v", u, err)
		}
		s.ups = append(s.ups, ups)
	}
	return s, nil
}

func (u *upstream) refreshCert() error {
	u.mu.Lock()
	defer u.mu.Unlock()

	if time.Since(u.lastUpdate) < 24*time.Hour {
		return nil
	}

	rootCAs, err := x509.SystemCertPool()
	if err != nil {
		rootCAs = x509.NewCertPool()
	}
	u.certPool = rootCAs

	roundTripper := &http3.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs: u.certPool,
		},
	}
	u.client = &http.Client{
		Transport: roundTripper,
		Timeout:   5 * time.Second,
	}
	u.lastUpdate = time.Now()
	log.Infof("refreshed cert pool for %s", u.url)
	return nil
}

func (s *Server) Run() error {
	udpAddr, err := net.ResolveUDPAddr("udp", s.cfg.Listen)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}
	s.conn = conn
	log.Infof("dns server listening on %s", s.cfg.Listen)

	// горутина обновления сертификатов
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				for _, u := range s.ups {
					if err := u.refreshCert(); err != nil {
						log.Warnf("cert refresh: %v", err)
					}
				}
			case <-s.closeCh:
				return
			}
		}
	}()

	// обработка UDP
	buf := make([]byte, 512)
	for {
		n, clientAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-s.closeCh:
				return nil
			default:
				log.Errorf("read udp: %v", err)
				continue
			}
		}
		go s.handleUDP(buf[:n], clientAddr)
	}
}

func (s *Server) handleUDP(b []byte, addr *net.UDPAddr) {
	q := new(dns.Msg)
	if err := q.Unpack(b); err != nil {
		log.Warnf("unpack request: %v", err)
		return
	}

	key := q.Question[0].String()
	if cached, ok := s.cache.Get(key); ok {
		cached.Id = q.Id
		s.writeUDP(cached, addr)
		return
	}

	for i := 0; i < len(s.ups); i++ {
		ups := s.ups[i]
		var resp *dns.Msg
		var err error
		for attempt := 0; attempt < 3; attempt++ {
			resp, err = s.doHQuery(ups, q)
			if err == nil && resp != nil && resp.Rcode == dns.RcodeSuccess {
				break
			}
			log.Debugf("attempt %d for %s failed: %v", attempt+1, ups.url, err)
			time.Sleep(100 * time.Millisecond)
		}
		if err == nil && resp != nil {
			s.cache.Put(key, resp)
			resp.Id = q.Id
			s.writeUDP(resp, addr)
			return
		}
		// канал упал → запускаем обновление в фоне
		go ups.refreshCert()
	}
	log.Warnf("all upstreams failed for %s", key)
}

func (s *Server) doHQuery(u *upstream, q *dns.Msg) (*dns.Msg, error) {
	u.mu.RLock()
	client := u.client
	u.mu.RUnlock()

	if client == nil {
		return nil, fmt.Errorf("no client")
	}

	// Сериализуем запрос
	pack, err := q.Pack()
	if err != nil {
		return nil, err
	}

	// Кодируем в base64url без padding
	encoded := base64.RawURLEncoding.EncodeToString(pack)
	url := fmt.Sprintf("%s?dns=%s", u.url, encoded)

	req, _ := http.NewRequestWithContext(context.Background(), "GET", url, nil)
	req.Header.Set("Accept", "application/dns-message")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bad status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	answer := new(dns.Msg)
	if err := answer.Unpack(body); err != nil {
		return nil, err
	}
	return answer, nil
}

func (s *Server) writeUDP(m *dns.Msg, addr *net.UDPAddr) {
	b, _ := m.Pack()
	_, _ = s.conn.WriteToUDP(b, addr)
}

func (s *Server) Stop() error {
	close(s.closeCh)
	_ = s.conn.Close()
	s.wg.Wait()
	return nil
}
