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
	zone    *Zone
}

func New(cfg *config.Config) (*Server, error) {
	s := &Server{
		cfg:     cfg,
		cache:   NewCache(cfg.CacheSize),
		closeCh: make(chan struct{}),
		zone:    NewZone(""),
	}

	// загрузить локальную зону
	if err := s.zone.LoadFromFile("/etc/godns/default.local"); err != nil {
		log.Warnf("local zone load: %v", err)
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
	pc, err := net.ListenPacket("udp", s.cfg.Listen)
	if err != nil {
		return err
	}

	// Приведём к *net.UDPConn, чтобы выставить буферы и опции
	udpConn, ok := pc.(*net.UDPConn)
	if !ok {
		return fmt.Errorf("expected *net.UDPConn, got %T", pc)
	}

	// SO_REUSEPORT (по желанию)
	if err := setReusePort(udpConn); err != nil {
		log.Warnf("SO_REUSEPORT not supported: %v", err)
	}

	// Буферы 1 МБ
	if err := udpConn.SetReadBuffer(1 << 20); err != nil {
		return fmt.Errorf("set read buffer: %w", err)
	}
	if err := udpConn.SetWriteBuffer(1 << 20); err != nil {
		return fmt.Errorf("set write buffer: %w", err)
	}

	// Сохраняем соединение
	s.conn = udpConn
	log.Infof("listening: addr=%s", s.cfg.Listen)

	// Горутина обновления сертификатов
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

	// Основной цикл приёма пакетов
	for {
		buf := make([]byte, dns.MaxMsgSize)
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			select {
			case <-s.closeCh:
				return nil
			default:
				log.Errorf("read error: %v", err)
				continue
			}
		}
		go s.handleUDP(pc, addr, buf[:n])
	}
}

func (s *Server) handleUDP(pc net.PacketConn, addr net.Addr, b []byte) {
	start := time.Now()
	log.Debugf("📥 UDP packet received from %s (%d bytes)", addr.String(), len(b))

	q := new(dns.Msg)
	if err := q.Unpack(b); err != nil {
		log.Warnf("❌ Failed to unpack DNS query: %v", err)
		return
	}

	// 1) Локальная зона
	name := dns.CanonicalName(q.Question[0].Name)
	rrs := s.zone.Match(name, q.Question[0].Qtype)

	// Если запрос A и есть CNAME — добавим CNAME + A
	if q.Question[0].Qtype == dns.TypeA {
		if cnameRRs := s.zone.Match(name, dns.TypeCNAME); len(cnameRRs) > 0 {
			rrs = append(rrs, cnameRRs...)
			target := cnameRRs[0].(*dns.CNAME).Target
			if aRRs := s.zone.Match(target, dns.TypeA); len(aRRs) > 0 {
				rrs = append(rrs, aRRs...)
			}
		}
	}

	if len(rrs) > 0 {
		resp := new(dns.Msg)
		resp.SetReply(q)
		resp.Authoritative = true
		resp.Answer = rrs
		s.writeUDP(resp, addr)
		log.Debugf("✅ Local zone answered: %s → %v", name, rrs)
		return
	}

	key := q.Question[0].String()
	log.Debugf("🔍 Query: %s", key)

	// 2) Проверка кэша
	if cached, ok := s.cache.Get(key); ok {
		cached.Id = q.Id
		s.writeUDP(cached, addr)
		log.Debugf("✅ Cache hit, answered in %v", time.Since(start))
		return
	}
	log.Debugf("🔄 Cache miss, forwarding upstream")

	// 3) Пробуем upstream-ы
	for i, ups := range s.ups {
		log.Debugf("🚀 Trying upstream[%d]: %s", i, ups.url)
		for attempt := 0; attempt < 3; attempt++ {
			respStart := time.Now()
			resp, err := s.doHQuery(ups, q)
			log.Debugf("⏱️  doHQuery[%d][attempt %d] took %v", i, attempt+1, time.Since(respStart))
			if err == nil && resp != nil && resp.Rcode == dns.RcodeSuccess {
				s.cache.Put(key, resp)
				resp.Id = q.Id
				s.writeUDP(resp, addr)
				log.Debugf("✅ Upstream[%d] responded successfully in %v", i, time.Since(start))
				return
			}
			log.Debugf("❌ Upstream[%d][attempt %d] failed: %v", i, attempt+1, err)
		}
	}

	log.Warnf("🛑 All upstreams failed for %s, took %v", key, time.Since(start))
}

func (s *Server) doHQuery(u *upstream, q *dns.Msg) (*dns.Msg, error) {
	reqStart := time.Now()
	log.Debugf("📤 Sending DoH request to %s", u.url)

	pack, err := q.Pack()
	if err != nil {
		return nil, fmt.Errorf("pack failed: %w", err)
	}

	encoded := base64.RawURLEncoding.EncodeToString(pack)
	url := fmt.Sprintf("%s?dns=%s", u.url, encoded)

	req, _ := http.NewRequestWithContext(context.Background(), "GET", url, nil)
	req.Header.Set("Accept", "application/dns-message")

	resp, err := u.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body failed: %w", err)
	}

	log.Debugf("📦 DoH response: %d bytes in %v", len(body), time.Since(reqStart))

	answer := new(dns.Msg)
	if err := answer.Unpack(body); err != nil {
		return nil, fmt.Errorf("unpack failed: %w", err)
	}

	return answer, nil
}

func (s *Server) writeUDP(m *dns.Msg, addr net.Addr) error {
	b, err := m.Pack()
	if err != nil {
		return err
	}
	_, err = s.conn.WriteTo(b, addr)
	return err
}

func (s *Server) Stop() error {
	close(s.closeCh)
	_ = s.conn.Close()
	s.wg.Wait()
	return nil
}
