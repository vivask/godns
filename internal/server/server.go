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
	"net/netip"
	"sync"
	"time"

	"godns/internal/config"
	"godns/internal/log"
	"godns/internal/server/VRRP"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go/http3"
)

type upstream struct {
	url        string
	client     *http.Client
	certPool   *x509.CertPool
	lastUpdate time.Time
	mu         sync.RWMutex
	lastFail   time.Time
	failCount  int
}

type Server struct {
	cfg     *config.Config
	cache   *Cache
	ups     []*upstream
	conn    *net.UDPConn
	wg      sync.WaitGroup
	closeCh chan struct{}
	zone    *Zone
	upsMu   sync.Mutex
	nextIdx int
	adblock *Adblock
	vr      *VRRP.VirtualRouter
}

func New(cfg *config.Config) (*Server, error) {
	s := &Server{
		cfg:     cfg,
		cache:   NewCache(cfg.CacheSize),
		closeCh: make(chan struct{}),
		zone:    NewZone(""),
		vr:      nil,
	}

	if cfg.Adblock.Enable {
		s.adblock = NewAdblock(cfg)
		s.adblock.Start()
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

	// инициализируем VRRP
	if cfg.Vrrp.Enable {
		log.Infof("Initializing VRRP...")
		// Определяем версию IP
		ipVersion := VRRP.IPv4
		if vip, err := netip.ParseAddr(cfg.Vrrp.Vip); err == nil && vip.Is6() {
			ipVersion = VRRP.IPv6
		} else if err != nil {
			log.Errorf("Invalid VIP address format: %s", cfg.Vrrp.Vip)
			return nil, fmt.Errorf("invalid VIP address: %w", err)
		}

		// Создаем VirtualRouter
		// Предполагаем, что Owner = (cfg.Vrrp.Prior == 255) согласно RFC
		isOwner := cfg.Vrrp.Prior == 255
		s.vr = VRRP.NewVirtualRouter(byte(cfg.Vrrp.Vrid), cfg.Vrrp.Iface, isOwner, byte(ipVersion))

		// Устанавливаем параметры
		s.vr.SetPriorityAndMasterAdvInterval(byte(cfg.Vrrp.Prior), time.Duration(cfg.Vrrp.AdverInt)*time.Second)
		// s.vr.SetPreemptMode(true) // Можно установить, если нужно
		// s.vr.SetAdvInterval(time.Duration(cfg.Vrrp.AdverInt) * time.Second) // Устанавливается через SetPriorityAndMasterAdvInterval

		// Добавляем VIP в список защищаемых адресов
		if vip := net.ParseIP(cfg.Vrrp.Vip); vip != nil {
			s.vr.AddIPvXAddr(vip)
			log.Infof("VIP %s added to VRRP", cfg.Vrrp.Vip)
		} else {
			log.Errorf("Failed to parse VIP address: %s", cfg.Vrrp.Vip)
			return nil, fmt.Errorf("failed to parse VIP address: %s", cfg.Vrrp.Vip)
		}

		// (Опционально) Регистрируем обработчики переходов состояний
		// s.vr.Enroll(vrrp.Master2Backup, func() { /* обработка перехода в BACKUP */ })
		// s.vr.Enroll(vrrp.Backup2Master, func() { /* обработка перехода в MASTER */ })
		// s.vr.Enroll(vrrp.Init2Master, func() { /* обработка перехода в MASTER из INIT */ })
		// s.vr.Enroll(vrrp.Init2Backup, func() { /* обработка перехода в BACKUP из INIT */ })

		log.Infof("VRRP initialized for VRID %d, priority %d on interface %s", cfg.Vrrp.Vrid, cfg.Vrrp.Prior, cfg.Vrrp.Iface)
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
	// Запускаем VRRP
	if s.vr != nil {
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			log.Infof("Starting VRRP...")
			// Выбираем метод запуска: StartWithEventLoop или StartWithEventSelector
			// eventSelector кажется более надежным, так как использует select во всех состояниях
			s.vr.StartWithEventSelector()
			// s.vr.StartWithEventLoop() // Альтернатива
			log.Infof("VRRP goroutine finished")
		}()
		log.Infof("VRRP started in a goroutine")
	}

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
		go s.handleUDP(addr, buf[:n])
	}
}

// выбираем живой upstream (без цикла)
func (s *Server) pickUpstream() *upstream {
	s.upsMu.Lock()
	defer s.upsMu.Unlock()

	now := time.Now()
	for _, u := range s.ups {
		if now.Sub(u.lastFail) < 30*time.Second {
			continue // недавно упал
		}
		return u
	}
	// fallback к первому
	return s.ups[0]
}

func (s *Server) handleUDP(addr net.Addr, b []byte) {
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

	// 3) Проверка на блокировку
	if s.adblock != nil && s.adblock.IsBlocked(name) {
		resp := new(dns.Msg)
		resp.SetReply(q)
		resp.Rcode = dns.RcodeNameError // NXDOMAIN
		s.writeUDP(resp, addr)
		log.Debugf("🚫 Blocked by adblock: %s", name)
		return
	}

	// 4) Пробуем upstream-ы
	for i, ups := range s.ups {
		log.Debugf("🚀 Trying upstream[%d]: %s", i, ups.url)
		for attempt := 0; attempt < 3; attempt++ {
			ups := s.pickUpstream()
			resp, err := s.doHQuery(ups, q)
			if err == nil && resp != nil && resp.Rcode == dns.RcodeSuccess {
				ups.failCount = 0
				s.cache.Put(key, resp)
				resp.Id = q.Id
				s.writeUDP(resp, addr)
				return
			}
			ups.lastFail = time.Now()
			ups.failCount++
			log.Debugf("❌ %s failed (attempt %d): %v", ups.url, attempt+1, err)
		}
	}

	log.Warnf("🛑 All upstreams failed for %s, took %v", key, time.Since(start))
}

func (s *Server) doHQuery(u *upstream, q *dns.Msg) (*dns.Msg, error) {
	reqStart := time.Now()
	log.Debugf("📤 Sending DoH request to %s", u.url)

	q = q.Copy()
	// добавляем EDNS0 OPT с DO=1
	opt := new(dns.OPT)
	opt.Hdr.Name = "."
	opt.Hdr.Rrtype = dns.TypeOPT
	opt.SetUDPSize(dns.DefaultMsgSize)
	opt.SetDo(true)
	q.Extra = append(q.Extra, opt)

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
	// Останавливаем VRRP
	if s.vr != nil {
		log.Infof("Stopping VRRP...")
		s.vr.Stop() // Отправляет SHUTDOWN в eventChannel
		// Ждем завершения VRRP? Текущая реализация VRRP не предоставляет явного WaitGroup.
		// Предполагается, что после отправки SHUTDOWN, VRRP завершится.
		// Возможно, потребуется добавить WaitGroup в VirtualRouter или использовать таймаут.
		// time.Sleep(1 * time.Second) // Простое ожидание, не идеально
		log.Infof("VRRP stop signal sent")
	}

	close(s.closeCh)
	_ = s.conn.Close()
	s.wg.Wait()
	return nil
}
