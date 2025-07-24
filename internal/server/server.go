package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"godns/internal/config"
	"godns/internal/log"

	"github.com/miekg/dns"
)

type Upstream struct {
	ServerName      string
	Address         string
	Port            int
	DialableAddress string
}

type Server struct {
	cfg   *config.Config
	cache *Cache

	upstreams []*Upstream

	conns map[*Upstream]*dns.Conn // persistent DoT-коннекты
	mu    sync.RWMutex
}

func parseUpstream(upstream string) (*Upstream, error) {
	// server:port@address
	parts := strings.SplitN(upstream, "@", 2)
	if len(parts) != 2 {
		return nil, errors.New("upstream must be in format server:port@address")
	}

	hostPort := strings.SplitN(parts[0], ":", 2)
	if len(hostPort) != 2 {
		return nil, errors.New("server part must be in format host:port")
	}

	port, err := strconv.Atoi(hostPort[1])
	if err != nil {
		return nil, errors.New("port must be integer")
	}

	return &Upstream{
		ServerName:      hostPort[0],
		Address:         parts[1],
		Port:            port,
		DialableAddress: fmt.Sprintf("%s:%d", parts[1], port),
	}, nil
}

func New(cfg *config.Config) (*Server, error) {

	// Парсинг dns строк
	u1, err := parseUpstream(cfg.DNS1)
	if err != nil {
		return nil, err
	}
	u2, err := parseUpstream(cfg.DNS2)
	if err != nil {
		return nil, err
	}
	u3, err := parseUpstream(cfg.DNS3)
	if err != nil {
		return nil, err
	}

	s := &Server{
		cfg:       cfg,
		cache:     NewCache(cfg.CacheSize),
		upstreams: []*Upstream{u1, u2, u3},
		conns:     make(map[*Upstream]*dns.Conn),
	}
	go s.initConnections() // стартуем в фоне
	return s, nil
}

func (s *Server) initConnections() {
	for _, up := range s.upstreams {
		go func(u *Upstream) {
			for {
				conn, err := s.dialUpstream(u)
				if err != nil {
					log.Errorf("health-check %s: %v", u.DialableAddress, err)
					time.Sleep(5 * time.Second)
					continue
				}
				s.mu.Lock()
				s.conns[u] = conn
				s.mu.Unlock()
				return
			}
		}(up)
	}
}

func (s *Server) dialUpstream(up *Upstream) (*dns.Conn, error) {
	tlsCfg := &tls.Config{ServerName: up.ServerName, MinVersion: tls.VersionTLS13}
	tcpConn, err := tls.Dial("tcp", up.DialableAddress, tlsCfg)
	if err != nil {
		return nil, err
	}
	return &dns.Conn{Conn: tcpConn}, nil
}

func (s *Server) Run() error {
	pc, err := net.ListenPacket("udp", s.cfg.Listen)
	if err != nil {
		return err
	}

	// SO_REUSEPORT при желании
	if udpConn, ok := pc.(*net.UDPConn); ok {
		if err := setReusePort(udpConn); err != nil {
			log.Warnf("SO_REUSEPORT not supported: %v", err)
		}
	}

	// 1 MB read buffer
	if err := pc.(*net.UDPConn).SetReadBuffer(1 << 20); err != nil {
		return err
	}
	if err := pc.(*net.UDPConn).SetWriteBuffer(1 << 20); err != nil {
		return err
	}

	log.Infof("listening: addr=%s", s.cfg.Listen)
	for {
		buf := make([]byte, dns.MaxMsgSize)
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			log.Errorf("read error: %v", err)
			continue
		}
		go s.handle(pc, addr, buf[:n])
	}
}

func (s *Server) handle(pc net.PacketConn, addr net.Addr, buf []byte) {
	req := new(dns.Msg)
	if err := req.Unpack(buf); err != nil {
		log.Debugf("malformed packet: err=%v addr=%s", err, addr)
		return
	}
	if len(req.Question) == 0 {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), s.cfg.Timeout)
	defer cancel()

	key := cacheKey(req)
	if resp, ok := s.cache.Get(key); ok {
		resp.Id = req.Id
		_ = s.send(pc, addr, resp)
		log.Debugf("served from cache: addr=%s q=%s", addr, req.Question[0].Name)
		return
	}

	start := time.Now()
	resp, err := s.resolve(ctx, req)
	if err != nil {
		log.Warnf("resolve error: %v", err)
		resp = new(dns.Msg)
		resp.SetRcode(req, dns.RcodeServerFailure)
	}

	resp.Id = req.Id
	s.cache.Put(key, resp)

	_ = s.send(pc, addr, resp)

	s.logDNSResponse(start, req.Question[0], resp)
}

func (s *Server) resolve(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	up := s.pickUpstream()
	conn := s.getConn(up)
	if conn == nil {
		return nil, fmt.Errorf("no connection to %s", up.DialableAddress)
	}

	req := msg.Copy()
	req.RecursionDesired = true

	// просим апстрим проверить DNSSEC
	opt := req.IsEdns0()
	if opt == nil {
		opt = new(dns.OPT)
		opt.Hdr.Name = "."
		opt.Hdr.Rrtype = dns.TypeOPT
		opt.SetUDPSize(1232)
		req.Extra = append(req.Extra, opt)
	}
	// устанавливаем DO (DNSSEC OK)
	opt.SetDo(true)

	// Оборачиваем ExchangeWithConn в мьютекс
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Создаем клиент только для этого вызова
	client := &dns.Client{
		Net:         "tcp-tls",
		DialTimeout: s.cfg.Timeout,
		ReadTimeout: s.cfg.Timeout,
	}

	resp, _, err := client.ExchangeWithConn(req, conn)
	return resp, err
}

// ---------- pickUpstream ----------
func (s *Server) pickUpstream() *Upstream {
	// round-robin
	n := time.Now().UnixNano()
	switch int(n % 3) {
	case 0:
		return s.upstreams[0]
	case 1:
		return s.upstreams[1]
	default:
		return s.upstreams[2]
	}
}

// ---------- getConn ----------
func (s *Server) getConn(up *Upstream) *dns.Conn {
	s.mu.RLock()
	conn, ok := s.conns[up]
	s.mu.RUnlock()
	if ok {
		return conn
	}
	// быстрый реконнект
	conn, _ = s.dialUpstream(up)
	if conn != nil {
		s.mu.Lock()
		s.conns[up] = conn
		s.mu.Unlock()
	}
	return conn
}

func (s *Server) send(pc net.PacketConn, addr net.Addr, m *dns.Msg) error {
	buf, err := m.Pack()
	if err != nil {
		return err
	}
	_, err = pc.WriteTo(buf, addr)
	return err
}

func cacheKey(m *dns.Msg) string {
	if len(m.Question) == 0 {
		return ""
	}
	q := m.Question[0]
	return fmt.Sprintf("%s|%d|%d", q.Name, q.Qtype, q.Qclass)
}

type timeWriter struct{}

func (w *timeWriter) Write(p []byte) (int, error) {
	return fmt.Printf("%s %s", time.Now().Format(time.RFC3339), p)
}

func (s *Server) logDNSResponse(start time.Time, q dns.Question, resp *dns.Msg) {
	duration := time.Since(start)
	status := "INSECURE"
	if resp.AuthenticatedData {
		status = "SECURE"
	}

	answers := len(resp.Answer)
	if resp.Rcode != dns.RcodeSuccess {
		status = dns.RcodeToString[resp.Rcode]
	}

	log.Debugf(
		"[%s] %s %s %s → %d answers in %v\n",
		status,
		dns.TypeToString[q.Qtype],
		q.Name,
		dns.ClassToString[q.Qclass],
		answers,
		duration,
	)
}
