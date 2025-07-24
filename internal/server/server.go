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
	cfg       *config.Config
	cache     *Cache
	upstreams []*Upstream

	// пул TLS-коннектов
	conns   map[*Upstream]*tls.Conn
	connMu  sync.RWMutex
	wg      sync.WaitGroup
	closeCh chan struct{}
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
		conns:     make(map[*Upstream]*tls.Conn),
		closeCh:   make(chan struct{}),
	}
	// запускаем health-check в фоне
	s.wg.Add(1)
	go s.healthLoop()
	return s, nil
}

func (s *Server) Run() error {
	pc, err := net.ListenPacket("udp", s.cfg.Listen)
	if err != nil {
		return err
	}
	defer pc.Close()

	// SO_REUSEPORT / буферы (как было)
	if udpConn, ok := pc.(*net.UDPConn); ok {
		_ = setReusePort(udpConn)
		_ = udpConn.SetReadBuffer(1 << 20)
		_ = udpConn.SetWriteBuffer(1 << 20)
	}
	log.Infof("listening: addr=%s", s.cfg.Listen)

	buf := make([]byte, dns.MaxMsgSize)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			log.Errorf("read error: %v", err)
			continue
		}
		go s.handle(pc, addr, buf[:n])
	}
}

// ---------- Shutdown ----------
func (s *Server) Shutdown() {
	close(s.closeCh)
	s.wg.Wait()
	s.connMu.Lock()
	for u, c := range s.conns {
		_ = c.Close()
		delete(s.conns, u)
	}
	s.connMu.Unlock()
}

// ---------- handle ----------
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

	// копия запроса
	// req := msg.Copy()
	// req.RecursionDesired = true
	// opt := req.IsEdns0()
	// if opt == nil {
	// 	opt = new(dns.OPT)
	// 	opt.Hdr.Name = "."
	// 	opt.Hdr.Rrtype = dns.TypeOPT
	// 	opt.SetUDPSize(1232)
	// 	req.Extra = append(req.Extra, opt)
	// }
	// устанавливаем DO (DNSSEC OK)
	// opt.SetDo(true)

	up := s.pickUpstream()
	conn := s.getConn(up)
	if conn == nil {
		return nil, fmt.Errorf("no connection to %s", up.DialableAddress)
	}

	req := msg.Copy()
	req.RecursionDesired = true
	req.SetEdns0(1232, true)

	client := &dns.Client{Net: "tcp"}
	// ExchangeWithConn использует уже готовый *tls.Conn
	r, _, err := client.ExchangeWithConn(req, &dns.Conn{Conn: conn})
	return r, err
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
func (s *Server) getConn(up *Upstream) *tls.Conn {
	s.connMu.RLock()
	conn, ok := s.conns[up]
	s.connMu.RUnlock()
	if ok {
		return conn
	}
	// быстрый реконнект
	conn, err := s.dialUpstream(up)
	if err != nil {
		log.Warnf("dial %s: %v", up.DialableAddress, err)
		return nil
	}
	s.connMu.Lock()
	s.conns[up] = conn
	s.connMu.Unlock()
	return conn
}

// ---------- dialUpstream ----------
func (s *Server) dialUpstream(up *Upstream) (*tls.Conn, error) {
	tlsCfg := &tls.Config{
		ServerName: up.ServerName,
		MinVersion: tls.VersionTLS13,
	}
	return tls.Dial("tcp", up.DialableAddress, tlsCfg)
}

// ---------- healthLoop ----------
func (s *Server) healthLoop() {
	defer s.wg.Done()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.checkConnections()
		case <-s.closeCh:
			return
		}
	}
}

// ---------- checkConnections ----------
func (s *Server) checkConnections() {
	for _, up := range s.upstreams {
		go func(u *Upstream) {
			conn := s.getConn(u)
			if conn == nil {
				return
			}

			m := new(dns.Msg)
			m.SetQuestion("example.com.", dns.TypeA)

			_, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			// ExchangeWithConn через уже готовый *tls.Conn
			client := &dns.Client{Net: "tcp"}
			_, _, err := client.ExchangeWithConn(m, &dns.Conn{Conn: conn})
			if err != nil {
				log.Warnf("health-check %s: %v", u.DialableAddress, err)
				s.connMu.Lock()
				_ = conn.Close()
				delete(s.conns, u)
				s.connMu.Unlock()
			}
		}(up)
	}
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
