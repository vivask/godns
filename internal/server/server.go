package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
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
	dns1  *Upstream
	dns2  *Upstream
	dns3  *Upstream
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
	dns1, err := parseUpstream(cfg.DNS1)
	if err != nil {
		log.Errorf("parse upstream [%s] error: %v", cfg.DNS1, err)
		return nil, err
	}
	dns2, err := parseUpstream(cfg.DNS2)
	if err != nil {
		log.Errorf("parse upstream [%s] error: %v", cfg.DNS2, err)
		return nil, err
	}
	dns3, err := parseUpstream(cfg.DNS3)
	if err != nil {
		log.Errorf("parse upstream [%s] error: %v", cfg.DNS3, err)
		return nil, err
	}

	return &Server{
		cfg:   cfg,
		cache: NewCache(cfg.CacheSize),
		dns1:  dns1,
		dns2:  dns2,
		dns3:  dns3,
	}, nil
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
	// round-robin выбор upstream-а (DoT)
	up := s.dns1
	switch time.Now().UnixNano() % 3 {
	case 1:
		up = s.dns2
	case 2:
		up = s.dns3
	}

	tlsCfg := &tls.Config{
		ServerName: up.ServerName,
		MinVersion: tls.VersionTLS13,
	}

	client := &dns.Client{
		Net:       "tcp-tls",
		TLSConfig: tlsCfg,
		Timeout:   s.cfg.Timeout,
	}

	// копия запроса
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

	r, _, err := client.ExchangeContext(ctx, req, up.DialableAddress)

	return r, err
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
