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
	"github.com/miekg/unbound"
)

type Upstream struct {
	ServerName      string
	Address         string
	Port            int
	DialableAddress string
}

type Server struct {
	cfg   *config.Config
	ub    *unbound.Unbound
	cache *Cache
	dns1  *Upstream
	dns2  *Upstream
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
	ub := unbound.New()

	if err := ub.SetOption("tls-cert-bundle", "/etc/ssl/certs/ca-certificates.crt"); err != nil {
		log.Errorf("unbound tls-cert-bundle: %v", err)
		return nil, err
	}
	if err := ub.SetOption("edns-buffer-size", "1232"); err != nil {
		log.Errorf("unbound edns-buffer-size: %v", err)
		return nil, err
	}
	if err := ub.SetOption("auto-trust-anchor-file", "/etc/unbound/root.key"); err != nil {
		log.Errorf("auto-trust-anchor-file: %v", err)
		return nil, err
	}
	if err := ub.SetOption("module-config", "validator iterator"); err != nil {
		log.Errorf("module-config: %v", err)
		return nil, err
	}

	log.Infof("unbound initialized")

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

	return &Server{
		cfg:   cfg,
		ub:    ub,
		cache: NewCache(cfg.CacheSize),
		dns1:  dns1,
		dns2:  dns2,
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

	ctx, cancel := context.WithTimeout(context.Background(), s.cfg.Timeout)
	defer cancel()

	key := cacheKey(req)
	if resp, ok := s.cache.Get(key); ok {
		resp.Id = req.Id
		_ = s.send(pc, addr, resp)
		log.Debugf("served from cache: addr=%s q=%s", addr, req.Question[0].Name)
		return
	}

	resp, err := s.resolve(ctx, req)
	if err != nil {
		log.Warnf("resolve error: %v", err)
		resp = new(dns.Msg)
		resp.SetRcode(req, dns.RcodeServerFailure)
	}

	resp.Id = req.Id
	s.cache.Put(key, resp)

	_ = s.send(pc, addr, resp)
	log.Debugf("resolved: addr=%s q=%s rcode=%s", addr, req.Question[0].Name, dns.RcodeToString[resp.Rcode])
}

func (s *Server) resolve(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	// round-robin выбор upstream-а (DoT)
	up := s.dns1.DialableAddress
	serverName := s.dns1.ServerName
	if time.Now().UnixNano()%2 == 0 {
		up = s.dns2.DialableAddress
		serverName = s.dns2.ServerName
	}

	tlsCfg := &tls.Config{
		ServerName: serverName,
		MinVersion: tls.VersionTLS13,
	}

	client := &dns.Client{
		Net:       "tcp-tls",
		TLSConfig: tlsCfg,
		Timeout:   s.cfg.Timeout,
	}

	r, _, err := client.ExchangeContext(ctx, req, up)

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
