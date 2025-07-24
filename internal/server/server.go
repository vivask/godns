package server

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
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
	cfg  *config.Config
	ub   *unbound.Unbound
	mu   sync.Mutex
	dns1 *Upstream
	dns2 *Upstream
	dns3 *Upstream
}

/* ---------- parseUpstream (без изменений) ---------- */
func parseUpstream(upstream string) (*Upstream, error) {
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

/* ---------- New (сигнатура и вызовы не менялись) ---------- */
func New(cfg *config.Config) (*Server, error) {
	ub := unbound.New()

	// DNSSEC + cache + DoT-настройки
	if err := ub.SetOption("auto-trust-anchor-file", "/etc/unbound/root.key"); err != nil {
		log.Errorf("auto-trust-anchor-file: %v", err)
		return nil, err
	}
	if err := ub.SetOption("module-config", "validator iterator"); err != nil {
		log.Errorf("module-config: %v", err)
		return nil, err
	}
	if err := ub.SetOption("harden-dnssec-stripped", "yes"); err != nil {
		log.Errorf("harden-dnssec-stripped: %v", err)
		return nil, err
	}
	if err := ub.SetOption("val-clean-additional", "yes"); err != nil {
		log.Errorf("val-clean-additional: %v", err)
		return nil, err
	}
	if err := ub.SetOption("msg-cache-size", "50m"); err != nil {
		log.Errorf("msg-cache-size: %v", err)
		return nil, err
	}
	if err := ub.SetOption("rrset-cache-size", "100m"); err != nil {
		log.Errorf("rrset-cache-size: %v", err)
		return nil, err
	}
	if err := ub.SetOption("cache-min-ttl", "300"); err != nil {
		log.Errorf("cache-min-ttl: %v", err)
		return nil, err
	}
	if err := ub.SetOption("cache-max-ttl", "3600"); err != nil {
		log.Errorf("cache-max-ttl: %v", err)
		return nil, err
	}

	// Upstream-ы
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

	// Формируем строку для SetFwd
	servers := []string{
		fmt.Sprintf("%s@%d", dns1.Address, dns1.Port),
		fmt.Sprintf("%s@%d", dns2.Address, dns2.Port),
		fmt.Sprintf("%s@%d", dns3.Address, dns3.Port),
	}
	fwdStr := strings.Join(servers, " ")
	if err := ub.SetFwd(fwdStr); err != nil {
		log.Errorf("set fwd: %v", err)
		return nil, err
	}
	if err := ub.SetOption("tls-upstream", "yes"); err != nil {
		log.Errorf("tls-upstream: %v", err)
		return nil, err
	}
	if err := ub.SetOption("tls-cert-bundle", "/etc/ssl/certs/ca-certificates.crt"); err != nil {
		log.Errorf("tls-cert-bundle: %v", err)
		return nil, err
	}
	if err := ub.SetOption("target-fetch-policy", "2 1 0"); err != nil {
		log.Errorf("target-fetch-policy: %v", err)
		return nil, err
	}

	log.Infof("unbound initialized")
	return &Server{
		cfg:  cfg,
		ub:   ub,
		dns1: dns1,
		dns2: dns2,
		dns3: dns3,
	}, nil
}

/* ---------- Run ---------- */
func (s *Server) Run() error {
	pc, err := net.ListenPacket("udp", s.cfg.Listen)
	if err != nil {
		return err
	}
	defer pc.Close()

	// SO_REUSEPORT
	if udpConn, ok := pc.(*net.UDPConn); ok {
		_ = setReusePort(udpConn)
		_ = udpConn.SetReadBuffer(1 << 20)
		_ = udpConn.SetWriteBuffer(1 << 20)
	}

	log.Infof("listening: addr=%s", s.cfg.Listen)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	buf := make([]byte, 4096)
	for {
		select {
		case <-sig:
			log.Infof("received shutdown signal; exiting")
			return nil
		default:
		}

		pc.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue // timeout → просто повтор
			}
			return err
		}
		go s.handleDNSQuery(buf[:n], addr, pc)
	}
}

/* ---------- handleDNSQuery (бывший handleDNSQuery) ---------- */
func (s *Server) handleDNSQuery(data []byte, addr net.Addr, pc net.PacketConn) {
	msg := new(dns.Msg)
	if err := msg.Unpack(data); err != nil {
		log.Errorf("failed to unpack DNS query: %v", err)
		return
	}
	if len(msg.Question) == 0 {
		return
	}

	start := time.Now()
	q := msg.Question[0]

	resp, err := s.resolveWithDNSSEC(msg)
	if err != nil {
		log.Errorf("DNSSEC resolution error for %s: %v", q.Name, err)
		s.sendServfail(pc, addr, msg)
		return
	}

	resp.Id = msg.Id
	respData, err := resp.Pack()
	if err != nil {
		log.Errorf("failed to pack DNS response: %v", err)
		s.sendServfail(pc, addr, msg)
		return
	}
	if _, err := pc.WriteTo(respData, addr); err != nil {
		log.Errorf("failed to send response: %v", err)
	} else {
		s.logDNSResponse(start, q, resp)
	}
}

/* ---------- resolveWithDNSSEC ---------- */
func (s *Server) resolveWithDNSSEC(msg *dns.Msg) (*dns.Msg, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(msg.Question) == 0 {
		return nil, fmt.Errorf("no question in DNS query")
	}
	q := msg.Question[0]

	result, err := s.ub.Resolve(q.Name, uint16(q.Qtype), uint16(q.Qclass))
	if err != nil {
		return nil, err
	}

	resp := new(dns.Msg)
	resp.SetReply(msg)
	resp.Authoritative = false
	resp.RecursionAvailable = true
	resp.RecursionDesired = true
	resp.CheckingDisabled = false

	if result.Secure {
		resp.AuthenticatedData = true
	}
	if result.NxDomain {
		resp.Rcode = dns.RcodeNameError
	} else {
		resp.Rcode = dns.RcodeSuccess
	}

	// result.Rr уже []dns.RR
	for _, rr := range result.Rr {
		switch rr.Header().Rrtype {
		case dns.TypeRRSIG, dns.TypeDNSKEY, dns.TypeDS, dns.TypeNSEC, dns.TypeNSEC3:
			resp.Ns = append(resp.Ns, rr)
		default:
			resp.Answer = append(resp.Answer, rr)
		}
	}

	return resp, nil
}

/* ---------- sendServfail ---------- */
func (s *Server) sendServfail(pc net.PacketConn, addr net.Addr, query *dns.Msg) {
	resp := new(dns.Msg)
	resp.SetRcode(query, dns.RcodeServerFailure)
	if data, err := resp.Pack(); err == nil {
		pc.WriteTo(data, addr)
	}
}

/* ---------- logDNSResponse ---------- */
func (s *Server) logDNSResponse(start time.Time, q dns.Question, resp *dns.Msg) {
	duration := time.Since(start)
	status := "INSECURE"
	if resp.AuthenticatedData {
		status = "SECURE"
	}
	if resp.Rcode != dns.RcodeSuccess {
		status = dns.RcodeToString[resp.Rcode]
	}
	log.Infof("[%s] %s %s %s → %d answers in %v",
		status,
		dns.TypeToString[q.Qtype],
		q.Name,
		dns.ClassToString[q.Qclass],
		len(resp.Answer),
		duration,
	)
}
