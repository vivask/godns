package server

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
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

	// Загружаем готовый конфиг-файл
	if err := ub.Config("/etc/unbound/unbound.conf"); err != nil {
		return nil, fmt.Errorf("unbound config: %w", err)
	}

	log.Infof("unbound initialized from /etc/unbound/unbound.conf")
	return &Server{cfg: cfg, ub: ub}, nil
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
	if len(msg.Question) == 0 {
		return nil, fmt.Errorf("no question")
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
	resp.Answer = append(resp.Answer, result.Rr...)

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
