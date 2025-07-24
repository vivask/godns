package server

import (
	"os"
	"sync"

	"github.com/miekg/dns"
)

// Zone содержит все RR из одного файла
type Zone struct {
	mu     sync.RWMutex
	origin string
	rr     map[string][]dns.RR
}

// NewZone создаёт пустую зону
func NewZone(origin string) *Zone {
	return &Zone{
		origin: dns.Fqdn(origin),
		rr:     make(map[string][]dns.RR),
	}
}

// LoadFromFile читает master-файл
func (z *Zone) LoadFromFile(path string) error {
	z.mu.Lock()
	defer z.mu.Unlock()

	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	// очищаем старые данные
	for k := range z.rr {
		delete(z.rr, k)
	}

	zp := dns.NewZoneParser(f, z.origin, path)
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		if err := zp.Err(); err != nil {
			return err
		}
		name := dns.CanonicalName(rr.Header().Name)
		z.rr[name] = append(z.rr[name], rr)
	}
	return nil
}

// Match возвращает все RR для имени и типа; nil если нет
func (z *Zone) Match(name string, qtype uint16) []dns.RR {
	z.mu.RLock()
	defer z.mu.RUnlock()

	name = dns.CanonicalName(name)
	rrs, ok := z.rr[name]
	if !ok {
		return nil
	}

	var out []dns.RR
	for _, rr := range rrs {
		if qtype == dns.TypeANY || rr.Header().Rrtype == qtype {
			out = append(out, rr)
		}
	}
	return out
}
