package server

import (
	"container/list"
	"sync"

	"github.com/miekg/dns"
)

type Cache struct {
	mu   sync.Mutex
	data map[string]*list.Element
	lru  *list.List
	cap  int
}

type entry struct {
	key string
	msg *dns.Msg
}

func NewCache(cap int) *Cache {
	return &Cache{
		data: make(map[string]*list.Element),
		lru:  list.New(),
		cap:  cap,
	}
}

func (c *Cache) Get(key string) (*dns.Msg, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if e, ok := c.data[key]; ok {
		c.lru.MoveToFront(e)
		return e.Value.(*entry).msg, true
	}
	return nil, false
}

func (c *Cache) Put(key string, msg *dns.Msg) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if e, ok := c.data[key]; ok {
		c.lru.MoveToFront(e)
		e.Value.(*entry).msg = msg
		return
	}

	if c.lru.Len() >= c.cap {
		back := c.lru.Back()
		if back != nil {
			c.lru.Remove(back)
			delete(c.data, back.Value.(*entry).key)
		}
	}
	e := c.lru.PushFront(&entry{key, msg})
	c.data[key] = e
}
