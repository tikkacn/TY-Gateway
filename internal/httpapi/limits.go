package httpapi

import (
	"net"
	"net/http"
	"sync"
	"time"
)

// The local aaPanel vhost overwrites X-Real-IP. Never trust it from direct peers.
func loginPeer(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		if forwarded := net.ParseIP(r.Header.Get("X-Real-IP")); forwarded != nil {
			return forwarded.String()
		}
	}
	return host
}

// Bounded global admission control protects the small control plane without
// trusting spoofable forwarded headers. Registration and admin have separate budgets.
type windowLimit struct {
	mu    sync.Mutex
	start time.Time
	used  int
}

type keyedLimit struct {
	mu      sync.Mutex
	entries map[string]*windowLimit
	start   time.Time
}

func (l *keyedLimit) allow(key string, max int) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.entries == nil || time.Since(l.start) >= time.Minute {
		l.entries = make(map[string]*windowLimit)
		l.start = time.Now()
	}
	w := l.entries[key]
	if w == nil {
		if len(l.entries) >= 10000 {
			return false
		}
		w = &windowLimit{}
		l.entries[key] = w
	}
	return w.allow(max)
}

func (l *windowLimit) allow(max int) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if time.Since(l.start) >= time.Minute {
		l.start = time.Now()
		l.used = 0
	}
	if l.used >= max {
		return false
	}
	l.used++
	return true
}
