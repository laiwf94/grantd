package server

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// maxBuckets bounds the limiter's memory. When full, idle buckets are
// dropped; if that is not enough, the oldest half goes.
const maxBuckets = 100_000

// rateLimiter is a token bucket per client address: rate requests per
// minute, bursting up to rate.
type rateLimiter struct {
	rate  float64 // tokens per second
	burst float64
	now   func() time.Time

	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newRateLimiter(perMinute int, now func() time.Time) *rateLimiter {
	return &rateLimiter{rate: float64(perMinute) / 60, burst: float64(perMinute), now: now, buckets: map[string]*bucket{}}
}

// allow takes one token for key. When none is left it returns how long
// until the next one.
func (l *rateLimiter) allow(key string) (time.Duration, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	b := l.buckets[key]
	if b == nil {
		if len(l.buckets) >= maxBuckets {
			l.evictLocked(now)
		}
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}
	// A clock that steps backwards must not drain the bucket.
	if now.After(b.last) {
		b.tokens = min(l.burst, b.tokens+now.Sub(b.last).Seconds()*l.rate)
		b.last = now
	}
	if b.tokens < 1 {
		return time.Duration((1 - b.tokens) / l.rate * float64(time.Second)), false
	}
	b.tokens--
	return 0, true
}

// sweep drops buckets that have refilled completely; they hold no state.
func (l *rateLimiter) sweep() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.sweepLocked(l.now())
}

func (l *rateLimiter) sweepLocked(now time.Time) {
	for k, b := range l.buckets {
		if b.tokens+now.Sub(b.last).Seconds()*l.rate >= l.burst {
			delete(l.buckets, k)
		}
	}
}

func (l *rateLimiter) evictLocked(now time.Time) {
	l.sweepLocked(now)
	if len(l.buckets) < maxBuckets {
		return
	}
	cutoff := now
	for _, b := range l.buckets {
		if b.last.Before(cutoff) {
			cutoff = b.last
		}
	}
	// Still full of active clients: forget the less recent half rather than
	// grow. A forgotten client just starts again with a full bucket.
	mid := cutoff.Add(now.Sub(cutoff) / 2)
	for k, b := range l.buckets {
		if !b.last.After(mid) {
			delete(l.buckets, k)
		}
	}
}

// clientIP returns the client address. X-Forwarded-For is read right to
// left and believed only while the hop that added an entry is a trusted
// proxy, so a client can't pick its own rate-limit key.
func clientIP(r *http.Request, trusted []netip.Prefix) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return host
	}
	addr = addr.Unmap()
	if !isTrusted(addr, trusted) {
		return addr.String()
	}
	hops := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			break
		}
		addr = a.Unmap()
		if !isTrusted(addr, trusted) {
			break
		}
	}
	return addr.String()
}

func isTrusted(a netip.Addr, trusted []netip.Prefix) bool {
	for _, p := range trusted {
		if p.Contains(a) {
			return true
		}
	}
	return false
}
