// Package ratelimit provides the gateway's three admission controls: token
// buckets (per agent and per agent+tool), a daily call quota per agent, and a
// concurrency limit per upstream.
package ratelimit

import (
	"context"
	"math"
	"sync"
	"time"
)

// Limit is a token bucket: Rate tokens per second, holding at most Burst.
// A zero Rate means unlimited.
type Limit struct {
	Rate  float64
	Burst int
}

// Limiter keeps one token bucket per key. It is safe for concurrent use.
//
// Buckets are implemented as GCRA (the generic cell rate algorithm of ITU-T
// I.371): each key stores only its theoretical arrival time (TAT) in integer
// nanoseconds. With emission interval T = 1/Rate and tolerance
// tau = T*(Burst-1), a take at time t is admitted when max(TAT, t) - t <= tau,
// and then TAT = max(TAT, t) + T. This is exactly a token bucket, with no
// floating-point refill to drift.
//
// Memory is bounded: a key whose TAT has passed is a full bucket, equivalent
// to no entry, so such entries are swept whenever the map has doubled in size
// since the last sweep. Live keys are bounded by agents x tools.
type Limiter struct {
	mu      sync.Mutex
	tat     map[string]int64
	now     func() time.Time
	sweepAt int
}

// NewLimiter returns an empty limiter. now may be nil for time.Now.
func NewLimiter(now func() time.Time) *Limiter {
	if now == nil {
		now = time.Now
	}
	return &Limiter{tat: map[string]int64{}, now: now, sweepAt: 1024}
}

// Take removes one token from key's bucket. When the bucket is empty it
// returns false and how long until a token is available.
func (l *Limiter) Take(key string, lim Limit) (bool, time.Duration) {
	if lim.Rate <= 0 {
		return true, 0
	}
	interval := int64(math.Round(float64(time.Second) / lim.Rate))
	interval = max(interval, 1)
	tau := interval * int64(max(lim.Burst, 1)-1)
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now().UnixNano()
	tat, ok := l.tat[key]
	if !ok && len(l.tat) >= l.sweepAt {
		l.sweepLocked(now)
	}
	tat = max(tat, now)
	if tat-now > tau {
		return false, time.Duration(tat - now - tau)
	}
	l.tat[key] = tat + interval
	return true, 0
}

// sweepLocked drops keys whose bucket has refilled completely.
func (l *Limiter) sweepLocked(now int64) {
	for k, tat := range l.tat {
		if tat <= now {
			delete(l.tat, k)
		}
	}
	l.sweepAt = max(1024, 2*len(l.tat))
}

// Len returns the number of buckets held, for metrics and tests.
func (l *Limiter) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.tat)
}

// Quota counts calls per key per UTC day. It is safe for concurrent use.
type Quota struct {
	mu     sync.Mutex
	day    int64
	counts map[string]int
	now    func() time.Time
}

// NewQuota returns an empty quota counter. now may be nil for time.Now.
func NewQuota(now func() time.Time) *Quota {
	if now == nil {
		now = time.Now
	}
	return &Quota{counts: map[string]int{}, now: now}
}

const day = 24 * time.Hour

// Take counts one call against key's daily limit (0 means unlimited). When
// the limit is reached it returns false and the time until the next UTC day.
func (q *Quota) Take(key string, limit int) (bool, time.Duration) {
	if limit <= 0 {
		return true, 0
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	now := q.now().UTC()
	if d := now.Unix() / int64(day/time.Second); d != q.day {
		q.day, q.counts = d, map[string]int{}
	}
	if q.counts[key] >= limit {
		return false, now.Truncate(day).Add(day).Sub(now)
	}
	q.counts[key]++
	return true, 0
}

// Refund gives back one call taken today, when the call was then refused for
// another reason before reaching the upstream.
func (q *Quota) Refund(key string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.counts[key] > 0 {
		q.counts[key]--
	}
}

// Used returns key's count for the current day.
func (q *Quota) Used(key string) int {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.now().UTC().Unix()/int64(day/time.Second) != q.day {
		return 0
	}
	return q.counts[key]
}

// Semaphore bounds concurrent calls to one upstream.
type Semaphore struct{ ch chan struct{} }

// NewSemaphore allows n concurrent holders (n >= 1).
func NewSemaphore(n int) *Semaphore { return &Semaphore{ch: make(chan struct{}, max(n, 1))} }

// Acquire waits up to maxWait (and no longer than ctx) for a slot.
func (s *Semaphore) Acquire(ctx context.Context, maxWait time.Duration) bool {
	select {
	case s.ch <- struct{}{}:
		return true
	default:
	}
	t := time.NewTimer(maxWait)
	defer t.Stop()
	select {
	case s.ch <- struct{}{}:
		return true
	case <-t.C:
		return false
	case <-ctx.Done():
		return false
	}
}

// Release frees a slot taken by Acquire.
func (s *Semaphore) Release() { <-s.ch }

// InUse returns the number of slots held.
func (s *Semaphore) InUse() int { return len(s.ch) }
