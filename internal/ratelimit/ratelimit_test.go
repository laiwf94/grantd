package ratelimit

import (
	"context"
	"fmt"
	"math/rand/v2"
	"sync"
	"testing"
	"time"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func TestBucket(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	l := NewLimiter(clk.now)
	lim := Limit{Rate: 2, Burst: 3}
	for i := range 3 {
		if ok, _ := l.Take("a", lim); !ok {
			t.Fatalf("burst take %d refused", i)
		}
	}
	ok, wait := l.Take("a", lim)
	if ok || wait != 500*time.Millisecond {
		t.Fatalf("empty bucket: ok=%v wait=%v", ok, wait)
	}
	if ok, _ := l.Take("b", lim); !ok {
		t.Fatal("keys are not independent")
	}
	clk.add(250 * time.Millisecond)
	if ok, wait := l.Take("a", lim); ok || wait != 250*time.Millisecond {
		t.Fatalf("half refilled: ok=%v wait=%v", ok, wait)
	}
	clk.add(250 * time.Millisecond)
	if ok, _ := l.Take("a", lim); !ok {
		t.Fatal("refilled token refused")
	}
	clk.add(time.Hour)
	for range 3 {
		if ok, _ := l.Take("a", lim); !ok {
			t.Fatal("refill must cap at burst, and allow burst")
		}
	}
	if ok, _ := l.Take("a", lim); ok {
		t.Fatal("refill exceeded burst")
	}
	if ok, _ := l.Take("u", Limit{}); !ok {
		t.Fatal("zero rate must be unlimited")
	}
	if ok, _ := l.Take("z", Limit{Rate: 1}); !ok {
		t.Fatal("burst 0 must behave as 1")
	}
	clk.add(-time.Minute) // a clock step backwards must not mint tokens
	if ok, _ := l.Take("z", Limit{Rate: 1}); ok {
		t.Fatal("backwards clock refilled")
	}
}

// Over any schedule, a bucket admits at most burst + rate*elapsed takes, and
// never refuses when the reference count says a token is available.
func TestBucketRandomSchedules(t *testing.T) {
	seed := uint64(time.Now().UnixNano())
	rng := rand.New(rand.NewPCG(seed, 1))
	for iter := 0; iter < 200; iter++ {
		clk := &fakeClock{t: time.Unix(0, 0)}
		l := NewLimiter(clk.now)
		// Rates whose interval is a whole number of nanoseconds, so the
		// reference below is exact.
		lim := Limit{Rate: float64(pick(rng, []int{1, 2, 4, 5, 8, 10, 16, 20, 25, 40, 50, 100})), Burst: 1 + rng.IntN(10)}
		start := clk.now()
		// Reference: a classic token bucket holding credit in nanoseconds,
		// where one token is worth one emission interval.
		scale := int64(time.Second) / int64(lim.Rate)
		ref := int64(lim.Burst) * scale
		refLast := start
		taken := 0
		for range 300 {
			clk.add(time.Duration(rng.IntN(200)) * time.Millisecond)
			now := clk.now()
			ref = min(int64(lim.Burst)*scale, ref+now.Sub(refLast).Nanoseconds())
			refLast = now
			ok, _ := l.Take("k", lim)
			refOK := ref >= scale
			if refOK {
				ref -= scale
			}
			if ok != refOK {
				t.Fatalf("seed %d: take at %v: limiter %v, reference %v (rate %v burst %d)", seed, now.Sub(start), ok, refOK, lim.Rate, lim.Burst)
			}
			if ok {
				taken++
			}
			if bound := float64(lim.Burst) + lim.Rate*now.Sub(start).Seconds(); float64(taken) > bound+1e-9 {
				t.Fatalf("seed %d: %d takes exceeds bound %.2f", seed, taken, bound)
			}
		}
	}
}

func pick[T any](rng *rand.Rand, xs []T) T { return xs[rng.IntN(len(xs))] }

func TestSweep(t *testing.T) {
	clk := &fakeClock{t: time.Unix(0, 0)}
	l := NewLimiter(clk.now)
	lim := Limit{Rate: 1, Burst: 1}
	for i := range 1023 {
		l.Take(fmt.Sprint("k", i), lim)
	}
	l.Take("hot", Limit{Rate: 0.001, Burst: 5}) // slow refill: must survive the sweep
	clk.add(2 * time.Second)
	l.Take("trigger", lim)
	if n := l.Len(); n != 2 {
		t.Fatalf("after sweep %d buckets remain, want 2 (hot, trigger)", n)
	}
	if ok, _ := l.Take("hot", Limit{Rate: 0.001, Burst: 5}); !ok {
		t.Fatal("hot bucket lost tokens")
	}
}

func TestQuota(t *testing.T) {
	clk := &fakeClock{t: time.Date(2000, 1, 1, 23, 0, 0, 0, time.UTC)}
	q := NewQuota(clk.now)
	for range 3 {
		if ok, _ := q.Take("a", 3); !ok {
			t.Fatal("under quota refused")
		}
	}
	ok, wait := q.Take("a", 3)
	if ok || wait != time.Hour {
		t.Fatalf("over quota: ok=%v wait=%v", ok, wait)
	}
	if q.Used("a") != 3 {
		t.Fatalf("used = %d", q.Used("a"))
	}
	q.Refund("a")
	q.Refund("never")
	if ok, _ := q.Take("a", 3); !ok {
		t.Fatal("refund not applied")
	}
	if ok, _ := q.Take("b", 0); !ok {
		t.Fatal("zero limit must be unlimited")
	}
	clk.add(time.Hour)
	if q.Used("a") != 0 {
		t.Fatal("new day must report zero")
	}
	if ok, _ := q.Take("a", 3); !ok {
		t.Fatal("quota did not reset at UTC midnight")
	}
}

func TestSemaphore(t *testing.T) {
	s := NewSemaphore(1)
	ctx := context.Background()
	if !s.Acquire(ctx, 0) || s.InUse() != 1 {
		t.Fatal("first acquire failed")
	}
	if s.Acquire(ctx, 10*time.Millisecond) {
		t.Fatal("over-acquired")
	}
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if s.Acquire(cctx, time.Second) {
		t.Fatal("acquired on a cancelled context")
	}
	go func() { time.Sleep(10 * time.Millisecond); s.Release() }()
	if !s.Acquire(ctx, 5*time.Second) {
		t.Fatal("waiter not admitted after release")
	}
	s.Release()
	if NewSemaphore(0).Acquire(ctx, 0) != true {
		t.Fatal("n<1 must allow one holder")
	}
}

func TestConcurrentTakes(t *testing.T) {
	l := NewLimiter(nil)
	q := NewQuota(nil)
	var wg sync.WaitGroup
	var mu sync.Mutex
	admitted := 0
	for range 50 {
		wg.Go(func() {
			for range 20 {
				if ok, _ := l.Take("k", Limit{Rate: 0.0001, Burst: 100}); ok {
					if ok, _ := q.Take("k", 1000); ok {
						mu.Lock()
						admitted++
						mu.Unlock()
					}
				}
			}
		})
	}
	wg.Wait()
	if admitted != 100 {
		t.Fatalf("admitted %d, want exactly the burst of 100", admitted)
	}
}

func BenchmarkTake(b *testing.B) {
	l := NewLimiter(nil)
	lim := Limit{Rate: 1e9, Burst: 1e9}
	for b.Loop() {
		l.Take("agent:tool", lim)
	}
}
