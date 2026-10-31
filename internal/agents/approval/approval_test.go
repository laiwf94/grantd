package approval

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func newStore() (*Store, *clock) {
	c := &clock{t: time.Unix(1000, 0)}
	return New(Config{PendingTTL: time.Minute, MaxGrantTTL: 10 * time.Minute, MaxOpen: 8, MaxOpenByAgent: 3, Now: c.now}), c
}

func bind(agent, args string) Binding {
	return Binding{AgentID: agent, Owner: "o", Tool: "ops.deploy", ArgsHash: "h-" + args,
		Arguments: json.RawMessage(`{"a":"` + args + `"}`), RuleID: "deploy"}
}

func TestApproveIsSingleUseAndBound(t *testing.T) {
	s, _ := newStore()
	r, out, err := s.Begin(bind("alice", "v1"))
	if err != nil || out != OutcomeOpened || r.Status != Pending || r.ID == "" {
		t.Fatalf("begin: %+v %v %v", r, out, err)
	}
	// Retrying the same call finds the same request.
	if r2, out, _ := s.Begin(bind("alice", "v1")); out != OutcomePending || r2.ID != r.ID {
		t.Fatalf("retry opened a new request: %+v", r2)
	}
	if s.PendingCount() != 1 {
		t.Fatalf("pending = %d", s.PendingCount())
	}
	d, err := s.Decide(r.ID, true, 5*time.Minute, "ok")
	if err != nil || d.Status != Approved || d.Note != "ok" {
		t.Fatalf("decide: %+v %v", d, err)
	}
	if _, err := s.Decide(r.ID, false, 0, ""); !errors.Is(err, ErrNotPending) {
		t.Fatalf("second decision: %v", err)
	}
	// Other arguments and other agents are not covered by the grant.
	if _, out, _ := s.Begin(bind("alice", "v2")); out != OutcomeOpened {
		t.Fatal("grant covered different arguments")
	}
	if _, out, _ := s.Begin(bind("bob", "v1")); out != OutcomeOpened {
		t.Fatal("grant covered another agent")
	}
	if _, out, _ := s.Begin(bind("alice", "v1")); out != OutcomeProceed {
		t.Fatal("approved call did not proceed")
	}
	// Begin does not use the grant up; Consume does, once.
	if _, out, _ := s.Begin(bind("alice", "v1")); out != OutcomeProceed {
		t.Fatal("Begin consumed the grant")
	}
	if !s.Consume(r.ID) || s.Consume(r.ID) {
		t.Fatal("Consume must succeed exactly once")
	}
	if s.Consume("apr_missing") {
		t.Fatal("consumed a missing approval")
	}
	// Used up: the next identical call needs a new approval.
	r3, out, _ := s.Begin(bind("alice", "v1"))
	if out != OutcomeOpened || r3.ID == r.ID {
		t.Fatalf("grant was reusable: %v %+v", out, r3)
	}
}

func TestDenyAndExpiry(t *testing.T) {
	s, c := newStore()
	r, _, _ := s.Begin(bind("alice", "x"))
	if _, err := s.Decide(r.ID, false, 0, "no"); err != nil {
		t.Fatal(err)
	}
	if _, out, _ := s.Begin(bind("alice", "x")); out != OutcomeDenied {
		t.Fatal("denial not remembered")
	}
	c.add(time.Minute)
	if _, out, _ := s.Begin(bind("alice", "x")); out != OutcomeOpened {
		t.Fatal("denial must be forgotten after the pending TTL")
	}
	// A pending request lapses.
	p, _, _ := s.Begin(bind("alice", "lapse"))
	c.add(time.Minute)
	if _, ok := s.Get(p.ID); ok {
		t.Fatal("expired request still visible")
	}
	if _, err := s.Decide(p.ID, true, time.Minute, ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("decided an expired request: %v", err)
	}
	// An unused approval lapses after its TTL, which is capped.
	g, _, _ := s.Begin(bind("alice", "grant"))
	if s.Consume(g.ID) {
		t.Fatal("consumed a pending request")
	}
	d, _ := s.Decide(g.ID, true, 24*time.Hour, "")
	if d.ExpiresAt.Sub(d.DecidedAt) != 10*time.Minute {
		t.Fatalf("grant TTL not capped: %v", d.ExpiresAt.Sub(d.DecidedAt))
	}
	c.add(10*time.Minute - time.Nanosecond)
	if _, out, _ := s.Begin(bind("alice", "grant")); out != OutcomeProceed {
		t.Fatal("grant expired early")
	}
	c.add(time.Nanosecond)
	if s.Consume(g.ID) {
		t.Fatal("consumed an expired grant")
	}
	if _, out, _ := s.Begin(bind("alice", "grant")); out != OutcomeOpened {
		t.Fatal("expired grant was used")
	}
	if s.MaxGrantTTL() != 10*time.Minute {
		t.Fatal("MaxGrantTTL")
	}
}

func TestLimits(t *testing.T) {
	s, _ := newStore()
	for i := range 3 {
		if _, _, err := s.Begin(bind("alice", fmt.Sprint(i))); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := s.Begin(bind("alice", "4")); !errors.Is(err, ErrTooMany) {
		t.Fatalf("per-agent limit: %v", err)
	}
	for i := range 5 {
		if _, _, err := s.Begin(bind(fmt.Sprint("agent", i), "x")); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := s.Begin(bind("zed", "x")); !errors.Is(err, ErrTooMany) {
		t.Fatalf("global limit: %v", err)
	}
	list := s.List()
	if len(list) != 8 {
		t.Fatalf("list has %d", len(list))
	}
	for i := 1; i < len(list); i++ {
		if list[i].CreatedAt.Before(list[i-1].CreatedAt) {
			t.Fatal("list not ordered")
		}
	}
	if d := New(Config{}); d.cfg.MaxOpen != 1024 || d.cfg.PendingTTL != 10*time.Minute {
		t.Fatal("defaults not applied")
	}
}

func TestWait(t *testing.T) {
	s, _ := newStore()
	ctx := context.Background()
	if s.Wait(ctx, "missing", time.Millisecond) != OutcomePending {
		t.Fatal("unknown id")
	}
	r, _, _ := s.Begin(bind("alice", "w"))
	if s.Wait(ctx, r.ID, 5*time.Millisecond) != OutcomePending {
		t.Fatal("timeout must report pending")
	}
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if s.Wait(cctx, r.ID, time.Second) != OutcomePending {
		t.Fatal("cancelled wait must report pending")
	}
	go func() {
		time.Sleep(10 * time.Millisecond)
		_, _ = s.Decide(r.ID, true, time.Minute, "")
	}()
	if s.Wait(ctx, r.ID, 5*time.Second) != OutcomeProceed || !s.Consume(r.ID) {
		t.Fatal("approval not seen by waiter")
	}
	if s.Wait(ctx, r.ID, time.Millisecond) != OutcomePending {
		t.Fatal("a consumed grant is still visible to waiters")
	}
	d, _, _ := s.Begin(bind("alice", "d"))
	go func() {
		time.Sleep(10 * time.Millisecond)
		_, _ = s.Decide(d.ID, false, 0, "")
	}()
	if s.Wait(ctx, d.ID, 5*time.Second) != OutcomeDenied {
		t.Fatal("denial not seen by waiter")
	}
}

// Many identical calls waiting on one approval: exactly one goes through.
func TestConcurrentWaitersSingleUse(t *testing.T) {
	s, _ := newStore()
	r, _, _ := s.Begin(bind("alice", "race"))
	var proceeded atomic.Int32
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			if s.Wait(context.Background(), r.ID, 5*time.Second) == OutcomeProceed && s.Consume(r.ID) {
				proceeded.Add(1)
			}
		})
	}
	time.Sleep(20 * time.Millisecond)
	if _, err := s.Decide(r.ID, true, time.Minute, ""); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	if n := proceeded.Load(); n != 1 {
		t.Fatalf("%d calls used one approval", n)
	}
}
