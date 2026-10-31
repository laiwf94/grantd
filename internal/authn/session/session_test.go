package session

import (
	"bytes"
	"errors"
	"fmt"
	"hash/crc32"
	mrand "math/rand/v2"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/laiwf94/grantd/internal/authn/policy"
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

func alice() policy.Identity {
	return policy.Identity{Provider: "corp", Subject: "alice", Email: "alice@example.org", Groups: []string{"eng"}}
}

func open(t *testing.T, path string, c *clock) *Store {
	t.Helper()
	s, err := Open(Options{Path: path, IdleTimeout: time.Hour, AbsoluteTimeout: 8 * time.Hour, Now: c.now})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestLifecycle(t *testing.T) {
	c := &clock{t: time.Unix(1_000_000, 0)}
	s := open(t, "", c)
	secret, sess, err := s.Create(alice(), time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if sess.ID != IDFromSecret(secret) || len(sess.ID) != 32 || strings.Contains(sess.ID, secret) {
		t.Fatalf("id %q", sess.ID)
	}
	got, err := s.Lookup(secret)
	if err != nil || got.Identity.Subject != "alice" {
		t.Fatal(err)
	}
	if _, err := s.Lookup("not-a-secret"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	// Idle timeout: activity keeps it alive, an hour of silence ends it.
	for i := 0; i < 5; i++ {
		c.add(50 * time.Minute)
		if _, err := s.Lookup(secret); err != nil {
			t.Fatalf("active session expired after %d checks: %v", i, err)
		}
	}
	c.add(61 * time.Minute)
	if _, err := s.Lookup(secret); !errors.Is(err, ErrNotFound) {
		t.Fatal("idle session still valid")
	}
	if s.Len() != 0 {
		t.Fatal("expired session not dropped")
	}
}

func TestAbsoluteTimeoutAndProviderCap(t *testing.T) {
	c := &clock{t: time.Unix(1_000_000, 0)}
	s := open(t, "", c)
	secret, _, _ := s.Create(alice(), time.Time{})
	for i := 0; i < 16; i++ { // 16 x 30m = 8h, always active
		c.add(30 * time.Minute)
		_, err := s.Lookup(secret)
		if i < 15 && err != nil {
			t.Fatalf("expired early at step %d", i)
		}
		if i == 15 && !errors.Is(err, ErrNotFound) {
			t.Fatal("absolute timeout not enforced")
		}
	}
	// The identity provider can end the session sooner.
	secret, sess, _ := s.Create(alice(), c.now().Add(10*time.Minute))
	if !sess.ExpiresAt.Equal(c.now().Add(10 * time.Minute)) {
		t.Fatalf("expiry %v", sess.ExpiresAt)
	}
	c.add(10 * time.Minute)
	if _, err := s.Lookup(secret); !errors.Is(err, ErrNotFound) {
		t.Fatal("IdP cap ignored")
	}
	if _, _, err := s.Create(alice(), c.now().Add(-time.Second)); !errors.Is(err, ErrExpired) {
		t.Fatalf("already-ended IdP session: %v", err)
	}
	s.SetTimeouts(time.Minute, time.Hour)
	secret, sess, _ = s.Create(alice(), time.Time{})
	if !sess.ExpiresAt.Equal(c.now().Add(time.Hour)) {
		t.Fatal("SetTimeouts absolute")
	}
	c.add(2 * time.Minute)
	if _, err := s.Lookup(secret); err == nil {
		t.Fatal("SetTimeouts idle")
	}
}

func TestRevokeAndList(t *testing.T) {
	c := &clock{t: time.Unix(1_000_000, 0)}
	s := open(t, "", c)
	a1, s1, _ := s.Create(alice(), time.Time{})
	c.add(time.Second)
	a2, _, _ := s.Create(alice(), time.Time{})
	other := policy.Identity{Provider: "partner", Subject: "alice"}
	a3, _, _ := s.Create(other, time.Time{})
	b1, _, _ := s.Create(policy.Identity{Provider: "corp", Subject: "bob"}, time.Time{})

	if l := s.List("alice", 0); len(l) != 3 || l[0].ID != s1.ID {
		t.Fatalf("list %+v", l)
	}
	if l := s.List("", 2); len(l) != 2 {
		t.Fatal("limit")
	}
	if ok, err := s.Revoke(s1.ID); !ok || err != nil {
		t.Fatal("revoke")
	}
	if ok, _ := s.Revoke(s1.ID); ok {
		t.Fatal("double revoke")
	}
	if _, err := s.Lookup(a1); err == nil {
		t.Fatal("revoked session works")
	}
	if n, err := s.RevokeSubject("corp", "alice"); n != 1 || err != nil {
		t.Fatalf("revoke subject at one provider: %d %v", n, err)
	}
	if _, err := s.Lookup(a3); err != nil {
		t.Fatal("other provider's session revoked")
	}
	if n, _ := s.RevokeSubject("", "alice"); n != 1 {
		t.Fatal("revoke subject at all providers")
	}
	if n, _ := s.RevokeSubject("", "nobody"); n != 0 {
		t.Fatal("unknown subject")
	}
	for _, sec := range []string{a2, a3} {
		if _, err := s.Lookup(sec); err == nil {
			t.Fatal("still valid")
		}
	}
	if _, err := s.Lookup(b1); err != nil {
		t.Fatal("bob affected")
	}
}

func TestLimits(t *testing.T) {
	c := &clock{t: time.Unix(1_000_000, 0)}
	s, _ := Open(Options{MaxSessions: 3, MaxPerSubject: 2, Now: c.now})
	first, _, _ := s.Create(alice(), time.Time{})
	c.add(time.Second)
	second, _, _ := s.Create(alice(), time.Time{})
	c.add(time.Second)
	third, _, _ := s.Create(alice(), time.Time{})
	if _, err := s.Lookup(first); err == nil {
		t.Fatal("oldest session of the user should have been evicted")
	}
	for _, sec := range []string{second, third} {
		if _, err := s.Lookup(sec); err != nil {
			t.Fatal(err)
		}
	}
	s.Create(policy.Identity{Provider: "corp", Subject: "bob"}, time.Time{})
	if _, _, err := s.Create(policy.Identity{Provider: "corp", Subject: "carol"}, time.Time{}); !errors.Is(err, ErrFull) {
		t.Fatalf("full store: %v", err)
	}
	// Expired sessions make room.
	c.add(DefaultIdleTimeout + time.Second)
	if _, _, err := s.Create(policy.Identity{Provider: "corp", Subject: "carol"}, time.Time{}); err != nil {
		t.Fatal(err)
	}
}

func TestPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sessions.log")
	c := &clock{t: time.Unix(1_000_000, 0)}
	s := open(t, path, c)
	keep, _, _ := s.Create(alice(), time.Time{})
	gone, goneSess, _ := s.Create(policy.Identity{Provider: "corp", Subject: "bob"}, time.Time{})
	s.Revoke(goneSess.ID)
	c.add(2 * time.Minute)
	s.Lookup(keep) // writes a touch
	s.Close()

	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("log permissions %v", info.Mode().Perm())
	}
	raw, _ := os.ReadFile(path)
	if bytes.Contains(raw, []byte(keep)) || bytes.Contains(raw, []byte(gone)) {
		t.Fatal("the log must not contain cookie secrets")
	}

	c.add(50 * time.Minute) // 52m after creation, 50m after the touch
	s2 := open(t, path, c)
	// Reopening compacts: one create record per live session.
	raw, _ = os.ReadFile(path)
	if n := bytes.Count(raw, []byte("\n")); n != 1 {
		t.Fatalf("compacted log has %d records:\n%s", n, raw)
	}
	if _, err := s2.Lookup(keep); err != nil {
		t.Fatalf("session lost across restart: %v", err)
	}
	if _, err := s2.Lookup(gone); err == nil {
		t.Fatal("revocation lost across restart")
	}
}

func TestTornTailAndCorruption(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "s.log")
	c := &clock{t: time.Unix(1_000_000, 0)}
	s := open(t, path, c)
	var secrets []string
	for i := 0; i < 4; i++ {
		sec, _, _ := s.Create(policy.Identity{Provider: "corp", Subject: fmt.Sprint("u", i)}, time.Time{})
		secrets = append(secrets, sec)
	}
	s.Close()
	full, _ := os.ReadFile(path)
	lines := bytes.SplitAfter(full, []byte("\n"))

	// Cut the log at every byte: recovery must give exactly the sessions
	// whose records are complete, and report where the good data ends.
	for cut := 0; cut <= len(full); cut++ {
		complete, good, off := 0, 0, 0
		for _, l := range lines {
			if off+len(l) <= cut && len(l) > 0 && l[len(l)-1] == '\n' {
				complete++
				good = off + len(l)
			}
			off += len(l)
		}
		got, end, err := replay(bytes.NewReader(full[:cut]))
		if err != nil || len(got) != complete || end != int64(good) {
			t.Fatalf("cut %d: %d sessions ending at %d (%v), want %d ending at %d", cut, len(got), end, err, complete, good)
		}
	}
	// And through Open, which also truncates the torn tail away.
	for _, cut := range []int{0, len(lines[0]) - 1, len(lines[0]), len(lines[0]) + 7, len(full) - 1} {
		p := filepath.Join(dir, fmt.Sprintf("cut-%d.log", cut))
		os.WriteFile(p, full[:cut], 0o600)
		st, err := Open(Options{Path: p, Now: c.now})
		if err != nil {
			t.Fatalf("cut %d: %v", cut, err)
		}
		st.Close()
		if after, _ := os.ReadFile(p); len(after) > 0 && after[len(after)-1] != '\n' {
			t.Fatalf("cut %d: torn tail kept", cut)
		}
	}

	// A bad record in the middle is damage: refuse to start.
	bad := bytes.Clone(full)
	bad[len(lines[0])+12] ^= 0xff
	os.WriteFile(path, bad, 0o600)
	if _, err := Open(Options{Path: path, Now: c.now}); err == nil || !strings.Contains(err.Error(), "damaged") {
		t.Fatalf("mid-log corruption: %v", err)
	}
	// A bad final record is a torn write: dropped.
	bad = bytes.Clone(full)
	bad[len(full)-5] ^= 0xff
	os.WriteFile(path, bad, 0o600)
	if st, err := Open(Options{Path: path, Now: c.now}); err != nil || st.Len() != 3 {
		t.Fatalf("torn final record: %v", err)
	} else {
		st.Close()
	}
	// An over-long line is refused rather than buffered.
	os.WriteFile(path, bytes.Repeat([]byte("a"), maxRecordBytes+10), 0o600)
	if _, err := Open(Options{Path: path, Now: c.now}); err == nil {
		t.Fatal("over-long record accepted")
	}
}

func TestParseLineRejects(t *testing.T) {
	good, _ := encode([]record{{Op: opRevoke, ID: strings.Repeat("a", 32)}})
	if _, err := parseLine(good); err != nil {
		t.Fatal(err)
	}
	frame := func(body string) []byte {
		return []byte(fmt.Sprintf("%08x %s\n", crc32.Checksum([]byte(body), castagnoli), body))
	}
	for name, line := range map[string][]byte{
		"short":       []byte("abc\n"),
		"no space":    []byte("0000000000{}\n"),
		"bad hex":     []byte("zzzzzzzz {}\n"),
		"bad crc":     []byte("00000000 {}\n"),
		"bad json":    frame("{"),
		"unknown op":  frame(`{"op":"drop"}`),
		"create bare": frame(`{"op":"create"}`),
		"touch bare":  frame(`{"op":"touch"}`),
		"extra field": frame(`{"op":"revoke","id":"` + strings.Repeat("a", 32) + `","x":1}`),
	} {
		if _, err := parseLine(line); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// TestWriteFailures injects storage failures: logins fail cleanly, a
// revocation still takes effect in memory and reports that it was not
// saved, and a log that can't be repaired refuses further writes.
func TestWriteFailures(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.log")
	c := &clock{t: time.Unix(1_000_000, 0)}
	s := open(t, path, c)
	sec, sess, _ := s.Create(alice(), time.Time{})
	// Swap in a read-only handle: writes fail, and so does the truncate
	// that would repair them.
	s.log.f.Close()
	ro, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	ro.Seek(0, 2)
	s.log.f = ro

	if _, _, err := s.Create(alice(), time.Time{}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("create on a dead log: %v", err)
	}
	ok, err := s.Revoke(sess.ID)
	if !ok || !errors.Is(err, ErrUnavailable) {
		t.Fatalf("revoke on a dead log: %v %v", ok, err)
	}
	if _, err := s.Lookup(sec); err == nil {
		t.Fatal("revocation must apply even when it can't be saved")
	}
	if s.log.broken == nil {
		t.Fatal("log should be marked broken after a failed truncate")
	}
	if _, err := s.RevokeSubject("", "alice"); err != nil {
		t.Fatal("nothing to revoke should not error")
	}
	if err := s.log.compact(nil); !errors.Is(err, ErrUnavailable) {
		t.Fatal("compact on a broken log")
	}
	if _, err := Open(Options{Path: filepath.Join(t.TempDir(), "missing", "dir", "s.log")}); err == nil {
		t.Fatal("unopenable path accepted")
	}
}

func TestSweepCompacts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.log")
	c := &clock{t: time.Unix(1_000_000, 0)}
	s := open(t, path, c)
	defer func(old int) { compactSlack = old }(compactSlack)
	compactSlack = 10
	for i := 0; i < 12; i++ {
		_, sess, err := s.Create(alice(), time.Time{})
		if err != nil {
			t.Fatal(err)
		}
		s.Revoke(sess.ID)
	}
	if err := s.Sweep(); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	if len(raw) != 0 {
		t.Fatalf("log not compacted: %d bytes", len(raw))
	}
	mem, _ := Open(Options{})
	if err := mem.Sweep(); err != nil || mem.Close() != nil {
		t.Fatal("memory store")
	}
}

// TestPropertyReplay: after any random sequence of operations, reopening
// the log gives exactly the live sessions the running store had.
func TestPropertyReplay(t *testing.T) {
	r := mrand.New(mrand.NewPCG(9, 10))
	for trial := 0; trial < 12; trial++ {
		path := filepath.Join(t.TempDir(), "s.log")
		c := &clock{t: time.Unix(1_000_000, 0)}
		s, err := Open(Options{Path: path, IdleTimeout: time.Hour, AbsoluteTimeout: 4 * time.Hour, MaxPerSubject: 3, Now: c.now})
		if err != nil {
			t.Fatal(err)
		}
		var secrets []string
		for op := 0; op < 50; op++ {
			switch r.IntN(5) {
			case 0, 1:
				sec, _, err := s.Create(policy.Identity{Provider: "corp", Subject: fmt.Sprint("u", r.IntN(4))}, time.Time{})
				if err == nil {
					secrets = append(secrets, sec)
				}
			case 2:
				if len(secrets) > 0 {
					s.Lookup(secrets[r.IntN(len(secrets))])
				}
			case 3:
				if len(secrets) > 0 {
					s.Revoke(IDFromSecret(secrets[r.IntN(len(secrets))]))
				}
			case 4:
				c.add(time.Duration(r.IntN(40)) * time.Minute)
			}
		}
		want := ids(s.List("", 0))
		s.Close()
		s2, err := Open(Options{Path: path, IdleTimeout: time.Hour, AbsoluteTimeout: 4 * time.Hour, Now: c.now})
		if err != nil {
			t.Fatal(err)
		}
		got := ids(s2.List("", 0))
		s2.Close()
		// The restarted store may have expired a session slightly earlier
		// (touches are written at most once a minute), never later.
		for _, id := range got {
			if !contains(want, id) {
				t.Fatalf("trial %d: session %s alive after restart but not before", trial, id)
			}
		}
	}
}

func ids(list []Session) []string {
	out := make([]string, len(list))
	for i, s := range list {
		out[i] = s.ID
	}
	sort.Strings(out)
	return out
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func BenchmarkLookup(b *testing.B) {
	s, _ := Open(Options{})
	sec, _, _ := s.Create(alice(), time.Time{})
	for b.Loop() {
		if _, err := s.Lookup(sec); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCreatePersistent(b *testing.B) {
	s, _ := Open(Options{Path: filepath.Join(b.TempDir(), "s.log"), MaxPerSubject: 1 << 30, MaxSessions: 1 << 30})
	defer s.Close()
	for b.Loop() {
		if _, _, err := s.Create(alice(), time.Time{}); err != nil {
			b.Fatal(err)
		}
	}
}
