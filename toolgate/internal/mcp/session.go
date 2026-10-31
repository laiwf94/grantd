package mcp

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

// errTooManySessions is returned when the session table is full of live
// sessions.
var errTooManySessions = errors.New("too many open sessions")

type session struct {
	id       string
	key      string // principal the session belongs to
	version  string // negotiated legacy protocol version
	lastSeen time.Time
}

// sessionStore holds legacy (2025-11-25 and earlier) sessions. A session is
// bound to the principal that opened it: presenting its ID with another
// credential finds nothing, so a leaked session ID is useless on its own.
type sessionStore struct {
	mu        sync.Mutex
	m         map[string]*session
	idle      time.Duration
	max       int
	maxPerKey int
	now       func() time.Time
}

func newSessionStore(idle time.Duration, max, maxPerKey int, now func() time.Time) *sessionStore {
	return &sessionStore{m: map[string]*session{}, idle: idle, max: max, maxPerKey: maxPerKey, now: now}
}

// create opens a session. When the principal already holds maxPerKey
// sessions its least recently used one is closed, so a client that
// re-initializes in a loop cannot lock itself out or fill the table.
func (s *sessionStore) create(key, version string) (string, error) {
	var b [32]byte
	_, _ = rand.Read(b[:])
	id := hex.EncodeToString(b[:])
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	var oldest *session
	n := 0
	for _, x := range s.m {
		if x.key == key {
			n++
			if oldest == nil || x.lastSeen.Before(oldest.lastSeen) {
				oldest = x
			}
		}
	}
	if n >= s.maxPerKey {
		delete(s.m, oldest.id)
	}
	if len(s.m) >= s.max {
		for sid, x := range s.m {
			if now.Sub(x.lastSeen) >= s.idle {
				delete(s.m, sid)
			}
		}
		if len(s.m) >= s.max {
			return "", errTooManySessions
		}
	}
	s.m[id] = &session{id: id, key: key, version: version, lastSeen: now}
	return id, nil
}

// get returns the session if it exists, belongs to key and has not idled out.
func (s *sessionStore) get(id, key string) (session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	x, ok := s.m[id]
	if !ok || x.key != key {
		return session{}, false
	}
	now := s.now()
	if now.Sub(x.lastSeen) >= s.idle {
		delete(s.m, id)
		return session{}, false
	}
	x.lastSeen = now
	return *x, true
}

// remove closes a session owned by key.
func (s *sessionStore) remove(id, key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	x, ok := s.m[id]
	if !ok || x.key != key {
		return false
	}
	delete(s.m, id)
	return true
}

func (s *sessionStore) len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.m)
}
