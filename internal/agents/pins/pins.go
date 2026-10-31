// Package pins detects tool definitions that change after they were trusted
// (a "rug pull": a server shows a harmless description, then swaps in one
// that carries injected instructions or a wider schema).
//
// The first definition seen for each tool is pinned by its SHA-256 (trust on
// first use). If the upstream later serves a different definition, the tool
// is quarantined: hidden from agents and refused, until an administrator
// approves the new definition by its exact hash. Pins are persisted so a
// restart does not reset trust.
package pins

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/laiwf94/grantd/internal/agents/jsonrpc"
)

// Errors.
var (
	ErrNotFound    = errors.New("pins: no such tool")
	ErrNoChange    = errors.New("pins: tool is not quarantined")
	ErrHashChanged = errors.New("pins: the quarantined definition has a different hash; review it again")
)

// Pin records the trusted definition of one tool and any pending change.
type Pin struct {
	Tool       string          `json:"tool"`
	Hash       string          `json:"hash"`
	Definition json.RawMessage `json:"definition"`
	FirstSeen  time.Time       `json:"first_seen"`
	ApprovedAt time.Time       `json:"approved_at"`
	ApprovedBy string          `json:"approved_by"` // "first-use" or "admin"

	PendingHash       string          `json:"pending_hash,omitempty"`
	PendingDefinition json.RawMessage `json:"pending_definition,omitempty"`
	ChangedAt         time.Time       `json:"changed_at,omitzero"`
}

// Quarantined reports whether the upstream's current definition differs from
// the trusted one.
func (p Pin) Quarantined() bool { return p.PendingHash != "" }

// Hash returns the hex SHA-256 of a canonical tool definition.
func Hash(canonical []byte) string {
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:])
}

// Store holds pins. It is safe for concurrent use.
type Store struct {
	mu   sync.Mutex
	pins map[string]*Pin
	path string // empty: memory only
	now  func() time.Time
}

// Open loads pins from path, or starts empty if the file does not exist. An
// empty path keeps pins in memory only.
func Open(path string, now func() time.Time) (*Store, error) {
	if now == nil {
		now = time.Now
	}
	s := &Store{pins: map[string]*Pin{}, path: path, now: now}
	if path == "" {
		return s, nil
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("pins: %w", err)
	}
	var list []*Pin
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&list); err != nil {
		return nil, fmt.Errorf("pins: %s is damaged: %w", path, err)
	}
	for _, p := range list {
		if p.Tool == "" || p.Hash != Hash(p.Definition) || p.PendingHash != "" && p.PendingHash != Hash(p.PendingDefinition) {
			return nil, fmt.Errorf("pins: %s has an entry whose hash does not match its definition", path)
		}
		s.pins[p.Tool] = p
	}
	return s, nil
}

// Observe records the definition an upstream currently serves for tool and
// reports whether the tool may be used. New tools are trusted on first use.
// A failure to persist a new pin is returned, and the tool must then not be
// used.
func (s *Store) Observe(tool string, canonical []byte) (trusted bool, newlyQuarantined bool, err error) {
	h := Hash(canonical)
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.pins[tool]
	now := s.now().UTC()
	switch {
	case !ok:
		p = &Pin{Tool: tool, Hash: h, Definition: bytes.Clone(canonical), FirstSeen: now, ApprovedAt: now, ApprovedBy: "first-use"}
		s.pins[tool] = p
		if err := s.saveLocked(); err != nil {
			delete(s.pins, tool)
			return false, false, err
		}
		return true, false, nil
	case p.Hash == h:
		if p.PendingHash != "" {
			// The upstream went back to the trusted definition.
			old := *p
			p.PendingHash, p.PendingDefinition, p.ChangedAt = "", nil, time.Time{}
			if err := s.saveLocked(); err != nil {
				*p = old
				return false, false, err
			}
		}
		return true, false, nil
	case p.PendingHash == h:
		return false, false, nil
	default:
		p.PendingHash, p.PendingDefinition, p.ChangedAt = h, bytes.Clone(canonical), now
		// Quarantine holds in memory even if persisting fails; the next
		// observation retries the write.
		return false, true, s.saveLocked()
	}
}

// Approve trusts the quarantined definition of tool. hash must be the hash
// the administrator reviewed, so a definition that changed again in the
// meantime is not approved by accident.
func (s *Store) Approve(tool, hash string) (Pin, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.pins[tool]
	if !ok {
		return Pin{}, ErrNotFound
	}
	if p.PendingHash == "" {
		return *p, ErrNoChange
	}
	if p.PendingHash != hash {
		return *p, ErrHashChanged
	}
	old := *p
	p.Hash, p.Definition = p.PendingHash, p.PendingDefinition
	p.PendingHash, p.PendingDefinition, p.ChangedAt = "", nil, time.Time{}
	p.ApprovedAt, p.ApprovedBy = s.now().UTC(), "admin"
	if err := s.saveLocked(); err != nil {
		*p = old
		return old, err
	}
	return *p, nil
}

// Trusted reports whether hash is the trusted definition of tool and no
// different definition is waiting for review.
func (s *Store) Trusted(tool, hash string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.pins[tool]
	return ok && p.Hash == hash && p.PendingHash == ""
}

// Get returns one pin.
func (s *Store) Get(tool string) (Pin, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.pins[tool]
	if !ok {
		return Pin{}, false
	}
	return *p, true
}

// List returns every pin, sorted by tool.
func (s *Store) List() []Pin {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Pin, 0, len(s.pins))
	for _, p := range s.pins {
		out = append(out, *p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Tool < out[j].Tool })
	return out
}

// QuarantinedCount returns the number of quarantined tools.
func (s *Store) QuarantinedCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, p := range s.pins {
		if p.Quarantined() {
			n++
		}
	}
	return n
}

// saveLocked writes all pins atomically: a temporary file in the same
// directory, fsynced, renamed over the old one, and the directory fsynced.
func (s *Store) saveLocked() error {
	if s.path == "" {
		return nil
	}
	list := make([]*Pin, 0, len(s.pins))
	for _, p := range s.pins {
		list = append(list, p)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Tool < list[j].Tool })
	// Compact and without HTML escaping, so each definition is stored as the
	// exact bytes its hash covers.
	data, err := jsonrpc.Marshal(list)
	if err != nil {
		return fmt.Errorf("pins: %w", err)
	}
	dir := filepath.Dir(s.path)
	tmp, err := os.CreateTemp(dir, ".pins-*.tmp")
	if err != nil {
		return fmt.Errorf("pins: %w", err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("pins: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("pins: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("pins: %w", err)
	}
	if err := os.Rename(tmp.Name(), s.path); err != nil {
		return fmt.Errorf("pins: %w", err)
	}
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("pins: %w", err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("pins: %w", err)
	}
	return nil
}
