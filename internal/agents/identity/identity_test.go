package identity

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

var (
	keyA = bytes.Repeat([]byte{1}, 32)
	keyB = bytes.Repeat([]byte{2}, 32)
	t0   = time.Unix(1_000_000, 0)
)

const aliceKey = "tgk_alice_0123456789abcdefghijklmnopqrstuv"

func newAuth(t testing.TB, now *time.Time) *Authenticator {
	t.Helper()
	a, err := New(Config{
		Agents: []Agent{
			{ID: "alice-bot", Owner: "alice", Scopes: []string{"files:read"}, TokenSHA256: HashToken(aliceKey)},
			{ID: "bob-bot", Owner: "bob", TokenSHA256: HashToken("tgk_bob_0123456789abcdefghijklmnopqrstuvwx")},
		},
		Keys:      map[string][]byte{"k1": keyA, "k2": keyB},
		ActiveKey: "k2",
		Issuer:    "toolgate",
		Audience:  "toolgate-gw",
		MaxTTL:    time.Hour,
		Now:       func() time.Time { return *now },
	})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestStatic(t *testing.T) {
	now := t0
	a := newAuth(t, &now)
	id, err := a.Authenticate(aliceKey)
	if err != nil || id.AgentID != "alice-bot" || id.Owner != "alice" || id.Method != "static" || id.Scopes[0] != "files:read" {
		t.Fatalf("got %+v %v", id, err)
	}
	for _, bad := range []string{"", "short", aliceKey + "x", strings.Repeat("a", MaxTokenBytes+1), "tgk_unknown_0123456789abcdefghijklmnopqrstu"} {
		if _, err := a.Authenticate(bad); !errors.Is(err, ErrUnauthenticated) {
			t.Errorf("%.20q: got %v", bad, err)
		}
	}
	if tok := NewStaticToken(); !strings.HasPrefix(tok, "tgk_") || len(tok) < MinStaticBytes || strings.Contains(tok, ".") {
		t.Fatalf("bad generated token %q", tok)
	}
}

func TestSignedRoundTripAndRotation(t *testing.T) {
	now := t0
	a := newAuth(t, &now)
	tok, err := a.Mint("ci-agent", "carol", []string{"deploy", "files:read"}, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	id, err := a.Authenticate(tok)
	if err != nil {
		t.Fatal(err)
	}
	if id.AgentID != "ci-agent" || id.Owner != "carol" || id.KeyID != "k2" || id.Method != "signed" ||
		len(id.Scopes) != 2 || !id.ExpiresAt.Equal(t0.Add(10*time.Minute)) {
		t.Fatalf("got %+v", id)
	}
	// A token signed with the older key still verifies after rotation.
	old := sign(t, keyA, `{"alg":"HS256","typ":"JWT","kid":"k1"}`, claims(t0, 600))
	if id, err := a.Authenticate(old); err != nil || id.KeyID != "k1" {
		t.Fatalf("old key: %+v %v", id, err)
	}
	// Expiry with leeway.
	now = t0.Add(10*time.Minute + DefaultLeeway - time.Second)
	if _, err := a.Authenticate(tok); err != nil {
		t.Fatalf("inside leeway: %v", err)
	}
	now = t0.Add(10*time.Minute + DefaultLeeway)
	if _, err := a.Authenticate(tok); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("expired token accepted: %v", err)
	}
}

func claims(iat time.Time, ttl int64) string {
	c := Claims{Issuer: "toolgate", Audience: "toolgate-gw", Subject: "ci-agent", IssuedAt: iat.Unix(),
		NotBefore: iat.Unix(), ExpiresAt: iat.Unix() + ttl}
	b, _ := json.Marshal(c)
	return string(b)
}

func sign(t testing.TB, key []byte, header, claims string) string {
	t.Helper()
	s := b64.EncodeToString([]byte(header)) + "." + b64.EncodeToString([]byte(claims))
	m := hmac.New(sha256.New, key)
	m.Write([]byte(s))
	return s + "." + b64.EncodeToString(m.Sum(nil))
}

func TestSignedRejects(t *testing.T) {
	now := t0
	a := newAuth(t, &now)
	good := `{"alg":"HS256","typ":"JWT","kid":"k1"}`
	mut := func(f func(*Claims)) string {
		var c Claims
		_ = json.Unmarshal([]byte(claims(t0, 600)), &c)
		f(&c)
		b, _ := json.Marshal(c)
		return string(b)
	}
	valid := sign(t, keyA, good, claims(t0, 600))
	parts := strings.Split(valid, ".")
	cases := map[string]string{
		"alg none":         sign(t, keyA, `{"alg":"none","kid":"k1"}`, claims(t0, 600)),
		"alg HS512":        sign(t, keyA, `{"alg":"HS512","kid":"k1"}`, claims(t0, 600)),
		"typ":              sign(t, keyA, `{"alg":"HS256","typ":"at+jwt","kid":"k1"}`, claims(t0, 600)),
		"unknown kid":      sign(t, keyA, `{"alg":"HS256","kid":"k9"}`, claims(t0, 600)),
		"wrong key":        sign(t, keyB, good, claims(t0, 600)),
		"header extra":     sign(t, keyA, `{"alg":"HS256","kid":"k1","jku":"https://evil"}`, claims(t0, 600)),
		"header garbage":   sign(t, keyA, `nope`, claims(t0, 600)),
		"claims garbage":   sign(t, keyA, good, `[]`),
		"claims extra":     sign(t, keyA, good, strings.TrimSuffix(claims(t0, 600), "}")+`,"admin":true}`),
		"claims trailing":  sign(t, keyA, good, claims(t0, 600)+`{}`),
		"issuer":           sign(t, keyA, good, mut(func(c *Claims) { c.Issuer = "other" })),
		"audience":         sign(t, keyA, good, mut(func(c *Claims) { c.Audience = "other" })),
		"subject":          sign(t, keyA, good, mut(func(c *Claims) { c.Subject = "bad subject" })),
		"no exp":           sign(t, keyA, good, mut(func(c *Claims) { c.ExpiresAt = 0 })),
		"future nbf":       sign(t, keyA, good, mut(func(c *Claims) { c.NotBefore = t0.Unix() + 120 })),
		"future iat":       sign(t, keyA, good, mut(func(c *Claims) { c.IssuedAt = t0.Unix() + 120; c.ExpiresAt = t0.Unix() + 600 })),
		"too long":         sign(t, keyA, good, claims(t0, 7200)),
		"exp before iat":   sign(t, keyA, good, mut(func(c *Claims) { c.ExpiresAt = c.IssuedAt })),
		"bad scope":        sign(t, keyA, good, mut(func(c *Claims) { c.Scope = "ok b@d!" })),
		"long owner":       sign(t, keyA, good, mut(func(c *Claims) { c.Owner = strings.Repeat("o", 129) })),
		"tampered claims":  parts[0] + "." + b64.EncodeToString([]byte(mut(func(c *Claims) { c.Subject = "root" }))) + "." + parts[2],
		"padded signature": valid + "=",
		"bad base64":       parts[0] + ".!!!." + parts[2],
		"empty signature":  parts[0] + "." + parts[1] + ".",
	}
	for name, tok := range cases {
		if _, err := a.Authenticate(tok); !errors.Is(err, ErrUnauthenticated) {
			t.Errorf("%s: accepted (%v)", name, err)
		}
	}
	if _, err := a.Authenticate(valid); err != nil {
		t.Fatalf("control token rejected: %v", err)
	}
}

func TestConfigErrors(t *testing.T) {
	h := HashToken(aliceKey)
	cases := map[string]Config{
		"agent id":   {Agents: []Agent{{ID: "bad id", TokenSHA256: h}}},
		"dup agent":  {Agents: []Agent{{ID: "a", TokenSHA256: h}, {ID: "a", TokenSHA256: HashToken("x")}}},
		"dup token":  {Agents: []Agent{{ID: "a", TokenSHA256: h}, {ID: "b", TokenSHA256: h}}},
		"no hash":    {Agents: []Agent{{ID: "a"}}},
		"scope":      {Agents: []Agent{{ID: "a", TokenSHA256: h, Scopes: []string{"bad scope"}}}},
		"owner":      {Agents: []Agent{{ID: "a", TokenSHA256: h, Owner: strings.Repeat("o", 129)}}},
		"kid":        {Keys: map[string][]byte{"bad kid!": keyA}, ActiveKey: "bad kid!", Issuer: "i", Audience: "a"},
		"short key":  {Keys: map[string][]byte{"k": []byte("short")}, ActiveKey: "k", Issuer: "i", Audience: "a"},
		"active":     {Keys: map[string][]byte{"k": keyA}, ActiveKey: "x", Issuer: "i", Audience: "a"},
		"no issuer":  {Keys: map[string][]byte{"k": keyA}, ActiveKey: "k", Audience: "a"},
		"too scoped": {Agents: []Agent{{ID: "a", TokenSHA256: h, Scopes: make([]string, MaxScopes+1)}}},
	}
	for name, c := range cases {
		if _, err := New(c); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	a, err := New(Config{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Mint("x", "", nil, time.Minute); err == nil {
		t.Fatal("minted without a key")
	}
	if _, err := a.Authenticate(sign(t, keyA, `{"alg":"HS256","kid":"k1"}`, claims(time.Now(), 60))); err == nil {
		t.Fatal("signed token accepted with no keys")
	}
}

func TestMintErrors(t *testing.T) {
	now := t0
	a := newAuth(t, &now)
	for name, f := range map[string]func() (string, error){
		"subject": func() (string, error) { return a.Mint("bad subject", "", nil, time.Minute) },
		"scope":   func() (string, error) { return a.Mint("a", "", []string{"bad scope"}, time.Minute) },
		"ttl":     func() (string, error) { return a.Mint("a", "", nil, 2*time.Hour) },
		"ttl0":    func() (string, error) { return a.Mint("a", "", nil, 0) },
		"owner":   func() (string, error) { return a.Mint("a", strings.Repeat("o", 129), nil, time.Minute) },
	} {
		if _, err := f(); err == nil {
			t.Errorf("%s: minted", name)
		}
	}
}

func BenchmarkAuthenticateStatic(b *testing.B) {
	now := t0
	a := newAuth(b, &now)
	for b.Loop() {
		if _, err := a.Authenticate(aliceKey); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAuthenticateSigned(b *testing.B) {
	now := t0
	a := newAuth(b, &now)
	tok, _ := a.Mint("ci-agent", "carol", []string{"deploy"}, time.Minute)
	for b.Loop() {
		if _, err := a.Authenticate(tok); err != nil {
			b.Fatal(err)
		}
	}
}

func FuzzAuthenticate(f *testing.F) {
	now := t0
	a := newAuth(f, &now)
	tok, _ := a.Mint("ci-agent", "carol", []string{"deploy"}, time.Minute)
	f.Add(tok)
	f.Add(aliceKey)
	f.Add("a.b.c")
	f.Add("eyJhbGciOiJIUzI1NiJ9.e30.")
	f.Fuzz(func(t *testing.T, token string) {
		id, err := a.Authenticate(token)
		if err != nil {
			if !errors.Is(err, ErrUnauthenticated) {
				t.Fatalf("unexpected error type: %v", err)
			}
			return
		}
		if id.AgentID == "" || id.Method == "" {
			t.Fatalf("accepted identity is incomplete: %+v", id)
		}
		if id.Method == "signed" {
			// Anything accepted must carry a valid MAC over its first two parts.
			parts := strings.Split(token, ".")
			m := hmac.New(sha256.New, a.cfg.Keys[id.KeyID])
			m.Write([]byte(parts[0] + "." + parts[1]))
			sig, _ := b64.DecodeString(parts[2])
			if !hmac.Equal(sig, m.Sum(nil)) {
				t.Fatalf("accepted a token without a valid MAC: %q", token)
			}
		}
	})
}
