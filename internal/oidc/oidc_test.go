package oidc

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

var (
	opKey, _    = rsa.GenerateKey(rand.Reader, 2048)
	otherKey, _ = rsa.GenerateKey(rand.Reader, 2048)
)

const testKid = "k1"

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

// testOP is an OpenID provider whose every answer a test can change.
type testOP struct {
	srv *httptest.Server
	clk *clock

	mu           sync.Mutex
	meta         map[string]any
	jwks         []map[string]string
	jwksStatus   int
	jwksFetches  int
	tokenHandler func(form url.Values, r *http.Request) (int, any)
	userinfo     map[string]any
	lastForm     url.Values
	lastAuth     string
}

func enc(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func rsaJWK(k *rsa.PublicKey, kid string) map[string]string {
	return map[string]string{"kty": "RSA", "kid": kid, "use": "sig", "n": enc(k.N.Bytes()), "e": enc(big.NewInt(int64(k.E)).Bytes())}
}

func newOP(t testing.TB) *testOP {
	op := &testOP{clk: &clock{t: time.Unix(1_700_000_000, 0)}, jwksStatus: 200}
	op.srv = httptest.NewTLSServer(http.HandlerFunc(op.serve))
	t.Cleanup(op.srv.Close)
	iss := op.srv.URL
	op.meta = map[string]any{"issuer": iss, "authorization_endpoint": iss + "/authorize", "token_endpoint": iss + "/token",
		"jwks_uri": iss + "/jwks", "userinfo_endpoint": iss + "/userinfo", "end_session_endpoint": iss + "/logout",
		"response_types_supported": []string{"code"}, "code_challenge_methods_supported": []string{"S256"}}
	op.jwks = []map[string]string{rsaJWK(&opKey.PublicKey, testKid)}
	return op
}

func (op *testOP) serve(w http.ResponseWriter, r *http.Request) {
	op.mu.Lock()
	defer op.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		json.NewEncoder(w).Encode(op.meta)
	case "/jwks":
		op.jwksFetches++
		w.Header().Set("Cache-Control", "max-age=3600")
		w.WriteHeader(op.jwksStatus)
		json.NewEncoder(w).Encode(map[string]any{"keys": op.jwks})
	case "/token":
		r.ParseForm()
		op.lastForm, op.lastAuth = r.PostForm, r.Header.Get("Authorization")
		status, body := op.tokenHandler(r.PostForm, r)
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(body)
	case "/userinfo":
		if r.Header.Get("Authorization") != "Bearer at-123" {
			w.WriteHeader(401)
			return
		}
		json.NewEncoder(w).Encode(op.userinfo)
	case "/redirect":
		http.Redirect(w, r, "https://example.com/", http.StatusFound)
	default:
		w.WriteHeader(404)
	}
}

func (op *testOP) set(f func(op *testOP)) {
	op.mu.Lock()
	defer op.mu.Unlock()
	f(op)
}

func (op *testOP) provider(t testing.TB, mutate func(*Config)) *Provider {
	t.Helper()
	cfg := Config{ID: "corp", Issuer: op.srv.URL, ClientID: "client", ClientSecret: "s3cret", RedirectURL: "https://gw.test/callback/corp",
		HTTPClient: NewHTTPClient(op.srv.Client().Transport.(*http.Transport).Clone()), Now: op.clk.now}
	if mutate != nil {
		mutate(&cfg)
	}
	p, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// token signs claims; alg may be anything, including ones that must fail.
func token(t testing.TB, alg string, key any, kid string, header map[string]any, claims map[string]any) string {
	h := map[string]any{"alg": alg, "kid": kid}
	for k, v := range header {
		h[k] = v
	}
	if kid == "" {
		delete(h, "kid")
	}
	hb, _ := json.Marshal(h)
	pb, _ := json.Marshal(claims)
	input := enc(hb) + "." + enc(pb)
	var sig []byte
	switch alg {
	case "RS256":
		d := sha256.Sum256([]byte(input))
		sig, _ = rsa.SignPKCS1v15(rand.Reader, key.(*rsa.PrivateKey), crypto.SHA256, d[:])
	case "ES256":
		d := sha256.Sum256([]byte(input))
		k := key.(*ecdsa.PrivateKey)
		r, s, _ := ecdsa.Sign(rand.Reader, k, d[:])
		sig = make([]byte, 64)
		r.FillBytes(sig[:32])
		s.FillBytes(sig[32:])
	case "HS256":
		m := hmac.New(sha256.New, key.([]byte))
		m.Write([]byte(input))
		sig = m.Sum(nil)
	}
	return input + "." + enc(sig)
}

func (op *testOP) claims() map[string]any {
	now := op.clk.now().Unix()
	return map[string]any{"iss": op.srv.URL, "aud": "client", "sub": "alice", "exp": now + 300, "iat": now,
		"nonce": "n-1", "email": "Alice@Example.org", "email_verified": true, "name": "Alice", "groups": []string{"eng"}}
}

func TestExchangeHappyPath(t *testing.T) {
	op := newOP(t)
	p := op.provider(t, func(c *Config) { c.UseUserinfo = true })
	op.set(func(op *testOP) {
		op.userinfo = map[string]any{"sub": "alice", "groups": []string{"ignored"}, "nickname": "al"}
		op.tokenHandler = func(form url.Values, r *http.Request) (int, any) {
			c := op.claims()
			delete(c, "groups") // comes from userinfo instead
			c["at_hash"] = AccessTokenHash("RS256", "at-123")
			return 200, map[string]any{"access_token": "at-123", "token_type": "bearer", "id_token": token(t, "RS256", opKey, testKid, nil, c)}
		}
	})
	u, err := p.AuthURL(context.Background(), "st", "n-1", "verifier-0123456789012345678901234567890123")
	if err != nil {
		t.Fatal(err)
	}
	au, _ := url.Parse(u)
	q := au.Query()
	if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") != Challenge("verifier-0123456789012345678901234567890123") ||
		q.Get("state") != "st" || q.Get("nonce") != "n-1" || q.Get("scope") != "openid email profile" || q.Get("response_type") != "code" {
		t.Fatalf("auth URL %s", u)
	}
	res, err := p.Exchange(context.Background(), "code-1", "verifier", "n-1")
	if err != nil {
		t.Fatal(err)
	}
	id := res.Identity
	if id.Subject != "alice" || id.Email != "alice@example.org" || id.Name != "Alice" || len(id.Groups) != 1 || id.Groups[0] != "ignored" || id.Provider != "corp" {
		t.Fatalf("identity %+v", id)
	}
	op.mu.Lock()
	defer op.mu.Unlock()
	if op.lastForm.Get("code_verifier") != "verifier" || op.lastForm.Get("redirect_uri") != "https://gw.test/callback/corp" ||
		op.lastForm.Get("client_secret") != "" || !strings.HasPrefix(op.lastAuth, "Basic ") {
		t.Fatalf("token request %v %q", op.lastForm, op.lastAuth)
	}
}

func TestClientAuthMethods(t *testing.T) {
	op := newOP(t)
	op.set(func(op *testOP) {
		op.tokenHandler = func(url.Values, *http.Request) (int, any) {
			return 200, map[string]any{"id_token": token(t, "RS256", opKey, testKid, nil, op.claims())}
		}
	})
	for _, mode := range []string{ClientSecretPost, ClientAuthNone} {
		p := op.provider(t, func(c *Config) { c.ClientAuth = mode })
		if _, err := p.Exchange(context.Background(), "c", "v", "n-1"); err != nil {
			t.Fatal(mode, err)
		}
		op.mu.Lock()
		if op.lastAuth != "" || op.lastForm.Get("client_id") != "client" || (mode == ClientSecretPost) != (op.lastForm.Get("client_secret") == "s3cret") {
			t.Fatalf("%s: %v %q", mode, op.lastForm, op.lastAuth)
		}
		op.mu.Unlock()
	}
}

// TestIDTokenAttacks lists attacks on the ID token and the reason code
// each must produce.
func TestIDTokenAttacks(t *testing.T) {
	op := newOP(t)
	p := op.provider(t, nil)
	pemKey, _ := x509.MarshalPKIXPublicKey(&opKey.PublicKey)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mod := func(f func(c map[string]any)) map[string]any { c := op.claims(); f(c); return c }
	now := op.clk.now().Unix()
	cases := []struct {
		name   string
		tok    string
		at     string
		reason string
	}{
		{"valid", token(t, "RS256", opKey, testKid, nil, op.claims()), "", ""},
		{"alg none", token(t, "none", nil, testKid, nil, op.claims()), "", ReasonIDToken},
		{"HS256 signed with the RSA public key", token(t, "HS256", pemKey, testKid, nil, op.claims()), "", ReasonIDToken},
		{"ES256 token naming the RSA key", token(t, "ES256", ecKey, testKid, nil, op.claims()), "", ReasonUnknownKey},
		{"signed by an unknown key", token(t, "RS256", otherKey, testKid, nil, op.claims()), "", ReasonIDToken},
		{"unknown kid", token(t, "RS256", otherKey, "k-other", nil, op.claims()), "", ReasonUnknownKey},
		{"wrong audience", token(t, "RS256", opKey, testKid, nil, mod(func(c map[string]any) { c["aud"] = "another-client" })), "", "id_token_wrong_audience"},
		{"extra untrusted audience", token(t, "RS256", opKey, testKid, nil, mod(func(c map[string]any) { c["aud"] = []string{"client", "evil"}; c["azp"] = "client" })), "", "id_token_wrong_audience"},
		{"wrong azp", token(t, "RS256", opKey, testKid, nil, mod(func(c map[string]any) { c["azp"] = "evil" })), "", "id_token_wrong_authorized_party"},
		{"wrong issuer", token(t, "RS256", opKey, testKid, nil, mod(func(c map[string]any) { c["iss"] = "https://evil.example" })), "", "id_token_wrong_issuer"},
		{"expired", token(t, "RS256", opKey, testKid, nil, mod(func(c map[string]any) { c["exp"] = now - 600 })), "", "id_token_expired"},
		{"not yet valid", token(t, "RS256", opKey, testKid, nil, mod(func(c map[string]any) { c["nbf"] = now + 600 })), "", "id_token_not_yet_valid"},
		{"issued in the future", token(t, "RS256", opKey, testKid, nil, mod(func(c map[string]any) { c["iat"] = now + 600 })), "", "id_token_bad_issued_at"},
		{"issued long ago", token(t, "RS256", opKey, testKid, nil, mod(func(c map[string]any) { c["iat"] = now - 3600 })), "", "id_token_bad_issued_at"},
		{"replayed nonce from another login", token(t, "RS256", opKey, testKid, nil, mod(func(c map[string]any) { c["nonce"] = "n-other" })), "", ReasonNonce},
		{"no nonce", token(t, "RS256", opKey, testKid, nil, mod(func(c map[string]any) { delete(c, "nonce") })), "", ReasonNonce},
		{"no sub", token(t, "RS256", opKey, testKid, nil, mod(func(c map[string]any) { delete(c, "sub") })), "", ReasonClaims},
		{"sub too long", token(t, "RS256", opKey, testKid, nil, mod(func(c map[string]any) { c["sub"] = strings.Repeat("a", 256) })), "", ReasonClaims},
		{"sub with control chars", token(t, "RS256", opKey, testKid, nil, mod(func(c map[string]any) { c["sub"] = "a\nb" })), "", ReasonClaims},
		{"access token passed as ID token", token(t, "RS256", opKey, testKid, map[string]any{"typ": "at+jwt"}, op.claims()), "", ReasonIDToken},
		{"at_hash mismatch", token(t, "RS256", opKey, testKid, nil, mod(func(c map[string]any) { c["at_hash"] = "AAAA" })), "at-123", ReasonIDToken},
		{"malformed", "not.a.jwt", "", ReasonIDToken},
		{"bad claims JSON", token(t, "RS256", opKey, testKid, nil, mod(func(c map[string]any) { c["exp"] = "tomorrow" })), "", ReasonClaims},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := p.VerifyIDToken(context.Background(), c.tok, "n-1", c.at)
			var oe *Error
			switch {
			case c.reason == "" && err != nil:
				t.Fatalf("unexpected: %v", err)
			case c.reason != "" && (!errors.As(err, &oe) || oe.Reason != c.reason):
				t.Fatalf("got %v, want reason %s", err, c.reason)
			}
		})
	}
}

func TestDiscoveryChecks(t *testing.T) {
	cases := map[string]func(m map[string]any){
		"issuer mismatch":        func(m map[string]any) { m["issuer"] = "https://evil.example" },
		"http token endpoint":    func(m map[string]any) { m["token_endpoint"] = "http://x/token" },
		"missing jwks":           func(m map[string]any) { delete(m, "jwks_uri") },
		"http userinfo":          func(m map[string]any) { m["userinfo_endpoint"] = "http://x/u" },
		"http end session":       func(m map[string]any) { m["end_session_endpoint"] = "http://x/l" },
		"no code flow":           func(m map[string]any) { m["response_types_supported"] = []string{"id_token"} },
		"no S256":                func(m map[string]any) { m["code_challenge_methods_supported"] = []string{"plain"} },
		"endpoint with userinfo": func(m map[string]any) { m["authorization_endpoint"] = "https://u:p@x/a" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			op := newOP(t)
			op.set(func(op *testOP) { mutate(op.meta) })
			p := op.provider(t, nil)
			_, err := p.Discover(context.Background())
			var oe *Error
			if !errors.As(err, &oe) || oe.Reason != ReasonDiscovery {
				t.Fatalf("got %v", err)
			}
		})
	}
	op := newOP(t)
	op.set(func(op *testOP) { delete(op.meta, "userinfo_endpoint") })
	if _, err := op.provider(t, func(c *Config) { c.UseUserinfo = true }).Discover(context.Background()); err == nil {
		t.Fatal("userinfo enabled without an endpoint")
	}
	op.set(func(op *testOP) { op.meta = nil })
	if _, err := op.provider(t, nil).Discover(context.Background()); err == nil {
		t.Fatal("null metadata accepted")
	}
}

func TestDiscoveryCaching(t *testing.T) {
	op := newOP(t)
	p := op.provider(t, nil)
	ctx := context.Background()
	if _, err := p.Discover(ctx); err != nil {
		t.Fatal(err)
	}
	// The provider goes down: cached metadata keeps serving.
	op.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) })
	op.clk.add(2 * time.Hour)
	if _, err := p.Discover(ctx); err != nil {
		t.Fatalf("stale metadata should be served during an outage: %v", err)
	}
	// A provider that was never reachable fails, and the failure is
	// remembered briefly.
	op2 := newOP(t)
	op2.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) })
	p2 := op2.provider(t, nil)
	if _, err := p2.Discover(ctx); err == nil {
		t.Fatal("expected failure")
	}
	if _, err := p2.Discover(ctx); err == nil {
		t.Fatal("expected remembered failure")
	}
	if u := p2.EndSessionURL(ctx, ""); u != "" {
		t.Fatal("end session without metadata")
	}
	if _, err := p2.AuthURL(ctx, "s", "n", "v"); err == nil {
		t.Fatal("auth URL without metadata")
	}
	if _, err := p2.Exchange(ctx, "c", "v", "n"); err == nil {
		t.Fatal("exchange without metadata")
	}
}

func TestJWKSRotationAndRateLimit(t *testing.T) {
	op := newOP(t)
	p := op.provider(t, nil)
	ctx := context.Background()
	good := token(t, "RS256", opKey, testKid, nil, op.claims())
	if _, err := p.VerifyIDToken(ctx, good, "n-1", ""); err != nil {
		t.Fatal(err)
	}
	if p.KeyFetches() != 1 {
		t.Fatalf("fetches %d", p.KeyFetches())
	}
	// The provider rotates to a new key. The first token with the new kid
	// triggers one refetch.
	op.set(func(op *testOP) { op.jwks = []map[string]string{rsaJWK(&otherKey.PublicKey, "k2")} })
	rotated := token(t, "RS256", otherKey, "k2", nil, op.claims())
	op.clk.add(2 * time.Minute)
	if _, err := p.VerifyIDToken(ctx, rotated, "n-1", ""); err != nil {
		t.Fatalf("rotated key: %v", err)
	}
	if p.KeyFetches() != 2 {
		t.Fatalf("fetches %d", p.KeyFetches())
	}
	// A stream of unknown kids within a minute causes at most one fetch.
	for i := 0; i < 20; i++ {
		bogus := token(t, "RS256", otherKey, "bogus-"+string(rune('a'+i)), nil, op.claims())
		if _, err := p.VerifyIDToken(ctx, bogus, "n-1", ""); err == nil {
			t.Fatal("bogus kid accepted")
		}
	}
	if p.KeyFetches() > 3 {
		t.Fatalf("unknown kids caused %d fetches", p.KeyFetches())
	}
	// Expired cache plus a failing JWKS endpoint: keep the last good keys.
	op.clk.add(2 * time.Hour)
	op.set(func(op *testOP) { op.jwksStatus = 500 })
	if _, err := p.VerifyIDToken(ctx, token(t, "RS256", otherKey, "k2", nil, op.claims()), "n-1", ""); err != nil {
		t.Fatalf("stale keys during an outage: %v", err)
	}
	// No kid: accepted only when exactly one key fits.
	if _, err := p.VerifyIDToken(ctx, token(t, "RS256", otherKey, "", nil, op.claims()), "n-1", ""); err != nil {
		t.Fatalf("single key without kid: %v", err)
	}
	// First fetch failing with nothing cached is an error.
	op2 := newOP(t)
	op2.set(func(op *testOP) { op.jwksStatus = 500 })
	if _, err := op2.provider(t, nil).VerifyIDToken(ctx, token(t, "RS256", opKey, testKid, nil, op2.claims()), "n-1", ""); err == nil {
		t.Fatal("no keys at all")
	}
	op3 := newOP(t)
	op3.set(func(op *testOP) { op.jwks = []map[string]string{{"kty": "RSA", "n": "AQAB", "e": "AQAB"}} })
	if _, err := op3.provider(t, nil).VerifyIDToken(ctx, token(t, "RS256", opKey, testKid, nil, op3.claims()), "n-1", ""); err == nil {
		t.Fatal("invalid key set")
	}
}

func TestTokenEndpointFailures(t *testing.T) {
	op := newOP(t)
	p := op.provider(t, nil)
	ctx := context.Background()
	cases := map[string]func(url.Values, *http.Request) (int, any){
		"oauth error": func(url.Values, *http.Request) (int, any) { return 400, map[string]string{"error": "invalid_grant"} },
		"not json":    func(url.Values, *http.Request) (int, any) { return 200, "x" },
		"no id_token": func(url.Values, *http.Request) (int, any) {
			return 200, map[string]string{"access_token": "a", "token_type": "Bearer"}
		},
		"mac token type": func(url.Values, *http.Request) (int, any) {
			return 200, map[string]string{"access_token": "a", "token_type": "mac", "id_token": "x"}
		},
		"server error": func(url.Values, *http.Request) (int, any) { return 500, map[string]string{} },
		"bad id token": func(url.Values, *http.Request) (int, any) { return 200, map[string]string{"id_token": "x.y.z"} },
		"bad groups type": func(url.Values, *http.Request) (int, any) {
			c := op.claims()
			c["groups"] = map[string]int{"x": 1}
			return 200, map[string]string{"id_token": token(t, "RS256", opKey, testKid, nil, c)}
		},
		"too many groups": func(url.Values, *http.Request) (int, any) {
			c := op.claims()
			g := make([]string, MaxGroups+1)
			for i := range g {
				g[i] = "g" + strings.Repeat("x", i%7) + string(rune('a'+i%26)) + string(rune('a'+i/26%26))
			}
			c["groups"] = g
			return 200, map[string]string{"id_token": token(t, "RS256", opKey, testKid, nil, c)}
		},
	}
	for name, h := range cases {
		op.set(func(op *testOP) { op.tokenHandler = h })
		if _, err := p.Exchange(ctx, "code", "v", "n-1"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := p.Exchange(ctx, "", "v", "n"); err == nil {
		t.Error("empty code")
	}
	if _, err := p.Exchange(ctx, strings.Repeat("c", 5000), "v", "n"); err == nil {
		t.Error("huge code")
	}
}

func TestUserinfo(t *testing.T) {
	op := newOP(t)
	p := op.provider(t, func(c *Config) { c.UseUserinfo = true })
	tokenWith := func(c map[string]any) func(url.Values, *http.Request) (int, any) {
		return func(url.Values, *http.Request) (int, any) {
			return 200, map[string]any{"access_token": "at-123", "token_type": "Bearer", "id_token": token(t, "RS256", opKey, testKid, nil, c)}
		}
	}
	// A userinfo response for another user must not be merged.
	op.set(func(op *testOP) {
		op.userinfo = map[string]any{"sub": "mallory", "email": "x@y.z"}
		op.tokenHandler = tokenWith(op.claims())
	})
	if _, err := p.Exchange(context.Background(), "c", "v", "n-1"); err == nil || !strings.Contains(err.Error(), ReasonUserinfo) {
		t.Fatalf("sub mismatch: %v", err)
	}
	op.set(func(op *testOP) { op.userinfo = nil })
	if _, err := p.Exchange(context.Background(), "c", "v", "n-1"); err == nil {
		t.Fatal("null userinfo")
	}
	// An unverified email is not used for policy.
	op.set(func(op *testOP) {
		c := op.claims()
		c["email_verified"] = false
		op.userinfo = map[string]any{"sub": "alice"}
		op.tokenHandler = tokenWith(c)
	})
	res, err := p.Exchange(context.Background(), "c", "v", "n-1")
	if err != nil || res.Identity.Email != "" {
		t.Fatalf("unverified email: %+v %v", res, err)
	}
	// Userinfo rejecting the access token is a failure.
	op.set(func(op *testOP) {
		op.tokenHandler = func(url.Values, *http.Request) (int, any) {
			return 200, map[string]any{"access_token": "wrong", "token_type": "Bearer", "id_token": token(t, "RS256", opKey, testKid, nil, op.claims())}
		}
	})
	if _, err := p.Exchange(context.Background(), "c", "v", "n-1"); err == nil {
		t.Fatal("userinfo 401 accepted")
	}
}

func TestNewValidation(t *testing.T) {
	base := Config{Issuer: "https://idp", ClientID: "c", ClientSecret: "s", RedirectURL: "https://gw/cb"}
	bad := map[string]func(c *Config){
		"http issuer":     func(c *Config) { c.Issuer = "http://idp" },
		"no client":       func(c *Config) { c.ClientID = "" },
		"bad auth":        func(c *Config) { c.ClientAuth = "private_key_jwt" },
		"no secret":       func(c *Config) { c.ClientSecret = "" },
		"http redirect":   func(c *Config) { c.RedirectURL = "http://gw/cb" },
		"no openid scope": func(c *Config) { c.Scopes = []string{"email"} },
		"bad scope":       func(c *Config) { c.Scopes = []string{"openid", "a b"} },
		"empty scope":     func(c *Config) { c.Scopes = []string{"openid", ""} },
		"HS256":           func(c *Config) { c.Algorithms = []string{"HS256"} },
		"none":            func(c *Config) { c.Algorithms = []string{"none"} },
	}
	for name, f := range bad {
		c := base
		f(&c)
		if _, err := New(c); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	c := base
	c.ClientAuth, c.ClientSecret = ClientAuthNone, ""
	p, err := New(c)
	if err != nil || p.ID() != "" {
		t.Fatal(err)
	}
}

func TestHelpers(t *testing.T) {
	if len(RandomToken()) != 43 || RandomToken() == RandomToken() {
		t.Fatal("RandomToken")
	}
	// RFC 7636 appendix B.
	if Challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk") != "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" {
		t.Fatal("PKCE S256 vector")
	}
	for alg, n := range map[string]int{"RS256": 22, "ES384": 32, "PS512": 43, "EdDSA": 43} {
		if len(AccessTokenHash(alg, "token")) != n {
			t.Errorf("at_hash length for %s", alg)
		}
	}
	emails := map[string]string{"A@B.c": "a@b.c", "a@@b": "", "@b": "", "a@": "", "a b@c": "", "a@b@c": "", strings.Repeat("a", 250) + "@b.co": "", "é@x.y": ""}
	for in, want := range emails {
		if got := NormalizeEmail(in); got != want {
			t.Errorf("NormalizeEmail(%q) = %q", in, got)
		}
	}
	if g, err := CleanGroups([]string{"a", "a", "b"}); err != nil || len(g) != 2 {
		t.Fatal("dedupe")
	}
	for _, bad := range [][]string{{""}, {"a\nb"}, {strings.Repeat("g", 257)}} {
		if _, err := CleanGroups(bad); err == nil {
			t.Errorf("group %q accepted", bad)
		}
	}
	if printable("ab\x00c\u0085d", 3) != "abc" || redact("https://u:p@x/y?code=1#f") != "https://x/y" || redact("%") != "(invalid URL)" {
		t.Fatal("printable/redact")
	}
	if cacheMaxAge("public, max-age=60") != time.Minute || cacheMaxAge("no-store") != -1 || cacheMaxAge("max-age=x") != -1 {
		t.Fatal("cacheMaxAge")
	}
	e := &Error{Reason: "r", Err: errors.New("e")}
	if e.Error() != "oidc: r: e" || errors.Unwrap(e).Error() != "e" {
		t.Fatal("Error")
	}
}

func TestBackChannelLimits(t *testing.T) {
	op := newOP(t)
	client := NewHTTPClient(op.srv.Client().Transport.(*http.Transport).Clone())
	// Redirects are never followed, so a credential can't be forwarded.
	if _, _, err := get(context.Background(), client, op.srv.URL+"/redirect", "secret"); err == nil {
		t.Fatal("redirect followed")
	}
	big := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(make([]byte, maxResponseBytes+10))
	}))
	defer big.Close()
	if _, _, err := get(context.Background(), NewHTTPClient(big.Client().Transport.(*http.Transport).Clone()), big.URL, ""); err == nil {
		t.Fatal("oversized response accepted")
	}
	if _, _, err := get(context.Background(), client, "://bad", ""); err == nil {
		t.Fatal("bad URL")
	}
	if NewHTTPClient(nil).Timeout != requestTimeout {
		t.Fatal("default client")
	}
}

func TestEndSessionURL(t *testing.T) {
	op := newOP(t)
	p := op.provider(t, nil)
	u, _ := url.Parse(p.EndSessionURL(context.Background(), "https://gw/logged-out"))
	if u.Query().Get("client_id") != "client" || u.Query().Get("post_logout_redirect_uri") != "https://gw/logged-out" {
		t.Fatalf("%s", u)
	}
	op.set(func(op *testOP) { delete(op.meta, "end_session_endpoint") })
	if p := op.provider(t, nil); p.EndSessionURL(context.Background(), "") != "" {
		t.Fatal("no end_session_endpoint")
	}
}

func BenchmarkVerifyIDToken(b *testing.B) {
	op := newOP(b)
	p := op.provider(b, nil)
	tok := token(b, "RS256", opKey, testKid, nil, op.claims())
	ctx := context.Background()
	for b.Loop() {
		if _, err := p.VerifyIDToken(ctx, tok, "n-1", ""); err != nil {
			b.Fatal(err)
		}
	}
}
