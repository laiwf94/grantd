package redirect

import (
	mrand "math/rand/v2"
	"net/url"
	"strings"
	"testing"
)

func validator(t testing.TB) *Validator {
	t.Helper()
	base, _ := url.Parse("https://auth.example.com/_wicket")
	v, err := New([]string{"app.example.com", "localhost:8443", "*.apps.example.com", "*.dev.example.com:8443"}, base)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestValidate(t *testing.T) {
	v := validator(t)
	allowed := map[string]string{
		"https://app.example.com/":            "https://app.example.com/",
		"https://app.example.com:443/x?y=1#z": "https://app.example.com:443/x?y=1#z",
		"https://APP.example.com/":            "https://APP.example.com/",
		"https://localhost:8443/a/b":          "https://localhost:8443/a/b",
		"https://a.apps.example.com/":         "https://a.apps.example.com/",
		"https://a.b.apps.example.com/":       "https://a.b.apps.example.com/",
		"https://x.dev.example.com:8443/":     "https://x.dev.example.com:8443/",
		"https://auth.example.com/done":       "https://auth.example.com/done",
		"/relative/path?q=1":                  "https://auth.example.com/relative/path?q=1",
		"https://app.example.com/a%2Fb?x=%25": "https://app.example.com/a%2Fb?x=%25",
	}
	for in, want := range allowed {
		got, err := v.Validate(in)
		if err != nil || got != want {
			t.Errorf("%q: got %q, %v; want %q", in, got, err, want)
		}
	}
	// Each of these has been used to escape allow-list checks somewhere.
	rejected := []string{
		"",
		"http://app.example.com/",             // not https
		"https://evil.com/",                   // not listed
		"//evil.com/",                         // scheme-relative
		"/\\evil.com",                         // backslash
		"https:\\\\evil.com",                  // backslashes as slashes
		"https://app.example.com\\@evil.com/", // backslash before @
		"https://app.example.com@evil.com/",   // user info
		"https://user:pw@app.example.com/",    // user info
		"https://evil.com#@app.example.com",   // fragment trick
		"https://evil.com?@app.example.com",   // query trick
		"https://app.example.com.evil.com/",   // suffix
		"https://evilapp.example.com/",        // prefix
		"https://apps.example.com/",           // wildcard needs a label
		"https://x.apps.example.com:8443/",    // wildcard pattern implies 443
		"https://x.dev.example.com/",          // wildcard pattern has port 8443
		"https://localhost/",                  // listed only with port
		"https://app%2Eexample.com/",          // encoded host
		"https://%61pp.example.com/",          // encoded host
		"https://app.example.com /",           // space
		"https://app.example.com/\tx",         // control character
		"https://app.example.com/\nx",         // newline
		" https://app.example.com/",           // leading space
		"javascript:alert(1)",                 // other scheme
		"data:text/html,x",                    // other scheme
		"https:app.example.com",               // opaque
		"https:/app.example.com",              // single slash
		"HTTPS://app.example.com/",            // upper-case scheme (refused, not guessed)
		"https://[::1]/",                      // not listed
		"https://app.example.com:99999/",      // bad port
		"https://app.example.com:/",           // empty port
		"/" + strings.Repeat("a", MaxLength),  // too long
		"https://app.example.com/\x7f",        // DEL
	}
	for _, in := range rejected {
		if got, err := v.Validate(in); err == nil {
			t.Errorf("%q accepted as %q", in, got)
		}
	}
}

func TestNew(t *testing.T) {
	base, _ := url.Parse("https://auth.example.com")
	for _, p := range []string{"", "bad host", "*.", "a..b", "-a.com", "a-.com", "a.com:x", "a.com:123456", strings.Repeat("a", 64) + ".com", "*.bad host"} {
		if _, err := New([]string{p}, base); err == nil {
			t.Errorf("pattern %q accepted", p)
		}
	}
	http, _ := url.Parse("http://auth.example.com")
	if _, err := New(nil, http); err == nil {
		t.Error("http base accepted")
	}
	if _, err := New(nil, nil); err == nil {
		t.Error("nil base accepted")
	}
	v, err := New([]string{"10.0.0.1:8443", " Spaced.Example.com "}, base)
	if err != nil {
		t.Fatal(err)
	}
	if !v.HostAllowed("10.0.0.1:8443") || !v.HostAllowed("spaced.example.com") || v.HostAllowed("10.0.0.1") {
		t.Error("IP and normalized hosts")
	}
}

// referenceAllowed is an independent statement of the allow-list used by
// validator(): exact hosts with their effective port, and the two wildcard
// patterns, which need at least one extra label.
func referenceAllowed(u *url.URL) bool {
	host, port := strings.ToLower(u.Hostname()), u.Port()
	if port == "" {
		port = "443"
	}
	switch host + ":" + port {
	case "app.example.com:443", "localhost:8443", "auth.example.com:443":
		return true
	}
	for _, w := range []struct{ suffix, port string }{{".apps.example.com", "443"}, {".dev.example.com", "8443"}} {
		if port == w.port && strings.HasSuffix(host, w.suffix) && len(host) > len(w.suffix) {
			return true
		}
	}
	return false
}

// TestPropertyAccepted builds random URLs part by part from pieces that
// have caused open redirects elsewhere (user info, backslashes, encoded
// hosts, look-alike suffixes, odd ports). Whatever Validate accepts must,
// read the way a browser reads it (backslashes as slashes), be https with no
// user info and a host the independent reference allows; validating the
// result again must give the same URL.
func TestPropertyAccepted(t *testing.T) {
	v := validator(t)
	r := mrand.New(mrand.NewPCG(5, 6))
	pick := func(list ...string) string { return list[r.IntN(len(list))] }
	accepted, rejected := 0, 0
	for i := 0; i < 50000; i++ {
		in := pick("https://", "https://", "https://", "http://", "//", "/", "https:/", "https:", "https:\\\\", "HTTPS://", "javascript:", "") +
			pick("", "", "", "user@", "user:pw@", "app.example.com@", "app.example.com\\@", "@") +
			pick("app.example.com", "APP.example.com", "evil.com", "apps.example.com", "evilapps.example.com", "a.apps.example.com",
				"a.b.apps.example.com", "x.dev.example.com", "localhost", "auth.example.com", "app.example.com.evil.com",
				"%61pp.example.com", "app%2eexample.com", "[::1]", "") +
			pick("", "", ":443", ":8443", ":444", ":", ":99999") +
			pick("", "", "/", "/path", "\\evil.com", "#@evil.com", "?@evil.com", "/..//evil.com", " ", "\t", "%2f%2fevil.com")
		out, err := v.Validate(in)
		if err != nil {
			rejected++
			continue
		}
		accepted++
		u, perr := url.Parse(strings.ReplaceAll(out, "\\", "/"))
		if perr != nil || u.Scheme != "https" || u.User != nil || !referenceAllowed(u) {
			t.Fatalf("%q accepted as %q, which reaches %q", in, out, u)
		}
		if again, err := v.Validate(out); err != nil || again != out {
			t.Fatalf("%q -> %q not stable: %q %v", in, out, again, err)
		}
	}
	if accepted < 1000 || rejected < 1000 {
		t.Fatalf("generator is unbalanced: %d accepted, %d rejected", accepted, rejected)
	}
}

func FuzzValidate(f *testing.F) {
	v := validator(f)
	for _, s := range []string{"https://app.example.com/", "/x", "//evil.com", "https://app.example.com@evil.com"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		out, err := v.Validate(s)
		if err != nil {
			return
		}
		u, perr := url.Parse(out)
		if perr != nil || u.Scheme != "https" || u.User != nil || !v.HostAllowed(u.Host) || strings.ContainsAny(out, "\\ \t\r\n") {
			t.Fatalf("%q accepted as %q", s, out)
		}
	})
}

func BenchmarkValidate(b *testing.B) {
	v := validator(b)
	for b.Loop() {
		if _, err := v.Validate("https://a.apps.example.com/path?q=1"); err != nil {
			b.Fatal(err)
		}
	}
}

func TestCheckHost(t *testing.T) {
	for _, c := range []struct {
		p        string
		wildcard bool
		ok       bool
	}{
		{"app.example.com", false, true}, {"App.Example.com:8443", false, true}, {"10.0.0.1:443", false, true},
		{"*.example.com", true, true}, {"*.example.com", false, false}, {"a b", true, false}, {"a_b.com", false, false},
		{"x.com:", false, false}, {"x.com:123456", false, false}, {"", false, false}, {"-a.com", false, false},
	} {
		if err := CheckHost(c.p, c.wildcard); (err == nil) != c.ok {
			t.Errorf("CheckHost(%q, %v) = %v", c.p, c.wildcard, err)
		}
		// CheckHost accepts exactly what New accepts.
		if c.wildcard || !strings.HasPrefix(c.p, "*.") {
			_, err := New([]string{c.p}, &url.URL{Scheme: "https", Host: "gw.example.com"})
			if (err == nil) != c.ok {
				t.Errorf("New(%q) = %v, CheckHost disagrees", c.p, err)
			}
		}
	}
	if Canonical("A.com") != "a.com:443" || Canonical("a.com:80") != "a.com:80" {
		t.Error("Canonical")
	}
}
