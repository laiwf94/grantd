package check

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/laiwf94/wicket/internal/config"
	"github.com/laiwf94/wicket/internal/fakeidp"
)

var now = time.Date(2026, 11, 2, 9, 0, 0, 0, time.UTC)

var (
	keyOnce sync.Once
	spKey   *rsa.PrivateKey
	otherSP *rsa.PrivateKey
)

func keys(t *testing.T) {
	keyOnce.Do(func() {
		var err error
		if spKey, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
			panic(err)
		}
		if otherSP, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
			panic(err)
		}
	})
}

func cert(t *testing.T, key *rsa.PrivateKey, cn string, from, to time.Time) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn}, NotBefore: from, NotAfter: to,
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c
}

func write(t *testing.T, dir, name string, b []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func certPEM(c *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
}

func keyPEM(k *rsa.PrivateKey) []byte {
	der, _ := x509.MarshalPKCS8PrivateKey(k)
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// fixture is a directory of valid files and a config that uses them.
type fixture struct {
	dir                     string
	ca, spKey, spCert, meta string
	idp                     *fakeidp.IdP
}

func newFixture(t *testing.T) *fixture {
	keys(t)
	f := &fixture{dir: t.TempDir()}
	f.ca = write(t, f.dir, "ca.pem", certPEM(cert(t, otherSP, "ca", now.AddDate(-1, 0, 0), now.AddDate(5, 0, 0))))
	f.spKey = write(t, f.dir, "sp-key.pem", keyPEM(spKey))
	f.spCert = write(t, f.dir, "sp.pem", certPEM(cert(t, spKey, "sp", now.AddDate(-1, 0, 0), now.AddDate(2, 0, 0))))
	var err error
	if f.idp, err = fakeidp.New(fakeidp.Config{Issuer: "https://idp.example.com", Now: func() time.Time { return now }}); err != nil {
		t.Fatal(err)
	}
	f.meta = write(t, f.dir, "idp.xml", f.idp.Metadata())
	return f
}

func (f *fixture) config() map[string]any {
	return map[string]any{
		"public_url": "https://gw.example.com",
		"providers": []any{
			map[string]any{"id": "corp", "type": "oidc", "issuer": "https://idp.example.com", "client_id": "c",
				"client_secret_env": "SECRET", "ca_file": f.ca},
			map[string]any{"id": "partner", "type": "saml", "idp_metadata_file": f.meta, "sp_key_file": f.spKey,
				"sp_cert_file": f.spCert, "sign_requests": true},
		},
		"apps": []any{map[string]any{"id": "app", "hosts": []string{"app.example.com"}, "providers": []string{"corp", "partner"},
			"allow": map[string]any{"any_user": true}}},
	}
}

func provider(m map[string]any, i int) map[string]any {
	return m["providers"].([]any)[i].(map[string]any)
}

// offline fails the test if anything tries to use the network.
func offline(t *testing.T) Options {
	return Options{
		Getenv: func(k string) string { return map[string]string{"SECRET": "s"}[k] },
		Now:    func() time.Time { return now },
		Client: func(*config.Provider, *x509.CertPool) *http.Client {
			return &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				t.Errorf("offline check fetched %s", r.URL)
				return nil, http.ErrHandlerTimeout
			})}
		},
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func run(t *testing.T, m map[string]any, o Options) config.Problems {
	t.Helper()
	b, _ := json.MarshalIndent(m, "", "  ")
	return Bytes(context.Background(), b, o).Problems
}

type want struct {
	path string
	sev  config.Severity
	msg  string
}

func expect(t *testing.T, got config.Problems, wants ...want) {
	t.Helper()
	if len(got) != len(wants) {
		t.Fatalf("got %d problems, want %d:\n%s", len(got), len(wants), got.Error())
	}
	for i, w := range wants {
		g := got[i]
		if g.Path != w.path || g.Severity != w.sev || !strings.Contains(g.Message, w.msg) {
			t.Errorf("problem %d = %s %s %q, want %s %s containing %q", i, g.Severity, g.Path, g.Message, w.sev, w.path, w.msg)
		}
		if g.Line == 0 {
			t.Errorf("%s has no position", g)
		}
	}
}

func TestOfflineGood(t *testing.T) {
	f := newFixture(t)
	expect(t, run(t, f.config(), offline(t)))
	// A metadata URL is not fetched offline.
	m := f.config()
	delete(provider(m, 1), "idp_metadata_file")
	provider(m, 1)["idp_metadata_url"] = "https://idp.example.com/saml/metadata"
	expect(t, run(t, m, offline(t)))
}

func TestOfflineFiles(t *testing.T) {
	f := newFixture(t)
	small, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	noCerts := write(t, f.dir, "none.pem", []byte("not pem"))
	smallKey := write(t, f.dir, "small.pem", keyPEM(small))
	otherCert := write(t, f.dir, "other.pem", certPEM(cert(t, otherSP, "other", now.AddDate(-1, 0, 0), now.AddDate(1, 0, 0))))
	expiredSP := write(t, f.dir, "expired-sp.pem", certPEM(cert(t, spKey, "old sp", now.AddDate(-2, 0, 0), now.AddDate(-1, 0, 0))))
	soonSP := write(t, f.dir, "soon-sp.pem", certPEM(cert(t, spKey, "soon sp", now.AddDate(-1, 0, 0), now.AddDate(0, 0, 10))))
	badMeta := write(t, f.dir, "bad.xml", []byte("<x/>"))
	oldIdP, err := fakeidp.New(fakeidp.Config{Issuer: "https://idp.example.com", Now: func() time.Time { return now.AddDate(-2, 0, 0) }})
	if err != nil {
		t.Fatal(err)
	}
	expiredMeta := write(t, f.dir, "expired.xml", oldIdP.Metadata())
	wantsSigned := write(t, f.dir, "signed.xml", []byte(strings.Replace(string(f.idp.Metadata()), "<md:IDPSSODescriptor ",
		`<md:IDPSSODescriptor WantAuthnRequestsSigned="true" `, 1)))

	cases := []struct {
		name  string
		edit  func(m map[string]any)
		wants []want
	}{
		{"missing ca file", func(m map[string]any) { provider(m, 0)["ca_file"] = f.dir + "/missing.pem" },
			[]want{{"$.providers[0].ca_file", config.SeverityError, "no such file"}}},
		{"ca file without certificates", func(m map[string]any) { provider(m, 0)["ca_file"] = noCerts },
			[]want{{"$.providers[0].ca_file", config.SeverityError, "no PEM certificates"}}},
		{"expired ca", func(m map[string]any) { provider(m, 0)["ca_file"] = expiredSP },
			[]want{{"$.providers[0].ca_file", config.SeverityWarning, `CA certificate: "old sp" expired 2025-11-02`}}},
		{"sp key missing", func(m map[string]any) { provider(m, 1)["sp_key_file"] = f.dir + "/nope.pem" },
			[]want{{"$.providers[1].sp_key_file", config.SeverityError, "no such file"}}},
		{"sp key not a key", func(m map[string]any) { provider(m, 1)["sp_key_file"] = f.spCert },
			[]want{{"$.providers[1].sp_key_file", config.SeverityError, "no PRIVATE KEY PEM block"}}},
		{"sp key too small", func(m map[string]any) { provider(m, 1)["sp_key_file"] = smallKey },
			[]want{{"$.providers[1].sp_key_file", config.SeverityError, "1024 bits"}}},
		{"sp cert and key both bad", func(m map[string]any) {
			provider(m, 1)["sp_key_file"] = noCerts
			provider(m, 1)["sp_cert_file"] = noCerts
		}, []want{ // in file order: keys are marshalled sorted
			{"$.providers[1].sp_cert_file", config.SeverityError, "no CERTIFICATE PEM block"},
			{"$.providers[1].sp_key_file", config.SeverityError, "no PRIVATE KEY PEM block"},
		}},
		{"sp cert for another key", func(m map[string]any) { provider(m, 1)["sp_cert_file"] = otherCert },
			[]want{{"$.providers[1].sp_cert_file", config.SeverityError, "is not the certificate for"}}},
		{"sp cert expired", func(m map[string]any) { provider(m, 1)["sp_cert_file"] = expiredSP },
			[]want{{"$.providers[1].sp_cert_file", config.SeverityWarning, "expired"}}},
		{"sp cert expiring", func(m map[string]any) { provider(m, 1)["sp_cert_file"] = soonSP },
			[]want{{"$.providers[1].sp_cert_file", config.SeverityWarning, `SP certificate "soon sp" expires 2026-11-12`}}},
		{"metadata missing", func(m map[string]any) { provider(m, 1)["idp_metadata_file"] = f.dir + "/no.xml" },
			[]want{{"$.providers[1].idp_metadata_file", config.SeverityError, "no such file"}}},
		{"metadata invalid", func(m map[string]any) { provider(m, 1)["idp_metadata_file"] = badMeta },
			[]want{{"$.providers[1].idp_metadata_file", config.SeverityError, "root must be md:EntityDescriptor"}}},
		{"idp certificate expired", func(m map[string]any) { provider(m, 1)["idp_metadata_file"] = expiredMeta },
			[]want{{"$.providers[1].idp_metadata_file", config.SeverityError, "no valid certificate left"}}},
		{"idp wants signed requests", func(m map[string]any) {
			p := provider(m, 1)
			p["idp_metadata_file"] = wantsSigned
			delete(p, "sign_requests")
		}, []want{{"$.providers[1].sign_requests", config.SeverityError, "wants signed requests"}}},
		{"idp wants signed requests and gets them", func(m map[string]any) { provider(m, 1)["idp_metadata_file"] = wantsSigned }, nil},
		{"config and file problems together", func(m map[string]any) {
			m["public_url"] = "http://gw.example.com"
			provider(m, 0)["ca_file"] = noCerts
			provider(m, 1)["sp_cert_file"] = otherCert
		}, []want{
			{"$.providers[0].ca_file", config.SeverityError, "no PEM certificates"},
			{"$.providers[1].sp_cert_file", config.SeverityError, "is not the certificate for"},
			{"$.public_url", config.SeverityError, "absolute https URL"},
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := f.config()
			c.edit(m)
			expect(t, run(t, m, offline(t)), c.wants...)
		})
	}
}

// onlineIdP serves fakeidp over TLS; the returned options trust it.
func onlineIdP(t *testing.T, wrap func(http.Handler) http.Handler) (*fixture, map[string]any, Options) {
	t.Helper()
	f := newFixture(t)
	srv := httptest.NewUnstartedServer(nil)
	issuer := "https://" + srv.Listener.Addr().String()
	idp, err := fakeidp.New(fakeidp.Config{Issuer: issuer, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	var h http.Handler = idp
	if wrap != nil {
		h = wrap(h)
	}
	srv.Config.Handler = h
	srv.StartTLS()
	t.Cleanup(srv.Close)
	m := f.config()
	p0 := provider(m, 0)
	p0["issuer"] = issuer
	delete(p0, "ca_file")
	p0["userinfo"] = true
	p0["post_logout_redirect_url"] = "https://gw.example.com/bye"
	p1 := provider(m, 1)
	delete(p1, "idp_metadata_file")
	p1["idp_metadata_url"] = issuer + "/saml/metadata"
	o := Options{
		Online: true,
		Getenv: func(k string) string { return map[string]string{"SECRET": "s"}[k] },
		Now:    func() time.Time { return now },
		Client: func(*config.Provider, *x509.CertPool) *http.Client { return srv.Client() },
	}
	return f, m, o
}

func TestOnline(t *testing.T) {
	_, m, o := onlineIdP(t, nil)
	expect(t, run(t, m, o))

	// Discovery for an issuer that does not exist.
	provider(m, 0)["issuer"] = provider(m, 0)["issuer"].(string) + "/tenant"
	provider(m, 1)["idp_metadata_url"] = provider(m, 1)["idp_metadata_url"].(string) + "-missing"
	expect(t, run(t, m, o),
		want{"$.providers[0].issuer", config.SeverityError, "discovery"},
		want{"$.providers[1].idp_metadata_url", config.SeverityError, "status 404"},
	)
}

func TestOnlineKeysMustFitAlgorithms(t *testing.T) {
	_, m, o := onlineIdP(t, nil)
	provider(m, 0)["algorithms"] = []string{"ES256"}
	expect(t, run(t, m, o), want{"$.providers[0].issuer", config.SeverityError, "can verify [ES256]"})
}

func TestOnlineNoEndSession(t *testing.T) {
	_, m, o := onlineIdP(t, func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/.well-known/openid-configuration" {
				h.ServeHTTP(w, r)
				return
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, r)
			var doc map[string]any
			json.Unmarshal(rec.Body.Bytes(), &doc)
			delete(doc, "end_session_endpoint")
			json.NewEncoder(w).Encode(doc)
		})
	})
	expect(t, run(t, m, o), want{"$.providers[0].post_logout_redirect_url", config.SeverityWarning, "no end_session_endpoint"})
}

func TestOnlineTimeout(t *testing.T) {
	release := make(chan struct{})
	_, m, o := onlineIdP(t, func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			select {
			case <-release:
			case <-r.Context().Done():
			}
		})
	})
	defer close(release)
	o.Timeout = 200 * time.Millisecond
	start := time.Now()
	ps := run(t, m, o)
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("took %s; providers must be checked concurrently within the timeout", d)
	}
	expect(t, ps,
		want{"$.providers[0].issuer", config.SeverityError, "deadline"},
		want{"$.providers[1].idp_metadata_url", config.SeverityError, "deadline"},
	)
}

func TestOnlineSkippedWithoutCA(t *testing.T) {
	f, m, o := onlineIdP(t, nil)
	provider(m, 0)["ca_file"] = write(t, f.dir, "junk.pem", []byte("junk"))
	base := o.Client
	o.Client = func(p *config.Provider, roots *x509.CertPool) *http.Client {
		tr := base(p, roots).Transport
		return &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if p.ID == "corp" {
				t.Errorf("fetched %s for a provider whose CA bundle is broken", r.URL)
			}
			return tr.RoundTrip(r)
		})}
	}
	// The SAML provider is still checked online.
	expect(t, run(t, m, o), want{"$.providers[0].ca_file", config.SeverityError, "no PEM certificates"})
}

func TestFile(t *testing.T) {
	f := newFixture(t)
	b, _ := json.Marshal(f.config())
	path := write(t, f.dir, "wicket.json", b)
	if r := File(context.Background(), path, offline(t)); len(r.Problems) != 0 || r.Config == nil {
		t.Fatalf("%v", r.Problems)
	}
	r := File(context.Background(), f.dir+"/missing.json", offline(t))
	if len(r.Problems) != 1 || r.Problems[0].Path != "$" || !strings.Contains(r.Problems[0].Message, "no such file") {
		t.Fatalf("%v", r.Problems)
	}
	r = File(context.Background(), write(t, f.dir, "broken.json", []byte("{")), offline(t))
	if r.Config != nil || r.Problems.Err() == nil {
		t.Fatal("broken JSON")
	}
}

func TestDefaultClient(t *testing.T) {
	c := defaultClient(nil, nil)
	if c == nil || c.Transport == nil {
		t.Fatal("no client")
	}
}
