package config

import (
	"encoding/json"
	"errors"
	"math/rand/v2"
	"strings"
	"testing"
)

func getenvSecret(k string) string {
	if k == "SECRET" {
		return "s3cret"
	}
	return ""
}

type want struct {
	path string
	sev  Severity
	msg  string // substring
}

func checkDoc(t *testing.T, doc string) Problems {
	t.Helper()
	return Check([]byte(doc), getenvSecret).Problems
}

func expect(t *testing.T, got Problems, wants ...want) {
	t.Helper()
	if len(got) != len(wants) {
		t.Fatalf("got %d problems, want %d:\n%s", len(got), len(wants), dump(got))
	}
	for i, w := range wants {
		g := got[i]
		if g.Path != w.path || g.Severity != w.sev || !strings.Contains(g.Message, w.msg) {
			t.Errorf("problem %d = %s %s %q, want %s %s containing %q\n%s", i, g.Severity, g.Path, g.Message, w.sev, w.path, w.msg, dump(got))
		}
	}
}

func dump(ps Problems) string {
	var b strings.Builder
	for _, p := range ps {
		b.WriteString("  ")
		b.WriteString(p.Severity.String())
		b.WriteString(" ")
		b.WriteString(p.String())
		b.WriteString("\n")
	}
	return b.String()
}

const goodDoc = `{
  "public_url": "https://auth.example.com",
  "providers": [
    {"id": "corp", "type": "oidc", "issuer": "https://idp.example.com", "client_id": "c", "client_secret_env": "SECRET"}
  ],
  "apps": [
    {"id": "app", "hosts": ["app.example.com"], "providers": ["corp"], "allow": {"groups": ["eng"]}}
  ]
}`

func TestCheckGood(t *testing.T) {
	r := Check([]byte(goodDoc), getenvSecret)
	if len(r.Problems) != 0 || r.Config == nil || r.Problems.Err() != nil {
		t.Fatalf("%v\n%s", r.Problems.Err(), dump(r.Problems))
	}
}

// TestCheckReportsEverything feeds one document with many independent
// mistakes and expects every one of them, in file order, with its path.
func TestCheckReportsEverything(t *testing.T) {
	doc := `{
  "public_url": "http://auth.example.com",
  "Clock_Skew": "1m",
  "session": {"idle_timeout": 5, "absolute_timeout": "900h"},
  "upstream_token_ttl": "1s",
  "redirect_hosts": ["*.ok.example.com", "bad host"],
  "providers": [
    {"id": "corp", "type": "oidc", "issuer": "http://idp.example.com", "client_id": "c",
     "client_secret_env": "NOPE", "algorithms": ["RS256", "HS256"], "scopes": ["email"], "sp_key_file": "k"},
    {"id": "corp", "type": "saml", "idp_metadata_file": "m.xml", "idp_metadata_url": "https://m", "client_id": "x"},
    {"id": "spare", "type": "saml", "sign_requests": true},
    {"id": "Bad!", "type": "ldap"}
  ],
  "apps": [
    {"id": "a", "hosts": ["a.example.com", "A.example.com"], "providers": ["corp", "corp"], "allow": {"any_user": true, "emails": ["x@y"]}},
    {"id": "a", "hosts": ["a.example.com:443", "b_x.example.com", "*.c.example.com"], "providers": ["ghost"],
     "allow": {"emails": ["alice"], "email_domains": ["@x.com"]}, "default_url": "http://a.example.com/"},
    {"id": "d", "hosts": [], "providers": []}
  ]
}`
	expect(t, checkDoc(t, doc),
		want{"$.public_url", SeverityError, "absolute https URL"},
		want{"$.Clock_Skew", SeverityError, `unknown field (did you mean "clock_skew"?)`},
		want{"$.session.idle_timeout", SeverityError, "must be a duration string"},
		want{"$.session.absolute_timeout", SeverityError, "at most 720h"},
		want{"$.upstream_token_ttl", SeverityError, "between 10s"},
		want{"$.redirect_hosts[1]", SeverityError, `invalid host "bad host"`},
		want{"$.providers[0].issuer", SeverityError, "absolute https URL"},
		want{"$.providers[0].client_secret_env", SeverityError, "NOPE is empty"},
		want{"$.providers[0].algorithms[1]", SeverityError, `"HS256" is not allowed`},
		want{"$.providers[0].scopes", SeverityError, `must include "openid"`},
		want{"$.providers[0].sp_key_file", SeverityError, "SAML setting on an oidc provider"},
		want{"$.providers[1].id", SeverityError, `duplicate provider id "corp" (also $.providers[0])`},
		want{"$.providers[1].idp_metadata_url", SeverityError, "exactly one"},
		want{"$.providers[1].client_id", SeverityError, "OpenID Connect setting on a saml provider"},
		want{"$.providers[2]", SeverityError, "set idp_metadata_file or idp_metadata_url"},
		want{"$.providers[2]", SeverityWarning, "spare is not used"},
		want{"$.providers[2].sign_requests", SeverityError, "needs sp_key_file"},
		want{"$.providers[3].id", SeverityError, `provider id "Bad!"`},
		want{"$.providers[3].type", SeverityError, `must be "oidc" or "saml"`},
		want{"$.apps[0].hosts[1]", SeverityWarning, "listed twice in this app (also $.apps[0].hosts[0])"},
		want{"$.apps[0].providers[1]", SeverityWarning, `"corp" is listed twice`},
		want{"$.apps[0].allow", SeverityWarning, "other lists have no effect"},
		want{"$.apps[1].id", SeverityError, `duplicate app id "a" (also $.apps[0])`},
		want{"$.apps[1].hosts[0]", SeverityError, `"a.example.com:443" overlaps $.apps[0].hosts[0]`},
		want{"$.apps[1].hosts[1]", SeverityError, `invalid host "b_x.example.com"`},
		want{"$.apps[1].hosts[2]", SeverityError, "wildcard"},
		want{"$.apps[1].providers[0]", SeverityError, `unknown provider "ghost"`},
		want{"$.apps[1].allow.emails[0]", SeverityError, `"alice" is not an email address`},
		want{"$.apps[1].allow.email_domains[0]", SeverityError, "should look like example.com"},
		want{"$.apps[1].default_url", SeverityError, "absolute https URL"},
		want{"$.apps[2].allow", SeverityWarning, "nobody is allowed"},
		want{"$.apps[2].hosts", SeverityError, "at least one host"},
		want{"$.apps[2].providers", SeverityError, "list the identity providers"},
	)
}

func TestCheckPositions(t *testing.T) {
	doc := "{\n  \"public_url\": \"https://auth.example.com\",\n  \"providers\": [\n    {\"id\": \"corp\", \"type\": \"oidc\", \"issuer\": \"https://i.example.com\",\n     \"client_id\": \"c\"}\n  ],\n  \"apps\": [{\"id\": \"a\", \"hosts\": [\"x y\"], \"providers\": [\"corp\"], \"allow\": {\"any_user\": true}}]\n}"
	ps := checkDoc(t, doc)
	expect(t, ps,
		want{"$.providers[0]", SeverityError, "a client secret is required"},
		want{"$.apps[0].hosts[0]", SeverityError, "invalid host"},
	)
	// A missing field is located at the object it belongs in.
	if ps[0].Line != 4 || ps[0].Column != 5 {
		t.Errorf("provider at %d:%d, want 4:5", ps[0].Line, ps[0].Column)
	}
	if ps[1].Line != 7 || ps[1].Column != 34 {
		t.Errorf("host at %d:%d, want 7:34", ps[1].Line, ps[1].Column)
	}
}

func TestCheckSchema(t *testing.T) {
	cases := []struct {
		name string
		doc  string
		want []want
	}{
		{"syntax", "{\n  \"public_url\": \"x\",,\n}", []want{{"$", SeverityError, "invalid JSON"}}},
		{"truncated", `{"public_url": "x"`, []want{{"$", SeverityError, "unexpected end of file"}}},
		{"empty", ``, []want{{"$", SeverityError, "unexpected end of file"}}},
		{"trailing data", goodDoc + ` {}`, []want{{"$", SeverityError, "trailing data"}}},
		{"not an object", `[1]`, []want{
			{"$", SeverityError, "must be an object, not an array"},
			{"$.public_url", SeverityError, "absolute https URL"},
			{"$.providers", SeverityError, "need 1 to 64 providers"},
			{"$.apps", SeverityError, "need 1 to 1024 apps"},
		}},
		{"duplicate key", strings.Replace(goodDoc, `"client_id": "c"`, `"client_id": "c", "client_id": "d"`, 1),
			[]want{{"$.providers[0].client_id", SeverityError, `duplicate field "client_id"`}}},
		{"wrong types", strings.Replace(goodDoc, `"allow": {"groups": ["eng"]}`,
			`"allow": {"groups": "eng", "any_user": "yes", "emails": [1, "a@b.c"]}`, 1), []want{
			{"$.apps[0].allow.groups", SeverityError, "must be an array, not a string"},
			{"$.apps[0].allow.any_user", SeverityError, "must be true or false, not a string"},
			{"$.apps[0].allow.emails[0]", SeverityError, "must be a string, not a number"},
		}},
		{"object for string", strings.Replace(goodDoc, `"client_id": "c"`, `"client_id": {"a": [1, {"b": 2}]}`, 1), []want{
			{"$.providers[0]", SeverityError, "client_id is required"},
			{"$.providers[0].client_id", SeverityError, "must be a string, not an object"},
		}},
		{"unknown nested with odd key", strings.Replace(goodDoc, `"allow": {`, `"allow": {"a b": {"x": [1]}, `, 1),
			[]want{{`$.apps[0].allow["a b"]`, SeverityError, "unknown field"}}},
		{"null is unset", strings.Replace(goodDoc, `"public_url": "https://auth.example.com",`,
			`"public_url": "https://auth.example.com", "clock_skew": null, "session": null,`, 1), nil},
		{"bad duration", strings.Replace(goodDoc, `"public_url"`, `"clock_skew": "soon", "public_url"`, 1),
			[]want{{"$.clock_skew", SeverityError, `invalid duration "soon"`}}},
		{"negative duration", strings.Replace(goodDoc, `"public_url"`, `"clock_skew": "-1s", "public_url"`, 1),
			[]want{{"$.clock_skew", SeverityError, "invalid duration"}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ps := checkDoc(t, c.doc)
			expect(t, ps, c.want...)
			for _, p := range ps {
				if p.Line == 0 {
					t.Errorf("%s has no position", p)
				}
			}
		})
	}
}

func TestCheckDefaultURLMustBeRedirectable(t *testing.T) {
	doc := strings.Replace(goodDoc, `"allow"`, `"default_url": "https://elsewhere.example.com/", "allow"`, 1)
	expect(t, checkDoc(t, doc), want{"$.apps[0].default_url", SeverityError, "not on an app host or a redirect_hosts entry"})
	doc = strings.Replace(doc, `"public_url"`, `"redirect_hosts": ["*.example.com"], "public_url"`, 1)
	expect(t, checkDoc(t, doc))
}

func TestCheckClientAuth(t *testing.T) {
	none := strings.Replace(goodDoc, `"client_id": "c"`, `"client_id": "c", "client_auth": "none"`, 1)
	expect(t, checkDoc(t, none), want{"$.providers[0].client_auth", SeverityWarning, "never sent"})
	public := strings.Replace(none, `, "client_secret_env": "SECRET"`, ``, 1)
	expect(t, checkDoc(t, public))
	bad := strings.Replace(goodDoc, `"client_id": "c"`, `"client_id": "c", "client_auth": "private_key_jwt"`, 1)
	expect(t, checkDoc(t, bad), want{"$.providers[0].client_auth", SeverityError, "is not one of"})
}

func TestParseErrorListsEveryError(t *testing.T) {
	doc := strings.Replace(goodDoc, `"https://auth.example.com"`, `"http://x"`, 1)
	doc = strings.Replace(doc, `"app.example.com"`, `"a b"`, 1)
	_, err := Parse([]byte(doc), getenvSecret)
	var ps Problems
	if !errors.As(err, &ps) || len(ps) != 2 {
		t.Fatalf("%v", err)
	}
	if want := "config: $.public_url: must be an absolute https URL"; !strings.HasPrefix(err.Error(), want) ||
		!strings.Contains(err.Error(), "; $.apps[0].hosts[0]: invalid host") {
		t.Fatalf("%v", err)
	}
	// Warnings alone never fail a load.
	doc = strings.Replace(goodDoc, `"allow": {"groups": ["eng"]}`, `"allow": {}`, 1)
	if _, err := Parse([]byte(doc), getenvSecret); err != nil {
		t.Fatal(err)
	}
	if Check([]byte(doc), getenvSecret).Problems.Count(SeverityWarning) != 1 {
		t.Fatal("warning not reported")
	}
}

// TestCheckNeverPanics mutates a valid document byte by byte, the way a
// typo would: Check must report something located, never crash, and
// agree with Parse.
func TestCheckNeverPanics(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	alphabet := []byte(`{}[]",:0123456789 abcdefghijklmnopqrstuvwxyz_-.null` + "\n")
	for range 3000 {
		b := []byte(goodDoc)
		for range 1 + rng.IntN(4) {
			i := rng.IntN(len(b))
			switch rng.IntN(3) {
			case 0:
				b[i] = alphabet[rng.IntN(len(alphabet))]
			case 1:
				b = append(b[:i], b[i+1:]...)
			default:
				b = append(b[:i], append([]byte{alphabet[rng.IntN(len(alphabet))]}, b[i:]...)...)
			}
		}
		r := Check(b, getenvSecret)
		_, err := Parse(b, getenvSecret)
		if (r.Problems.Err() == nil) != (err == nil) {
			t.Fatalf("Check and Parse disagree on %s", b)
		}
		valid := json.Valid(b)
		for _, p := range r.Problems {
			if p.Path == "" || p.Path[0] != '$' {
				t.Fatalf("bad path %q for %s", p.Path, b)
			}
			if valid && p.Line == 0 {
				t.Fatalf("%s has no position in %s", p, b)
			}
		}
	}
}

func TestEditDistanceAndPaths(t *testing.T) {
	for _, c := range []struct {
		a, b string
		d    int
	}{{"", "", 0}, {"abc", "", 3}, {"issuer", "isuer", 1}, {"client_id", "clientid", 1}, {"kitten", "sitting", 3}} {
		if got := editDistance(c.a, c.b); got != c.d {
			t.Errorf("editDistance(%q, %q) = %d", c.a, c.b, got)
		}
	}
	for in, out := range map[string]string{"$.a[0].b": "$.a[0]", "$.a[0]": "$.a", "$.a": "$", "$": "", `$["x y"]`: "$"} {
		if got := parentPath(in); got != out {
			t.Errorf("parentPath(%q) = %q", in, got)
		}
	}
	if keyPath("$", "a.b") != `$["a.b"]` || keyPath("$", "ok_1") != "$.ok_1" {
		t.Error("keyPath")
	}
	if SeverityError.String() != "error" || SeverityWarning.String() != "warning" {
		t.Error("severity names")
	}
}

// FuzzCheck: Check never panics, always agrees with Parse, gives every
// problem a JSON path, and locates every problem in a valid JSON document.
func FuzzCheck(f *testing.F) {
	f.Add([]byte(goodDoc))
	f.Add([]byte(`{"providers": [{"id": "x", "type": "saml"}], "apps": [{"hosts": ["a:443", "A"]}]}`))
	f.Add([]byte(`[{"a": {"b": [1, 2, {"c": null}]}}]`))
	f.Add([]byte(`{"public_url": "https://x", "public_url": 1, "Apps": {}} {`))
	f.Fuzz(func(t *testing.T, b []byte) {
		r := Check(b, getenvSecret)
		_, err := Parse(b, getenvSecret)
		if (r.Problems.Err() == nil) != (err == nil) {
			t.Fatalf("Check and Parse disagree: %v", err)
		}
		if r.Config == nil && r.Problems.Err() == nil {
			t.Fatal("no config and no error")
		}
		valid := json.Valid(b)
		for _, p := range r.Problems {
			if !strings.HasPrefix(p.Path, "$") {
				t.Fatalf("path %q", p.Path)
			}
			if valid && p.Line == 0 {
				t.Fatalf("%s has no position", p)
			}
		}
	})
}

func TestCheckSAMLMetadataURL(t *testing.T) {
	doc := strings.Replace(goodDoc, `"providers": [`,
		`"providers": [{"id": "p", "type": "saml", "idp_metadata_url": "http://idp.example.com/md", "sp_cert_file": "c.pem"},`, 1)
	doc = strings.Replace(doc, `"providers": ["corp"]`, `"providers": ["corp", "p"]`, 1)
	expect(t, checkDoc(t, doc),
		want{"$.providers[0].idp_metadata_url", SeverityError, "absolute https URL"},
		want{"$.providers[0].sp_cert_file", SeverityError, "go together"},
	)
}
