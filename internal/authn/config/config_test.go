package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func base() map[string]any {
	return map[string]any{
		"public_url": "https://auth.example.com/_wicket/",
		"providers": []any{
			map[string]any{"id": "corp", "type": "oidc", "issuer": "https://idp.example.com", "client_id": "c", "client_secret_env": "SECRET"},
			map[string]any{"id": "partner", "type": "saml", "idp_metadata_file": "/etc/idp.xml"},
		},
		"apps": []any{
			map[string]any{"id": "app", "hosts": []string{"App.example.com"}, "providers": []string{"corp"}, "allow": map[string]any{"groups": []string{"eng"}}},
		},
	}
}

func parse(t *testing.T, m map[string]any) (*Config, error) {
	t.Helper()
	b, _ := json.Marshal(m)
	return Parse(b, func(k string) string {
		if k == "SECRET" {
			return "s3cret"
		}
		return ""
	})
}

func TestDefaults(t *testing.T) {
	c, err := parse(t, base())
	if err != nil {
		t.Fatal(err)
	}
	if c.PublicURL != "https://auth.example.com/_wicket" || c.Public.Host != "auth.example.com" {
		t.Fatalf("public URL %q", c.PublicURL)
	}
	if time.Duration(c.Session.IdleTimeout) != DefaultIdle || time.Duration(c.Session.AbsoluteTimeout) != DefaultAbsolute ||
		time.Duration(c.ClockSkew) != DefaultSkew || time.Duration(c.UpstreamTokenTTL) != DefaultTokenTTL {
		t.Fatal("defaults")
	}
	if c.Providers[0].ClientSecret != "s3cret" || c.Providers[0].DisplayName != "corp" {
		t.Fatal("secret from environment")
	}
	if c.Apps[0].Hosts[0] != "app.example.com" || c.Apps[0].DefaultURL != "https://app.example.com/" {
		t.Fatal("app normalization")
	}
}

func TestInvalid(t *testing.T) {
	set := func(path string, v any) func(m map[string]any) {
		return func(m map[string]any) {
			parts := strings.Split(path, ".")
			var cur any = m
			for i, p := range parts {
				last := i == len(parts)-1
				switch c := cur.(type) {
				case map[string]any:
					if last {
						if v == nil {
							delete(c, p)
						} else {
							c[p] = v
						}
						return
					}
					cur = c[p]
				case []any:
					idx := int(p[0] - '0')
					if last {
						c[idx] = v
						return
					}
					cur = c[idx]
				}
			}
		}
	}
	cases := map[string]func(m map[string]any){
		"http public url":         set("public_url", "http://auth.example.com"),
		"public url query":        set("public_url", "https://auth.example.com/?x=1"),
		"cookie domain unrelated": set("cookie_domain", "other.com"),
		"cookie domain tld":       set("cookie_domain", "com"),
		"cookie domain ip":        set("cookie_domain", "10.0.0.1"),
		"idle over absolute":      set("session", map[string]any{"idle_timeout": "48h", "absolute_timeout": "24h"}),
		"absolute too long":       set("session", map[string]any{"absolute_timeout": "800h"}),
		"idle too short":          set("session", map[string]any{"idle_timeout": "10s"}),
		"bad duration":            set("session", map[string]any{"idle_timeout": "soon"}),
		"duration as number":      set("session", map[string]any{"idle_timeout": 5}),
		"negative duration":       set("clock_skew", "-1s"),
		"huge skew":               set("clock_skew", "1h"),
		"token ttl too long":      set("upstream_token_ttl", "1h"),
		"token ttl too short":     set("upstream_token_ttl", "1s"),
		"unknown field":           set("colour", "blue"),
		"no providers":            set("providers", []any{}),
		"bad provider id":         set("providers.0.id", "Corp!"),
		"duplicate provider":      set("providers.1", map[string]any{"id": "corp", "type": "saml", "idp_metadata_file": "x"}),
		"unknown type":            set("providers.0.type", "ldap"),
		"long display name":       set("providers.0.display_name", strings.Repeat("x", 65)),
		"oidc without issuer":     set("providers.0.issuer", nil),
		"secret env empty":        set("providers.0.client_secret_env", "NOPE"),
		"two secret sources":      set("providers.0.client_secret_file", "/x"),
		"secret file missing": func(m map[string]any) {
			set("providers.0.client_secret_env", nil)(m)
			set("providers.0.client_secret_file", "/nonexistent")(m)
		},
		"oidc with saml field":  set("providers.0.sp_key_file", "/x"),
		"bad post logout url":   set("providers.0.post_logout_redirect_url", "http://x"),
		"saml with oidc field":  set("providers.1.client_id", "x"),
		"saml two metadata":     set("providers.1.idp_metadata_url", "https://x"),
		"saml no metadata":      set("providers.1.idp_metadata_file", nil),
		"saml key without cert": set("providers.1.sp_key_file", "/k"),
		"saml sign without key": set("providers.1.sign_requests", true),
		"no apps":               set("apps", []any{}),
		"bad app id":            set("apps.0.id", "x y"),
		"app without hosts":     set("apps.0.hosts", []string{}),
		"app host with path":    set("apps.0.hosts", []string{"a.com/x"}),
		"app without providers": set("apps.0.providers", []string{}),
		"app unknown provider":  set("apps.0.providers", []string{"ghost"}),
		"bad email domain":      set("apps.0.allow", map[string]any{"email_domains": []string{"@example.com"}}),
		"bad email":             set("apps.0.allow", map[string]any{"emails": []string{"alice"}}),
		"http default url":      set("apps.0.default_url", "http://app.example.com/"),
		"trailing data":         nil,
	}
	for name, f := range cases {
		t.Run(name, func(t *testing.T) {
			m := base()
			if f == nil {
				b, _ := json.Marshal(m)
				if _, err := Parse(append(b, []byte(" {}")...), func(string) string { return "" }); err == nil {
					t.Fatal("trailing data accepted")
				}
				return
			}
			f(m)
			if _, err := parse(t, m); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	m := base()
	m["apps"] = append(m["apps"].([]any), map[string]any{"id": "app", "hosts": []string{"b.example.com"}, "providers": []string{"corp"}})
	if _, err := parse(t, m); err == nil {
		t.Error("duplicate app id")
	}
	m = base()
	m["apps"] = append(m["apps"].([]any), map[string]any{"id": "two", "hosts": []string{"app.example.com"}, "providers": []string{"corp"}})
	if _, err := parse(t, m); err == nil {
		t.Error("host in two apps")
	}
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	m := base()
	secret := filepath.Join(dir, "secret")
	os.WriteFile(secret, []byte("from-file\n"), 0o600)
	p := m["providers"].([]any)[0].(map[string]any)
	delete(p, "client_secret_env")
	p["client_secret_file"] = secret
	m["cookie_domain"] = ".Example.com"
	b, _ := json.Marshal(m)
	path := filepath.Join(dir, "wicket.json")
	os.WriteFile(path, b, 0o600)
	c, err := Load(path, func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	if c.Providers[0].ClientSecret != "from-file" || c.CookieDomain != "example.com" {
		t.Fatalf("%q %q", c.Providers[0].ClientSecret, c.CookieDomain)
	}
	if _, err := Load(filepath.Join(dir, "missing.json"), nil); err == nil {
		t.Fatal("missing file")
	}
	big := filepath.Join(dir, "big.json")
	os.WriteFile(big, make([]byte, MaxFileBytes+1), 0o600)
	if _, err := Load(big, nil); err == nil {
		t.Fatal("oversized file")
	}
	if _, err := Load(dir, nil); err == nil {
		t.Fatal("directory accepted")
	}
}
