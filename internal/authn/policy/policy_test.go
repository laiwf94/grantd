package policy

import (
	"fmt"
	mrand "math/rand/v2"
	"strings"
	"testing"
)

func TestEvaluate(t *testing.T) {
	rule := Compile(Rule{Providers: []string{"corp", "partner"}, Emails: []string{"Boss@Example.org"},
		EmailDomains: []string{"Example.com"}, Groups: []string{"eng"}})
	cases := []struct {
		name   string
		id     Identity
		ok     bool
		reason string
	}{
		{"group", Identity{Provider: "corp", Subject: "a", Groups: []string{"x", "eng"}}, true, Allowed},
		{"group is case-sensitive", Identity{Provider: "corp", Subject: "a", Groups: []string{"ENG"}}, false, DeniedNoMatch},
		{"email folds case", Identity{Provider: "corp", Subject: "a", Email: "boss@EXAMPLE.org"}, true, Allowed},
		{"domain", Identity{Provider: "partner", Subject: "a", Email: "x@example.com"}, true, Allowed},
		{"subdomain is not the domain", Identity{Provider: "corp", Subject: "a", Email: "x@sub.example.com"}, false, DeniedNoMatch},
		{"domain needs the @", Identity{Provider: "corp", Subject: "a", Email: "example.com"}, false, DeniedNoMatch},
		{"wrong provider", Identity{Provider: "other", Subject: "a", Groups: []string{"eng"}}, false, DeniedProvider},
		{"no subject", Identity{Provider: "corp", Groups: []string{"eng"}}, false, DeniedNoSubject},
		{"nothing matches", Identity{Provider: "corp", Subject: "a", Email: "a@b.c"}, false, DeniedNoMatch},
	}
	for _, c := range cases {
		ok, reason := rule.Evaluate(c.id)
		if ok != c.ok || reason != c.reason {
			t.Errorf("%s: got %v %s, want %v %s", c.name, ok, reason, c.ok, c.reason)
		}
	}
	if ok, _ := Compile(Rule{Providers: []string{"corp"}}).Evaluate(Identity{Provider: "corp", Subject: "a", Email: "a@b.c", Groups: []string{"g"}}); ok {
		t.Error("an empty rule must allow nobody")
	}
	if ok, _ := Compile(Rule{Providers: []string{"corp"}, AnyUser: true}).Evaluate(Identity{Provider: "corp", Subject: "a"}); !ok {
		t.Error("any_user")
	}
	if ok, _ := Compile(Rule{AnyUser: true}).Evaluate(Identity{Provider: "corp", Subject: "a"}); ok {
		t.Error("any_user still needs an accepted provider")
	}
}

// reference is a deliberately naive restatement of the policy: build the
// full list of reasons a user might be allowed, then look for one.
func reference(r Rule, id Identity) bool {
	if id.Subject == "" {
		return false
	}
	providerOK := false
	for _, p := range r.Providers {
		if p == id.Provider {
			providerOK = true
		}
	}
	if !providerOK {
		return false
	}
	var grants []bool
	grants = append(grants, r.AnyUser)
	for _, e := range r.Emails {
		grants = append(grants, id.Email != "" && strings.EqualFold(e, id.Email))
	}
	parts := strings.Split(id.Email, "@")
	for _, d := range r.EmailDomains {
		grants = append(grants, len(parts) >= 2 && parts[0] != "" && strings.EqualFold(parts[len(parts)-1], d))
	}
	for _, g := range r.Groups {
		for _, have := range id.Groups {
			grants = append(grants, g == have)
		}
	}
	for _, g := range grants {
		if g {
			return true
		}
	}
	return false
}

// TestPropertyMatchesReference compares the compiled evaluator with the
// reference on random rules and identities drawn from small alphabets, so
// matches and near misses (case, provider, domain) are frequent.
func TestPropertyMatchesReference(t *testing.T) {
	r := mrand.New(mrand.NewPCG(7, 8))
	pick := func(list []string, n int) []string {
		var out []string
		for i := 0; i < n; i++ {
			out = append(out, list[r.IntN(len(list))])
		}
		return out
	}
	providers := []string{"corp", "partner", "other"}
	users := []string{"alice", "Alice", "bob", ""}
	domains := []string{"example.org", "EXAMPLE.org", "sub.example.org", "partner.example"}
	groups := []string{"eng", "Eng", "sales", "admins", ""}
	for i := 0; i < 50000; i++ {
		rule := Rule{Providers: pick(providers, r.IntN(3)), AnyUser: r.IntN(10) == 0,
			Groups: pick(groups, r.IntN(3)), EmailDomains: pick(domains, r.IntN(2))}
		for _, e := range pick(users, r.IntN(2)) {
			rule.Emails = append(rule.Emails, e+"@"+domains[r.IntN(len(domains))])
		}
		email := ""
		if u := users[r.IntN(len(users))]; r.IntN(4) != 0 {
			email = u + "@" + domains[r.IntN(len(domains))]
		}
		id := Identity{Provider: providers[r.IntN(len(providers))], Subject: users[r.IntN(len(users))],
			Email: email, Groups: pick(groups, r.IntN(4))}
		got, _ := Compile(rule).Evaluate(id)
		if want := reference(rule, id); got != want {
			t.Fatalf("rule %+v identity %+v: got %v, reference %v", rule, id, got, want)
		}
	}
}

func BenchmarkEvaluate(b *testing.B) {
	var groups []string
	for i := 0; i < 200; i++ {
		groups = append(groups, fmt.Sprintf("group-%d", i))
	}
	rule := Compile(Rule{Providers: []string{"corp"}, Groups: groups[150:], EmailDomains: []string{"example.com"}})
	id := Identity{Provider: "corp", Subject: "alice", Email: "alice@example.org", Groups: groups[:151]}
	for b.Loop() {
		if ok, _ := rule.Evaluate(id); !ok {
			b.Fatal("denied")
		}
	}
}
