package check

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/laiwf94/grantd/internal/store"
)

const model = `
definition user {}

definition group {
  relation member: user | group#member
}

definition folder {
  relation parent: folder
  relation viewer: user | user:* | group#member
  permission view = viewer + parent->view
}

definition doc {
  relation parent: folder
  relation owner: user
  relation editor: user | group#member
  relation viewer: user | group#member
  relation banned: user
  permission edit = owner + editor
  permission view = (viewer + edit + parent->view) - banned
  permission both = edit & parent->view
}
`

type fixture struct {
	t   testing.TB
	st  *store.Store
	eng *Engine
}

func newFixture(t testing.TB, cache *Cache, rels ...string) *fixture {
	t.Helper()
	st, err := store.Open(store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.WriteSchema(model); err != nil {
		t.Fatal(err)
	}
	f := &fixture{t: t, st: st, eng: New(st, cache)}
	f.write(rels...)
	return f
}

func (f *fixture) write(rels ...string) {
	f.t.Helper()
	if len(rels) == 0 {
		return
	}
	ups := make([]store.Update, len(rels))
	for i, r := range rels {
		rel, err := store.ParseRelationship(r)
		if err != nil {
			f.t.Fatal(err)
		}
		ups[i] = store.Update{Op: store.OpTouch, Relationship: rel}
	}
	if _, err := f.st.Write(ups, nil); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) check(resource, perm, subject string) bool {
	f.t.Helper()
	ok, err := f.try(resource, perm, subject)
	if err != nil {
		f.t.Fatalf("check %s#%s@%s: %v", resource, perm, subject, err)
	}
	return ok
}

func (f *fixture) try(resource, perm, subject string) (bool, error) {
	rt, rid, _ := strings.Cut(resource, ":")
	subj, err := store.ParseSubject(subject, false)
	if err != nil {
		return false, err
	}
	sc, _ := f.st.Schema()
	ok, _, err := f.eng.Check(context.Background(), sc, f.st.Head(), Request{ResourceType: rt, ResourceID: rid, Permission: perm, Subject: subj})
	return ok, err
}

func TestDocumentSharing(t *testing.T) {
	f := newFixture(t, nil,
		"group:eng#member@user:alice",
		"group:staff#member@group:eng#member",
		"group:staff#member@user:carol",
		"folder:root#viewer@group:staff#member",
		"folder:specs#parent@folder:root",
		"doc:design#parent@folder:specs",
		"doc:design#owner@user:dave",
		"doc:design#editor@group:eng#member",
		"doc:design#banned@user:carol",
		"folder:public#viewer@user:*",
		"doc:readme#parent@folder:public",
	)
	cases := []struct {
		res, perm, sub string
		want           bool
	}{
		{"doc:design", "view", "user:alice", true},   // editor via eng, and via folder chain
		{"doc:design", "edit", "user:alice", true},   // eng member is an editor
		{"doc:design", "view", "user:carol", false},  // staff can see the folder, but carol is banned
		{"doc:design", "edit", "user:carol", false},  // staff are not editors
		{"doc:design", "view", "user:dave", true},    // owner
		{"doc:design", "view", "user:erin", false},   // stranger
		{"doc:design", "both", "user:alice", true},   // edit AND folder view
		{"doc:design", "both", "user:dave", false},   // owner, but cannot see the folder
		{"doc:readme", "view", "user:anyone", true},  // public folder: user:*
		{"folder:specs", "view", "user:carol", true}, // inherited from root
		{"doc:design", "owner", "user:dave", true},   // a relation can be checked directly
		{"doc:design", "edit", "group:eng#member", true},
		{"doc:design", "view", "group:staff#member", true}, // usersets are subjects too
		{"group:staff", "member", "group:staff#member", true},
		{"doc:nothing", "view", "user:alice", false},
	}
	for _, c := range cases {
		if got := f.check(c.res, c.perm, c.sub); got != c.want {
			t.Errorf("%s#%s@%s = %v, want %v", c.res, c.perm, c.sub, got, c.want)
		}
	}
}

func TestWildcardOnlyMatchesPlainSubjects(t *testing.T) {
	f := newFixture(t, nil, "folder:pub#viewer@user:*")
	if !f.check("folder:pub", "view", "user:x") {
		t.Fatal("wildcard did not match a user")
	}
	if f.check("folder:pub", "view", "group:g#member") {
		t.Fatal("user:* matched a group userset")
	}
}

func TestCyclesTerminate(t *testing.T) {
	f := newFixture(t, nil,
		"group:a#member@group:b#member",
		"group:b#member@group:c#member",
		"group:c#member@group:a#member",
		"group:c#member@user:zed",
		"folder:x#parent@folder:y",
		"folder:y#parent@folder:x",
		"folder:y#viewer@user:yan",
	)
	for _, g := range []string{"a", "b", "c"} {
		if !f.check("group:"+g, "member", "user:zed") {
			t.Errorf("group %s should contain zed through the cycle", g)
		}
		if f.check("group:"+g, "member", "user:nobody") {
			t.Errorf("group %s contains a stranger", g)
		}
	}
	if !f.check("folder:x", "view", "user:yan") || f.check("folder:x", "view", "user:nobody") {
		t.Fatal("folder cycle evaluated wrongly")
	}
}

func TestDepthLimit(t *testing.T) {
	var rels []string
	n := DefaultMaxDepth + 5
	for i := 0; i < n; i++ {
		rels = append(rels, fmt.Sprintf("group:g%d#member@group:g%d#member", i, i+1))
	}
	rels = append(rels, fmt.Sprintf("group:g%d#member@user:deep", n))
	f := newFixture(t, nil, rels...)
	if _, err := f.try("group:g0", "member", "user:deep"); !errors.Is(err, ErrDepthExceeded) {
		t.Fatalf("deep chain: %v", err)
	}
	if !f.check(fmt.Sprintf("group:g%d", n-10), "member", "user:deep") {
		t.Fatal("chain within the limit failed")
	}
}

func TestWorkLimit(t *testing.T) {
	// One group containing many groups: each is a separate dispatch.
	var rels []string
	for i := 0; i < 999; i++ {
		rels = append(rels, fmt.Sprintf("group:top#member@group:g%d#member", i))
	}
	f := newFixture(t, nil, rels...)
	for b := 0; b < 101; b++ {
		var batch []string
		for i := 0; i < 1000; i++ {
			batch = append(batch, fmt.Sprintf("group:g%d#member@group:h%d_%d#member", b, b, i))
		}
		f.write(batch...)
	}
	if _, err := f.try("group:top", "member", "user:x"); !errors.Is(err, ErrTooMuchWork) {
		t.Fatalf("expected the work limit to stop the check, got %v", err)
	}
}

func TestValidation(t *testing.T) {
	f := newFixture(t, nil)
	sc, _ := f.st.Schema()
	cases := []struct {
		q    Request
		want error
	}{
		{Request{"nope", "a", "view", store.Subject{Type: "user", ID: "x"}}, ErrUnknownType},
		{Request{"doc", "a", "nope", store.Subject{Type: "user", ID: "x"}}, ErrUnknownName},
		{Request{"doc", "a b", "view", store.Subject{Type: "user", ID: "x"}}, store.ErrInvalid},
		{Request{"doc", "a", "view", store.Subject{Type: "ghost", ID: "x"}}, ErrUnknownType},
		{Request{"doc", "a", "view", store.Subject{Type: "group", ID: "x", Relation: "nope"}}, ErrUnknownName},
		{Request{"doc", "a", "view", store.Subject{Type: "user", ID: "*"}}, store.ErrInvalid},
	}
	for _, c := range cases {
		if _, _, err := f.eng.Check(context.Background(), sc, f.st.Head(), c.q); !errors.Is(err, c.want) {
			t.Errorf("%+v: err = %v, want %v", c.q, err, c.want)
		}
	}
	if err := (Request{}).Validate(nil); !errors.Is(err, store.ErrNoSchema) {
		t.Errorf("nil schema: %v", err)
	}
}

func TestCanceledContext(t *testing.T) {
	f := newFixture(t, nil, "doc:a#viewer@user:x")
	sc, _ := f.st.Schema()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, err := f.eng.Check(ctx, sc, f.st.Head(), Request{"doc", "a", "view", store.Subject{Type: "user", ID: "x"}})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled check: %v", err)
	}
}

func TestReadsAtSnapshots(t *testing.T) {
	f := newFixture(t, NewCache(1000), "doc:a#viewer@user:x")
	before := f.st.Head()
	rel, _ := store.ParseRelationship("doc:a#banned@user:x")
	if _, err := f.st.Write([]store.Update{{Op: store.OpTouch, Relationship: rel}}, nil); err != nil {
		t.Fatal(err)
	}
	sc, _ := f.st.Schema()
	q := Request{"doc", "a", "view", store.Subject{Type: "user", ID: "x"}}
	old, _, _ := f.eng.Check(context.Background(), sc, before, q)
	now, _, _ := f.eng.Check(context.Background(), sc, f.st.Head(), q)
	if !old || now {
		t.Fatalf("snapshot isolation broken: before=%v now=%v", old, now)
	}
	if _, _, err := f.eng.Check(context.Background(), sc, f.st.Head()+1, q); !errors.Is(err, store.ErrFutureRevision) {
		t.Fatalf("future revision: %v", err)
	}
}

func TestCacheIsUsedAndCorrect(t *testing.T) {
	cache := NewCache(10_000)
	f := newFixture(t, cache, "group:eng#member@user:a", "doc:d#editor@group:eng#member")
	sc, _ := f.st.Schema()
	q := Request{"doc", "d", "view", store.Subject{Type: "user", ID: "a"}}
	ok1, s1, _ := f.eng.Check(context.Background(), sc, f.st.Head(), q)
	ok2, s2, _ := f.eng.Check(context.Background(), sc, f.st.Head(), q)
	if !ok1 || !ok2 || s1.CacheHits != 0 || s2.CacheHits == 0 || s2.Dispatches != 0 {
		t.Fatalf("cache not used: %v %+v %v %+v", ok1, s1, ok2, s2)
	}
	if cache.Len() == 0 {
		t.Fatal("cache is empty")
	}
}

func TestCacheEviction(t *testing.T) {
	c := NewCache(cacheShards) // one entry per shard
	for i := 0; i < 1000; i++ {
		c.Put(fmt.Sprint(i), i%2 == 0)
	}
	if c.Len() > cacheShards {
		t.Fatalf("cache grew to %d", c.Len())
	}
	c.Put("k", true)
	c.Put("k", false)
	if v, ok := c.Get("k"); !ok || v {
		t.Fatal("update in place failed")
	}
	if NewCache(0) != nil {
		t.Fatal("zero capacity should disable the cache")
	}
	if NewCache(3).shards[0].cap != 1 {
		t.Fatal("tiny cache should keep one entry per shard")
	}
}

func TestLookupResources(t *testing.T) {
	var rels []string
	for i := 0; i < 30; i++ {
		rels = append(rels, fmt.Sprintf("doc:d%02d#viewer@user:u%d", i, i%3))
	}
	rels = append(rels, "doc:d05#banned@user:u2")
	f := newFixture(t, nil, rels...)
	sc, _ := f.st.Schema()
	var got []string
	cursor := ""
	for {
		res, err := f.eng.LookupResources(context.Background(), sc, f.st, f.st.Head(), "doc", "view", store.Subject{Type: "user", ID: "u2"}, cursor, 3)
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, res.IDs...)
		if res.Next == "" {
			break
		}
		cursor = res.Next
	}
	want := "d02,d08,d11,d14,d17,d20,d23,d26,d29" // every third, minus banned d05
	if strings.Join(got, ",") != want {
		t.Fatalf("lookup = %v, want %s", got, want)
	}
	if _, err := f.eng.LookupResources(context.Background(), sc, f.st, f.st.Head(), "doc", "nope", store.Subject{Type: "user", ID: "u2"}, "", 0); !errors.Is(err, ErrUnknownName) {
		t.Fatalf("bad permission: %v", err)
	}
	res, _ := f.eng.LookupResources(context.Background(), sc, f.st, f.st.Head(), "doc", "view", store.Subject{Type: "user", ID: "u0"}, "", 10_000)
	if len(res.IDs) != 10 || res.Next != "" {
		t.Fatalf("large limit: %v %q", res.IDs, res.Next)
	}
}

func TestLookupEvaluationCap(t *testing.T) {
	f := newFixture(t, nil)
	for b := 0; b < 11; b++ {
		var batch []string
		for i := 0; i < 1000; i++ {
			batch = append(batch, fmt.Sprintf("doc:b%02d_%04d#viewer@user:x", b, i))
		}
		f.write(batch...)
	}
	sc, _ := f.st.Schema()
	res, err := f.eng.LookupResources(context.Background(), sc, f.st, f.st.Head(), "doc", "view", store.Subject{Type: "user", ID: "nobody"}, "", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.IDs) != 0 || res.Next == "" {
		t.Fatalf("cap did not page: %v %q", res.IDs, res.Next)
	}
	res2, _ := f.eng.LookupResources(context.Background(), sc, f.st, f.st.Head(), "doc", "view", store.Subject{Type: "user", ID: "nobody"}, res.Next, 10)
	if res2.Next != "" {
		t.Fatalf("second page should finish the scan, got cursor %q", res2.Next)
	}
}

// ---- property test against an independent reference evaluator --------------

func TestOldSnapshotAfterSchemaChange(t *testing.T) {
	f := newFixture(t, nil, "group:eng#member@user:a", "doc:d#viewer@group:eng#member")
	old := f.st.Head()
	rel, _ := store.ParseRelationship("doc:d#viewer@group:eng#member")
	if _, err := f.st.Write([]store.Update{{Op: store.OpDelete, Relationship: rel}}, nil); err != nil {
		t.Fatal(err)
	}
	rel2, _ := store.ParseRelationship("group:eng#member@user:a")
	if _, err := f.st.Write([]store.Update{{Op: store.OpDelete, Relationship: rel2}}, nil); err != nil {
		t.Fatal(err)
	}
	// Remove groups from the schema entirely.
	noGroups := strings.Replace(strings.Replace(model, "definition group {\n  relation member: user | group#member\n}", "", 1), " | group#member", "", -1)
	if _, err := f.st.WriteSchema(noGroups); err != nil {
		t.Fatal(err)
	}
	sc, _ := f.st.Schema()
	ok, _, err := f.eng.Check(context.Background(), sc, old, Request{"doc", "d", "view", store.Subject{Type: "user", ID: "a"}})
	if err != nil || ok {
		t.Fatalf("old snapshot with a removed type: ok=%v err=%v", ok, err)
	}
}
