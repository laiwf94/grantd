package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

const testSchema = `
definition user {}
definition group { relation member: user | group#member }
definition doc {
  relation owner: user
  relation viewer: user | user:* | group#member
  permission view = viewer + owner
}`

func mustRel(t testing.TB, s string) Relationship {
	t.Helper()
	r, err := ParseRelationship(s)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func newStore(t testing.TB, dir string) *Store {
	t.Helper()
	s, err := Open(Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func withSchema(t testing.TB, s *Store) {
	t.Helper()
	if _, err := s.WriteSchema(testSchema); err != nil {
		t.Fatal(err)
	}
}

func write(t testing.TB, s *Store, op Op, rels ...string) Revision {
	t.Helper()
	ups := make([]Update, len(rels))
	for i, r := range rels {
		ups[i] = Update{Op: op, Relationship: mustRel(t, r)}
	}
	rev, err := s.Write(ups, nil)
	if err != nil {
		t.Fatal(err)
	}
	return rev
}

func direct(t testing.TB, s *Store, rev Revision, typ, id, rel string) []string {
	t.Helper()
	rels, err := s.ReadDirect(rev, typ, id, rel)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]string, len(rels))
	for i, r := range rels {
		out[i] = r.Subject().String()
	}
	return out
}

func TestSnapshotsAreImmutable(t *testing.T) {
	s := newStore(t, "")
	withSchema(t, s)
	r1 := write(t, s, OpTouch, "doc:a#viewer@user:alice")
	r2 := write(t, s, OpTouch, "doc:a#viewer@user:bob")
	r3 := write(t, s, OpDelete, "doc:a#viewer@user:alice")
	if got := strings.Join(direct(t, s, r1, "doc", "a", "viewer"), ","); got != "user:alice" {
		t.Fatalf("at r1: %s", got)
	}
	if got := strings.Join(direct(t, s, r2, "doc", "a", "viewer"), ","); got != "user:alice,user:bob" {
		t.Fatalf("at r2: %s", got)
	}
	if got := strings.Join(direct(t, s, r3, "doc", "a", "viewer"), ","); got != "user:bob" {
		t.Fatalf("at r3: %s", got)
	}
	r4 := write(t, s, OpTouch, "doc:a#viewer@user:alice")
	if got := strings.Join(direct(t, s, r4, "doc", "a", "viewer"), ","); got != "user:alice,user:bob" {
		t.Fatalf("re-created at r4: %s", got)
	}
	if got := strings.Join(direct(t, s, r3, "doc", "a", "viewer"), ","); got != "user:bob" {
		t.Fatalf("r3 changed after a later write: %s", got)
	}
	if _, err := s.ReadDirect(r4+1, "doc", "a", "viewer"); !errors.Is(err, ErrFutureRevision) {
		t.Fatalf("future read: %v", err)
	}
}

func TestWriteSemantics(t *testing.T) {
	s := newStore(t, "")
	if _, err := s.Write([]Update{{Op: OpTouch, Relationship: mustRel(t, "doc:a#viewer@user:x")}}, nil); !errors.Is(err, ErrNoSchema) {
		t.Fatalf("write before schema: %v", err)
	}
	withSchema(t, s)
	head := write(t, s, OpCreate, "doc:a#viewer@user:x")
	if _, err := s.Write([]Update{{Op: OpCreate, Relationship: mustRel(t, "doc:a#viewer@user:x")}}, nil); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate create: %v", err)
	}
	if rev := write(t, s, OpTouch, "doc:a#viewer@user:x"); rev != head {
		t.Fatalf("no-op touch advanced the revision to %d", rev)
	}
	if rev := write(t, s, OpDelete, "doc:a#viewer@user:nobody"); rev != head {
		t.Fatal("no-op delete advanced the revision")
	}
	// A failed write changes nothing, even if earlier updates in it were fine.
	_, err := s.Write([]Update{
		{Op: OpTouch, Relationship: mustRel(t, "doc:b#viewer@user:y")},
		{Op: OpCreate, Relationship: mustRel(t, "doc:a#viewer@user:x")},
	}, nil)
	if !errors.Is(err, ErrConflict) || s.Head() != head || len(direct(t, s, head, "doc", "b", "viewer")) != 0 {
		t.Fatalf("partial write leaked: err=%v head=%d", err, s.Head())
	}
}

func TestWriteValidation(t *testing.T) {
	s := newStore(t, "")
	withSchema(t, s)
	cases := []struct {
		rel, want string
	}{
		{"nope:a#viewer@user:x", `type "nope" is not defined`},
		{"doc:a#nope@user:x", `has no relation "nope"`},
		{"doc:a#view@user:x", "is a permission"},
		{"doc:a#owner@group:g#member", "does not allow group#member"},
		{"doc:a#owner@user:*", "does not allow user:*"},
		{"doc:a#viewer@group:g", "does not allow group"},
	}
	for _, c := range cases {
		_, err := s.Write([]Update{{Op: OpTouch, Relationship: mustRel(t, c.rel)}}, nil)
		if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want %q", c.rel, err, c.want)
		}
	}
	bad := []struct {
		ups  []Update
		want string
	}{
		{nil, "at least one update"},
		{make([]Update, MaxUpdatesPerWrite+1), "at most"},
		{[]Update{{Op: "upsert", Relationship: mustRel(t, "doc:a#viewer@user:x")}}, "op must be"},
		{[]Update{{Op: OpTouch, Relationship: Relationship{ResourceType: "doc"}}}, "resource id"},
		{[]Update{{Op: OpTouch, Relationship: mustRel(t, "doc:a#viewer@user:x")}, {Op: OpDelete, Relationship: mustRel(t, "doc:a#viewer@user:x")}}, "more than once"},
	}
	for _, c := range bad {
		if _, err := s.Write(c.ups, nil); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("err = %v, want %q", err, c.want)
		}
	}
	ups := []Update{{Op: OpTouch, Relationship: mustRel(t, "doc:a#viewer@user:x")}}
	if _, err := s.Write(ups, make([]Precondition, MaxPreconditions+1)); err == nil {
		t.Error("too many preconditions accepted")
	}
	if _, err := s.Write(ups, []Precondition{{Filter: Filter{}}}); err == nil {
		t.Error("invalid precondition filter accepted")
	}
	// Deleting is allowed even if the schema would no longer accept the relationship.
	if _, err := s.Write([]Update{{Op: OpDelete, Relationship: mustRel(t, "doc:a#owner@user:*")}}, nil); err != nil {
		t.Errorf("delete was validated against the schema: %v", err)
	}
}

func TestPreconditions(t *testing.T) {
	s := newStore(t, "")
	withSchema(t, s)
	write(t, s, OpTouch, "doc:a#owner@user:alice")
	ups := []Update{{Op: OpTouch, Relationship: mustRel(t, "doc:a#viewer@user:bob")}}
	owner := Filter{ResourceType: "doc", ResourceID: "a", Relation: "owner", SubjectType: "user", SubjectID: "alice"}
	if _, err := s.Write(ups, []Precondition{{MustExist: true, Filter: owner}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Write(ups, []Precondition{{MustExist: false, Filter: owner}}); !errors.Is(err, ErrPrecondition) {
		t.Fatalf("must-not-exist on an existing relationship: %v", err)
	}
	other := Filter{ResourceType: "doc", ResourceID: "zzz"}
	if _, err := s.Write(ups, []Precondition{{MustExist: true, Filter: other}}); !errors.Is(err, ErrPrecondition) {
		t.Fatalf("must-exist on nothing: %v", err)
	}
}

func TestSchemaChangeGuardsData(t *testing.T) {
	s := newStore(t, "")
	withSchema(t, s)
	write(t, s, OpTouch, "doc:a#viewer@user:*")
	narrower := strings.Replace(testSchema, "user | user:* | group#member", "user | group#member", 1)
	if _, err := s.WriteSchema(narrower); !errors.Is(err, ErrPrecondition) || !strings.Contains(err.Error(), "doc:a#viewer@user:*") {
		t.Fatalf("schema change orphaning data: %v", err)
	}
	if _, err := s.WriteSchema("definition broken {"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bad schema: %v", err)
	}
	write(t, s, OpDelete, "doc:a#viewer@user:*")
	if _, err := s.WriteSchema(narrower); err != nil {
		t.Fatal(err)
	}
	if sc, src := s.Schema(); sc == nil || !strings.Contains(src, "relation viewer: user | group#member") {
		t.Fatalf("schema not stored: %s", src)
	}
}

func TestReadFiltersAndPages(t *testing.T) {
	s := newStore(t, "")
	withSchema(t, s)
	for i := 0; i < 25; i++ {
		write(t, s, OpTouch, fmt.Sprintf("doc:d%02d#viewer@user:u%d", i, i%3))
	}
	write(t, s, OpTouch, "doc:d00#viewer@group:g#member", "doc:d00#owner@user:o", "doc:d01#viewer@user:*")
	head := s.Head()
	var all []string
	cursor := ""
	for page := 0; ; page++ {
		rels, next, err := s.Read(head, Filter{ResourceType: "doc", Relation: "viewer"}, cursor, 10)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range rels {
			all = append(all, r.String())
		}
		if next == "" {
			break
		}
		if page > 5 {
			t.Fatal("pagination does not terminate")
		}
		cursor = next
	}
	if len(all) != 27 {
		t.Fatalf("read %d viewer relationships, want 27: %v", len(all), all)
	}
	for i := 1; i < len(all); i++ {
		if all[i-1] >= all[i] {
			t.Fatalf("not strictly ordered at %d: %s, %s", i, all[i-1], all[i])
		}
	}
	count := func(f Filter) int {
		rels, _, err := s.Read(head, f, "", MaxReadLimit)
		if err != nil {
			t.Fatal(err)
		}
		return len(rels)
	}
	checks := map[string]struct {
		f    Filter
		want int
	}{
		"by subject":        {Filter{ResourceType: "doc", SubjectType: "user", SubjectID: "u1"}, 8},
		"exact object":      {Filter{ResourceType: "doc", ResourceID: "d00", Relation: "viewer"}, 2},
		"userset only":      {Filter{ResourceType: "doc", SubjectType: "group", SubjectRelation: "member"}, 1},
		"plain users only":  {Filter{ResourceType: "doc", ResourceID: "d00", SubjectType: "group", SubjectRelation: NoRelation}, 0},
		"wildcard":          {Filter{ResourceType: "doc", SubjectType: "user", SubjectID: "*"}, 1},
		"one object":        {Filter{ResourceType: "doc", ResourceID: "d00"}, 3},
		"unknown type":      {Filter{ResourceType: "nothing"}, 0},
		"relation anywhere": {Filter{ResourceType: "doc", Relation: "owner"}, 1},
	}
	for name, c := range checks {
		if got := count(c.f); got != c.want {
			t.Errorf("%s: %d, want %d", name, got, c.want)
		}
	}
	if rels, next, _ := s.Read(head, Filter{ResourceType: "doc"}, "", 0); len(rels) != 28 || next != "" {
		t.Errorf("limit 0 should use the default page size: got %d, next %q", len(rels), next)
	}
	if rels, _, _ := s.Read(head, Filter{ResourceType: "doc"}, "", MaxReadLimit+50); len(rels) != 28 {
		t.Errorf("oversized limit: got %d", len(rels))
	}
	for _, f := range []Filter{{}, {ResourceType: "doc", ResourceID: "*"}, {ResourceType: "doc", SubjectID: "x"},
		{ResourceType: "doc", Relation: "X"}, {ResourceType: "doc", SubjectType: "U"}, {ResourceType: "doc", SubjectType: "u", SubjectID: "a b"},
		{ResourceType: "doc", SubjectRelation: "B"}} {
		if _, _, err := s.Read(head, f, "", 1); !errors.Is(err, ErrInvalid) {
			t.Errorf("filter %+v accepted", f)
		}
	}
}

func TestObjectIDs(t *testing.T) {
	s := newStore(t, "")
	withSchema(t, s)
	r1 := write(t, s, OpTouch, "doc:b#viewer@user:x", "doc:a#owner@user:x", "doc:a#viewer@user:y")
	r2 := write(t, s, OpDelete, "doc:b#viewer@user:x")
	ids, err := s.ObjectIDs(r1, "doc")
	if err != nil || strings.Join(ids, ",") != "a,b" {
		t.Fatalf("at r1: %v %v", ids, err)
	}
	ids, _ = s.ObjectIDs(r2, "doc")
	if strings.Join(ids, ",") != "a" {
		t.Fatalf("at r2: %v", ids)
	}
	if _, err := s.ObjectIDs(r2+5, "doc"); !errors.Is(err, ErrFutureRevision) {
		t.Fatal("future revision accepted")
	}
}

func TestGarbageCollection(t *testing.T) {
	s, err := Open(Options{Retention: 10})
	if err != nil {
		t.Fatal(err)
	}
	withSchema(t, s)
	for i := 0; i < gcEvery+20; i++ {
		write(t, s, OpTouch, "doc:a#viewer@user:x")
		write(t, s, OpDelete, "doc:a#viewer@user:x")
	}
	min := s.MinRevision()
	if min == 0 {
		t.Fatal("GC never ran")
	}
	if _, err := s.ReadDirect(min-1, "doc", "a", "viewer"); !errors.Is(err, ErrSnapshotExpired) {
		t.Fatalf("expired read: %v", err)
	}
	if _, err := s.Changes(min-1, 0); !errors.Is(err, ErrSnapshotExpired) {
		t.Fatalf("expired changes: %v", err)
	}
	if _, err := s.Changes(s.Head()+1, 0); !errors.Is(err, ErrFutureRevision) {
		t.Fatalf("future changes: %v", err)
	}
	s.mu.RLock()
	versions := len(s.byType["doc"]["a#viewer"]["user:x"].versions)
	s.mu.RUnlock()
	// GC runs every gcEvery revisions, so at most retention+gcEvery revisions of history remain.
	if versions > (10+gcEvery)/2+1 {
		t.Fatalf("GC kept %d versions", versions)
	}
	// Everything inside the window is still readable and correct.
	for rev := min; rev <= s.Head(); rev++ {
		got := direct(t, s, rev, "doc", "a", "viewer")
		alive := rev%2 == 0 // schema is rev 1, then touch on even, delete on odd
		if alive != (len(got) == 1) {
			t.Fatalf("rev %d: %v", rev, got)
		}
	}
	// Fully deleted objects disappear from the index.
	write(t, s, OpTouch, "doc:gone#viewer@user:x")
	write(t, s, OpDelete, "doc:gone#viewer@user:x")
	for i := 0; i < 2*gcEvery; i++ {
		write(t, s, OpTouch, "doc:a#viewer@user:x")
		write(t, s, OpDelete, "doc:a#viewer@user:x")
	}
	s.mu.RLock()
	_, still := s.byType["doc"]["gone#viewer"]
	s.mu.RUnlock()
	if still {
		t.Fatal("GC kept a fully deleted object")
	}
}

func TestChangesAndWatch(t *testing.T) {
	s := newStore(t, "")
	withSchema(t, s)
	start := s.Head()
	r1 := write(t, s, OpTouch, "doc:a#viewer@user:x", "doc:a#viewer@user:y")
	write(t, s, OpDelete, "doc:a#viewer@user:x")
	ch, err := s.Changes(start, 0)
	if err != nil || len(ch) != 3 || ch[2].Op != OpDelete {
		t.Fatalf("changes: %+v %v", ch, err)
	}
	// A page never splits a revision.
	ch, _ = s.Changes(start, 1)
	if len(ch) != 2 || ch[0].Revision != r1 || ch[1].Revision != r1 {
		t.Fatalf("page split a revision: %+v", ch)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := s.WaitForRevision(ctx, s.Head()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("wait without a write: %v", err)
	}
	done := make(chan error, 1)
	head := s.Head()
	go func() { done <- s.WaitForRevision(context.Background(), head) }()
	time.Sleep(5 * time.Millisecond)
	write(t, s, OpTouch, "doc:b#viewer@user:z")
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("watcher was not woken")
	}
	if err := s.WaitForRevision(context.Background(), head); err != nil {
		t.Fatal("wait on an already newer head blocked or failed")
	}
}

func dump(t testing.TB, s *Store) string {
	if sc, _ := s.Schema(); sc == nil {
		return ""
	}
	rels, _, err := s.Read(s.Head(), Filter{ResourceType: "doc"}, "", MaxReadLimit)
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for _, r := range rels {
		b.WriteString(r.String() + ";")
	}
	return b.String()
}
