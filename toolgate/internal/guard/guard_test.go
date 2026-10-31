package guard

import (
	"strings"
	"testing"

	"github.com/laiwf94/toolgate/internal/jsonrpc"
)

func decode(t *testing.T, s string) map[string]any {
	t.Helper()
	v, err := jsonrpc.DecodeValue([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return v.(map[string]any)
}

func encode(t *testing.T, v any) string {
	t.Helper()
	b, err := jsonrpc.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestBuiltinsMatch(t *testing.T) {
	samples := map[string]string{
		"aws_access_key_id": "key=AKIAIOSFODNN7EXAMPLE end",
		"github_token":      "ghp_" + strings.Repeat("a", 36),
		"slack_token":       "xoxb-1234567890-abcdef",
		"stripe_key":        "sk_live_" + strings.Repeat("Z", 24),
		"sk_prefixed_key":   "sk-" + strings.Repeat("q", 40),
		"private_key":       "-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----",
		"bearer_token":      "Authorization: Bearer abcdefghijklmnopqrstuvwxyz",
		"jwt":               "eyJhbGciOi.eyJzdWIiOi.c2lnbmF0dXJl",
	}
	if len(samples) != len(BuiltinNames()) {
		t.Fatalf("every built-in needs a sample: %v", BuiltinNames())
	}
	for name, s := range samples {
		g, err := New([]string{name}, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		res := map[string]any{"content": []any{map[string]any{"type": "text", "text": s}}}
		rep := g.Apply(res)
		if rep.Redactions != 1 || !strings.Contains(encode(t, res), Placeholder) {
			t.Errorf("%s: not redacted: %v %s", name, rep, encode(t, res))
		}
	}
	// Ordinary prose must survive every pattern.
	g, _ := New(BuiltinNames(), nil, 0)
	prose := "The bearer of this letter asked for a skeleton key; AKIA is a prefix. eyJ alone is fine."
	res := map[string]any{"content": []any{map[string]any{"type": "text", "text": prose}}}
	if rep := g.Apply(res); rep.Redactions != 0 {
		t.Fatalf("prose redacted: %s", encode(t, res))
	}
}

func TestApplyRedactsEverywhereButBinary(t *testing.T) {
	g, err := New([]string{"aws_access_key_id"}, []string{`secret-[0-9]+`}, 0)
	if err != nil {
		t.Fatal(err)
	}
	res := decode(t, `{
	  "content":[{"type":"text","text":"a AKIAIOSFODNN7EXAMPLE b secret-42"},
	             {"type":"image","data":"AKIAIOSFODNN7EXAMPLE","mimeType":"image/png"},
	             {"type":"resource","resource":{"uri":"file:///x","text":"secret-7","blob":"secret-8"}}],
	  "structuredContent":{"k":["secret-1",{"n":"AKIAIOSFODNN7EXAMPLE"}],"num":5,"data":"secret-9","AKIAIOSFODNN7EXAMPLE":1},
	  "isError":false}`)
	rep := g.Apply(res)
	got := encode(t, res)
	want := `{"content":[{"text":"a [REDACTED] b [REDACTED]","type":"text"},{"data":"AKIAIOSFODNN7EXAMPLE","mimeType":"image/png","type":"image"},{"resource":{"blob":"secret-8","text":"[REDACTED]","uri":"file:///x"},"type":"resource"}],"isError":false,"structuredContent":{"[REDACTED]":1,"data":"[REDACTED]","k":["[REDACTED]",{"n":"[REDACTED]"}],"num":5}}`
	if got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
	if rep.Redactions != 7 || rep.Truncated || rep.BytesAfter >= rep.BytesBefore {
		t.Fatalf("report %+v", rep)
	}
}

func TestRedactText(t *testing.T) {
	g, _ := New(nil, []string{`ssn-[0-9]+`}, 0)
	if got := g.RedactText("ssn-123 and AKIAIOSFODNN7EXAMPLE"); got != "[REDACTED] and [REDACTED]" {
		t.Fatal(got)
	}
	var none *Guard
	if got := none.RedactText("ssn-123 AKIAIOSFODNN7EXAMPLE"); got != "ssn-123 [REDACTED]" {
		t.Fatal(got)
	}
}

func TestTruncate(t *testing.T) {
	g, err := New(nil, nil, 10)
	if err != nil {
		t.Fatal(err)
	}
	res := decode(t, `{"content":[{"type":"text","text":"abc"},{"type":"text","text":"défghijklmnop"},{"type":"text","text":"gone"},{"type":"image","data":"QUJD","mimeType":"image/png"}],"structuredContent":{"a":1}}`)
	rep := g.Apply(res)
	got := encode(t, res)
	want := `{"content":[{"text":"abc","type":"text"},{"text":"défghi…[truncated by toolgate]","type":"text"},{"text":"[2 more content item(s) omitted by toolgate: output size limit]","type":"text"}]}`
	if got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
	if !rep.Truncated {
		t.Fatal("not marked truncated")
	}
	// A rune split by the budget is dropped, not cut in half.
	g2, _ := New(nil, nil, 4)
	res = decode(t, `{"content":[{"type":"text","text":"abcé and more text"}]}`)
	g2.Apply(res)
	if got := encode(t, res); got != `{"content":[{"text":"abc…[truncated by toolgate]","type":"text"}]}` {
		t.Fatalf("rune boundary: %s", got)
	}
	// Small enough results are untouched.
	res = decode(t, `{"content":[{"type":"text","text":"ok"}],"structuredContent":{"a":1}}`)
	if rep := g.Apply(res); rep.Truncated || res["structuredContent"] == nil {
		t.Fatal("small result changed")
	}
	// Non-text items that fit are kept.
	g3, _ := New(nil, nil, 60)
	res = decode(t, `{"content":[{"type":"image","data":"QUJD","mimeType":"image/png"},{"type":"text","text":"`+strings.Repeat("x", 100)+`"}]}`)
	g3.Apply(res)
	if items := res["content"].([]any); items[0].(map[string]any)["type"] != "image" {
		t.Fatalf("image dropped: %s", encode(t, res))
	}
	// A non-text item that does not fit ends the content.
	g4, _ := New(nil, nil, 5)
	res = decode(t, `{"content":[{"type":"text","text":"abc"},{"type":"image","data":"QUJDREVGR0g=","mimeType":"image/png"}]}`)
	g4.Apply(res)
	if got := encode(t, res); got != `{"content":[{"text":"abc","type":"text"},{"text":"[1 more content item(s) omitted by toolgate: output size limit]","type":"text"}]}` {
		t.Fatalf("oversized image: %s", got)
	}
}

func TestNilGuardAndErrors(t *testing.T) {
	var g *Guard
	res := map[string]any{"content": []any{}}
	if rep := g.Apply(res); rep.Redactions != 0 || rep.BytesBefore != rep.BytesAfter {
		t.Fatal("nil guard changed something")
	}
	bad := []struct {
		names, custom []string
		max           int
		want          string
	}{
		{[]string{"nope"}, nil, 0, "unknown redaction pattern"},
		{nil, []string{"("}, 0, "redaction pattern"},
		{nil, []string{""}, 0, "1 to"},
		{nil, []string{"a*"}, 0, "empty string"},
		{nil, nil, -1, "max_bytes"},
		{nil, nil, MaxOutputBytes + 1, "max_bytes"},
		{nil, make([]string, MaxPatterns+1), 0, "at most"},
	}
	for _, c := range bad {
		if _, err := New(c.names, c.custom, c.max); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%v %v %d: got %v want %q", c.names, c.custom, c.max, err, c.want)
		}
	}
	if encodedSize(func() {}) != 0 {
		t.Fatal("unencodable size")
	}
}

func TestPreview(t *testing.T) {
	args, _ := jsonrpc.DecodeValue([]byte(`{"path":"/sandbox/a","password":"hunter2","nested":{"api_key":"x","note":"use AKIAIOSFODNN7EXAMPLE"},"list":[1,true,null,"Bearer abcdefghijklmnopqrstuvwxyz"]}`))
	got := Preview(args, 1000)
	want := `{"list":[1,true,null,"[REDACTED]"],"nested":{"api_key":"[REDACTED]","note":"use [REDACTED]"},"password":"[REDACTED]","path":"/sandbox/a"}`
	if got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
	if got := Preview(map[string]any{"t": "héllo wörld"}, 8); got != `{"t":"hé…` {
		t.Fatalf("cut: %q", got)
	}
	if got := Preview(map[string]any{"f": 1.5}, 100); got != `{"f":"float64"}` {
		t.Fatalf("unexpected type: %s", got)
	}
	if got := Preview(func() {}, 10); got != `"func()"` {
		t.Fatalf("func: %s", got)
	}
}
