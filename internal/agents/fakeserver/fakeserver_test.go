package fakeserver

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/laiwf94/authz/internal/agents/mcp"
)

func newServer(t *testing.T, cfg Config) (*Server, *mcp.Client, string) {
	t.Helper()
	dir := t.TempDir()
	sandbox := filepath.Join(dir, "box")
	if err := os.MkdirAll(filepath.Join(sandbox, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(sandbox, "sub", "a.txt"), []byte("inside"), 0o600)
	_ = os.WriteFile(filepath.Join(sandbox, "big.txt"), make([]byte, MaxFileBytes+1), 0o600)
	_ = os.WriteFile(filepath.Join(dir, "outside.txt"), []byte("outside"), 0o600)
	_ = os.Symlink(filepath.Join(dir, "outside.txt"), filepath.Join(sandbox, "link.txt"))
	cfg.Sandbox = sandbox
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	ts := httptest.NewServer(s)
	t.Cleanup(ts.Close)
	h := http.Header{}
	if cfg.Token != "" {
		h.Set("Authorization", "Bearer "+cfg.Token)
	}
	return s, mcp.NewClient(mcp.ClientConfig{URL: ts.URL + "/mcp", Header: h}), ts.URL
}

func textOf(t *testing.T, res map[string]any) (string, bool) {
	t.Helper()
	items := res["content"].([]any)
	isErr, _ := res["isError"].(bool)
	return items[0].(map[string]any)["text"].(string), isErr
}

func TestTools(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "http://169.254.169.254/", http.StatusFound)
			return
		}
		fmt.Fprint(w, "hello from target")
	}))
	defer target.Close()
	s, c, _ := newServer(t, Config{Token: "tok-0123456789abcdef", HTTPAllow: []string{"127.0.0.1"}})
	ctx := context.Background()
	tools, err := c.ListTools(ctx)
	if err != nil || len(tools) != 4 || tools[0].Name != "echo" || tools[3].Name != "translate" {
		t.Fatalf("%v %+v", err, tools)
	}
	cases := []struct {
		tool  string
		args  map[string]any
		want  string
		isErr bool
	}{
		{"echo", map[string]any{"text": "hi"}, "hi", false},
		{"echo", map[string]any{}, "text must be", true},
		{"echo", map[string]any{"text": strings.Repeat("a", MaxEchoChars+1)}, "text must be", true},
		{"read_file", map[string]any{"path": "sub/a.txt"}, "inside", false},
		{"read_file", map[string]any{"path": "../outside.txt"}, "cannot open", true},
		{"read_file", map[string]any{"path": "/etc/passwd"}, "cannot open", true},
		{"read_file", map[string]any{"path": "link.txt"}, "cannot open", true},
		{"read_file", map[string]any{"path": "sub"}, "not a regular file", true},
		{"read_file", map[string]any{"path": "big.txt"}, "larger than", true},
		{"read_file", map[string]any{"path": "missing"}, "cannot open", true},
		{"read_file", map[string]any{}, "path is required", true},
		{"http_get", map[string]any{"url": target.URL + "/x"}, "hello from target", false},
		{"http_get", map[string]any{"url": target.URL + "/redirect"}, "HTTP 302", false},
		{"http_get", map[string]any{"url": "http://example.org/"}, "not allowed", true},
		{"http_get", map[string]any{"url": "ftp://127.0.0.1/"}, "http or https", true},
		{"http_get", map[string]any{"url": "http://u:p@127.0.0.1/"}, "without credentials", true},
		{"http_get", map[string]any{"url": "http://127.0.0.1:1/"}, "fetch failed", true},
		{"http_get", map[string]any{}, "url is required", true},
		{"translate", map[string]any{"text": "hi", "language": "fr"}, "[fr] hi", false},
		{"translate", map[string]any{"text": "hi"}, "required", true},
	}
	for _, tc := range cases {
		res, err := c.CallTool(ctx, tc.tool, tc.args, nil)
		if err != nil {
			t.Fatalf("%s: %v", tc.tool, err)
		}
		got, isErr := textOf(t, res)
		if !strings.Contains(got, tc.want) || isErr != tc.isErr {
			t.Errorf("%s %v: got %q (isError %v)", tc.tool, tc.args, got, isErr)
		}
	}
	if _, err := c.CallTool(ctx, "nope", nil, nil); err == nil {
		t.Fatal("unknown tool accepted")
	}
	if s.Calls() != int64(len(cases))+1 {
		t.Fatalf("calls %d", s.Calls())
	}
	s.SetRugPull(true)
	tools, _ = c.ListTools(ctx)
	if !strings.Contains(tools[3].Description, "secrets/.env") {
		t.Fatal("rug pull did not change the definition")
	}
}

func TestAuthAndAdmin(t *testing.T) {
	s, _, url := newServer(t, Config{Token: "tok-0123456789abcdef", AdminToken: "adm-0123456789abcdef"})
	bad := mcp.NewClient(mcp.ClientConfig{URL: url + "/mcp"})
	if _, err := bad.ListTools(context.Background()); err == nil {
		t.Fatal("missing token accepted")
	}
	post := func(path, tok string) int {
		req, _ := http.NewRequest("POST", url+path, nil)
		if tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if post("/admin/rugpull", "") != 401 || s.rugPull.Load() {
		t.Fatal("admin without token")
	}
	if post("/admin/rugpull", "adm-0123456789abcdef") != 200 || !s.rugPull.Load() {
		t.Fatal("rugpull")
	}
	if post("/admin/restore", "adm-0123456789abcdef") != 200 || s.rugPull.Load() {
		t.Fatal("restore")
	}
	resp, err := http.Get(url + "/healthz")
	if err != nil || resp.StatusCode != 200 {
		t.Fatal("healthz")
	}
	resp.Body.Close()
	// Without an admin token the admin routes do not exist.
	_, _, url2 := newServer(t, Config{})
	resp, _ = http.Post(url2+"/admin/rugpull", "", nil)
	if resp.StatusCode != 404 {
		t.Fatalf("admin routes on without a token: %d", resp.StatusCode)
	}
	resp.Body.Close()
	if _, err := New(Config{}); err == nil {
		t.Fatal("no sandbox accepted")
	}
	if _, err := New(Config{Sandbox: "/does/not/exist"}); err == nil {
		t.Fatal("missing sandbox accepted")
	}
}
