package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/laiwf94/toolgate/internal/jsonrpc"
)

func clientFor(url string, mut ...func(*ClientConfig)) *Client {
	cfg := ClientConfig{URL: url, Header: http.Header{"Authorization": {"Bearer alice"}},
		Info: Implementation{Name: "toolgate", Version: "test"}}
	for _, m := range mut {
		m(&cfg)
	}
	return NewClient(cfg)
}

func TestClientModern(t *testing.T) {
	hs := newHarness(t)
	c := clientFor(hs.ts.URL)
	tools, err := c.ListTools(context.Background())
	if err != nil || len(tools) != 1 || tools[0].Name != "echo" {
		t.Fatalf("%v %+v", err, tools)
	}
	res, err := c.CallTool(context.Background(), "echo", map[string]any{"q": "v"}, nil)
	if err != nil || !strings.Contains(fmt.Sprint(res["content"]), `echo:{"q":"v"}`) {
		t.Fatalf("%v %v", err, res)
	}
	if e, _, _ := c.state(); e != eraModern {
		t.Fatal("era not recorded")
	}
	// The credential is injected and the agent cannot override it.
	bad := clientFor(hs.ts.URL, func(cfg *ClientConfig) { cfg.Header = http.Header{"Authorization": {"Bearer nobody"}} })
	_, err = bad.ListTools(context.Background())
	var re *RPCError
	if !errors.As(err, &re) || re.Status != 401 || re.Err.Code != CodeUnauthenticated || re.Error() == "" {
		t.Fatalf("bad credential: %v", err)
	}
}

// legacyServer mimics a 2025-era SDK server: sessions, SSE responses,
// pagination and session expiry.
type legacyServer struct {
	mu          sync.Mutex
	sessions    map[string]bool
	inits       atomic.Int32
	version     string
	sawParam    http.Header
	noSession   bool
	notifStatus int
}

func (l *legacyServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	msg, _, derr := jsonrpc.Decode(body)
	if derr != nil {
		http.Error(w, "bad", 400)
		return
	}
	writeJSON := func(status int, v string) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, v)
	}
	if msg.Method == MethodInitialize {
		l.inits.Add(1)
		sid := fmt.Sprintf("sess-%d", l.inits.Load())
		l.mu.Lock()
		l.sessions[sid] = true
		l.mu.Unlock()
		if !l.noSession {
			w.Header().Set(HeaderSessionID, sid)
		}
		writeJSON(200, `{"jsonrpc":"2.0","id":`+string(msg.ID)+`,"result":{"protocolVersion":"`+l.version+`","capabilities":{"tools":{}},"serverInfo":{"name":"legacy","version":"0"}}}`)
		return
	}
	sid := r.Header.Get(HeaderSessionID)
	l.mu.Lock()
	ok := l.sessions[sid] || l.noSession && r.Header.Get(HeaderProtocolVersion) == l.version
	l.mu.Unlock()
	if sid == "" && !l.noSession {
		writeJSON(400, `{"jsonrpc":"2.0","error":{"code":-32000,"message":"Bad Request: No valid session ID provided"},"id":null}`)
		return
	}
	if !ok {
		writeJSON(404, `{"jsonrpc":"2.0","error":{"code":-32001,"message":"Session not found"},"id":null}`)
		return
	}
	if r.Header.Get(HeaderProtocolVersion) != l.version {
		writeJSON(400, `{"jsonrpc":"2.0","error":{"code":-32000,"message":"bad version"},"id":null}`)
		return
	}
	switch msg.Method {
	case MethodInitialized:
		status := l.notifStatus
		if status == 0 {
			status = 202
		}
		w.WriteHeader(status)
	case MethodToolsList:
		var p struct {
			Cursor string `json:"cursor"`
		}
		_ = json.Unmarshal(msg.Params, &p)
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		name, next := "first", `,"nextCursor":"p2"`
		if p.Cursor == "p2" {
			name, next = "second", ""
		}
		fmt.Fprintf(w, ": keep-alive\n\nevent: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{}}\n\n")
		fmt.Fprintf(w, "data: {\"jsonrpc\":\"2.0\",\"id\":999,\"result\":{}}\n\n")
		fmt.Fprintf(w, "data: {\"jsonrpc\":\"2.0\",\"id\":%s,\n", msg.ID)
		fmt.Fprintf(w, "data: \"result\":{\"tools\":[{\"name\":\"%s\",\"inputSchema\":{\"type\":\"object\"}}]%s}}\n\n", name, next)
	case MethodToolsCall:
		l.mu.Lock()
		l.sawParam = r.Header.Clone()
		l.mu.Unlock()
		writeJSON(200, `{"jsonrpc":"2.0","id":`+string(msg.ID)+`,"result":{"content":[{"type":"text","text":"legacy ok"}]}}`)
	}
}

func newLegacy(version string) (*legacyServer, *httptest.Server) {
	l := &legacyServer{sessions: map[string]bool{}, version: version}
	return l, httptest.NewServer(l)
}

func TestClientFallsBackToLegacy(t *testing.T) {
	l, ts := newLegacy(Version250618)
	defer ts.Close()
	c := clientFor(ts.URL)
	tools, err := c.ListTools(context.Background())
	if err != nil || len(tools) != 2 || tools[0].Name != "first" || tools[1].Name != "second" {
		t.Fatalf("paginated SSE list: %v %+v", err, tools)
	}
	if e, sess, v := c.state(); e != eraLegacy || sess != "sess-1" || v != Version250618 {
		t.Fatalf("state %v %q %q", e, sess, v)
	}
	if _, err := c.CallTool(context.Background(), "x", nil, nil); err != nil {
		t.Fatal(err)
	}
	if l.inits.Load() != 1 {
		t.Fatalf("initialized %d times", l.inits.Load())
	}
	// The server forgets the session: the client starts a new one, once.
	l.mu.Lock()
	l.sessions = map[string]bool{}
	l.mu.Unlock()
	res, err := c.CallTool(context.Background(), "x", nil, nil)
	if err != nil || l.inits.Load() != 2 {
		t.Fatalf("re-initialize: %v %d", err, l.inits.Load())
	}
	if !strings.Contains(fmt.Sprint(res), "legacy ok") {
		t.Fatalf("result %v", res)
	}
	// A server without sessions works too.
	l2, ts2 := newLegacy(Version251125)
	defer ts2.Close()
	l2.noSession = true
	if _, err := clientFor(ts2.URL).CallTool(context.Background(), "x", nil, nil); err != nil {
		t.Fatalf("sessionless legacy: %v", err)
	}
}

func TestClientLegacyHandshakeErrors(t *testing.T) {
	l, ts := newLegacy("1999-01-01")
	defer ts.Close()
	if _, err := clientFor(ts.URL).ListTools(context.Background()); !errors.Is(err, ErrProtocol) {
		t.Fatalf("unsupported negotiated version: %v", err)
	}
	l.version = Version251125
	l.notifStatus = 500
	if _, err := clientFor(ts.URL).ListTools(context.Background()); err == nil || !strings.Contains(err.Error(), "initialized") {
		t.Fatalf("failed initialized notification: %v", err)
	}
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		msg, _, _ := jsonrpc.Decode(body)
		if msg.Method != MethodInitialize {
			w.WriteHeader(400)
			return
		}
		w.Header().Set(HeaderSessionID, "bad\x01id")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-11-25"}}`, msg.ID)
	}))
	defer bad.Close()
	if _, err := clientFor(bad.URL).ListTools(context.Background()); err == nil {
		t.Fatal("control characters in the session id accepted")
	}
}

func serve(t *testing.T, h http.HandlerFunc) string {
	ts := httptest.NewServer(h)
	t.Cleanup(ts.Close)
	return ts.URL
}

func echoID(r *http.Request) string {
	body, _ := io.ReadAll(r.Body)
	msg, _, _ := jsonrpc.Decode(body)
	return string(msg.ID)
}

func TestClientErrors(t *testing.T) {
	ctx := context.Background()
	jsonResp := func(status int, body func(id string) string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			id := echoID(r)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_, _ = io.WriteString(w, body(id))
		}
	}
	cases := []struct {
		name string
		h    http.HandlerFunc
		want func(error) bool
	}{
		{"too large", jsonResp(200, func(id string) string {
			return `{"jsonrpc":"2.0","id":` + id + `,"result":{"x":"` + strings.Repeat("a", 2000) + `"}}`
		}), func(e error) bool { return errors.Is(e, ErrResponseTooLarge) }},
		{"redirect", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://evil.example/steal", http.StatusFound)
		}, func(e error) bool { return errors.Is(e, ErrProtocol) && strings.Contains(e.Error(), "redirect") }},
		{"id mismatch", jsonResp(200, func(string) string { return `{"jsonrpc":"2.0","id":12345,"result":{}}` }),
			func(e error) bool { return errors.Is(e, ErrProtocol) }},
		{"not json", jsonResp(200, func(string) string { return `<html>` }), func(e error) bool { return errors.Is(e, ErrProtocol) }},
		{"http 500", jsonResp(500, func(string) string { return `oops` }), func(e error) bool { return strings.Contains(e.Error(), "HTTP 500") }},
		{"request back", jsonResp(200, func(string) string { return `{"jsonrpc":"2.0","id":1,"method":"x"}` }),
			func(e error) bool { return errors.Is(e, ErrProtocol) }},
		{"error for another id", jsonResp(200, func(string) string {
			return `{"jsonrpc":"2.0","id":424242,"error":{"code":-32602,"message":"not yours"}}`
		}), func(e error) bool { return errors.Is(e, ErrProtocol) }},
		{"rpc error", jsonResp(200, func(id string) string {
			return `{"jsonrpc":"2.0","id":` + id + `,"error":{"code":-32602,"message":"Unknown tool"}}`
		}), func(e error) bool { var re *RPCError; return errors.As(e, &re) && re.Err.Code == -32602 }},
		{"modern error, no fallback", jsonResp(400, func(id string) string {
			return `{"jsonrpc":"2.0","id":` + id + `,"error":{"code":-32022,"message":"Unsupported protocol version"}}`
		}), func(e error) bool { var re *RPCError; return errors.As(e, &re) && re.Err.Code == -32022 }},
		{"input required", jsonResp(200, func(id string) string {
			return `{"jsonrpc":"2.0","id":` + id + `,"result":{"resultType":"input_required","inputRequests":{}}}`
		}), func(e error) bool { return errors.Is(e, ErrInputRequired) }},
		{"unknown result type", jsonResp(200, func(id string) string {
			return `{"jsonrpc":"2.0","id":` + id + `,"result":{"resultType":"weird"}}`
		}), func(e error) bool { return errors.Is(e, ErrProtocol) }},
		{"result not object", jsonResp(200, func(id string) string { return `{"jsonrpc":"2.0","id":` + id + `,"result":[1]}` }),
			func(e error) bool { return errors.Is(e, ErrProtocol) }},
		{"result with 201", jsonResp(201, func(id string) string { return `{"jsonrpc":"2.0","id":` + id + `,"result":{}}` }),
			func(e error) bool { return errors.Is(e, ErrProtocol) }},
		{"sse without response", func(w http.ResponseWriter, r *http.Request) {
			echoID(r)
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = io.WriteString(w, "data: {\"jsonrpc\":\"2.0\",\"method\":\"n\"}\n\n")
		}, func(e error) bool { return errors.Is(e, ErrProtocol) }},
		{"sse too large", func(w http.ResponseWriter, r *http.Request) {
			echoID(r)
			w.Header().Set("Content-Type", "text/event-stream")
			for range 100 {
				_, _ = io.WriteString(w, ": "+strings.Repeat("x", 100)+"\n")
			}
		}, func(e error) bool { return errors.Is(e, ErrResponseTooLarge) }},
		{"sse long line", func(w http.ResponseWriter, r *http.Request) {
			echoID(r)
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = io.WriteString(w, "data: "+strings.Repeat("x", 5000)+"\n\n")
		}, func(e error) bool { return errors.Is(e, ErrResponseTooLarge) }},
	}
	for _, c := range cases {
		cl := clientFor(serve(t, c.h), func(cfg *ClientConfig) { cfg.MaxResponseBytes = 1024 })
		_, err := cl.CallTool(ctx, "x", nil, nil)
		if err == nil || !c.want(err) {
			t.Errorf("%s: got %v", c.name, err)
		}
	}
	// A stream whose final event has no trailing blank line still counts.
	url := serve(t, func(w http.ResponseWriter, r *http.Request) {
		id := echoID(r)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, `data: {"jsonrpc":"2.0","id":`+id+`,"result":{"content":[]}}`)
	})
	if _, err := clientFor(url).CallTool(ctx, "x", nil, nil); err != nil {
		t.Fatalf("unterminated final event: %v", err)
	}
	// Paging forever is cut off.
	url = serve(t, func(w http.ResponseWriter, r *http.Request) {
		id := echoID(r)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":`+id+`,"result":{"tools":[],"nextCursor":"again"}}`)
	})
	if _, err := clientFor(url, func(c *ClientConfig) { c.MaxPages = 3 }).ListTools(ctx); !errors.Is(err, ErrProtocol) {
		t.Fatalf("endless pages: %v", err)
	}
	url = serve(t, func(w http.ResponseWriter, r *http.Request) {
		id := echoID(r)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":`+id+`,"result":{"tools":"nope"}}`)
	})
	if _, err := clientFor(url).ListTools(ctx); !errors.Is(err, ErrProtocol) {
		t.Fatalf("bad tools: %v", err)
	}
	// Timeouts are recognizable.
	url = serve(t, func(w http.ResponseWriter, r *http.Request) { time.Sleep(200 * time.Millisecond) })
	tctx, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
	defer cancel()
	if _, err := clientFor(url).CallTool(tctx, "x", nil, nil); !IsTimeout(err) {
		t.Fatalf("timeout: %v", err)
	}
	if IsTimeout(errors.New("x")) {
		t.Fatal("IsTimeout")
	}
	if _, err := clientFor("http://127.0.0.1:1").CallTool(ctx, "x", nil, nil); err == nil {
		t.Fatal("connection refused not reported")
	}
	if _, err := clientFor("::bad url").CallTool(ctx, "x", nil, nil); err == nil {
		t.Fatal("bad URL not reported")
	}
}

func TestClientSendsParamHeaders(t *testing.T) {
	var got http.Header
	url := serve(t, func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		id := echoID(r)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":`+id+`,"result":{"content":[]}}`)
	})
	h := http.Header{"Mcp-Param-Region": {"eu"}}
	if _, err := clientFor(url).CallTool(context.Background(), "ünï", map[string]any{"region": "eu"}, h); err != nil {
		t.Fatal(err)
	}
	if got.Get("Mcp-Param-Region") != "eu" || got.Get(HeaderMethod) != "tools/call" || got.Get(HeaderName) != EncodeHeaderValue("ünï") ||
		got.Get(HeaderProtocolVersion) != VersionModern || got.Get("Authorization") != "Bearer alice" ||
		got.Get("Accept") != "application/json, text/event-stream" {
		t.Fatalf("headers %v", got)
	}
}

func TestLegacyFallbackDecision(t *testing.T) {
	re := func(code int) error { return &RPCError{Err: jsonrpc.NewError(code, "m")} }
	cases := []struct {
		status int
		err    error
		want   bool
	}{
		{400, re(-32000), true},
		{400, errors.New("no body"), true},
		{405, errors.New("x"), true},
		{400, re(CodeHeaderMismatch), false},
		{400, re(CodeUnsupportedProtocolVersion), false},
		{400, re(CodeMissingRequiredCapability), false},
		{404, re(jsonrpc.CodeMethodNotFound), false},
		{400, re(jsonrpc.CodeMethodNotFound), true},
		{500, re(-32000), false},
		{401, re(CodeUnauthenticated), false},
	}
	for _, c := range cases {
		if got := legacyFallback(c.status, c.err); got != c.want {
			t.Errorf("%d %v: got %v", c.status, c.err, got)
		}
	}
}

// One ambiguous error must not pin a modern server to the legacy era.
func TestClientDoesNotPinEraOnAmbiguousError(t *testing.T) {
	hs := newHarness(t)
	var fail atomic.Bool
	fail.Store(true)
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail.Load() {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(404)
			_, _ = io.WriteString(w, "<html>not found</html>")
			return
		}
		hs.srv.ServeHTTP(w, r)
	}))
	defer front.Close()
	c := clientFor(front.URL)
	if _, err := c.ListTools(context.Background()); err == nil {
		t.Fatal("expected a failure while the proxy answers 404")
	}
	if e, _, _ := c.state(); e != eraUnknown {
		t.Fatalf("era pinned after an ambiguous error: %v", e)
	}
	fail.Store(false)
	if _, err := c.ListTools(context.Background()); err != nil {
		t.Fatalf("recovered server: %v", err)
	}
	if e, _, _ := c.state(); e != eraModern {
		t.Fatal("modern era not recorded")
	}
}
