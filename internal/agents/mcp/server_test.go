package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/laiwf94/grantd/internal/agents/jsonrpc"
)

type testHandler struct {
	mu       sync.Mutex
	lastCall *Caller
	callErr  error
}

func (h *testHandler) Authenticate(r *http.Request) (any, string, error) {
	switch r.Header.Get("Authorization") {
	case "Bearer alice":
		return "alice-principal", "alice", nil
	case "Bearer bob":
		return "bob-principal", "bob", nil
	}
	return nil, "", NewError(http.StatusUnauthorized, CodeUnauthenticated, "who are you")
}

func (h *testHandler) ListTools(ctx context.Context, c *Caller) ([]Tool, error) {
	if c.Principal == "bob-principal" {
		return nil, nil
	}
	return []Tool{{Name: "echo", Description: "Echo", InputSchema: json.RawMessage(`{"type":"object"}`)}}, nil
}

func (h *testHandler) CallTool(ctx context.Context, c *Caller, name string, args map[string]any) (map[string]any, error) {
	h.mu.Lock()
	h.lastCall = c
	err := h.callErr
	h.mu.Unlock()
	if err != nil {
		return nil, err
	}
	b, _ := json.Marshal(args)
	return map[string]any{"content": []any{map[string]any{"type": "text", "text": name + ":" + string(b)}}, "resultType": "x"}, nil
}

type harness struct {
	t   *testing.T
	srv *Server
	h   *testHandler
	ts  *httptest.Server
}

func newHarness(t *testing.T) *harness {
	h := &testHandler{}
	srv := NewServer(ServerConfig{Info: Implementation{Name: "gw", Version: "1"}, Handler: h,
		AllowedOrigins: []string{"https://app.example.com"}, MaxBodyBytes: 4096, MaxSessionsPerKey: 2})
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)
	return &harness{t: t, srv: srv, h: h, ts: ts}
}

type resp struct {
	status int
	header http.Header
	body   map[string]any
	raw    string
}

func (hs *harness) do(method string, headers map[string]string, body string) resp {
	hs.t.Helper()
	req, _ := http.NewRequest(method, hs.ts.URL, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Authorization", "Bearer alice")
	for k, v := range headers {
		if v == "" {
			req.Header.Del(k)
		} else {
			req.Header.Set(k, v)
		}
	}
	r, err := http.DefaultClient.Do(req)
	if err != nil {
		hs.t.Fatal(err)
	}
	defer r.Body.Close()
	data, _ := io.ReadAll(r.Body)
	out := resp{status: r.StatusCode, header: r.Header, raw: string(data)}
	if len(data) > 0 {
		_ = json.Unmarshal(data, &out.body)
	}
	return out
}

func modernHeaders(method string) map[string]string {
	return map[string]string{HeaderProtocolVersion: VersionModern, HeaderMethod: method}
}

const meta = `"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{},"io.modelcontextprotocol/clientInfo":{"name":"t","version":"1"}}`

func errCode(r resp) int {
	e, _ := r.body["error"].(map[string]any)
	c, _ := e["code"].(float64)
	return int(c)
}

func result(r resp) map[string]any {
	m, _ := r.body["result"].(map[string]any)
	return m
}

func TestModernFlow(t *testing.T) {
	hs := newHarness(t)
	r := hs.do("POST", modernHeaders(MethodDiscover), `{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{`+meta+`}}`)
	res := result(r)
	if r.status != 200 || res["resultType"] != "complete" || res["cacheScope"] != "public" {
		t.Fatalf("discover: %d %s", r.status, r.raw)
	}
	if v := res["supportedVersions"].([]any); v[0] != VersionModern || len(v) != 4 {
		t.Fatalf("versions %v", v)
	}
	if res["_meta"].(map[string]any)[MetaServerInfo].(map[string]any)["name"] != "gw" {
		t.Fatal("serverInfo missing")
	}
	r = hs.do("POST", modernHeaders(MethodToolsList), `{"jsonrpc":"2.0","id":"l","method":"tools/list","params":{`+meta+`}}`)
	res = result(r)
	if r.body["id"] != "l" || res["cacheScope"] != "private" || len(res["tools"].([]any)) != 1 || res["ttlMs"].(float64) != 30000 {
		t.Fatalf("list: %s", r.raw)
	}
	h := modernHeaders(MethodToolsCall)
	h[HeaderName] = "echo"
	r = hs.do("POST", h, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{"x":1},`+meta+`}}`)
	res = result(r)
	if r.status != 200 || res["resultType"] != "complete" || !strings.Contains(r.raw, `echo:{\"x\":1}`) {
		t.Fatalf("call: %d %s", r.status, r.raw)
	}
	if hs.h.lastCall.Version != VersionModern || hs.h.lastCall.Legacy || hs.h.lastCall.PrincipalKey != "alice" {
		t.Fatalf("caller %+v", hs.h.lastCall)
	}
	// Names outside the plain ASCII set travel base64-encoded.
	h[HeaderName] = EncodeHeaderValue("échо")
	r = hs.do("POST", h, `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"échо",`+meta+`}}`)
	if r.status != 200 {
		t.Fatalf("encoded name: %s", r.raw)
	}
	// Bob's list is empty, not null.
	bob := modernHeaders(MethodToolsList)
	bob["Authorization"] = "Bearer bob"
	r = hs.do("POST", bob, `{"jsonrpc":"2.0","id":4,"method":"tools/list","params":{`+meta+`}}`)
	if !strings.Contains(r.raw, `"tools":[]`) {
		t.Fatalf("empty list: %s", r.raw)
	}
	// A modern notification is accepted with 202 and no body.
	r = hs.do("POST", modernHeaders("notifications/cancelled"), `{"jsonrpc":"2.0","method":"notifications/cancelled"}`)
	if r.status != 202 || r.raw != "" {
		t.Fatalf("notification: %d %q", r.status, r.raw)
	}
}

func TestModernValidation(t *testing.T) {
	hs := newHarness(t)
	call := func(name string) map[string]string {
		h := modernHeaders(MethodToolsCall)
		h[HeaderName] = name
		return h
	}
	cases := []struct {
		name    string
		headers map[string]string
		body    string
		status  int
		code    int
	}{
		{"no version header", map[string]string{HeaderMethod: "tools/list"}, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, 400, CodeHeaderMismatch},
		{"unknown version", map[string]string{HeaderProtocolVersion: "1900-01-01"}, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, 400, CodeUnsupportedProtocolVersion},
		{"legacy version without session", map[string]string{HeaderProtocolVersion: Version251125}, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, 400, jsonrpc.CodeInvalidRequest},
		{"no method header", map[string]string{HeaderProtocolVersion: VersionModern}, `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{` + meta + `}}`, 400, CodeHeaderMismatch},
		{"method mismatch", modernHeaders("tools/call"), `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{` + meta + `}}`, 400, CodeHeaderMismatch},
		{"missing meta", modernHeaders("tools/list"), `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, 400, jsonrpc.CodeInvalidParams},
		{"meta version mismatch", modernHeaders("tools/list"), `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2025-11-25","io.modelcontextprotocol/clientCapabilities":{}}}}`, 400, CodeHeaderMismatch},
		{"no capabilities", modernHeaders("tools/list"), `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`, 400, jsonrpc.CodeInvalidParams},
		{"bad clientInfo", modernHeaders("tools/list"), `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{},"io.modelcontextprotocol/clientInfo":"x"}}}`, 400, jsonrpc.CodeInvalidParams},
		{"cursor", modernHeaders("tools/list"), `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"cursor":"abc",` + meta + `}}`, 400, jsonrpc.CodeInvalidParams},
		{"no name header", modernHeaders("tools/call"), `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo",` + meta + `}}`, 400, CodeHeaderMismatch},
		{"name mismatch", call("other"), `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo",` + meta + `}}`, 400, CodeHeaderMismatch},
		{"bad base64 name", call("=?base64?!!?="), `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo",` + meta + `}}`, 400, CodeHeaderMismatch},
		{"empty name", call(""), `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"",` + meta + `}}`, 400, CodeHeaderMismatch},
		{"arguments not object", call("echo"), `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":[1],` + meta + `}}`, 400, jsonrpc.CodeInvalidParams},
		{"ping removed", modernHeaders("ping"), `{"jsonrpc":"2.0","id":1,"method":"ping","params":{` + meta + `}}`, 404, jsonrpc.CodeMethodNotFound},
		{"unknown method", modernHeaders("resources/list"), `{"jsonrpc":"2.0","id":1,"method":"resources/list","params":{` + meta + `}}`, 404, jsonrpc.CodeMethodNotFound},
		{"batch", modernHeaders("tools/list"), `[{"jsonrpc":"2.0","id":1,"method":"tools/list"}]`, 400, jsonrpc.CodeInvalidRequest},
		{"parse error", modernHeaders("tools/list"), `{"jsonrpc":`, 400, jsonrpc.CodeParseError},
		{"duplicate keys", modernHeaders("tools/list"), `{"jsonrpc":"2.0","id":1,"id":2,"method":"tools/list"}`, 400, jsonrpc.CodeParseError},
		{"response from client", modernHeaders("x"), `{"jsonrpc":"2.0","id":1,"result":{}}`, 400, jsonrpc.CodeInvalidRequest},
		{"notification method mismatch", modernHeaders("a"), `{"jsonrpc":"2.0","method":"b"}`, 400, CodeHeaderMismatch},
	}
	for _, c := range cases {
		r := hs.do("POST", c.headers, c.body)
		if r.status != c.status || errCode(r) != c.code {
			t.Errorf("%s: got %d %d (%s)", c.name, r.status, errCode(r), r.raw)
		}
	}
	// Errors keep the request id when it was readable.
	r := hs.do("POST", modernHeaders("tools/list"), `{"jsonrpc":"2.0","id":"keep","method":"tools/list"}`)
	if r.body["id"] != "keep" {
		t.Fatalf("id lost: %s", r.raw)
	}
	r = hs.do("POST", map[string]string{HeaderProtocolVersion: "1900-01-01"}, `{"jsonrpc":"2.0","id":1,"method":"x"}`)
	if !strings.Contains(r.raw, `"requested":"1900-01-01"`) || !strings.Contains(r.raw, `"supported":["2026-07-28"`) {
		t.Fatalf("unsupported version data: %s", r.raw)
	}
}

func TestTransportRules(t *testing.T) {
	hs := newHarness(t)
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{` + meta + `}}`
	h := modernHeaders("tools/list")
	with := func(k, v string) map[string]string {
		m := map[string]string{}
		for a, b := range h {
			m[a] = b
		}
		m[k] = v
		return m
	}
	if r := hs.do("POST", with("Origin", "https://evil.example"), body); r.status != 403 || r.body["id"] != nil {
		t.Fatalf("foreign origin: %d %s", r.status, r.raw)
	}
	if r := hs.do("POST", with("Origin", "https://APP.example.com"), body); r.status != 200 {
		t.Fatalf("allowed origin: %d %s", r.status, r.raw)
	}
	if r := hs.do("GET", h, ""); r.status != 405 || r.header.Get("Allow") != "POST, DELETE" {
		t.Fatalf("GET: %d", r.status)
	}
	r := hs.do("POST", with("Authorization", "Bearer nobody"), body)
	if r.status != 401 || errCode(r) != CodeUnauthenticated || !strings.HasPrefix(r.header.Get("WWW-Authenticate"), "Bearer") {
		t.Fatalf("unauthenticated: %d %s", r.status, r.raw)
	}
	if r := hs.do("POST", with("Content-Type", "text/plain"), body); r.status != 415 {
		t.Fatalf("content type: %d", r.status)
	}
	if r := hs.do("POST", with("Accept", "text/event-stream"), body); r.status != 406 {
		t.Fatalf("accept: %d", r.status)
	}
	if r := hs.do("POST", with("Accept", "application/json;q=0, text/html"), body); r.status != 406 {
		t.Fatalf("accept q=0: %d", r.status)
	}
	if r := hs.do("POST", with("Accept", "*/*"), body); r.status != 200 {
		t.Fatalf("accept */*: %d", r.status)
	}
	if r := hs.do("POST", with("Accept", ""), body); r.status != 200 {
		t.Fatalf("no accept header: %d", r.status)
	}
	big := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"x":"` + strings.Repeat("a", 5000) + `"}}`
	if r := hs.do("POST", h, big); r.status != 413 {
		t.Fatalf("body limit: %d", r.status)
	}
}

func legacyInit(t *testing.T, hs *harness, auth, version string) string {
	t.Helper()
	r := hs.do("POST", map[string]string{"Authorization": "Bearer " + auth},
		`{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"`+version+`","capabilities":{},"clientInfo":{"name":"old","version":"1"}}}`)
	sid := r.header.Get(HeaderSessionID)
	if r.status != 200 || len(sid) != 64 {
		t.Fatalf("initialize: %d %s", r.status, r.raw)
	}
	return sid
}

func TestLegacyFlow(t *testing.T) {
	hs := newHarness(t)
	r := hs.do("POST", nil, `{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{}}}`)
	res := result(r)
	sid := r.header.Get(HeaderSessionID)
	if res["protocolVersion"] != Version250618 || res["resultType"] != nil || sid == "" {
		t.Fatalf("initialize: %s", r.raw)
	}
	// An unknown version gets the newest legacy one.
	r = hs.do("POST", nil, `{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2099-01-01","capabilities":{}}}`)
	if result(r)["protocolVersion"] != Version251125 {
		t.Fatalf("fallback version: %s", r.raw)
	}
	s := map[string]string{HeaderSessionID: sid, HeaderProtocolVersion: Version250618}
	if r := hs.do("POST", s, `{"jsonrpc":"2.0","method":"notifications/initialized"}`); r.status != 202 {
		t.Fatalf("initialized: %d", r.status)
	}
	if r := hs.do("POST", s, `{"jsonrpc":"2.0","id":1,"method":"ping"}`); r.status != 200 || r.raw != "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n" {
		t.Fatalf("ping: %s", r.raw)
	}
	r = hs.do("POST", s, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	if res := result(r); res["ttlMs"] != nil || res["resultType"] != nil || len(res["tools"].([]any)) != 1 {
		t.Fatalf("legacy list: %s", r.raw)
	}
	r = hs.do("POST", s, `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{"a":"b"}}}`)
	if res := result(r); res["resultType"] != nil || r.status != 200 || !hs.h.lastCall.Legacy || hs.h.lastCall.Version != Version250618 {
		t.Fatalf("legacy call: %s", r.raw)
	}
	// Without the version header the session's version applies.
	if r := hs.do("POST", map[string]string{HeaderSessionID: sid}, `{"jsonrpc":"2.0","id":4,"method":"ping"}`); r.status != 200 {
		t.Fatalf("no version header: %d", r.status)
	}
	for name, c := range map[string]struct {
		h      map[string]string
		body   string
		status int
		code   int
	}{
		"wrong version":   {map[string]string{HeaderSessionID: sid, HeaderProtocolVersion: Version251125}, `{"jsonrpc":"2.0","id":5,"method":"ping"}`, 400, jsonrpc.CodeInvalidRequest},
		"unknown session": {map[string]string{HeaderSessionID: strings.Repeat("0", 64)}, `{"jsonrpc":"2.0","id":5,"method":"ping"}`, 404, jsonrpc.CodeInvalidRequest},
		"other principal": {map[string]string{HeaderSessionID: sid, "Authorization": "Bearer bob"}, `{"jsonrpc":"2.0","id":5,"method":"ping"}`, 404, jsonrpc.CodeInvalidRequest},
		"discover":        {s, `{"jsonrpc":"2.0","id":5,"method":"server/discover"}`, 200, jsonrpc.CodeMethodNotFound},
		"cursor":          {s, `{"jsonrpc":"2.0","id":5,"method":"tools/list","params":{"cursor":"x"}}`, 200, jsonrpc.CodeInvalidParams},
		"no name":         {s, `{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{}}`, 200, jsonrpc.CodeInvalidParams},
		"init notif":      {nil, `{"jsonrpc":"2.0","method":"initialize","params":{}}`, 400, jsonrpc.CodeInvalidRequest},
		"init no version": {nil, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"capabilities":{}}}`, 400, jsonrpc.CodeInvalidParams},
		"init no caps":    {nil, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}`, 400, jsonrpc.CodeInvalidParams},
	} {
		r := hs.do("POST", c.h, c.body)
		if r.status != c.status || errCode(r) != c.code {
			t.Errorf("%s: %d %d %s", name, r.status, errCode(r), r.raw)
		}
	}
	// DELETE ends the session; only its owner can.
	if r := hs.do("DELETE", map[string]string{HeaderSessionID: sid, "Authorization": "Bearer bob"}, ""); r.status != 404 {
		t.Fatalf("delete by other: %d", r.status)
	}
	if r := hs.do("DELETE", map[string]string{HeaderSessionID: sid}, ""); r.status != 204 {
		t.Fatalf("delete: %d", r.status)
	}
	if r := hs.do("POST", s, `{"jsonrpc":"2.0","id":6,"method":"ping"}`); r.status != 404 {
		t.Fatalf("after delete: %d", r.status)
	}
	if r := hs.do("DELETE", nil, ""); r.status != 400 {
		t.Fatalf("delete without session: %d", r.status)
	}
}

func TestSessionLimits(t *testing.T) {
	hs := newHarness(t)
	a := legacyInit(t, hs, "alice", Version251125)
	b := legacyInit(t, hs, "alice", Version251125)
	c := legacyInit(t, hs, "alice", Version251125) // evicts a, the least recently used
	ping := func(sid string) int {
		return hs.do("POST", map[string]string{HeaderSessionID: sid}, `{"jsonrpc":"2.0","id":1,"method":"ping"}`).status
	}
	if ping(a) != 404 || ping(b) != 200 || ping(c) != 200 {
		t.Fatal("per-principal eviction")
	}
	if hs.srv.SessionCount() != 2 {
		t.Fatalf("count %d", hs.srv.SessionCount())
	}
	// Global limit and idle expiry.
	now := time.Unix(0, 0)
	st := newSessionStore(time.Minute, 2, 5, func() time.Time { return now })
	x, _ := st.create("k1", "v")
	st.create("k2", "v")
	if _, err := st.create("k3", "v"); !errors.Is(err, errTooManySessions) {
		t.Fatalf("global limit: %v", err)
	}
	now = now.Add(time.Minute)
	if _, err := st.create("k3", "v"); err != nil {
		t.Fatalf("idle sessions must be reclaimed: %v", err)
	}
	if _, ok := st.get(x, "k1"); ok {
		t.Fatal("idle session still usable")
	}
	y, _ := st.create("k4", "v")
	now = now.Add(2 * time.Minute)
	if _, ok := st.get(y, "k4"); ok {
		t.Fatal("expired session returned")
	}
	// The table full of live sessions answers 503.
	full := NewServer(ServerConfig{Handler: &testHandler{}, MaxSessions: 1})
	ts := httptest.NewServer(full)
	defer ts.Close()
	hs2 := &harness{t: t, srv: full, ts: ts}
	legacyInit(t, hs2, "alice", Version251125)
	r := hs2.do("POST", map[string]string{"Authorization": "Bearer bob"}, `{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{}}}`)
	if r.status != 503 {
		t.Fatalf("full table: %d %s", r.status, r.raw)
	}
}

func TestHandlerErrors(t *testing.T) {
	hs := newHarness(t)
	h := modernHeaders(MethodToolsCall)
	h[HeaderName] = "echo"
	body := `{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"echo",` + meta + `}}`
	cases := []struct {
		err    error
		status int
		code   int
		retry  string
	}{
		{&Error{RPC: jsonrpc.NewError(CodeRateLimited, "slow down"), Status: 429, RetryAfter: 1500 * time.Millisecond}, 429, CodeRateLimited, "2"},
		{&Error{RPC: jsonrpc.NewError(CodePolicyDenied, "no")}, 200, CodePolicyDenied, ""},
		{jsonrpc.NewError(-32602, "Unknown tool"), 200, -32602, ""},
		{errors.New("database password is hunter2"), 500, jsonrpc.CodeInternalError, ""},
	}
	for _, c := range cases {
		hs.h.mu.Lock()
		hs.h.callErr = c.err
		hs.h.mu.Unlock()
		r := hs.do("POST", h, body)
		if r.status != c.status || errCode(r) != c.code || r.header.Get("Retry-After") != c.retry || strings.Contains(r.raw, "hunter2") {
			t.Errorf("%v: %d %d %q %s", c.err, r.status, errCode(r), r.header.Get("Retry-After"), r.raw)
		}
	}
	// On a legacy session the same errors come with HTTP 200, keeping Retry-After.
	sid := legacyInit(t, hs, "alice", Version251125)
	hs.h.mu.Lock()
	hs.h.callErr = &Error{RPC: jsonrpc.NewError(CodeRateLimited, "slow down"), Status: 429, RetryAfter: time.Second}
	hs.h.mu.Unlock()
	r := hs.do("POST", map[string]string{HeaderSessionID: sid}, `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo"}}`)
	if r.status != 200 || errCode(r) != CodeRateLimited || r.header.Get("Retry-After") != "1" {
		t.Fatalf("legacy error status: %d %q %s", r.status, r.header.Get("Retry-After"), r.raw)
	}
	if (&Error{RPC: jsonrpc.NewError(1, "m")}).Error() == "" {
		t.Fatal("Error()")
	}
}

func TestEncodeDecodeHeaderValues(t *testing.T) {
	cases := map[string]string{
		"us-west1":           "us-west1",
		"Hello, 世界":          "=?base64?SGVsbG8sIOS4lueVjA==?=",
		" padded ":           "=?base64?IHBhZGRlZCA=?=",
		"line1\nline2":       "=?base64?bGluZTEKbGluZTI=?=",
		"=?base64?literal?=": "=?base64?PT9iYXNlNjQ/bGl0ZXJhbD89?=",
		"":                   "",
	}
	for in, want := range cases {
		if got := EncodeHeaderValue(in); got != want {
			t.Errorf("encode %q = %q, want %q", in, got, want)
		}
		if back, err := DecodeHeaderValue(want); err != nil || back != in {
			t.Errorf("decode %q = %q %v", want, back, err)
		}
	}
	for _, bad := range []string{"=?base64?***?=", "=?base64?/w==?=", "a\x01b"} {
		if _, err := DecodeHeaderValue(bad); err == nil {
			t.Errorf("decoded %q", bad)
		}
	}
}

func TestHeaderParams(t *testing.T) {
	schema := json.RawMessage(`{"type":"object","properties":{
	  "region":{"type":"string","x-mcp-header":"Region"},
	  "opts":{"type":"object","properties":{"dry":{"type":"boolean","x-mcp-header":"Dry-Run"},"n":{"type":"integer","x-mcp-header":"N"}}},
	  "query":{"type":"string","enum":[{"x-mcp-header":"NotAnAnnotation"}]},
	  "x-mcp-header":{"type":"string"}}}`)
	params, err := HeaderParams(schema)
	if err != nil || len(params) != 3 {
		t.Fatalf("%v %+v", err, params)
	}
	args := map[string]any{"region": "eu west", "opts": map[string]any{"dry": true, "n": json.Number("42")}}
	h, err := ParamHeaders(params, args)
	if err != nil {
		t.Fatal(err)
	}
	if h.Get("Mcp-Param-Region") != "eu west" || h.Get("Mcp-Param-Dry-Run") != "true" || h.Get("Mcp-Param-N") != "42" {
		t.Fatalf("headers %v", h)
	}
	if err := CheckParamHeaders(h, params, args); err != nil {
		t.Fatal(err)
	}
	h2 := h.Clone()
	h2.Set("Mcp-Param-N", "42.0")
	if err := CheckParamHeaders(h2, params, args); err != nil {
		t.Fatalf("numeric comparison: %v", err)
	}
	for name, mutate := range map[string]func(http.Header){
		"missing":  func(h http.Header) { h.Del("Mcp-Param-Region") },
		"mismatch": func(h http.Header) { h.Set("Mcp-Param-Region", "us") },
		"twice":    func(h http.Header) { h.Add("Mcp-Param-Region", "eu west") },
		"bad enc":  func(h http.Header) { h.Set("Mcp-Param-Region", "=?base64?%%?=") },
		"int text": func(h http.Header) { h.Set("Mcp-Param-N", "forty-two") },
	} {
		hh := h.Clone()
		mutate(hh)
		if err := CheckParamHeaders(hh, params, args); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// Absent or null values need no header, and must not have one.
	none := map[string]any{"opts": map[string]any{"dry": nil}}
	if err := CheckParamHeaders(http.Header{}, params, none); err != nil {
		t.Fatal(err)
	}
	if err := CheckParamHeaders(http.Header{"Mcp-Param-Region": {"x"}}, params, none); err == nil {
		t.Fatal("header without argument accepted")
	}
	if _, err := ParamHeaders(params, map[string]any{"region": map[string]any{}}); err == nil {
		t.Fatal("object value accepted")
	}
	if _, err := ParamHeaders(params, map[string]any{"opts": map[string]any{"n": json.Number("1.5")}}); err == nil {
		t.Fatal("fractional integer accepted")
	}
	if err := CheckParamHeaders(http.Header{}, params, map[string]any{"opts": map[string]any{"n": json.Number("1e300")}}); err == nil {
		t.Fatal("unsafe integer accepted")
	}
	if _, err := ParamHeaders(params, map[string]any{"opts": "flat"}); err != nil {
		t.Fatalf("non-object along the path means absent: %v", err)
	}
	bad := map[string]string{
		"in items":    `{"type":"object","properties":{"a":{"type":"array","items":{"type":"string","x-mcp-header":"A"}}}}`,
		"in anyOf":    `{"anyOf":[{"type":"object","properties":{"a":{"type":"string","x-mcp-header":"A"}}}]}`,
		"at root":     `{"type":"object","x-mcp-header":"Root"}`,
		"bad token":   `{"type":"object","properties":{"a":{"type":"string","x-mcp-header":"Bad Name"}}}`,
		"duplicate":   `{"type":"object","properties":{"a":{"type":"string","x-mcp-header":"X"},"b":{"type":"string","x-mcp-header":"x"}}}`,
		"number type": `{"type":"object","properties":{"a":{"type":"number","x-mcp-header":"A"}}}`,
		"not json":    `{`,
	}
	for name, s := range bad {
		if _, err := HeaderParams(json.RawMessage(s)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestToolCanonical(t *testing.T) {
	a := Tool{Name: "t", Description: "d", Title: "T", InputSchema: json.RawMessage(`{ "type" : "object", "b":1, "a":2 }`),
		Annotations: json.RawMessage(`{"readOnlyHint":true}`)}
	b := Tool{Name: "t", Description: "d", Title: "T", InputSchema: json.RawMessage(`{"a":2,"b":1,"type":"object"}`),
		Annotations: json.RawMessage(`{"readOnlyHint": true}`)}
	ca, err := a.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	cb, _ := b.Canonical()
	if string(ca) != string(cb) {
		t.Fatalf("reformatting changed the canonical form:\n%s\n%s", ca, cb)
	}
	b.Description = "d2"
	if cb, _ = b.Canonical(); string(ca) == string(cb) {
		t.Fatal("description change not reflected")
	}
	for _, bad := range []Tool{{Name: "x"}, {Name: "x", InputSchema: json.RawMessage(`[]`)}, {Name: "x", InputSchema: json.RawMessage(`{`)}} {
		if _, err := bad.Canonical(); err == nil {
			t.Errorf("%+v accepted", bad)
		}
	}
	if !ValidToolName("admin.tools_list-2") || ValidToolName("has space") || ValidToolName("") {
		t.Fatal("ValidToolName")
	}
	if !IsLegacy(Version250326) || IsLegacy(VersionModern) {
		t.Fatal("IsLegacy")
	}
}
