package jsonrpc

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestDecodeKinds(t *testing.T) {
	cases := []struct {
		in     string
		kind   Kind
		id     string
		method string
	}{
		{`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, KindRequest, `1`, "tools/list"},
		{`{"jsonrpc":"2.0","id":"a-1","method":"x","params":{}}`, KindRequest, `"a-1"`, "x"},
		{`{"jsonrpc":"2.0","id":-7,"method":"x"}`, KindRequest, `-7`, "x"},
		{` {"jsonrpc":"2.0","method":"notifications/initialized"} `, KindNotification, ``, "notifications/initialized"},
		{`{"jsonrpc":"2.0","id":3,"result":{}}`, KindResponse, `3`, ""},
		{`{"jsonrpc":"2.0","id":3,"error":{"code":-1,"message":"m","data":{"x":1}}}`, KindResponse, `3`, ""},
		{`{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"parse"}}`, KindResponse, ``, ""},
		{`{"jsonrpc":"2.0","error":{"code":-31000,"message":"who"}}`, KindResponse, ``, ""},
		{`{"jsonrpc":"2.0","id":1,"method":"x","extra":true}`, KindRequest, `1`, "x"},
	}
	for _, c := range cases {
		m, _, err := Decode([]byte(c.in))
		if err != nil {
			t.Fatalf("%s: %v", c.in, err)
		}
		if m.Kind != c.kind || string(m.ID) != c.id || m.Method != c.method {
			t.Errorf("%s: got kind=%d id=%s method=%q", c.in, m.Kind, m.ID, m.Method)
		}
	}
	m, _, _ := Decode([]byte(`{"jsonrpc":"2.0","id":3,"error":{"code":-5,"message":"m"}}`))
	if m.Error == nil || m.Error.Code != -5 || m.Error.Message != "m" {
		t.Fatalf("error not decoded: %+v", m.Error)
	}
}

func TestDecodeRejects(t *testing.T) {
	cases := []struct {
		in   string
		code int
		id   string
	}{
		{``, CodeParseError, ""},
		{"\xff\xfe", CodeParseError, ""},
		{`{"jsonrpc":"2.0",`, CodeParseError, ""},
		{`{} {}`, CodeParseError, ""},
		{`[{"jsonrpc":"2.0","id":1,"method":"x"}]`, CodeInvalidRequest, ""},
		{`[1,`, CodeParseError, ""},
		{`"hello"`, CodeInvalidRequest, ""},
		{`{"jsonrpc":"1.0","id":1,"method":"x"}`, CodeInvalidRequest, "1"},
		{`{"id":1,"method":"x"}`, CodeInvalidRequest, "1"},
		{`{"jsonrpc":"2.0","id":null,"method":"x"}`, CodeInvalidRequest, ""},
		{`{"jsonrpc":"2.0","id":1.5,"method":"x"}`, CodeInvalidRequest, ""},
		{`{"jsonrpc":"2.0","id":1e3,"method":"x"}`, CodeInvalidRequest, ""},
		{`{"jsonrpc":"2.0","id":01,"method":"x"}`, CodeParseError, ""},
		{`{"jsonrpc":"2.0","id":{},"method":"x"}`, CodeInvalidRequest, ""},
		{`{"jsonrpc":"2.0","id":1,"method":""}`, CodeInvalidRequest, "1"},
		{`{"jsonrpc":"2.0","id":1,"method":"` + strings.Repeat("m", MaxMethodBytes+1) + `"}`, CodeInvalidRequest, "1"},
		{`{"jsonrpc":"2.0","id":1,"method":"x","params":[1]}`, CodeInvalidRequest, "1"},
		{`{"jsonrpc":"2.0","id":1,"method":"x","params":null}`, CodeInvalidRequest, "1"},
		{`{"jsonrpc":"2.0","id":1,"method":"x","result":{}}`, CodeInvalidRequest, "1"},
		{`{"jsonrpc":"2.0","id":1}`, CodeInvalidRequest, "1"},
		{`{"jsonrpc":"2.0","id":1,"result":{},"error":{"code":1,"message":"x"}}`, CodeInvalidRequest, "1"},
		{`{"jsonrpc":"2.0","result":{}}`, CodeInvalidRequest, ""},
		{`{"jsonrpc":"2.0","id":null,"result":{}}`, CodeInvalidRequest, ""},
		{`{"jsonrpc":"2.0","id":true,"result":{}}`, CodeInvalidRequest, ""},
		{`{"jsonrpc":"2.0","id":2,"error":{"message":"no code"}}`, CodeInvalidRequest, "2"},
		{`{"jsonrpc":"2.0","id":2,"error":"str"}`, CodeInvalidRequest, "2"},
		{`{"jsonrpc":"2.0","id":1,"method":"x","method":"y"}`, CodeParseError, ""},
		{`{"jsonrpc":"2.0","id":"` + strings.Repeat("i", MaxIDBytes) + `","method":"x"}`, CodeInvalidRequest, ""},
		{`{"jsonrpc":"2.0","id":1,"method":"x","params":` + strings.Repeat(`{"a":`, MaxDepth) + `1` + strings.Repeat(`}`, MaxDepth) + `}`, CodeParseError, ""},
	}
	for _, c := range cases {
		_, id, err := Decode([]byte(c.in))
		if err == nil {
			t.Errorf("%.60s: accepted", c.in)
			continue
		}
		if err.Code != c.code || string(id) != c.id {
			t.Errorf("%.60s: got code %d id %q, want %d %q (%s)", c.in, err.Code, id, c.code, c.id, err.Message)
		}
	}
}

func TestCheckStructure(t *testing.T) {
	ok := []string{`1`, `"s"`, `[]`, `{}`, `{"a":{"a":1},"b":[{"a":1},{"a":2}]}`, `[[[]]]`, `{"a":[],"b":{}}`}
	for _, s := range ok {
		if err := CheckStructure([]byte(s)); err != nil {
			t.Errorf("%s: %v", s, err)
		}
	}
	bad := []string{``, `{"a":1,"a":2}`, `{"x":{"b":1,"b":1}}`, `[{"k":1,"k":1}]`, `1 2`, `{`, `{"a":}`}
	for _, s := range bad {
		if err := CheckStructure([]byte(s)); err == nil {
			t.Errorf("%s: accepted", s)
		}
	}
	if err := CheckStructure([]byte(`{"a":1,"a":2}`)); !errors.Is(err, ErrDuplicateKey) {
		t.Fatalf("want ErrDuplicateKey, got %v", err)
	}
	deep := strings.Repeat("[", MaxDepth) + strings.Repeat("]", MaxDepth)
	if err := CheckStructure([]byte(deep)); err != nil {
		t.Fatalf("depth %d rejected: %v", MaxDepth, err)
	}
	if err := CheckStructure([]byte("[" + deep + "]")); err == nil {
		t.Fatal("depth over limit accepted")
	}
}

func TestEncodeAndCanonical(t *testing.T) {
	b, err := json.Marshal(ErrorResponse(nil, NewError(CodeInvalidRequest, "bad %d", 1).WithData(map[string]int{"x": 1})))
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `{"jsonrpc":"2.0","error":{"code":-32600,"message":"bad 1","data":{"x":1}}}` {
		t.Fatalf("got %s", b)
	}
	b, _ = json.Marshal(ResultResponse(json.RawMessage(`"q"`), map[string]any{}))
	if string(b) != `{"jsonrpc":"2.0","id":"q","result":{}}` {
		t.Fatalf("got %s", b)
	}
	v, err := DecodeValue([]byte(`{"b":12345678901234567890,"a":"<x>","c":[1.50,true,null]}`))
	if err != nil {
		t.Fatal(err)
	}
	c, err := Canonical(v)
	if err != nil {
		t.Fatal(err)
	}
	if string(c) != `{"a":"<x>","b":12345678901234567890,"c":[1.50,true,null]}` {
		t.Fatalf("canonical = %s", c)
	}
	if _, err := DecodeValue([]byte(`{"a":1,"a":1}`)); err == nil {
		t.Fatal("duplicate accepted")
	}
	if _, err := Marshal(func() {}); err == nil {
		t.Fatal("marshal of func succeeded")
	}
	if e := NewError(1, "m"); e.Error() != "jsonrpc error 1: m" {
		t.Fatal(e.Error())
	}
}

func FuzzDecode(f *testing.F) {
	for _, s := range []string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x","arguments":{"a":[1,2]}}}`,
		`{"jsonrpc":"2.0","method":"n"}`,
		`{"jsonrpc":"2.0","id":"x","result":{"tools":[]}}`,
		`{"jsonrpc":"2.0","id":null,"error":{"code":1,"message":"m"}}`,
		`[{}]`, `{"a":1,"a":2}`, `{`, ``,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		m, _, err := Decode(data)
		if (m == nil) == (err == nil) {
			t.Fatalf("exactly one of message and error must be set: %v %v", m, err)
		}
		if err != nil {
			return
		}
		// Anything accepted must be one well-formed value without duplicate keys.
		if CheckStructure(data) != nil {
			t.Fatalf("accepted structurally invalid input %q", data)
		}
		switch m.Kind {
		case KindRequest:
			if m.ID == nil || m.Method == "" {
				t.Fatalf("request without id or method: %q", data)
			}
		case KindNotification:
			if m.ID != nil || m.Method == "" {
				t.Fatalf("bad notification: %q", data)
			}
		case KindResponse:
			if (m.Result == nil) == (m.Error == nil) {
				t.Fatalf("response needs exactly one of result and error: %q", data)
			}
		default:
			t.Fatalf("unknown kind %d", m.Kind)
		}
		if m.Params != nil && m.Params[0] != '{' {
			t.Fatalf("params not an object: %q", data)
		}
	})
}
