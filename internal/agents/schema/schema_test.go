package schema

import (
	"errors"
	"strings"
	"testing"

	"github.com/laiwf94/authz/internal/agents/jsonrpc"
)

func mustCompile(t testing.TB, src string) *Schema {
	t.Helper()
	s, err := Compile([]byte(src))
	if err != nil {
		t.Fatalf("compile %s: %v", src, err)
	}
	return s
}

func check(t *testing.T, s *Schema, value string) error {
	t.Helper()
	v, err := jsonrpc.DecodeValue([]byte(value))
	if err != nil {
		t.Fatalf("bad test value %s: %v", value, err)
	}
	return s.Validate(v)
}

func TestValidate(t *testing.T) {
	s := mustCompile(t, `{
	  "type": "object",
	  "title": "args", "description": "d", "$comment": "c",
	  "required": ["name"],
	  "additionalProperties": false,
	  "properties": {
	    "name":  {"type": "string", "minLength": 1, "maxLength": 5, "pattern": "^[a-z]+$"},
	    "count": {"type": "integer", "minimum": 1, "maximum": 10},
	    "ratio": {"type": ["number", "null"], "minimum": -1.5, "maximum": 1.5},
	    "mode":  {"enum": ["fast", "slow", 1, {"a": [1]}]},
	    "tags":  {"type": "array", "minItems": 1, "maxItems": 2, "items": {"type": "string", "maxLength": 3}},
	    "flag":  {"type": "boolean"},
	    "any":   {},
	    "odd key": {"type": "string"}
	  }
	}`)
	ok := []string{
		`{"name":"abc"}`,
		`{"name":"abcde"}`,
		`{"name":"a","count":1,"ratio":null,"mode":"slow","tags":["x","yz"],"flag":true,"any":[{}]}`,
		`{"name":"a","count":10.0,"ratio":1.5,"mode":1.0}`,
		`{"name":"a","mode":1e0}`,
		`{"name":"a","mode":{"a":[1.0]}}`,
		`{"name":"a","odd key":"v"}`,
	}
	for _, v := range ok {
		if err := check(t, s, v); err != nil {
			t.Errorf("%s: %v", v, err)
		}
	}
	bad := map[string]string{
		`[]`:                                "$: must be object",
		`{}`:                                `$: missing required property "name"`,
		`{"name":""}`:                       "$.name: must be at least 1 characters",
		`{"name":"abcdef"}`:                 "$.name: must be at most 5 characters",
		`{"name":"ABC"}`:                    "$.name: does not match the required pattern",
		`{"name":1}`:                        "$.name: must be string",
		`{"name":"a","count":0}`:            "$.count: must be at least 1",
		`{"name":"a","count":11}`:           "$.count: must be at most 10",
		`{"name":"a","count":1.5}`:          "$.count: must be integer",
		`{"name":"a","ratio":-2}`:           "$.ratio: must be at least -1.5",
		`{"name":"a","ratio":"x"}`:          "$.ratio: must be null or number",
		`{"name":"a","mode":"medium"}`:      "$.mode: must be one of the allowed values",
		`{"name":"a","tags":[]}`:            "$.tags: must have at least 1 items",
		`{"name":"a","tags":["a","b","c"]}`: "$.tags: must have at most 2 items",
		`{"name":"a","tags":["long"]}`:      "$.tags[0]: must be at most 3 characters",
		`{"name":"a","flag":"yes"}`:         "$.flag: must be boolean",
		`{"name":"a","extra":1}`:            `$: property "extra" is not allowed`,
		`{"name":"a","odd key":2}`:          `$["odd key"]: must be string`,
		`{"name":"a","count":1e999}`:        "$.count: must be integer",
	}
	for v, want := range bad {
		err := check(t, s, v)
		if err == nil || err.Error() != want {
			t.Errorf("%s: got %v, want %s", v, err, want)
		}
		var ve *ValidationError
		if err != nil && !errors.As(err, &ve) {
			t.Errorf("%s: not a ValidationError", v)
		}
	}
	if err := s.Validate(struct{}{}); err == nil || !strings.Contains(err.Error(), "unsupported value type") {
		t.Fatalf("got %v", err)
	}
}

func TestPathPrefix(t *testing.T) {
	s := mustCompile(t, `{"type":"string","x-path-prefix":["/sandbox","/srv/data/","reports"]}`)
	ok := []string{`"/sandbox"`, `"/sandbox/a.txt"`, `"/sandbox/a/b/c"`, `"/srv/data/x"`, `"reports/q1.csv"`, `"reports"`}
	for _, v := range ok {
		if err := check(t, s, v); err != nil {
			t.Errorf("%s: %v", v, err)
		}
	}
	bad := map[string]string{
		`"../../etc/passwd"`:       `".." segments`,
		`"/sandbox/../etc/passwd"`: `".." segments`,
		`"/sandbox/a/.."`:          `".." segments`,
		`"/sandbox/./a"`:           "canonical form",
		`"/sandbox//a"`:            "canonical form",
		`"//sandbox/a"`:            "canonical form",
		`"/sandboxed/a"`:           "outside the allowed directories",
		`"/etc/passwd"`:            "outside the allowed directories",
		`"sandbox/a"`:              "outside the allowed directories",
		`"/sandbox\\a"`:            "backslashes",
		`"/sandbox/a\u0000b"`:      "control characters",
		`""`:                       "must be 1 to",
		`"/srv"`:                   "outside the allowed directories",
	}
	for v, want := range bad {
		err := check(t, s, v)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: got %v, want %q", v, err, want)
		}
	}
	if err := check(t, s, `"/`+strings.Repeat("a", MaxPathBytes)+`"`); err == nil {
		t.Error("over-long path accepted")
	}
	root := mustCompile(t, `{"x-path-prefix":["/"]}`)
	if err := check(t, root, `"/anything/at/all"`); err != nil {
		t.Errorf("root prefix: %v", err)
	}
	if err := check(t, root, `"relative"`); err == nil {
		t.Error("root prefix allowed a relative path")
	}
	if err := check(t, root, `5`); err == nil {
		t.Error("non-string accepted by a path check")
	}
	if !root.UsesAllowLists() || !mustCompile(t, `{"items":{"properties":{"u":{"x-allowed-hosts":["a.com"]}}}}`).UsesAllowLists() ||
		mustCompile(t, `{"properties":{"a":{"maxLength":3}}}`).UsesAllowLists() {
		t.Error("UsesAllowLists")
	}
}

func TestAllowedHosts(t *testing.T) {
	s := mustCompile(t, `{"type":"string","x-allowed-hosts":["api.example.com","*.example.org","LOCALHOST:8443","127.0.0.1","[::1]:9000"]}`)
	ok := []string{
		`"https://api.example.com/v1?q=1"`,
		`"http://api.example.com"`,
		`"https://API.Example.com./x"`,
		`"https://api.example.com:443/x"`,
		`"https://a.example.org/x"`,
		`"https://b.a.example.org/x"`,
		`"https://localhost:8443/x"`,
		`"http://127.0.0.1/x"`,
		`"http://[::1]:9000/x"`,
	}
	for _, v := range ok {
		if err := check(t, s, v); err != nil {
			t.Errorf("%s: %v", v, err)
		}
	}
	bad := map[string]string{
		`"https://example.org/x"`:                    "not in the allowed list",
		`"https://api.example.com.evil.net/"`:        "not in the allowed list",
		`"https://evilapi.example.com/"`:             "not in the allowed list",
		`"https://api.example.com:8443/"`:            "not in the allowed list",
		`"https://localhost/"`:                       "not in the allowed list",
		`"http://169.254.169.254/latest/meta-data/"`: "not in the allowed list",
		`"ftp://api.example.com/"`:                   "http or https",
		`"file:///etc/passwd"`:                       "http or https",
		`"https://user:pw@api.example.com/"`:         "no user information",
		`"https:api.example.com"`:                    "must have a host",
		`"/relative/path"`:                           "http or https",
		`"https://api.example.com\\@evil.net/"`:      "backslashes",
		`"https://api.example.com /"`:                "without spaces",
		`"https://exämple.com/"`:                     "printable ASCII",
		`"https://api.example.com:99999/"`:           "port must be",
		`"https://bad_host.example.com/"`:            "not a valid host name",
		`"http://[::1/"`:                             "does not parse",
	}
	for v, want := range bad {
		err := check(t, s, v)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: got %v, want %q", v, err, want)
		}
	}
	if err := check(t, s, `"https://api.example.com/`+strings.Repeat("a", MaxURLBytes)+`"`); err == nil {
		t.Error("over-long URL accepted")
	}
}

func TestCompileErrors(t *testing.T) {
	cases := map[string]string{
		`[]`:                                               "must be an object",
		`{"maxLenght":3}`:                                  `unsupported keyword "maxLenght"`,
		`{"type":"text"}`:                                  `unknown type "text"`,
		`{"type":[]}`:                                      "type must be",
		`{"type":["string","string"]}`:                     `repeats "string"`,
		`{"type":5}`:                                       "type must be",
		`{"enum":[]}`:                                      "enum must be",
		`{"enum":[1,1.0]}`:                                 "repeats 1",
		`{"pattern":"("}`:                                  "not a valid RE2",
		`{"pattern":"(a)\\1"}`:                             "not a valid RE2",
		`{"pattern":"a{1001}"}`:                            "not a valid RE2",
		`{"pattern":5}`:                                    "pattern must be",
		`{"maxLength":-1}`:                                 "maxLength must be",
		`{"maxLength":1.5}`:                                "maxLength must be",
		`{"maxLength":"3"}`:                                "maxLength must be",
		`{"minLength":3,"maxLength":2}`:                    "minLength is greater",
		`{"minItems":3,"maxItems":2}`:                      "minItems is greater",
		`{"minimum":3,"maximum":2}`:                        "minimum is greater",
		`{"minimum":"1"}`:                                  "minimum must be a number",
		`{"maximum":1e999}`:                                "finite number",
		`{"required":"a"}`:                                 "required must be",
		`{"required":["a","a"]}`:                           `repeats "a"`,
		`{"properties":[]}`:                                "properties must be",
		`{"properties":{"a":5}}`:                           "schema $.a: must be an object",
		`{"additionalProperties":{}}`:                      "must be a boolean",
		`{"items":[]}`:                                     "schema $[]: must be an object",
		`{"x-path-prefix":[]}`:                             "x-path-prefix must be",
		`{"x-path-prefix":["/a/../b"]}`:                    `".." segments`,
		`{"x-path-prefix":["/a//b"]}`:                      "canonical form",
		`{"x-allowed-hosts":["*.1.2.3.4"]}`:                "cannot have a wildcard",
		`{"x-allowed-hosts":["a b"]}`:                      "must be a host name",
		`{"x-allowed-hosts":["a.com:0"]}`:                  "port must be",
		`{"x-allowed-hosts":"a.com"}`:                      "x-allowed-hosts must be",
		`{"type":"integer","x-path-prefix":["/a"]}`:        "apply to strings",
		`{"x-path-prefix":["/a"],"x-allowed-hosts":["a"]}`: "not both",
		`{"title":1}`:                                      "title must be a string",
		`{"a":1,"a":2}`:                                    "duplicate object key",
	}
	for src, want := range cases {
		_, err := Compile([]byte(src))
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: got %v, want %q", src, err, want)
		}
	}
	deep := strings.Repeat(`{"items":`, MaxDepth+1) + `{}` + strings.Repeat(`}`, MaxDepth+1)
	if _, err := Compile([]byte(deep)); err == nil || !strings.Contains(err.Error(), "nested deeper") {
		t.Errorf("deep schema: %v", err)
	}
	var props []string
	for i := 0; i < MaxProperties; i++ {
		props = append(props, `"p`+strings.Repeat("x", i%3)+string(rune('a'+i%26))+itoa(i)+`":{"properties":{"a":{},"b":{},"c":{},"d":{},"e":{},"f":{},"g":{},"h":{}}}`)
	}
	if _, err := Compile([]byte(`{"properties":{` + strings.Join(props, ",") + `}}`)); err == nil || !strings.Contains(err.Error(), "subschemas") {
		t.Errorf("node limit: %v", err)
	}
}

func itoa(i int) string {
	const d = "0123456789"
	if i < 10 {
		return d[i : i+1]
	}
	return itoa(i/10) + d[i%10:i%10+1]
}

func BenchmarkValidate(b *testing.B) {
	s := mustCompile(b, `{"type":"object","required":["path"],"additionalProperties":false,"properties":{
	  "path":{"type":"string","maxLength":256,"x-path-prefix":["/sandbox"]},
	  "url":{"type":"string","x-allowed-hosts":["api.example.com"]},
	  "mode":{"enum":["r","w"]}, "n":{"type":"integer","minimum":0,"maximum":100}}}`)
	v, _ := jsonrpc.DecodeValue([]byte(`{"path":"/sandbox/reports/q1.csv","url":"https://api.example.com/x","mode":"r","n":5}`))
	for b.Loop() {
		if err := s.Validate(v); err != nil {
			b.Fatal(err)
		}
	}
}

func FuzzCompileValidate(f *testing.F) {
	f.Add([]byte(`{"type":"object","properties":{"p":{"x-path-prefix":["/s"]}}}`), []byte(`{"p":"/s/a"}`))
	f.Add([]byte(`{"type":"string","x-allowed-hosts":["*.a.com"]}`), []byte(`"https://b.a.com"`))
	f.Add([]byte(`{"enum":[1,"a",null],"pattern":"^a"}`), []byte(`"ab"`))
	f.Add([]byte(`{"items":{"maximum":3},"maxItems":2}`), []byte(`[1,2]`))
	f.Fuzz(func(t *testing.T, schemaSrc, value []byte) {
		s, err := Compile(schemaSrc)
		if err != nil {
			return
		}
		v, err := jsonrpc.DecodeValue(value)
		if err != nil {
			return
		}
		err1 := s.Validate(v)
		err2 := s.Validate(v)
		if (err1 == nil) != (err2 == nil) || err1 != nil && err1.Error() != err2.Error() {
			t.Fatalf("validation is not deterministic: %v vs %v", err1, err2)
		}
		var ve *ValidationError
		if err1 != nil && !errors.As(err1, &ve) {
			t.Fatalf("error is not a ValidationError: %v", err1)
		}
	})
}
