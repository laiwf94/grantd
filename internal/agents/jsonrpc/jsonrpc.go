// Package jsonrpc decodes and encodes JSON-RPC 2.0 messages as MCP uses them.
//
// MCP narrows JSON-RPC 2.0: request IDs are strings or integers and never
// null, params are objects, and since revision 2025-06-18 a message is never a
// batch. Decode enforces all of that, plus rules a gateway needs so that it and
// the servers behind it read the same message the same way: the body must be
// valid UTF-8, hold exactly one JSON value, nest at most MaxDepth levels and
// repeat no object key.
package jsonrpc

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"unicode/utf8"
)

// Version is the only accepted value of the "jsonrpc" member.
const Version = "2.0"

// Standard JSON-RPC 2.0 error codes.
const (
	CodeParseError     = -32700
	CodeInvalidRequest = -32600
	CodeMethodNotFound = -32601
	CodeInvalidParams  = -32602
	CodeInternalError  = -32603
)

// Decoding limits.
const (
	MaxDepth       = 64
	MaxMethodBytes = 256
	MaxIDBytes     = 256
)

// Kind says what a decoded message is.
type Kind int

// Message kinds.
const (
	KindRequest Kind = iota + 1
	KindNotification
	KindResponse
)

// Message is one decoded JSON-RPC message.
type Message struct {
	Kind   Kind
	ID     json.RawMessage // request and response only; the exact bytes received
	Method string          // request and notification only
	Params json.RawMessage // nil when absent; otherwise a JSON object
	Result json.RawMessage // response only
	Error  *Error          // response only
}

// Error is a JSON-RPC error object. It is also a Go error.
type Error struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

func (e *Error) Error() string { return fmt.Sprintf("jsonrpc error %d: %s", e.Code, e.Message) }

// NewError builds an error object.
func NewError(code int, format string, args ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...)}
}

// WithData returns a copy of e carrying data.
func (e *Error) WithData(data any) *Error {
	c := *e
	c.Data = data
	return &c
}

// Response is an outgoing response. Exactly one of Result and Error is set.
// ID is omitted when the request's ID could not be read.
type Response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *Error          `json:"error,omitempty"`
}

// Request is an outgoing request or, without ID, notification.
type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  any             `json:"params,omitempty"`
}

// ResultResponse builds a success response.
func ResultResponse(id json.RawMessage, result any) Response {
	return Response{JSONRPC: Version, ID: id, Result: result}
}

// ErrorResponse builds an error response.
func ErrorResponse(id json.RawMessage, err *Error) Response {
	return Response{JSONRPC: Version, ID: id, Error: err}
}

var integerID = regexp.MustCompile(`^-?(0|[1-9][0-9]*)$`)

type wire struct {
	JSONRPC *string         `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  *string         `json:"method"`
	Params  json.RawMessage `json:"params"`
	Result  json.RawMessage `json:"result"`
	Error   json.RawMessage `json:"error"`
}

// Decode parses one message. On failure it returns a JSON-RPC error with the
// code a server should answer with, and the message's ID when it was readable
// (so the error response can carry it).
func Decode(data []byte) (*Message, json.RawMessage, *Error) {
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return nil, nil, NewError(CodeParseError, "empty body")
	}
	if !utf8.Valid(data) {
		return nil, nil, NewError(CodeParseError, "body is not valid UTF-8")
	}
	if data[0] == '[' {
		if err := CheckStructure(data); err != nil {
			return nil, nil, NewError(CodeParseError, "invalid JSON: %v", err)
		}
		return nil, nil, NewError(CodeInvalidRequest, "batch requests are not supported: send one JSON-RPC message per HTTP request")
	}
	if err := CheckStructure(data); err != nil {
		return nil, nil, NewError(CodeParseError, "invalid JSON: %v", err)
	}
	if data[0] != '{' {
		return nil, nil, NewError(CodeInvalidRequest, "a message must be a JSON object")
	}
	var w wire
	if err := json.Unmarshal(data, &w); err != nil {
		return nil, nil, NewError(CodeInvalidRequest, "invalid message: %v", err)
	}
	id, idErr := checkID(w.ID)
	if w.JSONRPC == nil || *w.JSONRPC != Version {
		return nil, id, NewError(CodeInvalidRequest, `"jsonrpc" must be "2.0"`)
	}
	isResponse := w.Result != nil || w.Error != nil
	if w.Method != nil {
		if isResponse {
			return nil, id, NewError(CodeInvalidRequest, "a message cannot have both method and result/error")
		}
		m := &Message{Method: *w.Method, Kind: KindNotification}
		if m.Method == "" || len(m.Method) > MaxMethodBytes {
			return nil, id, NewError(CodeInvalidRequest, "method must be 1 to %d bytes", MaxMethodBytes)
		}
		if w.ID != nil {
			if idErr != nil {
				return nil, nil, idErr
			}
			m.Kind, m.ID = KindRequest, id
		}
		if w.Params != nil {
			if w.Params[0] != '{' {
				return nil, m.ID, NewError(CodeInvalidRequest, "params must be a JSON object")
			}
			m.Params = w.Params
		}
		return m, m.ID, nil
	}
	if !isResponse {
		return nil, id, NewError(CodeInvalidRequest, "a message needs a method, a result or an error")
	}
	if w.Result != nil && w.Error != nil {
		return nil, id, NewError(CodeInvalidRequest, "a response cannot have both result and error")
	}
	m := &Message{Kind: KindResponse}
	switch {
	case w.ID == nil || string(w.ID) == "null":
		// MCP lets an error response omit the id (JSON-RPC uses null) when
		// the request's id could not be read.
		if w.Error == nil {
			return nil, nil, NewError(CodeInvalidRequest, "only an error response may omit the id")
		}
	case idErr != nil:
		return nil, nil, idErr
	default:
		m.ID = id
	}
	if w.Result != nil {
		m.Result = w.Result
		return m, m.ID, nil
	}
	var e struct {
		Code    *int    `json:"code"`
		Message *string `json:"message"`
		Data    any     `json:"data"`
	}
	dec := json.NewDecoder(bytes.NewReader(w.Error))
	dec.UseNumber()
	if err := dec.Decode(&e); err != nil || e.Code == nil || e.Message == nil {
		return nil, m.ID, NewError(CodeInvalidRequest, "error must be an object with an integer code and a message")
	}
	m.Error = &Error{Code: *e.Code, Message: *e.Message, Data: e.Data}
	return m, m.ID, nil
}

// checkID validates a request ID: a string or an integer, never null.
func checkID(raw json.RawMessage) (json.RawMessage, *Error) {
	if raw == nil {
		return nil, nil
	}
	if len(raw) > MaxIDBytes {
		return nil, NewError(CodeInvalidRequest, "id is longer than %d bytes", MaxIDBytes)
	}
	switch {
	case raw[0] == '"':
		return raw, nil
	case integerID.Match(raw):
		return raw, nil
	case string(raw) == "null":
		return nil, NewError(CodeInvalidRequest, "id must not be null")
	default:
		return nil, NewError(CodeInvalidRequest, "id must be a string or an integer")
	}
}

// ErrDuplicateKey reports an object key that appears twice.
var ErrDuplicateKey = errors.New("duplicate object key")

// CheckStructure verifies that data is exactly one well-formed JSON value,
// nested at most MaxDepth deep, with no repeated key in any object.
//
// Duplicate keys matter at a security boundary: parsers disagree on which
// copy wins, so a gateway and an upstream could otherwise validate and
// execute different arguments.
func CheckStructure(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	type frame struct {
		obj     bool
		keyNext bool
		keys    map[string]struct{}
	}
	var stack []frame
	done := false
	valueDone := func() {
		if n := len(stack); n > 0 {
			if stack[n-1].obj {
				stack[n-1].keyNext = true
			}
		} else {
			done = true
		}
	}
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			if !done {
				return io.ErrUnexpectedEOF
			}
			return nil
		}
		if err != nil {
			return err
		}
		if done {
			return errors.New("unexpected data after the JSON value")
		}
		if n := len(stack); n > 0 && stack[n-1].obj && stack[n-1].keyNext {
			if tok == json.Delim('}') {
				stack = stack[:n-1]
				valueDone()
				continue
			}
			k, _ := tok.(string)
			if _, dup := stack[n-1].keys[k]; dup {
				return fmt.Errorf("%w %q", ErrDuplicateKey, k)
			}
			stack[n-1].keys[k] = struct{}{}
			stack[n-1].keyNext = false
			continue
		}
		switch tok {
		case json.Delim('{'), json.Delim('['):
			if len(stack) >= MaxDepth {
				return fmt.Errorf("nested deeper than %d levels", MaxDepth)
			}
			obj := tok == json.Delim('{')
			f := frame{obj: obj, keyNext: obj}
			if obj {
				f.keys = map[string]struct{}{}
			}
			stack = append(stack, f)
		case json.Delim(']'), json.Delim('}'):
			stack = stack[:len(stack)-1]
			valueDone()
		default:
			valueDone()
		}
	}
}

// Marshal encodes v without HTML escaping, so hashes and previews of
// arguments read naturally.
func Marshal(v any) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(b.Bytes(), []byte("\n")), nil
}

// DecodeValue parses one JSON value, keeping numbers as json.Number so that
// re-encoding reproduces them exactly.
func DecodeValue(data []byte) (any, error) {
	if err := CheckStructure(data); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	return v, nil
}

// Canonical re-encodes a decoded value deterministically: object keys sorted,
// numbers as received, no insignificant whitespace. Equal values give equal
// bytes, which is what argument hashes need.
func Canonical(v any) ([]byte, error) { return Marshal(v) }
