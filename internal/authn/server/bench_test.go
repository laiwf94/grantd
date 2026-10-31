package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// BenchmarkForwardAuth is the hot path: every proxied request asks /auth.
// The session is valid, the policy allows, and the upstream token is cached.
func BenchmarkForwardAuth(b *testing.B) {
	h := newHarness(b, harnessOpts{})
	br := h.browser()
	br.loginOIDC("alice", "alice-pass", "")
	req := httptest.NewRequest(http.MethodGet, "/auth", nil)
	req.Header.Set("X-Forwarded-Host", h.host)
	req.Header.Set("X-Forwarded-Uri", "/")
	for _, c := range br.jar.Cookies(mustURL(h.public)) {
		req.AddCookie(c)
	}
	handler := h.srv.Handler()
	b.ResetTimer()
	for b.Loop() {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			b.Fatalf("status %d", rec.Code)
		}
	}
}

func mustURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return u
}

// BenchmarkForwardAuthParallel measures the same path from all cores, which
// exercises the session store's lock.
func BenchmarkForwardAuthParallel(b *testing.B) {
	h := newHarness(b, harnessOpts{})
	br := h.browser()
	br.loginOIDC("alice", "alice-pass", "")
	cookies := br.jar.Cookies(mustURL(h.public))
	handler := h.srv.Handler()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			req := httptest.NewRequest(http.MethodGet, "/auth", nil)
			req.Header.Set("X-Forwarded-Host", h.host)
			for _, c := range cookies {
				req.AddCookie(c)
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				b.Errorf("status %d", rec.Code)
				return
			}
		}
	})
}
