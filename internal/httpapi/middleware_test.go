package httpapi

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/ncecere/open-mcp-portal/internal/config"
	"github.com/ncecere/open-mcp-portal/internal/httpx"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

func testDeps() Deps {
	return Deps{Config: config.Defaults(), Health: NewHealth(nil), Log: testutil.Logger()}
}

// Every response carries a request ID and the security headers; the ID is
// the one handlers see (and log, and audit).
func TestChainSetsRequestIDAndSecurityHeaders(t *testing.T) {
	var seen string
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/x", func(w http.ResponseWriter, r *http.Request) {
		seen = httpx.RequestID(r.Context())
		httpx.JSON(w, http.StatusOK, map[string]bool{"ok": true})
	})
	w := httptest.NewRecorder()
	chain(mux, testDeps()).ServeHTTP(w, httptest.NewRequest("GET", "/v1/x", nil))
	h := w.Header()
	if id := h.Get("X-Request-ID"); id == "" || id != seen {
		t.Errorf("X-Request-ID = %q, handler saw %q", id, seen)
	}
	for k, v := range map[string]string{
		"X-Content-Type-Options": "nosniff",
		"Referrer-Policy":        "strict-origin-when-cross-origin",
		"X-Frame-Options":        "DENY",
		"Content-Type":           "application/json; charset=utf-8",
		"Cache-Control":          "no-store",
	} {
		if got := h.Get(k); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
	if strings.TrimSpace(w.Body.String()) != `{"data":{"ok":true}}` {
		t.Errorf("body = %s", w.Body)
	}
}

// A panicking handler becomes a 500 error envelope, not a dropped connection.
func TestChainRecoversPanics(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /boom", func(http.ResponseWriter, *http.Request) { panic("boom") })
	w := httptest.NewRecorder()
	chain(mux, testDeps()).ServeHTTP(w, httptest.NewRequest("GET", "/boom", nil))
	if w.Code != http.StatusInternalServerError || !strings.Contains(w.Body.String(), `"code":"internal"`) {
		t.Fatalf("panic = %d %s", w.Code, w.Body)
	}
}

// Health: liveness never checks dependencies; readiness does and fails while
// draining.
func TestHealth(t *testing.T) {
	failing := NewHealth(map[string]func(context.Context) error{
		"postgres": func(context.Context) error { return context.DeadlineExceeded },
	})
	w := httptest.NewRecorder()
	failing.Live(w, httptest.NewRequest("GET", "/healthz", nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"status":"ok"`) {
		t.Errorf("live = %d %s", w.Code, w.Body)
	}
	w = httptest.NewRecorder()
	failing.Ready(w, httptest.NewRequest("GET", "/readyz", nil))
	if w.Code != 503 || !strings.Contains(w.Body.String(), `"postgres":"unavailable"`) {
		t.Errorf("ready = %d %s", w.Code, w.Body)
	}
	ok := NewHealth(map[string]func(context.Context) error{"postgres": func(context.Context) error { return nil }})
	w = httptest.NewRecorder()
	ok.Ready(w, httptest.NewRequest("GET", "/readyz", nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"postgres":"ok"`) {
		t.Errorf("ready = %d %s", w.Code, w.Body)
	}
	ok.SetDraining()
	w = httptest.NewRecorder()
	ok.Ready(w, httptest.NewRequest("GET", "/readyz", nil))
	if w.Code != 503 || !strings.Contains(w.Body.String(), `"status":"draining"`) {
		t.Errorf("draining = %d %s", w.Code, w.Body)
	}
}

// Missing If-Match is 428, malformed is 400, quoted and weak forms are read.
func TestIfMatch(t *testing.T) {
	cases := []struct {
		header string
		code   int
		rev    int64
	}{
		{"", 428, 0}, {`"3"`, 0, 3}, {`W/"4"`, 0, 4}, {"5", 0, 5}, {`"x"`, 400, 0}, {`"0"`, 400, 0},
	}
	for _, c := range cases {
		r := httptest.NewRequest("PATCH", "/", nil)
		if c.header != "" {
			r.Header.Set("If-Match", c.header)
		}
		w := httptest.NewRecorder()
		rev, ok := ifMatch(w, r)
		if (c.code == 0) != ok || (ok && rev != c.rev) || (!ok && w.Code != c.code) {
			t.Errorf("If-Match %q: rev=%d ok=%v code=%d", c.header, rev, ok, w.Code)
		}
	}
}

// A deployment behind a proxy with TRUSTED_PROXIES empty gets the warning
// (at most once a minute); a correctly configured install, a development
// install and requests without forwarding headers get none.
func TestChainWarnsAboutMissingTrustedProxies(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/x", func(w http.ResponseWriter, _ *http.Request) { httpx.JSON(w, http.StatusOK, true) })
	run := func(mutate func(*config.Config), forwarded bool, requests int) int {
		var buf bytes.Buffer
		d := testDeps()
		d.Log = slog.New(slog.NewTextHandler(&buf, nil))
		d.Config.AppURL = "https://mcp.example.com"
		mutate(&d.Config)
		h := chain(mux, d)
		for i := 0; i < requests; i++ {
			r := httptest.NewRequest("GET", "/v1/x", nil)
			r.RemoteAddr = "10.1.2.3:5555"
			if forwarded {
				r.Header.Set("X-Forwarded-For", "198.51.100.7")
			}
			h.ServeHTTP(httptest.NewRecorder(), r)
		}
		return strings.Count(buf.String(), "TRUSTED_PROXIES is empty")
	}
	none := func(*config.Config) {}
	if n := run(none, true, 20); n != 1 {
		t.Errorf("behind a proxy, TRUSTED_PROXIES empty: %d warnings in 20 requests, want 1", n)
	}
	if n := run(none, false, 5); n != 0 {
		t.Errorf("no forwarding header: %d warnings", n)
	}
	trusted := func(c *config.Config) { c.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")} }
	if n := run(trusted, true, 5); n != 0 {
		t.Errorf("TRUSTED_PROXIES set: %d warnings", n)
	}
	dev := func(c *config.Config) { c.AppURL = "http://localhost:8088" }
	if n := run(dev, true, 5); n != 0 {
		t.Errorf("development install: %d warnings", n)
	}
}
