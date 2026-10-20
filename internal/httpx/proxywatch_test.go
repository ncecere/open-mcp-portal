package httpx

import (
	"bytes"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func watchWithClock() (*ProxyWatch, *bytes.Buffer, *time.Time) {
	var buf bytes.Buffer
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	w := NewProxyWatch(slog.New(slog.NewTextHandler(&buf, nil)))
	w.now = func() time.Time { return now }
	return w, &buf, &now
}

// A request with X-Forwarded-For or Forwarded is counted; the warning is
// logged for the first, then at most once a minute.
func TestProxyWatchWarnsOncePerMinute(t *testing.T) {
	w, buf, now := watchWithClock()
	warn := func(header, value string) {
		r := httptest.NewRequest("GET", "/x", nil)
		r.RemoteAddr = "10.1.2.3:4444"
		r.Header.Set(header, value)
		w.Observe(r.Context(), r)
	}
	count := func() int { return strings.Count(buf.String(), "TRUSTED_PROXIES is empty") }

	warn("X-Forwarded-For", "203.0.113.9")
	if count() != 1 || !strings.Contains(buf.String(), "level=WARN") || !strings.Contains(buf.String(), "peer=10.1.2.3") {
		t.Fatalf("first request: %q", buf)
	}
	for i := 0; i < 50; i++ {
		warn("Forwarded", "for=203.0.113.9")
		*now = now.Add(time.Second)
	}
	if count() != 1 {
		t.Fatalf("a warning every request: %d in %q", count(), buf)
	}
	*now = now.Add(ProxyWarnEvery)
	warn("X-Forwarded-For", "203.0.113.9")
	if count() != 2 {
		t.Fatalf("after a minute: %d warnings", count())
	}
	if w.Total() != 52 {
		t.Errorf("total = %d, want 52", w.Total())
	}
	if strings.Contains(buf.String(), "203.0.113.9") {
		t.Error("the warning names a client address from the header")
	}
}

// Requests without a forwarding header are not counted, and a nil watch is a
// no-op (the chain builds none for correctly configured installs).
func TestProxyWatchIgnoresPlainRequests(t *testing.T) {
	w, buf, _ := watchWithClock()
	r := httptest.NewRequest("GET", "/x", nil)
	w.Observe(r.Context(), r)
	if buf.Len() != 0 || w.Total() != 0 {
		t.Fatalf("logged %q, total %d", buf, w.Total())
	}
	var none *ProxyWatch
	r.Header.Set("X-Forwarded-For", "203.0.113.9")
	none.Observe(r.Context(), r)
}
