package upstream

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

func testClient(allowPrivate bool) *Client {
	return &Client{AllowPrivate: allowPrivate, Log: slog.New(slog.DiscardHandler)}
}

func byKey(caps []Capability) map[string]Capability {
	out := map[string]Capability{}
	for _, c := range caps {
		out[c.Kind+" "+c.Name] = c
	}
	return out
}

func TestDiscoverEveryKind(t *testing.T) {
	fake := testutil.NewFakeMCP(t)
	fake.RequireHeader("X-API-Key", "k-123456789")
	c := testClient(true)
	tgt := Target{URL: fake.URL(), Credentials: []Credential{{Kind: CredHeader, Name: "X-API-Key", Value: "k-123456789"}}, Timeout: 5 * time.Second}
	d, err := c.Discover(context.Background(), tgt)
	if err != nil {
		t.Fatal(err)
	}
	if d.ServerName != "fake-status" || d.ServerVersion != "1.0.0" || d.ProtocolVersion == "" {
		t.Fatalf("server info = %+v", d)
	}
	if n := CountKinds(d.Capabilities); n != (Counts{Tools: 3, Resources: 1, ResourceTemplates: 1, Prompts: 1}) {
		t.Fatalf("counts = %+v", n)
	}
	caps := byKey(d.Capabilities)
	tool := caps["tool check_outage"]
	if tool.Title != "Check outage" || !strings.Contains(string(tool.Definition), `"service"`) || len(tool.Fingerprint) != 64 {
		t.Fatalf("check_outage = %+v", tool)
	}
	if !strings.Contains(string(caps["tool create_ticket"].Definition), `"destructiveHint":true`) {
		t.Fatalf("annotations missing: %s", caps["tool create_ticket"].Definition)
	}
	if r := caps["resource status://services"]; r.Title != "Services" || !strings.Contains(string(r.Definition), `"mimeType":"text/plain"`) {
		t.Fatalf("resource = %+v", r)
	}
	if _, ok := caps["resource_template status://services/{service}"]; !ok {
		t.Fatalf("template missing: %v", caps)
	}
	if p := caps["prompt incident_summary"]; !strings.Contains(string(p.Definition), `"arguments"`) {
		t.Fatalf("prompt = %+v", p)
	}

	// Every page is read; the result is the same.
	fake.SetPageSize(1)
	paged, err := c.Discover(context.Background(), tgt)
	if err != nil || len(paged.Capabilities) != len(d.Capabilities) {
		t.Fatalf("paged = %d, %v", len(paged.Capabilities), err)
	}
	for k, v := range byKey(paged.Capabilities) {
		if caps[k].Fingerprint != v.Fingerprint {
			t.Errorf("%s: fingerprint differs when paged", k)
		}
	}

	// A changed description changes only that fingerprint.
	fake.SetPageSize(0)
	fake.SetDescription("check_outage", "Now also reports planned maintenance.")
	again, err := c.Discover(context.Background(), tgt)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range byKey(again.Capabilities) {
		if changed := caps[k].Fingerprint != v.Fingerprint; changed != (k == "tool check_outage") {
			t.Errorf("%s: changed = %v", k, changed)
		}
	}
}

func TestDiscoverErrorClasses(t *testing.T) {
	fake := testutil.NewFakeMCP(t)
	fake.RequireHeader("Authorization", "Bearer right-value")
	ctx := context.Background()
	var e *Error

	// Wrong credentials: auth, with the status, never the value.
	_, err := testClient(true).Discover(ctx, Target{URL: fake.URL(), Credentials: []Credential{{Kind: CredHeader, Name: "Authorization", Value: "Bearer wrong-value"}}, Timeout: 5 * time.Second})
	if !errors.As(err, &e) || e.Class != ClassAuth || e.HTTPStatus != 401 || strings.Contains(e.Message, "wrong-value") {
		t.Fatalf("wrong key = %#v", err)
	}
	// The private address rule applies when dialling.
	if _, err := testClient(false).Discover(ctx, Target{URL: fake.URL(), Timeout: 5 * time.Second}); !errors.As(err, &e) || e.Class != ClassNotAllowed {
		t.Fatalf("loopback without the allowance = %v", err)
	}
	// Redirects are never followed.
	redirect := httptest.NewServer(http.RedirectHandler(fake.URL(), http.StatusTemporaryRedirect))
	defer redirect.Close()
	if _, err := testClient(true).Discover(ctx, Target{URL: redirect.URL, Timeout: 5 * time.Second}); !errors.As(err, &e) || e.Class != ClassNotAllowed {
		t.Fatalf("redirect = %v", err)
	}
	// 404.
	missing := httptest.NewServer(http.NotFoundHandler())
	defer missing.Close()
	if _, err := testClient(true).Discover(ctx, Target{URL: missing.URL + "/mcp", Timeout: 5 * time.Second}); !errors.As(err, &e) || e.Class != ClassNotFound {
		t.Fatalf("404 = %v", err)
	}
	// Nothing listening: unavailable.
	if _, err := testClient(true).Discover(ctx, Target{URL: "http://127.0.0.1:1/mcp", Timeout: 2 * time.Second}); !errors.As(err, &e) || e.Class != ClassUnavailable {
		t.Fatalf("closed port = %v", err)
	}
	// A response over the cap.
	small := testClient(true)
	small.MaxResponseBytes = 64
	_, err = small.Discover(ctx, Target{URL: fake.URL(), Credentials: []Credential{{Kind: CredHeader, Name: "Authorization", Value: "Bearer right-value"}}, Timeout: 5 * time.Second})
	if !errors.As(err, &e) || e.Class != ClassTooLarge {
		t.Fatalf("over the cap = %v", err)
	}
	// A server that never answers: timeout.
	hang := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(time.Second):
		}
	}))
	defer hang.Close()
	start := time.Now()
	if _, err := testClient(true).Discover(ctx, Target{URL: hang.URL, Timeout: 300 * time.Millisecond}); !errors.As(err, &e) || e.Class != ClassTimeout || time.Since(start) > 3*time.Second {
		t.Fatalf("hang = %v after %s", err, time.Since(start))
	}
}

func TestSafeMessage(t *testing.T) {
	got := SafeMessage("bad header  sentinel-123 and Bearer abc.def and api_key=xyz\n", "sentinel-123")
	if strings.Contains(got, "sentinel-123") || strings.Contains(got, "abc.def") || strings.Contains(got, "xyz") || strings.Contains(got, "\n") {
		t.Fatalf("SafeMessage = %q", got)
	}
	if n := len([]rune(SafeMessage(strings.Repeat("x", 1000), ""))); n != MaxMessage {
		t.Fatalf("length = %d", n)
	}
}

func TestErrorDetail(t *testing.T) {
	cases := map[string]string{
		"":                                      "",
		"<html><body>Bad Gateway</body></html>": "",
		"bad request: missing required Authorization header\n":                                     "bad request: missing required Authorization header",
		`{"error":"invalid_request","error_description":"Resource not accessible by integration"}`: "Resource not accessible by integration",
		`{"message":"Not Found","documentation_url":"https://docs.github.com"}`:                    "Not Found",
		`{"error":{"code":403,"message":"Resource not accessible"}}`:                               "Resource not accessible",
		`{"detail":"Repository access blocked"}`:                                                   "Repository access blocked",
		"event: message\ndata: {\"message\":\"from SSE\"}\n\n":                                     "from SSE",
		`{"message":"cut off`: "",
		"bin\x00ary":          "",
	}
	for body, want := range cases {
		if got := errorDetail(body); got != want {
			t.Errorf("errorDetail(%q) = %q, want %q", body, got, want)
		}
	}
}

func TestErrorBodyExplainsFailure(t *testing.T) {
	const token = "ghu_SENTINELtoken1234567890"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		// A server that echoes the caller's token in its error.
		_, _ = w.Write([]byte(`{"message":"Resource not accessible by integration (token ` + token + `)"}`))
	}))
	defer srv.Close()
	_, err := testClient(true).Discover(context.Background(), Target{URL: srv.URL, BearerToken: token, Timeout: 5 * time.Second})
	var e *Error
	if !errors.As(err, &e) || e.Class != ClassBadRequest {
		t.Fatalf("got %v", err)
	}
	if !strings.Contains(e.Message, "HTTP 400") || !strings.Contains(e.Message, "Resource not accessible by integration") {
		t.Errorf("message lacks the server's reason: %q", e.Message)
	}
	if strings.Contains(e.Message, token) || strings.Contains(e.Message, "SENTINEL") {
		t.Errorf("message carries the token: %q", e.Message)
	}
	if len([]rune(e.Message)) > MaxMessage {
		t.Errorf("message longer than MaxMessage: %d", len([]rune(e.Message)))
	}
}
