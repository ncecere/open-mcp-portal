package upstream

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

func TestReadRetry503AndAdmissionBothEras(t *testing.T) {
	for _, protocol := range []testutil.Protocol{testutil.ProtocolLegacy, testutil.ProtocolModern} {
		t.Run(string(protocol), func(t *testing.T) {
			fake, handler := testutil.NewFakeMCPHandler()
			fake.SetProtocol(protocol)
			fake.EnableGatewayTools()
			var calls atomic.Int32
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				r.Body = io.NopCloser(bytes.NewReader(body))
				var m struct{ Method string }
				_ = json.Unmarshal(body, &m)
				if m.Method == MethodToolsCall && calls.Add(1) == 1 {
					http.Error(w, "busy", 503)
					return
				}
				handler.ServeHTTP(w, r)
			}))
			defer ts.Close()
			c := eraClient()
			c.retryPause = func(context.Context, time.Duration) error { return nil }
			var admissions []int
			target := Target{URL: ts.URL + "/mcp", ServerID: "one", Timeout: 5 * time.Second, BeforeAttempt: func(_ context.Context, n int) error { admissions = append(admissions, n); return nil }}
			res, err := c.Forward(context.Background(), target, ForwardRequest{Method: MethodToolsCall, Name: "echo", Arguments: []byte(`{"text":"ok"}`), Retryable: true})
			if err != nil || res.Tool == nil || calls.Load() != 2 || res.Retries != 1 || len(admissions) != 2 || admissions[0] != 0 || admissions[1] != 1 {
				t.Fatalf("retry result=%+v err=%v calls=%d admission=%v", res, err, calls.Load(), admissions)
			}
		})
	}
}

func TestReadRetryNegativeBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name                          string
		status                        int
		after, body, content          string
		retry, noReplay, continuation bool
		want                          int32
	}{
		{"write-not-opted-in", 503, "", "busy", "text/plain", false, false, false, 1},
		{"governed-read", 503, "", "busy", "text/plain", true, true, false, 1},
		{"continuation", 503, "", "busy", "text/plain", true, false, true, 1},
		{"long-delay", 503, "30", "busy", "text/plain", true, false, false, 1},
		{"invalid-delay", 503, "garbage", "busy", "text/plain", true, false, false, 1},
		{"429-missing-delay", 429, "", "busy", "text/plain", true, false, false, 1},
		{"429-short-delay", 429, "1", "busy", "text/plain", true, false, false, 3},
		{"503-short-delay", 503, "1", "busy", "text/plain", true, false, false, 3},
		{"ordinary-500", 500, "", "busy", "text/plain", true, false, false, 1},
		{"rpc-error", 503, "", `{"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"bad"}}`, "application/json", true, false, false, 1},
		{"streamed-error", 503, "", "data: partial\n\n", "text/event-stream", true, false, false, 1},
		{"partial-success", 200, "", `{"jsonrpc":`, "application/json", true, false, false, 1},
		{"stream-progress-disconnect", 200, "", "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{\"progressToken\":1,\"progress\":1}}\n\n", "text/event-stream", true, false, false, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Content-Type", tc.content)
				if tc.after != "" {
					w.Header().Set("Retry-After", tc.after)
				}
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			}))
			defer ts.Close()
			c := eraClient()
			c.retryPause = func(context.Context, time.Duration) error { return nil }
			target := Target{URL: ts.URL, Timeout: 3 * time.Second, NoReplay: tc.noReplay}
			c.remember(target, Protocol{Era: EraModern, Version: ModernVersion})
			req := ForwardRequest{Method: MethodToolsCall, Name: "echo", Retryable: tc.retry, ProgressToken: []byte(`1`)}
			if tc.continuation {
				req.RequestState = "state"
				req.InputResponses = []byte(`{}`)
			}
			_, err := c.Forward(context.Background(), target, req)
			if err == nil || calls.Load() != tc.want {
				t.Fatalf("err=%v calls=%d want=%d", err, calls.Load(), tc.want)
			}
		})
	}
}

func TestReadRetryCancellationAndLocalAuthorityRefusal(t *testing.T) {
	for _, cancelDuringWait := range []bool{false, true} {
		t.Run(boolName(cancelDuringWait), func(t *testing.T) {
			var calls atomic.Int32
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); http.Error(w, "busy", 503) }))
			defer ts.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			cause := errors.New("private policy lookup: password=do-not-show")
			c := eraClient()
			c.retryPause = func(context.Context, time.Duration) error {
				if cancelDuringWait {
					cancel()
				}
				return nil
			}
			target := Target{URL: ts.URL, Timeout: 3 * time.Second, ServerID: "one", MaxConcurrent: 1, BeforeAttempt: func(_ context.Context, n int) error {
				if n > 0 {
					return cause
				}
				return nil
			}}
			c.remember(target, Protocol{Era: EraModern, Version: ModernVersion})
			_, err := c.Forward(ctx, target, ForwardRequest{Method: MethodToolsCall, Name: "echo", Retryable: true})
			if err == nil || calls.Load() != 1 {
				t.Fatalf("err=%v calls=%d", err, calls.Load())
			}
			if !cancelDuringWait && !errors.Is(err, cause) {
				t.Fatal("lost private authority cause")
			}
			if c.protector().entries["one"].active != 0 || c.protector().entries["one"].failures != 0 {
				t.Fatal("local/cancelled failure leaked lease or tripped breaker")
			}
		})
	}
}

func TestProtectionAdmissionBeforeNetworkAndStream(t *testing.T) {
	c := eraClient()
	entered, release := make(chan struct{}), make(chan struct{})
	cause := errors.New("quota unavailable")
	target := Target{URL: "http://127.0.0.1:1", ServerID: "one", MaxConcurrent: 1, Timeout: 3 * time.Second, BeforeAttempt: func(context.Context, int) error { close(entered); <-release; return cause }}
	done := make(chan error, 1)
	go func() {
		_, err := c.Forward(context.Background(), target, ForwardRequest{Method: MethodToolsCall})
		done <- err
	}()
	<-entered
	var committed bool
	_, err := c.Forward(context.Background(), target, ForwardRequest{Method: MethodToolsCall, OnAdmitted: func() { committed = true }})
	var classified *Error
	if !errors.As(err, &classified) || classified.Class != ClassServerBusy || committed {
		t.Fatalf("cap committed response/network: %v", err)
	}
	close(release)
	if err := <-done; !errors.Is(err, cause) {
		t.Fatal(err)
	}
	if c.protector().entries["one"].active != 0 {
		t.Fatal("local denial leaked lease")
	}
}

func TestRetryAfterParsing(t *testing.T) {
	now := time.Date(2026, 10, 29, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		s     string
		d     time.Duration
		valid bool
	}{
		{"0", 0, true}, {"2", 2 * time.Second, true}, {"30", 30 * time.Second, true}, {"-1", 0, false}, {"+1", 0, false}, {"NaN", 0, false}, {"1.5", 0, false}, {"", 0, false}, {"99999999999999999999999999", 0, false},
		{now.Add(time.Second).Format(http.TimeFormat), time.Second, true},
	} {
		if d, ok := parseRetryAfter(tc.s, now); d != tc.d || ok != tc.valid {
			t.Fatalf("%q: %v,%v", tc.s, d, ok)
		}
	}
}
