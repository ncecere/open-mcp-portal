package upstream

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type failedBodyReader struct {
	body string
	err  error
}

func (r *failedBodyReader) Read(p []byte) (int, error) {
	if r.body == "" {
		return 0, r.err
	}
	n := copy(p, r.body)
	r.body = r.body[n:]
	if r.body == "" {
		return n, r.err
	}
	return n, nil
}

func (*failedBodyReader) Close() error { return nil }

func TestTransportInspectionFailureRefusesDispatch(t *testing.T) {
	cause := errors.New("private reader failure")
	for _, tc := range []struct {
		name string
		body func() io.ReadCloser
	}{
		{"malformed", func() io.ReadCloser { return io.NopCloser(strings.NewReader(`not json`)) }},
		{"missing method", func() io.ReadCloser { return io.NopCloser(strings.NewReader(`{"params":{}}`)) }},
		{"valid body with read error", func() io.ReadCloser {
			return &failedBodyReader{body: `{"jsonrpc":"2.0","method":"tools/call"}`, err: cause}
		}},
	} {
		for _, noReplay := range []bool{false, true} {
			t.Run(tc.name+"/noReplay="+boolName(noReplay), func(t *testing.T) {
				req, _ := http.NewRequestWithContext(context.Background(), "POST", "https://example.com", tc.body())
				var hooks, sent int
				tr := &headerTransport{ex: &exchange{}, noReplay: noReplay,
					beforeTransport: func(context.Context, bool) error { hooks++; return nil },
					next: guardRoundTripper(func(*http.Request) (*http.Response, error) {
						sent++
						return guardResponse(), nil
					})}
				_, err := tr.RoundTrip(req)
				var refusal *BeforeTransportError
				if !errors.As(err, &refusal) || hooks != 0 || sent != 0 {
					t.Fatalf("inspection failure: err=%v hooks=%d sent=%d", err, hooks, sent)
				}
				if strings.Contains(err.Error(), "private") || (tc.name == "valid body with read error" && !errors.Is(err, cause)) {
					t.Fatal("inspection cause was exposed or lost")
				}
			})
		}
	}
}

// RawMessage is valid at its own depth limit, but its enclosing RPC message
// exceeds the decoder's depth. Failure to inspect that message must not turn
// a real tools/call into an ungoverned non-tool transport.
func TestModernDeepArgumentsCannotBypassTransportGuard(t *testing.T) {
	args := json.RawMessage(`{"x":` + strings.Repeat("[", 9999) + `0` + strings.Repeat("]", 9999) + `}`)
	if !json.Valid(args) {
		t.Fatal("fixture arguments must be valid independently")
	}
	var sent, hooks atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		sent.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()
	target := Target{URL: ts.URL, Timeout: time.Second, NoReplay: true,
		BeforeTransport: func(context.Context, bool) error { hooks.Add(1); return nil }}
	client := eraClient()
	client.remember(target, Protocol{Era: EraModern, Version: ModernVersion})
	_, err := client.Forward(context.Background(), target, ForwardRequest{Method: MethodToolsCall, Name: "echo", Arguments: args})
	var refusal *BeforeTransportError
	if !errors.As(err, &refusal) || sent.Load() != 0 || hooks.Load() != 0 {
		t.Fatalf("deep arguments: err=%v sent=%d hooks=%d", err, sent.Load(), hooks.Load())
	}
}
