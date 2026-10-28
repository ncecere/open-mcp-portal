package upstream

import (
	"bytes"
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

	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

type approvalRefusal struct{ reason string }

func (e *approvalRefusal) Error() string { return e.reason }

func TestForwardTransportHook(t *testing.T) {
	for _, protocol := range []testutil.Protocol{testutil.ProtocolLegacy, testutil.ProtocolModern} {
		t.Run(string(protocol), func(t *testing.T) {
			fake := testutil.NewFakeMCP(t)
			fake.SetProtocol(protocol)
			fake.EnableGatewayTools()
			var tools, negotiation atomic.Int32
			tgt := Target{URL: fake.URL(), Timeout: 5 * time.Second, NoReplay: true,
				BeforeTransport: func(_ context.Context, tool bool) error {
					if tool {
						tools.Add(1)
					} else {
						negotiation.Add(1)
					}
					return nil
				}}
			c := eraClient()
			for range 2 { // The gate belongs to Forward, not to the reusable Target.
				res, err := c.Forward(context.Background(), tgt, ForwardRequest{Method: MethodToolsCall, Name: "echo", Arguments: []byte(`{"text":"ok"}`)})
				if err != nil || res.Tool == nil {
					t.Fatalf("Forward = %+v, %v", res, err)
				}
			}
			if tools.Load() != 2 || countMethod(fake, MethodToolsCall) != 2 || negotiation.Load() == 0 {
				t.Fatalf("hook tools/other = %d/%d; server tools = %d", tools.Load(), negotiation.Load(), countMethod(fake, MethodToolsCall))
			}
		})
	}
}

func TestForwardTransportRefusalPreservesCause(t *testing.T) {
	for _, protocol := range []testutil.Protocol{testutil.ProtocolLegacy, testutil.ProtocolModern} {
		for _, rejectTool := range []bool{false, true} {
			t.Run(string(protocol)+"/tool="+boolName(rejectTool), func(t *testing.T) {
				fake := testutil.NewFakeMCP(t)
				fake.SetProtocol(protocol)
				fake.EnableGatewayTools()
				cause := &approvalRefusal{reason: "SQL approval lookup failed: password=database-secret"}
				var refused atomic.Int32
				tgt := Target{URL: fake.URL(), Timeout: 5 * time.Second, NoReplay: true,
					BeforeTransport: func(_ context.Context, tool bool) error {
						if tool == rejectTool {
							refused.Add(1)
							return cause
						}
						return nil
					}}
				_, err := eraClient().Forward(context.Background(), tgt, ForwardRequest{Method: MethodToolsCall, Name: "echo"})
				var hookErr *BeforeTransportError
				var typed *approvalRefusal
				var classified *Error
				if !errors.Is(err, cause) || !errors.As(err, &hookErr) || !errors.As(err, &typed) || typed != cause || !errors.As(err, &classified) {
					t.Fatalf("lost hook error identity: %T %v", err, err)
				}
				if strings.Contains(err.Error(), "SQL") || strings.Contains(err.Error(), "database-secret") {
					t.Fatalf("hook error leaked: %v", err)
				}
				if refused.Load() != 1 || countMethod(fake, MethodToolsCall) != 0 || (!rejectTool && len(fake.HTTPRequests()) != 0) {
					t.Fatalf("refused=%d; requests=%+v", refused.Load(), fake.HTTPRequests())
				}
			})
		}
	}
}

// Real MCP handlers for both eras, with failures injected at the actual
// tools/call HTTP boundary (not only a mock of Forward's result parsing).
func TestNoReplayPostDispatchFailures(t *testing.T) {
	for _, protocol := range []testutil.Protocol{testutil.ProtocolLegacy, testutil.ProtocolModern} {
		for _, fault := range []string{"400", "401", "403", "404", "406", "415", "500", "unsupported-version", "rpc-error", "lost-response", "truncated-response", "sse-disconnect"} {
			t.Run(string(protocol)+"/"+fault, func(t *testing.T) {
				fake, handler := testutil.NewFakeMCPHandler()
				fake.SetProtocol(protocol)
				fake.EnableGatewayTools()
				var dispatches, hooks atomic.Int32
				ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					body, _ := io.ReadAll(r.Body)
					r.Body = io.NopCloser(bytes.NewReader(body))
					var msg struct {
						Method string          `json:"method"`
						ID     json.RawMessage `json:"id"`
					}
					_ = json.Unmarshal(body, &msg)
					if msg.Method != MethodToolsCall {
						handler.ServeHTTP(w, r)
						return
					}
					dispatches.Add(1)
					switch fault {
					case "lost-response":
						conn, _, err := http.NewResponseController(w).Hijack()
						if err != nil {
							t.Error(err)
							return
						}
						_ = conn.Close()
					case "truncated-response":
						w.Header().Set("Content-Type", "application/json")
						w.Header().Set("Content-Length", "10000")
						_, _ = w.Write([]byte(`{"jsonrpc":`))
					case "sse-disconnect":
						w.Header().Set("Content-Type", "text/event-stream")
						_, _ = w.Write([]byte("id: resume-here\nretry: 1\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{\"progressToken\":1,\"progress\":1}}\n\n"))
					case "unsupported-version", "rpc-error":
						w.Header().Set("Content-Type", "application/json")
						code := "-32602"
						if fault == "unsupported-version" {
							code = "-32022"
							w.WriteHeader(http.StatusBadRequest)
						}
						_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":` + string(msg.ID) + `,"error":{"code":` + code + `,"message":"refused"}}`))
					default:
						status := map[string]int{"400": 400, "401": 401, "403": 403, "404": 404, "406": 406, "415": 415, "500": 500}[fault]
						http.Error(w, "refused", status)
					}
				}))
				defer ts.Close()
				tgt := Target{URL: ts.URL + "/mcp", Timeout: 2 * time.Second, NoReplay: true,
					Credentials: []Credential{{Kind: CredHeader, Name: "Idempotency-Key", Value: "replay-if-not-stripped"}},
					BeforeTransport: func(_ context.Context, tool bool) error {
						if tool {
							hooks.Add(1)
						}
						return nil
					}}
				c := eraClient()
				era := EraModern
				if protocol == testutil.ProtocolLegacy {
					era = EraLegacy
				}
				c.remember(tgt, Protocol{Era: era}) // Exercise cached-stale recovery too.
				_, err := c.Forward(context.Background(), tgt, ForwardRequest{Method: MethodToolsCall, Name: "echo"})
				if err == nil || dispatches.Load() != 1 || hooks.Load() != 1 {
					t.Fatalf("Forward err=%v; dispatches=%d; hooks=%d", err, dispatches.Load(), hooks.Load())
				}
			})
		}
	}
}

func TestNoReplayStillRecoversBeforeToolDispatch(t *testing.T) {
	fake := testutil.NewFakeMCP(t)
	fake.SetProtocol(testutil.ProtocolModern)
	fake.EnableGatewayTools()
	c := eraClient()
	var tools atomic.Int32
	tgt := Target{URL: fake.URL(), Timeout: 5 * time.Second, NoReplay: true,
		BeforeTransport: func(_ context.Context, tool bool) error {
			if tool {
				tools.Add(1)
			}
			return nil
		}}
	c.remember(tgt, Protocol{Era: EraLegacy})
	res, err := c.Forward(context.Background(), tgt, ForwardRequest{Method: MethodToolsCall, Name: "echo", Arguments: []byte(`{"text":"ok"}`)})
	if err != nil || res.Tool == nil || tools.Load() != 1 || countMethod(fake, MethodToolsCall) != 1 || countMethod(fake, "initialize") != 1 || countMethod(fake, "server/discover") != 1 {
		t.Fatalf("recovery result=%+v err=%v; tool hooks=%d; requests=%+v", res, err, tools.Load(), fake.SeenRequests())
	}
}

// A legacy session reuses the initialize/initialized connection. With an
// idempotency credential, Go itself can transparently replay a lost response
// inside one RoundTrip, below the authorization callback.
func TestNoReplayPreventsGoHTTPReplay(t *testing.T) {
	for _, noReplay := range []bool{false, true} {
		t.Run(boolName(noReplay), func(t *testing.T) {
			fake, handler := testutil.NewFakeMCPHandler()
			fake.SetProtocol(testutil.ProtocolLegacy)
			fake.EnableGatewayTools()
			var calls, hooks atomic.Int32
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				r.Body = io.NopCloser(bytes.NewReader(body))
				var msg struct {
					Method string `json:"method"`
				}
				_ = json.Unmarshal(body, &msg)
				if msg.Method == MethodToolsCall && calls.Add(1) == 1 {
					conn, _, err := http.NewResponseController(w).Hijack()
					if err != nil {
						t.Error(err)
						return
					}
					_ = conn.Close()
					return
				}
				handler.ServeHTTP(w, r)
			}))
			defer ts.Close()
			tgt := Target{URL: ts.URL + "/mcp", Timeout: 5 * time.Second, NoReplay: noReplay,
				Credentials: []Credential{{Kind: CredHeader, Name: "Idempotency-Key", Value: "replay"}},
				BeforeTransport: func(_ context.Context, tool bool) error {
					if tool {
						hooks.Add(1)
					}
					return nil
				}}
			_, err := eraClient().Forward(context.Background(), tgt, ForwardRequest{Method: MethodToolsCall, Name: "echo", Arguments: []byte(`{"text":"ok"}`)})
			want := int32(2)
			if noReplay {
				want = 1
			}
			if (err != nil) != noReplay || calls.Load() != want || hooks.Load() != 1 {
				t.Fatalf("NoReplay=%v err=%v dispatches=%d hooks=%d, want %d/1", noReplay, err, calls.Load(), hooks.Load(), want)
			}
		})
	}
}

func TestNoReplayControlsCachedStaleRetry(t *testing.T) {
	for _, noReplay := range []bool{false, true} {
		t.Run(boolName(noReplay), func(t *testing.T) {
			fake, handler := testutil.NewFakeMCPHandler()
			fake.SetProtocol(testutil.ProtocolModern)
			fake.EnableGatewayTools()
			var calls atomic.Int32
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Mcp-Method") == MethodToolsCall && calls.Add(1) == 1 {
					http.NotFound(w, r)
					return
				}
				handler.ServeHTTP(w, r)
			}))
			defer ts.Close()
			c := eraClient()
			tgt := Target{URL: ts.URL + "/mcp", Timeout: 5 * time.Second, NoReplay: noReplay}
			c.remember(tgt, Protocol{Era: EraModern, Version: ModernVersion})
			_, err := c.Forward(context.Background(), tgt, ForwardRequest{Method: MethodToolsCall, Name: "echo", Arguments: []byte(`{"text":"ok"}`)})
			want := int32(2)
			if noReplay {
				want = 1
			}
			if (err != nil) != noReplay || calls.Load() != want {
				t.Fatalf("NoReplay=%v err=%v calls=%d, want %d", noReplay, err, calls.Load(), want)
			}
		})
	}
}
