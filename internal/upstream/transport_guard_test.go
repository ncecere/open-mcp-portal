package upstream

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

type guardRoundTripper func(*http.Request) (*http.Response, error)

func (f guardRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func guardResponse() *http.Response {
	return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(`{}`))}
}

func TestBeforeTransportBoundary(t *testing.T) {
	for _, tc := range []struct {
		name, method, body, header string
		tool                       bool
	}{
		{"discover", "POST", `{"jsonrpc":"2.0","method":"server/discover"}`, "", false},
		{"initialize", "POST", `{"jsonrpc":"2.0","method":"initialize"}`, "", false},
		{"initialized", "POST", `{"jsonrpc":"2.0","method":"notifications/initialized"}`, "", false},
		{"legacy tool", "POST", `{"jsonrpc":"2.0","method":"tools/call"}`, "", true},
		{"modern tool", "POST", `{"jsonrpc":"2.0","method":"tools/call"}`, "tools/call", true},
		{"header is not authority", "POST", `{"jsonrpc":"2.0","method":"prompts/get"}`, "tools/call", false},
		{"get", "GET", "", "tools/call", false},
		{"delete", "DELETE", "", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequestWithContext(context.Background(), tc.method, "https://example.com/mcp", strings.NewReader(tc.body))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Mcp-Method", tc.header)
			var events []string
			tr := &headerTransport{
				creds:  []Credential{{Kind: CredHeader, Name: "X-Key", Value: "secret"}},
				params: map[string]string{"Mcp-Param-Region": "eu"}, maxResponse: 100, ex: &exchange{},
				beforeTransport: func(ctx context.Context, tool bool) error {
					if ctx != req.Context() || tool != tc.tool {
						t.Errorf("hook context/tool = %v/%v, want original/%v", ctx, tool, tc.tool)
					}
					events = append(events, "hook")
					return nil
				},
				next: guardRoundTripper(func(out *http.Request) (*http.Response, error) {
					events = append(events, "transport")
					body, _ := io.ReadAll(out.Body)
					if string(body) != tc.body || out.Header.Get("X-Key") != "secret" {
						t.Errorf("body/credentials changed: %s, %v", body, out.Header)
					}
					if (out.Header.Get("Mcp-Param-Region") != "") != tc.tool {
						t.Errorf("parameter headers = %v", out.Header)
					}
					return guardResponse(), nil
				}),
			}
			res, err := tr.RoundTrip(req)
			if err != nil {
				t.Fatal(err)
			}
			_ = res.Body.Close()
			if strings.Join(events, ",") != "hook,transport" {
				t.Fatalf("boundary order = %v", events)
			}
		})
	}
}

func TestBeforeTransportRefusalSendsNothing(t *testing.T) {
	cause := errors.New("SQL password=do-not-expose")
	for _, method := range []string{http.MethodPost, http.MethodGet, http.MethodDelete} {
		t.Run(method, func(t *testing.T) {
			req, _ := http.NewRequestWithContext(context.Background(), method, "https://example.com", nil)
			tr := &headerTransport{ex: &exchange{}, beforeTransport: func(context.Context, bool) error { return cause },
				next: guardRoundTripper(func(*http.Request) (*http.Response, error) {
					t.Fatal("refused request reached transport")
					return nil, nil
				})}
			_, err := tr.RoundTrip(req)
			var guardErr *BeforeTransportError
			if !errors.Is(err, cause) || !errors.As(err, &guardErr) || strings.Contains(err.Error(), "SQL") {
				t.Fatalf("refusal = %v", err)
			}
		})
	}
}

func TestNoReplayTransportRequest(t *testing.T) {
	for _, noReplay := range []bool{false, true} {
		for _, replayBody := range []bool{false, true} {
			for _, method := range []string{"tools/call", "server/discover"} {
				t.Run(method+"/noReplay="+boolName(noReplay)+"/getBody="+boolName(replayBody), func(t *testing.T) {
					body := `{"jsonrpc":"2.0","method":"` + method + `","params":{}}`
					req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://example.com", strings.NewReader(body))
					if !replayBody {
						req.GetBody = nil // SDK/body inspection must not restore replayability.
					}
					req.Header["idempotency-key"] = []string{"original"} // noncanonical spelling too
					tr := &headerTransport{ex: &exchange{}, maxResponse: 100, noReplay: noReplay,
						creds:  []Credential{{Kind: CredHeader, Name: "Idempotency-Key", Value: "credential"}},
						params: map[string]string{"X-Idempotency-Key": "parameter"},
						next: guardRoundTripper(func(out *http.Request) (*http.Response, error) {
							blocked := noReplay && method == "tools/call"
							if (out.GetBody == nil) != blocked {
								t.Errorf("GetBody nil = %v, want %v", out.GetBody == nil, blocked)
							}
							if out.Header.Get("Idempotency-Key") != "credential" {
								t.Error("configured idempotency credential was removed")
							}
							if method == "tools/call" && out.Header.Get("X-Idempotency-Key") != "parameter" {
								t.Error("configured idempotency parameter was removed")
							}
							got, _ := io.ReadAll(out.Body)
							if string(got) != body || out.ContentLength != int64(len(body)) {
								t.Error("outbound body changed")
							}
							return guardResponse(), nil
						})}
					res, err := tr.RoundTrip(req)
					if err != nil {
						t.Fatal(err)
					}
					_ = res.Body.Close()
					if (req.GetBody != nil) != replayBody || req.Header["idempotency-key"][0] != "original" {
						t.Fatal("original request's replay metadata mutated")
					}
				})
			}
		}
	}
}

// Recreated transports (SDK reconnects or era recovery) share Forward's
// gate. Even concurrent attempts may neither send nor re-authorize twice.
func TestNoReplaySharedGate(t *testing.T) {
	for _, refuse := range []bool{false, true} {
		t.Run(boolName(refuse), func(t *testing.T) {
			cause := errors.New("approval already consumed")
			var hooks, sent, prevented atomic.Int32
			gate := &forwardTransportGuard{before: func(context.Context, bool) error {
				hooks.Add(1)
				if refuse {
					return cause
				}
				return nil
			}}
			var wg sync.WaitGroup
			for range 16 {
				wg.Go(func() {
					tr := &headerTransport{ex: &exchange{}, maxResponse: 100, noReplay: true, beforeTransport: gate.check,
						next: guardRoundTripper(func(*http.Request) (*http.Response, error) {
							sent.Add(1)
							return guardResponse(), nil
						})}
					req, _ := http.NewRequestWithContext(context.Background(), "POST", "https://example.com", strings.NewReader(`{"jsonrpc":"2.0","method":"tools/call"}`))
					res, err := tr.RoundTrip(req)
					switch {
					case errors.Is(err, ErrReplayPrevented):
						prevented.Add(1)
					case errors.Is(err, cause) && refuse:
					case err == nil && !refuse:
						_ = res.Body.Close()
					default:
						t.Errorf("unexpected result: %v", err)
					}
				})
			}
			wg.Wait()
			wantSent := int32(1)
			if refuse {
				wantSent = 0
			}
			if hooks.Load() != 1 || sent.Load() != wantSent || prevented.Load() != 15 || !gate.attempted.Load() {
				t.Fatalf("hooks=%d sent=%d prevented=%d attempted=%v", hooks.Load(), sent.Load(), prevented.Load(), gate.attempted.Load())
			}
		})
	}
}

func TestNoTransportControlsPreserveRequest(t *testing.T) {
	req, _ := http.NewRequestWithContext(context.Background(), "POST", "https://example.com", strings.NewReader(`{"jsonrpc":"2.0","method":"tools/call"}`))
	req.Header.Set("Idempotency-Key", "unchanged")
	tr := &headerTransport{ex: &exchange{}, maxResponse: 100,
		next: guardRoundTripper(func(out *http.Request) (*http.Response, error) {
			if out != req || out.GetBody == nil || out.Header.Get("Idempotency-Key") != "unchanged" {
				t.Error("uncontrolled request changed")
			}
			return guardResponse(), nil
		})}
	res, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
}

func boolName(v bool) string {
	if v {
		return "true"
	}
	return "false"
}

func TestToolsCallInspectionDoesNotTruncateArguments(t *testing.T) {
	body := `{"jsonrpc":"2.0","method":"tools/call","params":{"text":"` + strings.Repeat("x", 4<<20) + `"}}`
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://example.com", strings.NewReader(body))
	if tool, err := isToolsCall(req); err != nil || !tool {
		t.Fatalf("large tools/call not recognized: %v", err)
	}
	got, _ := io.ReadAll(req.Body)
	if string(got) != body {
		t.Fatal("inspection truncated arguments")
	}
}
