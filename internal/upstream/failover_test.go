package upstream

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

type failoverWire struct {
	fake            *testutil.FakeMCP
	server          *httptest.Server
	tools, requests atomic.Int32
}

func newFailoverWire(t *testing.T, era testutil.Protocol, tool func(http.ResponseWriter, *http.Request) bool) *failoverWire {
	t.Helper()
	f, h := testutil.NewFakeMCPHandler()
	f.SetProtocol(era)
	f.EnableGatewayTools()
	w := &failoverWire{fake: f}
	w.server = httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		w.requests.Add(1)
		body, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewReader(body))
		var m struct{ Method string }
		_ = json.Unmarshal(body, &m)
		if m.Method == MethodToolsCall {
			w.tools.Add(1)
			if tool != nil && tool(rw, r) {
				return
			}
		}
		h.ServeHTTP(rw, r)
	}))
	t.Cleanup(w.server.Close)
	return w
}
func failoverExpected(t *testing.T, c *Client, target Target) *ExpectedCapability {
	t.Helper()
	d, err := c.Discover(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	for _, cap := range d.Capabilities {
		if cap.Kind == KindTool && cap.Name == "echo" {
			return &ExpectedCapability{cap.Kind, cap.Name, cap.Fingerprint}
		}
	}
	t.Fatal("echo definition missing")
	return nil
}
func failoverClient() *Client {
	c := eraClient()
	c.retryPause = func(context.Context, time.Duration) error { return nil }
	return c
}

func TestFailoverRead503DefinitionAndIndependentCredentialsBothEras(t *testing.T) {
	for _, era := range []testutil.Protocol{testutil.ProtocolLegacy, testutil.ProtocolModern} {
		t.Run(string(era), func(t *testing.T) {
			primary := newFailoverWire(t, era, func(w http.ResponseWriter, _ *http.Request) bool { http.Error(w, "busy", 503); return true })
			secondary := newFailoverWire(t, era, nil)
			primary.fake.RequireHeader("X-Key", "primary-private-value")
			secondary.fake.RequireHeader("Authorization", "Bearer secondary-private-value")
			c := failoverClient()
			target := Target{URL: primary.server.URL + "/mcp", ServerID: "logical", Timeout: 5 * time.Second, Credentials: []Credential{{Kind: CredHeader, Name: "X-Key", Value: "primary-private-value"}}, IdentityHeader: "MCP-Gateway-Identity", IdentityValue: "primary-identity"}
			expected := failoverExpected(t, c, target)
			target.Endpoints = []Endpoint{{ID: "secondary", URL: secondary.server.URL + "/mcp", Credentials: []Credential{{Kind: CredBearer, Value: "secondary-private-value"}}, IdentityHeader: "MCP-Gateway-Identity", IdentityValue: "secondary-identity"}}
			var admissions []int
			target.BeforeAttempt = func(_ context.Context, n int) error { admissions = append(admissions, n); return nil }
			out, err := c.Forward(context.Background(), target, ForwardRequest{Method: MethodToolsCall, Name: "echo", Arguments: []byte(`{"text":"safe"}`), Retryable: true, Expected: expected})
			if err != nil || out.Tool == nil || out.Retries != 1 || primary.tools.Load() != 1 || secondary.tools.Load() != 1 || len(admissions) != 2 {
				t.Fatalf("fallback: %+v %v primary=%d secondary=%d admission=%v", out, err, primary.tools.Load(), secondary.tools.Load(), admissions)
			}
			calls := secondary.fake.ToolCalls()
			if len(calls) != 1 || calls[0].Header.Get("X-Key") != "" || calls[0].Header.Get("Authorization") != "Bearer secondary-private-value" || calls[0].Header.Get("MCP-Gateway-Identity") != "secondary-identity" {
				t.Fatal("endpoint inherited another destination's credential/identity")
			}
		})
	}
}

func TestFailoverNegativeBoundariesBothEras(t *testing.T) {
	for _, era := range []testutil.Protocol{testutil.ProtocolLegacy, testutil.ProtocolModern} {
		for _, name := range []string{"write503", "unclassified503", "governed-read", "continuation", "definition-mismatch", "ambiguous-send", "auth-rejection"} {
			t.Run(string(era)+"/"+name, func(t *testing.T) {
				primary := newFailoverWire(t, era, func(w http.ResponseWriter, r *http.Request) bool {
					if name == "ambiguous-send" {
						conn, _, err := w.(http.Hijacker).Hijack()
						if err == nil {
							_ = conn.Close()
						}
						return true
					}
					status := 503
					if name == "auth-rejection" {
						status = 401
					}
					http.Error(w, "not a repeatability proof", status)
					return true
				})
				secondary := newFailoverWire(t, era, nil)
				c := failoverClient()
				target := Target{URL: primary.server.URL + "/mcp", ServerID: "logical", Timeout: 5 * time.Second}
				expected := failoverExpected(t, c, target)
				if name == "definition-mismatch" {
					secondary.fake.SetDescription("echo", "A different offered definition")
				}
				target.Endpoints = []Endpoint{{ID: "secondary", URL: secondary.server.URL + "/mcp"}}
				target.NoReplay = name == "governed-read"
				req := ForwardRequest{Method: MethodToolsCall, Name: "echo", Arguments: []byte(`{"text":"safe"}`), Retryable: name != "write503" && name != "unclassified503", Expected: expected}
				if name == "continuation" {
					req.RequestState = "must-not-replay"
					req.InputResponses = []byte(`{}`)
				}
				_, err := c.Forward(context.Background(), target, req)
				if err == nil || secondary.tools.Load() != 0 {
					t.Fatalf("negative boundary crossed: %v primary=%d secondary=%d", err, primary.tools.Load(), secondary.tools.Load())
				}
				if name != "definition-mismatch" && secondary.requests.Load() != 0 {
					t.Fatalf("forbidden fallback contacted secondary for %s", name)
				}
			})
		}
	}
}
