package upstream

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

func TestFailoverWriteOnlyProvenPreRequestDialOrHandshake(t *testing.T) {
	for _, era := range []testutil.Protocol{testutil.ProtocolLegacy, testutil.ProtocolModern} {
		for _, failure := range []string{"dial", "tls-handshake"} {
			t.Run(string(era)+"/"+failure, func(t *testing.T) {
				secondary := newFailoverWire(t, era, nil)
				c := failoverClient()
				good := Target{URL: secondary.server.URL + "/mcp", ServerID: "logical", Timeout: 5 * time.Second}
				expected := failoverExpected(t, c, good)
				var bad *httptest.Server
				if failure == "dial" {
					bad = httptest.NewServer(http.NotFoundHandler())
					bad.Close()
				} else {
					bad = httptest.NewTLSServer(http.NotFoundHandler())
					defer bad.Close()
				}
				target := Target{URL: bad.URL + "/mcp", ServerID: "logical", Timeout: 5 * time.Second, Endpoints: []Endpoint{{ID: "secondary", URL: good.URL}}}
				// Retryable is deliberately false: only positive pre-request evidence
				// permits an ordinary write to switch. A TLS error class alone does not.
				out, err := c.Forward(context.Background(), target, ForwardRequest{Method: MethodToolsCall, Name: "echo", Arguments: []byte(`{"text":"write-only-after-unsent"}`), Expected: expected})
				if err != nil || out.Tool == nil || out.Retries != 1 || secondary.tools.Load() != 1 {
					t.Fatalf("proven unsent fallback: %+v %v tools=%d", out, err, secondary.tools.Load())
				}
			})
		}
	}
}

func TestFailoverPreRequestFactsRefuseLabelsPartialWritesAndLocalPolicy(t *testing.T) {
	for _, tc := range []struct {
		name, class                    string
		handshake, dial, written, want bool
	}{
		{"TLS label not evidence", ClassTLS, false, false, false, false},
		{"observed handshake", ClassTLS, true, false, false, true},
		{"handshake after operation write", ClassTLS, true, false, true, false},
		{"observed dial", ClassUnavailable, false, true, false, true},
		{"dial after operation write", ClassUnavailable, false, true, true, false},
		{"policy not a dial outage", ClassNotAllowed, false, true, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ex := &exchange{handshakeFailed: tc.handshake, dialFailed: tc.dial, operationWritten: tc.written}
			retry, pre, _ := retryFacts(&Error{Class: tc.class}, ex, errors.New("not a dial cause"))
			if retry != tc.want || pre != tc.want {
				t.Fatalf("retry=%v pre=%v want=%v", retry, pre, tc.want)
			}
		})
	}
}

func TestFailoverTargetNeverInheritsAndRetainsRedaction(t *testing.T) {
	base := Target{URL: "https://primary.example", Credentials: []Credential{{Kind: CredHeader, Name: "X-Key", Value: "primary-private"}}, IdentityValue: "primary-identity"}
	ep := Endpoint{ID: "extra", URL: "https://secondary.example", Credentials: []Credential{{Kind: CredBearer, Value: "secondary-private"}}, IdentityHeader: "MCP-Gateway-Identity", IdentityValue: "secondary-identity"}
	base.Endpoints = []Endpoint{ep}
	selected := endpointTarget(base, ep)
	if selected.Credentials[0].Value != "secondary-private" || selected.IdentityValue != "secondary-identity" || selected.ProviderToken != "" || selected.BearerToken != "" || selected.PersonSecret != "" || selected.TLS != nil {
		t.Fatal("network target inherited credentials")
	}
	message := selected.safe("primary-private secondary-private primary-identity secondary-identity")
	for _, secret := range []string{"primary-private", "secondary-private", "primary-identity", "secondary-identity"} {
		if strings.Contains(message, secret) {
			t.Fatal("cross-attempt secret escaped redaction")
		}
	}
}
