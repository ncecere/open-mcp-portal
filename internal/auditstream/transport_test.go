package auditstream

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/ncecere/open-mcp-portal/internal/netpolicy"
	"github.com/ncecere/open-mcp-portal/internal/notify"
)

func TestSinkTransportPolicyAndRedirect(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://sentinel.invalid:1")
	t.Setenv("HTTPS_PROXY", "http://sentinel.invalid:1")
	t.Setenv("NO_PROXY", "")
	hits := 0
	status := 302
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Header().Set("Location", "http://127.0.0.1/sentinel")
		w.WriteHeader(status)
	}))
	defer server.Close()
	c := notify.NewWebhookClient([]netpolicy.Entry{{Kind: netpolicy.KindHost, Value: "receiver.example", AllowHTTP: true}}, nil)
	c.Lookup = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
	}
	c.Dial = func(ctx context.Context, n, a string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, n, server.Listener.Addr().String())
	}
	for _, tc := range []struct {
		status int
		class  string
	}{{302, "http_3xx"}, {400, "http_4xx"}, {500, "http_5xx"}, {204, ""}} {
		status = tc.status
		req, _ := http.NewRequest("POST", "http://receiver.example/?secret=sentinel", nil)
		if got := Send(SinkHTTPClient(c), req); got != tc.class {
			t.Fatalf("status %d: %s", tc.status, got)
		}
	}
	if hits != 4 {
		t.Fatal("redirect followed")
	}
	c.Lookup = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("93.184.216.34"), netip.MustParseAddr("127.0.0.1")}, nil
	}
	req, _ := http.NewRequest("POST", "http://receiver.example/?secret=sentinel", nil)
	if got := Send(SinkHTTPClient(c), req); got != "policy_denied" {
		t.Fatalf("mixed address dial permitted: %s", got)
	}
	if hits != 4 {
		t.Fatal("blocked request reached receiver")
	}
	for _, err := range []error{errors.New("sentinel"), &net.DNSError{Err: "sentinel", Name: "sentinel"}, context.DeadlineExceeded, errors.New("tls: sentinel")} {
		if strings.Contains(transportClass(err), "sentinel") {
			t.Fatal("secret in class")
		}
	}
}
