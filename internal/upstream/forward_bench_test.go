package upstream

import (
	"context"
	"encoding/pem"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

// BenchmarkForward is one modern tools/call to a server on loopback, the
// era already known. Every exchange builds its own transport (httpClient),
// so the TLS case pays a full handshake per call: the difference between
// the two is that cost with no network latency at all.
func BenchmarkForward(b *testing.B) {
	for _, secure := range []bool{false, true} {
		name := "http"
		if secure {
			name = "tls"
		}
		b.Run(name, func(b *testing.B) {
			fake, h := testutil.NewFakeMCPHandler()
			fake.SetProtocol(testutil.ProtocolModern)
			fake.EnableGatewayTools()
			srv := httptest.NewUnstartedServer(h)
			target := Target{ServerID: "bench", Timeout: 5 * time.Second}
			if secure {
				srv.StartTLS()
				ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
				id, err := NewTLSIdentity(string(ca), "", "")
				if err != nil {
					b.Fatal(err)
				}
				target.TLS = id
			} else {
				srv.Start()
			}
			defer srv.Close()
			target.URL = srv.URL + "/mcp"
			c := eraClient()
			req := ForwardRequest{Method: MethodToolsCall, Name: "echo", Arguments: []byte(`{"text":"hi"}`)}
			if _, err := c.Forward(context.Background(), target, req); err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			for b.Loop() {
				if _, err := c.Forward(context.Background(), target, req); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
