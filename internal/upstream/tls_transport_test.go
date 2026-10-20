package upstream

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

// tlsFake adapts the shared fake to this file's vocabulary.
type tlsFake struct{ *testutil.MTLSFake }

type tlsSeen struct {
	clientCN   string
	protoMajor int
	version    uint16
	serverName string
}

func (f *tlsFake) requests() []tlsSeen {
	var out []tlsSeen
	for _, s := range f.Seen() {
		out = append(out, tlsSeen{clientCN: s.ClientCN, protoMajor: s.ProtoMajor, version: s.Version, serverName: s.ServerName})
	}
	return out
}

func startTLSFake(t *testing.T, o testutil.MTLSOptions) *tlsFake {
	t.Helper()
	return &tlsFake{testutil.StartMTLSFake(t, o)}
}

// tlsID builds a target identity, failing the test on bad input.
func tlsID(t *testing.T, ca *testutil.Cert, client *testutil.Cert) *TLSIdentity {
	t.Helper()
	var caPEM, certPEM, keyPEM string
	if ca != nil {
		caPEM = ca.CertPEM
	}
	if client != nil {
		certPEM, keyPEM = client.CertPEM, client.KeyPEM
	}
	id, err := NewTLSIdentity(caPEM, certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func loopbackCert(t *testing.T, ca *testutil.Cert, names ...string) *testutil.Cert {
	t.Helper()
	return ca.Issue(t, testutil.IssueOptions{Server: true, DNSNames: names, IPs: []net.IP{net.ParseIP("127.0.0.1")}})
}

func class(t *testing.T, err error) *Error {
	t.Helper()
	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("err = %v, want *Error", err)
	}
	return e
}

// A server that requires a client certificate and uses a private CA can be
// discovered and called (every era's transport goes through httpClient), over
// HTTP/2, with TLS 1.2 at least; the era cache is keyed as before.
func TestTLSMutualDiscoverAndCall(t *testing.T) {
	ca := testutil.NewCA(t, "Internal CA")
	client := ca.Issue(t, testutil.IssueOptions{CommonName: "portal-client", Client: true})
	for _, proto := range []testutil.Protocol{testutil.ProtocolModern, testutil.ProtocolLegacy} {
		t.Run(string(proto), func(t *testing.T) {
			f := startTLSFake(t, testutil.MTLSOptions{Server: loopbackCert(t, ca), ClientCAs: []*testutil.Cert{ca}})
			f.SetProtocol(proto)
			f.EnableGatewayTools()
			c := eraClient()
			tgt := Target{URL: f.URL(), ServerID: "s1", Timeout: 5 * time.Second, TLS: tlsID(t, ca, client)}
			ctx := context.Background()

			d, err := c.Discover(ctx, tgt)
			if err != nil {
				t.Fatal(err)
			}
			if n := CountKinds(d.Capabilities); n.Tools < 3 {
				t.Fatalf("counts = %+v", n)
			}
			res, err := c.Forward(ctx, tgt, ForwardRequest{Method: MethodToolsCall, Name: "check_outage", Arguments: []byte(`{"service":"api"}`)})
			if err != nil || res.Tool == nil || res.Tool.IsError {
				t.Fatalf("forward = %+v, %v", res, err)
			}
			if _, _, err := c.CallTool(ctx, tgt, "check_outage", []byte(`{"service":"api"}`)); err != nil {
				t.Fatalf("CallTool: %v", err)
			}
			seen := f.requests()
			if len(seen) == 0 {
				t.Fatal("the server saw nothing")
			}
			for _, s := range seen {
				if s.clientCN != "portal-client" {
					t.Fatalf("a request arrived with client certificate %q", s.clientCN)
				}
				if s.version < tls.VersionTLS12 {
					t.Fatalf("TLS version %x", s.version)
				}
				if s.protoMajor != 2 {
					t.Fatalf("HTTP/%d: HTTP/2 isn't negotiated with a custom TLS config", s.protoMajor)
				}
				if s.serverName != "127.0.0.1" && s.serverName != "" {
					t.Fatalf("server name %q", s.serverName)
				}
			}
			// The era is learned and remembered as it always was: the TLS settings
			// are not part of its key, and a second discover doesn't probe again.
			if eraKey(tgt) != eraKey(Target{URL: tgt.URL, ServerID: tgt.ServerID}) {
				t.Fatal("the era key depends on the TLS settings")
			}
			if _, ok := c.Eras.get(eraKey(tgt)); !ok {
				t.Fatal("the era wasn't remembered")
			}
			before := countMethod(f.FakeMCP, "server/discover")
			if _, err := c.Discover(ctx, tgt); err != nil {
				t.Fatal(err)
			}
			if proto == testutil.ProtocolModern && countMethod(f.FakeMCP, "server/discover")-before > 1 {
				t.Fatalf("the era was probed again")
			}
		})
	}
}

// A streamed call (progress notifications over SSE) uses the same transport.
func TestTLSStreamedCall(t *testing.T) {
	ca := testutil.NewCA(t, "Internal CA")
	client := ca.Issue(t, testutil.IssueOptions{Client: true})
	f := startTLSFake(t, testutil.MTLSOptions{Server: loopbackCert(t, ca), ClientCAs: []*testutil.Cert{ca}})
	f.EnableStreamTools()
	c := eraClient()
	var mu sync.Mutex
	progress := 0
	res, err := c.Forward(context.Background(), Target{URL: f.URL(), ServerID: "s", Timeout: 10 * time.Second, TLS: tlsID(t, ca, client)}, ForwardRequest{
		Method: MethodToolsCall, Name: "progress", Arguments: []byte(`{"count":3,"delay_ms":1}`), ProgressToken: []byte(`"p1"`),
		OnProgress: func(Progress) { mu.Lock(); progress++; mu.Unlock() }})
	if err != nil || res.Tool == nil {
		t.Fatalf("streamed = %+v, %v", res, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if progress != 3 {
		t.Fatalf("progress notifications = %d", progress)
	}
}

// Without the private CA the same server fails with class tls, not
// unavailable; the message says what to do. Without the client certificate,
// or with one the server's CA didn't sign, it fails with class tls too.
func TestTLSFailureClasses(t *testing.T) {
	ca := testutil.NewCA(t, "Internal CA")
	otherCA := testutil.NewCA(t, "Other CA")
	client := ca.Issue(t, testutil.IssueOptions{Client: true})
	stranger := otherCA.Issue(t, testutil.IssueOptions{Client: true})
	f := startTLSFake(t, testutil.MTLSOptions{Server: loopbackCert(t, ca), ClientCAs: []*testutil.Cert{ca}})
	c := testClient(true)
	ctx := context.Background()
	call := func(id *TLSIdentity) *Error {
		t.Helper()
		_, err := c.Discover(ctx, Target{URL: f.URL(), Timeout: 5 * time.Second, TLS: id})
		if err == nil {
			t.Fatal("the handshake succeeded")
		}
		return class(t, err)
	}
	for _, tc := range []struct {
		name string
		id   *TLSIdentity
		want string
	}{
		{"no settings: the CA isn't trusted", nil, "private CA"},
		{"a client certificate but no CA", tlsID(t, nil, client), "private CA"},
		{"the CA but no client certificate", tlsID(t, ca, nil), "client certificate"},
		{"another CA's client certificate", tlsID(t, ca, stranger), "client certificate"},
		{"a CA that didn't sign the server", tlsID(t, otherCA, client), "isn't signed by a CA in this server's TLS settings"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := call(tc.id)
			if e.Class != ClassTLS || !strings.Contains(e.Message, tc.want) {
				t.Fatalf("class %s message %q, want tls with %q", e.Class, e.Message, tc.want)
			}
			if strings.Contains(e.Message, "BEGIN") || strings.Contains(e.Message, client.KeyPEM[30:60]) {
				t.Fatalf("message shows key material: %s", e.Message)
			}
		})
	}
	// And the right settings work on the same server.
	if _, err := c.Discover(ctx, Target{URL: f.URL(), Timeout: 5 * time.Second, TLS: tlsID(t, ca, client)}); err != nil {
		t.Fatalf("right settings: %v", err)
	}
}

// The host name is always verified: a server certificate without the name in
// its SANs fails with an error that says so plainly, however the CA is set.
func TestTLSHostNameIsVerified(t *testing.T) {
	ca := testutil.NewCA(t, "Internal CA")
	client := ca.Issue(t, testutil.IssueOptions{Client: true})
	// Names in the SANs, none matching the host the URL has; and a CN-only
	// certificate (which Go has not accepted since 1.15).
	for name, cert := range map[string]*testutil.Cert{
		"other names": ca.Issue(t, testutil.IssueOptions{Server: true, DNSNames: []string{"other.internal.test", "alt.internal.test"}}),
		"CN only":     ca.Issue(t, testutil.IssueOptions{Server: true, CommonName: "mcp.internal.test"}),
	} {
		t.Run(name, func(t *testing.T) {
			f := startTLSFake(t, testutil.MTLSOptions{Server: cert, ClientCAs: []*testutil.Cert{ca}})
			_, port, _ := net.SplitHostPort(f.Listener.Addr().String())
			c := testClient(true)
			c.Lookup = func(context.Context, string) ([]netip.Addr, error) {
				return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
			}
			_, err := c.Discover(context.Background(), Target{URL: "https://mcp.internal.test:" + port + "/mcp", Timeout: 5 * time.Second, TLS: tlsID(t, ca, client)})
			e := class(t, err)
			if e.Class != ClassTLS || !strings.Contains(e.Message, "isn't valid for the host name mcp.internal.test") ||
				!strings.Contains(e.Message, "Subject Alternative Names") {
				t.Fatalf("class %s: %q", e.Class, e.Message)
			}
			if name == "other names" && !strings.Contains(e.Message, "other.internal.test") {
				t.Fatalf("the certificate's names aren't listed: %q", e.Message)
			}
			// The name that is in the certificate works (the connection is dialled
			// to the checked address, the name verified is the URL's).
		})
	}
	f := startTLSFake(t, testutil.MTLSOptions{Server: ca.Issue(t, testutil.IssueOptions{Server: true, DNSNames: []string{"mcp.internal.test"}}), ClientCAs: []*testutil.Cert{ca}})
	_, port, _ := net.SplitHostPort(f.Listener.Addr().String())
	c := testClient(true)
	c.Lookup = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}
	if _, err := c.Discover(context.Background(), Target{URL: "https://mcp.internal.test:" + port + "/mcp", Timeout: 5 * time.Second, TLS: tlsID(t, ca, client)}); err != nil {
		t.Fatalf("the right name: %v", err)
	}
	if s := f.requests(); len(s) == 0 || s[0].serverName != "mcp.internal.test" {
		t.Fatalf("SNI = %+v", s)
	}
}

// TLS 1.1 and below are refused (the minimum is 1.2).
func TestTLSMinimumVersion(t *testing.T) {
	ca := testutil.NewCA(t, "Internal CA")
	client := ca.Issue(t, testutil.IssueOptions{Client: true})
	f := startTLSFake(t, testutil.MTLSOptions{Server: loopbackCert(t, ca), ClientCAs: []*testutil.Cert{ca}, MaxVersion: tls.VersionTLS11})
	_, err := testClient(true).Discover(context.Background(), Target{URL: f.URL(), Timeout: 5 * time.Second, TLS: tlsID(t, ca, client)})
	if e := class(t, err); e.Class != ClassTLS || !strings.Contains(e.Message, "TLS 1.2") {
		t.Fatalf("TLS 1.1 server: %+v", e)
	}
	// TLS 1.2 is accepted, and 1.3 is what is used when both speak it.
	f12 := startTLSFake(t, testutil.MTLSOptions{Server: loopbackCert(t, ca), ClientCAs: []*testutil.Cert{ca}, MaxVersion: tls.VersionTLS12})
	if _, err := testClient(true).Discover(context.Background(), Target{URL: f12.URL(), Timeout: 5 * time.Second, TLS: tlsID(t, ca, client)}); err != nil {
		t.Fatalf("TLS 1.2: %v", err)
	}
	if s := f12.requests(); len(s) == 0 || s[0].version != tls.VersionTLS12 {
		t.Fatalf("TLS 1.2 server saw %+v", s)
	}
	f13 := startTLSFake(t, testutil.MTLSOptions{Server: loopbackCert(t, ca), ClientCAs: []*testutil.Cert{ca}})
	if _, err := testClient(true).Discover(context.Background(), Target{URL: f13.URL(), Timeout: 5 * time.Second, TLS: tlsID(t, ca, client)}); err != nil {
		t.Fatalf("TLS 1.3: %v", err)
	}
	if s := f13.requests(); len(s) == 0 || s[0].version != tls.VersionTLS13 {
		t.Fatalf("1.3 isn't preferred: %+v", s)
	}
}

// A server with no TLS on the port, or one that answers plain HTTP, is a TLS
// problem with its own words, not a bare "unavailable".
func TestTLSNotTLS(t *testing.T) {
	plain := httptest.NewServer(http.NotFoundHandler())
	defer plain.Close()
	u := "https://" + strings.TrimPrefix(plain.URL, "http://") + "/mcp"
	_, err := testClient(true).Discover(context.Background(), Target{URL: u, Timeout: 5 * time.Second})
	if e := class(t, err); e.Class != ClassTLS || !strings.Contains(e.Message, "TLS") {
		t.Fatalf("plain server: %+v", e)
	}
}

// A connection (and the HTTP/2 session on it) is never shared between two TLS
// identities: each exchange builds its own transport, so two servers (or one
// server read with two client certificates) never ride each other's
// connection. The server sees every request with the certificate of the
// identity that made it, however they interleave.
func TestTLSConnectionsAreNotSharedBetweenIdentities(t *testing.T) {
	ca := testutil.NewCA(t, "Internal CA")
	alice := ca.Issue(t, testutil.IssueOptions{CommonName: "alice", Client: true})
	bob := ca.Issue(t, testutil.IssueOptions{CommonName: "bob", Client: true})
	f := startTLSFake(t, testutil.MTLSOptions{Server: loopbackCert(t, ca), ClientCAs: []*testutil.Cert{ca}})
	c := testClient(true)
	ids := map[string]*TLSIdentity{"alice": tlsID(t, ca, alice), "bob": tlsID(t, ca, bob)}
	if ids["alice"].Fingerprint() == ids["bob"].Fingerprint() {
		t.Fatal("two client certificates, one identity")
	}
	var wg sync.WaitGroup
	var failures atomic.Int64
	for i := 0; i < 6; i++ {
		for name, id := range ids {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, err := c.Discover(context.Background(), Target{URL: f.URL(), Timeout: 10 * time.Second, TLS: id}); err != nil {
					failures.Add(1)
					t.Errorf("%s: %v", name, err)
				}
			}()
		}
	}
	wg.Wait()
	if failures.Load() > 0 {
		return
	}
	got := map[string]int{}
	for _, s := range f.requests() {
		got[s.clientCN]++
	}
	if got["alice"] == 0 || got["bob"] == 0 || len(got) != 2 {
		t.Fatalf("requests by client certificate = %v", got)
	}
	// Twelve exchanges, none reusing another's connection: at least one
	// connection each (the transport of an exchange is closed with it).
	if f.Conns() < 12 {
		t.Fatalf("%d connections for 12 exchanges: connections are shared", f.Conns())
	}
	// And the server that trusts only one of the CAs never sees the other's
	// certificate: a connection can't carry a certificate it wasn't made with.
	solo := startTLSFake(t, testutil.MTLSOptions{Server: loopbackCert(t, ca), ClientCAs: []*testutil.Cert{ca}})
	if _, err := c.Discover(context.Background(), Target{URL: solo.URL(), Timeout: 5 * time.Second, TLS: ids["alice"]}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Discover(context.Background(), Target{URL: solo.URL(), Timeout: 5 * time.Second}); class(t, err).Class != ClassTLS {
		t.Fatalf("an exchange without a client certificate rode alice's connection: %v", err)
	}
}

// TLS settings don't touch the address rule: a private address still needs an
// allow-list entry, a name that resolves to a blocked address is refused at
// dial (and nothing is dialled), redirects are refused, and an allowed
// internal host is dialled at the address that was checked, with the TLS
// settings applying.
func TestTLSIsOrthogonalToTheAddressRule(t *testing.T) {
	ca := testutil.NewCA(t, "Internal CA")
	client := ca.Issue(t, testutil.IssueOptions{Client: true})
	f := startTLSFake(t, testutil.MTLSOptions{Server: loopbackCert(t, ca, "mcp.corp.example.com"), ClientCAs: []*testutil.Cert{ca}})
	_, port, _ := net.SplitHostPort(f.Listener.Addr().String())
	id := tlsID(t, ca, client)
	ctx := context.Background()
	url := "https://mcp.corp.example.com:" + port + "/mcp"

	var dialled []string
	standIn := func(ctx context.Context, network, address string) (net.Conn, error) {
		dialled = append(dialled, address)
		return (&net.Dialer{}).DialContext(ctx, network, f.Listener.Addr().String())
	}
	resolve := func(addr string) func(context.Context, string) ([]netip.Addr, error) {
		return func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr(addr)}, nil
		}
	}

	// Private and not allowed: refused before any connection, TLS or not.
	c := &Client{Lookup: resolve("10.99.0.5"), Dial: standIn, Networks: staticPolicy{testPolicy()}}
	_, err := c.Discover(ctx, Target{URL: "https://build.example.com:" + port + "/mcp", Timeout: 5 * time.Second, TLS: id})
	if e := class(t, err); e.Class != ClassNotAllowed || len(dialled) != 0 {
		t.Fatalf("private, not allowed: %+v, dialled %v", e, dialled)
	}
	// A name resolving to cloud metadata: refused at dial, whatever the policy.
	c = &Client{Lookup: resolve("169.254.169.254"), Dial: standIn, Networks: staticPolicy{testPolicy()}}
	_, err = c.Discover(ctx, Target{URL: url, Timeout: 5 * time.Second, TLS: id})
	if e := class(t, err); e.Class != ClassNotAllowed || len(dialled) != 0 {
		t.Fatalf("blocked address: %+v, dialled %v", e, dialled)
	}
	// An allow-listed internal address: dialled at the checked address, and the
	// handshake uses the settings.
	c = &Client{Lookup: resolve("10.20.3.4"), Dial: standIn, Networks: staticPolicy{testPolicy()}}
	if _, err = c.Discover(ctx, Target{URL: url, Timeout: 5 * time.Second, TLS: id}); err != nil {
		t.Fatalf("allowed internal host: %v", err)
	}
	if len(dialled) == 0 || dialled[0] != "10.20.3.4:"+port {
		t.Fatalf("dialled %v, want the checked address", dialled)
	}
	// An allowed host that fails TLS is a tls failure, not a way around the rule.
	if _, err = c.Discover(ctx, Target{URL: url, Timeout: 5 * time.Second}); class(t, err).Class != ClassTLS {
		t.Fatalf("no settings: %v", err)
	}
	// Redirects are never followed, with or without TLS settings.
	redirect := httptest.NewUnstartedServer(http.RedirectHandler("https://mcp.corp.example.com/", http.StatusTemporaryRedirect))
	redirect.TLS = &tls.Config{Certificates: []tls.Certificate{loopbackCert(t, ca).TLSCertificate()}}
	redirect.StartTLS()
	defer redirect.Close()
	_, err = testClient(true).Discover(ctx, Target{URL: redirect.URL, Timeout: 5 * time.Second, TLS: tlsID(t, ca, nil)})
	if e := class(t, err); e.Class != ClassNotAllowed {
		t.Fatalf("redirect: %+v", e)
	}
	// And the development allowance is what lets loopback through, as before.
	if _, err = (&Client{}).Discover(ctx, Target{URL: f.URL(), Timeout: 5 * time.Second, TLS: id}); class(t, err).Class != ClassNotAllowed {
		t.Fatalf("loopback without the allowance: %v", err)
	}
}

// A TLS failure is not cached as an era and doesn't send the probe down the
// legacy path.
func TestTLSFailureLeavesTheEraCacheAlone(t *testing.T) {
	ca := testutil.NewCA(t, "Internal CA")
	f := startTLSFake(t, testutil.MTLSOptions{Server: loopbackCert(t, ca), ClientCAs: []*testutil.Cert{ca}})
	c := eraClient()
	tgt := Target{URL: f.URL(), ServerID: "s9", Timeout: 5 * time.Second}
	if _, err := c.Discover(context.Background(), tgt); class(t, err).Class != ClassTLS {
		t.Fatal("expected a TLS failure")
	}
	if _, ok := c.Eras.get(eraKey(tgt)); ok {
		t.Fatal("a failed handshake was remembered as an era")
	}
}
