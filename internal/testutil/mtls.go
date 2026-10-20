package testutil

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
)

// MTLSFake is the fake MCP server behind TLS that requires and verifies
// client certificates (the setup of an internal service behind a private CA),
// over HTTP/2 when the client speaks it.
type MTLSFake struct {
	*FakeMCP
	conns atomic.Int64
	mu    sync.Mutex
	seen  []MTLSSeen
}

// MTLSSeen is what one request showed the server about its connection.
type MTLSSeen struct {
	// ClientCN is the common name of the client certificate ("" when none).
	ClientCN   string
	ProtoMajor int
	// Version is the TLS version; ServerName the SNI the client sent.
	Version    uint16
	ServerName string
}

// MTLSOptions shapes the fake.
type MTLSOptions struct {
	// Server is the server's certificate; ClientCAs sign the client
	// certificates it accepts.
	Server    *Cert
	ClientCAs []*Cert
	// NoClientCert asks for no client certificate at all.
	NoClientCert bool
	// MaxVersion caps the TLS version the server speaks (0: the default).
	MaxVersion uint16
}

// StartMTLSFake starts the fake (closed with the test). Its URL() is the
// https URL of the MCP endpoint.
func StartMTLSFake(t testing.TB, o MTLSOptions) *MTLSFake {
	t.Helper()
	fake, h := NewFakeMCPHandler()
	f := &MTLSFake{FakeMCP: fake}
	var srv *httptest.Server
	srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s := MTLSSeen{ProtoMajor: r.ProtoMajor}
		if r.TLS != nil {
			s.Version, s.ServerName = r.TLS.Version, r.TLS.ServerName
			if len(r.TLS.PeerCertificates) > 0 {
				s.ClientCN = r.TLS.PeerCertificates[0].Subject.CommonName
			}
		}
		f.mu.Lock()
		f.seen = append(f.seen, s)
		f.mu.Unlock()
		// The MCP handler's DNS-rebinding guard wants a loopback Host on a
		// loopback listener; the handshake already used the name it was given.
		r.Host = srv.Listener.Addr().String()
		h.ServeHTTP(w, r)
	}))
	srv.EnableHTTP2 = true
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{o.Server.TLSCertificate()}, MaxVersion: o.MaxVersion}
	if !o.NoClientCert {
		srv.TLS.ClientAuth = tls.RequireAndVerifyClientCert
		srv.TLS.ClientCAs = Pool(o.ClientCAs...)
	}
	if o.MaxVersion != 0 && o.MaxVersion < tls.VersionTLS12 {
		srv.TLS.MinVersion = tls.VersionTLS10
	}
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			f.conns.Add(1)
		}
	}
	srv.StartTLS()
	fake.Server = srv
	t.Cleanup(srv.Close)
	return f
}

// Seen is every request's connection facts, in order.
func (f *MTLSFake) Seen() []MTLSSeen {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]MTLSSeen(nil), f.seen...)
}

// Conns is how many connections the server accepted.
func (f *MTLSFake) Conns() int64 { return f.conns.Load() }

// Addr is the listener's address (host:port).
func (f *MTLSFake) Addr() string { return f.Listener.Addr().String() }
