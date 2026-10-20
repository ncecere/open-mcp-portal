package upstream

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"syscall"
	"testing"
)

// With TLS 1.3 a server that refuses the client certificate is seen, depending
// on timing, as its alert or as the connection dropped under the first write
// (or an HTTP/2 connection closed at once): both are class tls on https, and
// nothing else is.
func TestTLSFailureConnectionClosedAfterHandshake(t *testing.T) {
	write := func(errno error) error {
		return &url.Error{Op: "Post", URL: "https://x.example/mcp", Err: &net.OpError{Op: "write", Net: "tcp", Err: fmt.Errorf("write: %w", errno)}}
	}
	https, plain := Target{URL: "https://x.example/mcp"}, Target{URL: "http://x.example/mcp"}
	for name, tc := range map[string]struct {
		t    Target
		err  error
		want bool
	}{
		"broken pipe":        {https, write(syscall.EPIPE), true},
		"reset by peer":      {https, write(syscall.ECONNRESET), true},
		"http2 not started":  {https, &url.Error{Op: "Post", URL: https.URL, Err: errors.New("http2: client conn could not be established")}, true},
		"http2 closed":       {https, &url.Error{Op: "Post", URL: https.URL, Err: errors.New("http2: client conn is closed")}, true},
		"plain http":         {plain, write(syscall.EPIPE), false},
		"a refused dial":     {https, &url.Error{Op: "Post", URL: https.URL, Err: &net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}}, false},
		"a read that resets": {https, &url.Error{Op: "Post", URL: https.URL, Err: &net.OpError{Op: "read", Err: syscall.ECONNRESET}}, false},
	} {
		e := tlsFailure(tc.t, tc.err)
		if got := e != nil; got != tc.want {
			t.Errorf("%s: tls failure = %v, want %v", name, e, tc.want)
		}
		if e != nil && (e.Class != ClassTLS || !strings.Contains(e.Message, "client certificate")) {
			t.Errorf("%s: %+v", name, e)
		}
	}
}
