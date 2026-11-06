package auditstream

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/ncecere/open-mcp-portal/internal/upstream"
)

// SinkHTTPClient has no proxy or redirect escape from the destination guard.
func SinkHTTPClient(client *upstream.Client) *http.Client {
	return &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }, Transport: &http.Transport{
		Proxy: nil, DialContext: client.GuardedDial(), TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 10 * time.Second, DisableKeepAlives: true, ForceAttemptHTTP2: true,
	}}
}

// Send discards bounded response data and returns only a fixed, secret-free class.
func Send(client *http.Client, req *http.Request) string {
	resp, err := client.Do(req)
	if err != nil {
		return transportClass(err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return ""
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		return "http_3xx"
	case resp.StatusCode >= 400 && resp.StatusCode < 500:
		return "http_4xx"
	default:
		return "http_5xx"
	}
}
func transportClass(err error) string {
	var ne net.Error
	var dns *net.DNSError
	var ua x509.UnknownAuthorityError
	var hn x509.HostnameError
	var ci x509.CertificateInvalidError
	var rh tls.RecordHeaderError
	switch {
	case errors.Is(err, upstream.ErrBlockedAddress):
		return "policy_denied"
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &ne) && ne.Timeout():
		return "timeout"
	case errors.As(err, &dns):
		return "dns"
	case errors.As(err, &ua), errors.As(err, &hn), errors.As(err, &ci), errors.As(err, &rh), strings.Contains(err.Error(), "tls:"):
		return "tls"
	default:
		return "connect"
	}
}
