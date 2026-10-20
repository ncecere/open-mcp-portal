package upstream

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"syscall"
)

// ClassTLS: the TLS handshake with the server failed: its certificate isn't
// trusted or isn't for the host name, it expired, or the server refused the
// portal's client certificate. It is never a reason to fall back to anything
// weaker: there is no setting that skips verification.
const ClassTLS = "tls"

// hostOf is the host of the URL a failed request was for ("the server" when
// the error doesn't say).
func hostOf(err error, t Target) string {
	var ue *url.Error
	if errors.As(err, &ue) {
		if u, perr := url.Parse(ue.URL); perr == nil && u.Hostname() != "" {
			return u.Hostname()
		}
	}
	if u, perr := url.Parse(t.URL); perr == nil && u.Hostname() != "" {
		return u.Hostname()
	}
	return "the server"
}

// certNames lists the names a server certificate is valid for, for the
// message that says it isn't valid for the host.
func certNames(c *x509.Certificate) string {
	var names []string
	for _, n := range c.DNSNames {
		names = append(names, clip(n, 80))
	}
	for _, ip := range c.IPAddresses {
		names = append(names, ip.String())
	}
	if len(names) == 0 {
		return "no DNS or IP names at all"
	}
	more := ""
	if len(names) > 6 {
		names, more = names[:6], fmt.Sprintf(" and %d more", len(names)-6)
	}
	return strings.Join(names, ", ") + more
}

// tlsFailure turns a TLS error of an exchange into an *Error of class tls,
// with a message that says what to do; nil when err isn't a TLS problem.
// The messages quote only public facts (the host and the names the server's
// certificate lists), never the client key or certificate.
func tlsFailure(t Target, err error) *Error {
	host := hostOf(err, t)
	var (
		hostErr    x509.HostnameError
		unknownCA  x509.UnknownAuthorityError
		invalid    x509.CertificateInvalidError
		record     tls.RecordHeaderError
		verifyFail *tls.CertificateVerificationError
	)
	hasCA := t.TLS.HasCA()
	switch {
	case errors.As(err, &hostErr):
		return &Error{Class: ClassTLS, Message: clipMessage(fmt.Sprintf(
			"The server's certificate isn't valid for the host name %s: it lists %s in its Subject Alternative Names. "+
				"Host names are always verified (a common name alone doesn't count): use a certificate whose names include %s, or register the server under a name it lists.",
			host, certNames(hostErr.Certificate), host))}
	case errors.As(err, &invalid):
		switch invalid.Reason {
		case x509.Expired:
			return &Error{Class: ClassTLS, Message: messageServerCertExpired}
		case x509.NotAuthorizedToSign, x509.IncompatibleUsage, x509.CANotAuthorizedForThisName, x509.TooManyIntermediates, x509.NameConstraintsWithoutSANs,
			x509.UnconstrainedName, x509.TooManyConstraints, x509.CANotAuthorizedForExtKeyUsage:
			return &Error{Class: ClassTLS, Message: "The server's certificate chain isn't acceptable (" + certReason(invalid.Reason) + ")."}
		}
		return &Error{Class: ClassTLS, Message: "The server's certificate isn't valid (" + certReason(invalid.Reason) + ")."}
	case errors.As(err, &unknownCA):
		return &Error{Class: ClassTLS, Message: unknownAuthorityMessage(hasCA)}
	case errors.As(err, &record):
		return &Error{Class: ClassTLS, Message: "The server didn't answer with TLS on this port: check that the URL's host and port serve https."}
	}
	// What the standard library or the platform's verifier words as text only
	// (macOS and Windows verify against the system roots themselves), and the
	// alerts a server sends: "remote error: tls: bad certificate".
	s := err.Error()
	switch {
	case strings.Contains(s, "server gave HTTP response to HTTPS client"):
		return &Error{Class: ClassTLS, Message: "The server didn't answer with TLS: does the URL need http:// instead of https://?"}
	case strings.Contains(s, "protocol version not supported"), strings.Contains(s, "no supported versions"), strings.Contains(s, "protocol version"):
		return &Error{Class: ClassTLS, Message: "The server doesn't speak TLS 1.2 or newer, which is the minimum."}
	}
	if alert, ok := remoteAlert(s); ok {
		return &Error{Class: ClassTLS, Message: alertMessage(alert, t.TLS.HasClientCert())}
	}
	if closedAfterHandshake(err, t) {
		return &Error{Class: ClassTLS, Message: closedAfterHandshakeMessage(t.TLS.HasClientCert())}
	}
	switch {
	case strings.Contains(s, "unknown authority"), strings.Contains(s, "is not trusted"):
		return &Error{Class: ClassTLS, Message: unknownAuthorityMessage(hasCA)}
	case strings.Contains(s, "x509:") && strings.Contains(s, "expired"):
		return &Error{Class: ClassTLS, Message: messageServerCertExpired}
	case errors.As(err, &verifyFail):
		return &Error{Class: ClassTLS, Message: "The server's certificate couldn't be verified."}
	case strings.Contains(s, "x509:"), strings.Contains(s, "tls: "):
		return &Error{Class: ClassTLS, Message: "The TLS handshake with the server failed."}
	}
	return nil
}

const messageServerCertExpired = "The server's certificate (or one in its chain) has expired or isn't valid yet. Its owner needs to renew it."

func unknownAuthorityMessage(hasCA bool) string {
	if hasCA {
		return "The server's certificate isn't signed by a CA in this server's TLS settings. " +
			"The CA bundle replaces the system roots for this server: it must include the CA (and any intermediates) that signed the server's certificate."
	}
	return "The server's certificate is signed by an authority the portal doesn't trust (a private CA, perhaps). " +
		"If the server uses a private CA, add that CA's certificate in this server's TLS settings (it applies to this server only)."
}

// closedAfterHandshake reports whether an https request failed because the
// server dropped the connection right after the handshake: writing the request
// to a fresh connection (each exchange builds its own, so none is reused) got a
// broken pipe or a reset, or HTTP/2 found its connection closed or never got it started. With TLS 1.3 the
// client finishes its handshake before the server has checked the client
// certificate, so a server that refuses it (or wants one the portal didn't
// send) shows up like this when its alert is lost to the reset, rather than as
// "remote error: tls: bad certificate". Which of the two the client sees is a
// race, so both are the same class.
func closedAfterHandshake(err error, t Target) bool {
	if !strings.HasPrefix(strings.ToLower(t.URL), "https://") {
		return false
	}
	if m := err.Error(); strings.Contains(m, "http2: client conn could not be established") || strings.Contains(m, "http2: client conn is closed") {
		return true
	}
	var op *net.OpError
	return errors.As(err, &op) && op.Op == "write" && (errors.Is(err, syscall.EPIPE) || errors.Is(err, syscall.ECONNRESET))
}

func closedAfterHandshakeMessage(haveClientCert bool) string {
	const base = "The server closed the connection as soon as the TLS handshake finished. A server that requires a client certificate (mTLS) does this when it doesn't get one it accepts."
	if haveClientCert {
		return base + " Check the client certificate in this server's TLS settings: it must be one the server's CA signed."
	}
	return base + " If it does, add a client certificate in this server's TLS settings."
}

var alertRE = regexp.MustCompile(`remote error: tls: ([a-z0-9 ]{3,60})`)

// remoteAlert reads the alert a server sent ("bad certificate").
func remoteAlert(s string) (string, bool) {
	m := alertRE.FindStringSubmatch(s)
	if m == nil {
		return "", false
	}
	return m[1], true
}

func certReason(r x509.InvalidReason) string {
	switch r {
	case x509.Expired:
		return "expired or not yet valid"
	case x509.NotAuthorizedToSign:
		return "a certificate in the chain isn't a CA"
	case x509.IncompatibleUsage:
		return "its key usage doesn't allow this use"
	case x509.TooManyIntermediates:
		return "too many intermediates"
	case x509.CANotAuthorizedForThisName:
		return "a CA isn't allowed to sign this name"
	}
	return "see the server's certificate chain"
}

func alertMessage(alert string, haveClientCert bool) string {
	const clientHint = " Check the client certificate in this server's TLS settings: it must be one the server's CA signed."
	switch {
	case strings.Contains(alert, "certificate required"):
		if haveClientCert {
			return "The server requires a client certificate and did not accept the one presented." + clientHint
		}
		return "The server requires a client certificate (mTLS). Add one in this server's TLS settings."
	case strings.Contains(alert, "bad certificate"), strings.Contains(alert, "unknown certificate authority"), strings.Contains(alert, "certificate unknown"),
		strings.Contains(alert, "certificate expired"), strings.Contains(alert, "certificate revoked"), strings.Contains(alert, "unsupported certificate"):
		if haveClientCert {
			return "The server rejected the portal's client certificate (" + alert + ")." + clientHint
		}
		return "The server rejected the TLS handshake (" + alert + "). If it requires a client certificate, add one in this server's TLS settings."
	}
	return "The server ended the TLS handshake (" + alert + ")."
}
