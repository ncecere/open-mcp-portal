package upstream

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/ncecere/open-mcp-portal/internal/apperr"
	"github.com/ncecere/open-mcp-portal/internal/netpolicy"
)

// The address rule (adapted from Grounded's internal/mcpclient, see
// docs/registry.md "Security" and internal/netpolicy): an MCP server's URL
// is https, and every address its host is or resolves to is allowed by the
// policy: public addresses always, private (internal) ones when a platform
// admin's or the deployment's allowlist entry covers them, and loopback,
// link-local (including cloud metadata), unspecified, multicast and
// broadcast addresses never. Plain http is accepted only for hosts an entry
// allows it for. The rule is checked when the URL is saved (shape, scheme,
// literal addresses and host entries), before every exchange, and, pinned,
// every time a connection is dialled, against every address the host
// resolves to, so a DNS change can't point a registered server at an
// address the policy refuses. With the development allowance (DEV_AUTH on
// a loopback APP_URL) private, loopback and link-local addresses are
// accepted, and plain http is accepted for loopback hosts. Redirects are
// never followed and proxy settings from the environment are never used.

// ErrBlockedAddress: the URL's host is (or resolves to) an address the rule
// refuses, or the server redirected.
var ErrBlockedAddress = errors.New("upstream: address not allowed")

// MaxURL bounds a server URL.
const MaxURL = 500

// URL problems (details.reason of 422 url_not_allowed).
const (
	ReasonInvalid        = "invalid"
	ReasonTooLong        = "too_long"
	ReasonUserInfo       = "userinfo"
	ReasonQuery          = "query"
	ReasonFragment       = "fragment"
	ReasonScheme         = "scheme"
	ReasonPrivateAddress = netpolicy.ReasonPrivateAddress
	ReasonBlockedAddress = netpolicy.ReasonBlockedAddress
)

// Messages of the address problems.
const (
	MessagePrivateAddress = "The URL's address is internal (private). MCP servers must be reachable at a public address, " +
		"unless a platform admin allows the internal network (Admin › Internal networks)."
	MessageBlockedAddress = "The URL's address is loopback, link-local (such as cloud metadata), unspecified, multicast or broadcast, " +
		"which MCP servers may never use."
	messageNumericHost = "Write the address in standard form (such as 10.20.0.5); other numeric notations are refused."
	messageScheme      = "The URL must use https."
)

func refused(reason, msg string) error {
	e := apperr.New(http.StatusUnprocessableEntity, "url_not_allowed", msg)
	e.Details = map[string]any{"reason": reason}
	return e
}

// NormalizeURL is NormalizeURLWith without allowlist entries.
func NormalizeURL(raw string, allowPrivate bool) (string, error) {
	return NormalizeURLWith(raw, allowPrivate, nil)
}

// NormalizeURLWith checks a server URL against the policy: https (http
// only for a host an entry allows it for, or a loopback host with the
// development allowance), a host, no user info, query or fragment
// (credentials belong in the header, which is stored encrypted), and a
// literal IP address or localhost only when the rule allows it. Host names
// are resolved when dialling. Problems are 422 url_not_allowed with
// details.reason.
func NormalizeURLWith(raw string, allowPrivate bool, p *netpolicy.Policy) (string, error) {
	raw = strings.TrimSpace(raw)
	u, err := url.Parse(raw)
	if reason, msg := urlShapeProblem(raw, u, err); reason != "" {
		return "", refused(reason, msg)
	}
	host := u.Hostname()
	switch u.Scheme {
	case "https":
	case "http":
		_, entry := p.HTTPAllowed(host)
		if !entry && !(allowPrivate && loopbackHost(host)) {
			return "", refused(ReasonScheme, messageScheme)
		}
	default:
		return "", refused(ReasonScheme, messageScheme)
	}
	if allowPrivate {
		return u.String(), nil
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		if v := p.CheckAddr(host, ip); !v.Allowed {
			return "", addressRefused(v.Reason)
		}
		return u.String(), nil
	}
	if h := strings.ToLower(strings.TrimSuffix(host, ".")); h == "localhost" || strings.HasSuffix(h, ".localhost") {
		return "", refused(ReasonBlockedAddress, MessageBlockedAddress)
	}
	if netpolicy.NumericHost(host) {
		// Other notations of an address ("0177.0.0.1", "0x7f.1", "127.1") are
		// what SSRF attempts use; they are never allowed.
		return "", refused(ReasonPrivateAddress, messageNumericHost)
	}
	return u.String(), nil
}

func addressRefused(reason string) error {
	if reason == netpolicy.ReasonBlockedAddress {
		return refused(ReasonBlockedAddress, MessageBlockedAddress)
	}
	return refused(ReasonPrivateAddress, MessagePrivateAddress)
}

// urlShapeProblem says what is wrong with a URL's shape ("" when nothing
// is). A host name's addresses are checked when dialling, not here.
func urlShapeProblem(raw string, u *url.URL, err error) (reason, msg string) {
	switch {
	case len(raw) > MaxURL:
		return ReasonTooLong, fmt.Sprintf("The URL is too long: at most %d characters.", MaxURL)
	case err != nil || u.Host == "" || u.Hostname() == "":
		return ReasonInvalid, "Enter a full URL, such as https://status.example.com/mcp."
	case u.User != nil:
		return ReasonUserInfo, "The URL can't contain a user name or password. Put credentials in the header instead."
	case u.RawQuery != "" || u.ForceQuery:
		return ReasonQuery, "The URL can't have a query (?…). Put credentials in the header instead."
	case u.Fragment != "" || strings.Contains(raw, "#"):
		return ReasonFragment, "The URL can't have a fragment (#…)."
	}
	return "", ""
}

func loopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.IsLoopback()
}

// PublicAddr reports whether ip is a public unicast address: not private,
// loopback, link-local, CGNAT, metadata, documentation or translation space.
func PublicAddr(ip netip.Addr) bool { return netpolicy.PublicAddr(ip) }

// resolver looks up a host's addresses (tests replace it).
type resolver func(ctx context.Context, host string) ([]netip.Addr, error)

func defaultResolver(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// dialer dials only addresses the rule allows, resolving the host once and
// pinning the connection to the approved addresses.
type dialer struct {
	allowPrivate bool
	// policy is the allowlist in force (read at every dial; nil: none).
	policy func(ctx context.Context) *netpolicy.Policy
	lookup resolver
	// connect dials an approved address (nil: net.Dialer with a 10s timeout).
	connect func(ctx context.Context, network, address string) (net.Conn, error)
}

func (d *dialer) dial(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	var ips []netip.Addr
	if ip, err := netip.ParseAddr(host); err == nil {
		ips = []netip.Addr{ip}
	} else if ips, err = d.lookup(ctx, host); err != nil {
		return nil, fmt.Errorf("upstream: resolve %s: %w", host, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("upstream: %s has no addresses", host)
	}
	if !d.allowPrivate {
		var p *netpolicy.Policy
		if d.policy != nil {
			p = d.policy(ctx)
		}
		for _, ip := range ips {
			if v := p.CheckAddr(host, ip); !v.Allowed {
				return nil, fmt.Errorf("%w: %s resolved to %s (%s)", ErrBlockedAddress, host, ip, v.Reason)
			}
		}
	}
	connect := d.connect
	if connect == nil {
		nd := &net.Dialer{Timeout: 10 * time.Second}
		connect = nd.DialContext
	}
	var errs []error
	for _, ip := range ips {
		conn, err := connect(ctx, network, net.JoinHostPort(ip.Unmap().String(), port))
		if err == nil {
			return conn, nil
		}
		errs = append(errs, err)
		if ctx.Err() != nil {
			break
		}
	}
	return nil, fmt.Errorf("upstream: dial %s: %w", host, errors.Join(errs...))
}

// GuardedDial returns a dial function that applies the address rule of
// this client (the development allowance and the allowlist in force) to
// every address a host resolves to, and pins the connection to them; a
// refused address fails with ErrBlockedAddress. Other fetches of URLs
// chosen by someone else (OAuth client metadata documents) use it.
func (c *Client) GuardedDial() func(ctx context.Context, network, address string) (net.Conn, error) {
	d := &dialer{allowPrivate: c.AllowPrivate, policy: c.policy, lookup: c.resolve(), connect: c.Dial}
	return d.dial
}

// exchange records what the server answered, for error classes.
type exchange struct {
	mu     sync.Mutex
	status int // the last HTTP status >= 400 (0: none)
	// challenge holds the WWW-Authenticate values of the last 401 or 403
	// (an OAuth-protected server's error and scope).
	challenge []string
	// detail is the start of the last error response's body (at most
	// errorPeek bytes, raw: classify redacts it before anyone sees it).
	detail string
}

// errorPeek bounds how much of an error response's body is kept to explain
// the failure.
const errorPeek = 2048

func (e *exchange) setDetail(d string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.detail = d
}

func (e *exchange) lastDetail() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.detail
}

func (e *exchange) setStatus(code int, h http.Header) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if code >= 400 {
		e.status = code
	}
	if code == http.StatusUnauthorized || code == http.StatusForbidden {
		e.challenge = append([]string(nil), h.Values("WWW-Authenticate")...)
	}
}

func (e *exchange) lastStatus() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.status
}

func (e *exchange) lastChallenge() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.challenge
}

// ErrResponseTooLarge: a response body passed MaxResponseBytes.
var ErrResponseTooLarge = errors.New("upstream: response too large")

// headerTransport adds the server's credential parts, records error statuses
// and caps response bodies.
type headerTransport struct {
	next          http.RoundTripper
	creds         []Credential
	identity      string
	identityValue string
	provider      string
	providerToken string
	bearer        string
	params        map[string]string
	maxResponse   int64
	ex            *exchange
}

func (t *headerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	orig := req
	if len(t.creds) > 0 || t.identity != "" || t.providerToken != "" || t.bearer != "" || len(t.params) > 0 {
		req = req.Clone(req.Context())
	}
	if len(t.params) > 0 && isToolsCall(req) {
		for k, v := range t.params {
			req.Header.Set(k, v)
		}
	}
	applyCredentials(req, t.creds)
	// An oauth server's own token for the person (the registry refuses a
	// static Authorization header in oauth mode).
	if t.bearer != "" {
		req.Header.Set("Authorization", "Bearer "+t.bearer)
	}
	// The identity never replaces the server's own header: the caller picks
	// a different header name when a credential part is Authorization.
	if t.identity != "" && !t.occupied(t.identity) {
		req.Header.Set(t.identity, t.identityValue)
	}
	// A static header can't use these names (the registry refuses them).
	if t.providerToken != "" {
		req.Header.Set("MCP-Gateway-Provider", t.provider)
		req.Header.Set("MCP-Gateway-Provider-Token", t.providerToken)
	}
	res, err := t.next.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	// The response keeps the request as the caller made it: a query part
	// exists only on the copy that went out, so nothing that prints
	// res.Request.URL (the SDK's errors included) can show it.
	res.Request = orig
	t.ex.setStatus(res.StatusCode, res.Header)
	if res.StatusCode >= 400 && res.Body != nil {
		// Keep the start of an error body to explain the failure, and hand
		// the whole body on unchanged.
		head := make([]byte, errorPeek)
		n, _ := io.ReadFull(res.Body, head)
		head = head[:n]
		t.ex.setDetail(string(head))
		res.Body = struct {
			io.Reader
			io.Closer
		}{io.MultiReader(bytes.NewReader(head), res.Body), res.Body}
	}
	res.Body = &cappedBody{ReadCloser: res.Body, left: t.maxResponse}
	return res, nil
}

// occupied reports whether a credential part sets the header.
func (t *headerTransport) occupied(header string) bool {
	for _, c := range t.creds {
		if c.occupies(header) {
			return true
		}
	}
	return false
}

// isToolsCall reports whether a request posts a JSON-RPC tools/call (the
// only request that carries parameter headers). The body is read and put
// back unchanged.
func isToolsCall(req *http.Request) bool {
	if req.Method != http.MethodPost || req.Body == nil || req.Body == http.NoBody {
		return false
	}
	if req.Header.Get("Mcp-Method") == "tools/call" {
		return true
	}
	body, err := io.ReadAll(io.LimitReader(req.Body, 4<<20))
	_ = req.Body.Close()
	req.Body = io.NopCloser(bytes.NewReader(body))
	req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
	req.ContentLength = int64(len(body))
	if err != nil {
		return false
	}
	var msg struct {
		Method string `json:"method"`
	}
	return json.Unmarshal(body, &msg) == nil && msg.Method == "tools/call"
}

// cappedBody fails a read past its limit.
type cappedBody struct {
	io.ReadCloser
	left int64
}

func (b *cappedBody) Read(p []byte) (int, error) {
	if b.left <= 0 {
		return 0, ErrResponseTooLarge
	}
	if int64(len(p)) > b.left {
		p = p[:b.left+1] // one byte more tells a body that ends exactly at the limit from a longer one
	}
	n, err := b.ReadCloser.Read(p)
	b.left -= int64(n)
	if b.left < 0 {
		return n - 1, ErrResponseTooLarge
	}
	return n, err
}

// httpClient builds the client of one exchange with a server: the guarded
// dialer, no proxy from the environment, no redirects, the header and the
// body cap. done closes its idle connections.
func (c *Client) httpClient(t Target, ex *exchange) (client *http.Client, done func()) {
	d := &dialer{allowPrivate: c.AllowPrivate, policy: c.policy, lookup: c.resolve(), connect: c.Dial}
	tr := &http.Transport{
		Proxy:                 nil, // never HTTP(S)_PROXY: the dialer must see the real destination
		DialContext:           d.dial,
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: t.Timeout,
		MaxIdleConns:          4,
		IdleConnTimeout:       30 * time.Second,
		// TLS 1.2 at least, the host name verified, and, for a server that has
		// them, its own CA bundle in place of the system roots and its client
		// certificate (tls.go). Every exchange builds its own transport, so no
		// connection, HTTP/2 stream or TLS session is shared between servers
		// (or between two TLS identities of one server): the identity is part
		// of what the connection is.
		TLSClientConfig: tlsConfig(t.TLS),
	}
	return &http.Client{
		Transport: &headerTransport{next: tr, creds: t.Credentials, identity: t.IdentityHeader,
			identityValue: t.IdentityValue, provider: t.Provider, providerToken: t.ProviderToken, bearer: t.BearerToken,
			params: t.ParamHeaders, maxResponse: c.bodyCap(t), ex: ex},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return fmt.Errorf("%w: MCP servers may not redirect", ErrBlockedAddress)
		},
	}, tr.CloseIdleConnections
}
