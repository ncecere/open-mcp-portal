package upstream

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/otel/trace"

	"github.com/ncecere/open-mcp-portal/internal/observability"
)

// Machine tokens (decision 73, docs/machine-oauth.md): for a server in
// machine_oauth mode the portal is an OAuth client itself. It asks the server's
// authorization server for a token with the client credentials grant (RFC
// 6749 section 4.4) and sends it as Authorization: Bearer to the server.
//
// The token request goes through the address guard like every request to a
// server or provider endpoint (GuardedDial: no proxy, no redirects, 10 s, a
// body of at most 64 KiB), and a failed one is reduced to an OAuth error code
// (safeMachineCode): nothing the authorization server says is shown, logged or
// stored beyond it, and neither the client secret nor a token is ever in an
// error.
//
// Tokens are kept in memory, one per server, with their expiry less a margin;
// nothing is stored in the database. Concurrent requests for the same server
// share one token request (single flight). A configuration change (the token
// endpoint, the client, its secret, the scopes, the audience or the resource)
// changes the cache key, so the old token is never used for the new one.

// Machine token limits.
const (
	// MachineTimeout bounds one token request.
	MachineTimeout = 10 * time.Second
	// machineSkew is how long before its expiry a token stops being used.
	machineSkew = 60 * time.Second
	// machineDefaultLifetime applies when the answer has no expires_in.
	machineDefaultLifetime = 5 * time.Minute
	// machineMaxLifetime caps what a token's expires_in can keep it in memory.
	machineMaxLifetime = 24 * time.Hour
	maxMachineBody     = 64 << 10
	maxMachineToken    = 8192
)

// Client authentication at the token endpoint (RFC 6749 section 2.3.1).
const (
	MachineAuthBasic = "client_secret_basic"
	MachineAuthPost  = "client_secret_post"
)

// ReasonMachineAuthUnavailable is the data.reason of a call that could not
// be made because the portal could not get a machine token (the authorization
// server was unreachable, failing or refused by the address rules).
const ReasonMachineAuthUnavailable = "machine_auth_unavailable"

// MachineConfig is a server's machine OAuth client as the token source uses
// it: plain, for the length of a request.
type MachineConfig struct {
	// ServerID names the cache entry.
	ServerID string
	TokenURL string
	ClientID string
	// ClientSecret is never logged, audited or returned.
	ClientSecret string
	// AuthMethod is MachineAuthBasic (the default) or MachineAuthPost.
	AuthMethod string
	Scopes     []string
	// Audience and Resource (RFC 8707) are sent when set.
	Audience, Resource string
}

// fingerprint identifies everything a token depends on, secret included, so
// a changed configuration never reuses a token. It exists only in memory.
func (c MachineConfig) fingerprint() string {
	h := sha256.New()
	for _, s := range append([]string{c.TokenURL, c.ClientID, c.ClientSecret, c.AuthMethod, c.Audience, c.Resource}, c.Scopes...) {
		h.Write([]byte(strconv.Itoa(len(s)) + ":" + s + "\n"))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// MachineError is a failed token request. Code is an OAuth error code (or one
// of ours: not_allowed, redirect, timeout, unreachable, unreadable, too_large,
// invalid_response, server_error, config). Unavailable says the authorization
// server could not be used (network, address rules, 5xx, 429, a malformed
// answer): nothing is concluded about the client. Otherwise the client was
// refused. The text never holds a secret or anything the server said.
type MachineError struct {
	Code        string
	Status      int
	Unavailable bool
}

func (e *MachineError) Error() string {
	if e.Status > 0 {
		return fmt.Sprintf("machine token: %s (HTTP %d)", e.Code, e.Status)
	}
	return "machine token: " + e.Code
}

// AsError is the failure as a call or a check reports it: class auth when the
// authorization server refused the client, otherwise the class of what went
// wrong (not_allowed, timeout, unavailable) with Reason machine_auth_unavailable.
func (e *MachineError) AsError() *Error {
	if !e.Unavailable {
		return &Error{Class: ClassAuth, HTTPStatus: 0,
			Message: "The authorization server refused the portal's client (" + e.Code + "). Check the server's client ID, secret and scopes."}
	}
	class := ClassUnavailable
	switch e.Code {
	case "not_allowed":
		class = ClassNotAllowed
	case "timeout":
		class = ClassTimeout
	case "config":
		return &Error{Class: ClassConfig, Message: "The server's machine client can't be used: enter its secret again."}
	}
	return &Error{Class: class, Reason: ReasonMachineAuthUnavailable,
		Message: "The portal could not get a token for this server: its authorization server is unavailable (" + e.Code + ")."}
}

func machineUnavailable(code string, status int) *MachineError {
	return &MachineError{Code: code, Status: status, Unavailable: true}
}

var machineCodeRE = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)

// safeMachineCode keeps an OAuth error code when it looks like one.
func safeMachineCode(c string) string {
	if machineCodeRE.MatchString(c) {
		return strings.ToLower(c)
	}
	return "error"
}

// MachineTokens fetches and caches machine tokens.
type MachineTokens struct {
	client *Client
	// TLS is the TLS configuration of token requests (tests).
	TLS *tls.Config
	// Now is the clock (tests).
	Now func() time.Time

	once sync.Once
	http *http.Client

	mu      sync.Mutex
	cache   map[string]machineEntry
	flights map[string]*machineFlight
}

type machineEntry struct {
	token, fp string
	// refreshAt is when the token stops being used (expiry less the margin).
	refreshAt time.Time
}

type machineFlight struct {
	fp    string
	done  chan struct{}
	token string
	err   *MachineError
}

// NewMachineTokens returns a token source whose requests are guarded by c's
// address rules (the development allowance and the internal-network allowlist).
func NewMachineTokens(c *Client) *MachineTokens {
	return &MachineTokens{client: c, cache: map[string]machineEntry{}, flights: map[string]*machineFlight{}}
}

func (m *MachineTokens) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

func errMachineRedirect(*http.Request, []*http.Request) error {
	return errors.New("upstream: token endpoints may not redirect")
}

func (m *MachineTokens) httpClient() *http.Client {
	m.once.Do(func() {
		tr := &http.Transport{
			Proxy:                 nil, // never HTTP(S)_PROXY: the dialer must see the real destination
			DialContext:           m.client.GuardedDial(),
			TLSClientConfig:       m.TLS,
			ForceAttemptHTTP2:     true,
			TLSHandshakeTimeout:   MachineTimeout,
			ResponseHeaderTimeout: MachineTimeout,
			MaxIdleConns:          8,
			IdleConnTimeout:       30 * time.Second,
		}
		m.http = &http.Client{Transport: tr, Timeout: MachineTimeout, CheckRedirect: errMachineRedirect}
	})
	return m.http
}

// Token returns a current token for the client, from memory or from the
// authorization server (one request however many callers wait).
func (m *MachineTokens) Token(ctx context.Context, cfg MachineConfig) (string, *MachineError) {
	return m.token(ctx, cfg, "")
}

// Renew is Token after the server rejected rejected (a 401): it drops that
// token and gets another. A caller that finds a newer token already in memory
// (another call renewed it first) gets that one and no request is made.
func (m *MachineTokens) Renew(ctx context.Context, cfg MachineConfig, rejected string) (string, *MachineError) {
	return m.token(ctx, cfg, rejected)
}

// Forget drops a server's cached token (its configuration changed, or it was
// deleted or left machine_oauth).
func (m *MachineTokens) Forget(serverID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.cache, serverID)
}

// Cached reports whether a usable token is in memory for the configuration
// (tests).
func (m *MachineTokens) Cached(cfg MachineConfig) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.cache[cfg.ServerID]
	return ok && e.fp == cfg.fingerprint() && m.now().Before(e.refreshAt)
}

func (m *MachineTokens) token(ctx context.Context, cfg MachineConfig, rejected string) (string, *MachineError) {
	fp := cfg.fingerprint()
	m.mu.Lock()
	if e, ok := m.cache[cfg.ServerID]; ok && e.fp == fp && m.now().Before(e.refreshAt) && e.token != rejected {
		m.mu.Unlock()
		return e.token, nil
	}
	if rejected != "" {
		if e, ok := m.cache[cfg.ServerID]; ok && e.token == rejected {
			delete(m.cache, cfg.ServerID)
		}
	}
	f, ok := m.flights[cfg.ServerID]
	if !ok || f.fp != fp {
		f = &machineFlight{fp: fp, done: make(chan struct{})}
		m.flights[cfg.ServerID] = f
		go m.run(context.WithoutCancel(ctx), cfg, f)
	}
	m.mu.Unlock()
	select {
	case <-f.done:
		return f.token, f.err
	case <-ctx.Done():
		return "", machineUnavailable("timeout", 0)
	}
}

// run makes one token request for a flight and publishes its outcome.
func (m *MachineTokens) run(ctx context.Context, cfg MachineConfig, f *machineFlight) {
	ctx, cancel := context.WithTimeout(ctx, MachineTimeout)
	defer cancel()
	ctx, sp := observability.Start(ctx, "upstream.machine_token", trace.SpanKindClient)
	token, ttl, err := m.request(ctx, cfg)
	result := "ok"
	switch {
	case err == nil:
	case err.Unavailable:
		result = "unavailable"
		observability.Annotate(sp, observability.AttrErrorClass.String(err.Code))
		observability.Fail(sp, err.Code)
	default:
		result = "refused"
		observability.Annotate(sp, observability.AttrErrorClass.String(err.Code))
		observability.Fail(sp, err.Code)
	}
	observability.Annotate(sp, observability.AttrResult.String(result))
	sp.End()
	observability.MachineTokenRequests.WithLabelValues(result).Inc()

	m.mu.Lock()
	defer m.mu.Unlock()
	f.token, f.err = token, err
	if err == nil {
		now := m.now()
		margin := machineSkew
		if ttl <= 2*margin {
			margin = ttl / 2 // a short-lived token is still reused for the first half of its life
		}
		m.cache[cfg.ServerID] = machineEntry{token: token, fp: f.fp, refreshAt: now.Add(ttl - margin)}
		for id, e := range m.cache {
			if !now.Before(e.refreshAt) {
				delete(m.cache, id)
			}
		}
	}
	if m.flights[cfg.ServerID] == f {
		delete(m.flights, cfg.ServerID)
	}
	close(f.done)
}

// request posts the client credentials grant and reads the answer.
func (m *MachineTokens) request(ctx context.Context, cfg MachineConfig) (string, time.Duration, *MachineError) {
	// The address rules may have changed since the URL was saved.
	if _, err := m.client.NormalizeURL(ctx, cfg.TokenURL); err != nil {
		return "", 0, machineUnavailable("not_allowed", 0)
	}
	form := url.Values{"grant_type": {"client_credentials"}}
	if len(cfg.Scopes) > 0 {
		form.Set("scope", strings.Join(cfg.Scopes, " "))
	}
	if cfg.Audience != "" {
		form.Set("audience", cfg.Audience)
	}
	if cfg.Resource != "" {
		form.Set("resource", cfg.Resource)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.TokenURL, nil)
	if err != nil {
		return "", 0, machineUnavailable("config", 0)
	}
	switch cfg.AuthMethod {
	case MachineAuthPost:
		form.Set("client_id", cfg.ClientID)
		form.Set("client_secret", cfg.ClientSecret)
	default:
		// RFC 6749 section 2.3.1: the form-urlencoded ID and secret, in Basic.
		cred := url.QueryEscape(cfg.ClientID) + ":" + url.QueryEscape(cfg.ClientSecret)
		req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(cred)))
	}
	body := form.Encode()
	req.Body = io.NopCloser(strings.NewReader(body))
	req.ContentLength = int64(len(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	res, err := m.httpClient().Do(req)
	if err != nil {
		switch {
		case errors.Is(err, ErrBlockedAddress):
			return "", 0, machineUnavailable("not_allowed", 0)
		case strings.Contains(err.Error(), "may not redirect"):
			return "", 0, machineUnavailable("redirect", 0)
		case errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded):
			return "", 0, machineUnavailable("timeout", 0)
		}
		return "", 0, machineUnavailable("unreachable", 0)
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, maxMachineBody+1))
	if err != nil {
		return "", 0, machineUnavailable("unreadable", res.StatusCode)
	}
	if len(raw) > maxMachineBody {
		return "", 0, machineUnavailable("too_large", res.StatusCode)
	}
	return parseMachineToken(res.StatusCode, raw)
}

// parseMachineToken reads a token endpoint's answer to the client credentials
// grant.
func parseMachineToken(status int, body []byte) (string, time.Duration, *MachineError) {
	if status >= 500 || status == http.StatusTooManyRequests {
		return "", 0, machineUnavailable("server_error", status)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(body, &m); err != nil {
		if status >= 400 {
			return "", 0, &MachineError{Code: "http_" + strconv.Itoa(status), Status: status}
		}
		return "", 0, machineUnavailable("invalid_response", status)
	}
	str := func(k string) string {
		var s string
		if raw, ok := m[k]; ok && json.Unmarshal(raw, &s) == nil {
			return s
		}
		return ""
	}
	if code := str("error"); code != "" {
		e := &MachineError{Code: safeMachineCode(code), Status: status}
		e.Unavailable = e.Code == "temporarily_unavailable" || e.Code == "server_error"
		return "", 0, e
	}
	if status >= 400 {
		return "", 0, &MachineError{Code: "http_" + strconv.Itoa(status), Status: status}
	}
	token := str("access_token")
	if token == "" || len(token) > maxMachineToken || strings.IndexFunc(token, func(r rune) bool { return r <= ' ' || r == 0x7f }) >= 0 {
		return "", 0, machineUnavailable("invalid_response", status)
	}
	if tt := str("token_type"); tt != "" && !strings.EqualFold(tt, "bearer") {
		// A DPoP or MAC token can't be sent as a bearer.
		return "", 0, &MachineError{Code: "unsupported_token_type", Status: status}
	}
	ttl := machineDefaultLifetime
	if raw, ok := m["expires_in"]; ok {
		var n json.Number
		secs := int64(0)
		if json.Unmarshal(raw, &n) == nil {
			if v, err := n.Int64(); err == nil {
				secs = v
			} else if f, err := n.Float64(); err == nil {
				secs = int64(f)
			}
		} else if s := str("expires_in"); s != "" {
			secs, _ = strconv.ParseInt(s, 10, 64)
		}
		if secs > 0 {
			ttl = min(time.Duration(secs)*time.Second, machineMaxLifetime)
		}
	}
	return token, ttl, nil
}
