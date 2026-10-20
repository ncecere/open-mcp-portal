package providers

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/internal/upstream"
)

// Exchanges with a provider's token, revocation and userinfo endpoints:
// through the address guard (internal/upstream), no proxy, no redirects,
// bounded in time and size. Error bodies are reduced to an OAuth error
// code: nothing a provider says is shown, logged or stored beyond it.
const (
	endpointTimeout = 10 * time.Second
	userinfoTimeout = 5 * time.Second
	maxEndpointBody = 64 << 10
)

var errRedirect = errors.New("providers: provider endpoints may not redirect")

func noRedirect(*http.Request, []*http.Request) error { return errRedirect }

// SetEndpointTLS sets the TLS configuration of provider endpoint requests
// (tests: to trust a test server's certificate). The address guard stays.
func (s *Service) SetEndpointTLS(c *tls.Config) { s.tr.TLSClientConfig = c }

// endpointError is a failed exchange: Code is an OAuth error code (or one
// of ours), Unavailable says the provider couldn't be reached or failed
// (network, 5xx, timeout, too large): then nothing is concluded about the
// grant.
type endpointError struct {
	Code        string
	Status      int
	Unavailable bool
}

func (e *endpointError) Error() string {
	if e.Status > 0 {
		return fmt.Sprintf("provider endpoint: %s (HTTP %d)", e.Code, e.Status)
	}
	return "provider endpoint: " + e.Code
}

func unavailable(code string, status int) *endpointError {
	return &endpointError{Code: code, Status: status, Unavailable: true}
}

var codeRE = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)

// safeCode keeps an OAuth error code when it looks like one.
func safeCode(c string) string {
	if codeRE.MatchString(c) {
		return strings.ToLower(c)
	}
	return "error"
}

// do sends a request to a provider endpoint and reads its bounded body.
func (s *Service) do(ctx context.Context, req *http.Request, timeout time.Duration) (int, string, []byte, *endpointError) {
	// The allowlist may have changed since the URL was saved.
	if _, err := s.up.NormalizeURL(ctx, req.URL.String()); err != nil {
		return 0, "", nil, unavailable("not_allowed", 0)
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	res, err := s.http.Do(req.WithContext(ctx))
	if err != nil {
		switch {
		case errors.Is(err, upstream.ErrBlockedAddress):
			return 0, "", nil, unavailable("not_allowed", 0)
		case errors.Is(err, errRedirect):
			return 0, "", nil, unavailable("redirect", 0)
		case errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded):
			return 0, "", nil, unavailable("timeout", 0)
		}
		return 0, "", nil, unavailable("unreachable", 0)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, maxEndpointBody+1))
	if err != nil {
		return res.StatusCode, "", nil, unavailable("unreadable", res.StatusCode)
	}
	if len(body) > maxEndpointBody {
		return res.StatusCode, "", nil, unavailable("too_large", res.StatusCode)
	}
	mt, _, _ := mime.ParseMediaType(res.Header.Get("Content-Type"))
	return res.StatusCode, mt, body, nil
}

// clientAuth adds the provider's client authentication to a token or
// revocation request.
func clientAuth(p dbgen.AuthProvider, secret string, form url.Values, req *http.Request) {
	switch p.TokenAuthMethod {
	case AuthClientSecretBasic:
		cred := url.QueryEscape(p.ClientID) + ":" + url.QueryEscape(secret)
		req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(cred)))
	case AuthClientSecretPost:
		form.Set("client_id", p.ClientID)
		form.Set("client_secret", secret)
	default:
		form.Set("client_id", p.ClientID)
	}
}

func (s *Service) secretOf(p dbgen.AuthProvider) (string, error) {
	if p.ClientSecretCipher == nil {
		return "", nil
	}
	b, err := s.box.Open(p.ClientSecretCipher, SecretAAD(p.ID))
	if err != nil {
		return "", errors.New("providers: the client secret can't be decrypted with the current ENCRYPTION_KEY")
	}
	return string(b), nil
}

// clientOf is the provider whose client (ID, secret, token endpoint
// authentication) a provider's requests use: the linked platform provider
// of an oauth server registered with platform_provider (its client is
// shared, never its connections), else the provider itself.
func (s *Service) clientOf(ctx context.Context, p dbgen.AuthProvider) (dbgen.AuthProvider, error) {
	if !p.LinkProviderID.Valid {
		return p, nil
	}
	return s.q.GetAuthProvider(ctx, p.LinkProviderID.UUID)
}

// postForm posts a form to a provider endpoint with client authentication.
func (s *Service) postForm(ctx context.Context, p dbgen.AuthProvider, endpoint string, form url.Values) (int, string, []byte, *endpointError) {
	p, err := s.clientOf(ctx, p)
	if err != nil {
		return 0, "", nil, unavailable("config", 0)
	}
	secret, err := s.secretOf(p)
	if err != nil {
		s.Log.ErrorContext(ctx, "auth provider client secret unreadable", "provider", p.Slug)
		return 0, "", nil, unavailable("config", 0)
	}
	req, err := http.NewRequest(http.MethodPost, endpoint, nil)
	if err != nil {
		return 0, "", nil, unavailable("bad_url", 0)
	}
	clientAuth(p, secret, form, req)
	body := form.Encode()
	req.Body = io.NopCloser(strings.NewReader(body))
	req.ContentLength = int64(len(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// GitHub answers form-encoded without it.
	req.Header.Set("Accept", "application/json")
	return s.do(ctx, req, endpointTimeout)
}

// tokenSet is a token endpoint's answer.
type tokenSet struct {
	Access, Refresh string
	// ExpiresIn in seconds (0: no expiry given).
	ExpiresIn int64
	// Scopes as granted, when the answer said (HasScope).
	Scopes   []string
	HasScope bool
}

// splitScopes reads a scope string: space-separated per RFC 6749, though
// some providers (GitHub, Slack) answer with commas.
func splitScopes(s string) []string {
	out := []string{}
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ' ' || r == ',' }) {
		if f != "" && !contains(out, f) {
			out = append(out, f)
		}
	}
	return out
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// decodeAnswer reads a JSON or form-encoded body into a flat map (nested
// objects kept as raw JSON).
func decodeAnswer(mt string, body []byte) (map[string]json.RawMessage, bool) {
	trimmed := bytes.TrimSpace(body)
	if strings.Contains(mt, "json") || (len(trimmed) > 0 && trimmed[0] == '{') {
		var m map[string]json.RawMessage
		if json.Unmarshal(trimmed, &m) != nil {
			return nil, false
		}
		return m, true
	}
	vals, err := url.ParseQuery(string(trimmed))
	if err != nil {
		return nil, false
	}
	m := map[string]json.RawMessage{}
	for k, v := range vals {
		if len(v) > 0 {
			b, _ := json.Marshal(v[0])
			m[k] = b
		}
	}
	return m, true
}

func stringField(m map[string]json.RawMessage, k string) string {
	var s string
	if raw, ok := m[k]; ok && json.Unmarshal(raw, &s) == nil {
		return s
	}
	return ""
}

func intField(m map[string]json.RawMessage, k string) int64 {
	raw, ok := m[k]
	if !ok {
		return 0
	}
	var n json.Number
	if json.Unmarshal(raw, &n) == nil {
		if v, err := n.Int64(); err == nil {
			return v
		}
		if f, err := n.Float64(); err == nil {
			return int64(f)
		}
	}
	if s := stringField(m, k); s != "" {
		v, _ := strconv.ParseInt(s, 10, 64)
		return v
	}
	return 0
}

// parseToken reads a token endpoint's answer in the provider's format.
func parseToken(format string, status int, mt string, body []byte) (tokenSet, *endpointError) {
	if status >= 500 || status == http.StatusTooManyRequests {
		return tokenSet{}, unavailable("server_error", status)
	}
	m, ok := decodeAnswer(mt, body)
	if !ok {
		if status >= 400 {
			return tokenSet{}, &endpointError{Code: "http_" + strconv.Itoa(status), Status: status}
		}
		return tokenSet{}, unavailable("invalid_response", status)
	}
	if code := stringField(m, "error"); code != "" {
		e := &endpointError{Code: safeCode(code), Status: status}
		e.Unavailable = e.Code == "temporarily_unavailable" || e.Code == "server_error" || e.Code == "ratelimited"
		return tokenSet{}, e
	}
	if status >= 400 {
		return tokenSet{}, &endpointError{Code: "http_" + strconv.Itoa(status), Status: status}
	}
	if format == FormatSlackAuthedUser {
		if raw, ok := m["ok"]; ok && string(raw) != "true" {
			return tokenSet{}, &endpointError{Code: "error", Status: status}
		}
		var user map[string]json.RawMessage
		if json.Unmarshal(m["authed_user"], &user) != nil || user == nil {
			return tokenSet{}, unavailable("invalid_response", status)
		}
		m = user
	}
	out := tokenSet{Access: stringField(m, "access_token"), Refresh: stringField(m, "refresh_token"), ExpiresIn: intField(m, "expires_in")}
	if out.Access == "" || len(out.Access) > 8192 || len(out.Refresh) > 8192 {
		return tokenSet{}, unavailable("invalid_response", status)
	}
	// An absent scope means the request's scopes were granted (RFC 6749
	// \u00a75.1). An empty one is read the same way: GitHub Apps answer
	// "scope": "" because they use permissions, not scopes. If a resource
	// then answers insufficient_scope, the step-up flow asks again.
	if sc, ok := m["scope"]; ok {
		var s string
		if json.Unmarshal(sc, &s) == nil {
			if scopes := splitScopes(s); len(scopes) > 0 {
				out.Scopes, out.HasScope = scopes, true
			}
		}
	}
	return out, nil
}

// resourceParam adds RFC 8707's resource to a request of an oauth server's
// provider (the MCP spec), unless the server turned it off.
func resourceParam(p dbgen.AuthProvider, form url.Values) {
	if p.Kind == KindMCPServer && p.SendResource && p.Resource != nil {
		form.Set("resource", *p.Resource)
	}
}

// exchange trades an authorization code for tokens.
func (s *Service) exchange(ctx context.Context, p dbgen.AuthProvider, code, verifier string) (tokenSet, *endpointError) {
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {s.RedirectURI()}}
	if verifier != "" {
		form.Set("code_verifier", verifier)
	}
	resourceParam(p, form)
	status, mt, body, ee := s.postForm(ctx, p, p.TokenUrl, form)
	if ee != nil {
		return tokenSet{}, ee
	}
	return parseToken(p.TokenResponseFormat, status, mt, body)
}

// refresh uses a refresh token (the redirect URI is sent too: GitLab wants
// it, and authorization servers ignore parameters they don't know).
func (s *Service) refresh(ctx context.Context, p dbgen.AuthProvider, refreshToken string) (tokenSet, *endpointError) {
	return s.refreshScoped(ctx, p, refreshToken, nil)
}

// refreshScoped is refresh with a scope parameter (RFC 6749 section 6: the
// scopes of the new access token, which may not exceed what was granted),
// joined with the provider's scope separator; none: the grant's own scopes.
func (s *Service) refreshScoped(ctx context.Context, p dbgen.AuthProvider, refreshToken string, scopes []string) (tokenSet, *endpointError) {
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshToken}, "redirect_uri": {s.RedirectURI()}}
	if len(scopes) > 0 {
		form.Set("scope", strings.Join(scopes, p.ScopeSeparator))
	}
	resourceParam(p, form)
	status, mt, body, ee := s.postForm(ctx, p, p.TokenUrl, form)
	if ee != nil {
		return tokenSet{}, ee
	}
	return parseToken(p.TokenResponseFormat, status, mt, body)
}

// revoke revokes a token at the provider's RFC 7009 endpoint: true when it
// answered 200.
func (s *Service) revoke(ctx context.Context, p dbgen.AuthProvider, token, hint string) bool {
	if p.RevocationUrl == nil || token == "" {
		return false
	}
	form := url.Values{"token": {token}, "token_type_hint": {hint}}
	status, _, _, ee := s.postForm(ctx, p, *p.RevocationUrl, form)
	return ee == nil && status == http.StatusOK
}

// accountLabel reads the userinfo endpoint (5 s; any failure is "").
func (s *Service) accountLabel(ctx context.Context, p dbgen.AuthProvider, access string) string {
	if p.UserinfoUrl == nil {
		return ""
	}
	req, err := http.NewRequest(http.MethodGet, *p.UserinfoUrl, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Authorization", "Bearer "+access)
	req.Header.Set("Accept", "application/json")
	status, _, body, ee := s.do(ctx, req, userinfoTimeout)
	if ee != nil || status != http.StatusOK {
		return ""
	}
	var m map[string]any
	if json.Unmarshal(body, &m) != nil {
		return ""
	}
	for _, k := range []string{"preferred_username", "email", "login", "username", "name"} {
		if v, ok := m[k].(string); ok {
			if v = strings.Join(strings.Fields(v), " "); v != "" && v != access {
				r := []rune(v)
				if len(r) > 200 {
					r = r[:200]
				}
				return string(r)
			}
		}
	}
	return ""
}
