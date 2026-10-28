// Package providers is delegated credentials (docs/phase5-delegated-
// credentials.md; decisions 25-30): the auth providers platform admins
// configure (OAuth apps of GitHub, Google, ...), the connections people make
// to them, the consent links calls answer with when a connection is missing,
// and the tokens the gateway sends with calls that need them.
//
// Secrets never leave this package in clear except as the access token of a
// call (Credential), which internal/mcpgw sends only to the server whose
// capability requires that provider. Client secrets, access and refresh
// tokens and PKCE verifiers are sealed with ENCRYPTION_KEY (internal/secrets)
// and bound to their row; they are never returned, logged, audited or put
// into errors. Provider endpoints (token, revocation, userinfo) are dialled
// through internal/upstream's address guard and the internal-network
// allowlist (decision 20): no proxy, no redirects, 10 s, responses of at most
// 64 KiB. Authorization URLs are only visited by browsers.
package providers

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ncecere/open-mcp-portal/internal/apperr"
	"github.com/ncecere/open-mcp-portal/internal/audit"
	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/gateways"
	"github.com/ncecere/open-mcp-portal/internal/registry"
	"github.com/ncecere/open-mcp-portal/internal/secrets"
	"github.com/ncecere/open-mcp-portal/internal/store"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/internal/upstream"
)

// Limits.
const (
	// MaxProviders bounds how many providers exist (lists are not paged).
	MaxProviders   = 100
	maxExtraParams = 10
	maxSecret      = 2000
	maxParamValue  = 500
	maxURL         = 500
)

// Token endpoint authentication methods.
const (
	AuthClientSecretPost  = "client_secret_post"
	AuthClientSecretBasic = "client_secret_basic"
	AuthNone              = "none"
)

// Token response formats.
const (
	FormatStandard        = "standard"
	FormatSlackAuthedUser = "slack_authed_user"
)

// CallbackPath is where providers send the browser back (registered with
// the provider's OAuth app as <APP_URL>/connect/callback).
const CallbackPath = "/connect/callback"

var (
	errPlatformRead = apperr.Forbidden("Only platform admins and auditors can see this")
	errAdminOnly    = apperr.Forbidden("Only platform admins can do this")
	errNoProvider   = apperr.NotFound("provider_not_found", "Auth provider not found")
	errSlugTaken    = apperr.Conflict("slug_taken", "Another auth provider already uses that slug")
	slugRE          = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,46}[a-z0-9])?$`)
	paramKeyRE      = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)
	// reservedSlugs are paths under /connect/ of the web app and the server.
	reservedSlugs     = map[string]bool{"done": true, "callback": true}
	reservedParamKeys = []string{"response_type", "client_id", "redirect_uri", "state", "scope", "code_challenge", "code_challenge_method"}
)

// Service is delegated credentials.
type Service struct {
	pool   *pgxpool.Pool
	q      *dbgen.Queries
	box    *secrets.Box
	up     *upstream.Client
	appURL string
	http   *http.Client
	// tr is the transport of provider endpoint requests (tests set TLS).
	tr  *http.Transport
	Log *slog.Logger
	now func() time.Time
	// Registry reads an oauth server's capabilities after its setup
	// sign-in (nil: not read).
	Registry *registry.Service
	// Notify hears of connections that turn needs_reconsent (nil: nobody).
	Notify Notifier
	// Reachable lists the servers a person may use through a gateway now
	// (gateways.Service.ReachableServers; nil: none), which the person may
	// allow to use a connection (allow.go).
	Reachable func(ctx context.Context, u dbgen.User) ([]gateways.ReachableServer, error)
	// narrow holds the short-lived narrowed tokens in memory (narrow.go).
	narrow narrowCache
	// SessionIdleTimeout mirrors browser authentication for service callbacks.
	SessionIdleTimeout time.Duration
}

// New returns the service. up supplies the address guard (the development
// allowance and the allowlist of internal networks) for provider endpoints.
func New(pool *pgxpool.Pool, box *secrets.Box, up *upstream.Client, appURL string, log *slog.Logger) *Service {
	if log == nil {
		log = slog.Default()
	}
	if up == nil {
		up = &upstream.Client{}
	}
	var q *dbgen.Queries
	if pool != nil {
		q = dbgen.New(pool)
	}
	tr := &http.Transport{
		Proxy:                 nil, // never HTTP(S)_PROXY: the dialer must see the real destination
		DialContext:           up.GuardedDial(),
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   endpointTimeout,
		ResponseHeaderTimeout: endpointTimeout,
		MaxIdleConns:          8,
		IdleConnTimeout:       30 * time.Second,
	}
	return &Service{
		pool: pool, q: q, box: box, up: up, appURL: strings.TrimRight(appURL, "/"), tr: tr, Log: log, now: time.Now,
		http: &http.Client{Transport: tr, Timeout: endpointTimeout, CheckRedirect: noRedirect},
	}
}

// RedirectURI is <APP_URL>/connect/callback.
func (s *Service) RedirectURI() string { return s.appURL + CallbackPath }

func by(a authz.Actor) uuid.NullUUID {
	return uuid.NullUUID{UUID: a.UserID, Valid: a.UserID != uuid.Nil}
}

// SecretAAD binds a provider's sealed client secret to its row.
func SecretAAD(id uuid.UUID) []byte { return registry.ProviderSecretAAD(id) }

// Provider kinds.
const (
	KindOAuth2    = registry.KindOAuth2
	KindMCPServer = registry.KindMCPServer
)

// ServerSlugPrefix starts every server-bound provider's slug; platform
// providers can't use it.
const ServerSlugPrefix = "mcp-"

// View is a provider as platform admins see it: never the secret.
type View struct {
	Provider        dbgen.AuthProvider
	ExtraParams     map[string]string
	ServerCount     int64
	ConnectionCount int64
	CreatedByName   string
}

// HasSecret reports whether a client secret is stored.
func (v View) HasSecret() bool { return v.Provider.ClientSecretCipher != nil }

func extraParams(raw json.RawMessage) map[string]string {
	out := map[string]string{}
	_ = json.Unmarshal(raw, &out)
	return out
}

func (s *Service) views(ctx context.Context, q *dbgen.Queries, rows []dbgen.AuthProvider) ([]View, error) {
	out := make([]View, len(rows))
	if len(rows) == 0 {
		return out, nil
	}
	ids := make([]uuid.UUID, len(rows))
	index := map[uuid.UUID]int{}
	for i, p := range rows {
		ids[i], index[p.ID] = p.ID, i
		out[i] = View{Provider: p, ExtraParams: extraParams(p.ExtraAuthorizeParams)}
	}
	stats, err := q.AuthProviderStats(ctx, ids)
	if err != nil {
		return nil, err
	}
	for _, st := range stats {
		v := &out[index[st.ProviderID]]
		v.ServerCount, v.ConnectionCount, v.CreatedByName = st.ServerCount, st.ConnectionCount, st.CreatedByName
	}
	return out, nil
}

func (s *Service) view(ctx context.Context, q *dbgen.Queries, id uuid.UUID) (View, error) {
	p, err := getPlatformProvider(ctx, q, id, false)
	if err != nil {
		return View{}, err
	}
	vs, err := s.views(ctx, q, []dbgen.AuthProvider{p})
	if err != nil {
		return View{}, err
	}
	return vs[0], nil
}

func getProvider(ctx context.Context, q *dbgen.Queries, id uuid.UUID, lock bool) (dbgen.AuthProvider, error) {
	var (
		p   dbgen.AuthProvider
		err error
	)
	if lock {
		p, err = q.LockAuthProvider(ctx, id)
	} else {
		p, err = q.GetAuthProvider(ctx, id)
	}
	if errors.Is(store.NotFound(err), store.ErrNotFound) {
		return p, errNoProvider
	}
	return p, err
}

// getPlatformProvider is getProvider for the platform's routes: a
// server-bound provider (kind mcp_server) is not found there.
func getPlatformProvider(ctx context.Context, q *dbgen.Queries, id uuid.UUID, lock bool) (dbgen.AuthProvider, error) {
	p, err := getProvider(ctx, q, id, lock)
	if err == nil && p.Kind != KindOAuth2 {
		return p, errNoProvider
	}
	return p, err
}

// List is the enabled providers, by name, for picking one (any active
// signed-in person): no client ID, secret or endpoint.
func (s *Service) List(ctx context.Context) ([]registry.Provider, error) {
	rows, err := s.q.ListPlatformAuthProviders(ctx)
	if err != nil {
		return nil, err
	}
	out := []registry.Provider{}
	for _, p := range rows {
		if p.Enabled {
			out = append(out, registry.ProviderOf(p))
		}
	}
	return out, nil
}

// AdminList lists every provider (platform admins and auditors).
func (s *Service) AdminList(ctx context.Context, a authz.Actor) ([]View, error) {
	if !a.CanReadPlatform() {
		return nil, errPlatformRead
	}
	rows, err := s.q.ListPlatformAuthProviders(ctx)
	if err != nil {
		return nil, err
	}
	return s.views(ctx, s.q, rows)
}

// AdminGet returns one provider (platform admins and auditors).
func (s *Service) AdminGet(ctx context.Context, a authz.Actor, id uuid.UUID) (View, error) {
	if !a.CanReadPlatform() {
		return View{}, errPlatformRead
	}
	return s.view(ctx, s.q, id)
}

// CreateInput configures a provider; nil fields take their defaults.
type CreateInput struct {
	Slug, Name, ClientID                   string
	Preset                                 *string
	Enabled                                *bool
	ClientSecret                           *string
	TokenAuthMethod                        *string
	PKCE                                   *bool
	AuthorizationURL, TokenURL             string
	RevocationURL, UserinfoURL, LogoURL    *string
	DefaultScopes                          *[]string
	ScopeParam, ScopeSeparator, RespFormat *string
	ExtraParams                            *map[string]string
	// NarrowOnRefresh: calls get a token refreshed with only the scopes
	// they need (decision 69); nil: off.
	NarrowOnRefresh *bool
}

// UpdateInput holds changes; nil keeps a field. The Clear* flags remove an
// optional field (null in the API).
type UpdateInput struct {
	Name, ClientID, ClientSecret, TokenAuthMethod          *string
	Preset                                                 *string
	ClearPreset                                            bool
	Enabled, PKCE                                          *bool
	AuthorizationURL, TokenURL, RevocationURL, UserinfoURL *string
	ClearRevocationURL, ClearUserinfoURL, ClearLogoURL     bool
	LogoURL                                                *string
	DefaultScopes                                          *[]string
	ScopeParam, ScopeSeparator, RespFormat                 *string
	ExtraParams                                            *map[string]string
	NarrowOnRefresh                                        *bool
}

// fields are a provider's settings while validating.
type fields struct {
	name, clientID, method              string
	preset                              *string
	enabled, pkce                       bool
	secret                              *string // a new secret ("" removes it)
	storedSecret                        bool
	authorizationURL, tokenURL          string
	revocationURL, userinfoURL, logoURL *string
	scopes                              []string
	scopeParam, separator, format       string
	params                              map[string]string
}

func invalidURL(field string, err error) error {
	e, ok := apperr.As(err)
	if !ok {
		return err
	}
	out := apperr.New(e.Status, e.Code, e.Message)
	details := map[string]any{"field": field}
	if d, ok := e.Details.(map[string]any); ok {
		for k, v := range d {
			details[k] = v
		}
	}
	out.Details = details
	return out
}

func unprocessable(code, msg string, details any) error {
	e := apperr.New(http.StatusUnprocessableEntity, code, msg)
	e.Details = details
	return e
}

func oneLine(s string) bool { return strings.IndexFunc(s, unicode.IsControl) < 0 }

// checkLogo: an https URL or a same-origin path.
func checkLogo(raw string) error {
	bad := func(reason string) error {
		return unprocessable("url_not_allowed", "The logo must be an https URL or a path on this site", map[string]any{"field": "logoUrl", "reason": reason})
	}
	if len(raw) > maxURL || !oneLine(raw) {
		return bad("invalid")
	}
	if SafeReturnPath(raw) {
		return nil
	}
	u, err := url.Parse(raw)
	switch {
	case err != nil || u.Host == "":
		return bad("invalid")
	case u.User != nil:
		return bad("userinfo")
	case u.Scheme != "https":
		return bad("scheme")
	}
	return nil
}

// validate checks a provider's settings and normalizes them.
func (s *Service) validate(ctx context.Context, f *fields) error {
	f.name = strings.TrimSpace(f.name)
	if n := len([]rune(f.name)); n < 1 || n > 100 {
		return apperr.Invalid("invalid_name", "Name must be 1-100 characters")
	}
	f.clientID = strings.TrimSpace(f.clientID)
	if n := len(f.clientID); n < 1 || n > 500 || !oneLine(f.clientID) {
		return apperr.Invalid("invalid_client_id", "The client ID must be 1-500 characters on one line")
	}
	if f.preset != nil && !ValidPreset(*f.preset) {
		return apperr.Invalid("invalid_preset", "preset must be github, google, microsoft, atlassian, slack or gitlab")
	}
	switch f.method {
	case AuthClientSecretPost, AuthClientSecretBasic, AuthNone:
	default:
		return apperr.Invalid("invalid_token_auth_method", "tokenAuthMethod must be client_secret_post, client_secret_basic or none")
	}
	if f.method == AuthNone && !f.pkce {
		return unprocessable("pkce_required", "A public client (tokenAuthMethod none) must use PKCE", nil)
	}
	if f.secret != nil {
		if len(*f.secret) > maxSecret || !oneLine(*f.secret) {
			return apperr.Invalid("invalid_client_secret", "The client secret must be at most 2000 characters on one line")
		}
	}
	hasSecret := f.storedSecret
	if f.secret != nil {
		hasSecret = *f.secret != ""
	}
	if f.method != AuthNone && !hasSecret {
		return unprocessable("client_secret_required", "Enter the client secret (or use tokenAuthMethod none with PKCE)", nil)
	}
	for _, u := range []struct {
		field string
		raw   *string
	}{{"authorizationUrl", &f.authorizationURL}, {"tokenUrl", &f.tokenURL}, {"revocationUrl", f.revocationURL}, {"userinfoUrl", f.userinfoURL}} {
		if u.raw == nil {
			continue
		}
		norm, err := s.up.NormalizeURL(ctx, *u.raw)
		if err != nil {
			return invalidURL(u.field, err)
		}
		*u.raw = norm
	}
	if f.logoURL != nil {
		if err := checkLogo(*f.logoURL); err != nil {
			return err
		}
	}
	scopes, err := registry.NormalizeScopes(f.scopes)
	if err != nil {
		return err
	}
	f.scopes = scopes
	if !paramKeyRE.MatchString(f.scopeParam) || (f.scopeParam != "scope" && slices.Contains(reservedParamKeys, f.scopeParam)) {
		return apperr.Invalid("invalid_scope_param", "scopeParam must be a parameter name such as scope or user_scope")
	}
	if f.separator != " " && f.separator != "," {
		return apperr.Invalid("invalid_scope_separator", "scopeSeparator must be a space or a comma")
	}
	if f.format != FormatStandard && f.format != FormatSlackAuthedUser {
		return apperr.Invalid("invalid_token_response_format", "tokenResponseFormat must be standard or slack_authed_user")
	}
	if len(f.params) > maxExtraParams {
		return unprocessable("invalid_param", "At most 10 extra authorization parameters", map[string]any{"reason": "too_many"})
	}
	for k, v := range f.params {
		switch {
		case !paramKeyRE.MatchString(k):
			return unprocessable("invalid_param", "Parameter names are 1-64 letters, digits, _, . or -", map[string]any{"key": k, "reason": "invalid"})
		case slices.Contains(reservedParamKeys, k) || k == f.scopeParam:
			return unprocessable("invalid_param", "The portal sets this parameter itself", map[string]any{"key": k, "reason": "reserved"})
		case len(v) > maxParamValue || !oneLine(v):
			return unprocessable("invalid_param", "Parameter values are at most 500 characters on one line", map[string]any{"key": k, "reason": "invalid"})
		}
	}
	return nil
}

// snapshot is a provider's audited configuration: never the secret.
func snapshot(p dbgen.AuthProvider) map[string]any {
	return map[string]any{
		"slug": p.Slug, "name": p.Name, "preset": p.Preset, "enabled": p.Enabled, "clientId": p.ClientID,
		"hasClientSecret": p.ClientSecretCipher != nil, "tokenAuthMethod": p.TokenAuthMethod, "pkce": p.Pkce,
		"authorizationUrl": p.AuthorizationUrl, "tokenUrl": p.TokenUrl, "revocationUrl": p.RevocationUrl,
		"userinfoUrl": p.UserinfoUrl, "defaultScopes": nonNil(p.DefaultScopes), "scopeParam": p.ScopeParam,
		"scopeSeparator": p.ScopeSeparator, "tokenResponseFormat": p.TokenResponseFormat,
		"extraAuthorizeParams": extraParams(p.ExtraAuthorizeParams), "logoUrl": p.LogoUrl,
		"accessMode": p.AccessMode, "narrowOnRefresh": p.NarrowOnRefresh,
	}
}

func ptr[T any](v T) *T { return &v }

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// secretHint is the last four characters of a secret of at least eight.
func secretHint(v string) string {
	r := []rune(v)
	if len(r) < 8 {
		return ""
	}
	return string(r[len(r)-4:])
}

func or[T any](p *T, def T) T {
	if p != nil {
		return *p
	}
	return def
}

// Create configures a provider (platform admins). Audited as
// auth_provider.create.
func (s *Service) Create(ctx context.Context, a authz.Actor, in CreateInput) (View, error) {
	if !a.IsPlatformAdmin() {
		return View{}, errAdminOnly
	}
	in.Slug = strings.TrimSpace(in.Slug)
	if !slugRE.MatchString(in.Slug) {
		return View{}, apperr.Invalid("invalid_slug", "Slug must be 1-48 lowercase letters, digits or hyphens, and cannot start or end with a hyphen")
	}
	if reservedSlugs[in.Slug] || strings.HasPrefix(in.Slug, ServerSlugPrefix) {
		// /connect/{slug} is the consent page: these paths are taken.
		return View{}, unprocessable("invalid_slug", "This slug is reserved", map[string]any{"reason": "reserved"})
	}
	f := fields{
		name: in.Name, clientID: in.ClientID, method: or(in.TokenAuthMethod, AuthClientSecretPost), preset: in.Preset,
		enabled: or(in.Enabled, true), pkce: or(in.PKCE, true), secret: in.ClientSecret,
		authorizationURL: in.AuthorizationURL, tokenURL: in.TokenURL, revocationURL: in.RevocationURL, userinfoURL: in.UserinfoURL,
		logoURL: in.LogoURL, scopes: or(in.DefaultScopes, []string{}), scopeParam: or(in.ScopeParam, "scope"),
		separator: or(in.ScopeSeparator, " "), format: or(in.RespFormat, FormatStandard), params: or(in.ExtraParams, map[string]string{}),
	}
	if f.secret != nil && *f.secret == "" {
		f.secret = nil
	}
	if err := s.validate(ctx, &f); err != nil {
		return View{}, err
	}
	id := uuid.New()
	params, _ := json.Marshal(f.params)
	p := dbgen.InsertAuthProviderParams{
		ID: id, Slug: in.Slug, Name: f.name, Preset: f.preset, Enabled: f.enabled, ClientID: f.clientID, TokenAuthMethod: f.method,
		Pkce: f.pkce, AuthorizationUrl: f.authorizationURL, TokenUrl: f.tokenURL, RevocationUrl: f.revocationURL,
		UserinfoUrl: f.userinfoURL, DefaultScopes: f.scopes, ScopeParam: f.scopeParam, ScopeSeparator: f.separator,
		TokenResponseFormat: f.format, ExtraAuthorizeParams: params, LogoUrl: f.logoURL, CreatedBy: by(a),
		// New providers start restricted: no team or server may require
		// them until an admin lists some (decision 69).
		AccessMode: AccessRestricted, NarrowOnRefresh: or(in.NarrowOnRefresh, false),
	}
	if f.secret != nil {
		ct, err := s.box.Seal([]byte(*f.secret), SecretAAD(id))
		if err != nil {
			return View{}, err
		}
		p.ClientSecretCipher, p.ClientSecretHint = ct, secretHint(*f.secret)
	}
	err := store.InTx(ctx, s.pool, func(q *dbgen.Queries, tx pgx.Tx) error {
		// One creation at a time keeps the limit exact.
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('omp.auth-providers'))`); err != nil {
			return err
		}
		n, err := q.CountAuthProviders(ctx)
		if err != nil {
			return err
		}
		if n >= MaxProviders {
			return apperr.Conflict("too_many_providers", "At most 100 auth providers can be configured")
		}
		row, err := q.InsertAuthProvider(ctx, p)
		if apperr.IsUniqueViolation(err, "auth_providers_slug_key") {
			return errSlugTaken
		} else if err != nil {
			return err
		}
		e := a.Audit("auth_provider.create", "auth_provider", id.String())
		e.After = snapshot(row)
		e.Metadata = map[string]any{"name": row.Name}
		return audit.Record(ctx, q, e)
	})
	if err != nil {
		return View{}, err
	}
	return s.view(ctx, s.q, id)
}

// Update changes a provider (platform admins); the slug never changes.
// Changing the client ID marks every connection needs_reconsent and erases
// their tokens (they belong to the old app). Audited as auth_provider.update
// with clientSecretChanged and connectionsReset.
func (s *Service) Update(ctx context.Context, a authz.Actor, id uuid.UUID, in UpdateInput, expectedRevision int64) (View, error) {
	if !a.IsPlatformAdmin() {
		return View{}, errAdminOnly
	}
	err := store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		cur, err := getPlatformProvider(ctx, q, id, true)
		if err != nil {
			return err
		}
		if cur.Revision != expectedRevision {
			return apperr.Stale()
		}
		linked, err := q.LinkedServerProviders(ctx, uuid.NullUUID{UUID: id, Valid: true})
		if err != nil {
			return err
		}
		f := fields{
			name: or(in.Name, cur.Name), clientID: or(in.ClientID, cur.ClientID), method: or(in.TokenAuthMethod, cur.TokenAuthMethod),
			preset: cur.Preset, enabled: or(in.Enabled, cur.Enabled), pkce: or(in.PKCE, cur.Pkce), secret: in.ClientSecret,
			storedSecret: cur.ClientSecretCipher != nil, authorizationURL: or(in.AuthorizationURL, cur.AuthorizationUrl),
			tokenURL: or(in.TokenURL, cur.TokenUrl), revocationURL: cur.RevocationUrl, userinfoURL: cur.UserinfoUrl, logoURL: cur.LogoUrl,
			scopes: or(in.DefaultScopes, nonNil(cur.DefaultScopes)), scopeParam: or(in.ScopeParam, cur.ScopeParam),
			separator: or(in.ScopeSeparator, cur.ScopeSeparator), format: or(in.RespFormat, cur.TokenResponseFormat),
			params: or(in.ExtraParams, extraParams(cur.ExtraAuthorizeParams)),
		}
		switch {
		case in.ClearPreset:
			f.preset = nil
		case in.Preset != nil:
			f.preset = in.Preset
		}
		switch {
		case in.ClearRevocationURL:
			f.revocationURL = nil
		case in.RevocationURL != nil:
			f.revocationURL = in.RevocationURL
		}
		switch {
		case in.ClearUserinfoURL:
			f.userinfoURL = nil
		case in.UserinfoURL != nil:
			f.userinfoURL = in.UserinfoURL
		}
		switch {
		case in.ClearLogoURL:
			f.logoURL = nil
		case in.LogoURL != nil:
			f.logoURL = in.LogoURL
		}
		if err := s.validate(ctx, &f); err != nil {
			return err
		}
		params, _ := json.Marshal(f.params)
		p := dbgen.UpdateAuthProviderParams{
			ID: id, Name: f.name, Preset: f.preset, Enabled: f.enabled, ClientID: f.clientID, ClientSecretCipher: cur.ClientSecretCipher,
			ClientSecretHint: cur.ClientSecretHint, TokenAuthMethod: f.method, Pkce: f.pkce, AuthorizationUrl: f.authorizationURL,
			TokenUrl: f.tokenURL, RevocationUrl: f.revocationURL, UserinfoUrl: f.userinfoURL, DefaultScopes: f.scopes,
			ScopeParam: f.scopeParam, ScopeSeparator: f.separator, TokenResponseFormat: f.format, ExtraAuthorizeParams: params,
			LogoUrl: f.logoURL, UpdatedBy: by(a), NarrowOnRefresh: or(in.NarrowOnRefresh, cur.NarrowOnRefresh),
		}
		secretChanged := false
		if f.secret != nil {
			secretChanged = true
			if *f.secret == "" {
				p.ClientSecretCipher, p.ClientSecretHint = nil, ""
			} else {
				ct, err := s.box.Seal([]byte(*f.secret), SecretAAD(id))
				if err != nil {
					return err
				}
				p.ClientSecretCipher, p.ClientSecretHint = ct, secretHint(*f.secret)
			}
		}
		if len(linked) > 0 && (f.authorizationURL != cur.AuthorizationUrl || f.tokenURL != cur.TokenUrl) {
			// oauth servers use this client because its endpoints matched
			// their authorization server's.
			return s.inUse(ctx, q, id)
		}
		row, err := q.UpdateAuthProvider(ctx, p)
		if err != nil {
			return err
		}
		var reset int64
		if row.ClientID != cur.ClientID {
			if reset, err = q.MarkProviderConnectionsReconsent(ctx, id); err != nil {
				return err
			}
			// The linked servers' connections belong to the old client too.
			for _, l := range linked {
				n, err := q.ResetProviderConnections(ctx, dbgen.ResetProviderConnectionsParams{ProviderID: l.ID, ErrorClass: ptr("client_changed")})
				if err != nil {
					return err
				}
				reset += n
			}
		}
		e := a.Audit("auth_provider.update", "auth_provider", id.String())
		e.Before, e.After = snapshot(cur), snapshot(row)
		e.Metadata = map[string]any{"name": row.Name, "clientSecretChanged": secretChanged, "connectionsReset": reset}
		return audit.Record(ctx, q, e)
	})
	if err != nil {
		return View{}, err
	}
	return s.view(ctx, s.q, id)
}

// Delete deletes a provider and every connection to it (platform admins).
// 409 in_use while any MCP server requires it. Connections' tokens are
// revoked at the provider first where it has a revocation endpoint (best
// effort, at most a minute in all). Audited as auth_provider.delete
// (connectionCount) and provider_connection.revoke (reason
// provider_deleted) per connection.
func (s *Service) Delete(ctx context.Context, a authz.Actor, id uuid.UUID) error {
	if !a.IsPlatformAdmin() {
		return errAdminOnly
	}
	p, err := getPlatformProvider(ctx, s.q, id, false)
	if err != nil {
		return err
	}
	if err := s.inUse(ctx, s.q, id); err != nil {
		return err
	}
	conns, err := s.q.ListProviderConnectionsForProvider(ctx, id)
	if err != nil {
		return err
	}
	revoked := s.revokeAll(ctx, p, conns)
	return store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		cur, err := getPlatformProvider(ctx, q, id, true)
		if err != nil {
			return err
		}
		if err := s.inUse(ctx, q, id); err != nil {
			return err
		}
		all, err := q.ListProviderConnectionsForProvider(ctx, id)
		if err != nil {
			return err
		}
		names, err := s.userNames(ctx, q, all)
		if err != nil {
			return err
		}
		for _, c := range all {
			if err := q.DeleteProviderConnection(ctx, c.ID); err != nil {
				return err
			}
			result, ok := revoked[c.ID]
			if !ok {
				result = revokeResult(cur, false)
			}
			e := a.Audit("provider_connection.revoke", "provider_connection", c.ID.String())
			e.Before = connectionSnapshot(c)
			e.Metadata = map[string]any{"name": names[c.UserID] + " · " + cur.Name, "reason": "provider_deleted",
				"providerRevoked": result, "userId": c.UserID.String(), "provider": cur.Slug}
			if err := audit.Record(ctx, q, e); err != nil {
				return err
			}
		}
		if err := q.DeleteAuthProvider(ctx, id); err != nil {
			if apperr.IsForeignKeyViolation(err, "") {
				return s.inUse(ctx, q, id)
			}
			return err
		}
		e := a.Audit("auth_provider.delete", "auth_provider", id.String())
		e.Before = snapshot(cur)
		e.Metadata = map[string]any{"name": cur.Name, "connectionCount": len(all)}
		return audit.Record(ctx, q, e)
	})
}

// inUse is 409 in_use while a server requires the provider.
func (s *Service) inUse(ctx context.Context, q *dbgen.Queries, id uuid.UUID) error {
	rows, err := q.ServersRequiringProvider(ctx, dbgen.ServersRequiringProviderParams{ProviderID: uuid.NullUUID{UUID: id, Valid: true}, PageSize: 1000})
	if err != nil || len(rows) == 0 {
		return err
	}
	servers := []map[string]any{}
	for i, r := range rows {
		if i == 20 {
			break
		}
		servers = append(servers, map[string]any{"id": r.ID, "slug": r.Slug, "name": r.Name, "teamSlug": r.TeamSlug})
	}
	e := apperr.Conflict("in_use", "MCP servers require this provider or use its client. Remove their requirement or sign-in first.")
	e.Details = map[string]any{"serverCount": len(rows), "servers": servers}
	return e
}

// userNames are the display names (else emails) of connections' people.
func (s *Service) userNames(ctx context.Context, q *dbgen.Queries, conns []dbgen.ProviderConnection) (map[uuid.UUID]string, error) {
	out := map[uuid.UUID]string{}
	for _, c := range conns {
		if _, ok := out[c.UserID]; ok {
			continue
		}
		u, err := q.GetUser(ctx, c.UserID)
		if err != nil {
			return nil, err
		}
		out[c.UserID] = displayName(u)
	}
	return out, nil
}

func displayName(u dbgen.User) string {
	if u.DisplayName != "" {
		return u.DisplayName
	}
	return u.Email
}

// connectionSnapshot is a connection as audited: never a token.
func connectionSnapshot(c dbgen.ProviderConnection) map[string]any {
	return map[string]any{"status": c.Status, "scopes": nonNil(c.Scopes), "accountLabel": c.AccountLabel,
		"refreshable": c.RefreshTokenCipher != nil}
}
