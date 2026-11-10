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
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ncecere/open-mcp-portal/internal/apperr"
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
