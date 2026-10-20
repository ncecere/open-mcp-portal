// Package oauth is the gateway as a small OAuth 2.1 authorization server
// for its MCP endpoints (docs/phase4-client-auth.md; decisions 12, 21 and
// 24), adapted from Grounded's internal/oauth. It is always on.
//
// What it does, and nothing more:
//
//   - Clients identify themselves with a Client ID Metadata Document (an
//     https URL whose JSON document is fetched through the upstream address
//     guard, metadata.go) or register with Dynamic Client Registration (RFC
//     7591, clients.go). All clients are public: no client secrets.
//   - The authorization code flow with PKCE S256 (required), a resource
//     indicator (RFC 8707) that must be <APP_URL>/mcp/{slug} of a gateway the
//     person may use, and the iss parameter in authorization responses (RFC
//     9207), authorize.go.
//   - Consent is a person's grant for a client on one gateway (decision 21),
//     remembered until revoked. Clients on the platform's trusted list skip
//     the consent screen (decision 24), never the sign-in; with a loopback
//     redirect they ask once per person and gateway (decision 62).
//   - Opaque access tokens (one hour) and rotating refresh tokens (30 days,
//     renewed on each use, but never beyond OAUTH_REFRESH_ABSOLUTE_TTL, 180
//     days by default, after the person last signed the app in, decision
//     63); presenting a rotated refresh token again after a 30-second grace
//     revokes the grant, and inside the grace answers the same new pair
//     (token.go). Tokens and codes are stored as
//     HMAC-SHA256 digests under API_KEY_PEPPER, like API keys (token.go).
//     An access token is accepted only by /mcp/{slug} of its gateway, and
//     every request re-checks the person, the grant and their access.
//
// Sign-in itself is the gateway's own (OIDC, or the development login);
// the consent page is a page of the web app, behind its session and CSRF
// token.
package oauth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ncecere/open-mcp-portal/internal/gateways"
	"github.com/ncecere/open-mcp-portal/internal/ratelimit"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/internal/upstream"
)

// Lifetimes.
const (
	// AccessTokenTTL is an access token's life: short, since a token is only
	// checked against its grant, its person and their access when used.
	AccessTokenTTL = time.Hour
	// RefreshTokenTTL is a refresh token's life. Each use returns a new one
	// with a new 30 days, so a client used at least monthly stays connected
	// until the grant is revoked.
	RefreshTokenTTL = 30 * 24 * time.Hour
	// RefreshReuseGrace: a refresh token presented again this soon after its
	// rotation is a client refreshing twice at once, not a stolen token, so
	// it gets the same new pair again (not a second one) instead of
	// revoking the grant.
	RefreshReuseGrace = 30 * time.Second
	// DefaultRefreshAbsoluteTTL is the default of OAUTH_REFRESH_ABSOLUTE_TTL:
	// how long after the person last signed an app in its refresh tokens
	// stop working, however often they are used (0: no limit).
	DefaultRefreshAbsoluteTTL = 180 * 24 * time.Hour
	// CodeTTL is an authorization code's life (single use).
	CodeTTL = time.Minute
	// ClientUnusedTTL: a registered client unused this long is deleted.
	ClientUnusedTTL = 30 * 24 * time.Hour
	// ClientUnauthorizedTTL: a registered client that has not received
	// tokens (completed one authorization) within this long is deleted, so
	// registrations nobody used age out quickly (decision 62's sibling, H-4).
	ClientUnauthorizedTTL = 24 * time.Hour
)

// Token prefixes: they tell tokens from API keys (omp_) at a glance and in
// secret scanners.
const (
	AccessPrefix  = "ompat_"
	RefreshPrefix = "omprt_"
	codePrefix    = "ompac_"
	clientPrefix  = "ompcl_"
	// tokenBytes of randomness in every token and code (256 bits).
	tokenBytes = 32
)

// Token kinds (oauth_tokens.kind).
const (
	kindAccess  = "access"
	kindRefresh = "refresh"
)

// Config configures the service.
type Config struct {
	// Issuer is the authorization server's identifier: APP_URL.
	Issuer string
	// Pepper is API_KEY_PEPPER (decoded).
	Pepper []byte
	// PepperPrevious is API_KEY_PEPPER_PREVIOUS (decoded, nil when unset):
	// tokens and codes digested with it are still accepted. Access tokens
	// and codes expire soon; refresh tokens are replaced by their rotation.
	PepperPrevious []byte
	// Upstream supplies the address guard for metadata documents: the
	// development allowance (which also lets a document be served over
	// plain http on a loopback host) and the allowlist of internal networks.
	Upstream *upstream.Client
	// MaxRegisteredClients caps the live (used within ClientUnusedTTL)
	// clients registered with Dynamic Client Registration
	// (OAUTH_MAX_REGISTERED_CLIENTS); 0 is no cap. Metadata-document clients
	// are not rows and never count.
	MaxRegisteredClients int
	// MaxUnusedClientsPerAddress caps the registrations one source address
	// can hold that have not received tokens yet
	// (OAUTH_MAX_UNUSED_CLIENTS_PER_ADDRESS); 0 is no cap.
	MaxUnusedClientsPerAddress int
	// RefreshAbsoluteTTL is OAUTH_REFRESH_ABSOLUTE_TTL; 0 is no limit.
	RefreshAbsoluteTTL time.Duration
	// Rates counts metadata document fetches per source address (nil: not
	// limited, for tests of other things).
	Rates ratelimit.Store
}

// Service is the authorization server.
type Service struct {
	pool       *pgxpool.Pool
	q          *dbgen.Queries
	pepper     []byte
	previous   []byte
	issuer     string
	maxClients int
	// maxUnused caps unused registrations per address; refreshTTL is the
	// absolute lifetime of a refresh token chain (0: none); rates limits
	// metadata fetches per address.
	maxUnused  int
	refreshTTL time.Duration
	rates      ratelimit.Store
	gateways   *gateways.Service
	docs       *metadataDocs
	Log        *slog.Logger
	now        func() time.Time
}

// New returns the service.
func New(pool *pgxpool.Pool, gws *gateways.Service, cfg Config) *Service {
	var q *dbgen.Queries
	if pool != nil {
		q = dbgen.New(pool)
	}
	up := cfg.Upstream
	if up == nil {
		up = &upstream.Client{}
	}
	s := &Service{
		pool: pool, q: q, pepper: cfg.Pepper, previous: cfg.PepperPrevious, issuer: strings.TrimRight(cfg.Issuer, "/"), maxClients: cfg.MaxRegisteredClients, gateways: gws,
		maxUnused: cfg.MaxUnusedClientsPerAddress, refreshTTL: cfg.RefreshAbsoluteTTL, rates: cfg.Rates,
		docs: newMetadataDocs(up.GuardedDial(), up.AllowPrivate),
		Log:  slog.Default(), now: time.Now,
	}
	s.docs.log = func() *slog.Logger { return s.Log }
	s.docs.allow = s.allowFetch
	return s
}

// Issuer is the authorization server's identifier (APP_URL).
func (s *Service) Issuer() string { return s.issuer }

// Resource is the protected resource of a gateway: <APP_URL>/mcp/{slug}.
func (s *Service) Resource(slug string) string { return s.issuer + "/mcp/" + slug }

var slugRE = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,46}[a-z0-9])?$`)

// ValidSlug reports whether s has the shape of a gateway slug.
func ValidSlug(s string) bool { return slugRE.MatchString(s) }

// resourceSlug returns the gateway slug a resource names, when it is
// exactly <APP_URL>/mcp/{slug}.
func (s *Service) resourceSlug(resource string) (string, bool) {
	slug, ok := strings.CutPrefix(resource, s.issuer+"/mcp/")
	return slug, ok && slugRE.MatchString(slug)
}

// newToken returns a random token with a prefix.
func newToken(prefix string) string {
	b := make([]byte, tokenBytes)
	_, _ = rand.Read(b) // crypto/rand never fails on supported platforms
	return prefix + base64.RawURLEncoding.EncodeToString(b)
}

// validTokenShape reports whether a presented value can be one of ours, so
// junk never reaches the database.
func validTokenShape(token, prefix string) bool {
	body, ok := strings.CutPrefix(token, prefix)
	if !ok || len(body) != base64.RawURLEncoding.EncodedLen(tokenBytes) {
		return false
	}
	_, err := base64.RawURLEncoding.DecodeString(body)
	return err == nil
}

// IsAccessToken reports whether a bearer value looks like one of our access
// tokens (rather than an API key).
func IsAccessToken(token string) bool { return validTokenShape(token, AccessPrefix) }

// digest is a token's stored form: hex HMAC-SHA256(pepper, "oauth:" +
// token). The label keeps it apart from API-key digests.
func (s *Service) digest(token string) string { return digestWith(s.pepper, token) }

// digests are a token's possible stored forms: with the current pepper,
// then the previous one.
func (s *Service) digests(token string) []string {
	out := []string{s.digest(token)}
	if s.previous != nil {
		out = append(out, digestWith(s.previous, token))
	}
	return out
}

// pepperID is the pepper_id stored with new token digests.
func (s *Service) pepperID() []byte {
	sum := sha256.Sum256(s.pepper)
	return sum[:8]
}

func digestWith(pepper []byte, token string) string {
	m := hmac.New(sha256.New, pepper)
	m.Write([]byte("oauth:"))
	m.Write([]byte(token))
	return hex.EncodeToString(m.Sum(nil))
}

// Error is an OAuth error (RFC 6749 §5.2, §4.1.2.1): its code, a
// description for people, and the HTTP status for the token endpoint.
type Error struct {
	Code        string
	Description string
	Status      int
	// page: the error comes before the client and its redirect URI are
	// known to be good, so it is shown as a page and never redirected.
	page bool
}

func (e *Error) Error() string { return e.Code + ": " + e.Description }

// ShowPage reports an authorization error that must be shown to the person
// rather than sent to the client's redirect URI (it could be anyone's).
func (e *Error) ShowPage() bool { return e.page }

func oauthError(code, description string) *Error {
	return &Error{Code: code, Description: description, Status: http.StatusBadRequest}
}

func pageError(code, description string) *Error {
	e := oauthError(code, description)
	e.page = true
	return e
}

// errInvalidGrant is the token endpoint's answer to any bad code or
// refresh token: which check failed isn't told.
func errInvalidGrant() *Error {
	return oauthError("invalid_grant", "The authorization code or refresh token is invalid, expired or revoked.")
}

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func ptr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
