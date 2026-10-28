// Package auth implements browser sign-in (generic OIDC with PKCE, plus a
// loopback-only development login), server-side sessions, CSRF protection
// and the request identity used by every authenticated handler.
package auth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/config"
	"github.com/ncecere/open-mcp-portal/internal/httpx"
	"github.com/ncecere/open-mcp-portal/internal/ratelimit"
	"github.com/ncecere/open-mcp-portal/internal/store"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

// Platform roles (aliases of the authz constants).
const (
	RoleNone            = authz.PlatformNone
	RolePlatformAdmin   = authz.PlatformAdmin
	RolePlatformAuditor = authz.PlatformAuditor
)

// User statuses.
const (
	StatusActive    = "active"
	StatusSuspended = "suspended"
)

// ViteDevPort is the port of the web UI's Vite dev server (make web-dev),
// whose origin is accepted for writes while DEV_AUTH is on.
const ViteDevPort = "5175"

// Identity is the authenticated caller attached to the request context.
type Identity struct {
	User      dbgen.User
	SessionID string
	CSRFToken string
}

// Actor converts the identity into the authz principal for a request.
func (i Identity) Actor(requestID, clientIP string) authz.Actor {
	return authz.Actor{UserID: i.User.ID, PlatformRole: i.User.PlatformRole, RequestID: requestID, ClientIP: clientIP}
}

func (i Identity) IsPlatformAdmin() bool { return i.User.PlatformRole == RolePlatformAdmin }

func (i Identity) IsPlatformAuditor() bool { return i.User.PlatformRole == RolePlatformAuditor }

type identityKey struct{}

// FromContext returns the caller identity set by RequireSession.
func FromContext(ctx context.Context) (Identity, bool) {
	id, ok := ctx.Value(identityKey{}).(Identity)
	return id, ok
}

// WithIdentity attaches an identity to ctx (used by middleware and tests).
func WithIdentity(ctx context.Context, id Identity) context.Context {
	return context.WithValue(ctx, identityKey{}, id)
}

// Service holds the dependencies for sign-in and session handling.
type Service struct {
	cfg  config.Config
	pool *pgxpool.Pool
	q    *dbgen.Queries
	// limiter counts sign-in attempts per address and /v1 requests per
	// person (in memory until SetRateStore installs the shared store).
	limiter ratelimit.Store
	log     *slog.Logger
	now     func() time.Time

	oidcMu sync.Mutex
	oidc   *oidcClient // discovered lazily so an IdP outage cannot stop the API from starting
}

func NewService(cfg config.Config, pool *pgxpool.Pool, log *slog.Logger) *Service {
	return &Service{
		cfg:     cfg,
		pool:    pool,
		q:       dbgen.New(pool),
		limiter: ratelimit.New(),
		log:     log,
		now:     time.Now,
	}
}

// Digest is the SHA-256 (hex) under which session secrets and OIDC states
// are stored; the secrets themselves never are.
func Digest(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// SessionCookieName is the session cookie's name: __Host- prefixed under
// HTTPS, so it is host-only, Secure and Path=/.
func SessionCookieName(secure bool) string {
	if secure {
		return "__Host-omp_session"
	}
	return "omp_session"
}

// HasSessionCookie reports whether the request carries a session cookie at
// all (it may still be expired or revoked).
func (s *Service) HasSessionCookie(r *http.Request) bool {
	c, err := r.Cookie(s.sessionCookieName())
	return err == nil && c.Value != ""
}

func (s *Service) sessionCookieName() string { return SessionCookieName(s.cfg.SecureCookies()) }

func (s *Service) setCookie(w http.ResponseWriter, name, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		Secure:   s.cfg.SecureCookies(),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   maxAge,
	})
}

// originAllowed rejects cross-site browser writes. Requests without an Origin
// header (non-browser clients) are still protected by the CSRF token.
func (s *Service) originAllowed(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" || origin == s.cfg.AppURL {
		return true
	}
	return s.cfg.DevAuth && s.cfg.LoopbackAppURL() &&
		(origin == "http://localhost:"+ViteDevPort || origin == "http://127.0.0.1:"+ViteDevPort)
}

// sameHost reports whether the request was addressed to APP_URL's host.
func (s *Service) sameHost(r *http.Request) bool {
	app, err := url.Parse(s.cfg.AppURL)
	return err == nil && app.Host != "" && r.Host == app.Host
}

func (s *Service) clientIP(r *http.Request) string { return httpx.ClientIP(r, s.cfg.TrustedProxies) }

// createSession stores a new session and returns the cookie secret. The
// caller sets the cookie only after the surrounding transaction commits.
func (s *Service) createSession(ctx context.Context, r *http.Request, q *dbgen.Queries, user dbgen.User) (string, error) {
	secret := httpx.NewID(32)
	csrf := httpx.NewID(32)
	ua := r.UserAgent()
	if len(ua) > 512 {
		ua = ua[:512]
	}
	now := s.now()
	_, err := q.CreateSession(ctx, dbgen.CreateSessionParams{
		AsOf:        now,
		UserID:      user.ID,
		TokenDigest: Digest(secret),
		CSRFToken:   csrf,
		UserAgent:   ua,
		ClientIP:    s.clientIP(r),
		ExpiresAt:   now.Add(s.cfg.SessionTTL),
	})
	return secret, err
}

func (s *Service) setSessionCookie(w http.ResponseWriter, secret string) {
	s.setCookie(w, s.sessionCookieName(), secret, int(s.cfg.SessionTTL.Seconds()))
}

// RequireSession authenticates the browser session, enforces CSRF + Origin on
// unsafe methods and applies the per-user request limit.
func (s *Service) RequireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			httpx.Error(w, http.StatusUnauthorized, "unauthorized", "Bearer tokens are not accepted on this endpoint")
			return
		}
		cookie, err := r.Cookie(s.sessionCookieName())
		if err != nil || cookie.Value == "" || len(cookie.Value) > 256 {
			httpx.Error(w, http.StatusUnauthorized, "unauthorized", "Sign in to continue")
			return
		}
		row, err := s.session(r.Context(), Digest(cookie.Value))
		if err != nil {
			if errors.Is(store.NotFound(err), store.ErrNotFound) {
				s.setCookie(w, s.sessionCookieName(), "", -1)
				httpx.Error(w, http.StatusUnauthorized, "unauthorized", "Your session has expired. Sign in again.")
				return
			}
			httpx.Internal(w, r, err)
			return
		}
		if row.User.Status != StatusActive {
			httpx.Error(w, http.StatusForbidden, "user_suspended", "This account is suspended")
			return
		}
		if !isSafeMethod(r.Method) {
			if !s.originAllowed(r) ||
				subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(row.Session.CSRFToken)) != 1 {
				httpx.Error(w, http.StatusForbidden, "csrf_failed", "Invalid request token or origin. Reload the page and try again.")
				return
			}
		}
		if !s.admit(w, r, "user:"+row.User.ID.String(), s.cfg.RequestsPerMinute, "Too many requests. Try again shortly.") {
			return
		}
		id := Identity{User: row.User, SessionID: row.Session.ID.String(), CSRFToken: row.Session.CSRFToken}
		next.ServeHTTP(w, r.WithContext(WithIdentity(r.Context(), id)))
	})
}

// SessionUser returns the person a request's browser session belongs to,
// without CSRF checks (for top-level GET navigations such as the OAuth
// authorization endpoint). ok is false without a current session; a
// suspended person is returned with ok true (callers check the status).
func (s *Service) SessionUser(r *http.Request) (dbgen.User, bool, error) {
	cookie, err := r.Cookie(s.sessionCookieName())
	if err != nil || cookie.Value == "" || len(cookie.Value) > 256 {
		return dbgen.User{}, false, nil
	}
	row, err := s.session(r.Context(), Digest(cookie.Value))
	if errors.Is(store.NotFound(err), store.ErrNotFound) {
		return dbgen.User{}, false, nil
	} else if err != nil {
		return dbgen.User{}, false, err
	}
	return row.User, true, nil
}

// SessionIdentity is SessionUser with the session itself (its ID binds an
// authorization in progress to the browser that started it). ok is false
// without a current session.
func (s *Service) SessionIdentity(r *http.Request) (Identity, bool, error) {
	cookie, err := r.Cookie(s.sessionCookieName())
	if err != nil || cookie.Value == "" || len(cookie.Value) > 256 {
		return Identity{}, false, nil
	}
	row, err := s.session(r.Context(), Digest(cookie.Value))
	if errors.Is(store.NotFound(err), store.ErrNotFound) {
		return Identity{}, false, nil
	} else if err != nil {
		return Identity{}, false, err
	}
	return Identity{User: row.User, SessionID: row.Session.ID.String(), CSRFToken: row.Session.CSRFToken}, true, nil
}

// LoginURL is where to send a browser to sign in and come back to next (a
// same-origin path): single sign-on when it is configured, otherwise the web
// app's sign-in page (the development accounts), which returns to next.
func (s *Service) LoginURL(next string) string {
	if s.cfg.OIDC.Enabled() {
		return "/auth/login?next=" + url.QueryEscape(next)
	}
	return "/?next=" + url.QueryEscape(next)
}

// SetRateStore makes sign-in and /v1 limits use a shared store (the
// PostgreSQL counters every replica uses).
func (s *Service) SetRateStore(st ratelimit.Store) { s.limiter = st }

// admitLogin limits sign-in attempts per client address (hashed).
func (s *Service) admitLogin(w http.ResponseWriter, r *http.Request) bool {
	return s.admit(w, r, ratelimit.Bucket("login", s.clientIP(r)), s.cfg.LoginAttemptsPerMinute, "Too many sign-in attempts. Try again shortly.")
}

func (s *Service) admit(w http.ResponseWriter, r *http.Request, key string, limit int, message string) bool {
	ok, wait, err := ratelimit.Allow(r.Context(), s.limiter, key, limit)
	if err != nil {
		httpx.Internal(w, r, err)
		return false
	}
	if !ok {
		w.Header().Set("Retry-After", retryAfter(wait))
		httpx.Error(w, http.StatusTooManyRequests, "rate_limited", message)
	}
	return ok
}

func retryAfter(d time.Duration) string {
	secs := int((d + time.Second - 1) / time.Second)
	if secs < 1 {
		secs = 1
	}
	return strconv.Itoa(secs)
}

func isSafeMethod(m string) bool {
	return m == http.MethodGet || m == http.MethodHead || m == http.MethodOptions
}

// Cleanup deletes expired sessions and abandoned sign-ins. It is safe to
// run on several replicas at once.
func (s *Service) Cleanup(ctx context.Context) (sessions, logins int64, err error) {
	now := s.now()
	if sessions, err = s.q.DeleteExpiredSessions(ctx, dbgen.DeleteExpiredSessionsParams{AsOf: now, IdleSince: s.idleSince(now)}); err != nil {
		return 0, 0, err
	}
	logins, err = s.q.DeleteExpiredLoginStates(ctx)
	return sessions, logins, err
}
