package providers

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ncecere/open-mcp-portal/internal/registry"
	"github.com/ncecere/open-mcp-portal/internal/store"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

// Narrower tokens per call (decision 69, issue #27, threat model H-5): a
// person's connection holds the union of every scope they ever granted. A
// call carries only what its capability needs when the provider is marked
// narrow_on_refresh: the stored refresh token is traded for a short-lived
// access token whose scope is the call's requirement (RFC 6749 section 6),
// and that token is what the server receives. The stored access token is
// not sent.
//
// The short-lived token is kept in memory only, per (connection, scope set),
// until RefreshAhead before it expires, and is never stored, logged or
// audited. A replica that has none asks the provider, under the connection's
// row lock, so a provider that rotates refresh tokens never sees one used
// twice (the rotated token is stored at once). Each replica caches for itself.
//
// Providers that ignore scope on refresh return the full token: nothing is
// narrowed there, so the switch is the admin's and the presets pre-fill it
// only where the provider documents it (presets.go). A connection without a
// refresh token (GitHub OAuth apps' tokens do not expire) cannot be narrowed
// and keeps today's behaviour; My connections says so.

const (
	// narrowCacheMax bounds the cached tokens.
	narrowCacheMax = 2048
	// narrowNoExpiry is how long a token whose answer gave no lifetime is kept.
	narrowNoExpiry = 5 * time.Minute
)

type narrowKey struct {
	conn uuid.UUID
	// connected is the connection's connected_at: a reconnect (the same
	// row, new consent) never finds the old consent's tokens.
	connected int64
	scopes    string
}

type narrowEntry struct {
	token   string
	expires time.Time
}

// narrowCache holds short-lived narrowed tokens in memory.
type narrowCache struct {
	mu sync.Mutex
	m  map[narrowKey]narrowEntry
}

func (c *narrowCache) get(k narrowKey, now time.Time) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[k]
	if !ok {
		return "", false
	}
	if !e.expires.After(now) {
		delete(c.m, k)
		return "", false
	}
	return e.token, true
}

func (c *narrowCache) put(k narrowKey, token string, expires, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = map[narrowKey]narrowEntry{}
	}
	if len(c.m) >= narrowCacheMax {
		for key, e := range c.m {
			if !e.expires.After(now) {
				delete(c.m, key)
			}
		}
		for key := range c.m {
			if len(c.m) < narrowCacheMax {
				break
			}
			delete(c.m, key)
		}
	}
	c.m[k] = narrowEntry{token: token, expires: expires}
}

// Len is the number of cached tokens (tests).
func (c *narrowCache) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.m)
}

// narrows reports whether a call of a requirement on connection c carries a
// narrowed token: the provider is a platform provider marked
// narrow_on_refresh, a refresh token is held, and the call names scopes.
func narrows(p dbgen.AuthProvider, c dbgen.ProviderConnection, scopes []string) bool {
	return p.NarrowOnRefresh && p.Kind != KindMCPServer && c.RefreshTokenCipher != nil && len(scopes) > 0
}

func narrowKeyOf(c dbgen.ProviderConnection, scopes []string) narrowKey {
	sorted := slices.Clone(scopes)
	slices.Sort(sorted)
	return narrowKey{conn: c.ID, connected: c.ConnectedAt.UnixNano(), scopes: strings.Join(sorted, " ")}
}

// narrowedToken returns an access token for exactly scopes: the cached one,
// else a refresh with scope under the connection's lock. Failures as
// refreshConnection: errReconsent (the grant is gone), *UnavailableError (the
// provider failed or refused the narrower scope: the connection is kept and
// the call is not forwarded with the full token).
func (s *Service) narrowedToken(ctx context.Context, p dbgen.AuthProvider, c dbgen.ProviderConnection, scopes []string) (string, error) {
	if t, ok := s.narrow.get(narrowKeyOf(c, scopes), s.now()); ok {
		return t, nil
	}
	var token string
	var outcome error
	asked := false
	err := store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		lc, err := q.LockProviderConnectionByID(ctx, c.ID)
		if errors.Is(store.NotFound(err), store.ErrNotFound) {
			outcome = errReconsent
			return nil
		} else if err != nil {
			return err
		}
		if lc.Status != StatusActive {
			outcome = errReconsent
			return nil
		}
		key := narrowKeyOf(lc, scopes)
		if t, ok := s.narrow.get(key, s.now()); ok {
			token = t // another request got it while this one waited
			return nil
		}
		rt, err := s.open(lc.ID, "refresh", lc.RefreshTokenCipher)
		if err != nil || rt == "" {
			outcome = errReconsent
			return s.markReconsent(ctx, q, p, lc, "expired")
		}
		asked = true
		tok, ee := s.refreshScoped(ctx, p, rt, scopes)
		if ee != nil {
			switch {
			case ee.Unavailable:
				s.Log.InfoContext(ctx, "auth provider narrowed refresh failed", "provider", p.Slug, "error", ee.Code, "status", ee.Status)
				outcome = &UnavailableError{Provider: registry.ProviderOf(p), Code: ee.Code}
			case ee.Code == "invalid_scope":
				// The provider will not issue these scopes alone. The full
				// token is not a substitute (it is what narrowing avoids):
				// the call is refused and the admin sees the log.
				s.Log.WarnContext(ctx, "auth provider refused a narrowed refresh: turn narrowing off for it, or fix the scopes",
					"provider", p.Slug, "scopes", scopes)
				outcome = &UnavailableError{Provider: registry.ProviderOf(p), Code: "narrowing_refused"}
			default:
				outcome = errReconsent
				return s.markReconsent(ctx, q, p, lc, ee.Code)
			}
			return nil
		}
		if tok.Refresh != "" {
			// A provider that rotates refresh tokens has just retired the
			// one used: the new one must be stored in this transaction.
			ct, err := s.seal(lc.ID, "refresh", tok.Refresh)
			if err != nil {
				return err
			}
			if err := q.RotateProviderConnectionRefreshToken(ctx, dbgen.RotateProviderConnectionRefreshTokenParams{ID: lc.ID, RefreshTokenCipher: ct}); err != nil {
				return err
			}
		}
		if tok.HasScope {
			for _, got := range tok.Scopes {
				if !slices.Contains(scopes, got) {
					// Some providers add identity scopes (openid, profile) to
					// the answer; others ignore the request and return it all.
					s.Log.InfoContext(ctx, "auth provider answered a narrowed refresh with more scopes than asked", "provider", p.Slug,
						"asked", scopes, "answered", tok.Scopes)
					break
				}
			}
		}
		token = tok.Access
		now := s.now()
		ttl := narrowNoExpiry
		if tok.ExpiresIn > 0 {
			ttl = time.Duration(tok.ExpiresIn)*time.Second - RefreshAhead
		}
		if ttl > 0 {
			s.narrow.put(key, token, now.Add(ttl), now)
		}
		return nil
	})
	if asked && err == nil {
		observeRefresh(p.Slug, outcome) // a cached token is no refresh
	}
	if err != nil {
		return "", err
	}
	return token, outcome
}
