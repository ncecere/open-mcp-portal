// Package apikeys manages personal API keys (docs/decisions.md, decision
// 15): the credential MCP clients send to /mcp/{slug} in Phase 3.
//
// A key is "omp_" followed by 43 random URL-safe characters (32 bytes).
// Only its HMAC-SHA256 digest, keyed with API_KEY_PEPPER, is stored, with
// its first characters (the prefix) so people can recognise it. The key is
// shown once, when it is created. Keys always expire, are limited to
// MaxActive per person, and authenticate nothing but /mcp/{slug}: the
// management API takes browser sessions only, so a key can't create keys.
//
// A key may be limited to some gateways (at most MaxGateways, each one its
// creator could use when the key was created); without a limit it works on
// every gateway its owner may use. A limit never widens access: every
// request still checks the owner's access. Deleting a gateway leaves the
// entry, so a key whose gateways are all gone works nowhere.
package apikeys

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"net/http"
	"slices"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ncecere/open-mcp-portal/internal/apperr"
	"github.com/ncecere/open-mcp-portal/internal/audit"
	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/httpx"
	"github.com/ncecere/open-mcp-portal/internal/secrets"
	"github.com/ncecere/open-mcp-portal/internal/store"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/internal/toolscope"
)

// Prefix starts every key.
const Prefix = "omp_"

// Limits.
const (
	// MaxActive is how many active (unrevoked, unexpired) keys a person may
	// have.
	MaxActive = 20
	// MaxGateways is how many gateways a key may be limited to.
	MaxGateways = 50
	// DefaultDays and MaxDays bound a key's lifetime.
	DefaultDays = 90
	MaxDays     = 365
	// prefixLen is how much of a key is stored in the clear: "omp_" and 8.
	prefixLen = len(Prefix) + 8
	// secretLen is the length of a key: "omp_" and 43 characters.
	secretLen = len(Prefix) + 43
)

// Statuses.
const (
	StatusActive  = "active"
	StatusExpired = "expired"
	StatusRevoked = "revoked"
)

var (
	errNotFound  = apperr.NotFound("api_key_not_found", "API key not found")
	errTooMany   = apperr.Conflict("too_many_keys", "You have 20 active API keys. Revoke one you no longer use first.")
	errBadName   = apperr.Invalid("invalid_name", "Name must be 1-100 characters on one line")
	errBadExpiry = apperr.Invalid("invalid_expiry", "expiresInDays must be between 1 and 365")
	errTooManyGw = apperr.Invalid("too_many_gateways", "A key can be limited to at most 50 gateways")
	// ErrInvalid is any key that doesn't authenticate: unknown, revoked,
	// expired, or its owner suspended.
	ErrInvalid = errors.New("invalid API key")
)

// Gateways says which gateways a person may use now (internal/gateways).
type Gateways interface {
	Usable(ctx context.Context, u dbgen.User, ids []uuid.UUID) ([]dbgen.Gateway, []uuid.UUID, error)
}

// Service manages keys.
type Service struct {
	pool     *pgxpool.Pool
	q        *dbgen.Queries
	pepper   []byte
	previous []byte
	gateways Gateways
}

// SetPreviousPepper accepts keys digested with API_KEY_PEPPER_PREVIOUS
// (decoded) and re-digests them with the current pepper when used.
func (s *Service) SetPreviousPepper(p []byte) { s.previous = p }

// PepperID is the pepper_id stored with a digest: the first 8 bytes of
// SHA-256 of the pepper.
func PepperID(pepper []byte) []byte { return secrets.KeyID(pepper) }

// New returns a Service; pepper is API_KEY_PEPPER (decoded), and gateways
// checks the gateways a new key is limited to (nil: keys can't be limited).
func New(pool *pgxpool.Pool, pepper []byte, gateways Gateways) *Service {
	var q *dbgen.Queries
	if pool != nil {
		q = dbgen.New(pool)
	}
	return &Service{pool: pool, q: q, pepper: pepper, gateways: gateways}
}

// Digest is the stored form of a key: HMAC-SHA256 keyed with the pepper.
func Digest(pepper []byte, secret string) string {
	m := hmac.New(sha256.New, pepper)
	m.Write([]byte(secret))
	return hex.EncodeToString(m.Sum(nil))
}

// Status says whether a key is active, expired or revoked at now.
func Status(k dbgen.ApiKey, now time.Time) string {
	switch {
	case k.RevokedAt != nil:
		return StatusRevoked
	case !k.ExpiresAt.After(now):
		return StatusExpired
	}
	return StatusActive
}

// LooksLikeKey reports whether s has the shape of a key (before any lookup).
func LooksLikeKey(s string) bool {
	if len(s) != secretLen || !strings.HasPrefix(s, Prefix) {
		return false
	}
	for _, r := range s[len(Prefix):] {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

// GatewayRef is a gateway a key is limited to: its current slug and name,
// or as they were when the key was created if it no longer exists.
type GatewayRef struct {
	ID         uuid.UUID
	Slug, Name string
	Exists     bool
}

// View is a key with the gateways it is limited to (none: every gateway
// its owner may use).
type View struct {
	Key      dbgen.ApiKey
	Gateways []GatewayRef
}

// Created is a new key and its secret (shown once).
type Created struct {
	View
	Secret string
}

// snapshot is a key's audited form: never the secret or its digest.
func snapshot(k dbgen.ApiKey, gatewayIDs []uuid.UUID) map[string]any {
	ids := make([]string, len(gatewayIDs))
	for i, id := range gatewayIDs {
		ids[i] = id.String()
	}
	return map[string]any{"name": k.Name, "prefix": k.Prefix, "expiresAt": k.ExpiresAt, "gatewayIds": ids, "toolScope": toolscope.Stored(k.ToolScope)}
}

// CreateInput is a new key.
type CreateInput struct {
	ToolScope []byte
	Name      string
	// Days is its lifetime (0: DefaultDays).
	Days int32
	// GatewayIDs limits it to these gateways (empty: every gateway its owner
	// may use). Each must be one the creator may use now.
	GatewayIDs []uuid.UUID
}

func dedupe(ids []uuid.UUID) []uuid.UUID {
	out := make([]uuid.UUID, 0, len(ids))
	for _, id := range ids {
		if !slices.Contains(out, id) {
			out = append(out, id)
		}
	}
	return out
}

// Create makes a key for the actor (at most MaxActive active ones).
// Audited as api_key.create (with the gateways it is limited to), without
// the secret.
func (s *Service) Create(ctx context.Context, a authz.Actor, in CreateInput) (Created, error) {
	toolScope, err := toolscope.Canonical(in.ToolScope)
	if err != nil {
		return Created{}, err
	}
	name := strings.TrimSpace(in.Name)
	if n := utf8.RuneCountInString(name); n < 1 || n > 100 || strings.ContainsAny(name, "\r\n\x00") {
		return Created{}, errBadName
	}
	days := in.Days
	if days == 0 {
		days = DefaultDays
	}
	if days < 1 || days > MaxDays {
		return Created{}, errBadExpiry
	}
	gatewayIDs := dedupe(in.GatewayIDs)
	if len(gatewayIDs) > MaxGateways {
		return Created{}, errTooManyGw
	}
	secret := Prefix + httpx.NewID(32)
	var out Created
	err = store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		// Locking the person serialises their creates, so the limit holds.
		u, err := q.GetUserForUpdate(ctx, a.UserID)
		if err != nil {
			return err
		}
		var scope []dbgen.Gateway
		if len(gatewayIDs) > 0 {
			if s.gateways == nil {
				return errors.New("apikeys: no gateway checker")
			}
			usable, refused, err := s.gateways.Usable(ctx, u, gatewayIDs)
			if err != nil {
				return err
			}
			if len(refused) > 0 {
				e := apperr.New(http.StatusUnprocessableEntity, "gateway_not_usable",
					"You can only limit a key to gateways you can use now")
				e.Details = map[string]any{"gatewayIds": refused}
				return e
			}
			scope = usable
		}
		n, err := q.CountActiveAPIKeys(ctx, a.UserID)
		if err != nil {
			return err
		}
		if n >= MaxActive {
			return errTooMany
		}
		k, err := q.InsertAPIKey(ctx, dbgen.InsertAPIKeyParams{
			UserID: a.UserID, Name: name, Prefix: secret[:prefixLen], Digest: Digest(s.pepper, secret), ToolScope: toolScope,
			ExpiresAt: time.Now().Add(time.Duration(days) * 24 * time.Hour), PepperID: PepperID(s.pepper),
		})
		if err != nil {
			return err
		}
		refs := make([]GatewayRef, 0, len(scope))
		for _, g := range scope {
			if err := q.InsertAPIKeyGateway(ctx, dbgen.InsertAPIKeyGatewayParams{
				ApiKeyID: k.ID, GatewayID: g.ID, GatewaySlug: g.Slug, GatewayName: g.Name,
			}); err != nil {
				return err
			}
			refs = append(refs, GatewayRef{ID: g.ID, Slug: g.Slug, Name: g.Name, Exists: true})
		}
		slices.SortFunc(refs, func(x, y GatewayRef) int { return strings.Compare(x.Name, y.Name) })
		out = Created{View: View{Key: k, Gateways: refs}, Secret: secret}
		e := a.Audit("api_key.create", "api_key", k.ID.String())
		e.After = snapshot(k, gatewayIDs)
		return audit.Record(ctx, q, e)
	})
	return out, err
}

// List returns the actor's keys, newest first: active ones, and those
// revoked or expired in the last 30 days, with the gateways each is
// limited to.
func (s *Service) List(ctx context.Context, a authz.Actor) ([]View, error) {
	keys, err := s.q.ListAPIKeys(ctx, a.UserID)
	if err != nil {
		return nil, err
	}
	ids := make([]uuid.UUID, len(keys))
	for i, k := range keys {
		ids[i] = k.ID
	}
	rows, err := s.q.ListAPIKeyGateways(ctx, ids)
	if err != nil {
		return nil, err
	}
	scopes := map[uuid.UUID][]GatewayRef{}
	for _, r := range rows {
		scopes[r.ApiKeyID] = append(scopes[r.ApiKeyID], GatewayRef{ID: r.GatewayID, Slug: r.Slug, Name: r.Name, Exists: r.GatewayExists})
	}
	out := make([]View, len(keys))
	for i, k := range keys {
		out[i] = View{Key: k, Gateways: scopes[k.ID]}
		if out[i].Gateways == nil {
			out[i].Gateways = []GatewayRef{}
		}
	}
	return out, nil
}

// Revoke revokes one of the actor's keys; it stops working at once.
// Revoking a revoked key changes nothing. Audited as api_key.revoke.
func (s *Service) Revoke(ctx context.Context, a authz.Actor, id uuid.UUID) error {
	return store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		cur, err := q.GetUserAPIKey(ctx, dbgen.GetUserAPIKeyParams{ID: id, UserID: a.UserID})
		if errors.Is(store.NotFound(err), store.ErrNotFound) {
			return errNotFound
		} else if err != nil {
			return err
		}
		if cur.RevokedAt != nil {
			return nil
		}
		k, err := q.RevokeAPIKey(ctx, dbgen.RevokeAPIKeyParams{ID: id, UserID: a.UserID})
		if errors.Is(store.NotFound(err), store.ErrNotFound) {
			return nil // revoked concurrently
		} else if err != nil {
			return err
		}
		scope, err := q.ListAPIKeyGatewayIDs(ctx, k.ID)
		if err != nil {
			return err
		}
		e := a.Audit("api_key.revoke", "api_key", k.ID.String())
		e.Before = snapshot(cur, scope)
		e.Metadata = map[string]any{"name": k.Name}
		return audit.Record(ctx, q, e)
	})
}

// Principal is who a key authenticates.
type Principal struct {
	Key  dbgen.ApiKey
	User dbgen.User
	// Gateways limits the key to these gateways (empty: every gateway the
	// person may use).
	Gateways []uuid.UUID
}

// InScope reports whether the key may be used on a gateway (its owner's
// access is checked separately).
func (p Principal) InScope(gatewayID uuid.UUID) bool {
	return len(p.Gateways) == 0 || slices.Contains(p.Gateways, gatewayID)
}

// Authenticate checks a key: it must exist, be unrevoked and unexpired, and
// belong to an active person. Every failure is ErrInvalid.
func (s *Service) Authenticate(ctx context.Context, secret string) (Principal, error) {
	if !LooksLikeKey(secret) {
		return Principal{}, ErrInvalid
	}
	digest := Digest(s.pepper, secret)
	row, err := s.q.GetAPIKeyByDigest(ctx, digest)
	previous := false
	if errors.Is(store.NotFound(err), store.ErrNotFound) && s.previous != nil {
		// Made before the pepper rotation: re-digested below.
		digest, previous = Digest(s.previous, secret), true
		row, err = s.q.GetAPIKeyByDigest(ctx, digest)
	}
	if errors.Is(store.NotFound(err), store.ErrNotFound) {
		return Principal{}, ErrInvalid
	} else if err != nil {
		return Principal{}, err
	}
	// The digest lookup is exact; compare again in constant time anyway.
	if !hmac.Equal([]byte(row.ApiKey.Digest), []byte(digest)) ||
		Status(row.ApiKey, time.Now()) != StatusActive || row.User.Status != "active" {
		return Principal{}, ErrInvalid
	}
	if previous {
		if err := s.rehash(ctx, row.ApiKey, digest, Digest(s.pepper, secret)); err != nil {
			return Principal{}, err
		}
	}
	scope, err := s.q.ListAPIKeyGatewayIDs(ctx, row.ApiKey.ID)
	if err != nil {
		return Principal{}, err
	}
	return Principal{Key: row.ApiKey, User: row.User, Gateways: scope}, nil
}

// rehash moves a key found with the previous pepper to the current one.
// Audited as api_key.pepper_rehash by the system.
func (s *Service) rehash(ctx context.Context, k dbgen.ApiKey, old, digest string) error {
	return store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		n, err := q.RehashAPIKey(ctx, dbgen.RehashAPIKeyParams{ID: k.ID, OldDigest: old, Digest: digest, PepperID: PepperID(s.pepper)})
		if err != nil || n == 0 {
			return err // n == 0: another request did it
		}
		return audit.Record(ctx, q, audit.Entry{ActorKind: audit.ActorSystem, Action: "api_key.pepper_rehash", TargetType: "api_key",
			TargetID: k.ID.String(), Metadata: map[string]any{"name": k.Name, "prefix": k.Prefix}})
	})
}

// Touch records that a key was used (at most once a minute).
func (s *Service) Touch(ctx context.Context, id uuid.UUID) error { return s.q.TouchAPIKey(ctx, id) }
