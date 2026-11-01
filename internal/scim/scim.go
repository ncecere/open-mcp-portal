// Package scim implements supported SCIM 2.0 provisioning (decision 92,
// docs/scim.md): one directory bound to the verified OIDC issuer, directory
// bearer tokens, Users/Groups resources, enrollment at sign-in, reversible
// directory deactivation, irreversible deletion with bounded cleanup, and
// reviewed group-to-team-role mappings.
//
// A SCIM resource is not an identity. A resource links to a portal person
// only when its externalId equals that person's verified OIDC subject of the
// configured issuer, at enrollment or by explicit admin adoption. Email and
// userName never link. Platform admins and team owners are never directory
// managed (database triggers enforce it).
//
// Standing: users.status stays the single effective standing every reader
// checks; it is derived from users.manual_status and users.directory_standing
// by trigger. Directory deactivation therefore fences every existing final
// writer, and the session generation/request epoch triggers end old cookies
// and queued requests without deleting locked rows.
//
// Lock order: directory -> scim_user/scim_group -> users -> teams (sorted) ->
// memberships. No transaction here performs network I/O.
package scim

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ncecere/open-mcp-portal/internal/apperr"
	"github.com/ncecere/open-mcp-portal/internal/audit"
	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/credentials"
	"github.com/ncecere/open-mcp-portal/internal/httpx"
	"github.com/ncecere/open-mcp-portal/internal/secrets"
	"github.com/ncecere/open-mcp-portal/internal/store"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

// Enrollment policies.
const (
	EnrollmentOptional = "optional"
	EnrollmentRequired = "required"
)

// Directory standings (users.directory_standing).
const (
	StandingNone     = "none"
	StandingActive   = "active"
	StandingInactive = "inactive"
	StandingDeleted  = "deleted"
)

// Token limits.
const (
	MaxActiveTokens  = 5
	DefaultTokenDays = 90
	MaxTokenDays     = 365
)

var (
	errAdminOnly     = apperr.Forbidden("Only platform admins can manage provisioning")
	errReadOnly      = apperr.Forbidden("Only platform admins and auditors can see provisioning")
	errSessionNeeded = apperr.New(http.StatusForbidden, "session_required", "Provisioning is managed in a browser session only")
	errNoDirectory   = apperr.NotFound("directory_not_found", "Provisioning is not set up")
	errNoOIDC        = apperr.Conflict("oidc_required", "Provisioning needs single sign-on (OIDC) to be configured")
	errBadEnrollment = apperr.Invalid("invalid_enrollment", "enrollment must be optional or required")
	errBadName       = apperr.Invalid("invalid_name", "Name must be 1-100 characters on one line")
	errBadExpiry     = apperr.Invalid("invalid_expiry", "expiresInDays must be between 1 and 365")
	errTooManyTokens = apperr.Conflict("too_many_tokens", "There are 5 active provisioning tokens. Revoke one you no longer use first.")
	errTokenNotFound = apperr.NotFound("token_not_found", "Token not found")
	// ErrInvalid is any directory token that doesn't authenticate.
	ErrInvalid = errors.New("invalid provisioning token")
)

// Service manages provisioning.
type Service struct {
	pool     *pgxpool.Pool
	q        *dbgen.Queries
	pepper   []byte
	previous []byte
	// Issuer is the configured OIDC issuer ("" without OIDC): the only issuer
	// a directory may bind to.
	Issuer string
	// AppURL makes absolute resource locations (meta.location).
	AppURL string
	now    func() time.Time
}

// New returns a Service; pepper is API_KEY_PEPPER (decoded).
func New(pool *pgxpool.Pool, pepper []byte, issuer string) *Service {
	var q *dbgen.Queries
	if pool != nil {
		q = dbgen.New(pool)
	}
	return &Service{pool: pool, q: q, pepper: pepper, Issuer: issuer, now: time.Now}
}

// SetPreviousPepper accepts tokens digested with API_KEY_PEPPER_PREVIOUS.
func (s *Service) SetPreviousPepper(p []byte) { s.previous = p }

// Digest is a token's stored form: HMAC-SHA256 (hex) keyed with the pepper,
// the same construction as personal keys and automation tokens.
func Digest(pepper []byte, secret string) string {
	m := hmac.New(sha256.New, pepper)
	m.Write([]byte(secret))
	return hex.EncodeToString(m.Sum(nil))
}

// pepperID says which pepper made a digest (as for personal keys).
func pepperID(pepper []byte) []byte { return secrets.KeyID(pepper) }

// Directory is the provisioning setup as the admin API shows it.
type Directory struct {
	Row         dbgen.ScimDirectory
	IssuerMatch bool // the stored issuer is the configured OIDC issuer
}

func adminActor(a authz.Actor) error {
	if a.IsToken() {
		return errSessionNeeded
	}
	if !a.IsPlatformAdmin() {
		return errAdminOnly
	}
	return nil
}

// GetDirectory returns the directory (platform admins and auditors).
func (s *Service) GetDirectory(ctx context.Context, a authz.Actor) (Directory, error) {
	if !a.CanReadPlatform() {
		return Directory{}, errReadOnly
	}
	d, err := s.q.GetSCIMDirectory(ctx)
	if errors.Is(err, pgx.ErrNoRows) {
		return Directory{}, errNoDirectory
	} else if err != nil {
		return Directory{}, err
	}
	return Directory{Row: d, IssuerMatch: d.Issuer == s.Issuer}, nil
}

// DirectoryInput changes the directory. Revision 0 creates it.
type DirectoryInput struct {
	Enabled    bool
	Enrollment string
}

// SaveDirectory creates or updates the directory (platform admins, session).
// It binds to the configured OIDC issuer at creation; the issuer never
// changes afterwards. Audited as scim.directory_create / scim.directory_update.
func (s *Service) SaveDirectory(ctx context.Context, a authz.Actor, in DirectoryInput, expectedRevision int64) (Directory, error) {
	if err := adminActor(a); err != nil {
		return Directory{}, err
	}
	if in.Enrollment != EnrollmentOptional && in.Enrollment != EnrollmentRequired {
		return Directory{}, errBadEnrollment
	}
	var out dbgen.ScimDirectory
	err := store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		cur, err := q.LockSCIMDirectory(ctx)
		if errors.Is(err, pgx.ErrNoRows) {
			if expectedRevision != 0 {
				return apperr.Stale()
			}
			if s.Issuer == "" {
				return errNoOIDC
			}
			if out, err = q.InsertSCIMDirectory(ctx, dbgen.InsertSCIMDirectoryParams{
				Issuer: s.Issuer, Enabled: in.Enabled, Enrollment: in.Enrollment, CreatedBy: uuid.NullUUID{UUID: a.UserID, Valid: true},
			}); err != nil {
				return err
			}
			e := a.Audit("scim.directory_create", "scim_directory", out.ID.String())
			e.After = directorySnapshot(out)
			return audit.Record(ctx, q, e)
		} else if err != nil {
			return err
		}
		if cur.Revision != expectedRevision {
			return apperr.Stale()
		}
		if in.Enabled && cur.Issuer != s.Issuer {
			return apperr.Conflict("issuer_changed", "Single sign-on now uses another issuer than this directory. Provisioning stays off.")
		}
		if out, err = q.UpdateSCIMDirectory(ctx, dbgen.UpdateSCIMDirectoryParams{ID: cur.ID, Enabled: in.Enabled, Enrollment: in.Enrollment}); err != nil {
			return err
		}
		e := a.Audit("scim.directory_update", "scim_directory", out.ID.String())
		e.Before, e.After = directorySnapshot(cur), directorySnapshot(out)
		return audit.Record(ctx, q, e)
	})
	return Directory{Row: out, IssuerMatch: out.Issuer == s.Issuer}, err
}

func directorySnapshot(d dbgen.ScimDirectory) map[string]any {
	return map[string]any{"issuer": d.Issuer, "enabled": d.Enabled, "enrollment": d.Enrollment}
}

// Token is a directory token as the admin API shows it (never the secret).
type Token struct {
	Row dbgen.ScimToken
}

// Status is active, expired or revoked.
func (t Token) Status(now time.Time) string {
	switch {
	case t.Row.RevokedAt != nil:
		return "revoked"
	case !t.Row.ExpiresAt.After(now):
		return "expired"
	}
	return "active"
}

// CreatedToken carries the secret, shown once.
type CreatedToken struct {
	Token
	Secret string
}

// ListTokens lists the directory's tokens (platform admins and auditors).
func (s *Service) ListTokens(ctx context.Context, a authz.Actor) ([]Token, error) {
	d, err := s.GetDirectory(ctx, a)
	if err != nil {
		return nil, err
	}
	rows, err := s.q.ListSCIMTokens(ctx, d.Row.ID)
	if err != nil {
		return nil, err
	}
	out := make([]Token, len(rows))
	for i, r := range rows {
		out[i] = Token{Row: r}
	}
	return out, nil
}

// CreateToken makes a directory token (platform admins, session). The token
// is bound to the directory, not to its creator: it keeps working after the
// creator leaves, until it expires or is revoked. Audited as
// scim.token_create without the secret.
func (s *Service) CreateToken(ctx context.Context, a authz.Actor, name string, days int32) (CreatedToken, error) {
	if err := adminActor(a); err != nil {
		return CreatedToken{}, err
	}
	name = strings.TrimSpace(name)
	if n := utf8.RuneCountInString(name); n < 1 || n > 100 || strings.ContainsAny(name, "\r\n\x00") {
		return CreatedToken{}, errBadName
	}
	if days == 0 {
		days = DefaultTokenDays
	}
	if days < 1 || days > MaxTokenDays {
		return CreatedToken{}, errBadExpiry
	}
	secret := credentials.SCIMPrefix + httpx.NewID(32)
	var out CreatedToken
	err := store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		d, err := q.LockSCIMDirectory(ctx)
		if errors.Is(err, pgx.ErrNoRows) {
			return errNoDirectory
		} else if err != nil {
			return err
		}
		n, err := q.CountActiveSCIMTokens(ctx, d.ID)
		if err != nil {
			return err
		}
		if n >= MaxActiveTokens {
			return errTooManyTokens
		}
		creator, err := q.GetUser(ctx, a.UserID)
		if err != nil {
			return err
		}
		by := creator.DisplayName
		if by == "" {
			by = creator.Email
		}
		row, err := q.InsertSCIMToken(ctx, dbgen.InsertSCIMTokenParams{
			DirectoryID: d.ID, Name: name, Prefix: secret[:len(credentials.SCIMPrefix)+8], Digest: Digest(s.pepper, secret),
			PepperID: pepperID(s.pepper), CreatedBy: uuid.NullUUID{UUID: a.UserID, Valid: true}, CreatedByName: &by, Days: days,
		})
		if err != nil {
			return err
		}
		out = CreatedToken{Token: Token{Row: row}, Secret: secret}
		e := a.Audit("scim.token_create", "scim_token", row.ID.String())
		e.Metadata = map[string]any{"name": row.Name, "prefix": row.Prefix, "expiresAt": row.ExpiresAt}
		return audit.Record(ctx, q, e)
	})
	return out, err
}

// RevokeToken revokes a directory token at once (platform admins, session).
// Revoking a revoked token changes nothing. Audited as scim.token_revoke.
func (s *Service) RevokeToken(ctx context.Context, a authz.Actor, id uuid.UUID) error {
	if err := adminActor(a); err != nil {
		return err
	}
	return store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		d, err := q.GetSCIMDirectory(ctx)
		if errors.Is(err, pgx.ErrNoRows) {
			return errNoDirectory
		} else if err != nil {
			return err
		}
		cur, err := q.GetSCIMToken(ctx, dbgen.GetSCIMTokenParams{ID: id, DirectoryID: d.ID})
		if errors.Is(err, pgx.ErrNoRows) {
			return errTokenNotFound
		} else if err != nil {
			return err
		}
		if cur.RevokedAt != nil {
			return nil
		}
		row, err := q.RevokeSCIMToken(ctx, dbgen.RevokeSCIMTokenParams{ID: id, RevokedBy: uuid.NullUUID{UUID: a.UserID, Valid: true}})
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		} else if err != nil {
			return err
		}
		e := a.Audit("scim.token_revoke", "scim_token", row.ID.String())
		e.Metadata = map[string]any{"name": row.Name, "prefix": row.Prefix}
		return audit.Record(ctx, q, e)
	})
}

// Principal is an authenticated directory token.
type Principal struct {
	TokenID     uuid.UUID
	TokenName   string
	DirectoryID uuid.UUID
}

// Authenticate checks a directory token: shape, digest (current then
// previous pepper, re-digesting on use), unrevoked, unexpired and the
// directory enabled. Every failure is ErrInvalid.
func (s *Service) Authenticate(ctx context.Context, secret string) (Principal, error) {
	if credentials.Classify(secret) != credentials.SCIMToken {
		return Principal{}, ErrInvalid
	}
	digest := Digest(s.pepper, secret)
	row, err := s.q.GetSCIMTokenByDigest(ctx, digest)
	previous := false
	if errors.Is(err, pgx.ErrNoRows) && s.previous != nil {
		digest, previous = Digest(s.previous, secret), true
		row, err = s.q.GetSCIMTokenByDigest(ctx, digest)
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return Principal{}, ErrInvalid
	} else if err != nil {
		return Principal{}, err
	}
	t := row.ScimToken
	if !hmac.Equal([]byte(t.Digest), []byte(digest)) || !row.DirectoryEnabled || (Token{Row: t}).Status(s.now()) != "active" {
		return Principal{}, ErrInvalid
	}
	if previous {
		if _, err := s.q.RehashSCIMToken(ctx, dbgen.RehashSCIMTokenParams{ID: t.ID, OldDigest: digest, Digest: Digest(s.pepper, secret), PepperID: pepperID(s.pepper)}); err != nil {
			return Principal{}, err
		}
	}
	_ = s.q.TouchSCIMToken(ctx, t.ID)
	return Principal{TokenID: t.ID, TokenName: t.Name, DirectoryID: t.DirectoryID}, nil
}

// audit is the system audit entry of a directory write, attributed to the
// directory token that made it.
func (p Principal) audit(action, targetType, targetID, requestID string) audit.Entry {
	return audit.Entry{ActorKind: audit.ActorSystem, Action: action, TargetType: targetType, TargetID: targetID, RequestID: requestID,
		Metadata: map[string]any{"via": "scim", "tokenId": p.TokenID.String(), "tokenName": p.TokenName}}
}
