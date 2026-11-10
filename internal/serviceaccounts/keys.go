package serviceaccounts

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ncecere/open-mcp-portal/internal/apikeys"
	"github.com/ncecere/open-mcp-portal/internal/apperr"
	"github.com/ncecere/open-mcp-portal/internal/audit"
	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/httpx"
	"github.com/ncecere/open-mcp-portal/internal/store"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/internal/toolscope"
)

// KeyView is a key with the gateways it is limited to (none: every gateway
// the account may use).
type KeyView struct {
	Key           dbgen.ServiceAccountKey
	CreatedByName *string
	Gateways      []apikeys.GatewayRef
}

// CreatedKey is a new key and its secret (shown once).
type CreatedKey struct {
	KeyView
	Secret string
}

// KeyStatus says whether a key is active, expired or revoked at now.
func KeyStatus(k dbgen.ServiceAccountKey, now time.Time) string {
	switch {
	case k.RevokedAt != nil:
		return apikeys.StatusRevoked
	case !k.ExpiresAt.After(now):
		return apikeys.StatusExpired
	}
	return apikeys.StatusActive
}

// keySnapshot is a key's audited form: never the secret or its digest.
func keySnapshot(k dbgen.ServiceAccountKey, sa dbgen.ServiceAccount, gatewayIDs []uuid.UUID) map[string]any {
	ids := make([]string, len(gatewayIDs))
	for i, id := range gatewayIDs {
		ids[i] = id.String()
	}
	return map[string]any{"name": k.Name, "prefix": k.Prefix, "expiresAt": k.ExpiresAt, "gatewayIds": ids,
		"serviceAccountId": sa.ID.String(), "serviceAccount": sa.Name, "toolScope": toolscope.Stored(k.ToolScope)}
}

// account returns one of the team's accounts after the read check.
func (s *Service) account(ctx context.Context, q *dbgen.Queries, ta teamAccess, id uuid.UUID, lock bool) (dbgen.ServiceAccount, error) {
	var (
		sa  dbgen.ServiceAccount
		err error
	)
	if lock {
		sa, err = q.LockServiceAccount(ctx, dbgen.LockServiceAccountParams{ID: id, TeamID: ta.team.ID})
	} else {
		var row dbgen.GetServiceAccountViewRow
		row, err = q.GetServiceAccountView(ctx, dbgen.GetServiceAccountViewParams{ID: id, TeamID: ta.team.ID})
		sa = row.ServiceAccount
	}
	if errors.Is(store.NotFound(err), store.ErrNotFound) {
		return sa, errNotFound
	}
	return sa, err
}

// ListKeys lists an account's keys, newest first: active ones, and those
// revoked or expired in the last 30 days (team owners and admins; platform
// admins and auditors).
func (s *Service) ListKeys(ctx context.Context, a authz.Actor, ref string, id uuid.UUID) ([]KeyView, error) {
	ta, err := access(ctx, s.q, a, ref)
	if err != nil {
		return nil, err
	}
	sa, err := s.account(ctx, s.q, ta, id, false)
	if err != nil {
		return nil, err
	}
	if err := ta.readKeys(a); err != nil {
		return nil, err
	}
	rows, err := s.q.ListServiceAccountKeys(ctx, sa.ID)
	if err != nil {
		return nil, err
	}
	ids := make([]uuid.UUID, len(rows))
	for i, r := range rows {
		ids[i] = r.ServiceAccountKey.ID
	}
	scopes, err := s.scopes(ctx, s.q, ids)
	if err != nil {
		return nil, err
	}
	out := make([]KeyView, len(rows))
	for i, r := range rows {
		out[i] = KeyView{Key: r.ServiceAccountKey, CreatedByName: r.CreatedByName, Gateways: scopes[r.ServiceAccountKey.ID]}
		if out[i].Gateways == nil {
			out[i].Gateways = []apikeys.GatewayRef{}
		}
	}
	return out, nil
}

func (s *Service) scopes(ctx context.Context, q *dbgen.Queries, keyIDs []uuid.UUID) (map[uuid.UUID][]apikeys.GatewayRef, error) {
	rows, err := q.ListServiceAccountKeyGateways(ctx, keyIDs)
	if err != nil {
		return nil, err
	}
	out := map[uuid.UUID][]apikeys.GatewayRef{}
	for _, r := range rows {
		out[r.KeyID] = append(out[r.KeyID], apikeys.GatewayRef{ID: r.GatewayID, Slug: r.Slug, Name: r.Name, Exists: r.GatewayExists})
	}
	return out, nil
}

// CreateKeyInput is a new key.
type CreateKeyInput struct {
	ToolScope []byte
	Name      string
	// Days is its lifetime (0: apikeys.DefaultDays).
	Days int32
	// GatewayIDs limits it to these gateways (empty: every gateway the
	// account may use). Each must be one the account may use now.
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

// CreateKey makes a key for an account (team owners and admins; at most
// MaxActiveKeys active; the account must be on). Audited as
// service_account_key.create, without the secret.
func (s *Service) CreateKey(ctx context.Context, a authz.Actor, ref string, id uuid.UUID, in CreateKeyInput) (CreatedKey, error) {
	toolScope, err := toolscope.Canonical(in.ToolScope)
	if err != nil {
		return CreatedKey{}, err
	}
	name := strings.TrimSpace(in.Name)
	if n := utf8.RuneCountInString(name); n < 1 || n > 100 || strings.ContainsAny(name, "\r\n\x00") {
		return CreatedKey{}, errBadKeyName
	}
	days := in.Days
	if days == 0 {
		days = apikeys.DefaultDays
	}
	if days < 1 || days > apikeys.MaxDays {
		return CreatedKey{}, errBadExpiry
	}
	gatewayIDs := dedupe(in.GatewayIDs)
	if len(gatewayIDs) > apikeys.MaxGateways {
		return CreatedKey{}, errTooManyGw
	}
	secret := KeyPrefix + httpx.NewID(32)
	var out CreatedKey
	err = store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		ta, err := access(ctx, q, a, ref)
		if err != nil {
			return err
		}
		// Locking the account serialises its key creation, so the limit holds.
		sa, err := s.account(ctx, q, ta, id, true)
		if err != nil {
			return err
		}
		if err := ta.writable(); err != nil {
			return err
		}
		if sa.RelayPlatformID.Valid {
			return errRetired
		}
		if !sa.Enabled {
			return errDisabled
		}
		var scope []dbgen.Gateway
		if len(gatewayIDs) > 0 {
			usable, refused, err := s.gateways.UsableByServiceAccount(ctx, ta.team.ID, sa.Role, gatewayIDs)
			if err != nil {
				return err
			}
			if len(refused) > 0 {
				e := apperr.New(http.StatusUnprocessableEntity, "gateway_not_usable",
					"A key can only be limited to gateways the service account can use now")
				e.Details = map[string]any{"gatewayIds": refused}
				return e
			}
			scope = usable
		}
		n, err := q.CountActiveServiceAccountKeys(ctx, sa.ID)
		if err != nil {
			return err
		}
		if n >= MaxActiveKeys {
			return errTooManyKeys
		}
		k, err := q.InsertServiceAccountKey(ctx, dbgen.InsertServiceAccountKeyParams{
			ServiceAccountID: sa.ID, Name: name, Prefix: secret[:prefixLen], Digest: apikeys.Digest(s.pepper, secret), ToolScope: toolScope,
			PepperID:  apikeys.PepperID(s.pepper),
			CreatedBy: by(a), ExpiresAt: time.Now().Add(time.Duration(days) * 24 * time.Hour),
		})
		if err != nil {
			return err
		}
		refs := make([]apikeys.GatewayRef, 0, len(scope))
		for _, g := range scope {
			if err := q.InsertServiceAccountKeyGateway(ctx, dbgen.InsertServiceAccountKeyGatewayParams{
				KeyID: k.ID, GatewayID: g.ID, GatewaySlug: g.Slug, GatewayName: g.Name,
			}); err != nil {
				return err
			}
			refs = append(refs, apikeys.GatewayRef{ID: g.ID, Slug: g.Slug, Name: g.Name, Exists: true})
		}
		slices.SortFunc(refs, func(x, y apikeys.GatewayRef) int { return strings.Compare(x.Name, y.Name) })
		row, err := q.GetServiceAccountKey(ctx, dbgen.GetServiceAccountKeyParams{ID: k.ID, ServiceAccountID: sa.ID})
		if err != nil {
			return err
		}
		out = CreatedKey{KeyView: KeyView{Key: k, CreatedByName: row.CreatedByName, Gateways: refs}, Secret: secret}
		e := a.Audit("service_account_key.create", "service_account_key", k.ID.String())
		e.TeamID, e.After = ta.team.ID, keySnapshot(k, sa, gatewayIDs)
		return audit.Record(ctx, q, e)
	})
	return out, err
}

// RevokeKey revokes one of an account's keys (team owners and admins); it
// stops working at the next request. Revoking a revoked key changes
// nothing. Audited as service_account_key.revoke.
func (s *Service) RevokeKey(ctx context.Context, a authz.Actor, ref string, id, keyID uuid.UUID) error {
	return store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		ta, err := access(ctx, q, a, ref)
		if err != nil {
			return err
		}
		sa, err := s.account(ctx, q, ta, id, true)
		if err != nil {
			return err
		}
		if err := ta.writable(); err != nil {
			return err
		}
		cur, err := q.GetServiceAccountKey(ctx, dbgen.GetServiceAccountKeyParams{ID: keyID, ServiceAccountID: sa.ID})
		if errors.Is(store.NotFound(err), store.ErrNotFound) {
			return errKeyNotFound
		} else if err != nil {
			return err
		}
		if cur.ServiceAccountKey.RevokedAt != nil {
			return nil
		}
		k, err := q.RevokeServiceAccountKey(ctx, dbgen.RevokeServiceAccountKeyParams{ID: keyID, ServiceAccountID: sa.ID})
		if errors.Is(store.NotFound(err), store.ErrNotFound) {
			return nil // revoked concurrently
		} else if err != nil {
			return err
		}
		scope, err := q.ListServiceAccountKeyGatewayIDs(ctx, k.ID)
		if err != nil {
			return err
		}
		e := a.Audit("service_account_key.revoke", "service_account_key", k.ID.String())
		e.TeamID, e.Before = ta.team.ID, keySnapshot(cur.ServiceAccountKey, sa, scope)
		e.Metadata = map[string]any{"name": sa.Name + " · " + k.Name}
		return audit.Record(ctx, q, e)
	})
}
