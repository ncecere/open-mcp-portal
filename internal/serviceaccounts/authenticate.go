package serviceaccounts

import (
	"context"
	"crypto/hmac"
	"errors"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ncecere/open-mcp-portal/internal/apikeys"
	"github.com/ncecere/open-mcp-portal/internal/audit"
	"github.com/ncecere/open-mcp-portal/internal/store"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/internal/teams"
)

// Principal is who a service account key authenticates.
type Principal struct {
	Key     dbgen.ServiceAccountKey
	Account dbgen.ServiceAccount
	Team    dbgen.Team
	// Gateways limits the key to these gateways (empty: every gateway the
	// account may use).
	Gateways []uuid.UUID
}

// InScope reports whether the key may be used on a gateway (the account's
// access is checked separately).
func (p Principal) InScope(gatewayID uuid.UUID) bool {
	return len(p.Gateways) == 0 || slices.Contains(p.Gateways, gatewayID)
}

// Authenticate checks a key: it must exist, be unrevoked and unexpired, and
// belong to an enabled account of an active team. Every failure is
// ErrInvalid.
func (s *Service) Authenticate(ctx context.Context, secret string) (Principal, error) {
	if !LooksLikeKey(secret) {
		return Principal{}, ErrInvalid
	}
	d := apikeys.Digest(s.pepper, secret)
	row, err := s.q.GetServiceAccountKeyByDigest(ctx, d)
	previous := false
	if errors.Is(store.NotFound(err), store.ErrNotFound) && s.previous != nil {
		// Made before the pepper rotation: re-digested below.
		d, previous = apikeys.Digest(s.previous, secret), true
		row, err = s.q.GetServiceAccountKeyByDigest(ctx, d)
	}
	if errors.Is(store.NotFound(err), store.ErrNotFound) {
		return Principal{}, ErrInvalid
	} else if err != nil {
		return Principal{}, err
	}
	if !hmac.Equal([]byte(row.ServiceAccountKey.Digest), []byte(d)) ||
		KeyStatus(row.ServiceAccountKey, time.Now()) != apikeys.StatusActive ||
		row.ServiceAccount.RelayPlatformID.Valid || !row.ServiceAccount.Enabled || row.Team.Status != teams.StatusActive {
		return Principal{}, ErrInvalid
	}
	if previous {
		if err := s.rehash(ctx, row, d, apikeys.Digest(s.pepper, secret)); err != nil {
			return Principal{}, err
		}
	}
	scope, err := s.q.ListServiceAccountKeyGatewayIDs(ctx, row.ServiceAccountKey.ID)
	if err != nil {
		return Principal{}, err
	}
	return Principal{Key: row.ServiceAccountKey, Account: row.ServiceAccount, Team: row.Team, Gateways: scope}, nil
}

// rehash moves a key found with the previous pepper to the current one.
// Audited as service_account_key.pepper_rehash by the system.
func (s *Service) rehash(ctx context.Context, row dbgen.GetServiceAccountKeyByDigestRow, old, digest string) error {
	k := row.ServiceAccountKey
	return store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		n, err := q.RehashServiceAccountKey(ctx, dbgen.RehashServiceAccountKeyParams{ID: k.ID, OldDigest: old, Digest: digest,
			PepperID: apikeys.PepperID(s.pepper)})
		if err != nil || n == 0 {
			return err // n == 0: another request did it
		}
		return audit.Record(ctx, q, audit.Entry{ActorKind: audit.ActorSystem, TeamID: row.Team.ID, Action: "service_account_key.pepper_rehash",
			TargetType: "service_account_key", TargetID: k.ID.String(), Metadata: map[string]any{"name": k.Name, "prefix": k.Prefix,
				"serviceAccountId": row.ServiceAccount.ID.String()}})
	})
}

// Touch records that a key and its account were used (at most once a
// minute each).
func (s *Service) Touch(ctx context.Context, p Principal) error {
	if err := s.q.TouchServiceAccountKey(ctx, p.Key.ID); err != nil {
		return err
	}
	return s.q.TouchServiceAccount(ctx, p.Account.ID)
}
