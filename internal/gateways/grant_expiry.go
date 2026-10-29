package gateways

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/ncecere/open-mcp-portal/internal/apperr"
	"github.com/ncecere/open-mcp-portal/internal/audit"
	"github.com/ncecere/open-mcp-portal/internal/store"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

func grantDeadline(grants []dbgen.GatewayGrant) *time.Time {
	var deadline *time.Time
	for _, grant := range grants {
		if at := grant.ExpiresAt; at != nil && (deadline == nil || at.Before(*deadline)) {
			value := *at
			deadline = &value
		}
	}
	return deadline
}

func grantExpiry(ctx context.Context, q *dbgen.Queries, days *int32) (*time.Time, error) {
	if days == nil {
		return nil, nil
	}
	if *days < 1 || *days > 365 {
		return nil, apperr.Invalid("invalid_expiry", "Grant expiry must be 1–365 days, or omitted for permanent access")
	}
	at, err := q.GatewayGrantClock(ctx)
	if err != nil {
		return nil, err
	}
	expires := at.Add(time.Duration(*days) * 24 * time.Hour)
	return &expires, nil
}

// GrantDeadlineLive checks the authoritative database clock at the outbound
// boundary. An application host whose clock is behind PostgreSQL must not send
// a call after the SQL-enforced expiry. QueryRow's Scan releases its connection
// before returning; no pool lease or transaction survives into network I/O.
func (s *Service) GrantDeadlineLive(ctx context.Context, expires time.Time) (bool, error) {
	at, err := s.q.GatewayGrantClock(ctx)
	if err != nil {
		return false, err
	}
	return at.Before(expires), nil
}

// CleanupGrants removes a bounded batch and audits every removal. Every access
// path already excludes elapsed grants, so a failed/delayed sweep grants nothing.
// The retention loop supplies leader election; no authority fence spans I/O.
func (s *Service) CleanupGrants(ctx context.Context, batch int32) (int64, error) {
	var n int64
	err := store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		rows, err := q.DeleteExpiredGatewayGrants(ctx, dbgen.DeleteExpiredGatewayGrantsParams{BatchSize: min(max(batch, 1), 1000)})
		if err != nil {
			return err
		}
		for _, row := range rows {
			e := audit.Entry{ActorKind: audit.ActorSystem, Action: "gateway.grant_expire", TargetType: "gateway_grant", TargetID: row.ID.String(),
				Metadata: map[string]any{"gatewayId": row.GatewayID.String(), "expiresAt": row.ExpiresAt}}
			if err := audit.Record(ctx, q, e); err != nil {
				return err
			}
		}
		n = int64(len(rows))
		return nil
	})
	return n, err
}
