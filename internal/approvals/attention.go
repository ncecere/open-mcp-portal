package approvals

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/ncecere/open-mcp-portal/internal/apperr"
	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

// AttentionItem is deliberately narrower than a receipt: no requester,
// arguments, digests, preview metadata or decision authority are exposed.
type AttentionItem struct {
	ID          uuid.UUID
	ExposedName string
	CreatedAt   time.Time
}

// Attention returns at most limit pending approvals this human can review,
// together with their exact total, optionally restricted to the server's team.
// It is a read-only snapshot hint; decisions independently revalidate authority.
// Automation tokens get no private approval scope, without breaking overview.
func (s *Service) Attention(ctx context.Context, a authz.Actor, team *uuid.UUID, limit int32) ([]AttentionItem, int64, error) {
	if a.IsToken() || (a.Kind != "" && a.Kind != authz.KindUser) {
		return []AttentionItem{}, 0, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if a.UserID == uuid.Nil {
		return nil, 0, apperr.Forbidden("An active human browser session is required")
	}
	if err := pagination(0, limit); err != nil {
		return nil, 0, err
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, 0, safeError(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := dbgen.New(tx)
	u, err := q.GetUser(ctx, a.UserID)
	if err != nil || u.Status != "active" {
		return nil, 0, apperr.Forbidden("An active human browser session is required")
	}
	epoch, err := q.GetApprovalContext(ctx)
	if err != nil {
		return nil, 0, safeError(err)
	}
	teamID := uuid.NullUUID{}
	if team != nil {
		teamID = uuid.NullUUID{UUID: *team, Valid: true}
	}
	rows, err := q.ApprovalAttention(ctx, dbgen.ApprovalAttentionParams{
		ActorID: a.UserID, TeamID: teamID, AtTime: s.clock(), ContextEpoch: epoch,
		PlatformAdmin: u.PlatformRole == authz.PlatformAdmin, PageLimit: limit,
	})
	if err != nil {
		return nil, 0, safeError(err)
	}
	out := make([]AttentionItem, 0, len(rows))
	var total int64
	for _, row := range rows {
		total = row.Total
		out = append(out, AttentionItem{ID: row.ID, ExposedName: row.ExposedName, CreatedAt: row.CreatedAt})
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, 0, safeError(err)
	}
	return out, total, nil
}
