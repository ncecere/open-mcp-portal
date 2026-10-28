package approvals

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/ncecere/open-mcp-portal/internal/apperr"
	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

const queueCandidateBudget = 200

type queueCursor struct {
	View      string    `json:"view"`
	CreatedAt time.Time `json:"createdAt"`
	ID        uuid.UUID `json:"id"`
}

func parseQueueCursor(raw, view string) (queueCursor, error) {
	var c queueCursor
	if raw == "" {
		return c, nil
	}
	invalid := apperr.Invalid("invalid_cursor", "Invalid cursor")
	if len(raw) > 512 {
		return c, invalid
	}
	b, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return c, invalid
	}
	if err = json.Unmarshal(b, &c); err != nil || c.View != view || c.ID == uuid.Nil || c.CreatedAt.IsZero() || c.CreatedAt.Year() < 1 || c.CreatedAt.Year() > 9999 {
		return queueCursor{}, invalid
	}
	return c, nil
}

func encodeQueueCursor(view string, at time.Time, id uuid.UUID) string {
	b, _ := json.Marshal(queueCursor{View: view, CreatedAt: at, ID: id})
	return base64.RawURLEncoding.EncodeToString(b)
}

// ListRequestsPage returns metadata and advisory action flags, not authority or
// previews. A snapshot keeps actor, epoch and policy reads consistent without
// the global write fence or even a KEY SHARE actor lock. Decisions and consumes
// independently revalidate authority under their own fences.
//
// Each call examines at most 200 SQL-filtered candidates (plus one lookahead),
// even if none pass exact permissions. The cursor advances over the last
// examined candidate, so an empty page with a next cursor is intentional.
func (s *Service) ListRequestsPage(ctx context.Context, a authz.Actor, view, cursor string, limit int32) ([]Receipt, string, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if a.IsToken() || (a.Kind != "" && a.Kind != authz.KindUser) || a.UserID == uuid.Nil {
		return nil, "", apperr.Forbidden("A human browser session is required")
	}
	if view == "" {
		view = "actionable"
	}
	if view != "requested" && view != "actionable" {
		return nil, "", apperr.Invalid("invalid_view", "View must be requested or actionable")
	}
	if err := pagination(0, limit); err != nil {
		return nil, "", err
	}
	c, err := parseQueueCursor(cursor, view)
	if err != nil {
		return nil, "", err
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, "", safeError(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := dbgen.New(tx)
	// Fresh snapshot validation, never trust a role cached in the session.
	u, err := q.GetUser(ctx, a.UserID)
	if err != nil || u.Status != "active" {
		return nil, "", apperr.Forbidden("An active human browser session is required")
	}
	a.PlatformRole = u.PlatformRole
	epoch, err := q.GetApprovalContext(ctx)
	if err != nil {
		return nil, "", safeError(err)
	}
	scan := dbgen.ApprovalQueueCandidatesParams{ActorID: a.UserID, QueueView: view, AtTime: s.clock(), ContextEpoch: epoch, PlatformAdmin: a.PlatformRole == authz.PlatformAdmin, CandidateLimit: queueCandidateBudget + 1}
	if !c.CreatedAt.IsZero() {
		scan.BeforeTime = &c.CreatedAt
		scan.BeforeID = nullable(c.ID)
	}
	rows, err := q.ApprovalQueueCandidates(ctx, scan)
	if err != nil {
		return nil, "", safeError(err)
	}
	out := []Receipt{}
	next := ""
	for i, row := range rows {
		if i == queueCandidateBudget {
			break
		}
		r := metadataRequest(dbgen.ApprovalRequestMetadataBatchRow(row))
		// Passing false deliberately avoids permissions' detail/cipher binding
		// lookup for renewal. Compute that hint separately using metadata only.
		p, visible, _, e := s.permissions(ctx, q, a, r, epoch, false)
		if e != nil {
			return nil, "", safeError(e)
		}
		include := visible && (view == "requested" || p.CanDecide)
		if include {
			if view == "requested" && !p.Stale && terminal(r.Status) && row.HasPreview {
				p.CanRenew, e = s.queueCanRenew(ctx, q, r, epoch)
				if e != nil {
					return nil, "", safeError(e)
				}
			}
			out = append(out, p)
		}
		next = ""
		if i+1 < len(rows) {
			next = encodeQueueCursor(view, row.CreatedAt, row.ID)
		}
		if len(out) == int(limit) {
			break
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, "", safeError(err)
	}
	return out, next, nil
}

func (s *Service) queueCanRenew(ctx context.Context, q *dbgen.Queries, r dbgen.ApprovalRequest, epoch int64) (bool, error) {
	latest, err := q.ApprovalQueueLatestBindingID(ctx, r.BindingDigest)
	if err != nil || latest != r.ID {
		return false, err
	}
	rule, err := s.currentRequestRule(ctx, q, r, epoch)
	if err != nil {
		return false, err
	}
	ids, err := reviewers(ctx, q, *rule, requestBinding(r))
	return len(ids) > 0, err
}
