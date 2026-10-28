package approvals

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
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
	// Many candidates share the same requester/rule/target. Memoize exact
	// authority reads only within this immutable snapshot, so applying the
	// existing permissions predicate does not repeat those round trips 200
	// times. Nothing survives the transaction or caches a decision authority.
	q = dbgen.New(&queueSnapshotReads{Tx: tx, cache: make(map[string]queueResult)})
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

// queueSnapshotReads is transaction-local memoization of SELECT results. Raw
// wire values are copied, then scanned afresh using pgx's own codecs; callers
// cannot mutate a cached result. Only use this with the read-only RR transaction.
// In particular, do not reuse it for detail projections or mutating methods.
// Candidate count bounds the number of distinct cached reads.
type queueSnapshotReads struct {
	pgx.Tx
	cache map[string]queueResult
}

type queueResult struct {
	fields []pgconn.FieldDescription
	data   [][][]byte
}

func (q *queueSnapshotReads) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(args)
	if err != nil {
		return nil, err
	}
	key := sql + "\x00" + string(encoded)
	result, ok := q.cache[key]
	if !ok {
		rows, err := q.Tx.Query(ctx, sql, args...)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		result.fields = append([]pgconn.FieldDescription(nil), rows.FieldDescriptions()...)
		for rows.Next() {
			values := make([][]byte, len(result.fields))
			for i, v := range rows.RawValues() {
				if v != nil {
					values[i] = append([]byte{}, v...)
				}
			}
			result.data = append(result.data, values)
		}
		if err = rows.Err(); err != nil {
			return nil, err
		}
		q.cache[key] = result
	}
	return &queueRows{result: result, conn: q.Tx.Conn(), index: -1}, nil
}

func (q *queueSnapshotReads) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	rows, err := q.Query(ctx, sql, args...)
	return queueRow{rows: rows, err: err}
}

type queueRow struct {
	rows pgx.Rows
	err  error
}

func (r queueRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	defer r.rows.Close()
	if !r.rows.Next() {
		return pgx.ErrNoRows
	}
	return r.rows.Scan(dest...)
}

type queueRows struct {
	result queueResult
	conn   *pgx.Conn
	index  int
	closed bool
}

func (r *queueRows) Close()     { r.closed = true }
func (r *queueRows) Err() error { return nil }
func (r *queueRows) CommandTag() pgconn.CommandTag {
	return pgconn.NewCommandTag("SELECT " + strconv.Itoa(len(r.result.data)))
}
func (r *queueRows) FieldDescriptions() []pgconn.FieldDescription { return r.result.fields }
func (r *queueRows) Next() bool {
	if r.closed {
		return false
	}
	r.index++
	if r.index >= len(r.result.data) {
		r.Close()
		return false
	}
	return true
}
func (r *queueRows) Scan(dest ...any) error {
	return pgx.ScanRow(r.conn.TypeMap(), r.result.fields, r.RawValues(), dest...)
}
func (r *queueRows) Values() ([]any, error) {
	values := make([]any, len(r.result.fields))
	dest := make([]any, len(values))
	for i := range values {
		dest[i] = &values[i]
	}
	return values, r.Scan(dest...)
}
func (r *queueRows) RawValues() [][]byte  { return r.result.data[r.index] }
func (r *queueRows) Conn() *pgx.Conn      { return r.conn }
func (r *queueRows) TypeMap() *pgtype.Map { return r.conn.TypeMap() }

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
