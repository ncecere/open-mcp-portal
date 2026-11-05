package auditstream

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/ncecere/open-mcp-portal/internal/observability"
	"github.com/ncecere/open-mcp-portal/internal/store"
)

// Sealer provides normal history and watermark sealing. Recovery operations
// are deliberately separate from this slice's normal-operation interface.
type Sealer struct{ Pool *pgxpool.Pool }

// Batch re-reads candidates each time. A failed/stale batch never advances state.
func (s Sealer) Batch(ctx context.Context) (int64, error) {
	var count int64
	err := pgx.BeginTxFunc(ctx, s.Pool, pgx.TxOptions{IsoLevel: pgx.ReadCommitted}, func(tx pgx.Tx) error {
		var stream uuid.UUID
		var epoch uint32
		var seq int64
		var previous []byte
		var cursor string
		var cursorID, historyID int64
		if err := tx.QueryRow(ctx, `SELECT stream_id,epoch,last_seq,last_chain_hash,cursor_txid::text,cursor_id,history_id FROM omp_audit.state WHERE singleton`).Scan(&stream, &epoch, &seq, &previous, &cursor, &cursorID, &historyID); err != nil {
			return err
		}
		mode := "history"
		read := func(query string, args ...any) ([]Row, error) {
			rows, err := tx.Query(ctx, query, args...)
			if err != nil {
				return nil, err
			}
			defer rows.Close()
			var result []Row
			for rows.Next() {
				var raw []byte
				var before, after, meta *string
				if err := rows.Scan(&raw, &before, &after, &meta); err != nil {
					return nil, err
				}
				var r Row
				if err := json.Unmarshal(raw, &r); err != nil {
					return nil, err
				}
				r.BeforeState = nil
				r.AfterState = nil
				r.Metadata = nil
				if before != nil {
					r.BeforeState = json.RawMessage(*before)
				}
				if after != nil {
					r.AfterState = json.RawMessage(*after)
				}
				if meta != nil {
					r.Metadata = json.RawMessage(*meta)
				}
				result = append(result, r)
			}
			return result, rows.Err()
		}
		// JSONB renders xid8 as a string. Separately project JSON text to distinguish
		// SQL NULL from the jsonb token null, without passing numbers through floats.
		const projection = `SELECT to_jsonb(a),a.before_state::text,a.after_state::text,a.metadata::text FROM public.audit_log a `
		candidates, err := read(projection+`WHERE a.txid IS NULL AND a.id>$1 ORDER BY a.id LIMIT 500`, historyID)
		if err != nil {
			return err
		}
		if len(candidates) == 0 {
			mode = "fast"
			candidates, err = read(projection+`WHERE a.txid<pg_snapshot_xmin(pg_current_snapshot()) AND (a.txid,a.id)>($1::xid8,$2::bigint) AND NOT EXISTS(SELECT 1 FROM omp_audit.chain c WHERE c.row_uid=a.row_uid) ORDER BY a.txid,a.id LIMIT 500`, cursor, cursorID)
			if err != nil {
				return err
			}
		}
		if len(candidates) == 0 {
			return nil
		}
		var prev [32]byte
		copy(prev[:], previous)
		records := make([]Record, 0, len(candidates))
		for _, r := range candidates {
			seq++
			rec, ch, err := NewRecord(stream, epoch, seq, prev, r)
			if err != nil {
				return err
			}
			prev = ch
			records = append(records, rec)
		}
		raw, err := json.Marshal(records)
		if err != nil {
			return err
		}
		return tx.QueryRow(ctx, `SELECT omp_audit.seal_batch($1,$2::jsonb)`, mode, raw).Scan(&count)
	})
	if err == nil {
		observability.AuditStreamSealed.Add(float64(count))
	}
	return count, err
}

// Loop elects one leader per pass; all SQL and hashing stays within the local
// database transaction. No delivery or recovery is implied by this loop.
func (s Sealer) Loop(ctx context.Context, log *slog.Logger) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			release, ok, err := store.TryAdvisoryLockText(ctx, s.Pool, "omp.auditstream")
			if err != nil {
				log.Error("audit stream leadership failed", "error", err)
				continue
			}
			if !ok {
				continue
			}
			_, err = s.Batch(ctx)
			release()
			if err != nil {
				log.Error("audit stream batch failed", "error", err)
			}
			var lag float64
			if err := s.Pool.QueryRow(ctx, lagQuery).Scan(&lag); err == nil {
				observability.AuditStreamLag.Set(lag)
			}
		}
	}
}

// lagQuery is the age of the oldest unsealed row. It reads only the unsealed tail
// (above the history and watermark cursors, through 00059's partial indexes),
// never the whole audit log.
const lagQuery = `WITH s AS (SELECT cursor_txid,cursor_id,history_id FROM omp_audit.state WHERE singleton)
SELECT coalesce(greatest(0,extract(epoch FROM clock_timestamp()-least(
 (SELECT min(a.occurred_at) FROM public.audit_log a,s WHERE a.txid IS NULL AND a.id>s.history_id),
 (SELECT min(a.occurred_at) FROM public.audit_log a,s WHERE a.txid IS NOT NULL AND (a.txid,a.id)>(s.cursor_txid,s.cursor_id)
   AND NOT EXISTS(SELECT 1 FROM omp_audit.chain c WHERE c.row_uid=a.row_uid))))),0)::float8`
