package auditstream

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/ncecere/open-mcp-portal/internal/secrets"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/ncecere/open-mcp-portal/internal/observability"
	"github.com/ncecere/open-mcp-portal/internal/store"
)

// Sealer provides history/watermark sealing and owner-directed recovery.
type Sealer struct{ Pool *pgxpool.Pool }

// Batch re-reads candidates each time. A failed/stale batch never advances state.
func (s Sealer) Batch(ctx context.Context) (int64, error) {
	if _, err := s.Pool.Exec(ctx, `SELECT omp_audit.seal_batch('check','[]'::jsonb)`); err != nil {
		return 0, err
	}
	var status string
	var currentEpoch float64
	if err := s.Pool.QueryRow(ctx, `SELECT epoch FROM omp_audit.state WHERE singleton`).Scan(&currentEpoch); err != nil {
		return 0, err
	}
	observability.AuditStreamEpoch.Set(currentEpoch)
	if err := s.Pool.QueryRow(ctx, `SELECT status FROM omp_audit.state WHERE singleton`).Scan(&status); err != nil {
		return 0, err
	}
	for _, v := range []string{"running", "rebasing", "halted_incarnation"} {
		n := float64(0)
		if status == v {
			n = 1
		}
		observability.AuditStreamState.WithLabelValues(v).Set(n)
	}
	if status != "running" {
		return 0, nil
	}
	var count, snapshotSeq int64
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
		snapshotSeq = seq
		mode := "history"
		// JSONB renders xid8 as a string. Separately project JSON text to distinguish
		// SQL NULL from the jsonb token null, without passing numbers through floats.
		const projection = `SELECT to_jsonb(a),a.before_state::text,a.after_state::text,a.metadata::text FROM public.audit_log a `
		candidates, err := readRows(ctx, tx, projection+`WHERE a.txid IS NULL AND a.id>$1 AND NOT EXISTS(SELECT 1 FROM omp_audit.chain c WHERE c.legacy_id=a.id) ORDER BY a.id LIMIT 500`, historyID)
		if err != nil {
			return err
		}
		if len(candidates) == 0 {
			mode = "fast"
			candidates, err = readRows(ctx, tx, projection+`WHERE a.txid<pg_snapshot_xmin(pg_current_snapshot()) AND (a.txid,a.id)>($1::xid8,$2::bigint) AND NOT EXISTS(SELECT 1 FROM omp_audit.chain c WHERE c.row_uid=a.row_uid) ORDER BY a.txid,a.id LIMIT 500`, cursor, cursorID)
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
	// Rotation can advance the tip between candidate hashing and seal_batch.
	// Only suppress the specific invalid-record rejection when the tip moved.
	if s.staleBatch(ctx, err, snapshotSeq) {
		return 0, nil
	}
	return count, err
}

// Loop elects one leader per pass; all SQL and hashing stays within the local
// database transaction. Incarnation checks and safety sweeps run here; owner
// rebase/rebind operations remain explicit commands.
func (s Sealer) Loop(ctx context.Context, log *slog.Logger, boxes ...*secrets.Box) {
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
			var passTip int64
			if err := s.Pool.QueryRow(ctx, `SELECT last_seq FROM omp_audit.state WHERE singleton`).Scan(&passTip); err != nil {
				release()
				log.Error("audit stream tip read failed", "error", err)
				continue
			}
			_, err = s.Batch(ctx)
			if err == nil {
				_, err = s.Sweep(ctx)
			}
			if err == nil && len(boxes) > 0 {
				err = s.checkpointIfDue(ctx, boxes[0], time.Now(), 10000, 15*time.Minute)
			}
			release()
			if err != nil && !s.staleBatch(ctx, err, passTip) {
				log.Error("audit stream batch failed", "error", err)
			}
			var lag float64
			if err := s.Pool.QueryRow(ctx, lagQuery).Scan(&lag); err == nil {
				observability.AuditStreamLag.Set(lag)
				s.observeConsumers(ctx)
			}
		}
	}
}

// lagQuery is the age of the oldest unsealed row. It reads only the unsealed tail
// (above the history and watermark cursors, through 00059's partial indexes),
// never the whole audit log.
const lagQuery = `WITH s AS (SELECT cursor_txid,cursor_id,history_id FROM omp_audit.state WHERE singleton)
SELECT coalesce(greatest(0,extract(epoch FROM clock_timestamp()-least(
 (SELECT min(a.occurred_at) FROM public.audit_log a,s WHERE a.txid IS NULL AND a.id>s.history_id AND NOT EXISTS(SELECT 1 FROM omp_audit.chain c WHERE c.legacy_id=a.id)),
 (SELECT min(a.occurred_at) FROM public.audit_log a,s WHERE a.txid IS NOT NULL AND (a.txid,a.id)>(s.cursor_txid,s.cursor_id)
   AND NOT EXISTS(SELECT 1 FROM omp_audit.chain c WHERE c.row_uid=a.row_uid))))),0)::float8`

func readRows(ctx context.Context, tx pgx.Tx, query string, args ...any) ([]Row, error) {
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

// checkpointIfDue is called only by the elected leader. Clock and thresholds
// are arguments so tests exercise cadence without changing public settings.
func (s Sealer) checkpointIfDue(ctx context.Context, box *secrets.Box, now time.Time, threshold int64, interval time.Duration) error {
	var enabled, running bool
	var entries int64
	var last *time.Time
	if err := s.Pool.QueryRow(ctx, `SELECT coalesce(checkpoints_enabled,false),status='running' AND epoch_pending IS NULL,coalesce(entries_since_checkpoint,0),last_checkpoint_at FROM omp_audit.state WHERE singleton`).Scan(&enabled, &running, &entries, &last); err != nil {
		return err
	}
	observability.AuditStreamCheckpointsEnabled.Set(0)
	if enabled {
		observability.AuditStreamCheckpointsEnabled.Set(1)
	}
	observability.AuditStreamCheckpointPending.Set(float64(entries))
	if last != nil {
		observability.AuditStreamLastCheckpoint.Set(float64(last.UnixMicro()) / 1e6)
	}
	if !enabled || !running || entries == 0 || (entries < threshold && (last == nil || now.Sub(*last) < interval)) {
		return nil
	}
	if _, err := EnsureCheckpointKey(ctx, s.Pool, box); err != nil {
		return err
	}
	_, err := SubmitCheckpoint(ctx, s.Pool, box)
	return err
}

// staleBatch distinguishes a rotation racing candidate hashing from a malformed
// record at the same tip. A stale sweep is retried on the next leader pass.
func (s Sealer) staleBatch(ctx context.Context, err error, snapshotSeq int64) bool {
	var pe *pgconn.PgError
	if !errors.As(err, &pe) || pe.Code != "P0001" || pe.Message != "invalid record" {
		return false
	}
	var tip int64
	return s.Pool.QueryRow(ctx, `SELECT last_seq FROM omp_audit.state WHERE singleton`).Scan(&tip) == nil && tip != snapshotSeq
}
