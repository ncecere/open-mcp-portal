package auditstream

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/ncecere/open-mcp-portal/internal/observability"
	"github.com/ncecere/open-mcp-portal/internal/store"
)

// Rebind asserts xid continuity after pg_upgrade. Only the migration owner can
// update state; runtime credentials cannot perform recovery.
func (s Sealer) Rebind(ctx context.Context) error {
	return pgx.BeginTxFunc(ctx, s.Pool, pgx.TxOptions{}, func(tx pgx.Tx) error {
		var safe bool
		var status string
		if err := tx.QueryRow(ctx, `SELECT status FROM omp_audit.state WHERE singleton FOR UPDATE`).Scan(&status); err != nil {
			return err
		}
		if status != "halted_incarnation" {
			return fmt.Errorf("rebind requires halted_incarnation state")
		}
		if err := tx.QueryRow(ctx, `SELECT pg_snapshot_xmin(pg_current_snapshot())>=cursor_txid FROM omp_audit.state WHERE singleton FOR UPDATE`).Scan(&safe); err != nil {
			return err
		}
		if !safe {
			return fmt.Errorf("snapshot xmin is below cursor; rebase required")
		}
		_, err := tx.Exec(ctx, `UPDATE omp_audit.state SET system_identifier=(pg_control_system()).system_identifier::text,status='running' WHERE singleton AND status='halted_incarnation'`)
		return err
	})
}

// Rebase uses a lock-bounded, read-only snapshot solely for candidate identities.
// Its writer transactions always use fresh READ COMMITTED snapshots.
func (s Sealer) Rebase(ctx context.Context, resume *int64) error {
	return s.rebase(ctx, resume, nil)
}

func (s Sealer) rebase(ctx context.Context, resume *int64, hook func(string)) error {
	release, ok, err := storeLock(ctx, s)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("audit stream leader busy")
	}
	defer release()
	a, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer a.Rollback(ctx)
	if _, err = a.Exec(ctx, `LOCK public.audit_log IN SHARE MODE`); err != nil {
		return err
	}
	b, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return err
	}
	defer b.Rollback(ctx)
	// Force B's snapshot while A still holds the writer lock.
	if _, err = b.Exec(ctx, `SELECT pg_current_snapshot()`); err != nil {
		return err
	}
	if hook != nil {
		hook("locked")
	}
	var status string
	if err = a.QueryRow(ctx, `SELECT status FROM omp_audit.state WHERE singleton FOR UPDATE`).Scan(&status); err != nil {
		return err
	}
	if status != "rebasing" {
		if _, err = a.Exec(ctx, `SELECT omp_audit.prepare_epoch('rebase',$1::bigint)`, resume); err != nil {
			return err
		}
		if _, err = a.Exec(ctx, `UPDATE omp_audit.state SET status='rebasing',rebase_f=pg_current_xact_id(),rebase_resume_after=$1,cursor_txid=pg_current_xact_id(),cursor_id=0 WHERE singleton`, resume); err != nil {
			return err
		}
	} else if resume != nil {
		var stored *int64
		if err = a.QueryRow(ctx, `SELECT rebase_resume_after FROM omp_audit.state WHERE singleton`).Scan(&stored); err != nil {
			return err
		}
		if stored == nil || *stored != *resume {
			return fmt.Errorf("cannot change resume sequence during an unfinished rebase")
		}
	}
	if err = a.Commit(ctx); err != nil {
		return err
	}
	if hook != nil {
		hook("fenced")
	}
	var pending []byte
	if err = s.Pool.QueryRow(ctx, `SELECT epoch_pending FROM omp_audit.state WHERE singleton`).Scan(&pending); err != nil {
		return err
	}
	if pending != nil {
		var p struct {
			Summary EpochSummary `json:"summary"`
		}
		if err = json.Unmarshal(pending, &p); err != nil {
			return err
		}
		h := EpochSummaryHash(p.Summary)
		raw, _ := json.Marshal([]map[string]string{{"kind": "epoch_start", "summary_hash": fmt.Sprintf("%x", h)}})
		var n int64
		if err = s.Pool.QueryRow(ctx, `SELECT omp_audit.seal_batch('epoch',$1::jsonb)`, raw).Scan(&n); err != nil {
			return err
		}
		if n != 1 {
			return fmt.Errorf("incarnation changed while preparing rebase marker")
		}
	}
	if hook != nil {
		hook("marked")
	}
	rows, err := b.Query(ctx, `SELECT a.id,a.row_uid FROM public.audit_log a WHERE NOT EXISTS(SELECT 1 FROM omp_audit.chain c WHERE c.row_uid=a.row_uid OR (a.txid IS NULL AND c.legacy_id=a.id)) ORDER BY a.id`)
	if err != nil {
		return err
	}
	defer rows.Close()
	var ids []int64
	identities := map[int64]*uuid.UUID{}
	for rows.Next() {
		var id int64
		var uid *uuid.UUID
		if err = rows.Scan(&id, &uid); err != nil {
			return err
		}
		ids = append(ids, id)
		identities[id] = uid
		if len(ids) == 500 {
			if err = s.sealIDs(ctx, "rebase", ids, identities); err != nil {
				return err
			}
			ids = nil
			identities = map[int64]*uuid.UUID{}
		}
	}
	if err = rows.Err(); err != nil {
		return err
	}
	if len(ids) > 0 {
		if err = s.sealIDs(ctx, "rebase", ids, identities); err != nil {
			return err
		}
	}
	tag, err := s.Pool.Exec(ctx, `UPDATE omp_audit.state SET status='running' WHERE singleton AND status='rebasing' AND epoch_pending IS NULL`)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("rebase halted before completion")
	}
	return nil
}

func storeLock(ctx context.Context, s Sealer) (func(), bool, error) {
	return store.TryAdvisoryLockText(ctx, s.Pool, "omp.auditstream")
}

const sweepWhere = `((a.txid IS NULL AND a.id<=s.history_id) OR (a.txid IS NOT NULL AND (a.txid,a.id)<=(s.cursor_txid,s.cursor_id) AND a.txid<pg_snapshot_xmin(pg_current_snapshot()))) AND NOT EXISTS(SELECT 1 FROM omp_audit.chain c WHERE c.row_uid=a.row_uid) AND (a.txid IS NOT NULL OR NOT EXISTS(SELECT 1 FROM omp_audit.chain c WHERE c.legacy_id=a.id))`

// Sweep seals at most 500 gaps per pass. The loop holds leadership. Pending
// rebase sweeps remain scheduled until the cluster watermark has passed F.
func (s Sealer) Sweep(ctx context.Context) (int64, error) {
	var due bool
	if err := s.Pool.QueryRow(ctx, `SELECT status='running' AND (sweep_pending OR sweep_at IS NULL OR sweep_at<clock_timestamp()-interval '1 day') FROM omp_audit.state WHERE singleton`).Scan(&due); err != nil {
		return 0, err
	}
	if !due {
		return 0, nil
	}
	if _, err := s.Pool.Exec(ctx, `SELECT omp_audit.seal_batch('sweep_begin','[]'::jsonb)`); err != nil {
		return 0, err
	}
	rows, err := s.Pool.Query(ctx, sweepWindowQuery)
	if err != nil {
		return 0, err
	}
	var ids []int64
	var end *int64
	for rows.Next() {
		var id int64
		var missing bool
		if err = rows.Scan(&id, &missing); err != nil {
			rows.Close()
			return 0, err
		}
		v := id
		end = &v
		if missing {
			ids = append(ids, id)
			if len(ids) == 500 {
				break
			}
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return 0, err
	}
	if len(ids) > 0 {
		if err = s.sealIDs(ctx, "sweep", ids); err != nil {
			return 0, err
		}
		observability.AuditStreamLate.Add(float64(len(ids)))
	}
	raw, _ := json.Marshal([]map[string]any{{"end": end}})
	_, err = s.Pool.Exec(ctx, `SELECT omp_audit.seal_batch('sweep_done',$1::jsonb)`, raw)
	return int64(len(ids)), err
}

func (s Sealer) sealIDs(ctx context.Context, mode string, ids []int64, expected ...map[int64]*uuid.UUID) error {
	halted := false
	err := pgx.BeginTxFunc(ctx, s.Pool, pgx.TxOptions{IsoLevel: pgx.ReadCommitted}, func(tx pgx.Tx) error {
		var stream uuid.UUID
		var epoch uint32
		var seq int64
		var prev []byte
		if err := tx.QueryRow(ctx, `SELECT stream_id,epoch,last_seq,last_chain_hash FROM omp_audit.state WHERE singleton`).Scan(&stream, &epoch, &seq, &prev); err != nil {
			return err
		}
		candidates, err := readRows(ctx, tx, `SELECT to_jsonb(a),a.before_state::text,a.after_state::text,a.metadata::text FROM public.audit_log a WHERE a.id=ANY($1) AND NOT EXISTS(SELECT 1 FROM omp_audit.chain c WHERE c.row_uid=a.row_uid OR (a.txid IS NULL AND c.legacy_id=a.id)) ORDER BY a.id`, ids)
		if err != nil {
			return err
		}
		if len(candidates) == 0 {
			return nil
		}
		var previous [32]byte
		copy(previous[:], prev)
		var records []Record
		for _, r := range candidates {
			if len(expected) > 0 {
				uid, ok := expected[0][r.ID]
				if !ok || (uid == nil) != (r.RowUID == nil) || (uid != nil && *uid != *r.RowUID) {
					return fmt.Errorf("snapshot identity changed during rebase")
				}
			}
			seq++
			rec, ch, err := NewRecord(stream, epoch, seq, previous, r)
			if err != nil {
				return err
			}
			if mode == "sweep" {
				rec.Flags = 1
				sh := SummaryHash(r)
				eh, err := EntryHash(r)
				if err != nil {
					return err
				}
				ch = sha256.Sum256(append(append([]byte("OMP-AUDIT-EVIDENCE\x00CHAIN\x00V2\x00"), previous[:]...), RecordBytes(stream, epoch, seq, 1, r, sh, eh)...))
				rec.Chain = fmt.Sprintf("%x", ch)
			}
			previous = ch
			records = append(records, rec)
		}
		raw, err := json.Marshal(records)
		if err != nil {
			return err
		}
		var n int64
		if err = tx.QueryRow(ctx, `SELECT omp_audit.seal_batch($1,$2::jsonb)`, mode, raw).Scan(&n); err != nil {
			return err
		}
		if n != int64(len(records)) {
			halted = true
			return nil
		}
		return nil
	})
	if err == nil && halted {
		return fmt.Errorf("sealing halted during recovery")
	}
	return err
}

// Materialize a bounded primary-key window before testing eligibility/identity.
// Even a completely sealed billion-row log costs at most 5000 probes per pass.
const sweepWindowQuery = `WITH w AS MATERIALIZED (SELECT a.id,a.txid,a.row_uid FROM public.audit_log a WHERE a.id>=coalesce((SELECT sweep_scan_id FROM omp_audit.state WHERE singleton),'-9223372036854775808'::bigint) AND ((SELECT sweep_scan_id FROM omp_audit.state WHERE singleton) IS NULL OR a.id>(SELECT sweep_scan_id FROM omp_audit.state WHERE singleton)) ORDER BY a.id LIMIT 5000)
SELECT a.id,(` + sweepWhere + `) FROM w a CROSS JOIN (SELECT * FROM omp_audit.state WHERE singleton LIMIT 1) s ORDER BY a.id`
