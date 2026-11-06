package auditstream

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/ncecere/open-mcp-portal/internal/secrets"
)

// EnsureCheckpointKey discards a creation-race loser's key and authenticates the
// winner's sealed material before returning its public identity.
func EnsureCheckpointKey(ctx context.Context, pool *pgxpool.Pool, box *secrets.Box) (CheckpointKID, error) {
	kid, pub, cipher, err := GenerateCheckpointKey(box)
	if err != nil {
		return CheckpointKID{}, err
	}
	var storedKid, storedPub, storedCipher []byte
	err = pool.QueryRow(ctx, `SELECT kid,public_key,private_key_cipher FROM omp_audit_ext.ensure_checkpoint_key($1,$2,$3)`, kid[:], []byte(pub), cipher).Scan(&storedKid, &storedPub, &storedCipher)
	if err != nil {
		return CheckpointKID{}, err
	}
	if len(storedKid) != 16 {
		return CheckpointKID{}, fmt.Errorf("invalid stored checkpoint kid")
	}
	winner := CheckpointKID(storedKid)
	private, err := OpenCheckpointKey(box, winner, storedPub, storedCipher)
	clear(private)
	return winner, err
}

type checkpointSnapshot struct {
	statement CheckpointStatement
	system    string
	timeline  int64
	status    string
	enabled   bool
	pending   bool
	kid       CheckpointKID
	private   ed25519.PrivateKey
}

func readCheckpointSnapshot(ctx context.Context, tx pgx.Tx, box *secrets.Box) (checkpointSnapshot, error) {
	var s checkpointSnapshot
	var hash, kid, pub, cipher []byte
	q := `SELECT s.stream_id,s.epoch,s.last_seq,s.last_chain_hash,s.system_identifier,s.timeline,s.status,coalesce(s.checkpoints_enabled,false),s.epoch_pending IS NOT NULL,k.kid,k.public_key,k.private_key_cipher
 FROM omp_audit.state s JOIN omp_audit_ext.checkpoint_keys k ON k.state='active' WHERE s.singleton`
	err := tx.QueryRow(ctx, q).Scan(&s.statement.Stream, &s.statement.Epoch, &s.statement.CoveredSeq, &hash, &s.system, &s.timeline, &s.status, &s.enabled, &s.pending, &kid, &pub, &cipher)
	if err != nil {
		return s, err
	}
	if !s.enabled || s.status != "running" || s.pending {
		return s, fmt.Errorf("checkpoints require an enabled running stream without a pending epoch")
	}
	if len(hash) != 32 || len(kid) != 16 {
		return s, fmt.Errorf("invalid checkpoint state")
	}
	copy(s.statement.CoveredHash[:], hash)
	s.kid = CheckpointKID(kid)
	s.statement.Kids = []CheckpointKID{s.kid}
	s.statement.Seq = s.statement.CoveredSeq + 1
	s.statement.IssuedAtMicros = time.Now().UnixMicro()
	s.private, err = OpenCheckpointKey(box, s.kid, pub, cipher)
	return s, err
}

func checkpointRetry(err error) bool {
	var p *pgconn.PgError
	return errors.As(err, &p) && p.Code == "40001"
}

// SubmitCheckpoint rereads and resigns on serialization conflicts. No network
// calls occur while a state lock is held. Retries are bounded and cancellable.
func SubmitCheckpoint(ctx context.Context, pool *pgxpool.Pool, box *secrets.Box) (int64, error) {
	var seq int64
	var err error
	for range 8 {
		err = pgx.BeginTxFunc(ctx, pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead}, func(tx pgx.Tx) error {
			s, e := readCheckpointSnapshot(ctx, tx, box)
			if e != nil {
				return e
			}
			defer clear(s.private)
			raw, sigs, e := SignCheckpoint(s.statement, s.private)
			if e != nil {
				return e
			}
			sh, e := CheckpointSummaryHash(raw, sigs)
			if e != nil {
				return e
			}
			ch := sha256.Sum256(append(append([]byte("OMP-AUDIT-EVIDENCE\x00CHAIN\x00V2\x00"), s.statement.CoveredHash[:]...), CheckpointRecordBytes(s.statement, sh)...))
			b, e := json.Marshal([]any{map[string]any{"kind": "checkpoint", "seq": s.statement.Seq, "flags": 0, "entry_hash": hex.EncodeToString(make([]byte, 32)), "summary_hash": hex.EncodeToString(sh[:]), "chain_hash": hex.EncodeToString(ch[:]), "checkpoint_statement": hex.EncodeToString(raw), "checkpoint_signatures": hex.EncodeToString(sigs)}})
			if e != nil {
				return e
			}
			_, e = tx.Exec(ctx, `SELECT omp_audit.seal_batch('checkpoint',$1::jsonb)`, b)
			seq = s.statement.Seq
			return e
		})
		if !checkpointRetry(err) || ctx.Err() != nil {
			return seq, err
		}
	}
	return 0, fmt.Errorf("checkpoint retry limit: %w", err)
}

// RotateCheckpointKeyTx holds state FOR UPDATE while reading, signing and
// submitting the handover. The caller owns commit/rollback. The explicit lock
// precedes the key read, so a waiting rotation reads the committed winner.
func RotateCheckpointKeyTx(ctx context.Context, tx pgx.Tx, box *secrets.Box) (int64, error) {
	if err := lockCheckpointState(ctx, tx, box); err != nil {
		return 0, err
	}
	s, err := readCheckpointSnapshot(ctx, tx, box)
	if err != nil {
		return 0, err
	}
	defer clear(s.private)
	kid, pub, cipher, err := GenerateCheckpointKey(box)
	if err != nil {
		return 0, err
	}
	private, err := OpenCheckpointKey(box, kid, pub, cipher)
	if err != nil {
		return 0, err
	}
	defer clear(private)
	s.statement.Kids = append(s.statement.Kids, kid)
	raw, sigs, err := SignCheckpoint(s.statement, s.private, private)
	if err != nil {
		return 0, err
	}
	var seq int64
	err = tx.QueryRow(ctx, `SELECT omp_audit_ext.rotate_checkpoint_key($1,$2,$3,$4,$5)`, kid[:], []byte(pub), cipher, raw, sigs).Scan(&seq)
	return seq, err
}

// RotateCheckpointKey retries transaction conflicts. Incarnation or status
// changes are never retried into a different stream incarnation.
func RotateCheckpointKey(ctx context.Context, pool *pgxpool.Pool, box *secrets.Box) (int64, error) {
	var system, status string
	var timeline int64
	if err := pool.QueryRow(ctx, `SELECT system_identifier,timeline,status FROM omp_audit.state WHERE singleton`).Scan(&system, &timeline, &status); err != nil {
		return 0, err
	}
	var seq int64
	var err error
	for range 8 {
		err = pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
			if e := lockCheckpointState(ctx, tx, box); e != nil {
				return e
			}
			var liveSystem, liveStatus string
			var liveTimeline int64
			if e := tx.QueryRow(ctx, `SELECT system_identifier,timeline,status FROM omp_audit.state WHERE singleton`).Scan(&liveSystem, &liveTimeline, &liveStatus); e != nil {
				return e
			}
			if status != "running" || liveStatus != status || liveSystem != system || liveTimeline != timeline {
				return fmt.Errorf("checkpoint rotation aborted: incarnation or status changed")
			}
			var e error
			seq, e = RotateCheckpointKeyTx(ctx, tx, box)
			return e
		})
		if !checkpointRetry(err) || ctx.Err() != nil {
			return seq, err
		}
	}
	return 0, fmt.Errorf("checkpoint rotation retry limit: %w", err)
}

// Row locking requires UPDATE rights even without modifying a row. Use the
// existing definer primitive so runtime needs no new omp_audit column grant.
func lockCheckpointState(ctx context.Context, tx pgx.Tx, box *secrets.Box) error {
	kid, pub, cipher, err := GenerateCheckpointKey(box)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `SELECT kid FROM omp_audit_ext.ensure_checkpoint_key($1,$2,$3)`, kid[:], []byte(pub), cipher)
	return err
}
