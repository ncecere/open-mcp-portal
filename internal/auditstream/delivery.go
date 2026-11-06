package auditstream

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/ncecere/open-mcp-portal/internal/observability"
)

// Envelope carries the original canonical record fields and an authenticated
// projection. Full rows contain only columns already readable in the audit API.
type Envelope struct {
	Record
	Stream        uuid.UUID           `json:"stream_id"`
	Epoch         uint32              `json:"epoch"`
	OccurredAt    time.Time           `json:"occurred_at"`
	Checkpoint    *CheckpointEnvelope `json:"checkpoint,omitempty"`
	EpochSummary  *EpochSummary       `json:"epoch_summary,omitempty"`
	SummaryFields json.RawMessage     `json:"summary_fields,omitempty"`
	Full          *Row                `json:"full,omitempty"`
	Oversized     bool                `json:"oversized,omitempty"`
	FullLength    int                 `json:"full_length,omitempty"`
	Reference     string              `json:"reference,omitempty"`
}

// FullRowJSONSQL is shared by envelope length and bounded fetch, so the
// advertised byte length is exactly the referenced UTF-8 representation.
const FullRowJSONSQL = `(to_jsonb(a)||jsonb_build_object('sql_null_json',to_jsonb(array_remove(ARRAY[CASE WHEN a.before_state IS NULL THEN 'before_state' END,CASE WHEN a.after_state IS NULL THEN 'after_state' END,CASE WHEN a.metadata IS NULL THEN 'metadata' END],NULL))))::text`

const joinAudit = ` LEFT JOIN public.audit_log a ON a.id=c.audit_id AND (a.row_uid=c.row_uid OR (a.txid IS NULL AND a.id=c.legacy_id)) `

// CheckRange must run in the same repeatable-read snapshot as Read. PurgedSeq
// is an explicit prefix anchor: a missing row above it is corruption, never 410.
func CheckRange(ctx context.Context, tx pgx.Tx, after int64, limit int) (int64, error) {
	var expired int64
	if err := tx.QueryRow(ctx, `SELECT purged_seq FROM omp_audit.retention_floor WHERE singleton`).Scan(&expired); err != nil {
		return 0, err
	}
	if after < expired {
		return expired + 1, fmt.Errorf("range_expired")
	}
	var bad *int64
	err := tx.QueryRow(ctx, `SELECT min(seq) FROM (SELECT c.seq,c.kind,a.id FROM omp_audit.chain c `+joinAudit+` WHERE c.seq>$1 ORDER BY c.seq LIMIT $2) x WHERE kind='entry' AND id IS NULL`, after, limit).Scan(&bad)
	if err != nil {
		return 0, err
	}
	if bad != nil {
		observability.AuditStreamIntegrity.WithLabelValues("audit_row_missing").Inc()
		return 0, fmt.Errorf("audit_row_missing")
	}
	return expired + 1, nil
}

func Read(ctx context.Context, tx pgx.Tx, seq int64, full bool) (Envelope, error) {
	var e Envelope
	var raw, epochRaw, statement, signatures []byte
	var before, after, meta *string
	var timestamp time.Time
	err := tx.QueryRow(ctx, `SELECT s.stream_id,c.seq,c.kind,c.flags,c.row_uid,c.legacy_id,coalesce(c.audit_id,0),c.epoch,c.occurred_at,encode(c.summary_hash,'hex'),encode(c.entry_hash,'hex'),encode(c.chain_hash,'hex'),c.epoch_summary,c.checkpoint_statement,c.checkpoint_signatures,to_jsonb(a),a.before_state::text,a.after_state::text,a.metadata::text,coalesce(octet_length(`+FullRowJSONSQL+`),0) FROM omp_audit.chain c CROSS JOIN omp_audit.state s `+joinAudit+` WHERE c.seq=$1`, seq).Scan(&e.Stream, &e.Seq, &e.Kind, &e.Flags, &e.RowUID, &e.LegacyID, &e.AuditID, &e.Epoch, &timestamp, &e.Record.Summary, &e.Entry, &e.Chain, &epochRaw, &statement, &signatures, &raw, &before, &after, &meta, &e.FullLength)
	if err != nil {
		return e, err
	}
	e.OccurredAt = timestamp
	if e.Kind == "checkpoint" {
		e.Checkpoint, err = NewCheckpointEnvelope(statement, signatures)
		return e, err
	}
	if e.Kind != "entry" {
		err = json.Unmarshal(epochRaw, &e.EpochSummary)
		return e, err
	}
	if len(raw) == 0 || string(raw) == "null" {
		return e, fmt.Errorf("audit_row_missing")
	}
	var row Row
	if err = json.Unmarshal(raw, &row); err != nil {
		return e, err
	}
	row.SQLNullJSON = []string{}
	if before == nil {
		row.SQLNullJSON = append(row.SQLNullJSON, "before_state")
	}
	if after == nil {
		row.SQLNullJSON = append(row.SQLNullJSON, "after_state")
	}
	if meta == nil {
		row.SQLNullJSON = append(row.SQLNullJSON, "metadata")
	}
	row.BeforeState = nil
	row.AfterState = nil
	row.Metadata = nil
	if before != nil {
		row.BeforeState = json.RawMessage(*before)
	}
	if after != nil {
		row.AfterState = json.RawMessage(*after)
	}
	if meta != nil {
		row.Metadata = json.RawMessage(*meta)
	}
	e.SummaryFields, _ = json.Marshal(struct {
		OccurredAt   time.Time  `json:"occurred_at"`
		Action       string     `json:"action"`
		ActorKind    string     `json:"actor_kind"`
		ActorUserID  *uuid.UUID `json:"actor_user_id"`
		TeamID       *uuid.UUID `json:"team_id"`
		TargetType   string     `json:"target_type"`
		TargetID     string     `json:"target_id"`
		RequestID    string     `json:"request_id"`
		ActorTokenID *uuid.UUID `json:"actor_token_id"`
	}{row.OccurredAt, row.Action, row.ActorKind, row.ActorUserID, row.TeamID, row.TargetType, row.TargetID, row.RequestID, row.ActorTokenID})
	if full {
		e.Full = &row
	}
	return e, nil
}

// VerifyEntry also checks caller-supplied entry digests against the retained row.
func VerifyEntry(e Envelope, prev [32]byte) (bool, error) {
	if e.Full == nil {
		return false, fmt.Errorf("entry absent")
	}
	sh := SummaryHash(*e.Full)
	eh, err := EntryHash(*e.Full)
	if err != nil {
		return false, err
	}
	b := append([]byte("OMP-AUDIT-EVIDENCE\x00CHAIN\x00V2\x00"), prev[:]...)
	b = append(b, RecordBytes(e.Stream, e.Epoch, e.Seq, e.Flags, *e.Full, sh, eh)...)
	ch := sha256.Sum256(b)
	return hex.EncodeToString(sh[:]) == e.Record.Summary && hex.EncodeToString(eh[:]) == e.Entry && hex.EncodeToString(ch[:]) == e.Chain, nil
}

func VerifyEpoch(e Envelope, prev [32]byte) bool {
	if e.EpochSummary == nil {
		return false
	}
	declaration := e.EpochSummary
	if declaration.PreviousEpoch+1 != e.Epoch || declaration.PredecessorHash != hex.EncodeToString(prev[:]) {
		return false
	}
	if declaration.GapTo == nil {
		if declaration.PredecessorSeq != e.Seq-1 {
			return false
		}
	} else if *declaration.GapTo != e.Seq-1 {
		return false
	}
	sh := EpochSummaryHash(*e.EpochSummary)
	if hex.EncodeToString(sh[:]) != e.Record.Summary {
		return false
	}
	b := append([]byte("OMP-AUDIT-EVIDENCE\x00CHAIN\x00V2\x00"), prev[:]...)
	b = append(b, EpochRecordBytes(e.Stream, e.Epoch, e.Seq, e.OccurredAt, sh)...)
	ch := sha256.Sum256(b)
	return hex.EncodeToString(ch[:]) == e.Chain
}
