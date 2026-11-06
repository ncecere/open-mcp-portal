package auditstream

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/ncecere/open-mcp-portal/internal/observability"
)

var ErrRangeExpired = errors.New("range_expired")
var ErrIntegrity = errors.New("audit_chain_gap")

const LineCap = 16 << 20

// Range buffers and validates a complete request in the caller's read-only
// REPEATABLE READ snapshot. Last, when nonzero, pins a retry's endpoint.
type Range struct {
	Earliest  int64
	Envelopes []Envelope
	Lines     [][]byte
}

func EnvelopeLine(e Envelope, full bool) (Envelope, []byte, error) {
	raw, err := json.Marshal(e)
	if err != nil {
		return e, nil, err
	}
	if full && (e.Flags&2 != 0 || len(raw)+1 > LineCap) {
		e.Full = nil
		e.Oversized = true
		e.Reference = fmt.Sprintf("/v1/admin/audit/entries/%d/full", e.Seq)
		raw, err = json.Marshal(e)
	}
	return e, append(raw, '\n'), err
}

func ReadRange(ctx context.Context, tx pgx.Tx, after int64, limit int, full bool, last int64) (Range, error) {
	var result Range
	earliest, err := CheckRange(ctx, tx, after, limit)
	result.Earliest = earliest
	if err != nil {
		return result, err
	}
	var tip int64
	if err = tx.QueryRow(ctx, `SELECT last_seq FROM omp_audit.state WHERE singleton`).Scan(&tip); err != nil {
		return result, err
	}
	rows, err := tx.Query(ctx, `SELECT seq FROM omp_audit.chain WHERE seq>$1 AND ($3::bigint=0 OR seq<=$3) ORDER BY seq LIMIT $2`, after, limit, last)
	if err != nil {
		return result, err
	}
	var seqs []int64
	for rows.Next() {
		var n int64
		if err = rows.Scan(&n); err != nil {
			break
		}
		seqs = append(seqs, n)
	}
	rows.Close()
	if err == nil {
		err = rows.Err()
	}
	if err != nil {
		return result, err
	}
	previous := after
	for _, seq := range seqs {
		env, e := Read(ctx, tx, seq, full)
		if e != nil {
			return Range{}, e
		}
		if !contiguous(previous, env) {
			return Range{}, rangeIntegrity()
		}
		env, line, e := EnvelopeLine(env, full)
		if e != nil {
			return Range{}, e
		}
		result.Envelopes = append(result.Envelopes, env)
		result.Lines = append(result.Lines, line)
		previous = seq
	}
	// Detect a missing tail as well as interior holes, including an exact retry.
	if (last != 0 && previous != last) || (last == 0 && len(seqs) < limit && previous < tip) {
		return Range{}, rangeIntegrity()
	}
	return result, nil
}
func contiguous(previous int64, e Envelope) bool {
	if e.Seq == previous+1 {
		return true
	}
	d := e.EpochSummary
	return e.Seq > previous+1 && e.Kind == "epoch_start" && d != nil && d.GapFrom != nil && d.GapTo != nil && *d.GapFrom == previous+1 && *d.GapTo == e.Seq-1 && d.PredecessorSeq == previous
}
func rangeIntegrity() error {
	observability.AuditStreamIntegrity.WithLabelValues("chain_gap").Inc()
	return ErrIntegrity
}
