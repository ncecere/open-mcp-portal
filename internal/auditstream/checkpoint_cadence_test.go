package auditstream

import (
	"bytes"
	"testing"
	"time"

	"github.com/ncecere/open-mcp-portal/internal/secrets"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

func TestCheckpointCadence(t *testing.T) {
	p, _ := testutil.NewDB(t)
	owner := testutil.OwnerPool(t, p)
	box, err := secrets.New(bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	s := Sealer{Pool: p}
	due := func(now time.Time, threshold int64) {
		t.Helper()
		if err := s.checkpointIfDue(ctx, box, now, threshold, 15*time.Minute); err != nil {
			t.Fatal(err)
		}
	}
	count := func() int {
		t.Helper()
		var n int
		if err := p.QueryRow(ctx, `SELECT count(*) FROM omp_audit.chain WHERE kind='checkpoint'`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	exec(t, p, insert)
	drain(t, p)
	due(time.Now().Add(time.Hour), 1)
	if count() != 0 {
		t.Fatal("checkpoint before enable")
	}
	exec(t, owner, `SELECT omp_audit_ext.enable_checkpoints('0.15.0')`)
	var baseline time.Time
	if err := p.QueryRow(ctx, `SELECT last_checkpoint_at FROM omp_audit.state`).Scan(&baseline); err != nil {
		t.Fatal(err)
	}
	due(baseline.Add(time.Hour), 10000)
	if count() != 0 {
		t.Fatal("idle checkpoint")
	}
	exec(t, p, insert)
	drain(t, p)
	due(baseline.Add(14*time.Minute), 10000)
	if count() != 0 {
		t.Fatal("checkpoint before interval")
	}
	due(baseline.Add(15*time.Minute), 10000)
	if count() != 1 {
		t.Fatal("missing timed checkpoint")
	}
	due(baseline.Add(time.Hour), 1)
	if count() != 1 {
		t.Fatal("checkpoint counted as entry")
	}
	exec(t, p, insert)
	drain(t, p)
	due(time.Now(), 1)
	if count() != 2 {
		t.Fatal("missing threshold checkpoint")
	}
	// A timeline epoch must not count as an entry or reset the baseline.
	exec(t, owner, `UPDATE omp_audit.state SET timeline=timeline+1`)
	if _, err := s.Batch(ctx); err != nil {
		t.Fatal(err)
	}
	due(time.Now().Add(time.Hour), 1)
	if count() != 2 {
		t.Fatal("promotion epoch counted as entry")
	}
	// An approved gap/rebase cannot count as entries.
	if err := (Sealer{Pool: owner}).Rebase(ctx, func() *int64 {
		var n int64
		if err := p.QueryRow(ctx, `SELECT last_seq+50 FROM omp_audit.state`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return &n
	}()); err != nil {
		t.Fatal(err)
	}
	due(time.Now().Add(time.Hour), 1)
	if count() != 2 {
		t.Fatal("epoch counted as entry")
	}
}

func TestCheckpointResignsStaleSnapshot(t *testing.T) {
	p, _ := testutil.NewDB(t)
	owner := testutil.OwnerPool(t, p)
	box, _ := secrets.New(bytes.Repeat([]byte{9}, 32))
	exec(t, owner, `SELECT omp_audit_ext.enable_checkpoints('0.15.0')`)
	if _, err := EnsureCheckpointKey(ctx, p, box); err != nil {
		t.Fatal(err)
	}
	calls := 0
	seq, err := submitCheckpointWithHook(ctx, p, box, func() {
		calls++
		if calls == 1 {
			if _, err := SubmitCheckpoint(ctx, p, box); err != nil {
				t.Fatal(err)
			}
		}
	})
	if err != nil || calls != 2 {
		t.Fatalf("re-sign calls=%d seq=%d err=%v", calls, seq, err)
	}
	tx, err := p.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	e, err := Read(ctx, tx, seq, true)
	if err != nil {
		t.Fatal(err)
	}
	_, authorities, err := CheckpointKeys(ctx, tx)
	if err != nil {
		t.Fatal(err)
	}
	var previous []byte
	if err := tx.QueryRow(ctx, `SELECT chain_hash FROM omp_audit.chain WHERE seq=$1`, seq-1).Scan(&previous); err != nil {
		t.Fatal(err)
	}
	if err := VerifyCheckpoint(e, *e.Checkpoint, [32]byte(previous), authorities); err != nil {
		t.Fatal(err)
	}
}
