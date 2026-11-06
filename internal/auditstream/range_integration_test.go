package auditstream

import (
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
)

func TestRangeSnapshotCases(t *testing.T) {
	p, owner, id := sinkFixture(t, true)
	exec(t, p, insert)
	drain(t, p)
	resume := int64(20)
	if err := (Sealer{Pool: owner}).Rebase(ctx, &resume); err != nil {
		t.Fatal(err)
	}
	var last int64
	if err := p.QueryRow(ctx, `SELECT last_seq FROM omp_audit.state WHERE singleton`).Scan(&last); err != nil {
		t.Fatal(err)
	}
	for _, endpoint := range []int64{0, last} {
		tx, err := p.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
		if err != nil {
			t.Fatal(err)
		}
		batch, err := ReadRange(ctx, tx, 0, 1000, true, endpoint)
		_ = tx.Rollback(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(batch.Envelopes) < 2 || batch.Envelopes[1].Seq != 21 {
			t.Fatalf("declared gap not delivered: %+v", batch.Envelopes)
		}
	}
	exec(t, owner, `SELECT omp_audit_ext.set_sinks_enabled(true,'0.15.0')`)
	_ = sinkBegin(t, p, id, 1, 0, "data", 1, last)
	// Owner-only damage: no missing sequence may be silently accepted.
	exec(t, owner, `ALTER TABLE omp_audit.chain DISABLE TRIGGER USER`)
	exec(t, owner, `DELETE FROM omp_audit.chain WHERE seq=21`)
	exec(t, owner, `ALTER TABLE omp_audit.chain ENABLE TRIGGER USER`)
	tx, err := p.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		t.Fatal(err)
	}
	_, err = ReadRange(ctx, tx, 0, 1000, true, 0)
	_ = tx.Rollback(ctx)
	if !errors.Is(err, ErrIntegrity) {
		t.Fatalf("hole accepted: %v", err)
	}
}

func TestRangePurgeBeforeBegin(t *testing.T) {
	p, owner, id := sinkFixture(t, false)
	exec(t, p, `INSERT INTO public.audit_log(actor_kind,action,target_type,occurred_at) VALUES('system','old','test',now()-interval '4000 days')`)
	drain(t, p)
	tx, err := p.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		t.Fatal(err)
	}
	batch, err := ReadRange(ctx, tx, 0, 100, true, 0)
	if err != nil {
		t.Fatal(err)
	}
	exec(t, p, `SELECT public.omp_purge_audit_log(30,100)`)
	_ = tx.Rollback(ctx)
	exec(t, owner, `SELECT omp_audit_ext.set_sinks_enabled(true,'0.15.0')`)
	sinkReject(t, p, `SELECT omp_audit_ext.begin_attempt($1,1,0,'data',1,$2)`, id, batch.Envelopes[len(batch.Envelopes)-1].Seq)
}
