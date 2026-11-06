package auditstream

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/ncecere/open-mcp-portal/internal/secrets"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

func checkpointDBFixture(t *testing.T, p *pgxpool.Pool, kids ...CheckpointKID) (CheckpointStatement, map[string]any) {
	t.Helper()
	var s CheckpointStatement
	var hash []byte
	if err := p.QueryRow(ctx, `SELECT stream_id,epoch,last_seq,last_chain_hash FROM omp_audit.state`).Scan(&s.Stream, &s.Epoch, &s.CoveredSeq, &hash); err != nil {
		t.Fatal(err)
	}
	s.Seq = s.CoveredSeq + 1
	copy(s.CoveredHash[:], hash)
	s.IssuedAtMicros = time.Now().UnixMicro()
	s.Kids = kids
	return s, nil
}
func checkpointSubmission(t *testing.T, s CheckpointStatement, keys ...ed25519.PrivateKey) map[string]any {
	t.Helper()
	raw, sigs, err := SignCheckpoint(s, keys...)
	if err != nil {
		t.Fatal(err)
	}
	sh, err := CheckpointSummaryHash(raw, sigs)
	if err != nil {
		t.Fatal(err)
	}
	ch := sha256.Sum256(append(append([]byte("OMP-AUDIT-EVIDENCE\x00CHAIN\x00V2\x00"), s.CoveredHash[:]...), CheckpointRecordBytes(s, sh)...))
	return map[string]any{"kind": "checkpoint", "seq": s.Seq, "flags": 0, "entry_hash": hex.EncodeToString(make([]byte, 32)), "summary_hash": hex.EncodeToString(sh[:]), "chain_hash": hex.EncodeToString(ch[:]), "checkpoint_statement": hex.EncodeToString(raw), "checkpoint_signatures": hex.EncodeToString(sigs)}
}
func submitCheckpoint(p *pgxpool.Pool, r map[string]any) error {
	b, _ := json.Marshal([]any{r})
	_, err := p.Exec(ctx, `SELECT omp_audit.seal_batch('checkpoint',$1::jsonb)`, b)
	return err
}
func TestCheckpointDatabaseValidation(t *testing.T) {
	p, _ := testutil.NewDB(t)
	owner := testutil.OwnerPool(t, p)
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	kid := CheckpointKeyID(pub)
	exec(t, p, `SELECT omp_audit_ext.ensure_checkpoint_key($1,$2,$3)`, kid[:], []byte(pub), []byte{1})
	s, _ := checkpointDBFixture(t, p, kid)
	if err := submitCheckpoint(p, checkpointSubmission(t, s, key)); err == nil {
		t.Fatal("disabled checkpoint accepted")
	}
	pub2, key2, _ := ed25519.GenerateKey(rand.Reader)
	kid2 := CheckpointKeyID(pub2)
	handover := s
	handover.Kids = []CheckpointKID{kid, kid2}
	raw, sigs, err := SignCheckpoint(handover, key, key2)
	if err != nil {
		t.Fatal(err)
	}
	_, err = p.Exec(ctx, `SELECT omp_audit_ext.rotate_checkpoint_key($1,$2,$3,$4,$5)`, kid2[:], []byte(pub2), []byte{2}, raw, sigs)
	var pg *pgconn.PgError
	if !errors.As(err, &pg) || pg.Code != "40001" {
		t.Fatalf("disabled rotation must hit enable fence: %v", err)
	}
	drain(t, p)
	exec(t, owner, `SELECT omp_audit_ext.enable_checkpoints('0.15.0')`)
	for _, name := range []string{"seq", "covered_seq", "hash", "stream", "epoch", "inactive", "handover", "signature_length", "summary", "chain", "flags", "identity", "incarnation", "pending", "rebasing"} {
		t.Run(name, func(t *testing.T) {
			s, _ := checkpointDBFixture(t, p, kid)
			switch name {
			case "seq":
				s.Seq++
				s.CoveredSeq++
			case "covered_seq": // mutate encoded bytes below; codec correctly refuses invalid binding
			case "hash":
				s.CoveredHash[0] ^= 1
			case "stream":
				s.Stream = uuid.New()
			case "epoch":
				s.Epoch++
			case "inactive":
				s.Kids = []CheckpointKID{CheckpointKeyID(ed25519.PublicKey(make([]byte, 32)))}
			case "handover":
				pub2, key2, _ := ed25519.GenerateKey(rand.Reader)
				s.Kids = append(s.Kids, CheckpointKeyID(pub2))
				r := checkpointSubmission(t, s, key, key2)
				if err := submitCheckpoint(p, r); err == nil {
					t.Fatal("handover accepted")
				}
				return
			}
			if name == "inactive" {
				raw, _ := s.Bytes()
				s.Kids = []CheckpointKID{kid}
				r := checkpointSubmission(t, s, key)
				r["checkpoint_statement"] = hex.EncodeToString(raw)
				if err := submitCheckpoint(p, r); err == nil {
					t.Fatal("inactive accepted")
				}
				return
			}
			r := checkpointSubmission(t, s, key)
			switch name {
			case "covered_seq":
				raw, _ := hex.DecodeString(r["checkpoint_statement"].(string))
				raw[59] ^= 1
				r["checkpoint_statement"] = hex.EncodeToString(raw)
			case "signature_length":
				r["checkpoint_signatures"] = "00"
			case "summary":
				r["summary_hash"] = hex.EncodeToString(make([]byte, 32))
			case "chain":
				r["chain_hash"] = hex.EncodeToString(make([]byte, 32))
			case "flags":
				r["flags"] = 1
			case "identity":
				r["row_uid"] = uuid.New().String()
			case "incarnation":
				exec(t, owner, `UPDATE omp_audit.state SET system_identifier='stale'`)
				defer exec(t, owner, `UPDATE omp_audit.state SET system_identifier=(pg_control_system()).system_identifier::text`)
			case "pending":
				exec(t, owner, `UPDATE omp_audit.state SET epoch_pending='{}'`)
				defer exec(t, owner, `UPDATE omp_audit.state SET epoch_pending=NULL`)
			case "rebasing":
				exec(t, owner, `UPDATE omp_audit.state SET status='rebasing'`)
				defer exec(t, owner, `UPDATE omp_audit.state SET status='running'`)
			}
			if err := submitCheckpoint(p, r); err == nil {
				t.Fatal("invalid checkpoint accepted")
			}
		})
	}
	exec(t, p, insert)
	drain(t, p)
	if n := count(t, p, `SELECT entries_since_checkpoint FROM omp_audit.state`); n != 1 {
		t.Fatalf("entry counter %d", n)
	}
	exec(t, owner, `SELECT omp_audit.prepare_epoch('rebase',(SELECT last_seq+5 FROM omp_audit.state))`)
	exec(t, owner, `SELECT omp_audit.append_epoch(NULL)`)
	if n := count(t, p, `SELECT entries_since_checkpoint FROM omp_audit.state`); n != 1 {
		t.Fatalf("epoch/gap incremented entry counter: %d", n)
	}
	s, _ = checkpointDBFixture(t, p, kid)
	if err := submitCheckpoint(p, checkpointSubmission(t, s, key)); err != nil {
		t.Fatal(err)
	}
	if n := count(t, p, `SELECT entries_since_checkpoint FROM omp_audit.state`); n != 0 {
		t.Fatalf("checkpoint counter %d", n)
	}
}

func TestCheckpointFirstKeyRace(t *testing.T) {
	p, _ := testutil.NewDB(t)
	var wg sync.WaitGroup
	results := make(chan string, 12)
	errs := make(chan error, 12)
	for range 12 {
		wg.Go(func() {
			pub, _, _ := ed25519.GenerateKey(rand.Reader)
			kid := CheckpointKeyID(pub)
			var winner []byte
			err := p.QueryRow(ctx, `SELECT kid FROM omp_audit_ext.ensure_checkpoint_key($1,$2,$3)`, kid[:], []byte(pub), []byte{1}).Scan(&winner)
			if err != nil {
				errs <- err
			} else {
				results <- hex.EncodeToString(winner)
			}
		})
	}
	wg.Wait()
	close(results)
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	var first string
	for w := range results {
		if first != "" && w != first {
			t.Fatal("multiple winners")
		}
		first = w
	}
	if n := count(t, p, `SELECT count(*) FROM omp_audit_ext.checkpoint_keys`); n != 1 {
		t.Fatalf("keys %d", n)
	}
}

func TestCheckpointSQLSharedVectors(t *testing.T) {
	data, err := os.ReadFile("testdata/checkpoint_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []struct {
		Statement, Signatures, Summary, Record, Chain string
		PublicKeys                                    []string `json:"public_keys"`
	}
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	for i, v := range vectors {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			p, _ := testutil.NewDB(t)
			owner := testutil.OwnerPool(t, p)
			raw, _ := hex.DecodeString(v.Statement)
			s, err := ParseCheckpointStatement(raw)
			if err != nil {
				t.Fatal(err)
			}
			pub, _ := hex.DecodeString(v.PublicKeys[0])
			exec(t, p, `SELECT omp_audit_ext.ensure_checkpoint_key($1,$2,$3)`, s.Kids[0][:], pub, []byte{1})
			exec(t, owner, `UPDATE omp_audit.state SET stream_id=$1,epoch=$2,last_seq=$3,last_chain_hash=$4`, s.Stream, s.Epoch, s.CoveredSeq, s.CoveredHash[:])
			exec(t, owner, `SELECT omp_audit_ext.enable_checkpoints('0.15.0')`)
			if len(s.Kids) == 1 {
				r := map[string]any{"kind": "checkpoint", "seq": s.Seq, "flags": 0, "entry_hash": hex.EncodeToString(make([]byte, 32)), "summary_hash": v.Summary, "chain_hash": v.Chain, "checkpoint_statement": v.Statement, "checkpoint_signatures": v.Signatures}
				if err := submitCheckpoint(p, r); err != nil {
					t.Fatal(err)
				}
			} else {
				pub2, _ := hex.DecodeString(v.PublicKeys[1])
				sigs, _ := hex.DecodeString(v.Signatures)
				// A complete handover rolled back before commit must leave the old key and tip.
				tx, err := p.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := tx.Exec(ctx, `SELECT omp_audit_ext.rotate_checkpoint_key($1,$2,$3,$4,$5)`, s.Kids[1][:], pub2, []byte{2}, raw, sigs); err != nil {
					tx.Rollback(ctx)
					t.Fatal(err)
				}
				if err := tx.Rollback(ctx); err != nil {
					t.Fatal(err)
				}
				if n := count(t, p, `SELECT count(*) FROM omp_audit_ext.checkpoint_keys WHERE state='active' AND kid=$1`, s.Kids[0][:]); n != 1 {
					t.Fatal("rollback retired old key")
				}
				exec(t, p, `SELECT omp_audit_ext.rotate_checkpoint_key($1,$2,$3,$4,$5)`, s.Kids[1][:], pub2, []byte{2}, raw, sigs)
			}
			var summary, chain string
			if err := p.QueryRow(ctx, `SELECT encode(summary_hash,'hex'),encode(chain_hash,'hex') FROM omp_audit.chain WHERE seq=$1`, s.Seq).Scan(&summary, &chain); err != nil {
				t.Fatal(err)
			}
			if summary != v.Summary || chain != v.Chain {
				t.Fatalf("SQL differs from shared vectors: %s %s", summary, chain)
			}
		})
	}
}

func TestCheckpointHelpersRotationProgress(t *testing.T) {
	p, _ := testutil.NewDB(t)
	owner := testutil.OwnerPool(t, p)
	box, err := secrets.New(bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Go(func() { _, err := EnsureCheckpointKey(ctx, p, box); errs <- err })
	}
	wg.Wait()
	for range 8 {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	exec(t, owner, `SELECT omp_audit_ext.enable_checkpoints('0.15.0')`)
	if _, err := SubmitCheckpoint(ctx, p, box); err != nil {
		t.Fatal(err)
	}
	// Concurrent submissions must rebuild signed statements after a stale tip.
	for range 4 {
		wg.Go(func() { _, err := SubmitCheckpoint(ctx, p, box); errs <- err })
	}
	wg.Wait()
	for range 4 {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	var old []byte
	if err := p.QueryRow(ctx, `SELECT kid FROM omp_audit_ext.checkpoint_keys WHERE state='active'`).Scan(&old); err != nil {
		t.Fatal(err)
	}
	tx, err := p.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := RotateCheckpointKeyTx(ctx, tx, box); err != nil {
		tx.Rollback(ctx)
		t.Fatal(err)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if n := count(t, p, `SELECT count(*) FROM omp_audit_ext.checkpoint_keys WHERE kid=$1 AND state='active'`, old); n != 1 {
		t.Fatal("aborted rotation lost active key")
	}
	c, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		for c.Err() == nil {
			if _, err := (Sealer{p}).Batch(c); err != nil && c.Err() == nil {
				var pg *pgconn.PgError
				if errors.As(err, &pg) && pg.Code == "P0001" && pg.Message == "invalid record" {
					continue
				}
				done <- err
				return
			}
		}
		done <- nil
	}()
	for range 3 {
		exec(t, p, insert)
		if _, err := RotateCheckpointKey(c, p, box); err != nil {
			cancel()
			<-done
			t.Fatal(err)
		}
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if n := count(t, p, `SELECT count(*) FROM omp_audit_ext.checkpoint_keys WHERE state='retired' AND private_key_cipher IS NULL`); n != 3 {
		t.Fatalf("retired keys %d", n)
	}
}
