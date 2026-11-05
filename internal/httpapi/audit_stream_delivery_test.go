package httpapi_test

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/ncecere/open-mcp-portal/internal/auditstream"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
	"strings"
	"testing"
	"time"
)

func TestAuditPullDelivery(t *testing.T) {
	app := newTestApp(t, nil)
	admin := app.signIn("admin")
	if code, body := admin.raw("GET", "/v1/admin/audit/verify", nil, nil); code != 200 {
		t.Fatalf("empty verify: %d %s", code, body)
	}
	deadline := time.Now().Add(2 * time.Minute)
	for {
		if _, err := (auditstream.Sealer{Pool: app.Pool}).Batch(context.Background()); err != nil {
			t.Fatal(err)
		}
		var unsealed int
		if err := app.Pool.QueryRow(context.Background(), `SELECT count(*) FROM public.audit_log a WHERE NOT EXISTS(SELECT 1 FROM omp_audit.chain c WHERE c.row_uid=a.row_uid OR c.legacy_id=a.id AND a.txid IS NULL)`).Scan(&unsealed); err != nil {
			t.Fatal(err)
		}
		if unsealed == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("watermark blocked")
		}
		time.Sleep(10 * time.Millisecond)
	}
	code, body := admin.raw("GET", "/v1/admin/audit/stream?limit=100&profile=full", nil, nil)
	if code != 200 {
		t.Fatalf("%d %s", code, body)
	}
	lines := strings.Split(strings.TrimSpace(string(body)), "\n")
	var last int64
	for _, line := range lines {
		var e auditstream.Envelope
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatal(err)
		}
		if e.Seq != last+1 || e.Full == nil {
			t.Fatalf("bad envelope %+v", e)
		}
		last = e.Seq
	}
	code, body = admin.raw("GET", "/v1/admin/audit/entries/1/full", nil, nil)
	if code != 200 || !json.Valid(body) {
		t.Fatalf("full: %d %s", code, body)
	}
	o := testutil.OwnerPool(t, app.Pool)
	tx, err := o.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	if _, err = tx.Exec(context.Background(), `SELECT set_config('omp.audit_purge','on',true)`); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(context.Background(), `DELETE FROM public.audit_log WHERE id=(SELECT audit_id FROM omp_audit.chain WHERE seq=2)`); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(context.Background()); err != nil {
		t.Fatal(err)
	}
	code, body = admin.raw("GET", "/v1/admin/audit/stream", nil, nil)
	if code != 500 || !strings.Contains(string(body), "audit_row_missing") {
		t.Fatalf("interior expiry: %d %s", code, body)
	}
}

func TestAuditOversizedFetchAndAck(t *testing.T) {
	app := newTestApp(t, nil)
	admin := app.signIn("admin")
	ctx := context.Background()
	if _, err := app.Pool.Exec(ctx, `INSERT INTO public.audit_log(actor_kind,action,target_type,metadata) VALUES('system','test','test',jsonb_build_object('large',repeat('x',17*1024*1024)))`); err != nil {
		t.Fatal(err)
	}
	var id int64
	if err := app.Pool.QueryRow(ctx, `SELECT max(id) FROM public.audit_log`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Minute)
	var seq int64
	for {
		if _, err := (auditstream.Sealer{Pool: app.Pool}).Batch(ctx); err != nil {
			t.Fatal(err)
		}
		if err := app.Pool.QueryRow(ctx, `SELECT coalesce(max(seq),0) FROM omp_audit.chain WHERE audit_id=$1`, id).Scan(&seq); err != nil {
			t.Fatal(err)
		}
		if seq > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("watermark blocked")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := app.Pool.Exec(ctx, `SELECT omp_audit.register_consumer('http-full','full',true,$1)`, admin.me.User.Id); err != nil {
		t.Fatal(err)
	}
	ack := map[string]any{"consumer": "http-full", "seq": seq}
	code, body := admin.raw("POST", "/v1/admin/audit/stream/ack", ack, nil)
	var pending struct {
		Error struct {
			Code    string `json:"code"`
			Details struct {
				Seqs []int64 `json:"seqs"`
			} `json:"details"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &pending); err != nil {
		t.Fatal(err)
	}
	if code != 409 || pending.Error.Code != "oversized_pending" || len(pending.Error.Details.Seqs) != 1 || pending.Error.Details.Seqs[0] != seq {
		t.Fatalf("pending: %d %s", code, body)
	}
	code, body = admin.raw("GET", fmt.Sprintf("/v1/admin/audit/stream?after_seq=%d&limit=1&profile=full", seq-1), nil, nil)
	var envelope auditstream.Envelope
	if err := json.Unmarshal(body, &envelope); err != nil {
		t.Fatal(err)
	}
	if code != 200 || !envelope.Oversized || envelope.Full != nil || len(body) > 16<<20 {
		t.Fatalf("bad oversized envelope: status %d length %d", code, len(body))
	}
	code, body = admin.raw("GET", envelope.Reference+"?consumer=http-full", nil, nil)
	if code != 200 || !json.Valid(body) || len(body) != envelope.FullLength {
		t.Fatalf("full fetch status=%d actual=%d advertised=%d", code, len(body), envelope.FullLength)
	}
	code, body = admin.raw("POST", "/v1/admin/audit/stream/ack", ack, nil)
	if code != 200 {
		t.Fatalf("ack after fetch: %d %s", code, body)
	}
}

func TestAuditVerifyDeclaredGapMarker(t *testing.T) {
	app := newTestApp(t, nil)
	admin := app.signIn("admin")
	ctx := context.Background()
	owner := testutil.OwnerPool(t, app.Pool)
	resume := int64(100)
	if err := (auditstream.Sealer{Pool: owner}).Rebase(ctx, &resume); err != nil {
		t.Fatal(err)
	}
	var result struct {
		Valid bool `json:"valid"`
	}
	code, ec := admin.call("GET", "/v1/admin/audit/verify?from=101&to=101", nil, &result, nil)
	if code != 200 || !result.Valid {
		t.Fatalf("gap marker verify: %d %s %+v", code, ec, result)
	}
}
