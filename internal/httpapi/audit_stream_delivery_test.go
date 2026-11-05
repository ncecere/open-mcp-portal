package httpapi_test

import (
	"context"
	"encoding/json"
	"github.com/ncecere/open-mcp-portal/internal/auditstream"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
	"strings"
	"testing"
	"time"
)

func TestAuditPullDelivery(t *testing.T) {
	app := newTestApp(t, nil)
	admin := app.signIn("admin")
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
