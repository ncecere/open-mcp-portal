package auditstream

import (
	"context"
	"net"
	"os"
	osexec "os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/ncecere/open-mcp-portal/internal/notify"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

// Use an unchanged executable, not a reimplementation of fanOutNext. Older
// dispatchers consume unknown events without creating any recipient deliveries.
func TestOldDispatcherDropsSinkEvents(t *testing.T) {
	if os.Getenv("OMP_TEST_PREVIOUS_BINARY") == "" && os.Getenv("OMP_TEST_2A_BINARY") == "" {
		t.Skip("set OMP_TEST_PREVIOUS_BINARY and OMP_TEST_2A_BINARY to real old executables")
	}
	for _, binary := range []string{os.Getenv("OMP_TEST_PREVIOUS_BINARY"), os.Getenv("OMP_TEST_2A_BINARY")} {
		if binary == "" {
			continue
		}
		t.Run(filepath.Base(filepath.Dir(binary)), func(t *testing.T) {
			p, _ := testutil.NewDB(t)
			owner := testutil.OwnerPool(t, p)
			if _, e := owner.Exec(ctx, `SELECT omp_audit_ext.set_sinks_enabled(true,'0.15.0')`); e != nil {
				t.Fatal(e)
			}
			_, err := notify.InsertStrict(ctx, dbgen.New(p), notify.Event{Type: notify.AuditSinkFailing, DedupKey: "old-dispatcher-hazard", SubjectType: "audit_sink", SubjectID: "fixture", Data: map[string]string{"sink_id": "fixture"}})
			if err != nil {
				t.Fatal(err)
			}
			execSQL := func(sql string) {
				if _, e := p.Exec(ctx, sql); e != nil {
					t.Fatal(e)
				}
			}
			execSQL(`INSERT INTO users(oidc_issuer,oidc_subject,email,display_name,platform_role) VALUES('fixture','sink-admin','sink-admin@example.com','Sink admin','platform_admin')`)
			listener, e := net.Listen("tcp", "127.0.0.1:0")
			if e != nil {
				t.Fatal(e)
			}
			addr := listener.Addr().String()
			listener.Close()
			c, cancel := context.WithTimeout(ctx, 25*time.Second)
			defer cancel()
			cmd := osexec.CommandContext(c, binary, "serve")
			cmd.Env = append(os.Environ(), "DATABASE_URL="+p.Config().ConnString(), "DATABASE_MIGRATE_URL="+owner.Config().ConnString(), "DB_RUNTIME_ROLE="+p.Config().ConnConfig.User, "DB_REQUIRE_SPLIT_ROLES=false", "APP_URL=http://"+addr, "LISTEN_ADDR="+addr, "DEV_AUTH=true", "MIGRATE_ON_START=false", "ENCRYPTION_KEY=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "API_KEY_PEPPER=BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=", "AUDIT_STREAM_ENABLED=false")
			log, e := os.CreateTemp(t.TempDir(), "dispatcher-*.log")
			if e != nil {
				t.Fatal(e)
			}
			defer log.Close()
			cmd.Stdout = log
			cmd.Stderr = log
			if e = cmd.Start(); e != nil {
				t.Fatal(e)
			}
			defer func() { cancel(); _ = cmd.Wait() }()
			for deadline := time.Now().Add(20 * time.Second); ; {
				if count(t, p, `SELECT count(*) FROM notification_events WHERE dedup_key='old-dispatcher-hazard' AND fanned_out_at IS NOT NULL`) == 1 {
					break
				}
				if time.Now().After(deadline) {
					b, _ := os.ReadFile(log.Name())
					t.Fatalf("old dispatcher did not fan out: %s", b)
				}
				time.Sleep(25 * time.Millisecond)
			}
			if count(t, p, `SELECT count(*) FROM notification_inbox`) != 0 || count(t, p, `SELECT count(*) FROM notification_outbox`) != 0 {
				t.Fatal("old dispatcher unexpectedly routed sink event")
			}
			t.Log("schema 64: real old dispatcher marked audit.sink_failing fanned-out with zero recipients despite a platform admin")
		})
	}
}
