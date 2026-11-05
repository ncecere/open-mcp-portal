package auditstream

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	osexec "os/exec"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/ncecere/open-mcp-portal/internal/store"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
	"github.com/ncecere/open-mcp-portal/migrations"
	"github.com/pressly/goose/v3"
)

// OMP_TEST_PREVIOUS_BINARY points to the unchanged executable extracted from
// the public previous-release image. No container needs starting or stopping.
func TestPreviousImageCurrentSchemas(t *testing.T) {
	binary := os.Getenv("OMP_TEST_PREVIOUS_BINARY")
	if binary == "" {
		t.Skip("set OMP_TEST_PREVIOUS_BINARY to the previous image executable")
	}
	t.Setenv("OMP_TEST_SPLIT_ROLES", "1")
	for _, version := range []int64{58, 59, 60, 61, 62} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			p, _ := testutil.NewDBWithMigration(t, func(ctx context.Context, owner *pgxpool.Pool, role string) error {
				db := stdlib.OpenDBFromPool(owner)
				defer db.Close()
				provider, err := goose.NewProvider(goose.DialectPostgres, db, migrations.FS)
				if err != nil {
					return err
				}
				if _, err := provider.UpTo(ctx, version); err != nil {
					return err
				}
				conn, err := owner.Acquire(ctx)
				if err != nil {
					return err
				}
				defer conn.Release()
				return store.ReconcileRuntimeGrants(ctx, conn.Conn(), role)
			})
			owner := testutil.OwnerPool(t, p)
			if version == 62 {
				exec(t, p, `INSERT INTO public.audit_log(actor_kind,action,target_type,occurred_at) VALUES('system','old.fixture','fixture',now()-interval '4000 days')`)
			}

			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			addr := listener.Addr().String()
			listener.Close()
			env := append(os.Environ(), "DATABASE_URL="+p.Config().ConnString(), "DATABASE_MIGRATE_URL="+owner.Config().ConnString(), "DB_RUNTIME_ROLE="+p.Config().ConnConfig.User, "DB_REQUIRE_SPLIT_ROLES=true", "APP_URL=http://"+addr, "LISTEN_ADDR="+addr, "DEV_AUTH=true", "MIGRATE_ON_START=false", "ENCRYPTION_KEY=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "API_KEY_PEPPER=BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=", "AUDIT_STREAM_ENABLED=false")
			cmd := osexec.Command(binary, "migrate")
			cmd.Env = env
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("previous migrate/reconcile: %v %s", err, out)
			}
			c, cancel := context.WithTimeout(ctx, 15*time.Second)
			defer cancel()
			cmd = osexec.CommandContext(c, binary, "serve")
			cmd.Env = env
			var output bytes.Buffer
			cmd.Stdout = &output
			cmd.Stderr = &output
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			client := &http.Client{Timeout: time.Second}
			signedIn := false
			for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); {
				response, err := client.Post("http://"+addr+"/auth/dev", "application/json", strings.NewReader(`{"account":"admin"}`))
				if err == nil {
					body, _ := io.ReadAll(response.Body)
					response.Body.Close()
					if response.StatusCode != 200 {
						cancel()
						_ = cmd.Wait()
						t.Fatalf("old writer login: %d %s %s", response.StatusCode, body, output.String())
					}
					signedIn = true
					break
				}
				time.Sleep(50 * time.Millisecond)
			}
			if version == 62 && signedIn {
				deadline := time.Now().Add(5 * time.Second)
				for count(t, p, `SELECT count(*) FROM public.retention_settings WHERE last_run IS NOT NULL`) == 0 && time.Now().Before(deadline) {
					time.Sleep(20 * time.Millisecond)
				}
				if count(t, p, `SELECT count(*) FROM public.retention_settings WHERE last_run IS NOT NULL AND coalesce(last_run->'errors','{}')='{}'::jsonb`) == 0 {
					cancel()
					_ = cmd.Wait()
					t.Fatal("previous retention loop did not complete successfully")
				}
				if count(t, p, `SELECT count(*) FROM public.audit_log WHERE action='old.fixture'`) != 1 {
					cancel()
					_ = cmd.Wait()
					t.Fatal("previous retention loop bypassed sealed-only interlock")
				}
			}

			cancel()
			_ = cmd.Wait()
			if !signedIn || !strings.Contains(output.String(), "http listening") {
				t.Fatalf("previous startup: %s", output.String())
			}
			if count(t, p, `SELECT count(*) FROM public.audit_log WHERE action='auth.login' AND txid IS NOT NULL AND row_uid IS NOT NULL`) == 0 {
				t.Fatal("previous executable did not write a stamped auth.login")
			}

			// Historical startup remains verified above. Upgrade to the current
			// boundary before asking the current sealer to use recovery modes.
			db := stdlib.OpenDBFromPool(owner)
			provider, err := goose.NewProvider(goose.DialectPostgres, db, migrations.FS)
			if err != nil {
				db.Close()
				t.Fatal(err)
			}
			_, err = provider.Up(ctx)
			db.Close()
			if err != nil {
				t.Fatal(err)
			}
			drain(t, p)
		})
	}
}
