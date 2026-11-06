package auditstream

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"github.com/ncecere/open-mcp-portal/internal/keyrotation"
	"github.com/ncecere/open-mcp-portal/internal/secrets"
	"io"
	"net"
	"net/http"
	"os"
	osexec "os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
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
	for _, version := range []int64{58, 59, 60, 61, 62, 63, 64} {
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
			if version == 64 {
				exec(t, p, createSinkSQL, uuid.New(), true)
				exec(t, p, `INSERT INTO public.audit_log(actor_kind,action,target_type,occurred_at) VALUES('system','sink.cap.fixture','fixture',now()-interval '4000 days')`)
			}
			if version >= 62 {
				// Start the stream (seal at least one row) so the sealed-only interlock is
				// in force; before anything is sealed the purge deliberately deletes by age
				// (TestRetentionBeforeStreamingPurgesByAge). The old fixture stays unsealed:
				// the previous binary's retention loop must not delete it.
				exec(t, p, insert)
				drain(t, p)
				exec(t, p, `INSERT INTO public.audit_log(actor_kind,action,target_type,occurred_at) VALUES('system','old.fixture','fixture',now()-interval '4000 days')`)
			}

			if version >= 63 {
				if count(t, p, `SELECT count(*) FROM omp_audit.state WHERE coalesce(checkpoints_enabled,false) OR min_reader_version IS NOT NULL`) != 0 {
					t.Fatal("previous release fixture must remain pre-enable")
				}
				if version == 63 {
					exec(t, p, `SELECT omp_audit.register_consumer('compat.hold','summary',true,gen_random_uuid())`)
				}
			}
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			addr := listener.Addr().String()
			listener.Close()
			env := append(os.Environ(), "DATABASE_URL="+p.Config().ConnString(), "DATABASE_MIGRATE_URL="+owner.Config().ConnString(), "DB_RUNTIME_ROLE="+p.Config().ConnConfig.User, "DB_REQUIRE_SPLIT_ROLES=true", "APP_URL=http://"+addr, "LISTEN_ADDR="+addr, "DEV_AUTH=true", "MIGRATE_ON_START=false", "ENCRYPTION_KEY=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "API_KEY_PEPPER=BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=", "AUDIT_STREAM_ENABLED=false")
			if version >= 63 {
				env = append(env, "AUDIT_STREAM_ENABLED=true")
			}
			cmd := osexec.Command(binary, "migrate")
			cmd.Env = env
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("previous migrate/reconcile: %v %s", err, out)
			}
			if version >= 63 {
				conn, err := owner.Acquire(ctx)
				if err != nil {
					t.Fatal(err)
				}
				err = store.ReconcileRuntimeGrants(ctx, conn.Conn(), p.Config().ConnConfig.User)
				conn.Release()
				if err != nil {
					t.Fatal(err)
				}
				safe, err := store.InspectRoles(ctx, owner, p.Config().ConnConfig.User, true)
				if err != nil || !safe.Safe() {
					t.Fatalf("new reconcile after old: %v %s", err, safe.Detail())
				}
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
					if version >= 63 {
						// The old executable seals and serves the pre-enable stream.
						deadline := time.Now().Add(8 * time.Second)
						for count(t, p, `SELECT count(*) FROM omp_audit.chain WHERE audit_id IN (SELECT id FROM public.audit_log WHERE action='auth.login')`) == 0 && time.Now().Before(deadline) {
							time.Sleep(25 * time.Millisecond)
						}
						if count(t, p, `SELECT count(*) FROM omp_audit.chain WHERE audit_id IN (SELECT id FROM public.audit_log WHERE action='auth.login')`) == 0 {
							cancel()
							_ = cmd.Wait()
							t.Fatal("old sealer made no progress")
						}
						req, _ := http.NewRequest("GET", "http://"+addr+"/v1/admin/audit/stream?limit=100", nil)
						for _, cookie := range response.Cookies() {
							req.AddCookie(cookie)
						}
						pulled, e := client.Do(req)
						if e != nil {
							cancel()
							_ = cmd.Wait()
							t.Fatal(e)
						}
						content, _ := io.ReadAll(pulled.Body)
						pulled.Body.Close()
						if pulled.StatusCode != 200 || !bytes.Contains(content, []byte(`"kind":"entry"`)) {
							cancel()
							_ = cmd.Wait()
							t.Fatalf("old pull: %d %s", pulled.StatusCode, content)
						}
					}
					signedIn = true
					break
				}
				time.Sleep(50 * time.Millisecond)
			}
			if version >= 62 && signedIn {
				deadline := time.Now().Add(5 * time.Second)
				for count(t, p, `SELECT count(*) FROM public.retention_settings WHERE last_run IS NOT NULL`) == 0 && time.Now().Before(deadline) {
					time.Sleep(20 * time.Millisecond)
				}
				if count(t, p, `SELECT count(*) FROM public.retention_settings WHERE last_run IS NOT NULL AND coalesce(last_run->'errors','{}')='{}'::jsonb`) == 0 {
					cancel()
					_ = cmd.Wait()
					t.Fatal("previous retention loop did not complete successfully")
				}
				if version == 64 && count(t, p, `SELECT count(*) FROM public.audit_log WHERE action='sink.cap.fixture'`) != 1 {
					t.Fatal("old retention bypassed sink cap")
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

// The historical utility succeeds while leaving extension ciphertext untouched.
// Operators must use the current utility before retiring the previous root.
func TestPreviousCheckpointKeyRotationCoverage(t *testing.T) {
	binary := os.Getenv("OMP_TEST_PREVIOUS_BINARY")
	if binary == "" {
		t.Skip("set OMP_TEST_PREVIOUS_BINARY")
	}
	p, _ := testutil.NewDB(t)
	owner := testutil.OwnerPool(t, p)
	old := bytes.Repeat([]byte{5}, 32)
	current := bytes.Repeat([]byte{6}, 32)
	box, err := secrets.New(old)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := EnsureCheckpointKey(ctx, p, box); err != nil {
		t.Fatal(err)
	}
	sinkID := uuid.New()
	var sinkCiphers [][]byte
	for _, part := range []string{"url", "secret", "secret_previous"} {
		cipher, err := box.Seal([]byte("sink fixture"), []byte("audit_sink:"+sinkID.String()+":"+part))
		if err != nil {
			t.Fatal(err)
		}
		sinkCiphers = append(sinkCiphers, cipher)
	}
	exec(t, p, `SELECT omp_audit_ext.create_sink($1,'old-rotation','full',false,true,100,$2,'receiver.example',$3,$4,now()+interval '1 day','hint')`, sinkID, sinkCiphers[0], sinkCiphers[1], sinkCiphers[2])
	var before, after []byte
	if err := p.QueryRow(ctx, `SELECT private_key_cipher FROM omp_audit_ext.checkpoint_keys WHERE state='active'`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	cmd := osexec.Command(binary, "rotate-keys")
	cmd.Env = append(os.Environ(), "APP_URL=http://localhost:18789", "DEV_AUTH=true", "DATABASE_URL="+p.Config().ConnString(), "DATABASE_MIGRATE_URL="+owner.Config().ConnString(), "DB_RUNTIME_ROLE="+p.Config().ConnConfig.User, "DB_REQUIRE_SPLIT_ROLES="+strconv.FormatBool(p.Config().ConnConfig.User != owner.Config().ConnConfig.User), "ENCRYPTION_KEY="+base64.StdEncoding.EncodeToString(current), "ENCRYPTION_KEY_PREVIOUS="+base64.StdEncoding.EncodeToString(old), "API_KEY_PEPPER=BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("old key rotation: %v %s", err, out)
	}
	if err := p.QueryRow(ctx, `SELECT private_key_cipher FROM omp_audit_ext.checkpoint_keys WHERE state='active'`).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("old utility unexpectedly rewrapped extension key")
	}
	for i, part := range []string{"url", "secret", "secret_previous"} {
		var stored []byte
		if err := p.QueryRow(ctx, `SELECT `+part+`_cipher FROM omp_audit_ext.sinks WHERE id=$1`, sinkID).Scan(&stored); err != nil || !bytes.Equal(stored, sinkCiphers[i]) {
			t.Fatalf("old utility changed sink %s: %v", part, err)
		}
	}
	rotating, err := secrets.New(current, old)
	if err != nil {
		t.Fatal(err)
	}
	result, err := keyrotation.Run(ctx, p, rotating, keyrotation.Peppers{}, keyrotation.Options{})
	if err != nil || result.Reencrypted() != 4 {
		t.Fatalf("new utility checkpoint rewrap: %v %+v", err, result)
	}
	fresh, err := secrets.New(current)
	if err != nil {
		t.Fatal(err)
	}
	for _, part := range []string{"url", "secret", "secret_previous"} {
		var stored []byte
		if err := p.QueryRow(ctx, `SELECT `+part+`_cipher FROM omp_audit_ext.sinks WHERE id=$1`, sinkID).Scan(&stored); err != nil {
			t.Fatal(err)
		}
		if _, err := fresh.Open(stored, []byte("audit_sink:"+sinkID.String()+":"+part)); err != nil {
			t.Fatalf("rewrapped sink %s: %v", part, err)
		}
	}
	if _, err := EnsureCheckpointKey(ctx, p, fresh); err != nil {
		t.Fatalf("rewrapped key fails authentication: %v", err)
	}
}
