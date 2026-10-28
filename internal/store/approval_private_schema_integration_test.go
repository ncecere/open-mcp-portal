package store_test

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/ncecere/open-mcp-portal/internal/store"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
	"github.com/ncecere/open-mcp-portal/migrations"
)

func TestApprovalPrivateRelocationPreservesLiveState(t *testing.T) {
	t.Setenv("OMP_TEST_SPLIT_ROLES", "1")
	ctx := context.Background()
	var epoch int64
	cipher := bytes.Repeat([]byte{0x42}, 69)
	runtime, _ := testutil.NewDBWithMigration(t, func(ctx context.Context, owner *pgxpool.Pool, role string) error {
		db := stdlib.OpenDBFromPool(owner)
		defer db.Close()
		p, err := goose.NewProvider(goose.DialectPostgres, db, migrations.FS)
		if err != nil {
			return err
		}
		if _, err = p.UpTo(ctx, 41); err != nil {
			return err
		}
		if _, err = owner.Exec(ctx, `SELECT public.omp_ensure_approval_binding_key($1)`, cipher); err != nil {
			return err
		}
		if err = owner.QueryRow(ctx, `SELECT public.omp_current_approval_context()`).Scan(&epoch); err != nil {
			return err
		}
		return store.Migrate(ctx, owner, testutil.Logger(), role)
	})
	if got := approvalEpoch(t, runtime); got != epoch {
		t.Fatalf("relocation changed visible epoch: %d -> %d", epoch, got)
	}
	var got []byte
	if err := runtime.QueryRow(ctx, `SELECT binding_key_cipher FROM omp_private.approval_binding_keys WHERE id=1`).Scan(&got); err != nil || !bytes.Equal(got, cipher) {
		t.Fatal("relocation changed binding root", err)
	}
	if n := roleCount(t, runtime, `SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname IN ('approval_context','approval_context_events','approval_binding_keys','approval_context_events_event_id_seq')`); n != 0 {
		t.Fatal("public protected objects remain")
	}
	if n := roleCount(t, runtime, `SELECT count(*) FROM pg_depend d WHERE d.objid='omp_private.approval_context_events_event_id_seq'::regclass AND d.refobjid='omp_private.approval_context_events'::regclass AND d.deptype='a'`); n != 1 {
		t.Fatal("event sequence ownership lost")
	}
	roleExec(t, runtime, `INSERT INTO teams(slug,name) VALUES('old-update','Old update')`)
	before := approvalEpoch(t, runtime)
	// This ordinary UPDATE is also emitted by the previous release: triggers,
	// not a new serving-code hook, append the relocated protected journal.
	roleExec(t, runtime, `UPDATE teams SET status='archived' WHERE slug='old-update'`)
	if approvalEpoch(t, runtime) <= before {
		t.Fatal("ordinary authority writer missed private journal")
	}
	tx := approvalBegin(t, ctx, runtime)
	if _, err := dbgen.New(tx).LockApprovalContext(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestApprovalPrivateUnsafeACLsRejected(t *testing.T) {
	cases := []struct{ name, grant string }{
		{"schema PUBLIC create", "GRANT CREATE ON SCHEMA omp_private TO PUBLIC"},
		{"helper PUBLIC execute", "GRANT EXECUTE ON FUNCTION omp_private.omp_current_approval_context() TO PUBLIC"},
		{"trigger PUBLIC execute", "GRANT EXECUTE ON FUNCTION omp_private.approval_authority_changed() TO PUBLIC"},
		{"sequence PUBLIC usage", "GRANT USAGE ON SEQUENCE omp_private.approval_context_events_event_id_seq TO PUBLIC"},
		{"context PUBLIC update", "GRANT UPDATE ON omp_private.approval_context TO PUBLIC"},
		{"root PUBLIC delete", "GRANT DELETE ON omp_private.approval_binding_keys TO PUBLIC"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			runtime, owner, role := splitFixture(t)
			roleExec(t, owner, c.grant)
			s, err := store.InspectRoles(context.Background(), runtime, "", true)
			if err != nil || s.Safe() {
				t.Fatalf("unsafe private ACL accepted: %+v %v", s, err)
			}
			if err := store.Migrate(context.Background(), owner, testutil.Logger(), role); err == nil {
				t.Fatal("reconciliation accepted PUBLIC hazard")
			}
		})
	}
	for _, kind := range []string{"schema", "table", "function", "membership"} {
		t.Run(kind, func(t *testing.T) {
			runtime, owner, role := splitFixture(t)
			aux := "private_aux_" + role
			auxiliaryRole(t, owner, aux)
			cfg := owner.Config().ConnConfig.Copy()
			root, _ := pgx.ParseConfig(testutil.DatabaseURL())
			cfg.User, cfg.Password = root.User, root.Password
			admin, err := pgx.ConnectConfig(context.Background(), cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer admin.Close(context.Background())
			switch kind {
			case "schema":
				roleExec(t, admin, "ALTER SCHEMA omp_private OWNER TO "+pgx.Identifier{aux}.Sanitize())
			case "table":
				roleExec(t, admin, "ALTER TABLE omp_private.approval_binding_keys OWNER TO "+pgx.Identifier{aux}.Sanitize())
			case "function":
				roleExec(t, admin, "ALTER FUNCTION omp_private.approval_context_monotonic() OWNER TO "+pgx.Identifier{aux}.Sanitize())
			case "membership":
				roleExec(t, owner, "GRANT DELETE ON omp_private.approval_binding_keys TO "+pgx.Identifier{aux}.Sanitize())
				roleExec(t, admin, "GRANT "+pgx.Identifier{aux}.Sanitize()+" TO "+pgx.Identifier{role}.Sanitize())
			}
			s, err := store.InspectRoles(context.Background(), runtime, "", true)
			if err != nil || s.Safe() {
				t.Errorf("unsafe private boundary accepted: %+v %v", s, err)
			}
			if err := store.Migrate(context.Background(), owner, testutil.Logger(), role); err == nil {
				t.Error("unsafe private boundary accepted by reconciliation")
			}
			roleExec(t, admin, "REASSIGN OWNED BY "+pgx.Identifier{aux}.Sanitize()+" TO "+pgx.Identifier{owner.Config().ConnConfig.User}.Sanitize())
		})
	}
}

// Opt-in executable proof: build the untouched v0.4.0 tag in a scratch
// worktree, set OMP_TEST_V040_BINARY to that binary, and require PostgreSQL.
func TestApprovalPrivatePreviousReleaseStrictStartup(t *testing.T) {
	binary := os.Getenv("OMP_TEST_V040_BINARY")
	if binary == "" {
		t.Skip("set OMP_TEST_V040_BINARY to an unmodified v0.4.0 executable")
	}
	runtime, _, _ := splitFixture(t)
	if n := roleCount(t, runtime, `SELECT count(*) FROM approval_rules WHERE enabled`); n != 0 {
		t.Fatal("compatibility fixture must not enable approval enforcement")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "serve")
	// Do not inherit developer config, owner URLs, encryption keys or ports.
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + t.TempDir(), "LISTEN_ADDR=" + addr, "APP_URL=http://" + addr,
		"DATABASE_URL=" + runtime.Config().ConnString(), "MIGRATE_ON_START=false", "DB_REQUIRE_SPLIT_ROLES=true", "DEV_AUTH=true",
		"ENCRYPTION_KEY=94cwGQfaKGZdfF4A04/lGwT/LMSckeFIpgC3FO3lnm8=", "API_KEY_PEPPER=8gqQZFiYFPRaAwu73Ub9+AF0PVc3ZX6rEPR2CcFymgY="}
	cmd.Dir = t.TempDir()
	var logs bytes.Buffer
	cmd.Stdout = &logs
	cmd.Stderr = &logs
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	defer func() { cancel(); <-done }()
	client := http.Client{Timeout: time.Second}
	tick := time.NewTicker(25 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case err := <-done:
			done <- err
			t.Fatalf("released binary exited before ready: %v\n%s", err, logs.String())
		case <-ctx.Done():
			t.Fatal("released binary never ready")
		case <-tick.C:
			resp, err := client.Get("http://" + addr + "/readyz")
			if err != nil {
				continue
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				// Reconcile not run by the old process; the unchanged strict inspector
				// genuinely accepted current grants before its HTTP server was started.
				roleExec(t, runtime, `INSERT INTO teams(slug,name) VALUES('released-writer','Released writer')`)
				before := approvalEpoch(t, runtime)
				roleExec(t, runtime, `UPDATE teams SET status='archived' WHERE slug='released-writer'`)
				if approvalEpoch(t, runtime) <= before {
					t.Fatal("old-style authority mutation did not journal")
				}
				t.Log("unmodified v0.4.0 strict split-role startup and HTTP readiness passed")
				return
			}
			if strings.Contains(resp.Status, "500") {
				continue
			}
		}
	}
}
