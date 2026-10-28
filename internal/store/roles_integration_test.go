package store_test

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ncecere/open-mcp-portal/internal/store"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
	"github.com/ncecere/open-mcp-portal/migrations"
)

func roleExec(t *testing.T, db interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}, sql string, args ...any) {
	t.Helper()
	if _, err := db.Exec(context.Background(), sql, args...); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}
func roleCount(t *testing.T, db store.RoleDB, sql string, args ...any) int64 {
	t.Helper()
	var n int64
	if err := db.QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
	return n
}
func roleDenied(t *testing.T, pool *pgxpool.Pool, sql, code string) {
	t.Helper()
	_, err := pool.Exec(context.Background(), sql)
	var pg *pgconn.PgError
	if !errors.As(err, &pg) || pg.Code != code {
		t.Fatalf("%s: wanted %s, got %v", sql, code, err)
	}
}
func splitFixture(t *testing.T) (*pgxpool.Pool, *pgxpool.Pool, string) {
	t.Helper()
	t.Setenv("OMP_TEST_SPLIT_ROLES", "1")
	runtime, _ := testutil.NewDB(t)
	owner := testutil.OwnerPool(t, runtime)
	return runtime, owner, runtime.Config().ConnConfig.User
}

func TestRuntimeAppendOnlyBoundary(t *testing.T) {
	runtime, owner, role := splitFixture(t)
	ctx := context.Background()
	if got := roleCount(t, runtime, `SELECT (session_user=current_user AND current_user=$1)::int`, role); got != 1 {
		t.Fatal("not authenticated as runtime")
	}
	safety, err := store.InspectRoles(ctx, runtime, "", true)
	if err != nil || !safety.Safe() {
		t.Fatalf("%+v %v", safety, err)
	}
	roleExec(t, runtime, `INSERT INTO audit_log(actor_kind,action,target_type) VALUES ('system','fixture','test')`)
	roleExec(t, runtime, `INSERT INTO mcp_calls(method,outcome,gateway_id,gateway_slug,gateway_name,principal_kind,service_account_id)
 VALUES ('tools/list','ok',gen_random_uuid(),'fixture','Fixture','service_account',gen_random_uuid())`)
	for _, table := range []string{"audit_log", "mcp_calls"} {
		col := "action"
		if table == "mcp_calls" {
			col = "method"
		}
		for _, sql := range []string{"UPDATE " + table + " SET " + col + "=" + col, "DELETE FROM " + table, "TRUNCATE " + table} {
			roleDenied(t, runtime, sql, "42501")
		}
	}
	roleDenied(t, runtime, "TRUNCATE teams CASCADE", "42501")
	for _, flag := range []string{"omp.audit_purge", "omg.audit_purge", "omp.calls_purge", "omg.calls_purge"} {
		roleExec(t, runtime, "SELECT set_config($1,'on',false)", flag)
	}
	roleDenied(t, runtime, "DELETE FROM audit_log", "42501")
	// Even an accidental direct DELETE grant and SET ROLE do not bypass triggers.
	roleExec(t, owner, "GRANT UPDATE, DELETE ON public.audit_log, public.mcp_calls TO "+pgx.Identifier{role}.Sanitize())
	roleDenied(t, runtime, "DELETE FROM audit_log", "P0001")
	roleDenied(t, runtime, "DELETE FROM mcp_calls", "P0001")
	roleDenied(t, runtime, "UPDATE audit_log SET action=action", "P0001")
	roleDenied(t, owner, "UPDATE audit_log SET action=action", "P0001")
	root, err := pgx.ParseConfig(testutil.DatabaseURL())
	if err != nil {
		t.Fatal(err)
	}
	cfg := owner.Config().ConnConfig.Copy()
	cfg.User, cfg.Password = root.User, root.Password
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	roleExec(t, conn, "SET ROLE "+pgx.Identifier{role}.Sanitize())
	roleExec(t, conn, "SELECT set_config('omp.audit_purge','on',false)")
	if _, err := conn.Exec(ctx, "DELETE FROM audit_log"); err == nil {
		t.Fatal("SET ROLE bypassed trigger")
	}
	roleExec(t, conn, "SET ROLE "+pgx.Identifier{owner.Config().ConnConfig.User}.Sanitize())
	// Effective-owner previous binary retention, including legacy flag.
	roleExec(t, conn, "SELECT set_config('omg.audit_purge','on',false)")
	roleExec(t, conn, "DELETE FROM audit_log")
	if err := store.Migrate(ctx, owner, testutil.Logger(), role); err != nil {
		t.Fatal(err)
	}
	roleDenied(t, runtime, "DELETE FROM audit_log", "42501")
}

func TestPurgeMigrationRejectsDifferentSuperuserOwner(t *testing.T) {
	_, owner, _ := splitFixture(t)
	ctx := context.Background()
	root, err := pgx.ParseConfig(testutil.DatabaseURL())
	if err != nil {
		t.Fatal(err)
	}
	cfg := owner.Config().ConnConfig.Copy()
	cfg.User, cfg.Password = root.User, root.Password
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	raw, err := migrations.FS.ReadFile("00032_purge_functions.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, string(raw)); err == nil || !strings.Contains(err.Error(), "must be owned by the migration role") {
		t.Fatalf("inconsistent definer ownership accepted: %v", err)
	}
}

func TestRuntimeGrantsReconcile(t *testing.T) {
	runtime, owner, role := splitFixture(t)
	ctx := context.Background()
	quoted := pgx.Identifier{role}.Sanitize()
	roleExec(t, owner, `CREATE TABLE public.new_fixture(id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, value text)`)
	roleExec(t, owner, "GRANT ALL ON audit_log TO "+quoted+" WITH GRANT OPTION")
	roleExec(t, owner, "GRANT UPDATE(action) ON audit_log TO "+quoted+" WITH GRANT OPTION")
	roleExec(t, owner, "GRANT CREATE ON SCHEMA public TO "+quoted)
	roleExec(t, owner, "GRANT UPDATE ON goose_db_version TO "+quoted)
	var wg sync.WaitGroup
	errs := make(chan error, 4)
	for range 4 {
		wg.Go(func() { errs <- store.Migrate(ctx, owner, testutil.Logger(), role) })
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	for range 2 {
		if err := store.Migrate(ctx, owner, testutil.Logger(), role); err != nil {
			t.Fatal(err)
		}
	}
	roleExec(t, runtime, `INSERT INTO new_fixture(value) VALUES ('x')`)
	roleExec(t, runtime, `UPDATE new_fixture SET value='y'`)
	roleExec(t, runtime, `DELETE FROM new_fixture`)
	roleDenied(t, runtime, `TRUNCATE new_fixture`, "42501")
	roleDenied(t, runtime, `UPDATE audit_log SET action=action`, "42501")
	roleDenied(t, runtime, `UPDATE goose_db_version SET version_id=version_id`, "42501")
	roleDenied(t, runtime, `CREATE TABLE forbidden(id int)`, "42501")
	safety, err := store.InspectRoles(ctx, runtime, "", true)
	if err != nil || !safety.Safe() {
		t.Fatalf("%+v %v", safety, err)
	}
}

// auxiliaryRole creates only a uniquely named scratch role. Cleanup removes its
// privileges in this scratch database before dropping that new role.
func auxiliaryRole(t *testing.T, owner *pgxpool.Pool, name string) (*pgxpool.Pool, *pgx.Conn) {
	t.Helper()
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, testutil.DatabaseURL())
	if err != nil {
		t.Fatal(err)
	}
	quoted := pgx.Identifier{name}.Sanitize()
	roleExec(t, admin, "CREATE ROLE "+quoted+" LOGIN NOINHERIT PASSWORD 'scratch-only'")
	u, err := url.Parse(owner.Config().ConnString())
	if err != nil {
		t.Fatal(err)
	}
	u.User = url.UserPassword(name, "scratch-only")
	pool, err := store.Open(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		// A superuser connection to the scratch DB can drop only this role's grants.
		cfg := owner.Config().ConnConfig.Copy()
		root, err := pgx.ParseConfig(testutil.DatabaseURL())
		if err == nil {
			cfg.User, cfg.Password = root.User, root.Password
			c, err := pgx.ConnectConfig(ctx, cfg)
			if err == nil {
				_, _ = c.Exec(ctx, "DROP OWNED BY "+quoted)
				_ = c.Close(ctx)
			}
		}
		if _, err := admin.Exec(ctx, "DROP ROLE "+quoted); err != nil {
			t.Errorf("cleanup scratch role: %v", err)
		}
		_ = admin.Close(ctx)
	})
	return pool, admin
}

func TestRoleQuotingAndPublicExecution(t *testing.T) {
	_, owner, role := splitFixture(t)
	ctx := context.Background()
	strange := `quote " role; -- ` + role
	pool, _ := auxiliaryRole(t, owner, strange)
	if err := store.Migrate(ctx, owner, testutil.Logger(), strange); err != nil {
		t.Fatal(err)
	}
	if roleCount(t, pool, `SELECT count(*) FROM goose_db_version`) == 0 {
		t.Fatal("missing read grant")
	}
	for _, bad := range []string{strings.Repeat("a", 64), "a\x00b", "does_not_exist"} {
		if err := store.Migrate(ctx, owner, testutil.Logger(), bad); err == nil {
			t.Fatalf("accepted role %q", bad)
		}
	}
	outsider, _ := auxiliaryRole(t, owner, "outsider_"+role)
	roleDenied(t, outsider, `SELECT public.omp_purge_audit_log(30,1)`, "42501")
	roleDenied(t, outsider, `SELECT public.omp_purge_mcp_calls(now(),1,1)`, "42501")
}

func TestUnsafeRoleMembershipAndEffectiveGrants(t *testing.T) {
	for _, tc := range []struct{ name, grant, revoke string }{
		{"public table", "GRANT DELETE ON audit_log TO PUBLIC", "REVOKE DELETE ON audit_log FROM PUBLIC"},
		{"public column", "GRANT UPDATE(action) ON audit_log TO PUBLIC", "REVOKE UPDATE(action) ON audit_log FROM PUBLIC"},
		{"public schema", "GRANT CREATE ON SCHEMA public TO PUBLIC", "REVOKE CREATE ON SCHEMA public FROM PUBLIC"},
		{"public truncate", "GRANT TRUNCATE ON teams TO PUBLIC", "REVOKE TRUNCATE ON teams FROM PUBLIC"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runtime, owner, role := splitFixture(t)
			ctx := context.Background()
			roleExec(t, owner, tc.grant)
			safety, err := store.InspectRoles(ctx, runtime, "", true)
			if err != nil || safety.Safe() {
				t.Fatalf("unsafe grants missed: %+v %v", safety, err)
			}
			if err := store.Migrate(ctx, owner, testutil.Logger(), role); err == nil {
				t.Fatal("unsafe PUBLIC grants accepted")
			}
			roleExec(t, owner, tc.revoke)
			if err := store.Migrate(ctx, owner, testutil.Logger(), role); err != nil {
				t.Fatal(err)
			}
		})
	}
	t.Run("CREATE outside public", func(t *testing.T) {
		runtime, owner, role := splitFixture(t)
		ctx := context.Background()
		roleExec(t, owner, "CREATE SCHEMA shadow_fixture")
		roleExec(t, owner, "GRANT CREATE ON SCHEMA shadow_fixture TO "+pgx.Identifier{role}.Sanitize())
		safety, err := store.InspectRoles(ctx, runtime, "", true)
		if err != nil || safety.Safe() {
			t.Fatalf("schema CREATE missed: %+v %v", safety, err)
		}
		if err := store.Migrate(ctx, owner, testutil.Logger(), role); err == nil {
			t.Fatal("custom schema CREATE accepted")
		}
		roleExec(t, owner, "REVOKE CREATE ON SCHEMA shadow_fixture FROM "+pgx.Identifier{role}.Sanitize())
		if err := store.Migrate(ctx, owner, testutil.Logger(), role); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("NOINHERIT owner membership", func(t *testing.T) {
		runtime, owner, role := splitFixture(t)
		ctx := context.Background()
		admin, err := pgx.Connect(ctx, testutil.DatabaseURL())
		if err != nil {
			t.Fatal(err)
		}
		defer admin.Close(ctx)
		ownerName := owner.Config().ConnConfig.User
		roleExec(t, admin, "GRANT "+pgx.Identifier{ownerName}.Sanitize()+" TO "+pgx.Identifier{role}.Sanitize())
		safety, err := store.InspectRoles(ctx, runtime, "", true)
		if err != nil || safety.Safe() {
			t.Fatalf("owner membership missed: %+v %v", safety, err)
		}
		if err := store.Migrate(ctx, owner, testutil.Logger(), role); err == nil {
			t.Fatal("owner membership accepted")
		}
		roleExec(t, admin, "REVOKE "+pgx.Identifier{ownerName}.Sanitize()+" FROM "+pgx.Identifier{role}.Sanitize())
	})
	t.Run("inherited column and grant options", func(t *testing.T) {
		runtime, owner, role := splitFixture(t)
		ctx := context.Background()
		group, admin := auxiliaryRole(t, owner, "group_"+role)
		groupName := group.Config().ConnConfig.User
		roleExec(t, owner, "GRANT UPDATE(action) ON audit_log TO "+pgx.Identifier{groupName}.Sanitize()+" WITH GRANT OPTION")
		roleExec(t, admin, "GRANT "+pgx.Identifier{groupName}.Sanitize()+" TO "+pgx.Identifier{role}.Sanitize())
		safety, err := store.InspectRoles(ctx, runtime, "", true)
		if err != nil || safety.Safe() {
			t.Fatalf("inherited grant missed: %+v %v", safety, err)
		}
		if err := store.Migrate(ctx, owner, testutil.Logger(), role); err == nil {
			t.Fatal("inherited grant accepted")
		}
		roleExec(t, admin, "REVOKE "+pgx.Identifier{groupName}.Sanitize()+" FROM "+pgx.Identifier{role}.Sanitize())
	})
}
