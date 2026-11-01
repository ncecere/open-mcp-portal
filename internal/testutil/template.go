package testutil

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ncecere/open-mcp-portal/internal/store"
)

// Migrating every test database from empty replays the whole migration chain
// (over a second per database under the race detector), so each migration
// added to the chain made every integration test slower. NewDB instead copies
// a database migrated once per test process (CREATE DATABASE ... TEMPLATE),
// then makes the copy exactly as if the test's own owner had migrated it and
// runs the real per-test path: role-safety preflight, migrate (no pending
// migrations) and runtime-grant reconciliation. NewDBWithMigration and
// NewDBFromScratch still migrate from empty; TestTemplateMatchesFreshMigration
// compares the two catalogs.

type dbTemplate struct {
	name  string
	owner string // split roles: the role that migrated it ("" otherwise)
	mu    sync.Mutex
}

// templates holds one migrated template per role mode and server: tests
// may switch OMP_TEST_SPLIT_ROLES per subtest within one process, and the
// two modes need differently owned templates.
var templates sync.Map // key -> *templateEntry

type templateEntry struct {
	once sync.Once
	val  *dbTemplate
	err  error
}

// staleTemplateAge bounds how long a template can belong to a running test
// process: far beyond any package's 20-minute budget.
const staleTemplateAge = time.Hour

func migratedTemplate(t testing.TB, ctx context.Context, split bool) *dbTemplate {
	t.Helper()
	key := strconv.FormatBool(split) + " " + DatabaseURL()
	v, _ := templates.LoadOrStore(key, &templateEntry{})
	e := v.(*templateEntry)
	e.once.Do(func() { e.val, e.err = buildTemplate(ctx, split) })
	if e.err != nil {
		t.Fatalf("migrated template database: %v", e.err)
	}
	return e.val
}

func buildTemplate(ctx context.Context, split bool) (*dbTemplate, error) {
	admin, err := pgx.Connect(ctx, DatabaseURL())
	if err != nil {
		return nil, err
	}
	defer admin.Close(ctx)
	dropStaleTemplates(ctx, admin)
	tmpl := &dbTemplate{name: fmt.Sprintf("omp_tmpl_%d_%s", time.Now().Unix(), randomSuffix())}
	u, err := url.Parse(DatabaseURL())
	if err != nil {
		return nil, err
	}
	u.Path = "/" + tmpl.name
	create := "CREATE DATABASE " + pgx.Identifier{tmpl.name}.Sanitize()
	if split {
		tmpl.owner = tmpl.name + "_owner"
		password := "scratch-" + randomSuffix()
		if _, err := admin.Exec(ctx, "CREATE ROLE "+pgx.Identifier{tmpl.owner}.Sanitize()+" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT PASSWORD '"+password+"'"); err != nil {
			return nil, err
		}
		create += " OWNER " + pgx.Identifier{tmpl.owner}.Sanitize()
		u.User = url.UserPassword(tmpl.owner, password)
	}
	if _, err := admin.Exec(ctx, create); err != nil {
		return nil, err
	}
	owner, err := store.Open(ctx, u.String())
	if err != nil {
		return nil, err
	}
	// No runtime role here: each copy reconciles its own runtime grants.
	err = store.Migrate(ctx, owner, Logger(), "")
	owner.Close()
	if err != nil {
		return nil, err
	}
	if split {
		// The template database itself must not be a shared object of the
		// migrating role, or REASSIGN OWNED in a copy would move it too.
		if _, err := admin.Exec(ctx, "ALTER DATABASE "+pgx.Identifier{tmpl.name}.Sanitize()+" OWNER TO CURRENT_USER"); err != nil {
			return nil, err
		}
	}
	return tmpl, nil
}

// reassign moves every object of the template's migrating role in a fresh
// copy to the test's owner, as a superuser connected to that copy.
func reassign(ctx context.Context, dbURL, from, to string) error {
	u, err := url.Parse(DatabaseURL())
	if err != nil {
		return err
	}
	target, err := url.Parse(dbURL)
	if err != nil {
		return err
	}
	u.Path = target.Path
	conn, err := pgx.Connect(ctx, u.String())
	if err != nil {
		return err
	}
	defer conn.Close(ctx)
	_, err = conn.Exec(ctx, "REASSIGN OWNED BY "+pgx.Identifier{from}.Sanitize()+" TO "+pgx.Identifier{to}.Sanitize())
	return err
}

// dropStaleTemplates removes templates (and their roles) of test processes
// that have certainly ended. Names carry their creation time.
func dropStaleTemplates(ctx context.Context, admin *pgx.Conn) {
	rows, err := admin.Query(ctx, `SELECT datname FROM pg_database WHERE datname LIKE 'omp\_tmpl\_%'`)
	if err != nil {
		return
	}
	var stale []string
	for rows.Next() {
		var name string
		if rows.Scan(&name) != nil {
			continue
		}
		parts := strings.SplitN(strings.TrimPrefix(name, "omp_tmpl_"), "_", 2)
		created, err := strconv.ParseInt(parts[0], 10, 64)
		if err == nil && time.Since(time.Unix(created, 0)) > staleTemplateAge {
			stale = append(stale, name)
		}
	}
	rows.Close()
	for _, name := range stale {
		if _, err := admin.Exec(ctx, "DROP DATABASE IF EXISTS "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)"); err == nil {
			_, _ = admin.Exec(ctx, "DROP ROLE IF EXISTS "+pgx.Identifier{name + "_owner"}.Sanitize())
		}
	}
}
