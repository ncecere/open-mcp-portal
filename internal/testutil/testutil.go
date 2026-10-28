// Package testutil provides real-infrastructure helpers for integration tests.
//
// Tests needing PostgreSQL call NewDB, which creates a fresh, migrated
// database per test. The server comes from OMP_TEST_DATABASE_URL (default:
// the compose Postgres, postgres://omp:omp-dev-only@127.0.0.1:55442/postgres).
// When it is unreachable the test is skipped, except in CI (CI=true) or with
// OMP_TEST_REQUIRE_DB=1, where a missing database fails the test instead of
// silently skipping it.
package testutil

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"log/slog"
	"net/url"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ncecere/open-mcp-portal/internal/store"
)

// DefaultDatabaseURL is the compose Postgres (make deps-up), as a role
// allowed to create databases.
const DefaultDatabaseURL = "postgres://omp:omp-dev-only@127.0.0.1:55442/postgres?sslmode=disable"

// DatabaseURL is OMP_TEST_DATABASE_URL, or DefaultDatabaseURL.
func DatabaseURL() string {
	if v := os.Getenv("OMP_TEST_DATABASE_URL"); v != "" {
		return v
	}
	return DefaultDatabaseURL
}

func requireDB() bool {
	return os.Getenv("CI") == "true" || os.Getenv("OMP_TEST_REQUIRE_DB") == "1"
}

var (
	reachOnce sync.Once
	reachErr  error
)

// adminConn connects to the test server, skipping (or failing, see the
// package comment) when it is unreachable. Reachability is checked once per
// test binary so a missing database costs one connection timeout.
func adminConn(t testing.TB, ctx context.Context) *pgx.Conn {
	t.Helper()
	reachOnce.Do(func() {
		cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		c, err := pgx.Connect(cctx, DatabaseURL())
		if err == nil {
			_ = c.Close(cctx)
		}
		reachErr = err
	})
	if reachErr != nil {
		if requireDB() {
			t.Fatalf("test database unreachable (%v); run `make deps-up`", reachErr)
		}
		t.Skipf("test database unreachable; skipping integration test (run `make deps-up`): %v", reachErr)
	}
	admin, err := pgx.Connect(ctx, DatabaseURL())
	if err != nil {
		t.Fatalf("connect admin db: %v", err)
	}
	return admin
}

func randomSuffix() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Logger discards output unless OMP_TEST_LOG=1.
func Logger() *slog.Logger {
	if os.Getenv("OMP_TEST_LOG") == "1" {
		return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

type fixture struct {
	owner *pgxpool.Pool
	role  string
}

var fixtures sync.Map // runtime pool -> explicit privileged fixture access

// OwnerPool is only for migrations, DDL and privileged test instrumentation.
// Application/service operations must keep using the pool returned by NewDB.
func OwnerPool(t testing.TB, pool *pgxpool.Pool) *pgxpool.Pool {
	t.Helper()
	if f, ok := fixtures.Load(pool); ok {
		return f.(fixture).owner
	}
	return pool
}

// Regrant reconciles after a fixture recreates application tables.
func Regrant(t testing.TB, pool *pgxpool.Pool) {
	t.Helper()
	if f, ok := fixtures.Load(pool); ok {
		v := f.(fixture)
		if err := store.Migrate(context.Background(), v.owner, Logger(), v.role); err != nil {
			t.Fatal(err)
		}
	}
}

// NewDB returns a genuinely authenticated runtime pool when
// OMP_TEST_SPLIT_ROLES=1. Only unique new scratch databases/roles are touched.
func NewDB(t testing.TB) (*pgxpool.Pool, string) {
	t.Helper()
	return NewDBWithMigration(t, func(ctx context.Context, owner *pgxpool.Pool, role string) error {
		return store.Migrate(ctx, owner, Logger(), role)
	})
}

// NewDBWithMigration creates the same disposable database and authenticated
// pools as NewDB, but lets historical-schema fixtures migrate from empty using
// the owner. The callback must also grant the runtime role access to its schema.
func NewDBWithMigration(t testing.TB, migrate func(context.Context, *pgxpool.Pool, string) error) (*pgxpool.Pool, string) {
	t.Helper()
	ctx := context.Background()
	admin := adminConn(t, ctx)
	name := "omp_test_" + randomSuffix()
	ownerName, runtimeName := name+"_owner", name+"_app"
	split := os.Getenv("OMP_TEST_SPLIT_ROLES") == "1"
	var pool, owner *pgxpool.Pool
	var createdRoles []string
	// Register before creating anything so failures also clean up immediately.
	t.Cleanup(func() {
		if pool != nil {
			fixtures.Delete(pool)
			pool.Close()
		}
		if owner != nil && owner != pool {
			owner.Close()
		}
		cctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		conn, err := pgx.Connect(cctx, DatabaseURL())
		if err != nil {
			t.Logf("cleanup connect: %v", err)
			return
		}
		defer conn.Close(cctx)
		if _, err := conn.Exec(cctx, "DROP DATABASE IF EXISTS "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)"); err != nil {
			t.Logf("cleanup database: %v", err)
		}
		for _, role := range createdRoles {
			if _, err := conn.Exec(cctx, "DROP ROLE "+pgx.Identifier{role}.Sanitize()); err != nil {
				t.Logf("cleanup role: %v", err)
			}
		}
	})
	defer admin.Close(ctx)
	password := "scratch-" + randomSuffix()
	if split {
		for _, role := range []string{ownerName, runtimeName} {
			// Random hex suffixes/passwords are generated here, never user input.
			if _, err := admin.Exec(ctx, "CREATE ROLE "+pgx.Identifier{role}.Sanitize()+" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT PASSWORD '"+password+"'"); err != nil {
				t.Fatal(err)
			}
			createdRoles = append(createdRoles, role)
		}
	}
	create := "CREATE DATABASE " + pgx.Identifier{name}.Sanitize()
	if split {
		create += " OWNER " + pgx.Identifier{ownerName}.Sanitize()
	}
	if _, err := admin.Exec(ctx, create); err != nil {
		t.Fatalf("create database: %v", err)
	}
	u, err := url.Parse(DatabaseURL())
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + name
	if split {
		u.User = url.UserPassword(ownerName, password)
	}
	owner, err = store.Open(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	role := ""
	if split {
		role = runtimeName
	}
	if err := migrate(ctx, owner, role); err != nil {
		t.Fatalf("migrate test db: %v", err)
	}
	if split {
		u.User = url.UserPassword(runtimeName, password)
		pool, err = store.Open(ctx, u.String())
		if err != nil {
			t.Fatal(err)
		}
		fixtures.Store(pool, fixture{owner: owner, role: runtimeName})
	} else {
		pool = owner
	}
	return pool, u.String()
}
