// Package store owns the PostgreSQL connection pool, migrations and the
// sqlc-generated queries (package dbgen).
package store

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/migrations"
)

// migrationLockKey is the pg_advisory_lock key that serialises migrations
// across replicas and a Kubernetes migration Job.
const migrationLockKey int64 = 0x6f6d700000000001 // ASCII "omp" + 1

// ErrNotFound is returned when a row does not exist.
var ErrNotFound = errors.New("not found")

// Open creates a connection pool and verifies connectivity.
func Open(ctx context.Context, url string) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, errors.New("DATABASE_URL: invalid PostgreSQL connection configuration")
	}
	if cfg.ConnConfig.RuntimeParams == nil {
		cfg.ConnConfig.RuntimeParams = map[string]string{}
	}
	cfg.ConnConfig.RuntimeParams["application_name"] = "open-mcp-portal"
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, errors.New("postgres ping failed (check connectivity and credentials)")
	}
	return pool, nil
}

// OpenWait is Open, retried with backoff until Postgres answers or wait
// elapses. Pods often start before their database is ready (a first install,
// a cluster restart); waiting here keeps the process from crash-looping into
// long restart back-offs.
func OpenWait(ctx context.Context, url string, wait time.Duration, log *slog.Logger) (*pgxpool.Pool, error) {
	deadline := time.Now().Add(wait)
	delay := time.Second
	for attempt := 1; ; attempt++ {
		pool, err := Open(ctx, url)
		if err == nil {
			if attempt > 1 {
				log.Info("postgres reachable", "attempts", attempt)
			}
			return pool, nil
		}
		// A malformed DATABASE_URL never becomes valid: fail at once.
		if strings.HasPrefix(err.Error(), "DATABASE_URL:") || time.Now().Add(delay).After(deadline) {
			return nil, err
		}
		log.Warn("postgres not reachable yet; retrying", "attempt", attempt, "retryIn", delay.String(), "err", err)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(delay):
		}
		delay = min(delay*2, 10*time.Second)
	}
}

// Migrate applies the goose migrations while holding a session advisory
// lock, so concurrent starts are safe.
func Migrate(ctx context.Context, pool *pgxpool.Pool, log *slog.Logger, runtimeRole ...string) error {
	role := ""
	if len(runtimeRole) > 0 {
		role = runtimeRole[0]
	}
	if role != "" {
		safety, err := InspectRoles(ctx, pool, role, false)
		if err != nil {
			return fmt.Errorf("database role preflight: %w", err)
		}
		if !safety.Safe() {
			return fmt.Errorf("unsafe split database roles: %s", safety.Detail())
		}
	}
	// The advisory lock lives on its own connection, outside the pool: a
	// caller waiting for the lock must not hold a pool slot, or concurrent
	// callers sharing a small pool would leave the lock holder no
	// connections for goose.
	conn, err := pgx.ConnectConfig(ctx, pool.Config().ConnConfig.Copy())
	if err != nil {
		return fmt.Errorf("migration lock connection: %w", err)
	}
	defer func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = conn.Close(closeCtx) // also releases the session lock
	}()
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", migrationLockKey); err != nil {
		return fmt.Errorf("migration lock: %w", err)
	}
	defer func() {
		// Use a fresh context so the lock is released even if ctx was cancelled.
		unlockCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = conn.Exec(unlockCtx, "SELECT pg_advisory_unlock($1)", migrationLockKey)
	}()

	db := stdlib.OpenDBFromPool(pool)
	defer db.Close()
	provider, err := goose.NewProvider(goose.DialectPostgres, db, migrations.FS)
	if err != nil {
		return fmt.Errorf("goose: %w", err)
	}
	results, err := provider.Up(ctx)
	for _, r := range results {
		log.Info("applied migration", "source", r.Source.Path, "duration", r.Duration)
	}
	if err != nil {
		return fmt.Errorf("apply migrations: %w", err)
	}
	if role != "" {
		if err := ReconcileRuntimeGrants(ctx, conn, role); err != nil {
			return fmt.Errorf("runtime grants: %w", err)
		}
	}
	return nil
}

// InTx runs fn in a transaction with queries bound to it.
func InTx(ctx context.Context, pool *pgxpool.Pool, fn func(q *dbgen.Queries, tx pgx.Tx) error) error {
	return pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		q := dbgen.New(tx)
		txOf.Store(q, tx)
		defer txOf.Delete(q)
		return fn(q, tx)
	})
}

// txOf maps the queries InTx hands out to their transaction.
var txOf sync.Map

// TxOf returns the transaction queries from InTx are bound to (ok is false
// for queries on the pool, or on a transaction begun elsewhere). Code that
// must not fail its caller's transaction (notification events) uses it to
// work under a savepoint (tx.Begin).
func TxOf(q *dbgen.Queries) (pgx.Tx, bool) {
	tx, ok := txOf.Load(q)
	if !ok {
		return nil, false
	}
	return tx.(pgx.Tx), true
}

// NotFound maps pgx.ErrNoRows to ErrNotFound.
func NotFound(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

// EscapeLike escapes LIKE wildcards in user-supplied search text; queries use
// ESCAPE '\'.
func EscapeLike(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}
