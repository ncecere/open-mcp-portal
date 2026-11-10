package testutil

import (
	"context"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// QueryLog records the statements sent on a test pool while it is recording,
// so a test can hold a request to a budget of database round trips. Every
// pool NewDB returns carries one; QueryLogOf finds it.
type QueryLog struct {
	mu        sync.Mutex
	recording bool
	names     []string
}

var sqlcName = regexp.MustCompile(`^-- name: (\w+)`)

// TraceQueryStart implements pgx.QueryTracer. sqlc statements are recorded by
// name; anything else (begin, commit, hand-written SQL) by its first words.
func (q *QueryLog) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	q.mu.Lock()
	defer q.mu.Unlock()
	if !q.recording {
		return ctx
	}
	name := strings.Join(strings.Fields(data.SQL), " ")
	if m := sqlcName.FindStringSubmatch(data.SQL); m != nil {
		name = m[1]
	} else if len(name) > 60 {
		name = name[:60]
	}
	q.names = append(q.names, name)
	return ctx
}

// TraceQueryEnd implements pgx.QueryTracer.
func (*QueryLog) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

// Record runs fn and returns the statements the pool sent meanwhile, in
// order. Background loops sharing the pool can add to it: callers that
// assert a budget should take the smallest of a few runs.
func (q *QueryLog) Record(fn func()) []string {
	q.mu.Lock()
	q.recording, q.names = true, nil
	q.mu.Unlock()
	fn()
	q.mu.Lock()
	defer q.mu.Unlock()
	q.recording = false
	return q.names
}

// QueryLogOf is the QueryLog of a pool made by NewDB.
func QueryLogOf(t testing.TB, pool *pgxpool.Pool) *QueryLog {
	t.Helper()
	q, ok := pool.Config().ConnConfig.Tracer.(*QueryLog)
	if !ok {
		t.Fatal("pool has no QueryLog: was it made by testutil.NewDB?")
	}
	return q
}
