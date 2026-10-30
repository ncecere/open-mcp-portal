package registry

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

type transferTraceKey int

const (
	transferTraceOperation transferTraceKey = iota
	transferTraceServerQuery
)

// Pause a forced move immediately after it locks the server. Let an accept
// reach its server-lock attempt, then resume the forced move. A transfer-first
// accept now holds the transfer and waits for the server, while the forced
// move holds the server and waits for the transfer: a real PostgreSQL deadlock.
// A server-first accept waits without holding the transfer, so both finish.
type transferLockTrace struct {
	forceLocked, acceptStarted, resumeForce chan struct{}
	onceForce, onceAccept                   sync.Once
}

func (t *transferLockTrace) TraceQueryStart(ctx context.Context, _ *pgx.Conn, d pgx.TraceQueryStartData) context.Context {
	isServer := strings.Contains(d.SQL, "-- name: LockMCPServer :one")
	if isServer && ctx.Value(transferTraceOperation) == "accept" {
		t.onceAccept.Do(func() { close(t.acceptStarted) })
	}
	return context.WithValue(ctx, transferTraceServerQuery, isServer)
}
func (t *transferLockTrace) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, d pgx.TraceQueryEndData) {
	if d.Err == nil && ctx.Value(transferTraceServerQuery) == true && ctx.Value(transferTraceOperation) == "force" {
		t.onceForce.Do(func() {
			close(t.forceLocked)
			select {
			case <-t.resumeForce:
			case <-ctx.Done():
			}
		})
	}
}

func TestForceAndAcceptTransferUseOneLockOrder(t *testing.T) {
	e := newXferEnv(t)
	srv := e.server("transfer-lock-order", "private")
	tr := e.request(srv)
	revision := e.rev(srv)
	trace := &transferLockTrace{forceLocked: make(chan struct{}), acceptStarted: make(chan struct{}), resumeForce: make(chan struct{})}
	cfg := e.s.pool.Config()
	cfg.ConnConfig.Tracer = trace
	pool, err := pgxpool.NewWithConfig(e.ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	s := *e.s
	s.pool, s.q = pool, dbgen.New(pool)
	ctx, cancel := context.WithTimeout(e.ctx, 15*time.Second)
	defer cancel()
	var resume sync.Once
	defer resume.Do(func() { close(trace.resumeForce) })
	force, accept := make(chan error, 1), make(chan error, 1)
	go func() {
		_, err := s.ForceTransfer(context.WithValue(ctx, transferTraceOperation, "force"), e.actor(e.platform), srv, "recv", nil, revision)
		force <- err
	}()
	select {
	case <-trace.forceLocked:
	case <-ctx.Done():
		t.Fatal("forced move never locked server", ctx.Err())
	}
	go func() {
		_, err := s.AcceptTransfer(context.WithValue(ctx, transferTraceOperation, "accept"), e.actor(e.recvOwner), "recv", tr.Transfer.ID, 1)
		accept <- err
	}()
	select {
	case <-trace.acceptStarted:
	case <-ctx.Done():
		t.Fatal("accept never attempted server lock", ctx.Err())
	}
	resume.Do(func() { close(trace.resumeForce) })
	for name, ch := range map[string]<-chan error{"force": force, "accept": accept} {
		select {
		case err := <-ch:
			if name == "force" && err != nil {
				t.Errorf("forced move: %v", err)
			}
			if name == "accept" && code(err) != "transfer_closed" {
				t.Errorf("accept after forced cancellation: %v", err)
			}
		case <-ctx.Done():
			t.Fatalf("%s did not finish: %v", name, ctx.Err())
		}
	}
	if e.teamOf(srv) != e.recv {
		t.Fatal("forced move did not retain its destination")
	}
	if got := e.str(`SELECT state FROM server_transfers WHERE id=$1`, tr.Transfer.ID); got != TransferCancelled {
		t.Fatalf("original transfer: %s", got)
	}
}
