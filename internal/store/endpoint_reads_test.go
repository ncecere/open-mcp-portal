package store

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

type endpointReadFake struct{ read func(context.Context) error }

func (f endpointReadFake) GetNetworkSettings(ctx context.Context) (dbgen.NetworkSetting, error) {
	return dbgen.NetworkSetting{}, f.read(ctx)
}
func (f endpointReadFake) GetAuthProvider(ctx context.Context, _ uuid.UUID) (dbgen.AuthProvider, error) {
	return dbgen.AuthProvider{}, f.read(ctx)
}

func TestEndpointReadsSerializeBothQueries(t *testing.T) {
	var active, calls atomic.Int32
	ctx, scope := WithEndpointReads(context.Background(), endpointReadFake{read: func(context.Context) error {
		if active.Add(1) != 1 {
			t.Error("concurrent transaction queries")
		}
		calls.Add(1)
		time.Sleep(time.Millisecond)
		active.Add(-1)
		return nil
	}})
	defer scope.Close()
	q, _ := EndpointReads(ctx)
	var wg sync.WaitGroup
	for i := range 40 {
		wg.Go(func() {
			var err error
			if i%2 == 0 {
				_, err = q.GetNetworkSettings(ctx)
			} else {
				_, err = q.GetAuthProvider(ctx, uuid.Nil)
			}
			if err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if calls.Load() != 40 {
		t.Fatalf("calls = %d", calls.Load())
	}
}

func TestEndpointReadsCloseCancelsThenDrains(t *testing.T) {
	entered, cancelled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	ctx, scope := WithEndpointReads(context.Background(), endpointReadFake{read: func(ctx context.Context) error {
		calls.Add(1)
		close(entered)
		<-ctx.Done()
		close(cancelled)
		<-release // SQL has not finished cleaning up yet.
		return ctx.Err()
	}})
	q, _ := EndpointReads(ctx)
	active := make(chan error, 1)
	go func() { _, err := q.GetNetworkSettings(context.WithoutCancel(ctx)); active <- err }()
	<-entered
	queued := make(chan error, 1)
	go func() { _, err := q.GetAuthProvider(ctx, uuid.Nil); queued <- err }()
	closed := make(chan struct{})
	go func() { scope.Close(); close(closed) }()
	<-cancelled
	select {
	case <-closed:
		t.Fatal("Close returned before active SQL finished")
	default:
	}
	// A detached late dial must retain the closed capability, never a pool fallback.
	late, ok := EndpointReads(context.WithoutCancel(ctx))
	if !ok {
		t.Fatal("closed scope disappeared")
	}
	if _, err := late.GetNetworkSettings(context.WithoutCancel(ctx)); !errors.Is(err, ErrEndpointReadsClosed) {
		t.Fatalf("late read = %v", err)
	}
	close(release)
	<-closed
	if err := <-active; !errors.Is(err, context.Canceled) {
		t.Fatalf("active read = %v", err)
	}
	if err := <-queued; !errors.Is(err, ErrEndpointReadsClosed) {
		t.Fatalf("queued read = %v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("SQL calls = %d", calls.Load())
	}
	if !errors.Is(scope.Err(), context.Canceled) {
		t.Fatalf("scope error = %v", scope.Err())
	}
}

func TestEndpointReadsDetachedDialKeepsOwnDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	ctx, scope := WithEndpointReads(ctx, endpointReadFake{read: func(ctx context.Context) error {
		<-ctx.Done()
		return ctx.Err()
	}})
	defer scope.Close()
	q, _ := EndpointReads(context.WithoutCancel(ctx))
	start := time.Now()
	_, err := q.GetNetworkSettings(context.WithoutCancel(ctx))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("read = %v", err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("detached dial escaped scope deadline")
	}
	if !errors.Is(scope.Err(), context.DeadlineExceeded) {
		t.Fatal(scope.Err())
	}
}
