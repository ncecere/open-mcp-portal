package mcptasks_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ncecere/open-mcp-portal/internal/mcptasks"
)

// SQL/crypto fencing evidence only: no upstream exchange or live authority.
func firstKey(t *testing.T, raw json.RawMessage) string {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil || len(m) != 1 {
		t.Fatalf("mapped requests %s: %v", raw, err)
	}
	for k := range m {
		return k
	}
	return ""
}

func TestTaskOperationsAreExclusivePacedAndFenced(t *testing.T) {
	f := newTaskStoreFixture(t, 100)
	ctx := context.Background()
	h, _ := activate(t, f, f.binding)
	root := taskRoot(f.binding)
	snap, err := f.store.Lookup(ctx, h, root)
	if err != nil {
		t.Fatal(err)
	}
	var wins atomic.Int32
	var wg sync.WaitGroup
	ops := make(chan mcptasks.Operation, 20)
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			op, err := f.store.Begin(ctx, snap, false, 30*time.Second)
			if err == nil {
				wins.Add(1)
				ops <- op
			} else if !errors.Is(err, mcptasks.ErrBusy) {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	close(ops)
	if wins.Load() != 1 {
		t.Fatalf("%d concurrent claims succeeded", wins.Load())
	}
	op := <-ops
	if fmt.Sprintf("%v %+v %#v", op, op, op) != "private task operation private task operation private task operation" {
		t.Fatal("operation formatter exposed state")
	}
	if raw, _ := json.Marshal(op); string(raw) != "{}" {
		t.Fatal("operation serialized private state")
	}
	obs := mcptasks.Observation{ID: snap.Payload().UpstreamID, Status: "input_required", CreatedAt: op.Snapshot().UpstreamCreatedAt(), UpdatedAt: time.Now()}
	reqs := json.RawMessage(`{"server-private-key":{"method":"elicitation/create","params":{"message":"Approve?"}}}`)
	bad := obs
	bad.ID = "another-upstream-task"
	if _, _, err := f.store.Finish(ctx, op, bad, reqs); !errors.Is(err, mcptasks.ErrUnavailable) {
		t.Fatal("mismatched upstream ID accepted", err)
	}
	moved := obs
	moved.CreatedAt = moved.CreatedAt.Add(-time.Hour)
	if _, _, err := f.store.Finish(ctx, op, moved, reqs); !errors.Is(err, mcptasks.ErrUnavailable) {
		t.Fatal("rewritten creation time accepted", err)
	}
	snap, mapped, err := f.store.Finish(ctx, op, obs, reqs)
	if err != nil || snap.Status() != "input_required" {
		t.Fatal(err)
	}
	key := firstKey(t, mapped)
	if _, _, err := f.store.Finish(ctx, op, obs, reqs); !errors.Is(err, mcptasks.ErrBusy) {
		t.Fatal("finished claim committed twice", err)
	}
	// A poll right after one is paced; a non-poll update is not.
	if _, err := f.store.Begin(ctx, snap, true, 30*time.Second); !errors.Is(err, mcptasks.ErrBusy) {
		t.Fatal("poll interval not enforced", err)
	}
	op, err = f.store.Begin(ctx, snap, false, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	resp := json.RawMessage(fmt.Sprintf(`{%q:{"action":"accept","content":{}}}`, key))
	op, body, n, err := f.store.CommitInput(ctx, op, resp)
	if err != nil || n != 1 || firstKey(t, body) != "server-private-key" {
		t.Fatalf("input commit: n=%d %v", n, err)
	}
	// The send is lost: release. The attempt is NOT restored.
	if err := f.store.Release(ctx, op); err != nil {
		t.Fatal(err)
	}
	if err := f.store.Release(ctx, op); !errors.Is(err, mcptasks.ErrBusy) {
		t.Fatal("stale release accepted", err)
	}
	snap, err = f.store.Lookup(ctx, h, root)
	if err != nil {
		t.Fatal(err)
	}
	op, err = f.store.Begin(ctx, snap, false, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, n, err := f.store.CommitInput(ctx, op, resp); err != nil || n != 0 {
		t.Fatal("consumed input replayed after an ambiguous send", n, err)
	}
	// Terminal: lifetime only shrinks, status is sticky, results stay unpaced.
	long, short := int64((48 * time.Hour).Milliseconds()), int64((30 * time.Minute).Milliseconds())
	done := obs
	done.Status, done.TTLMillis = "completed", &long
	before := snap.ExpiresAt()
	snap, _, err = f.store.Finish(ctx, op, done, nil)
	if err != nil || snap.Status() != "completed" || !snap.ExpiresAt().Equal(before) {
		t.Fatal("terminal finish extended lifetime or failed", err)
	}
	op, err = f.store.Begin(ctx, snap, true, 30*time.Second)
	if err != nil {
		t.Fatal("terminal result fetch was paced", err)
	}
	regress := done
	regress.Status = "working"
	if _, _, err := f.store.Finish(ctx, op, regress, nil); !errors.Is(err, mcptasks.ErrUnavailable) {
		t.Fatal("terminal status regressed", err)
	}
	done.TTLMillis = &short
	snap, _, err = f.store.Finish(ctx, op, done, nil)
	if err != nil || !snap.ExpiresAt().Before(before) {
		t.Fatal("shorter upstream TTL did not shrink lifetime", err)
	}
	if _, _, err := f.store.Finish(ctx, op, done, json.RawMessage(`{"x":{}}`)); err == nil {
		t.Fatal("input requests accepted for a non-input status")
	}
	if f.pool.Stat().AcquiredConns() != 0 {
		t.Fatal("an operation API returned with a SQL connection still acquired")
	}
}
