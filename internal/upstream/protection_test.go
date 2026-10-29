package upstream

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestProtectionCapAndIdempotentRelease(t *testing.T) {
	p := NewProtection()
	lease, err := p.acquire("one", 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.acquire("one", 1); err == nil || err.Class != ClassServerBusy || err.RetryAfter != time.Second {
		t.Fatalf("cap: %v", err)
	}
	other, err := p.acquire("other", 1)
	if err != nil {
		t.Fatal("other server affected:", err)
	}
	other.finish(protectionNeutral)
	lease.finish(protectionNeutral)
	lease.finish(protectionFailure) // Must not double-release or manufacture a failure.
	next, err := p.acquire("one", 1)
	if err != nil {
		t.Fatal(err)
	}
	next.finish(protectionSuccess)
	if got := p.entries["one"]; got.active != 0 || got.failures != 0 {
		t.Fatalf("double release: %+v", got)
	}
	for _, cap := range []int32{-1, MaxServerConcurrency + 1} {
		if _, err := p.acquire("bad", cap); err == nil || err.Class != ClassConfig {
			t.Fatalf("corrupt cap %d allowed: %v", cap, err)
		}
	}
	noop, err := p.acquire("", 1)
	if err != nil {
		t.Fatal(err)
	}
	noop.finish(protectionFailure)
	if _, exists := p.entries[""]; exists {
		t.Fatal("unregistered target entered server cache")
	}
}

func TestProtectionOpenProbeRecoveryAndNeutralRefusal(t *testing.T) {
	now := time.Date(2026, 10, 29, 0, 0, 0, 0, time.UTC)
	p := newProtection(func() time.Time { return now }, 10)
	for i := 0; i < CircuitFailureThreshold; i++ {
		lease, err := p.acquire("server", 0)
		if err != nil {
			t.Fatal(err)
		}
		lease.finish(protectionFailure)
	}
	if p.CircuitState("server") != 1 {
		t.Fatal("did not open")
	}
	if _, err := p.acquire("server", 0); err == nil || err.Reason != "circuit_open" || err.RetryAfter != CircuitOpenDuration {
		t.Fatalf("open: %v", err)
	}
	now = now.Add(CircuitOpenDuration)
	probe, err := p.acquire("server", 0)
	if err != nil || !probe.probe || p.CircuitState("server") != 0.5 {
		t.Fatalf("probe: %+v %v", probe, err)
	}
	if _, err := p.acquire("server", 0); err == nil || err.Class != ClassCircuitOpen {
		t.Fatal("second probe admitted")
	}
	probe.finish(protectionNeutral) // Local quota/authority/cancellation is not a failed upstream probe.
	probe, err = p.acquire("server", 0)
	if err != nil {
		t.Fatal(err)
	}
	probe.finish(protectionFailure)
	if _, err := p.acquire("server", 0); err == nil || err.RetryAfter != CircuitOpenDuration {
		t.Fatal("failed probe did not reopen")
	}
	now = now.Add(CircuitOpenDuration)
	probe, err = p.acquire("server", 0)
	if err != nil {
		t.Fatal(err)
	}
	probe.finish(protectionSuccess)
	if p.CircuitState("server") != 0 {
		t.Fatal("healthy probe did not close")
	}
}

func TestProtectionLateCompletionCannotCloseNewCircuit(t *testing.T) {
	now := time.Now()
	p := newProtection(func() time.Time { return now }, 10)
	oldSuccess, _ := p.acquire("server", 0)
	oldFailure, _ := p.acquire("server", 0)
	for range CircuitFailureThreshold {
		lease, _ := p.acquire("server", 0)
		lease.finish(protectionFailure)
	}
	oldSuccess.finish(protectionSuccess)
	if p.CircuitState("server") != 1 {
		t.Fatal("pre-open success closed a newer circuit")
	}
	now = now.Add(CircuitOpenDuration)
	probe, err := p.acquire("server", 0)
	if err != nil {
		t.Fatal(err)
	}
	probe.finish(protectionSuccess)
	oldFailure.finish(protectionFailure)
	if p.CircuitState("server") != 0 || p.entries["server"].failures != 0 || p.entries["server"].active != 0 {
		t.Fatal("old completion changed recovered generation")
	}
}

func TestProtectionBoundedStateNeverEvictsActiveOrOpen(t *testing.T) {
	now := time.Now()
	p := newProtection(func() time.Time { return now }, 1)
	lease, _ := p.acquire("first", 1)
	if _, err := p.acquire("second", 1); err == nil {
		t.Fatal("active entry evicted")
	}
	lease.finish(protectionNeutral)
	lease, err := p.acquire("second", 1)
	if err != nil || len(p.entries) != 1 {
		t.Fatalf("idle eviction: %v", err)
	}
	lease.finish(protectionFailure)
	for i := 1; i < CircuitFailureThreshold; i++ {
		lease, _ = p.acquire("second", 1)
		lease.finish(protectionFailure)
	}
	if _, err := p.acquire("third", 1); err == nil {
		t.Fatal("unexpired open circuit evicted")
	}
	now = now.Add(CircuitOpenDuration)
	lease, err = p.acquire("third", 1)
	if err != nil {
		t.Fatal(err)
	}
	lease.finish(protectionNeutral)
}

func TestProtectionConcurrentFailFastCap(t *testing.T) {
	p := NewProtection()
	var held []*protectionLease
	for range 7 {
		l, err := p.acquire("server", 7)
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, l)
	}
	var wg sync.WaitGroup
	for range 100 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := p.acquire("server", 7); err == nil || err.Class != ClassServerBusy {
				t.Error("full cap did not fail fast")
			}
		}()
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("admission queued")
	}
	for _, l := range held {
		l.finish(protectionNeutral)
	}
	var active atomic.Int32
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 100 {
				l, err := p.acquire("server", 7)
				if err != nil {
					if err.Class != ClassServerBusy {
						t.Error(err)
					}
					continue
				}
				if n := active.Add(1); n > 7 {
					t.Errorf("cap exceeded: %d", n)
				}
				active.Add(-1)
				l.finish(protectionSuccess)
			}
		}()
	}
	wg.Wait()
	if p.entries["server"].active != 0 {
		t.Fatal("leaked leases")
	}
}
