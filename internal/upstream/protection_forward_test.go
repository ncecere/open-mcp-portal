package upstream

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestForwardCircuitNoContactAndSingleRecoveryProbe(t *testing.T) {
	now := time.Now()
	p := newProtection(func() time.Time { return now }, 10)
	var posts atomic.Int32
	entered, release := make(chan struct{}), make(chan struct{})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := posts.Add(1)
		if n <= CircuitFailureThreshold {
			http.Error(w, "busy", 503)
			return
		}
		if n == CircuitFailureThreshold+1 {
			close(entered)
			<-release
		}
		var m struct{ ID json.RawMessage }
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &m)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": m.ID, "result": map[string]any{"content": []any{}}})
	}))
	defer ts.Close()
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	c := eraClient()
	c.Protection = p
	target := Target{URL: ts.URL, ServerID: "server", MaxConcurrent: 2, Timeout: 5 * time.Second}
	c.remember(target, Protocol{Era: EraModern, Version: ModernVersion})
	req := ForwardRequest{Method: MethodToolsCall, Name: "read"}
	for range CircuitFailureThreshold {
		if _, err := c.Forward(context.Background(), target, req); err == nil {
			t.Fatal("failed upstream succeeded")
		}
	}
	_, err := c.Forward(context.Background(), target, req)
	var e *Error
	if !errors.As(err, &e) || e.Class != ClassCircuitOpen || posts.Load() != CircuitFailureThreshold {
		t.Fatalf("open contacted upstream: %v posts=%d", err, posts.Load())
	}
	now = now.Add(CircuitOpenDuration)
	done := make(chan error, 1)
	go func() { _, err := c.Forward(context.Background(), target, req); done <- err }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("recovery probe not dispatched")
	}
	_, err = c.Forward(context.Background(), target, req)
	if !errors.As(err, &e) || e.Class != ClassCircuitOpen || posts.Load() != CircuitFailureThreshold+1 {
		t.Fatalf("multiple probes: %v posts=%d", err, posts.Load())
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if p.CircuitState("server") != 0 {
		t.Fatal("successful probe did not recover")
	}
	if _, err := c.Forward(context.Background(), target, req); err != nil {
		t.Fatal(err)
	}
}

func TestForwardCancellationAtAdmissionNeverContacts(t *testing.T) {
	var posts atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { posts.Add(1); w.WriteHeader(503) }))
	defer ts.Close()
	c := eraClient()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, err := c.Forward(ctx, Target{URL: ts.URL, ServerID: "server", Timeout: time.Second}, ForwardRequest{OnAdmitted: cancel})
	var e *Error
	if !errors.As(err, &e) || e.Class != ClassUnavailable || !e.BeforeDispatch || e.PriorAttempts != 0 || posts.Load() != 0 {
		t.Fatalf("cancelled admission dispatched or lost proof: %v posts=%d", err, posts.Load())
	}
	if state := c.protector().entries["server"]; state.active != 0 || state.failures != 0 {
		t.Fatal("cancelled admission retained lease or changed health")
	}
}

func TestForwardAdmissionTimeoutReleasesWithoutUpstreamFailure(t *testing.T) {
	c := eraClient()
	target := Target{URL: "http://127.0.0.1:1", ServerID: "server", MaxConcurrent: 1, Timeout: 20 * time.Millisecond,
		BeforeAttempt: func(ctx context.Context, _ int) error { <-ctx.Done(); return ctx.Err() }}
	if _, err := c.Forward(context.Background(), target, ForwardRequest{}); err == nil {
		t.Fatal("admission timeout succeeded")
	}
	state := c.protector().entries["server"]
	if state.active != 0 || state.failures != 0 || !state.openedUntil.IsZero() {
		t.Fatalf("local admission timeout affected upstream health: %+v", state)
	}
}
