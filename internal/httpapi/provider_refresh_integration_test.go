package httpapi_test

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ncecere/open-mcp-portal/internal/httpapi"
	"github.com/ncecere/open-mcp-portal/internal/providers"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

// The background refresh (decision 69, issue #27): off by default, refreshes
// connections that expire soon and were used lately, finds a revoked grant
// before a call does, and never refreshes one connection twice for one
// expiry, however passes and calls overlap (the concurrent-refresh case of
// TestDelegatedCredentialsEndToEnd, with passes in the mix).
func TestBackgroundRefresh(t *testing.T) {
	var svc *providers.Service
	e := newProvEnvHook(t, func(d *httpapi.Deps) { svc = d.Providers })
	ctx := context.Background()
	const interval = 10 * time.Minute

	link := e.consentURL(e.callTool(e.key, f3Tool), "not_connected")
	if to := e.connect(e.member, map[string]any{"providerId": e.provider.Id, "requestId": requestID(link)}); !strings.Contains(to, "result=connected") {
		t.Fatalf("connect = %s", to)
	}
	if rep := e.providerReport(e.callTool(e.key, f3Tool)); !rep.Received {
		t.Fatalf("report = %+v", rep)
	}
	conn := e.myConnID()
	expireIn := func(d string) {
		e.scalar(`UPDATE provider_connections SET expires_at = now() + interval '`+d+`' WHERE id = $1 RETURNING 'x'`, conn)
	}
	pass := func() providers.RefreshSummary {
		t.Helper()
		sum, err := svc.RunRefresh(ctx, interval)
		if err != nil {
			t.Fatal(err)
		}
		return sum
	}

	// Off by default: the loop with a zero interval returns at once and refreshes nothing.
	expireIn("1 minute")
	done := make(chan struct{})
	go func() { svc.RefreshLoop(ctx, 0, testutil.Logger()); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("RefreshLoop with interval 0 did not return")
	}
	if n := e.oauth.RefreshRequests(); n != 0 {
		t.Fatalf("%d refreshes with the loop off", n)
	}

	// A token that does not expire inside the window is left alone.
	expireIn("2 hours")
	if sum := pass(); sum.Due != 0 || e.oauth.RefreshRequests() != 0 {
		t.Fatalf("not due: %+v, %d refreshes", sum, e.oauth.RefreshRequests())
	}
	// One nobody used lately is left alone too.
	expireIn("2 minutes")
	e.scalar(`UPDATE provider_connections SET last_used_at = now() - interval '30 days' WHERE id = $1 RETURNING 'x'`, conn)
	if sum := pass(); sum.Due != 0 || e.oauth.RefreshRequests() != 0 {
		t.Fatalf("unused: %+v, %d refreshes", sum, e.oauth.RefreshRequests())
	}
	// A used one that expires soon is refreshed once, then not again.
	e.scalar(`UPDATE provider_connections SET last_used_at = now() WHERE id = $1 RETURNING 'x'`, conn)
	if sum := pass(); sum.Due != 1 || sum.Refreshed != 1 || e.oauth.RefreshRequests() != 1 {
		t.Fatalf("due: %+v, %d refreshes", sum, e.oauth.RefreshRequests())
	}
	if sum := pass(); sum.Due != 0 || e.oauth.RefreshRequests() != 1 {
		t.Fatalf("second pass: %+v, %d refreshes", sum, e.oauth.RefreshRequests())
	}
	// The call that follows uses the refreshed token (the one the pass stored).
	if rep := e.providerReport(e.callTool(e.key, f3Tool)); !rep.Received || e.oauth.RefreshRequests() != 1 {
		t.Fatalf("call after a pass: %+v, %d refreshes", rep, e.oauth.RefreshRequests())
	}

	// Overlapping passes and calls: one refresh for the one expiry. The row
	// lock (and the advisory lock between passes) make the others wait or skip.
	expireIn("30 seconds")
	e.oauth.Set(func(f *testutil.FakeOAuth) { f.RefreshDelay = 300 * time.Millisecond })
	before := e.oauth.RefreshRequests()
	var wg sync.WaitGroup
	sums := make([]providers.RefreshSummary, 3)
	for i := range sums {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sum, err := svc.RunRefresh(ctx, interval)
			if err != nil {
				t.Error(err)
			}
			sums[i] = sum
		}(i)
	}
	results := make([]map[string]any, 3)
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, _, results[i] = rawMCP(t, e.app, "POST", "support", e.key, rpc(i, "tools/call", map[string]any{"name": f3Tool}), nil)
		}(i)
	}
	wg.Wait()
	e.oauth.Set(func(f *testutil.FakeOAuth) { f.RefreshDelay = 0 })
	for i, r := range results {
		if r["result"] == nil {
			t.Fatalf("concurrent call %d = %v", i, r)
		}
	}
	if n := e.oauth.RefreshRequests() - before; n != 1 {
		t.Fatalf("%d refreshes for one expiry (passes %+v)", n, sums)
	}
	refreshed := 0
	for _, s := range sums {
		refreshed += s.Refreshed
	}
	if refreshed > 1 {
		t.Fatalf("passes refreshed %d times: %+v", refreshed, sums)
	}

	// A provider that is down: the connection is kept for the next pass.
	expireIn("2 minutes")
	e.oauth.Set(func(f *testutil.FakeOAuth) { f.FailRefresh = "unavailable" })
	if sum := pass(); sum.Due != 1 || sum.Failed != 1 || sum.Lost != 0 {
		t.Fatalf("outage: %+v", sum)
	}
	if st := e.scalar(`SELECT status FROM provider_connections WHERE id = $1`, conn); st != "active" {
		t.Fatalf("status after an outage = %s", st)
	}
	e.oauth.Set(func(f *testutil.FakeOAuth) { f.FailRefresh = "" })

	// A grant the provider revoked is found by the pass, before any call: the
	// connection needs reconnecting (and the person is told), audited as a
	// system refresh failure; the next call then asks for consent.
	e.oauth.InvalidateAll(true)
	if sum := pass(); sum.Due != 1 || sum.Lost != 1 {
		t.Fatalf("revoked grant: %+v", sum)
	}
	if v := e.scalar(`SELECT status || ' ' || last_error_class FROM provider_connections WHERE id = $1`, conn); v != "needs_reconsent invalid_grant" {
		t.Fatalf("connection after the pass = %s", v)
	}
	if n := e.scalar(`SELECT count(*)::text FROM audit_log WHERE action = 'provider_connection.refresh_failed' AND actor_kind = 'system'
		AND target_id = $1 AND metadata->>'reason' = 'invalid_grant'`, conn); n != "1" {
		t.Fatalf("refresh_failed audits = %s", n)
	}
	if sum := pass(); sum.Due != 0 {
		t.Fatalf("a lost connection is not refreshed again: %+v", sum)
	}
	e.consentURL(e.callTool(e.key, f3Tool), "needs_reconsent")
	e.noSecretsAnywhere()
}
