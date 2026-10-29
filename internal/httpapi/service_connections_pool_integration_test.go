package httpapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/ncecere/open-mcp-portal/internal/app"
	"github.com/ncecere/open-mcp-portal/internal/config"
	"github.com/ncecere/open-mcp-portal/internal/httpapi"
	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/registry"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

func TestServiceConnectionRefreshWithBoundedPool(t *testing.T) {
	for _, calls := range []int{1, 8} {
		t.Run(fmt.Sprintf("%d_calls_two_handlers", calls), func(t *testing.T) {
			e, cfg, c, key := serviceRefreshPoolFixture(t)
			pool, replicas := serviceRefreshPoolHandlers(t, e, cfg, 1)
			old := e.scalar(`SELECT encode(refresh_token_cipher,'hex') FROM service_connections WHERE id=$1`, c.Id)
			before := e.oauth.RefreshRequests()

			// Each NewDeps has a genuinely cold registry.Networks. In particular,
			// do not prewarm it through the network API or an upstream call.
			results := serviceRefreshPoolCalls(t, e, pool, replicas, c.Id, key, calls)
			for i, r := range results {
				if r.err != nil || r.status != http.StatusOK {
					t.Errorf("call %d must finish with a credential within 5s: status=%d err=%v", i, r.status, r.err)
					continue
				}
				var out map[string]any
				if err := json.Unmarshal(r.body, &out); err != nil {
					t.Errorf("call %d: %v", i, err)
					continue
				}
				if !e.providerReport(out).Received {
					t.Errorf("call %d did not deliver the provider credential", i)
				}
			}
			if got := e.oauth.RefreshRequests() - before; got != 1 {
				t.Errorf("actual refreshes = %d, want exactly one across both handlers", got)
			}
			if now := e.scalar(`SELECT encode(refresh_token_cipher,'hex') FROM service_connections WHERE id=$1`, c.Id); now == old {
				t.Error("rotated refresh token was not committed")
			}
		})
	}
}

// A cold read must not turn the starvation fix into a permit. Without the
// fixture's development allowance, the actual loopback provider must be
// refused, including when the settings row cannot be read.
func TestServiceConnectionRefreshPoolNetworkDenial(t *testing.T) {
	for _, missing := range []bool{false, true} {
		t.Run(fmt.Sprintf("missing_settings_%t", missing), func(t *testing.T) {
			e, cfg, c, key := serviceRefreshPoolFixture(t)
			if missing {
				// Privileged instrumentation stays on the ORIGINAL fixture pool;
				// the new runtime pool is not registered with testutil.OwnerPool.
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if _, err := testutil.OwnerPool(t, e.app.Pool).Exec(ctx, `DELETE FROM network_settings`); err != nil {
					t.Fatal(err)
				}
			} else {
				serviceRefreshPoolNetworks(t, e, []any{})
			}
			cfg.DevAuth = false // Tighten to the production address guard.
			// Leave room for this negative control's cold policy read. The
			// one-connection positive regression above must also succeed.
			pool, replicas := serviceRefreshPoolHandlers(t, e, cfg, 2)
			old := e.scalar(`SELECT encode(refresh_token_cipher,'hex') FROM service_connections WHERE id=$1`, c.Id)
			before := e.oauth.RefreshRequests()
			r := serviceRefreshPoolCalls(t, e, pool, replicas, c.Id, key, 1)[0]
			if r.err != nil || r.status != http.StatusOK {
				t.Fatalf("network refusal did not complete: status=%d err=%v", r.status, r.err)
			}
			var out map[string]any
			if err := json.Unmarshal(r.body, &out); err != nil {
				t.Fatal(err)
			}
			serviceDenied(t, out, "provider_unavailable")
			if e.oauth.RefreshRequests() != before || e.toolCalls("provider_token") != 0 {
				t.Fatal("network refusal dispatched a refresh or a credential")
			}
			if now := e.scalar(`SELECT status||':'||encode(refresh_token_cipher,'hex') FROM service_connections WHERE id=$1`, c.Id); now != "active:"+old {
				t.Fatal("network refusal destroyed the existing grant")
			}
		})
	}
}

func serviceRefreshPoolFixture(t *testing.T) (*provEnv, config.Config, apitypes.ServiceConnection, string) {
	t.Helper()
	var cfg config.Config
	e := newProvEnvHook(t, func(d *httpapi.Deps) { cfg = d.Config })
	sa := createSA(t, e.owner, map[string]any{"name": "bounded-refresh"})
	key := createSAKey(t, e.owner, sa.Id.String(), map[string]any{"name": "ci"}).Secret
	c := connectShared(t, e.owner, e.provider.Id, "bounded-refresh")
	code, ec, c := assignShared(t, e.owner, c, []uuid.UUID{sa.Id}, []apitypes.ServiceConnectionGrant{{ServerId: e.server.Id, Origin: registry.OriginOf(e.server.Url), Scopes: []string{"repo"}}})
	mustCode(t, "assign", code, ec, 200, "")
	e.scalar(`UPDATE service_connections SET expires_at=now() WHERE id=$1 RETURNING 'ok'`, c.Id)
	return e, cfg, c, key
}

func serviceRefreshPoolNetworks(t *testing.T, e *provEnv, entries []any) {
	t.Helper()
	var st apitypes.NetworkSettings
	if code := e.admin.get(networkPath, &st); code != 200 {
		t.Fatalf("get network settings = %d", code)
	}
	code, ec := e.admin.call("PUT", networkPath, map[string]any{"entries": entries}, nil, ifMatch(st.Revision))
	mustCode(t, "set networks", code, ec, 200, "")
}

func serviceRefreshPoolHandlers(t *testing.T, e *provEnv, cfg config.Config, maxConns int32) (*pgxpool.Pool, []string) {
	t.Helper()
	// Copy the actual runtime login, password and hooks, NOT OwnerPool's
	// credentials (and not SET ROLE on an owner-authenticated connection).
	pc := e.app.Pool.Config().Copy()
	pc.MaxConns, pc.MinConns, pc.MinIdleConns = maxConns, 0, 0
	pool, err := pgxpool.NewWithConfig(context.Background(), pc)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var login, role string
	if err := pool.QueryRow(ctx, `SELECT session_user, current_user`).Scan(&login, &role); err != nil {
		t.Fatal(err)
	}
	if login != pc.ConnConfig.User || role != login {
		t.Fatalf("bounded pool did not authenticate as the fixture runtime: login=%q role=%q", login, role)
	}
	var replicas []string
	for range 2 {
		d, err := app.NewDeps(cfg, pool, testutil.Logger())
		if err != nil {
			t.Fatal(err)
		}
		h := httpapi.NewAPIHandler(d)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// This also bounds server-side work if the client disconnects.
			ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
			defer cancel()
			h.ServeHTTP(w, r.WithContext(ctx))
		}))
		t.Cleanup(srv.Close)
		replicas = append(replicas, srv.URL)
	}
	return pool, replicas
}

func serviceRefreshPoolCalls(t *testing.T, e *provEnv, pool *pgxpool.Pool, replicas []string, id uuid.UUID, key string, calls int) []oauthConcurrentResponse {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan oauthConcurrentResponse, calls)
	start := make(chan struct{})
	for i := range calls {
		body, err := json.Marshal(rpc(i, "tools/call", map[string]any{"name": f3Tool}))
		if err != nil {
			t.Fatal(err)
		}
		req, err := http.NewRequestWithContext(ctx, "POST", replicas[i%len(replicas)]+"/mcp/support", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+key)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		go func() {
			<-start
			res, err := http.DefaultClient.Do(req)
			if err != nil {
				done <- oauthConcurrentResponse{err: err}
				return
			}
			defer res.Body.Close()
			body, err := io.ReadAll(res.Body)
			done <- oauthConcurrentResponse{status: res.StatusCode, body: body, err: err}
		}()
	}
	close(start)
	results := make([]oauthConcurrentResponse, 0, calls)
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	observed := false
	for len(results) < calls {
		select {
		case r := <-done:
			results = append(results, r)
		case <-tick.C:
			if observed || pool.Stat().MaxConns() != 1 || pool.Stat().AcquiredConns() != 1 {
				continue
			}
			// An external NOWAIT probe proves the runtime transaction owns the
			// row while occupying the only connection. No timing sleep or
			// additional pool consumer is used to manufacture starvation.
			probeCtx, probeCancel := context.WithTimeout(context.Background(), time.Second)
			tx, err := e.app.Pool.Begin(probeCtx)
			if err == nil {
				_, err = tx.Exec(probeCtx, `SELECT id FROM service_connections WHERE id=$1 FOR UPDATE NOWAIT`, id)
				_ = tx.Rollback(probeCtx)
			}
			probeCancel()
			if pe, ok := err.(*pgconn.PgError); ok && pe.Code == "55P03" {
				observed = true
				t.Log("SQL NOWAIT confirmed the service-connection row is locked while the runtime pool's sole connection is occupied")
			}
		}
	}
	return results
}
