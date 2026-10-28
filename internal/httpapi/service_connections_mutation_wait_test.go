package httpapi_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/registry"
)

// All scheduling edges are observed in the disposable database's lock graph;
// elapsed time never stands in for a request reaching its blocking lock.
type serviceMutationWait struct {
	t        *testing.T
	e        *provEnv
	ctx      context.Context
	tx       pgx.Tx
	pid      int32
	observer *pgx.Conn
}

func pauseServiceMutation(t *testing.T, e *provEnv, lock string, args ...any) *serviceMutationWait {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	tx, err := e.app.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tx.Rollback(context.Background()) })
	observer, err := pgx.ConnectConfig(ctx, e.app.Pool.Config().ConnConfig.Copy())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = observer.Close(context.Background()) })
	g := &serviceMutationWait{t: t, e: e, ctx: ctx, tx: tx, observer: observer}
	if err := tx.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&g.pid); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, lock, args...); err != nil {
		t.Fatal(err)
	}
	return g
}

func (g *serviceMutationWait) blocked(queryPart string) {
	g.t.Helper()
	ctx, cancel := context.WithTimeout(g.ctx, 5*time.Second)
	defer cancel()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		var waiting bool
		err := g.observer.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity
WHERE datname=current_database() AND wait_event_type='Lock'
AND $1::int = ANY(pg_blocking_pids(pid)) AND strpos(query,$2)>0)`, g.pid, queryPart).Scan(&waiting)
		if err != nil {
			var dump string
			_ = g.e.app.Pool.QueryRow(g.ctx, `SELECT coalesce(json_agg(a)::text,'') FROM (SELECT pid,wait_event,query,pg_blocking_pids(pid) AS blockers FROM pg_stat_activity WHERE datname=current_database()) a`).Scan(&dump)
			g.t.Fatalf("observe lock: %v; %s", err, dump)
		}
		if waiting {
			return
		}
		select {
		case <-tick.C:
		case <-ctx.Done():
			g.t.Fatalf("mutation never queued on %s: %v", queryPart, ctx.Err())
		}
	}
}

func (g *serviceMutationWait) launch(method, path string, body any, rev int64) <-chan oauthConcurrentResponse {
	g.t.Helper()
	b, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(g.ctx, method, g.e.app.URL+path, strings.NewReader(string(b)))
	if err != nil {
		g.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", g.e.app.URL)
	req.Header.Set("X-CSRF-Token", g.e.owner.csrf)
	req.Header.Set("If-Match", fmt.Sprintf(`"%d"`, rev))
	client := &http.Client{Jar: g.e.owner.client.Jar, CheckRedirect: noFollow}
	done := make(chan oauthConcurrentResponse, 1)
	go func() {
		res, err := client.Do(req)
		if err != nil {
			done <- oauthConcurrentResponse{err: err}
			return
		}
		defer res.Body.Close()
		b, err := io.ReadAll(res.Body)
		done <- oauthConcurrentResponse{status: res.StatusCode, body: b, err: err}
	}()
	return done
}

func (g *serviceMutationWait) finish(done <-chan oauthConcurrentResponse, status int, code string) {
	g.t.Helper()
	select {
	case res := <-done:
		if res.err != nil || res.status != status {
			g.t.Fatalf("mutation = %d %s: %v", res.status, res.body, res.err)
		}
		if code != "" && !strings.Contains(string(res.body), `"code":"`+code+`"`) {
			g.t.Fatalf("want %s: %s", code, res.body)
		}
	case <-g.ctx.Done():
		g.t.Fatal("queued mutation did not finish")
	}
}

func serviceMutationSnapshot(e *provEnv) string {
	return e.scalar(`SELECT json_build_object(
'connections',(SELECT json_agg(c ORDER BY id) FROM service_connections c),
'accounts',(SELECT json_agg(a ORDER BY connection_id,service_account_id) FROM service_connection_accounts a),
'grants',(SELECT json_agg(g ORDER BY connection_id,server_id) FROM service_connection_server_grants g),
'states',(SELECT json_agg(s ORDER BY state_digest) FROM service_connection_auth_states s),
'audits',(SELECT count(*) FROM audit_log WHERE action LIKE 'service_connection.%'))::text`)
}

func TestServiceConnectionMutationsRecheckAuthorityAfterWait(t *testing.T) {
	for _, action := range []string{"update", "update_server", "assignment", "reconnect", "revoke", "start"} {
		for _, change := range []string{"demotion", "suspension", "archive"} {
			t.Run(action+"/"+change, func(t *testing.T) {
				e := newProvEnv(t)
				c := sharedByNameAfterStart(t, e)
				var account uuid.UUID
				if action == "assignment" {
					account = createSA(t, e.owner, map[string]any{"name": "queued-assignment"}).Id
				}
				before := serviceMutationSnapshot(e)
				lock, args, query := `SELECT 1 FROM service_connections WHERE id=$1 FOR UPDATE`, []any{c.Id}, "-- name: LockServiceConnection"
				method, path, body := "PUT", sharedBase+"/"+c.Id.String(), any(map[string]any{"accounts": []uuid.UUID{}, "servers": []apitypes.ServiceConnectionGrant{}})
				switch action {
				case "assignment":
					lock, args, query = `SELECT 1 FROM service_accounts WHERE id=$1 FOR UPDATE`, []any{account}, "INSERT INTO service_connection_accounts"
					body = map[string]any{"accounts": []uuid.UUID{account}, "servers": []apitypes.ServiceConnectionGrant{}}
				case "update_server":
					lock, args, query = `SELECT 1 FROM mcp_servers WHERE id=$1 FOR UPDATE`, []any{e.server.Id}, "-- name: LockMCPServer"
					body = map[string]any{"accounts": []uuid.UUID{}, "servers": []apitypes.ServiceConnectionGrant{{ServerId: e.server.Id, Origin: registry.OriginOf(e.server.Url), Scopes: []string{"repo"}}}}
				case "reconnect":
					method, path, body = "POST", path+"/reconnect", nil
				case "revoke":
					method, body = "DELETE", nil
				case "start":
					lock, args, query = `SELECT pg_advisory_xact_lock(hashtextextended('service-connections:' || $1::text,0))`, []any{c.TeamId.String()}, "service-connections:"
					method, path, body = "POST", sharedBase, map[string]any{"providerId": e.provider.Id, "name": "queued"}
				}
				g := pauseServiceMutation(t, e, lock, args...)
				done := g.launch(method, path, body, c.Revision)
				g.blocked(query)
				var sql string
				switch change {
				case "demotion":
					sql = `UPDATE team_members SET role='editor' WHERE user_id=(SELECT connected_by FROM service_connections WHERE id=$1)`
				case "suspension":
					sql = `UPDATE users SET status='suspended' WHERE id=(SELECT connected_by FROM service_connections WHERE id=$1)`
				case "archive":
					sql = `UPDATE teams SET status='archived' WHERE id=(SELECT team_id FROM service_connections WHERE id=$1)`
				}
				if _, err := g.tx.Exec(g.ctx, sql, c.Id); err != nil {
					t.Fatal(err)
				}
				if err := g.tx.Commit(g.ctx); err != nil {
					t.Fatal(err)
				}
				g.finish(done, 403, "forbidden")
				if after := serviceMutationSnapshot(e); after != before {
					t.Fatal("unauthorized queued action changed connections, assignments, consent or audit")
				}
			})
		}
	}
}

func sharedByNameAfterStart(t *testing.T, e *provEnv) apitypes.ServiceConnection {
	t.Helper()
	startShared(t, e.owner, e.provider.Id, "queued-target")
	return sharedByName(t, e.owner, "queued-target")
}

func TestServiceConnectionGrantProofAfterServerWait(t *testing.T) {
	for _, proof := range []string{"stale", "current"} {
		t.Run(proof, func(t *testing.T) {
			e := newProvEnv(t)
			c := sharedByNameAfterStart(t, e)
			before := serviceMutationSnapshot(e)
			g := pauseServiceMutation(t, e, `SELECT 1 FROM mcp_servers WHERE id=$1 FOR UPDATE`, e.server.Id)
			scopes := []string{"repo"}
			if proof == "current" {
				scopes = append(scopes, "write")
			}
			done := g.launch("PUT", sharedBase+"/"+c.Id.String(), map[string]any{"accounts": []uuid.UUID{}, "servers": []apitypes.ServiceConnectionGrant{{ServerId: e.server.Id, Origin: registry.OriginOf(e.server.Url), Scopes: scopes}}}, c.Revision)
			g.blocked("-- name: LockMCPServer")
			if _, err := g.tx.Exec(g.ctx, `UPDATE mcp_servers SET auth_scopes=ARRAY['repo','write'], revision=revision+1 WHERE id=$1`, e.server.Id); err != nil {
				t.Fatal(err)
			}
			if err := g.tx.Commit(g.ctx); err != nil {
				t.Fatal(err)
			}
			if proof == "stale" {
				g.finish(done, 409, "server_changed")
				if after := serviceMutationSnapshot(e); after != before {
					t.Fatal("stale scope proof changed transaction state")
				}
			} else {
				g.finish(done, 200, "")
				if n := e.scalar(`SELECT count(*)::text FROM service_connection_server_grants WHERE connection_id=$1 AND scopes @> ARRAY['repo','write']`, c.Id); n != "1" {
					t.Fatal("current proof was not stored")
				}
			}
		})
	}
}

func TestServiceConnectionGrantProofAfterConnectionWait(t *testing.T) {
	for _, change := range []string{"scopes", "current_scopes", "assignment_scopes", "provider_access", "visibility"} {
		t.Run(change, func(t *testing.T) {
			e := newProvEnv(t)
			// Empty server scopes inherit current provider defaults. Provider
			// edits can commit while the destination is locked by the writer.
			e.setRequirement(map[string]any{"providerId": e.provider.Id, "scopes": []string{}})
			c := sharedByNameAfterStart(t, e)
			accounts := []uuid.UUID{}
			lock, target, query := `SELECT 1 FROM service_connections WHERE id=$1 FOR UPDATE`, c.Id, "-- name: LockServiceConnection"
			if change == "assignment_scopes" {
				aid := createSA(t, e.owner, map[string]any{"name": "queued-proof"}).Id
				accounts = append(accounts, aid)
				lock, target, query = `SELECT 1 FROM service_accounts WHERE id=$1 FOR UPDATE`, aid, "INSERT INTO service_connection_accounts"
			}
			before := serviceMutationSnapshot(e)
			g := pauseServiceMutation(t, e, lock, target)
			scopes := []string{"read:user"}
			if change == "current_scopes" {
				scopes = append(scopes, "write")
			}
			done := g.launch("PUT", sharedBase+"/"+c.Id.String(), map[string]any{"accounts": accounts, "servers": []apitypes.ServiceConnectionGrant{{ServerId: e.server.Id, Origin: registry.OriginOf(e.server.Url), Scopes: scopes}}}, c.Revision)
			g.blocked(query)
			sql, status, code := `UPDATE auth_providers SET default_scopes=ARRAY['read:user','write'],revision=revision+1 WHERE id=$1`, 409, "server_changed"
			target = e.provider.Id
			switch change {
			case "current_scopes":
				status, code = 200, ""
			case "provider_access":
				sql, status, code = `UPDATE auth_providers SET access_mode='restricted',revision=revision+1 WHERE id=$1`, 422, "provider_not_allowed"
			case "visibility":
				sql, status, code, target = `UPDATE gateways SET enabled=false WHERE id=$1`, 404, "server_not_found", e.gateway.Id
			}
			if _, err := g.tx.Exec(g.ctx, sql, target); err != nil {
				t.Fatal(err)
			}
			if err := g.tx.Commit(g.ctx); err != nil {
				t.Fatal(err)
			}
			g.finish(done, status, code)
			if status != 200 {
				if after := serviceMutationSnapshot(e); after != before {
					t.Fatal("pre-connection-wait proof changed transaction state")
				}
			} else if n := e.scalar(`SELECT count(*)::text FROM service_connection_server_grants WHERE connection_id=$1 AND scopes @> ARRAY['read:user','write']`, c.Id); n != "1" {
				t.Fatal("current post-wait provider scope proof was not stored")
			}
			if e.oauth.TokenRequests() != 0 || e.oauth.RefreshRequests() != 0 {
				t.Fatal("grant validation made an OAuth network request")
			}
		})
	}
}
