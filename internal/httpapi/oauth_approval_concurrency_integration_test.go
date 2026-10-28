package httpapi_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

// An audit BEFORE INSERT trigger pauses a real service transaction after it
// owns the grant, but before the audit actor FK takes KEY SHARE on users. All
// trigger/function changes live only in this test's disposable database.
type oauthAuditGate struct {
	t   *testing.T
	e   *oauthEnv
	ctx context.Context
	tx  pgx.Tx
}

func pauseOAuthAudit(t *testing.T, e *oauthEnv, grantID, action string) *oauthAuditGate {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	tx, err := e.app.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		_ = tx.Rollback(cleanup)
	})
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(719229, 1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := testutil.OwnerPool(t, e.app.Pool).Exec(ctx, fmt.Sprintf(`
CREATE FUNCTION pause_oauth_audit() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  PERFORM pg_advisory_xact_lock(719229, 1);
  RETURN NEW;
END $$;
CREATE TRIGGER pause_oauth_audit BEFORE INSERT ON audit_log
FOR EACH ROW WHEN (NEW.target_id = '%s' AND NEW.action = '%s')
EXECUTE FUNCTION pause_oauth_audit();`, strings.ReplaceAll(grantID, "'", "''"), strings.ReplaceAll(action, "'", "''"))); err != nil {
		t.Fatal(err)
	}
	return &oauthAuditGate{t: t, e: e, ctx: ctx, tx: tx}
}

// Completion is never inferred from elapsed time: every scheduling edge is
// observed in PostgreSQL's lock graph. The ticker only bounds inspection load.
func (g *oauthAuditGate) blocked(label string, blocker int32, event, queryPart string) int32 {
	g.t.Helper()
	ctx, cancel := context.WithTimeout(g.ctx, 5*time.Second)
	defer cancel()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		var pid int32
		err := g.e.app.Pool.QueryRow(ctx, `SELECT coalesce((SELECT pid FROM pg_stat_activity
 WHERE datname=current_database() AND wait_event_type='Lock'
 AND $1::int = ANY(pg_blocking_pids(pid))
 AND ($2::text = '' OR wait_event=$2) AND strpos(query, $3)>0
 LIMIT 1), 0)`, blocker, event, queryPart).Scan(&pid)
		if err != nil {
			g.t.Fatalf("inspect %s: %v", label, err)
		}
		if pid != 0 {
			return pid
		}
		select {
		case <-tick.C:
		case <-ctx.Done():
			g.t.Fatalf("%s never blocked on backend %d: %v", label, blocker, ctx.Err())
		}
	}
}

func (g *oauthAuditGate) release() {
	g.t.Helper()
	if err := g.tx.Rollback(g.ctx); err != nil {
		g.t.Fatal(err)
	}
}

type oauthConcurrentResponse struct {
	status int
	body   []byte
	header http.Header
	err    error
}

func (g *oauthAuditGate) launch(s *session, method, path, contentType, body string) <-chan oauthConcurrentResponse {
	g.t.Helper()
	req, err := http.NewRequestWithContext(g.ctx, method, g.e.app.URL+path, strings.NewReader(body))
	if err != nil {
		g.t.Fatal(err)
	}
	req.Header.Set("Content-Type", contentType)
	client := &http.Client{CheckRedirect: noFollow}
	if s != nil {
		client.Jar = s.client.Jar
		req.Header.Set("Origin", g.e.app.URL)
		req.Header.Set("X-CSRF-Token", s.csrf)
	}
	done := make(chan oauthConcurrentResponse, 1)
	go func() {
		res, err := client.Do(req)
		if err != nil {
			done <- oauthConcurrentResponse{err: err}
			return
		}
		defer res.Body.Close()
		body, err := io.ReadAll(res.Body)
		done <- oauthConcurrentResponse{status: res.StatusCode, body: body, header: res.Header, err: err}
	}()
	return done
}

func (g *oauthAuditGate) finish(label string, done <-chan oauthConcurrentResponse, status int) oauthConcurrentResponse {
	g.t.Helper()
	select {
	case got := <-done:
		if got.err != nil || got.status != status {
			g.t.Errorf("%s = %d %s, err=%v; want %d (no deadlock)", label, got.status, got.body, got.err, status)
		}
		return got
	case <-g.ctx.Done():
		g.t.Fatalf("%s did not finish: %v", label, g.ctx.Err())
		return oauthConcurrentResponse{}
	}
}

func (g *oauthAuditGate) narrow(q url.Values) <-chan oauthConcurrentResponse {
	g.t.Helper()
	body, err := json.Marshal(map[string]any{"query": q.Encode(), "decision": "allow", "toolScope": classScope("read")})
	if err != nil {
		g.t.Fatal(err)
	}
	return g.launch(g.e.member, "POST", "/v1/oauth/consent", "application/json", string(body))
}

func concurrentConsentCode(t *testing.T, e *oauthEnv, res oauthConcurrentResponse) string {
	t.Helper()
	var out struct {
		Data struct {
			RedirectURL string `json:"redirectUrl"`
		}
	}
	if err := json.Unmarshal(res.body, &out); err != nil {
		t.Fatal(err)
	}
	return codeFrom(t, e.app, "concurrent narrowing", out.Data.RedirectURL)
}

func TestOAuthApprovalConcurrentWithGrantOperations(t *testing.T) {
	for _, operation := range []string{"refresh", "code_exchange", "client_revocation", "user_revocation"} {
		t.Run(operation, func(t *testing.T) {
			e := scopedOAuthEnv(t)
			p := newPKCE()
			client := e.docs.client("/lock-order.json", "Concurrent", testRedirect)
			q := authQuery(e.app, client, "support", p, nil)
			loc := scopeConsent(t, e.member, q, nil, false)
			status, old := scopeExchange(t, e, client, codeFrom(t, e.app, "initial", loc), p)
			if status != 200 {
				t.Fatal(old)
			}
			oldID := e.scalar(`SELECT id::text FROM oauth_grants WHERE client_id=$1 AND revoked_at IS NULL`, client)
			pending := codeFrom(t, e.app, "pending", scopeConsent(t, e.member, q, nil, false))
			exchangeCode := codeFrom(t, e.app, "exchange", scopeConsent(t, e.member, q, nil, false))

			action, reason := "oauth.token_issue", "scope_changed"
			path, method := "/oauth/token", "POST"
			form := url.Values{"client_id": {client}, "grant_type": {"refresh_token"}, "refresh_token": {old["refresh_token"].(string)}}
			switch operation {
			case "code_exchange":
				form = url.Values{"client_id": {client}, "grant_type": {"authorization_code"}, "code": {exchangeCode}, "code_verifier": {p.verifier}, "redirect_uri": {testRedirect}}
			case "client_revocation":
				action, reason, path = "oauth.revoke", "client", "/oauth/revoke"
				form = url.Values{"client_id": {client}, "token": {old["refresh_token"].(string)}}
			case "user_revocation":
				action, reason = "oauth.revoke", "user"
				path, method = "/v1/me/oauth-grants/"+oldID, "DELETE"
			}
			gate := pauseOAuthAudit(t, e, oldID, action)
			var browser *session
			if operation == "user_revocation" {
				browser = e.member
			}
			op := gate.launch(browser, method, path, "application/x-www-form-urlencoded", form.Encode())
			opPID := gate.blocked("grant operation at audit gate", int32(gate.tx.Conn().PgConn().PID()), "advisory", "")
			approval := gate.narrow(q)
			approvalPID := gate.blocked("approval holding user, waiting for grant", opPID, "", "FROM oauth_grants")
			t.Logf("grant operation backend %d; approval backend %d waits with user serialization lock", opPID, approvalPID)
			// FOR UPDATE on users creates user -> grant -> user here. NO KEY
			// UPDATE allows the audit FK's KEY SHARE so the operation commits.
			gate.release()
			issued := gate.finish(operation, op, 200)
			narrowed := gate.finish("narrowing approval", approval, 200)
			if t.Failed() {
				return
			}

			// The old ceiling is immutable, not edited in place. Narrowing
			// replaces even a grant revoked while approval was waiting.
			if n := e.scalar(`SELECT count(*)::text FROM oauth_grants WHERE client_id=$1`, client); n != "2" {
				t.Fatalf("%s grants; want original and replacement", n)
			}
			if n := e.scalar(`SELECT count(*)::text FROM oauth_grants WHERE id::text=$1 AND tool_scope IS NULL AND revoked_reason=$2 AND revoked_at IS NOT NULL`, oldID, reason); n != "1" {
				t.Fatal("original grant mutated or not revoked for " + reason)
			}
			if n := e.scalar(`SELECT count(*)::text FROM oauth_grants WHERE client_id=$1 AND id::text<>$2 AND revoked_at IS NULL AND tool_scope='{"classes":["read"]}'::jsonb`, client, oldID); n != "1" {
				t.Fatal("replacement missing or widened")
			}
			if n := e.scalar(`SELECT ((SELECT count(*) FROM oauth_tokens WHERE grant_id::text=$1) + (SELECT count(*) FROM oauth_codes WHERE grant_id::text=$1))::text`, oldID); n != "0" {
				t.Fatalf("%s old tokens/codes survived", n)
			}
			if c, out := scopeExchange(t, e, client, pending, p); c != 400 || out["error"] != "invalid_grant" {
				t.Fatalf("old pending code survived: %d %v", c, out)
			}
			pairs := []map[string]any{old}
			if action == "oauth.token_issue" {
				var pair map[string]any
				if err := json.Unmarshal(issued.body, &pair); err != nil {
					t.Fatal(err)
				}
				wantTokenScope(t, pair, "", false)
				pairs = append(pairs, pair)
			}
			for _, pair := range pairs {
				if c, _, _ := rawMCP(t, e.app, "POST", "support", pair["access_token"].(string), rpc(1, "tools/list", nil), nil); c != 401 {
					t.Fatalf("old access survived: %d", c)
				}
				c, out, _ := tokenCall(t, e.app, "/oauth/token", url.Values{"client_id": {client}, "grant_type": {"refresh_token"}, "refresh_token": {pair["refresh_token"].(string)}})
				wantOAuthError(t, "old refresh after replacement", c, out, 400, "invalid_grant")
			}
			status, current := scopeExchange(t, e, client, concurrentConsentCode(t, e, narrowed), p)
			if status != 200 {
				t.Fatal(current)
			}
			wantTokenScope(t, current, "omp:read", true)
			wantScopedList(t, e.rtEnv, true, "support", current["access_token"].(string), "status__whoami")
			wantScopeDenied(t, e.rtEnv, true, "support", current["access_token"].(string), "status__echo")
		})
	}
}

func TestOAuthConcurrentNarrowingCannotSilentlyExpand(t *testing.T) {
	e := scopedOAuthEnv(t)
	p := newPKCE()
	client := e.docs.client("/silent-lock.json", "Concurrent silent", testRedirect)
	trustClients(t, e, client)
	q := authQuery(e.app, client, "support", p, nil)
	scopeConsent(t, e.member, q, nil, false)
	oldID := e.scalar(`SELECT id::text FROM oauth_grants WHERE client_id=$1 AND revoked_at IS NULL`, client)
	gate := pauseOAuthAudit(t, e, oldID, "oauth.revoke")
	narrow := gate.narrow(q)
	narrowPID := gate.blocked("narrowing at audit gate", int32(gate.tx.Conn().PgConn().PID()), "advisory", "")
	// Narrowing is uncommitted, so this HTTP request sees the old remembered
	// ceiling and chooses silent approval before waiting on the user lock.
	silent := gate.launch(e.member, "GET", "/oauth/authorize?"+q.Encode(), "", "")
	gate.blocked("stale silent approval on user serialization", narrowPID, "", "FROM users")
	gate.release()
	narrowed := gate.finish("human narrowing", narrow, 200)
	refused := gate.finish("stale silent approval", silent, 302)
	if t.Failed() {
		return
	}
	if !strings.HasPrefix(refused.header.Get("Location"), "/oauth/consent?") {
		t.Fatalf("silent expansion was not sent for confirmation: %s", refused.header.Get("Location"))
	}
	if n := e.scalar(`SELECT count(*)::text FROM oauth_codes`); n != "1" {
		t.Fatalf("%s pending codes; want only human narrowing's code", n)
	}
	if n := e.scalar(`SELECT count(*)::text FROM oauth_grants WHERE client_id=$1`, client); n != "2" {
		t.Fatalf("silent expansion created another grant: %s", n)
	}
	status, current := scopeExchange(t, e, client, concurrentConsentCode(t, e, narrowed), p)
	if status != 200 {
		t.Fatal(current)
	}
	wantTokenScope(t, current, "omp:read", true)
}
