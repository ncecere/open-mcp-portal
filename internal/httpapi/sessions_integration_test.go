package httpapi_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ncecere/open-mcp-portal/internal/auth"
	"github.com/ncecere/open-mcp-portal/internal/config"
	"github.com/ncecere/open-mcp-portal/internal/httpapi"
	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

func browserSessionID(t *testing.T, s *session) string {
	t.Helper()
	for _, c := range s.client.Jar.Cookies(mustParse(t, s.app.URL)) {
		if c.Name == auth.SessionCookieName(false) {
			var id string
			if err := s.app.Pool.QueryRow(context.Background(), `SELECT id::text FROM sessions WHERE token_digest = $1`, auth.Digest(c.Value)).Scan(&id); err != nil {
				t.Fatal(err)
			}
			return id
		}
	}
	t.Fatal("missing session cookie")
	return ""
}

func sessionExec(t *testing.T, app *testApp, sql string, args ...any) {
	t.Helper()
	if _, err := app.Pool.Exec(context.Background(), sql, args...); err != nil {
		t.Fatal(err)
	}
}

func TestBrowserSessions(t *testing.T) {
	app := newTestApp(t, nil)
	me, other, foreign := app.signIn("alex"), app.signIn("alex"), app.signIn("blair")
	admin, auditor := app.signIn("admin"), app.signIn("auditor")
	current, remote, foreignID := browserSessionID(t, me), browserSessionID(t, other), browserSessionID(t, foreign)
	sessionExec(t, app, `UPDATE sessions SET user_agent = 'Chrome/120 on Mac', client_ip = '192.0.2.4' WHERE id = $1`, remote)
	var list []apitypes.BrowserSession
	if code := me.get("/v1/me/sessions", &list); code != 200 || len(list) != 2 {
		t.Fatalf("list = %d %+v", code, list)
	}
	currents := 0
	for _, x := range list {
		if x.Current {
			currents++
			if x.Id.String() != current {
				t.Fatal("wrong current session")
			}
		}
		if x.Id.String() == remote && (x.ClientIp != "192.0.2.4" || x.UserAgent != "Chrome/120 on Mac") {
			t.Fatalf("metadata = %+v", x)
		}
	}
	if currents != 1 {
		t.Fatalf("current markers = %d", currents)
	}
	_, raw := me.raw("GET", "/v1/me/sessions", nil, nil)
	for _, secret := range []string{"tokenDigest", "token_digest", "csrfToken", "csrf_token", me.csrf} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("session list leaked %q", secret)
		}
	}
	for _, id := range []string{foreignID, "00000000-0000-0000-0000-000000000000"} {
		code, ec := me.call("DELETE", "/v1/me/sessions/"+id, nil, nil, nil)
		mustCode(t, "foreign/unknown", code, ec, 404, "session_not_found")
	}
	code, ec := me.call("DELETE", "/v1/me/sessions/"+remote, nil, nil, map[string]string{"X-CSRF-Token": "wrong"})
	mustCode(t, "csrf", code, ec, 403, "csrf_failed")
	code, ec = me.call("DELETE", "/v1/me/sessions/"+remote, nil, nil, nil)
	mustCode(t, "revoke", code, ec, 200, "")
	if other.get("/v1/me", nil) != 401 {
		t.Fatal("revoked browser still works")
	}
	if me.get("/v1/me", nil) != 200 || foreign.get("/v1/me", nil) != 200 {
		t.Fatal("unrelated session revoked")
	}
	path := "/v1/admin/users/" + me.me.User.Id.String() + "/sessions"
	for _, s := range []*session{foreign, auditor} {
		for _, method := range []string{"GET", "DELETE"} {
			code, ec = s.call(method, path, nil, nil, nil)
			mustCode(t, "admin only", code, ec, 403, "forbidden")
		}
	}
	if code := admin.get(path, &list); code != 200 || len(list) != 1 || list[0].Current {
		t.Fatalf("admin list = %d %+v", code, list)
	}
	for _, method := range []string{"GET", "DELETE"} {
		code, ec = admin.call(method, "/v1/admin/users/00000000-0000-0000-0000-000000000000/sessions", nil, nil, nil)
		mustCode(t, "unknown user", code, ec, 404, "user_not_found")
	}
	code, ec = admin.call("DELETE", path, nil, nil, nil)
	mustCode(t, "admin revoke", code, ec, 200, "")
	if me.get("/v1/me", nil) != 401 {
		t.Fatal("admin revoked browser still works")
	}
	if foreign.get("/v1/me", nil) != 200 {
		t.Fatal("foreign browser revoked")
	}
	var actions int
	if err := app.Pool.QueryRow(context.Background(), `SELECT count(*) FROM audit_log WHERE action IN ('session.revoke','session.admin_revoke') AND target_type = 'user' AND metadata = '{"count":1}'::jsonb`).Scan(&actions); err != nil || actions != 2 {
		t.Fatalf("audits = %d %v", actions, err)
	}
}

func TestSignOutEverywhere(t *testing.T) {
	app := newTestApp(t, nil)
	me, other := app.signIn("alex"), app.signIn("alex")
	foreign := app.signIn("blair")
	var list []apitypes.BrowserSession
	code, ec := me.call("POST", "/v1/me/sessions/revoke-all", map[string]any{"keepCurrent": true}, nil, nil)
	mustCode(t, "keep current", code, ec, 200, "")
	if other.get("/v1/me", nil) != 401 || me.get("/v1/me", nil) != 200 {
		t.Fatal("wrong sessions kept")
	}
	if me.get("/v1/me/sessions", &list) != 200 || len(list) != 1 || !list[0].Current {
		t.Fatalf("kept = %+v", list)
	}
	code, ec = me.call("POST", "/v1/me/sessions/revoke-all", map[string]any{"unexpected": true}, nil, nil)
	mustCode(t, "strict body", code, ec, 400, "")
	another := app.signIn("alex")
	code, ec = me.call("POST", "/v1/me/sessions/revoke-all", nil, nil, nil)
	mustCode(t, "default ends current", code, ec, 200, "")
	if another.get("/v1/me", nil) != 401 || me.get("/v1/me", nil) != 401 {
		t.Fatal("sign out everywhere left a session")
	}
	if foreign.get("/v1/me", nil) != 200 {
		t.Fatal("foreign browser revoked")
	}
	// A single-session self-revoke also clears the cookie.
	self := app.signIn("alex")
	id := browserSessionID(t, self)
	code, ec = self.call("DELETE", "/v1/me/sessions/"+id, nil, nil, nil)
	mustCode(t, "self revoke", code, ec, 200, "")
	if self.get("/v1/me", nil) != 401 {
		t.Fatal("self revoked browser still works")
	}
}

func TestSessionActivityAndIdleExpiry(t *testing.T) {
	for _, idle := range []time.Duration{0, 30 * time.Minute} {
		t.Run(fmt.Sprint(idle), func(t *testing.T) {
			// Requests and the test clock are synchronized; safe under -race too.
			var mu sync.RWMutex
			now := time.Now().UTC()
			clock := func() time.Time { mu.RLock(); defer mu.RUnlock(); return now }
			advance := func(d time.Duration) { mu.Lock(); now = now.Add(d); mu.Unlock() }
			var service *auth.Service
			app := newTestAppDeps(t, func(c *config.Config) { c.SessionIdleTimeout = idle }, testutil.Logger(), func(d *httpapi.Deps) { service = d.Auth.WithClock(clock) })
			me := app.signIn("alex")
			id := browserSessionID(t, me)
			// PostgreSQL defaults use its own clock; align the activity timestamp exactly.
			sessionExec(t, app, `UPDATE sessions SET last_seen_at = $1, expires_at = $1::timestamptz + interval '12 hours' WHERE id = $2`, clock(), id)
			seen := func() time.Time {
				var out time.Time
				if err := app.Pool.QueryRow(context.Background(), `SELECT last_seen_at FROM sessions WHERE id=$1`, id).Scan(&out); err != nil {
					t.Fatal(err)
				}
				return out
			}
			first := seen()
			advance(59 * time.Second)
			if me.get("/v1/me", nil) != 200 || !seen().Equal(first) {
				t.Fatal("activity written before one minute")
			}
			advance(time.Second)
			if me.get("/v1/me", nil) != 200 || !seen().After(first) {
				t.Fatal("activity not updated at one minute")
			}
			touched := seen()
			for range 3 {
				if me.get("/v1/me/sessions", nil) != 200 {
					t.Fatal("list failed")
				}
			}
			if !seen().Equal(touched) {
				t.Fatal("activity written more than once a minute")
			}
			// Top-level entry points must also touch, and refuse either expiry.
			req, _ := http.NewRequest("GET", app.URL+"/oauth/authorize", nil)
			for _, cookie := range me.client.Jar.Cookies(mustParse(t, app.URL)) {
				req.AddCookie(cookie)
			}
			advance(time.Minute)
			if _, ok, err := service.SessionUser(req); err != nil || !ok {
				t.Fatalf("SessionUser: %v %v", ok, err)
			}
			if !seen().After(touched) {
				t.Fatal("SessionUser did not touch")
			}
			touched = seen()
			advance(time.Minute)
			if _, ok, err := service.SessionIdentity(req); err != nil || !ok {
				t.Fatalf("SessionIdentity: %v %v", ok, err)
			}
			if !seen().After(touched) {
				t.Fatal("SessionIdentity did not touch")
			}
			advance(30 * time.Minute)
			if idle != 0 {
				if _, ok, _ := service.SessionUser(req); ok {
					t.Fatal("idle SessionUser accepted")
				}
				if _, ok, _ := service.SessionIdentity(req); ok {
					t.Fatal("idle SessionIdentity accepted")
				}
				code, raw := me.raw("GET", "/v1/me", nil, nil)
				if code != 401 || !strings.Contains(string(raw), "Your session has expired") {
					t.Fatalf("idle response = %d %s", code, raw)
				}
				n, _, err := service.Cleanup(context.Background())
				if err != nil || n != 1 {
					t.Fatalf("idle cleanup = %d %v", n, err)
				}
			} else {
				n, _, err := service.Cleanup(context.Background())
				if err != nil || n != 0 {
					t.Fatalf("disabled cleanup = %d %v", n, err)
				}
				if me.get("/v1/me", nil) != 200 {
					t.Fatal("idle timeout off changed behavior")
				}
			}
			absolute := app.signIn("blair")
			absoluteID := browserSessionID(t, absolute)
			sessionExec(t, app, `UPDATE sessions SET expires_at = $1 WHERE id = $2`, clock(), absoluteID)
			if absolute.get("/v1/me", nil) != 401 {
				t.Fatal("absolute expiry accepted")
			}
			n, _, err := service.Cleanup(context.Background())
			if err != nil || n != 1 {
				t.Fatalf("absolute cleanup = %d %v", n, err)
			}
		})
	}
}

func TestSessionRevocationAuditRollback(t *testing.T) {
	app := newTestApp(t, nil)
	me, remote := app.signIn("alex"), app.signIn("alex")
	id := browserSessionID(t, remote)
	// Force the audit insert to fail: the mutation must roll back with it.
	if _, err := testutil.OwnerPool(t, app.Pool).Exec(context.Background(), `CREATE FUNCTION reject_session_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action LIKE 'session.%' THEN RAISE EXCEPTION 'audit unavailable'; END IF; RETURN NEW; END $$;
 CREATE TRIGGER reject_session_audit BEFORE INSERT ON audit_log FOR EACH ROW EXECUTE FUNCTION reject_session_audit()`); err != nil {
		t.Fatal(err)
	}
	code, raw := me.raw("DELETE", "/v1/me/sessions/"+id, nil, nil)
	if code != 500 {
		t.Fatalf("failed audit = %d %s", code, raw)
	}
	if remote.get("/v1/me", nil) != 200 {
		t.Fatal("revocation escaped rollback")
	}
	if _, err := testutil.OwnerPool(t, app.Pool).Exec(context.Background(), `DROP TRIGGER reject_session_audit ON audit_log; DROP FUNCTION reject_session_audit()`); err != nil {
		t.Fatal(err)
	}
	code, raw = me.raw("DELETE", "/v1/me/sessions/"+id, nil, nil)
	if code != 200 {
		t.Fatalf("retry = %d %s", code, raw)
	}
	var env struct{ Data apitypes.Ok }
	if err := json.Unmarshal(raw, &env); err != nil || !env.Data.Ok {
		t.Fatalf("reply = %s %v", raw, err)
	}
}
