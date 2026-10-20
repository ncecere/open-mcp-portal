package httpapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ncecere/open-mcp-portal/internal/automation"
	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/secrets"
)

// The token matrix (docs/automation-tokens.md, "Tests that must exist";
// docs/threat-model.md 10.2): every operation of the spec is called with
// every kind of token credential, built from the same request builders as the
// session matrix.
//
//   - annotated operation, scope held: never 401, never token_not_allowed or
//     session_required, never 500; on another team's path, 404 team_not_found;
//   - every other operation: 403 token_not_allowed (the four token-management
//     operations: 403 session_required), whatever the scopes;
//   - expired, revoked, creator-demoted tokens, MCP keys and OAuth tokens:
//     401 invalid_token everywhere.

const tokenBodyLen = 43

func tokenSecret(prefix string, n int) string {
	return prefix + fmt.Sprintf("%0*d", tokenBodyLen, n)
}

type tokenCred struct {
	name   string
	secret string
	kind   string
	team   string // the token's team ID
	scopes []string
	// invalid: the credential must answer 401 invalid_token.
	invalid bool
}

func (e *matrixEnv) pepper() []byte {
	// The test deployment's API_KEY_PEPPER (distinct from ENCRYPTION_KEY: the
	// config refuses equal values).
	key, err := secrets.ParseKey(testPepper)
	if err != nil {
		e.t.Fatal(err)
	}
	return key
}

// mintToken inserts a token with a known secret.
func (e *matrixEnv) mintToken(kind, teamID, creator, secret string, scopes []string, created, expires, revoked string) string {
	digest := automation.Digest(e.pepper(), secret)
	pepperID := fmt.Sprintf("%x", secrets.KeyID(e.pepper()))
	var team any
	if teamID != "" {
		team = teamID
	}
	return e.exec(`INSERT INTO automation_tokens (kind, team_id, name, prefix, digest, pepper_id, scopes, created_by, created_by_name, created_at, expires_at, revoked_at)
		VALUES ($1, $2::uuid, $3::text, $4, $5, decode($6, 'hex'), $7::text[], NULLIF($8, '')::uuid, 'matrix',
		        now() + $9::interval, now() + $10::interval, CASE WHEN $11 <> '' THEN now() END) RETURNING id::text`,
		kind, team, fmt.Sprintf("tok-%d", e.next()), secret[:15], digest, pepperID, scopes, creator, created, expires, revoked)
}

func (e *matrixEnv) tokenCreds() []tokenCred {
	admin := e.userIDs[cPlatformAdmin]
	mk := func(name, kind, team, creator string, n int, scopes []string, created, expires, revoked string) tokenCred {
		prefix := "ompadm_"
		if kind == "team_publisher" {
			prefix = "omppub_"
		}
		s := tokenSecret(prefix, n)
		e.mintToken(kind, team, creator, s, scopes, created, expires, revoked)
		return tokenCred{name: name, secret: s, kind: kind, team: team, scopes: scopes}
	}
	read, write := []string{"platform:read"}, []string{"platform:read", "platform:write"}
	sRead, sWrite := []string{"servers:read"}, []string{"servers:read", "servers:write"}
	creds := []tokenCred{
		mk("platform-read", "platform_admin", "", admin, 1, read, "-1 hour", "1 day", ""),
		mk("platform-write", "platform_admin", "", admin, 2, write, "-1 hour", "1 day", ""),
		mk("publisher-read", "team_publisher", e.b.id, "", 3, sRead, "-1 hour", "1 day", ""),
		mk("publisher-write", "team_publisher", e.b.id, "", 4, sWrite, "-1 hour", "1 day", ""),
		mk("publisher-write-other-team", "team_publisher", e.a.id, "", 5, sWrite, "-1 hour", "1 day", ""),
	}
	// Invalid credentials.
	expired := mk("expired", "platform_admin", "", admin, 6, write, "-2 days", "-1 hour", "")
	revoked := mk("revoked", "platform_admin", "", admin, 7, write, "-1 hour", "1 day", "x")
	demotedUser := e.newUser("demoted@example.com", "platform_auditor")
	demoted := mk("creator-demoted", "platform_admin", "", demotedUser, 8, write, "-1 hour", "1 day", "")
	expiredPub := mk("expired-publisher", "team_publisher", e.b.id, "", 9, sWrite, "-2 days", "-1 hour", "")
	for _, c := range []*tokenCred{&expired, &revoked, &demoted, &expiredPub} {
		c.invalid = true
		creds = append(creds, *c)
	}
	creds = append(creds,
		tokenCred{name: "mcp-key", secret: "omp_" + strings.Repeat("k", tokenBodyLen), invalid: true},
		tokenCred{name: "service-account-key", secret: "omp_sa_" + strings.Repeat("k", tokenBodyLen), invalid: true},
		tokenCred{name: "oauth-token", secret: "ompat_" + strings.Repeat("o", tokenBodyLen), invalid: true},
		tokenCred{name: "refresh-token", secret: "omprt_" + strings.Repeat("o", tokenBodyLen), invalid: true},
		tokenCred{name: "unknown-token", secret: tokenSecret("ompadm_", 99), invalid: true},
	)
	return creds
}

// bearer sends a request with an Authorization header, no cookie, no Origin
// and no CSRF token.
func (e *matrixEnv) bearer(secret string, req request) (int, http.Header, []byte) {
	e.t.Helper()
	var rdr io.Reader
	if req.body != nil {
		b, _ := json.Marshal(req.body)
		rdr = bytes.NewReader(b)
	}
	r, _ := http.NewRequest(req.method, e.app.URL+req.path, rdr)
	if req.body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	if secret != "" {
		r.Header.Set("Authorization", "Bearer "+secret)
	}
	for k, v := range req.headers {
		r.Header.Set(k, v)
	}
	res, err := (&http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(r)
	if err != nil {
		e.t.Fatal(err)
	}
	defer res.Body.Close()
	out, _ := io.ReadAll(res.Body)
	return res.StatusCode, res.Header, out
}

func errCode(body []byte) string { return errorCode(body) }

func TestTokenMatrix(t *testing.T) {
	e := newMatrixEnv(t)
	creds := e.tokenCreds()
	ops := make([]string, 0, len(matrixPolicies))
	for op := range matrixPolicies {
		ops = append(ops, op)
	}
	sort.Strings(ops)
	byOp := map[string]struct{ key string }{}
	for key, o := range apitypes.TokenOperations {
		byOp[o.OperationID] = struct{ key string }{key}
	}
	mgmt := map[string]bool{"adminCreateAutomationToken": true, "adminRevokeAutomationToken": true, "createTeamAutomationToken": true, "revokeTeamAutomationToken": true}
	checked := 0
	for _, op := range ops {
		p := matrixPolicies[op]
		probe := p.build(&mctx{e: e, tf: &e.b, who: cPlatformAdmin, allowed: false})
		if !strings.HasPrefix(probe.path, "/v1/") || probe.path == "/v1/auth/config" {
			continue // sign-in plumbing, probes and the public config
		}
		o, annotated := byOp[op]
		t.Run(op, func(t *testing.T) {
			for _, c := range creds {
				scopeHeld := false
				if annotated {
					for _, s := range apitypes.TokenOperations[o.key].Scopes {
						for _, h := range c.scopes {
							scopeHeld = scopeHeld || s == h
						}
					}
				}
				mayReach := !c.invalid && annotated && scopeHeld && !mgmt[op]
				req := p.build(&mctx{e: e, tf: &e.b, who: cPlatformAdmin, allowed: mayReach})
				code, hdr, body := e.bearer(c.secret, req)
				label := fmt.Sprintf("%s with %s (%s %s)", op, c.name, req.method, req.path)
				if hdr.Get("Set-Cookie") != "" {
					t.Errorf("%s: a cookie was set on a token response", label)
				}
				got := errCode(body)
				switch {
				case code >= 500:
					t.Errorf("%s: %d %s", label, code, body)
				case c.invalid:
					if code != 401 || got != "invalid_token" {
						t.Errorf("%s: %d %s, want 401 invalid_token", label, code, body)
					}
				case mgmt[op]:
					if code != 403 || got != "session_required" {
						t.Errorf("%s: %d %s, want 403 session_required", label, code, body)
					}
				case !annotated || !scopeHeld:
					if code != 403 || got != "token_not_allowed" {
						t.Errorf("%s: %d %s, want 403 token_not_allowed", label, code, body)
					}
					if annotated {
						var env struct {
							Error struct {
								Details struct{ RequiredScopes, TokenScopes []string }
							}
						}
						_ = json.Unmarshal(body, &env)
						if len(env.Error.Details.RequiredScopes) == 0 || len(env.Error.Details.TokenScopes) == 0 {
							t.Errorf("%s: the refusal should name requiredScopes and tokenScopes: %s", label, body)
						}
					}
				case strings.HasPrefix(req.path, "/v1/teams/") && c.team != e.b.id:
					if code != 404 || got != "team_not_found" {
						t.Errorf("%s: %d %s, want 404 team_not_found (another team's token)", label, code, body)
					}
					if strings.Contains(string(body), e.b.id) || strings.Contains(string(body), e.b.name) {
						t.Errorf("%s: the refusal leaks the team: %s", label, body)
					}
				default:
					if code == 401 || (code == 403 && (got == "token_not_allowed" || got == "session_required")) {
						t.Errorf("%s: %d %s, but the token holds the scope", label, code, body)
					}
				}
				checked++
			}
		})
	}
	if checked < 150*len(creds) {
		t.Errorf("only %d calls checked: the matrix lost operations", checked)
	}
}

// Tokens never reach /mcp: both prefixes get the same 401 challenge as any
// unknown credential, without a lookup (a revoked or valid token behaves the
// same), and MCP credentials never authorize /v1.
func TestTokensNeverReachMCP(t *testing.T) {
	e := newMatrixEnv(t)
	slug := e.exec(`SELECT slug FROM gateways WHERE id = $1`, e.platformGateway)
	creds := e.tokenCreds()
	for _, c := range creds {
		if c.scopes == nil {
			continue
		}
		r, _ := http.NewRequest("POST", e.app.URL+"/mcp/"+slug, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Accept", "application/json, text/event-stream")
		r.Header.Set("Authorization", "Bearer "+c.secret)
		res, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, res.Body)
		res.Body.Close()
		if res.StatusCode != 401 || !strings.Contains(res.Header.Get("WWW-Authenticate"), "Bearer") {
			t.Errorf("%s on /mcp: %d %q, want the 401 challenge", c.name, res.StatusCode, res.Header.Get("WWW-Authenticate"))
		}
	}
	// A token's last_used_at stays untouched by /mcp (no lookup happened).
	if n := e.exec(`SELECT count(*)::text FROM automation_tokens WHERE last_used_at IS NOT NULL`); n != "0" {
		t.Errorf("%s token(s) were looked up through /mcp", n)
	}
	// And a real personal key doesn't open /v1 either.
	secret := e.exec(`SELECT 'omp_' || repeat('x', 43)`)
	code, _, body := e.bearer(secret, get("/v1/teams"))
	if code != 401 || errCode(body) != "invalid_token" {
		t.Errorf("an MCP-shaped key on /v1: %d %s", code, body)
	}
}

// The token matrix's annotated operations really work for a token, end to end,
// and everything it does is audited with the token's ID, name and kind.
func TestTokenCallsAreAuditedAsTheToken(t *testing.T) {
	e := newMatrixEnv(t)
	creds := e.tokenCreds()
	var pub, plat tokenCred
	for _, c := range creds {
		switch c.name {
		case "publisher-write":
			pub = c
		case "platform-write":
			plat = c
		}
	}
	// Create a server (servers:write), refresh it, publish it (self_publish for team B).
	code, _, body := e.bearer(pub.secret, post("/v1/teams/bravo/mcp-servers", map[string]any{"slug": "from-ci", "name": "From CI", "url": e.fakeURL}))
	if code != 201 {
		t.Fatalf("create: %d %s", code, body)
	}
	var created struct{ Data apitypes.McpServerCreated }
	_ = json.Unmarshal(body, &created)
	id := created.Data.Server.Id.String()
	if code, _, body := e.bearer(pub.secret, post("/v1/teams/bravo/mcp-servers/"+id+"/refresh", nil)); code != 200 {
		t.Fatalf("refresh: %d %s", code, body)
	}
	if code, _, body := e.bearer(pub.secret, post("/v1/teams/bravo/mcp-servers/"+id+"/publish", nil)); code != 200 {
		t.Fatalf("publish: %d %s", code, body)
	}
	// A platform token provisions a team.
	if code, _, body := e.bearer(plat.secret, post("/v1/admin/teams", map[string]any{"slug": "from-platform-token", "name": "P", "ownerEmail": "nobody@example.com"})); code != 201 {
		t.Fatalf("create team: %d %s", code, body)
	}
	// Every mutation is in the log as the token: id, name and kind, no user.
	rows, err := e.app.Pool.Query(context.Background(), `SELECT action, actor_kind, actor_user_id::text, actor_token_id::text, actor_token_name, actor_token_kind
		FROM audit_log WHERE actor_kind = 'automation_token' ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	seen := map[string]bool{}
	for rows.Next() {
		var action, kind string
		var user, tokenID, name, tkind *string
		if err := rows.Scan(&action, &kind, &user, &tokenID, &name, &tkind); err != nil {
			t.Fatal(err)
		}
		if user != nil || tokenID == nil || name == nil || tkind == nil || !strings.HasPrefix(*name, "tok-") {
			t.Errorf("%s: user %v token %v name %v kind %v", action, user, tokenID, name, tkind)
		}
		seen[action] = true
	}
	for _, want := range []string{"mcp_server.create", "mcp_server.refresh", "mcp_server.publish", "team.create"} {
		if !seen[want] {
			t.Errorf("%s by a token is not audited as the token (seen %v)", want, seen)
		}
	}
	// The list shows it: actor.kind, the token's name and kind, via null, and
	// the actorKind filter works on both lists.
	owner := e.callers[cOwner]
	var page apitypes.AuditPage
	if c, _ := owner.call("GET", "/v1/teams/bravo/audit?actorKind=automation_token", nil, &page, nil); c != 200 || len(page.Items) < 3 {
		t.Fatalf("team audit: %d, %d items", c, len(page.Items))
	}
	for _, it := range page.Items {
		a := it.Actor
		if it.ActorKind != "automation_token" || a.Kind != "automation_token" || a.AutomationTokenId == nil || a.AutomationTokenName == nil || a.AutomationTokenKind == nil ||
			a.UserId != nil || it.Via != nil || it.ActorUserId != nil {
			t.Errorf("entry %s: %+v via %v", it.Action, a, it.Via)
		}
	}
	var all apitypes.AuditPage
	if c, _ := e.callers[cAuditor].call("GET", "/v1/admin/audit?actorKind=automation_token", nil, &all, nil); c != 200 || len(all.Items) < len(page.Items)+1 {
		t.Errorf("platform audit: %d, %d items", c, len(all.Items))
	}
	if c, _ := e.callers[cAuditor].call("GET", "/v1/admin/audit?actorKind=bogus", nil, nil, nil); c != 400 {
		t.Errorf("a bogus actor kind: %d", c)
	}
	// A mutation that wrote no entry of its own still gets one (detect-auth).
	before := e.exec(`SELECT count(*)::text FROM audit_log WHERE actor_kind = 'automation_token'`)
	if code, _, body := e.bearer(pub.secret, post("/v1/teams/bravo/mcp-servers/detect-auth", map[string]any{"url": e.fakeURL})); code >= 500 {
		t.Fatalf("detect-auth: %d %s", code, body)
	}
	after := e.exec(`SELECT count(*)::text FROM audit_log WHERE actor_kind = 'automation_token'`)
	if before == after {
		t.Error("a token's POST that wrote no audit entry must still be audited")
	}
	if c := e.exec(`SELECT count(*)::text FROM audit_log WHERE action = 'automation_token.request' AND actor_token_name LIKE 'tok-%'`); c == "0" {
		t.Error("the generic entry names the token")
	}
	// Reads are not audited.
	n := e.exec(`SELECT count(*)::text FROM audit_log`)
	e.bearer(plat.secret, get("/v1/admin/teams"))
	if e.exec(`SELECT count(*)::text FROM audit_log`) != n {
		t.Error("a read was audited")
	}
}

func TestTokenFieldRules(t *testing.T) {
	e := newMatrixEnv(t)
	var pub tokenCred
	for _, c := range e.tokenCreds() {
		if c.name == "publisher-write" {
			pub = c
		}
	}
	srv := e.newServer(e.b, "private")
	path := "/v1/teams/bravo/mcp-servers/" + srv
	rev := func() map[string]string {
		return map[string]string{"If-Match": `"` + e.exec(`SELECT revision::text FROM mcp_servers WHERE id = $1`, srv) + `"`}
	}
	// capturePayloads: only a person who accepted the notice may switch it.
	code, _, body := e.bearer(pub.secret, patch(path, map[string]any{"capturePayloads": true}).h(rev()))
	var env struct {
		Error struct {
			Code    string
			Details struct{ Field string }
		}
	}
	_ = json.Unmarshal(body, &env)
	if code != 403 || env.Error.Code != "token_not_allowed" || env.Error.Details.Field != "capturePayloads" {
		t.Errorf("capturePayloads: %d %s", code, body)
	}
	// A server without credentials may be edited, including its URL.
	if code, _, body := e.bearer(pub.secret, patch(path, map[string]any{"description": "from ci", "url": e.fakeURL + "/"}).h(rev())); code != 200 {
		t.Errorf("a server without credentials: %d %s", code, body)
	}
	// Once it holds a credential, a token can't re-point it or change what it sends.
	e.run(`UPDATE mcp_servers SET auth_header_name = 'X-Api-Key', auth_value_cipher = '\x00', auth_value_hint = 'abcd' WHERE id = $1`, srv)
	for field, change := range map[string]map[string]any{
		"url":            {"url": "https://attacker.example.com/mcp"},
		"authHeaderName": {"authHeaderName": "Authorization"},
		"authValue":      {"authValue": "x"},
		"credentials":    {"credentials": []any{map[string]any{"kind": "query", "name": "api_key", "value": "x"}}},
		"authMode":       {"authMode": "none"},
		"requirement":    {"requirement": nil},
		"sendIdentity":   {"sendIdentity": false},
		"oauth":          {"oauth": map[string]any{"scopes": []string{"x"}}},
	} {
		code, _, body := e.bearer(pub.secret, patch(path, change).h(rev()))
		var env struct {
			Error struct {
				Code    string
				Details struct{ Field string }
			}
		}
		_ = json.Unmarshal(body, &env)
		if code != 403 || env.Error.Code != "token_not_allowed" || env.Error.Details.Field != field {
			t.Errorf("%s on a server with credentials: %d %s", field, code, body)
		}
	}
	// Harmless fields still work.
	if code, _, body := e.bearer(pub.secret, patch(path, map[string]any{"description": "still fine"}).h(rev())); code != 200 {
		t.Errorf("description: %d %s", code, body)
	}
	if code, _, body := e.bearer(pub.secret, patch(path, map[string]any{"url": e.fakeURL + "/"}).h(rev())); code != 200 {
		// The same URL is not a change.
		t.Errorf("the unchanged url: %d %s", code, body)
	}
	if got := e.exec(`SELECT auth_header_name FROM mcp_servers WHERE id = $1`, srv); got != "X-Api-Key" {
		t.Errorf("the header was changed: %s", got)
	}
	// A server whose credential is a list of parts is as protected: a token
	// can neither change nor empty the list (decision 70).
	e.run(`UPDATE mcp_servers SET auth_header_name = NULL, auth_value_cipher = NULL, auth_value_hint = '', auth_mode = 'static_header' WHERE id = $1`, srv)
	e.run(`INSERT INTO mcp_server_credentials (server_id, position, kind, name, value_cipher) VALUES ($1, 0, 'query', 'api_key', '\x00')`, srv)
	for name, change := range map[string]map[string]any{
		"replace the list": {"credentials": []any{map[string]any{"kind": "header", "name": "X-Other", "value": "x"}}},
		"empty the list":   {"credentials": []any{}},
		"keep the list":    {"credentials": []any{map[string]any{"kind": "query", "name": "api_key", "keep": true}}},
	} {
		code, _, body := e.bearer(pub.secret, patch(path, change).h(rev()))
		var env struct {
			Error struct {
				Code    string
				Details struct{ Field string }
			}
		}
		_ = json.Unmarshal(body, &env)
		if code != 403 || env.Error.Code != "token_not_allowed" || env.Error.Details.Field != "credentials" {
			t.Errorf("%s on a server with credential parts: %d %s", name, code, body)
		}
	}
	if got := e.exec(`SELECT count(*)::text FROM mcp_server_credentials WHERE server_id = $1`, srv); got != "1" {
		t.Errorf("a token changed the parts: %s", got)
	}
	if code, _, body := e.bearer(pub.secret, patch(path, map[string]any{"description": "parts stay"}).h(rev())); code != 200 {
		t.Errorf("description on a server with parts: %d %s", code, body)
	}

	// TLS settings (decision 74): a client key and a CA are credentials and a
	// trust setting, so no token sends them, whatever the server holds, and on
	// a server that holds a client key it can't re-point the URL either.
	fieldOf := func(body []byte) string {
		var env struct {
			Error struct{ Details struct{ Field string } }
		}
		_ = json.Unmarshal(body, &env)
		return env.Error.Details.Field
	}
	e.run(`DELETE FROM mcp_server_credentials WHERE server_id = $1`, srv)
	e.run(`UPDATE mcp_servers SET auth_mode = 'none' WHERE id = $1`, srv)
	for name, tls := range map[string]map[string]any{
		"a CA":       {"caPem": "x"},
		"a key":      {"clientCertPem": "x", "clientKeyPem": "y"},
		"clear":      {"clear": true},
		"an empty":   {},
		"a removing": {"caPem": ""},
	} {
		code, _, body := e.bearer(pub.secret, patch(path, map[string]any{"tls": tls}).h(rev()))
		if code != 403 || fieldOf(body) != "tls" || strings.Contains(string(body), "BEGIN") {
			t.Errorf("tls (%s) on a server without credentials: %d %s", name, code, body)
		}
	}
	code, _, body = e.bearer(pub.secret, post("/v1/teams/bravo/mcp-servers", map[string]any{"slug": "with-tls", "name": "With TLS", "url": e.fakeURL,
		"tls": map[string]any{"caPem": "x"}}))
	if code != 403 || fieldOf(body) != "tls" {
		t.Errorf("create with tls: %d %s", code, body)
	}
	if got := e.exec(`SELECT count(*)::text FROM mcp_server_tls`); got != "0" {
		t.Errorf("a token stored TLS settings: %s", got)
	}
	e.run(`INSERT INTO mcp_server_tls (server_id, client_cert_pem, client_key_cipher, client_cert_sha256, client_not_after)
		VALUES ($1, 'x', '\x00', repeat('a', 64), now() + interval '90 days')`, srv)
	if code, _, body := e.bearer(pub.secret, patch(path, map[string]any{"url": "https://attacker.example.com/mcp"}).h(rev())); code != 403 || fieldOf(body) != "url" {
		t.Errorf("url on a server with a client key: %d %s", code, body)
	}
	if code, _, body := e.bearer(pub.secret, patch(path, map[string]any{"description": "tls stays"}).h(rev())); code != 200 {
		t.Errorf("description on a server with a client key: %d %s", code, body)
	}
}

// Detect-auth is limited per token (10 a minute), counted separately from
// every other token and from people.
func TestTokenDetectAuthLimit(t *testing.T) {
	e := newMatrixEnv(t)
	var pub tokenCred
	for _, c := range e.tokenCreds() {
		if c.name == "publisher-write" {
			pub = c
		}
	}
	var last int
	for i := 0; i < 12; i++ {
		last, _, _ = e.bearer(pub.secret, post("/v1/teams/bravo/mcp-servers/detect-auth", map[string]any{"url": e.fakeURL}))
		if i < 10 && last == 429 {
			t.Fatalf("limited after %d", i+1)
		}
	}
	if last != 429 {
		t.Errorf("the 12th detect-auth: %d, want 429", last)
	}
	other := tokenSecret("omppub_", 50)
	e.mintToken("team_publisher", e.b.id, "", other, []string{"servers:read", "servers:write"}, "-1 hour", "1 day", "")
	if code, _, body := e.bearer(other, post("/v1/teams/bravo/mcp-servers/detect-auth", map[string]any{"url": e.fakeURL})); code == 429 {
		t.Errorf("another token shares the bucket: %d %s", code, body)
	}
}

func TestTokenIntrospection(t *testing.T) {
	e := newMatrixEnv(t)
	for _, c := range e.tokenCreds() {
		if c.invalid {
			continue
		}
		code, _, body := e.bearer(c.secret, get("/v1/token"))
		if code != 200 {
			t.Errorf("%s: %d %s", c.name, code, body)
			continue
		}
		var out struct{ Data apitypes.AutomationToken }
		_ = json.Unmarshal(body, &out)
		tok := out.Data
		if string(tok.Kind) != c.kind || len(tok.Scopes) != len(c.scopes) || tok.Status != "active" || strings.Contains(string(body), c.secret) || strings.Contains(string(body), "digest") {
			t.Errorf("%s: %s", c.name, body)
		}
		if (c.team == "") != (tok.Team == nil) || (tok.Team != nil && tok.Team.Id.String() != c.team) {
			t.Errorf("%s: team %+v", c.name, tok.Team)
		}
	}
	// A session doesn't count.
	if code, _ := e.callers[cPlatformAdmin].raw("GET", "/v1/token", nil, nil); code != 401 {
		t.Errorf("a session on /v1/token: %d", code)
	}
	if code, _, body := e.bearer("", get("/v1/token")); code != 401 || errCode(body) != "invalid_token" {
		t.Errorf("no credential: %d %s", code, body)
	}
}

func TestTokenAuthenticationRules(t *testing.T) {
	e := newMatrixEnv(t)
	creds := e.tokenCreds()
	var plat tokenCred
	for _, c := range creds {
		if c.name == "platform-write" {
			plat = c
		}
	}
	good := "/v1/admin/teams"
	// The header must be exactly "Bearer <token>".
	for name, h := range map[string]string{"basic": "Basic " + plat.secret, "bare": plat.secret, "double space": "Bearer  " + plat.secret, "trailing": "Bearer " + plat.secret + " x", "empty": "Bearer "} {
		r, _ := http.NewRequest("GET", e.app.URL+good, nil)
		r.Header.Set("Authorization", h)
		res, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if res.StatusCode != 401 || errCode(body) != "invalid_token" {
			t.Errorf("%s: %d %s", name, res.StatusCode, body)
		}
	}
	if code, _, _ := e.bearer(plat.secret, get(good)); code != 200 {
		t.Fatalf("a valid token: %d", code)
	}
	// A browser cookie next to an Authorization header is ignored: the
	// request is the token's (here, an invalid one is refused though the
	// cookie belongs to a platform admin).
	admin := e.callers[cPlatformAdmin]
	r, _ := http.NewRequest("GET", e.app.URL+good, nil)
	r.Header.Set("Authorization", "Bearer "+tokenSecret("ompadm_", 77))
	for _, c := range admin.client.Jar.Cookies(mustParse(t, e.app.URL)) {
		r.AddCookie(c)
	}
	res, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 401 || errCode(body) != "invalid_token" || res.Header.Get("Set-Cookie") != "" {
		t.Errorf("a cookie must not stand in for a bad token: %d %s", res.StatusCode, body)
	}
	// A token on a session-only route (the cookie is ignored there too).
	r, _ = http.NewRequest("POST", e.app.URL+"/auth/logout", nil)
	r.Header.Set("Authorization", "Bearer "+plat.secret)
	res, _ = http.DefaultClient.Do(r)
	res.Body.Close()
	if res.StatusCode != 401 && res.StatusCode != 403 {
		t.Errorf("a token on /auth/logout: %d", res.StatusCode)
	}
	// No CSRF or Origin needed for a write, and a foreign Origin makes no
	// difference (bearer calls aren't ambient).
	req := post("/v1/admin/teams", map[string]any{"slug": "csrf-free", "name": "C", "ownerEmail": "x@example.com"})
	req.headers = map[string]string{"Origin": "https://evil.example"}
	if code, _, body := e.bearer(plat.secret, req); code != 201 {
		t.Errorf("a token write with no CSRF token: %d %s", code, body)
	}
	// last_used_at is written at most once a minute.
	e.run(`UPDATE automation_tokens SET last_used_at = NULL`)
	e.bearer(plat.secret, get(good))
	first := e.exec(`SELECT last_used_at::text FROM automation_tokens WHERE digest = $1`, automation.Digest(e.pepper(), plat.secret))
	e.bearer(plat.secret, get(good))
	if second := e.exec(`SELECT last_used_at::text FROM automation_tokens WHERE digest = $1`, automation.Digest(e.pepper(), plat.secret)); second != first || first == "" {
		t.Errorf("last_used_at moved within a minute: %s -> %s", first, second)
	}
	e.run(`UPDATE automation_tokens SET last_used_at = now() - interval '2 minutes'`)
	e.bearer(plat.secret, get(good))
	if got := e.exec(`SELECT (last_used_at > now() - interval '1 minute')::text FROM automation_tokens WHERE digest = $1`, automation.Digest(e.pepper(), plat.secret)); got != "true" {
		t.Error("last_used_at wasn't refreshed after a minute")
	}
}

// Revocation applies on the next request; a demoted creator blocks a platform
// token (and restoring them revives it) but never a team token; an archived
// team keeps its tokens under the normal read-only rules; a deleted team
// takes its tokens with it.
func TestTokenStandingRules(t *testing.T) {
	e := newMatrixEnv(t)
	byName := map[string]tokenCred{}
	for _, c := range e.tokenCreds() {
		byName[c.name] = c
	}
	plat, pub := byName["platform-write"], byName["publisher-write"]
	digest := func(c tokenCred) string { return automation.Digest(e.pepper(), c.secret) }
	status := func(c tokenCred, req request) int { code, _, _ := e.bearer(c.secret, req); return code }

	// Revocation is immediate.
	if status(pub, get("/v1/teams/bravo/mcp-servers")) != 200 {
		t.Fatal("setup")
	}
	e.run(`UPDATE automation_tokens SET revoked_at = now() WHERE digest = $1`, digest(pub))
	if got := status(pub, get("/v1/teams/bravo/mcp-servers")); got != 401 {
		t.Errorf("a revoked token: %d", got)
	}
	e.run(`UPDATE automation_tokens SET revoked_at = NULL WHERE digest = $1`, digest(pub))

	// Expiry boundary: a token that expires now is expired.
	e.run(`UPDATE automation_tokens SET expires_at = now() + interval '2 seconds' WHERE digest = $1`, digest(pub))
	if got := status(pub, get("/v1/teams/bravo/mcp-servers")); got != 200 {
		t.Errorf("a token with seconds left: %d", got)
	}
	time.Sleep(2100 * time.Millisecond)
	if got := status(pub, get("/v1/teams/bravo/mcp-servers")); got != 401 {
		t.Errorf("a token past its expiry: %d", got)
	}
	e.run(`UPDATE automation_tokens SET expires_at = now() + interval '1 day' WHERE digest = $1`, digest(pub))

	// A platform token dies with its creator's platform-admin role and comes back with it.
	creator := e.userIDs[cPlatformAdmin]
	if status(plat, get("/v1/admin/teams")) != 200 {
		t.Fatal("setup")
	}
	e.run(`UPDATE users SET platform_role = 'platform_auditor' WHERE id = $1`, creator)
	if got := status(plat, get("/v1/admin/teams")); got != 401 {
		t.Errorf("demoted creator: %d, want 401 on the next request", got)
	}
	var list struct{ Data []apitypes.AutomationToken }
	if c, _ := e.callers[cAuditor].call("GET", "/v1/admin/automation-tokens", nil, &list.Data, nil); c != 200 {
		t.Fatal(c)
	}
	blocked := 0
	for _, tk := range list.Data {
		if tk.BlockedReason != nil && *tk.BlockedReason == "creator_not_platform_admin" && tk.Status == "active" {
			blocked++
		}
	}
	if blocked < 2 {
		t.Errorf("%d tokens listed as blocked, want the creator's platform tokens", blocked)
	}
	e.run(`UPDATE users SET platform_role = 'platform_admin' WHERE id = $1`, creator)
	if got := status(plat, get("/v1/admin/teams")); got != 200 {
		t.Errorf("restored creator: %d", got)
	}
	e.run(`UPDATE users SET status = 'suspended' WHERE id = $1`, creator)
	if got := status(plat, get("/v1/admin/teams")); got != 401 {
		t.Errorf("suspended creator: %d", got)
	}
	e.run(`UPDATE users SET status = 'active' WHERE id = $1`, creator)

	// A team token survives its creator: a token made by someone who left.
	gone := e.newUser("gone@example.com", "none")
	s := tokenSecret("omppub_", 60)
	e.mintToken("team_publisher", e.b.id, gone, s, []string{"servers:read", "servers:write"}, "-1 hour", "1 day", "")
	e.run(`DELETE FROM users WHERE id = $1`, gone)
	if code, _, body := e.bearer(s, get("/v1/teams/bravo/mcp-servers")); code != 200 {
		t.Errorf("a team token after its creator left: %d %s", code, body)
	}
	if e.exec(`SELECT coalesce(created_by::text, 'null') FROM automation_tokens WHERE digest = $1`, automation.Digest(e.pepper(), s)) != "null" {
		t.Error("created_by should be SET NULL")
	}

	// An archived team: reads work, writes are 409 team_archived.
	e.run(`UPDATE teams SET status = 'archived' WHERE id = $1`, e.b.id)
	if got := status(pub, get("/v1/teams/bravo/mcp-servers")); got != 200 {
		t.Errorf("a read in an archived team: %d", got)
	}
	code, _, body := e.bearer(pub.secret, post("/v1/teams/bravo/mcp-servers", map[string]any{"slug": "x", "name": "X", "url": e.fakeURL}))
	if code != 409 || errCode(body) != "team_archived" {
		t.Errorf("a write in an archived team: %d %s", code, body)
	}
	e.run(`UPDATE teams SET status = 'active' WHERE id = $1`, e.b.id)

	// A deleted team takes its tokens with it.
	e.run(`DELETE FROM teams WHERE id = $1`, e.a.id)
	other := byName["publisher-write-other-team"]
	if code, _, body := e.bearer(other.secret, get("/v1/teams/alpha/mcp-servers")); code != 401 {
		t.Errorf("a token of a deleted team: %d %s", code, body)
	}
}

// Tokens made with the previous pepper keep working and are re-digested on
// use (audited by the system); one made with an unknown pepper doesn't.
func TestTokenPreviousPepper(t *testing.T) {
	e := newMatrixEnv(t)
	oldPepper := []byte("0123456789abcdef0123456789abcdef")
	secret := tokenSecret("ompadm_", 70)
	e.run(`INSERT INTO automation_tokens (kind, name, prefix, digest, pepper_id, scopes, created_by, expires_at)
		VALUES ('platform_admin', 'old-pepper', $1, $2, decode($3, 'hex'), '{platform:read}', $4, now() + interval '1 day')`,
		secret[:15], automation.Digest(oldPepper, secret), fmt.Sprintf("%x", secrets.KeyID(oldPepper)), e.userIDs[cPlatformAdmin])
	// Without a previous pepper configured: unknown.
	if code, _, _ := e.bearer(secret, get("/v1/admin/teams")); code != 401 {
		t.Fatalf("without API_KEY_PEPPER_PREVIOUS: %d", code)
	}
	e2 := newMatrixEnvWith(t, func(c *testConfig) { c.APIKeyPepperPrevious = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=" })
	secret2 := tokenSecret("ompadm_", 71)
	e2.run(`INSERT INTO automation_tokens (kind, name, prefix, digest, pepper_id, scopes, created_by, expires_at)
		VALUES ('platform_admin', 'old-pepper', $1, $2, decode($3, 'hex'), '{platform:read}', $4, now() + interval '1 day')`,
		secret2[:15], automation.Digest(oldPepper, secret2), fmt.Sprintf("%x", secrets.KeyID(oldPepper)), e2.userIDs[cPlatformAdmin])
	for i := 0; i < 2; i++ {
		if code, _, body := e2.bearer(secret2, get("/v1/admin/teams")); code != 200 {
			t.Fatalf("a token on the previous pepper (use %d): %d %s", i+1, code, body)
		}
	}
	if got := e2.exec(`SELECT (digest = $1 AND pepper_id = decode($2, 'hex'))::text FROM automation_tokens WHERE name = 'old-pepper'`,
		automation.Digest(e2.pepper(), secret2), fmt.Sprintf("%x", secrets.KeyID(e2.pepper()))); got != "true" {
		t.Error("the token was not re-digested with the current pepper")
	}
	if e2.exec(`SELECT count(*)::text FROM audit_log WHERE action = 'automation_token.pepper_rehash' AND actor_kind = 'system'`) != "1" {
		t.Error("one pepper_rehash entry by the system")
	}
}

// Rate limits: a token has its own bucket (REQUESTS_PER_MINUTE), and failed
// attempts count per address in a bucket of their own (the sign-in attempts'
// number), so bad tokens from a shared address neither lock people out of
// signing in nor stop a valid token.
func TestTokenRateLimits(t *testing.T) {
	e := newMatrixEnvWith(t, func(c *testConfig) { c.RequestsPerMinute, c.LoginAttemptsPerMinute = 5, 3 })
	byName := map[string]tokenCred{}
	for _, c := range e.tokenCreds() {
		byName[c.name] = c
	}
	a, b := byName["platform-read"], byName["platform-write"]
	var last int
	var hdr http.Header
	for i := 0; i < 6; i++ {
		last, hdr, _ = e.bearer(a.secret, get("/v1/admin/teams"))
	}
	if last != 429 || hdr.Get("Retry-After") == "" {
		t.Errorf("the 6th request of a token: %d (Retry-After %q)", last, hdr.Get("Retry-After"))
	}
	if code, _, _ := e.bearer(b.secret, get("/v1/admin/teams")); code != 200 {
		t.Errorf("another token shares the bucket: %d", code)
	}
	// Failed attempts: 3 a minute per address, then 429 with Retry-After.
	var codes []int
	for i := 0; i < 5; i++ {
		c, h, _ := e.bearer(tokenSecret("ompadm_", 900+i), get("/v1/admin/teams"))
		codes = append(codes, c)
		if c == 429 && h.Get("Retry-After") == "" {
			t.Error("429 without Retry-After")
		}
	}
	if codes[0] != 401 || codes[3] != 429 || codes[4] != 429 {
		t.Errorf("failed attempts: %v", codes)
	}
	// A valid token is not refused for the address's failures, and signing in still works.
	if code, _, _ := e.bearer(b.secret, get("/v1/admin/teams")); code != 200 {
		t.Errorf("a valid token after failures: %d", code)
	}
	if code, body := e.app.do("POST", "/auth/dev", map[string]string{"account": "admin"}, nil); code != 200 {
		t.Errorf("sign-in after bad tokens: %d %s", code, body)
	}
}

// What a platform:write token does is audited as the token, including the
// changes that widen access (gateway grants) and raise limits: the
// threat model's reason to keep every token mutation in the log.
func TestPlatformWriteMutationsAreAuditedAsTheToken(t *testing.T) {
	e := newMatrixEnv(t)
	var plat tokenCred
	for _, c := range e.tokenCreds() {
		if c.name == "platform-write" {
			plat = c
		}
	}
	gw := e.newGateway("")
	for _, req := range []request{
		post("/v1/admin/gateways/"+gw+"/grants", map[string]any{"subjectKind": "group", "group": "everyone"}),
		{method: "PUT", path: "/v1/admin/settings/limits", body: map[string]any{"items": []any{map[string]any{"key": "person_per_minute", "default": 7000, "ceiling": nil}}},
			headers: map[string]string{"If-Match": `"` + e.exec(`SELECT revision::text FROM limit_settings`) + `"`}},
		patch("/v1/admin/teams/"+e.b.slug, map[string]any{"description": "by token"}).h(map[string]string{"If-Match": `"` + e.exec(`SELECT revision::text FROM teams WHERE id = $1`, e.b.id) + `"`}),
	} {
		if code, _, body := e.bearer(plat.secret, req); code != 200 && code != 201 {
			t.Fatalf("%s %s: %d %s", req.method, req.path, code, body)
		}
	}
	for _, action := range []string{"gateway.grant_add", "settings.limits_update", "team.update"} {
		got := e.exec(`SELECT count(*)::text FROM audit_log WHERE actor_kind = 'automation_token' AND actor_user_id IS NULL AND actor_token_name LIKE 'tok-%' AND actor_token_kind = 'platform_admin' AND action = $1`, action)
		if got != "1" {
			t.Errorf("%s by the token: %s audit entries naming it, want 1 (actions: %s)", action, got, e.exec(`SELECT string_agg(action, ',') FROM audit_log WHERE actor_kind = 'automation_token'`))
		}
	}
	// Every mutation a token made has an entry naming it.
	if e.exec(`SELECT count(*)::text FROM audit_log WHERE actor_kind = 'automation_token' AND (actor_token_id IS NULL OR actor_token_name IS NULL)`) != "0" {
		t.Error("an entry of a token without its name")
	}
}
