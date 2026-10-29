package httpapi_test

import (
	"net/url"
	"strings"
	"testing"
)

// opAs runs every lifecycle method with the handle as the given credential and
// returns the (code, body) of each, for uniformity checks.
func (e *tasksEnv) opAs(gateway, key, handle string, why ...string) map[string]string {
	e.t.Helper()
	out := map[string]string{}
	for _, method := range []string{"tasks/get", "tasks/update", "tasks/cancel"} {
		extra := map[string]any(nil)
		if method == "tasks/update" {
			extra = map[string]any{"inputResponses": map[string]any{"ompin_x": map[string]any{"action": "cancel"}}}
		}
		e.allowPoll()
		code, _, body := e.op(gateway, key, method, handle, extra, declared(true))
		if code != 200 || !isNotFound(body) {
			e.t.Errorf("%v: %s as another credential = %d %v", why, method, code, body)
		}
		// The id echoes the request's: everything else must be identical.
		delete(body, "id")
		out[method] = e.mustJSON(body)
	}
	return out
}

func (e *tasksEnv) mustWork(gateway, key, handle string) {
	e.t.Helper()
	e.allowPoll()
	if code, _, out := e.op(gateway, key, "tasks/get", handle, nil, declared(true)); code != 200 || out["error"] != nil {
		e.t.Fatalf("the owner's own get on %s = %d %v", gateway, code, out)
	}
}

func TestTasksAreBoundToPrincipalStartingCredentialAndGateway(t *testing.T) {
	e := newTasksEnv(t, tasksOptions{})
	handle := e.create("shared", e.key.Secret)
	e.mustWork("shared", e.key.Secret, handle)
	callsBefore := e.up.Count("tasks/get") + e.up.Count("tasks/update") + e.up.Count("tasks/cancel")
	reference := e.opAs("shared", e.key.Secret, "omptask_"+strings.Repeat("A", 43)) // a well-formed handle nobody holds

	// Another key of the SAME person.
	second := newKey(t, e.member, "second")
	// A different person on the same gateway.
	caseyKey := newKey(t, e.outsider, "casey")
	for name, who := range map[string]struct{ gw, key string }{
		"second key of the same person":   {"shared", second.Secret},
		"another person":                  {"shared", caseyKey.Secret},
		"the same key on another gateway": {"support", e.key.Secret},
	} {
		got := e.opAs(who.gw, who.key, handle, name)
		for m, body := range got {
			if body != reference[m] {
				t.Errorf("%s: %s answer differs from an unknown handle:\n%s\n%s", name, m, body, reference[m])
			}
		}
	}
	// Malformed handles are the same answer, not a validation error.
	for _, bad := range []string{"x", handle[:len(handle)-1], handle + "A", strings.ToUpper(handle), "omptask_" + strings.Repeat("!", 43), strings.Repeat("a", 5000)} {
		for m, body := range e.opAs("shared", e.key.Secret, bad) {
			if body != reference[m] {
				t.Errorf("malformed handle %.12q: %s answer differs:\n%s", bad, m, body)
			}
		}
	}
	if got := e.up.Count("tasks/get") + e.up.Count("tasks/update") + e.up.Count("tasks/cancel"); got != callsBefore {
		t.Fatalf("a foreign or unknown handle reached the upstream (%d -> %d)", callsBefore, got)
	}
	// The owner is unaffected throughout.
	e.mustWork("shared", e.key.Secret, handle)

	// A connected OAuth client is bound by its stable grant: access-token
	// refresh keeps the task, another grant or key never sees it.
	clientID := e.docs.client("/assistant.json", "Test Assistant", testRedirect)
	access, refresh := connectApp(t, e.app, e.member, clientID, "shared")
	oauthHandle := e.create("shared", access)
	e.mustWork("shared", access, oauthHandle)
	e.opAs("shared", e.key.Secret, oauthHandle, "the person's API key on a grant's task")
	e.opAs("shared", access, handle, "the grant on a key's task")
	status, tok, _ := tokenCall(t, e.app, "/oauth/token", url.Values{"grant_type": {"refresh_token"}, "client_id": {clientID}, "refresh_token": {refresh}})
	refreshed, _ := tok["access_token"].(string)
	if status != 200 || refreshed == "" || refreshed == access {
		t.Fatalf("refresh = %d %v", status, tok)
	}
	e.mustWork("shared", refreshed, oauthHandle) // a new access token of the same grant
	// Signing the SAME app in again for the same person and gateway is the same
	// grant (the stable root), so its task stays reachable; a different app is a
	// different grant and never sees it.
	access2, _ := connectApp(t, e.app, e.member, clientID, "shared")
	e.mustWork("shared", access2, oauthHandle)
	otherClient := e.docs.client("/other.json", "Other App", testRedirect)
	access3, _ := connectApp(t, e.app, e.member, otherClient, "shared")
	e.mustWork("shared", access3, e.create("shared", access3))
	e.opAs("shared", access3, oauthHandle, "a different app's grant of the same person")

	// A service account is its own principal, bound to its key.
	sa := createSA(t, e.owner, map[string]any{"name": "task-bot"})
	saKey := createSAKey(t, e.owner, sa.Id.String(), map[string]any{"name": "one"})
	saKey2 := createSAKey(t, e.owner, sa.Id.String(), map[string]any{"name": "two"})
	saHandle := e.create("support", saKey.Secret)
	e.mustWork("support", saKey.Secret, saHandle)
	e.opAs("support", saKey2.Secret, saHandle, "another key of the account")
	e.opAs("support", e.key.Secret, saHandle, "a person on an account's task")
	ownerKey := newKey(t, e.owner, "owner")
	e.opAs("support", ownerKey.Secret, saHandle, "the team owner on an account's task")
	e.opAs("support", saKey.Secret, handle, "the account on a person's task")
}

// Revoking or narrowing the credential or the person's access stops a task at
// once; nothing reaches the upstream.
func TestTasksRecheckCurrentAuthorityOnEveryOperation(t *testing.T) {
	type env = tasksEnv
	cases := []struct {
		name     string
		gateway  string
		wantCode int // 0: JSON-RPC 200 with the uniform not-found
		mutate   func(e *env, handle string)
	}{
		{"revoked key", "support", 401, func(e *env, _ string) {
			code, ec := e.member.call("DELETE", "/v1/me/api-keys/"+e.key.Key.Id.String(), nil, nil, nil)
			mustCode(e.t, "revoke", code, ec, 200, "")
		}},
		{"suspended person", "support", 401, func(e *env, _ string) {
			id := e.userID("blair@localhost")
			var u struct{ User struct{ Revision int64 } }
			e.admin.get("/v1/admin/users/"+id, &u)
			code, ec := e.admin.call("PATCH", "/v1/admin/users/"+id, map[string]any{"status": "suspended"}, nil, ifMatch(u.User.Revision))
			mustCode(e.t, "suspend", code, ec, 200, "")
		}},
		{"key narrowed to another gateway", "support", 404, func(e *env, _ string) {
			if _, err := e.owned.Exec(t.Context(), `INSERT INTO api_key_gateways(api_key_id, gateway_id, gateway_slug, gateway_name) VALUES ($1, $2, 'shared', 'SHARED')`,
				e.key.Key.Id, e.shared.Id); err != nil {
				e.t.Fatal(err)
			}
		}},
		{"key narrowed to read tools only", "support", 0, func(e *env, _ string) {
			if _, err := e.owned.Exec(t.Context(), `UPDATE api_keys SET tool_scope = '{"classes":["read"]}'::jsonb WHERE id = $1`, e.key.Key.Id); err != nil {
				e.t.Fatal(err)
			}
		}},
		{"gateway disabled", "support", 404, func(e *env, _ string) {
			code, ec := e.owner.call("PATCH", e.supportPath, map[string]any{"enabled": false}, nil, ifMatch(e.gateway(e.owner, e.supportPath).Revision))
			mustCode(e.t, "disable gateway", code, ec, 200, "")
		}},
		{"server disabled", "support", 0, func(e *env, _ string) { e.patchServer(e.owner, e.srv, map[string]any{"enabled": false}) }},
		{"tool removed from the gateway", "support", 0, func(e *env, _ string) { e.mustSetCaps(e.owner, e.supportPath, sel()) }},
		{"gateway grant removed", "shared", 404, func(e *env, _ string) {
			code, ec := e.admin.call("DELETE", e.sharedPath+"/grants/"+e.grantID, nil, nil, nil)
			mustCode(e.t, "remove grant", code, ec, 200, "")
		}},
		{"gateway grant expired", "shared", 404, func(e *env, _ string) {
			if _, err := e.owned.Exec(t.Context(), `UPDATE gateway_grants SET added_at = now() - interval '2 days', expires_at = now() - interval '1 day' WHERE id = $1`, e.grantID); err != nil {
				e.t.Fatal(err)
			}
		}},
		{"server team archived", "shared", 0, func(e *env, _ string) { e.setTeamStatus("tools", "archived") }},
		{"server unpublished", "shared", 0, func(e *env, _ string) {
			code, ec := e.owner.call("POST", toolsTeam+"/mcp-servers/"+e.srv.Id.String()+"/unpublish", nil, nil, nil)
			mustCode(e.t, "unpublish", code, ec, 200, "")
		}},
		{"tool definition changed", "support", 0, func(e *env, _ string) {
			e.up.AddTool(testFakeTasksTool("slow", "Now it does something else."))
			e.refresh(e.owner, e.srv)
		}},
		{"curation changed", "support", 0, func(e *env, _ string) {
			setCuration(e.t, e.gwEnv, e.owner, e.supportPath, "slow", map[string]any{"constraints": map[string]any{"text": map[string]any{"fixed": "pinned"}}})
		}},
		{"server url changed", "support", 0, func(e *env, _ string) {
			other := newTasksUpstream(e.t)
			e.patchServer(e.owner, e.srv, map[string]any{"url": other.URL(), "credentials": []any{
				map[string]any{"kind": "header", "name": "X-Api-Key", "value": tasksStaticKey}}})
		}},
		{"server edited (revision only)", "support", 0, func(e *env, _ string) {
			e.patchServer(e.owner, e.srv, map[string]any{"description": "an unrelated edit"})
		}},
		{"server credential kind changed", "support", 0, func(e *env, _ string) {
			e.patchServer(e.owner, e.srv, map[string]any{"credentials": []any{
				map[string]any{"kind": "header", "name": "X-Other-Key", "value": "another-static-credential-9921"}}})
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newTasksEnv(t, tasksOptions{})
			// Pin the offer's exposed name through a curation-free creation.
			handle := e.create(tc.gateway, e.key.Secret)
			e.mustWork(tc.gateway, e.key.Secret, handle)
			tc.mutate(e, handle)
			upstreamOps := e.up.Count("tasks/get") + e.up.Count("tasks/update") + e.up.Count("tasks/cancel")
			receipts := e.rows(`SELECT (SELECT count(*) FROM approval_requests)::text`)
			for _, method := range []string{"tasks/get", "tasks/update", "tasks/cancel"} {
				extra := map[string]any(nil)
				if method == "tasks/update" {
					extra = map[string]any{"inputResponses": map[string]any{"ompin_x": map[string]any{"action": "cancel"}}}
				}
				e.allowPoll()
				code, _, out := e.op(tc.gateway, e.key.Secret, method, handle, extra, declared(true))
				switch {
				case tc.wantCode != 0 && code != tc.wantCode:
					t.Errorf("%s = %d %v, want HTTP %d", method, code, out, tc.wantCode)
				case tc.wantCode == 0 && (code != 200 || !isNotFound(out)):
					t.Errorf("%s = %d %v, want the uniform not-found", method, code, out)
				}
				if out["result"] != nil {
					t.Errorf("%s returned a result after the change: %v", method, out)
				}
			}
			if got := e.up.Count("tasks/get") + e.up.Count("tasks/update") + e.up.Count("tasks/cancel"); got != upstreamOps {
				t.Errorf("a refused operation reached the upstream (%d -> %d)", upstreamOps, got)
			}
			if got := e.rows(`SELECT (SELECT count(*) FROM approval_requests)::text`); got != receipts {
				t.Errorf("approval rows %s -> %s", receipts, got)
			}
		})
	}
}
