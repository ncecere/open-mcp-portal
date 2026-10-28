package httpapi_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

// The old inbound header is never ignored, regardless of credential, MCP era
// or HTTP/RPC method. Rejection happens before any transport or external fetch.
func TestRetiredInboundIdentityFailsClosed(t *testing.T) {
	e := newProvEnv(t)
	if code, msg := e.override("whoami", map[string]any{"mode": "none"}); code != 200 {
		t.Fatalf("override: %d %s", code, msg)
	}
	sa := createSA(t, e.owner, map[string]any{"name": "ordinary", "role": "editor"})
	saKey := createSAKey(t, e.owner, sa.Id.String(), map[string]any{"name": "ordinary"}).Secret
	const sentinel = "retired-identity-token-sentinel"
	for credential, key := range map[string]string{"personal": e.key, "ordinary service account": saKey, "invalid": "bad", "anonymous": ""} {
		for _, era := range []string{"2025-11-25", "2026-07-28"} {
			for _, method := range []string{"POST", "GET", "DELETE", "PUT", "OPTIONS", "HEAD"} {
				for _, rpcMethod := range []string{"initialize", "tools/list", "tools/call", "prompts/get", "resources/read", "server/discover", "notifications/initialized"} {
					before := e.fake.Requests()
					code, headers, out := rawMCP(t, e.app, method, "support", key, rpc(1, rpcMethod, map[string]any{"name": "status__whoami"}), map[string]string{"MCP-Gateway-Identity": sentinel, "MCP-Protocol-Version": era})
					if code != http.StatusForbidden {
						t.Fatalf("%s %s %s %s: %d %v", credential, era, method, rpcMethod, code, out)
					}
					b, _ := json.Marshal(out)
					if strings.Contains(string(b), sentinel) || strings.Contains(headers.Get("MCP-Gateway-Identity"), sentinel) {
						t.Fatal("refusal echoed identity token")
					}
					if e.fake.Requests() != before {
						t.Fatal("retired input reached upstream")
					}
				}
			}
		}
	}
	// Even an empty supplied header is rejected, not treated as absent.
	if code, _, _ := rawMCP(t, e.app, "POST", "support", saKey, rpc(1, "tools/list", nil), map[string]string{"MCP-Gateway-Identity": ""}); code != 403 {
		t.Fatalf("empty identity header: %d", code)
	}
	if e.connectRequests() != "0" {
		t.Fatal("retired input started consent")
	}
	if e.scalar(`SELECT count(*)::text FROM mcp_calls`) != "0" {
		t.Fatal("retired input ran as an ordinary principal")
	}
	if strings.Contains(e.logs.String(), sentinel) {
		t.Fatal("token in logs")
	}
	// Normal personal/ordinary service-account requests still sign outbound
	// identity in either era, without an actor claim.
	for _, key := range []string{e.key, saKey} {
		for _, modern := range []bool{false, true} {
			var out map[string]any
			if modern {
				_, _, out = rawModern(t, e.app, "support", key, "tools/call", toolCall("status__whoami", nil), nil, nil)
			} else {
				_, _, out = rawMCP(t, e.app, "POST", "support", key, rpc(1, "tools/call", toolCall("status__whoami", nil)), nil)
			}
			who := whoamiOf(t, out)
			if !who.Verified || who.Claims["act"] != nil {
				t.Fatalf("ordinary identity: %+v", who)
			}
		}
	}
}

func TestRetiredPlatformContractAndAccountAreReadOnly(t *testing.T) {
	e := newProvEnv(t)
	sa := createSA(t, e.owner, map[string]any{"name": "legacy", "role": "editor"})
	oldKey := createSAKey(t, e.owner, sa.Id.String(), map[string]any{"name": "old"}).Secret
	// Owner-only scratch instrumentation creates a retained legacy mark. Runtime
	// writes remain fenced; this is not a way for the product to create relays.
	owner := testutil.OwnerPool(t, e.app.Pool)
	sql := `ALTER TABLE service_accounts DISABLE TRIGGER retired_relay_account;
 INSERT INTO agent_platforms(name,issuer,jwks_url,audience,enabled) VALUES ('Historical','https://old.example','https://old.example/jwks','portal',false);
 UPDATE service_accounts SET relay_platform_id=(SELECT id FROM agent_platforms LIMIT 1),enabled=true WHERE name='legacy';
 ALTER TABLE service_accounts ENABLE TRIGGER retired_relay_account;`
	if _, err := owner.Exec(t.Context(), sql); err != nil {
		t.Fatal(err)
	}
	// The new authenticator rejects the mark independently of enabled/key state.
	if code, _, _ := rawMCP(t, e.app, "POST", "support", oldKey, rpc(1, "tools/list", nil), nil); code != 401 {
		t.Fatalf("marked old key: %d", code)
	}
	for _, body := range []map[string]any{{"enabled": true}, {"name": "converted"}} {
		cur := sa
		code, raw := e.owner.raw("PATCH", toolsTeam+"/service-accounts/"+sa.Id.String(), body, ifMatch(cur.Revision))
		if code != 409 || errorCode(raw) != "service_account_retired" {
			t.Fatalf("retired update: %d %s", code, raw)
		}
	}
	code, raw := e.owner.raw("POST", toolsTeam+"/service-accounts/"+sa.Id.String()+"/keys", map[string]any{"name": "new"}, nil)
	if code != 409 || errorCode(raw) != "service_account_retired" {
		t.Fatalf("retired key: %d %s", code, raw)
	}
	var view map[string]any
	if code := e.owner.get(toolsTeam+"/service-accounts/"+sa.Id.String(), &view); code != 200 || view["retired"] != true || view["relayPlatform"] != nil {
		t.Fatalf("retired view: %d %v", code, view)
	}
	// Removed fields are rejected by strict decoding; ordinary presence-free
	// updates and the useful self-service consent APIs stay covered separately.
	for _, body := range []map[string]any{{"requiresPresentPerson": true}} {
		code, raw := e.owner.raw("PATCH", toolsTeam+"/mcp-servers/"+e.server.Id.String(), body, ifMatch(e.server.Revision))
		if code != 400 {
			t.Fatalf("removed presence field: %d %s", code, raw)
		}
	}
	code, raw = e.member.raw("PUT", "/v1/me/server-secrets/"+e.server.Id.String(), map[string]any{"origin": "https://old.example", "allowAgents": true}, nil)
	if code != 400 {
		t.Fatalf("removed allowAgents field: %d %s", code, raw)
	}
}
