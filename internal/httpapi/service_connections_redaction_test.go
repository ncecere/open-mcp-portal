package httpapi_test

import (
	"bytes"
	"encoding/json"
	"github.com/google/uuid"
	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/registry"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestServiceConnectionTokensRedactedFromProgressSpansAndCaptures(t *testing.T) {
	for _, kind := range []string{"stored", "refreshed", "narrowed"} {
		t.Run(kind, func(t *testing.T) {
			sr := tracingOn(t)
			e := newProvEnv(t)
			e.fake.EnableStreamTools()
			code, ec := e.owner.call("POST", e.serverPath()+"/refresh", nil, nil, nil)
			mustCode(t, "discover progress", code, ec, 200, "")
			e.mustSetCaps(e.owner, toolsTeam+"/gateways/"+e.gateway.Id.String(), sel(e.capID(e.owner, e.server, "tool", "progress")))
			var current apitypes.McpServer
			if code := e.owner.get(e.serverPath(), &current); code != 200 {
				t.Fatal(code)
			}
			code, ec = e.owner.call("PATCH", e.serverPath(), map[string]any{"capturePayloads": true}, nil, ifMatch(current.Revision))
			mustCode(t, "capture", code, ec, 200, "")
			sa := createSA(t, e.owner, map[string]any{"name": "sentinel-ci"})
			key := createSAKey(t, e.owner, sa.Id.String(), map[string]any{"name": "ci"}).Secret
			c := connectShared(t, e.owner, e.provider.Id, "sentinel")
			code, ec, _ = assignShared(t, e.owner, c, []uuid.UUID{sa.Id}, []apitypes.ServiceConnectionGrant{{ServerId: e.server.Id, Origin: registry.OriginOf(e.server.Url), Scopes: []string{"repo"}}})
			mustCode(t, "assign", code, ec, 200, "")
			if kind == "refreshed" {
				e.scalar(`UPDATE service_connections SET expires_at=now() WHERE id=$1 RETURNING 'ok'`, c.Id)
			}
			if kind == "narrowed" {
				e.scalar(`UPDATE auth_providers SET narrow_on_refresh=true WHERE id=$1 RETURNING 'ok'`, e.provider.Id)
				e.oauth.Set(func(f *testutil.FakeOAuth) { f.HonourRefreshScope = true })
			}
			body, headers := toolRequest(true, "status__progress", map[string]any{"count": 2, "delay_ms": 1, "echo_credentials": true}, map[string]any{"progressToken": "safe-progress-id"})
			encoded, _ := json.Marshal(body)
			req, _ := http.NewRequest("POST", e.app.URL+"/mcp/support", bytes.NewReader(encoded))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Accept", "application/json, text/event-stream")
			req.Header.Set("Authorization", "Bearer "+key)
			for k, v := range headers {
				req.Header.Set(k, v)
			}
			res, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := io.ReadAll(res.Body)
			res.Body.Close()
			if err != nil {
				t.Fatal(err)
			}
			if res.StatusCode != 200 || !strings.Contains(string(raw), "notifications/progress") || !strings.Contains(string(raw), "REDACTED") {
				t.Fatalf("progress response = %d %s", res.StatusCode, raw)
			}
			var payloadID string
			for range 100 {
				payloadID = e.scalar(`SELECT coalesce(max(call_id)::text,'') FROM mcp_call_payloads`)
				if payloadID != "" {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			if payloadID == "" {
				t.Fatal("capture was not recorded")
			}
			code, payload := e.admin.raw("GET", "/v1/admin/calls/"+payloadID+"/payload", nil, nil)
			if code != 200 {
				t.Fatalf("payload %d %s", code, payload)
			}
			dump := string(raw) + string(payload) + e.logs.String() + e.scalar(`SELECT coalesce(json_agg(a)::text,'') FROM audit_log a`) + e.scalar(`SELECT coalesce(json_agg(c)::text,'') FROM mcp_calls c`)
			for _, span := range sr.Ended() {
				dump += span.Name() + span.Status().Description
				for _, a := range span.Attributes() {
					dump += a.Value.Emit()
				}
				for _, event := range span.Events() {
					dump += event.Name
					for _, a := range event.Attributes {
						dump += a.Value.Emit()
					}
				}
			}
			for _, token := range append(e.oauth.Issued(), e.oauth.IssuedRefresh()...) {
				if strings.Contains(dump, token) {
					t.Fatalf("%s token leaked into progress, spans, capture, response, audit or logs", kind)
				}
			}
		})
	}
}
