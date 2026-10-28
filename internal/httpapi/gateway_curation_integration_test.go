package httpapi_test

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
)

func curationItem(c apitypes.GatewayCapability, p any) map[string]any {
	return map[string]any{"capabilityId": c.CapabilityId.String(), "expectedFingerprint": *c.Fingerprint, "curation": p}
}
func currentSelection(t *testing.T, s *session, path string) apitypes.GatewayCapabilities {
	t.Helper()
	var out apitypes.GatewayCapabilities
	if code := s.get(path+"/capabilities", &out); code != 200 {
		t.Fatalf("selection: %d", code)
	}
	return out
}
func selectedTool(t *testing.T, s *session, path, name string) apitypes.GatewayCapability {
	t.Helper()
	for _, c := range currentSelection(t, s, path).Items {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("no selected %s", name)
	return apitypes.GatewayCapability{}
}
func setCuration(t *testing.T, e *gwEnv, s *session, path, name string, p any) apitypes.GatewayCapabilities {
	t.Helper()
	cur := currentSelection(t, s, path)
	items := []map[string]any{}
	for _, c := range cur.Items {
		if c.Name == name {
			items = append(items, curationItem(c, p))
		} else {
			it := map[string]any{"capabilityId": c.CapabilityId.String()}
			if c.MinRole != nil {
				it["minRole"] = *c.MinRole
			}
			items = append(items, it)
		}
	}
	return e.mustSetCaps(s, path, map[string]any{"items": items})
}
func lookupPolicy(region string) map[string]any {
	return map[string]any{"nameOverride": "lookup_team", "descriptionOverride": "Look up our region only", "constraints": map[string]any{"region": map[string]any{"fixed": region}, "limit": map[string]any{"allowed": []int{2, 3}}}}
}
func TestCurationListCallBothEras(t *testing.T) {
	e := newEraEnv(t)
	before := selectedTool(t, e.owner, e.path, "lookup")
	e.publish(e.owner, e.server)
	var catalogBefore apitypes.CatalogServerDetail
	if code := e.member.get("/v1/catalog/servers/"+e.server.Id.String(), &catalogBefore); code != 200 {
		t.Fatalf("catalog before: %d", code)
	}
	second := e.createGateway(e.owner, toolsTeam+"/gateways", "uncurated")
	secondPath := toolsTeam + "/gateways/" + second.Id.String()
	e.mustSetCaps(e.owner, secondPath, sel(before.CapabilityId.String()))
	setCuration(t, e.gwEnv, e.owner, e.path, "lookup", lookupPolicy("us"))
	for _, modern := range []bool{false, true} {
		t.Run(fmt.Sprint(modern), func(t *testing.T) {
			call := func(method string, p map[string]any, headers map[string]string) map[string]any {
				if modern {
					_, _, out := e.modern(method, p, nil, headers)
					return out
				}
				_, _, out := e.legacy(method, p)
				return out
			}
			out := call("tools/list", nil, nil)
			var tool map[string]any
			for _, raw := range resultOf(t, out)["tools"].([]any) {
				d := raw.(map[string]any)
				if d["name"] == "status__lookup" {
					t.Fatal("original name listed")
				}
				if d["name"] == "lookup_team" {
					tool = d
				}
			}
			if tool == nil || tool["description"] != "Look up our region only" {
				t.Fatalf("list: %v", out)
			}
			props := tool["inputSchema"].(map[string]any)["properties"].(map[string]any)
			if props["region"] != nil || !equalJSON(props["limit"].(map[string]any)["enum"], []int{2, 3}) {
				t.Fatalf("narrowed: %v", props)
			}
			for _, args := range []map[string]any{{"limit": 2}, {"limit": 2, "region": "us"}} {
				out = call("tools/call", map[string]any{"name": "lookup_team", "arguments": args}, map[string]string{"Mcp-Param-Limit": "2", "Mcp-Param-Region": "attacker"})
				if out["error"] != nil {
					t.Fatalf("call: %v", out)
				}
				calls := e.fake.ToolCalls()
				last := calls[len(calls)-1]
				if last.Tool != "lookup" || !strings.Contains(string(last.Arguments), `"region":"us"`) || (modern && (last.Header.Get("Mcp-Param-Region") != "us" || last.Header.Get("Mcp-Param-Limit") != "2")) {
					t.Fatalf("upstream: %+v", last)
				}
			}
			beforeCalls := len(e.fake.ToolCalls())
			for _, tc := range []struct {
				name string
				args map[string]any
			}{{"lookup_team", map[string]any{"region": "other", "limit": 2}}, {"lookup_team", map[string]any{"limit": 4}}, {"status__lookup", map[string]any{"limit": 2}}} {
				out = call("tools/call", map[string]any{"name": tc.name, "arguments": tc.args}, map[string]string{"Mcp-Param-Limit": fmt.Sprint(tc.args["limit"])})
				if rpcErrorCode(out) != -32602 {
					t.Errorf("refused: %v", out)
				}
			}
			if len(e.fake.ToolCalls()) != beforeCalls {
				t.Fatal("constraint refusal reached upstream")
			}
			if modern {
				status, _, out := e.modern("tools/call", map[string]any{"name": "lookup_team", "arguments": map[string]any{"limit": 2}}, nil, map[string]string{"Mcp-Name": "status__lookup", "Mcp-Param-Limit": "2"})
				if status != 400 || rpcErrorCode(out) != -32020 {
					t.Fatalf("name header: %d %v", status, out)
				}
			}
		})
	}
	var catalogAfter apitypes.CatalogServerDetail
	if code := e.member.get("/v1/catalog/servers/"+e.server.Id.String(), &catalogAfter); code != 200 || !equalJSON(catalogBefore, catalogAfter) {
		t.Fatal("curation changed the catalog")
	}
	after := selectedTool(t, e.owner, e.path, "lookup")
	if string(before.OriginalDefinition) != string(after.OriginalDefinition) || before.Fingerprint == nil || *before.Fingerprint != *after.Fingerprint {
		t.Fatal("stored definition changed")
	}
	other := selectedTool(t, e.owner, secondPath, "lookup")
	if len(other.Curation) > 0 || other.ExposedName != "status__lookup" || string(other.OriginalDefinition) != string(before.OriginalDefinition) {
		t.Fatal("other gateway changed")
	}
	var mine apitypes.MyGatewayDetail
	if code := e.member.get("/v1/me/gateways/"+e.gw.Id.String(), &mine); code != 200 {
		t.Fatalf("personal view: %d", code)
	}
	for _, c := range mine.Capabilities {
		if c.ExposedName == "lookup_team" && (len(c.OriginalDefinition) != 0 || string(c.Curation) != `{}`) {
			t.Fatal("personal view disclosed hidden policy")
		}
	}
	setCuration(t, e.gwEnv, e.owner, e.path, "lookup", nil)
	restored := selectedTool(t, e.owner, e.path, "lookup")
	if restored.ExposedName != "status__lookup" || restored.Description != before.Description || len(restored.Curation) > 0 {
		t.Fatalf("clear: %+v", restored)
	}
}

func TestCurationSelectionConcurrencyStaleAndAudit(t *testing.T) {
	logs := &syncBuffer{}
	e := newGwEnv(t, slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	e.fake.EnableSchemaTools()
	e.refresh(e.owner, e.server)
	gw := e.createGateway(e.owner, toolsTeam+"/gateways", "curated")
	path := toolsTeam + "/gateways/" + gw.Id.String()
	id := e.capID(e.owner, e.server, "tool", "lookup")
	echo := e.capID(e.owner, e.server, "tool", "echo")
	e.mustSetCaps(e.owner, path, sel(id, echo))
	const sentinel = "sentinel-fixed-secret-that-must-not-be-audited"
	setCuration(t, e, e.owner, path, "lookup", lookupPolicy(sentinel))
	cap := selectedTool(t, e.owner, path, "lookup")
	// Selection/minimum-role changes omit curation and must preserve every field.
	e.mustSetCaps(e.owner, path, sel(id+":editor", echo))
	kept := selectedTool(t, e.owner, path, "lookup")
	if string(kept.Curation) != string(cap.Curation) || kept.ExposedName != cap.ExposedName {
		t.Fatal("selection edit erased policy")
	}
	for _, who := range []*session{e.editor, e.member, e.auditor, e.admin} {
		code, _ := e.setCaps(who, path, map[string]any{"items": []any{curationItem(kept, nil)}})
		if code != 403 {
			t.Fatalf("unauthorized curation: %d", code)
		}
	}
	// Fingerprint is required even for explicit null; gateway If-Match remains required.
	item := curationItem(kept, nil)
	item["expectedFingerprint"] = "old"
	code, raw := e.setCaps(e.owner, path, map[string]any{"items": []any{item}})
	if code != 409 || !strings.Contains(string(raw), "changed_since_review") {
		t.Fatalf("stale fp: %d %s", code, raw)
	}
	delete(item, "expectedFingerprint")
	code, raw = e.setCaps(e.owner, path, map[string]any{"items": []any{item}})
	if code != 409 {
		t.Fatalf("missing fp clear: %d %s", code, raw)
	}
	code, _ = e.owner.raw("PUT", path+"/capabilities", map[string]any{"items": []any{curationItem(kept, nil)}}, nil)
	if code != 428 {
		t.Fatalf("missing If-Match: %d", code)
	}
	// Collisions include default names, unavailable selections, and swaps use the final batch.
	item = curationItem(kept, map[string]any{"nameOverride": "status__echo"})
	code, raw = e.setCaps(e.owner, path, map[string]any{"items": []any{item, map[string]any{"capabilityId": echo}}})
	if code != 409 || !strings.Contains(string(raw), "name_taken") {
		t.Fatalf("collision: %d %s", code, raw)
	}
	echoCap := selectedTool(t, e.owner, path, "echo")
	e.mustSetCaps(e.owner, path, map[string]any{"items": []any{curationItem(kept, map[string]any{"nameOverride": "status__echo"}), curationItem(echoCap, map[string]any{"nameOverride": "lookup_team"})}})
	e.fake.Hide("echo")
	e.refresh(e.owner, e.server)
	lookup := selectedTool(t, e.owner, path, "lookup")
	code, raw = e.setCaps(e.owner, path, map[string]any{"items": []any{curationItem(lookup, map[string]any{"nameOverride": "lookup_team"}), map[string]any{"capabilityId": echo}}})
	if code != 409 {
		t.Fatalf("unavailable collision: %d %s", code, raw)
	}
	// Restore meaningful policy, then change upstream description. Own-team tools
	// fail closed too; catalog reapproval is NOT a policy resave.
	echoCap = selectedTool(t, e.owner, path, "echo")
	e.mustSetCaps(e.owner, path, map[string]any{"items": []any{curationItem(lookup, lookupPolicy("us")), curationItem(echoCap, nil)}})
	e.publish(e.owner, e.server)
	e.fake.SetDescription("lookup", "Definition changed")
	e.refresh(e.owner, e.server)
	stale := selectedTool(t, e.owner, path, "lookup")
	if stale.Available || stale.Stale == nil || !*stale.Stale || stale.UnavailableReason == nil || *stale.UnavailableReason != "curation_stale" {
		t.Fatalf("stale: %+v", stale)
	}
	approval := "/v1/admin/mcp-servers/" + e.server.Id.String() + "/capabilities/" + id + "/approval"
	code, ec := e.admin.call("PUT", approval, approvalBody(t, e.admin, approval), nil, nil)
	mustCode(t, "approve upstream change", code, ec, 200, "")
	stillStale := selectedTool(t, e.owner, path, "lookup")
	if stillStale.Available || stillStale.UnavailableReason == nil || *stillStale.UnavailableReason != "curation_stale" {
		t.Fatal("reapproval bypassed stale curation")
	}
	var viewed apitypes.Gateway
	if status := e.owner.get(path, &viewed); status != 200 || viewed.UnavailableCount < 1 {
		t.Fatalf("management stale count: %d %+v", status, viewed)
	}
	setCuration(t, e, e.owner, path, "lookup", lookupPolicy("us"))
	fresh := selectedTool(t, e.owner, path, "lookup")
	if !fresh.Available || fresh.Stale == nil || *fresh.Stale {
		t.Fatalf("resave: %+v", fresh)
	}
	var auditText string
	if err := e.app.Pool.QueryRow(context.Background(), `SELECT string_agg(coalesce(before_state::text,'') || coalesce(after_state::text,''), '') FROM audit_log WHERE action='gateway.capabilities_set'`).Scan(&auditText); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(auditText, sentinel) || strings.Contains(logs.String(), sentinel) {
		t.Fatal("constraint secret leaked to audit/logs")
	}
	if !strings.Contains(auditText, "constraintsDigest") {
		t.Fatal("policy not audited")
	}
	// Removal cascades the policy; selecting again starts uncurated.
	e.mustSetCaps(e.owner, path, sel())
	e.mustSetCaps(e.owner, path, sel(id))
	if len(selectedTool(t, e.owner, path, "lookup").Curation) > 0 {
		t.Fatal("removed policy survived")
	}
}

// Ensure response policy raw JSON retains null and exact integer values.
func TestCurationExactPolicyAPI(t *testing.T) {
	e := newEraEnv(t)
	cap := selectedTool(t, e.owner, e.path, "lookup")
	p := json.RawMessage(`{"constraints":{"limit":{"fixed":9007199254740993}}}`)
	setCuration(t, e.gwEnv, e.owner, e.path, "lookup", p)
	out := selectedTool(t, e.owner, e.path, "lookup")
	if !strings.Contains(string(out.Curation), "9007199254740993") || *out.Fingerprint != *cap.Fingerprint {
		t.Fatalf("precision: %s", out.Curation)
	}
}
