package httpapi_test

import (
	"fmt"
	"strings"
	"testing"
)

func TestCurationConsentMergedBinding(t *testing.T) {
	e := newProvEnv(t)
	path := toolsTeam + "/gateways/" + e.gateway.Id.String()
	pin := func(text string) map[string]any {
		return map[string]any{"constraints": map[string]any{"text": map[string]any{"fixed": text}}}
	}
	setCuration(t, e.gwEnv, e.owner, path, "echo", pin("fixed-by-gateway"))
	// All three consent shapes are preserved under curation.
	params := toolCall("status__echo", nil)
	legacy := e.callTool(e.key, "status__echo")
	e.consentURL(legacy, "not_connected")
	plain := e.mcall(e.key, "tools/call", params, nil)
	if plainConsentLink(t, plain, e.app.URL, e.provider.Slug) == "" {
		t.Fatal("missing modern fallback link")
	}
	first := e.mcall(e.key, "tools/call", params, urlCaps)
	link, state := e.inputRequired(first, "status__echo")
	// Equal client fixed value versus omission seals the SAME effective request.
	for _, arguments := range []map[string]any{{}, {"text": "fixed-by-gateway"}} {
		p := toolCall("status__echo", retryWith(state, "accept"))
		p["arguments"] = arguments
		out := e.mcall(e.key, "tools/call", p, urlCaps)
		if rpcErrorCode(out) != 0 {
			t.Fatalf("equal/omitted retry: %v", out)
		}
		e.inputRequired(out, "status__echo")
	}
	// A current policy change cannot reuse an earlier effective argument binding.
	setCuration(t, e.gwEnv, e.owner, path, "echo", pin("new-fixed-value"))
	mismatch := e.mcall(e.key, "tools/call", toolCall("status__echo", retryWith(state, "accept")), urlCaps)
	if rpcErrorCode(mismatch) != -32602 || !strings.Contains(fmt.Sprint(mismatch), "different request") {
		t.Fatalf("fixed-change retry: %v", mismatch)
	}
	if e.toolCalls("echo") != 0 {
		t.Fatal("retry mismatch reached upstream")
	}
	setCuration(t, e.gwEnv, e.owner, path, "echo", pin("fixed-by-gateway"))
	if err := e.connectQuiet(link); err != nil {
		t.Fatal(err)
	}
	p := toolCall("status__echo", retryWith(state, "accept"))
	out := e.mcall(e.key, "tools/call", p, urlCaps)
	if out["error"] != nil || !strings.Contains(fmt.Sprint(resultOf(t, out)), "fixed-by-gateway") {
		t.Fatalf("connected retry: %v", out)
	}
	calls := e.fake.ToolCalls()
	last := calls[len(calls)-1]
	if last.Tool != "echo" || !strings.Contains(string(last.Arguments), "fixed-by-gateway") || last.Meta["io.modelcontextprotocol/clientInfo"] == nil {
		t.Fatalf("merged call/meta: %+v", last)
	}
}

func TestCurationRefusesBeforeConsent(t *testing.T) {
	e := newProvEnv(t)
	path := toolsTeam + "/gateways/" + e.gateway.Id.String()
	setCuration(t, e.gwEnv, e.owner, path, "echo", map[string]any{"constraints": map[string]any{"text": map[string]any{"allowed": []string{"safe"}}}})
	before := e.scalar(`SELECT count(*)::text FROM provider_connect_requests`)
	out := e.mcall(e.key, "tools/call", toolCall("status__echo", map[string]any{"arguments": map[string]any{"text": "refused"}}), urlCaps)
	if rpcErrorCode(out) != -32602 || !strings.Contains(fmt.Sprint(out), "argument text is not allowed") {
		t.Fatalf("constraint: %v", out)
	}
	if after := e.scalar(`SELECT count(*)::text FROM provider_connect_requests`); before != after {
		t.Fatal("constraint violation created consent")
	}
	if e.toolCalls("echo") != 0 {
		t.Fatal("constraint violation forwarded")
	}
}
