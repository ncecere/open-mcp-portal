package httpapi_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/ncecere/open-mcp-portal/internal/gateways/curation"
)

// The fake's raw echo handler permits additional arguments. Give its discovered
// definition numeric/complex properties in this test's owned database so the
// complete HTTP selection, storage, list, and call path exercises those values.
func numericCurationSchema(t *testing.T, e *gwEnv) {
	t.Helper()
	definition := `{"name":"echo","inputSchema":{"type":"object","properties":{"text":{"type":"string"},"n":{"type":"number"},"config":{},"choice":{},"allowed":{"type":"number"},"zero":{"type":"number"},"nil":{}}}}`
	if _, err := e.app.Pool.Exec(t.Context(), `UPDATE mcp_capabilities SET definition=$1 WHERE server_id=$2 AND name='echo' AND kind='tool'`, definition, e.server.Id); err != nil {
		t.Fatal(err)
	}
}

func numericCuration(n string) json.RawMessage {
	return json.RawMessage(fmt.Sprintf(`{"constraints":{"n":{"fixed":%s},"config":{"fixed":{"nested":[%s,null,"0e-9999"]}},"choice":{"allowed":[{"nested":[%s,null,"0e-9999"]}]},"allowed":{"allowed":[%s]},"zero":{"fixed":0e-9999},"nil":{"fixed":null}}}`, n, n, n, n))
}

func TestCurationNumbersHTTPStorageRoundTrip(t *testing.T) {
	e := newEraEnv(t)
	numericCurationSchema(t, e.gwEnv)
	for _, n := range []string{"1e-254", "1e-255", "1e-300", "5e-324", "0e-9999", "-0e10000", "0.1", "0.1000000000000000000000000000000000000"} {
		t.Run(n, func(t *testing.T) {
			authored := numericCuration(n)
			setCuration(t, e.gwEnv, e.owner, e.path, "echo", authored)
			loaded := selectedTool(t, e.owner, e.path, "echo")
			if !loaded.Available || (loaded.Stale != nil && *loaded.Stale) {
				t.Fatalf("policy became stale after JSONB reload: %+v", loaded)
			}
			if !curation.Equal(authored, loaded.Curation) {
				t.Fatalf("storage silently changed a numeric value: %s", loaded.Curation)
			}
			var storedZero string
			if err := e.app.Pool.QueryRow(t.Context(), `SELECT constraints->'zero'->>'fixed' FROM gateway_capabilities WHERE gateway_id=$1 AND capability_id=$2`, e.gw.Id, loaded.CapabilityId).Scan(&storedZero); err != nil || storedZero != "0" {
				t.Fatalf("zero exponent expanded in storage: length=%d err=%v", len(storedZero), err)
			}
			before, err := curation.Decode(authored)
			if err != nil {
				t.Fatal(err)
			}
			after, err := curation.Decode(loaded.Curation)
			if err != nil {
				t.Fatal(err)
			}
			a, err := curation.Merge(before, []byte(`{"text":"hello"}`))
			if err != nil {
				t.Fatal(err)
			}
			b, err := curation.Merge(after, []byte(`{"text":"hello"}`))
			if err != nil || !bytes.Equal(a, b) || sha256.Sum256(a) != sha256.Sum256(b) {
				t.Fatalf("fixed argument/retry digest changed on reload: %s / %s: %v", a, b, err)
			}
			var renamed map[string]json.RawMessage
			if err := json.Unmarshal(loaded.Curation, &renamed); err != nil {
				t.Fatal(err)
			}
			renamed["nameOverride"] = json.RawMessage(`"numeric_echo"`)
			setCuration(t, e.gwEnv, e.owner, e.path, "echo", renamed)
			_, _, listed := e.legacy("tools/list", nil)
			if !strings.Contains(fmt.Sprint(listed), "numeric_echo") {
				t.Fatalf("reloaded numeric policy not listed: %v", listed)
			}
			choice := json.RawMessage(fmt.Sprintf(`{"nested":[%s,null,"0e-9999"]}`, n))
			beforeCalls := len(e.fake.ToolCalls())
			_, _, out := e.legacy("tools/call", map[string]any{"name": "numeric_echo", "arguments": map[string]any{"text": "hello", "choice": choice, "allowed": json.RawMessage(n)}})
			calls := e.fake.ToolCalls()
			if out["error"] != nil || len(calls) != beforeCalls+1 {
				t.Fatalf("reloaded numeric policy refused call: %v", out)
			}
			expected := json.RawMessage(fmt.Sprintf(`{"text":"hello","n":%s,"config":{"nested":[%s,null,"0e-9999"]},"choice":%s,"allowed":%s,"zero":0,"nil":null}`, n, n, choice, n))
			if !curation.Equal(calls[len(calls)-1].Arguments, expected) {
				t.Fatalf("merged arguments silently rounded or lost null/string types: %s", calls[len(calls)-1].Arguments)
			}
			_, _, out = e.legacy("tools/call", map[string]any{"name": "numeric_echo", "arguments": map[string]any{"n": json.RawMessage(`0.10000000000000001`)}})
			if out["error"] == nil || len(e.fake.ToolCalls()) != beforeCalls+1 {
				t.Fatal("rounded conflicting fixed value reached upstream")
			}
		})
	}
}

func TestCurationNumericConsentBindingSurvivesResave(t *testing.T) {
	e := newProvEnv(t)
	numericCurationSchema(t, e.gwEnv)
	path := toolsTeam + "/gateways/" + e.gateway.Id.String()
	setCuration(t, e.gwEnv, e.owner, path, "echo", numericCuration("5e-324"))
	params := toolCall("status__echo", map[string]any{"arguments": map[string]any{"text": "hello"}})
	first := e.mcall(e.key, "tools/call", params, urlCaps)
	link, state := e.inputRequired(first, "status__echo")
	loaded := selectedTool(t, e.owner, path, "echo")
	var renamed map[string]json.RawMessage
	if err := json.Unmarshal(loaded.Curation, &renamed); err != nil {
		t.Fatal(err)
	}
	renamed["descriptionOverride"] = json.RawMessage(`"Changed after reload"`)
	setCuration(t, e.gwEnv, e.owner, path, "echo", renamed)
	retry := toolCall("status__echo", retryWith(state, "accept"))
	retry["arguments"] = map[string]any{"text": "hello", "n": json.RawMessage("0." + strings.Repeat("0", 323) + "5")}
	out := e.mcall(e.key, "tools/call", retry, urlCaps)
	if out["error"] != nil {
		t.Fatalf("numeric reload/resave changed consent digest: %v", out)
	}
	e.inputRequired(out, "status__echo")
	if err := e.connectQuiet(link); err != nil {
		t.Fatal(err)
	}
	out = e.mcall(e.key, "tools/call", retry, urlCaps)
	if out["error"] != nil || e.toolCalls("echo") != 1 {
		t.Fatalf("connected numeric retry failed: %v", out)
	}
}
