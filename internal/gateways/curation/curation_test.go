package curation

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

const definition = `{"name":"create","description":"Original","inputSchema":{"type":"object","properties":{"owner":{"type":"string","x-mcp-header":"Owner"},"repo":{"type":"string","enum":["a","b"]},"n":{"type":"integer","minimum":1},"config":{"type":"object","properties":{"active":{"type":"boolean"}},"required":["active"],"additionalProperties":false}},"required":["owner","repo"],"additionalProperties":false}}`

func policy(t *testing.T, raw string) *Policy {
	t.Helper()
	p, err := Decode([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func TestProjectionAndMerge(t *testing.T) {
	original := []byte(definition)
	snapshot := bytes.Clone(original)
	p := policy(t, `{"nameOverride":"issues","descriptionOverride":"For this team","constraints":{"owner":{"fixed":"org"},"repo":{"allowed":["a","unknown",1,"a"]}}}`)
	out, p, err := Project(original, p)
	if err != nil {
		t.Fatal(err)
	}
	var def map[string]any
	_ = json.Unmarshal(out, &def)
	schema := def["inputSchema"].(map[string]any)
	props := schema["properties"].(map[string]any)
	if _, ok := props["owner"]; ok {
		t.Fatal("fixed property remains")
	}
	if def["name"] != "issues" || def["description"] != "For this team" || !Equal(mustJSON(t, schema["required"]), []byte(`["repo"]`)) || !Equal(mustJSON(t, props["repo"].(map[string]any)["enum"]), []byte(`["a"]`)) {
		t.Fatalf("projection: %s", out)
	}
	if !bytes.Equal(original, snapshot) {
		t.Fatal("mutated input")
	}
	for _, args := range []string{`{"repo":"a"}`, `{"repo":"a","owner":"org"}`} {
		merged, err := Merge(p, []byte(args))
		if err != nil || !Equal(merged, []byte(`{"repo":"a","owner":"org"}`)) {
			t.Fatalf("merge: %s %v", merged, err)
		}
	}
	for _, tc := range []struct{ args, msg string }{{`{"owner":"else"}`, "argument owner is fixed"}, {`{"repo":"b"}`, "argument repo is not allowed"}, {`{"repo":1}`, "argument repo is not allowed"}} {
		_, err := Merge(p, []byte(tc.args))
		if err == nil || !strings.Contains(err.Error(), tc.msg) {
			t.Fatalf("%s: %v", tc.args, err)
		}
	}
}
func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func TestMalformedAndUnsupported(t *testing.T) {
	for _, raw := range []string{`null`, `[]`, `{"other":1}`, `{"constraints":null}`, `{"constraints":{"owner":{}}}`, `{"constraints":{"owner":{"fixed":1,"allowed":[1]}}}`, `{"constraints":{"owner":{"allowed":[]}}}`, `{"constraints":{"owner":{"allowed":null}}}`, `{"constraints":{"owner":{"allow":[1]}}}`, `{"nameOverride":"bad name"}`} {
		if _, err := Decode([]byte(raw)); err == nil {
			t.Errorf("accepted %s", raw)
		}
	}
	for _, raw := range []string{`{"constraints":{"absent":{"fixed":1}}}`, `{"constraints":{"owner":{"fixed":1}}}`, `{"constraints":{"repo":{"allowed":["other"]}}}`, `{"constraints":{"n":{"fixed":1.5}}}`, `{"constraints":{"n":{"fixed":0}}}`, `{"constraints":{"config":{"fixed":{"active":"yes"}}}}`} {
		p := policy(t, raw)
		if _, _, err := Project([]byte(definition), p); err == nil {
			t.Errorf("accepted %s", raw)
		}
	}
	for _, schema := range []string{`{"$ref":"#/x"}`, `{"type":"object","properties":{},"oneOf":[]}`, `{"type":"object","properties":{"owner":{"type":"string"}},"dependencies":{}}`, `{"type":"object","properties":{"owner":{"type":"string"}},"allOf":[]}`, `{"type":"object","properties":{"owner":{"type":"string"}},"if":{}}`, `{"type":"object","properties":{"owner":{"type":"string"}},"minProperties":1}`} {
		def := []byte(`{"name":"test","inputSchema":` + schema + `}`)
		if _, _, err := Project(def, policy(t, `{"constraints":{"owner":{"fixed":"org"}}}`)); err == nil {
			t.Errorf("accepted schema %s", schema)
		}
		if _, _, err := Project(def, policy(t, `{"nameOverride":"rename","descriptionOverride":"new"}`)); err != nil {
			t.Errorf("text-only: %v", err)
		}
	}
	for _, extra := range []string{`"oneOf":[]`, `"$ref":"#/x"`, `"format":"email"`, `"dependentRequired":{}`} {
		def := []byte(`{"inputSchema":{"type":"object","properties":{"owner":{"type":"string",` + extra + `}}}}`)
		if _, _, err := Project(def, policy(t, `{"constraints":{"owner":{"fixed":"org"}}}`)); err == nil {
			t.Errorf("ignored unsupported property %s", extra)
		}
	}
}
func TestExactJSONEquality(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want bool
	}{{`9007199254740992`, `9007199254740993`, false}, {`1`, `1.0`, true}, {`1e2`, `100.00`, true}, {`"1"`, `1`, false}, {`true`, `1`, false}, {`{"x":[1,null],"a":2}`, `{"a":2,"x":[1.0,null]}`, true}, {`[1,2]`, `[2,1]`, false}, {`null`, `false`, false}, {`1e100000000`, `1`, false}} {
		if got := Equal([]byte(tc.a), []byte(tc.b)); got != tc.want {
			t.Errorf("%s = %s: %v", tc.a, tc.b, got)
		}
	}
	p := policy(t, `{"constraints":{"n":{"fixed":9007199254740991}}}`)
	if _, err := Merge(p, []byte(`{"n":9007199254740991.1}`)); err == nil {
		t.Fatal("float precision bypass")
	}
	p = policy(t, `{"constraints":{"n":{"allowed":[9007199254740991]}}}`)
	if _, err := Merge(p, []byte(`{"n":9007199254740991.1}`)); err == nil {
		t.Fatal("allowed precision bypass")
	}
}
func TestNestedReferencesNeverFetch(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); w.WriteHeader(500) }))
	defer server.Close()
	for _, keyword := range []string{"$ref", "$dynamicRef"} {
		definition := []byte(`{"inputSchema":{"type":"object","properties":{"owner":{"type":"string"},"unconstrained":{"type":"object","properties":{"nested":{"` + keyword + `":"` + server.URL + `/schema"}}}}}}`)
		if _, _, err := Project(definition, policy(t, `{"constraints":{"owner":{"fixed":"org"}}}`)); err == nil {
			t.Fatalf("accepted nested %s", keyword)
		}
	}
	if requests.Load() != 0 {
		t.Fatal("untrusted schema triggered an outbound request")
	}
}

func TestBoundsAndAudit(t *testing.T) {
	many := strings.TrimSuffix(strings.Repeat(`0,`, MaxValueNodes+1), ",")
	if _, err := Decode([]byte(`{"constraints":{"items":{"fixed":[` + many + `]}}}`)); err == nil {
		t.Fatal("unbounded value work")
	}
	values := make([]string, 1001)
	for i := range values {
		values[i] = "org"
	}
	def := mustJSON(t, map[string]any{"inputSchema": map[string]any{"type": "object", "properties": map[string]any{"owner": map[string]any{"type": "string", "enum": values}}}})
	if _, _, err := Project(def, policy(t, `{"constraints":{"owner":{"fixed":"org"}}}`)); err == nil {
		t.Fatal("unbounded schema enum work")
	}
	if Equal([]byte(`1 2`), []byte(`1`)) || Equal([]byte(`nullx`), []byte(`null`)) {
		t.Fatal("malformed JSON compared equal")
	}
	if _, err := Decode([]byte(`{"descriptionOverride":"` + strings.Repeat("x", 2001) + `"}`)); err == nil {
		t.Fatal("long description")
	}
	if _, err := Decode([]byte(`{"constraints":{"owner":{"fixed":"` + strings.Repeat("x", MaxValueBytes) + `"}}}`)); err == nil {
		t.Fatal("large value")
	}
	p := policy(t, `{"descriptionOverride":"sensitive-description","constraints":{"owner":{"fixed":"sentinel-fixed-secret"},"repo":{"allowed":["sentinel-allowed-secret"]}}}`)
	b := mustJSON(t, Summary(p))
	if bytes.Contains(b, []byte("sentinel")) || bytes.Contains(b, []byte("sensitive-description")) {
		t.Fatalf("audit leaked: %s", b)
	}
}
