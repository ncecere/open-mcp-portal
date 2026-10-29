package ompcli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"gopkg.in/yaml.v3"
)

func compileSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "api", "omp-v1.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource("omp-v1.schema.json", doc); err != nil {
		t.Fatal(err)
	}
	s, err := c.Compile("omp-v1.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func schemaAccepts(t *testing.T, s *jsonschema.Schema, doc string) bool {
	t.Helper()
	var v any
	if err := yaml.Unmarshal([]byte(doc), &v); err != nil {
		return false
	}
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	return s.Validate(inst) == nil
}

// The published JSON Schema and the CLI's own validation agree on what is a
// valid file; the CLI additionally checks what a schema cannot (duplicates,
// default above ceiling).
func TestFileValidationAgreesWithTheJSONSchema(t *testing.T) {
	schema := compileSchema(t)
	const head = "schema: omp/v1\n"
	srv := "servers:\n- team: bravo\n  slug: status\n  name: Status\n  url: https://s.example.com/mcp\n"
	cases := []struct {
		name         string
		doc          string
		goOK, schOK  bool
		errorContain string
	}{
		{"minimal", head, true, true, ""},
		{"server", head + srv, true, true, ""},
		{"static header", head + srv + "  authMode: static_header\n  authHeaderName: X-API-Key\n  authValueEnv: STATUS_KEY\n  publish: request\n", true, true, ""},
		{"wrong schema", "schema: omp/v2\n", false, false, "schema must be"},
		{"missing schema", "servers: []\n", false, false, "schema must be"},
		{"unknown top-level key", head + "bogus: 1\n", false, false, "bogus"},
		{"unknown server key", head + srv + "  authValue: hunter2\n", false, false, "authValue"},
		{"bad slug", head + strings.Replace(srv, "status", "Bad_Slug", 1), false, false, "slug must be"},
		{"missing name", head + "servers:\n- team: bravo\n  slug: status\n  url: https://s.example.com/mcp\n", false, false, "name is required"},
		{"relative url", head + strings.Replace(srv, "https://s.example.com/mcp", "s.example.com/mcp", 1), false, false, "absolute"},
		{"oauth is not manageable", head + srv + "  authMode: oauth\n", false, false, "browser session"},
		{"header without mode", head + srv + "  authHeaderName: X-API-Key\n", false, false, "static_header"},
		{"static without header", head + srv + "  authMode: static_header\n", false, false, "authHeaderName"},
		{"secret literal in authValueEnv", head + srv + "  authMode: static_header\n  authHeaderName: X\n  authValueEnv: \"sk-live 123/abc\"\n", false, false, "NAME of an environment variable"},
		{"bad publish", head + srv + "  publish: yes\n", false, false, "publish must be"},
		{"duplicate server", head + srv + srv[len("servers:\n"):], false, true, "duplicate server slug"},
		{"team", head + "teams:\n- slug: bravo\n  name: Bravo\n  ownerEmail: boss@example.com\n  limits:\n    gateway_per_minute: 100\n    server_per_minute: null\n", true, true, ""},
		{"bad limit key", head + "teams:\n- slug: bravo\n  name: Bravo\n  limits:\n    nope: 1\n", false, false, "not a rate-limit key"},
		{"limit zero", head + "teams:\n- slug: bravo\n  name: Bravo\n  limits:\n    gateway_per_minute: 0\n", false, false, "between 1 and 1000000"},
		{"bad status", head + "teams:\n- slug: bravo\n  name: Bravo\n  status: gone\n", false, false, "status must be"},
		{"gateway", head + "gateways:\n- slug: support\n  name: Support\n  enabled: true\n  capabilities:\n  - {server: status, kind: tool, name: check}\n  grants:\n  - {team: bravo}\n  - {group: eng}\n  - {userEmail: a@example.com, toolScope: {classes: [read]}}\n", true, true, ""},
		{"empty lists are explicit", head + "gateways:\n- slug: support\n  name: Support\n  capabilities: []\n  grants: []\n", true, true, ""},
		{"bad capability kind", head + "gateways:\n- slug: g\n  name: G\n  capabilities:\n  - {server: s, kind: gadget, name: n}\n", false, false, "kind of tool"},
		{"grant with two subjects", head + "gateways:\n- slug: g\n  name: G\n  grants:\n  - {team: a, group: b}\n", false, false, "exactly one"},
		{"grant with none", head + "gateways:\n- slug: g\n  name: G\n  grants:\n  - {}\n", false, false, "exactly one"},
		{"bad tool class", head + "gateways:\n- slug: g\n  name: G\n  grants:\n  - {team: a, toolScope: {classes: [admin]}}\n", false, false, "read, write or destructive"},
		{"platform limits", head + "limits:\n  person_per_minute: {default: 600, ceiling: null}\n", true, true, ""},
		{"limit missing ceiling means none", head + "limits:\n  person_per_minute: {default: 600}\n", true, true, ""},
		{"default above ceiling", head + "limits:\n  person_per_minute: {default: 600, ceiling: 100}\n", false, true, "above the ceiling"},
		{"json is yaml", `{"schema":"omp/v1","servers":[{"team":"bravo","slug":"status","name":"S","url":"https://s.example.com/mcp"}]}`, true, true, ""},
	}
	for _, c := range cases {
		_, err := ParseFile([]byte(c.doc))
		if (err == nil) != c.goOK {
			t.Errorf("%s: ParseFile error = %v, want ok=%v", c.name, err, c.goOK)
		} else if err != nil {
			if e := asError(err); e.Exit != ExitUsage {
				t.Errorf("%s: exit %d", c.name, e.Exit)
			}
			if c.errorContain != "" && !strings.Contains(err.Error(), c.errorContain) {
				t.Errorf("%s: %q does not mention %q", c.name, err, c.errorContain)
			}
		}
		if got := schemaAccepts(t, schema, c.doc); got != c.schOK {
			t.Errorf("%s: the JSON Schema accepts = %v, want %v", c.name, got, c.schOK)
		}
	}
}

func TestParseFileRejectsMultipleDocumentsAndEmpty(t *testing.T) {
	for _, doc := range []string{"", "   \n", "schema: omp/v1\n---\nschema: omp/v1\n"} {
		if _, err := ParseFile([]byte(doc)); err == nil {
			t.Errorf("%q accepted", doc)
		}
	}
}

// The JSON Schema's property names are exactly the struct fields the CLI reads.
func TestSchemaPropertiesMatchTheTypes(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "api", "omp-v1.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Props map[string]any            `json:"properties"`
		Defs  map[string]map[string]any `json:"$defs"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	props := func(m map[string]any) []string {
		var out []string
		for k := range m["properties"].(map[string]any) {
			out = append(out, k)
		}
		return out
	}
	jsonFields := func(v any) []string {
		b, _ := json.Marshal(v)
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		var out []string
		for k := range m {
			out = append(out, k)
		}
		return out
	}
	full := func(v any) map[string]bool {
		out := map[string]bool{}
		for _, k := range tagNames(v) {
			out[k] = true
		}
		return out
	}
	check := func(name string, schemaProps []string, v any) {
		want := full(v)
		for _, p := range schemaProps {
			if !want[p] {
				t.Errorf("%s: the schema has %q, which the CLI does not read", name, p)
			}
			delete(want, p)
		}
		for p := range want {
			t.Errorf("%s: the CLI reads %q, which the schema lacks", name, p)
		}
	}
	_ = jsonFields
	check("top level", props(map[string]any{"properties": doc.Props}), File{})
	check("server", props(doc.Defs["server"]), Server{})
	check("team", props(doc.Defs["team"]), Team{})
	check("gateway", props(doc.Defs["gateway"]), Gateway{})
	check("capability", props(doc.Defs["capability"]), CapabilityRef{})
	check("grant", props(doc.Defs["grant"]), Grant{})
	check("platformLimit", props(doc.Defs["platformLimit"]), PlatformLimit{})
}
