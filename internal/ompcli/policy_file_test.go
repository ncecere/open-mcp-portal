package ompcli

import (
	"encoding/json"
	"strings"
	"testing"
)

// The omp/v1 file carries a tool's curation and a grant's deadline. Everything a
// file says about them is checked offline, with the portal's own rules, and
// nothing YAML-specific can turn into a different policy.

const gwHead = "schema: omp/v1\ngateways:\n- slug: g\n  name: G\n  capabilities:\n"

func parseCap(t *testing.T, capLines string) (*File, error) {
	t.Helper()
	return ParseFile([]byte(gwHead + capLines))
}

func TestCurationInAFileIsValidatedWithThePortalsRules(t *testing.T) {
	ok := "  - server: status\n    kind: tool\n    name: check\n    curation:\n      nameOverride: check_team\n      descriptionOverride: Our region only\n      constraints:\n        region: {fixed: us}\n        limit: {allowed: [2, 3]}\n        dry: {fixed: null}\n"
	f, err := parseCap(t, ok)
	if err != nil {
		t.Fatalf("valid curation: %v", err)
	}
	c := (*f.Gateways[0].Capabilities)[0].Curation
	if c == nil || c.Clear || c.Policy == nil || len(c.Policy.Constraints) != 3 {
		t.Fatalf("curation: %+v", c)
	}
	if string(c.Policy.Constraints["dry"].Fixed) != "null" {
		t.Errorf("fixed null is a value, not an omission: %q", c.Policy.Constraints["dry"].Fixed)
	}

	bad := map[string]struct{ lines, contain string }{
		"unknown field":      {"    curation: {rename: x}\n", `no field "rename"`},
		"bad name":           {"    curation: {nameOverride: 'has space'}\n", "nameOverride"},
		"fixed and allowed":  {"    curation: {constraints: {a: {fixed: 1, allowed: [1]}}}\n", "exactly one fixed"},
		"neither":            {"    curation: {constraints: {a: {}}}\n", "exactly one fixed"},
		"empty allowed":      {"    curation: {constraints: {a: {allowed: []}}}\n", "exactly one fixed"},
		"rounded number":     {"    curation: {constraints: {a: {fixed: 0.10000000000000001}}}\n", "round-trip"},
		"not a safe integer": {"    curation: {constraints: {a: {fixed: 9007199254740993}}}\n", "round-trip"},
		"hex integer":        {"    curation: {constraints: {a: {fixed: 0x10}}}\n", "plain decimal"},
		"timestamp":          {"    curation: {constraints: {a: {fixed: 2026-01-02}}}\n", "quote it"},
		"alias":              {"    curation: &p {constraints: {a: {fixed: *p}}}\n", "aliases"},
		"duplicate key":      {"    curation: {constraints: {a: {fixed: 1}, a: {fixed: 2}}}\n", "is given twice"},
		"not a mapping":      {"    curation: [1]\n", "mapping or null"},
		"a scalar":           {"    curation: yes please\n", "mapping or null"},
	}
	for name, c := range bad {
		_, err := parseCap(t, "  - server: status\n    kind: tool\n    name: check\n"+c.lines)
		if err == nil || !strings.Contains(err.Error(), c.contain) {
			t.Errorf("%s: %v (want %q)", name, err, c.contain)
		} else if e := asError(err); e.Exit != ExitUsage {
			t.Errorf("%s: exit %d", name, e.Exit)
		}
	}

	// Only tools can be curated.
	if _, err := parseCap(t, "  - server: status\n    kind: prompt\n    name: p\n    curation: {}\n"); err == nil || !strings.Contains(err.Error(), "only tools can be curated") {
		t.Errorf("prompt curation: %v", err)
	}
	// An exact number keeps its digits through the file.
	f, err = parseCap(t, "  - server: s\n    kind: tool\n    name: t\n    curation: {constraints: {a: {allowed: [1e-1, 0.1, 5e-324, 9007199254740991]}}}\n")
	if err != nil {
		t.Fatalf("exact numbers: %v", err)
	}
	var got []string
	for _, v := range (*f.Gateways[0].Capabilities)[0].Curation.Policy.Constraints["a"].Allowed {
		got = append(got, string(v))
	}
	if strings.Join(got, ",") != "1e-1,1e-1,5e-324,9007199254740991" {
		t.Errorf("canonical numbers: %v", got)
	}
}

func TestAbsentNullAndEmptyCurationAreDistinct(t *testing.T) {
	f, err := parseCap(t, "  - {server: s, kind: tool, name: a}\n  - {server: s, kind: tool, name: b, curation: null}\n  - {server: s, kind: tool, name: c, curation: {}}\n")
	if err != nil {
		t.Fatal(err)
	}
	caps := *f.Gateways[0].Capabilities
	if caps[0].Curation != nil {
		t.Error("absent curation must stay absent: it means leave the policy alone")
	}
	if caps[1].Curation == nil || !caps[1].Curation.Clear {
		t.Error("curation: null is a declaration that the tool has none")
	}
	if caps[2].Curation == nil || caps[2].Curation.Clear || caps[2].Curation.Policy == nil {
		t.Error("curation: {} is an empty policy, which is not the same as none")
	}
}

func TestCurationSurvivesYAMLAndJSONRoundTrips(t *testing.T) {
	doc := gwHead + "  - server: s\n    kind: tool\n    name: t\n    curation:\n      nameOverride: renamed\n      constraints:\n        a: {fixed: \"2026-01-02\"}\n        b: {fixed: \"0x10\"}\n        c: {allowed: [1e-1, \"yes\", true, null, {k: [1, 2]}]}\n        d: {fixed: null}\n  - {server: s, kind: tool, name: u, curation: null}\n"
	f, err := ParseFile([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	out, err := f.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	g, err := ParseFile(out)
	if err != nil {
		t.Fatalf("exported YAML does not parse: %v\n%s", err, out)
	}
	a, _ := json.Marshal(f)
	b, _ := json.Marshal(g)
	if string(a) != string(b) {
		t.Errorf("YAML round trip changed the file:\n%s\n%s", a, b)
	}
	// Strings that look like other YAML types stay strings; the explicit null survives.
	for _, want := range []string{`"2026-01-02"`, `"0x10"`, `"yes"`, "curation: null"} {
		if !strings.Contains(string(out), want) {
			t.Errorf("export lacks %s:\n%s", want, out)
		}
	}
	// JSON is YAML: the --json form parses back as the same document.
	if h, err := ParseFile(a); err != nil {
		t.Errorf("JSON form: %v", err)
	} else if c, _ := json.Marshal(h); string(c) != string(a) {
		t.Errorf("JSON round trip changed the file:\n%s\n%s", a, c)
	}
}

func TestGrantDeadlineAndScopeInAFile(t *testing.T) {
	head := "schema: omp/v1\ngateways:\n- slug: g\n  name: G\n  grants:\n"
	ok := map[string]string{
		"deadline":         "  - {team: a, expiresAt: '2026-12-31T00:00:00Z'}\n",
		"unquoted":         "  - {team: a, expiresAt: 2026-12-31T00:00:00Z}\n",
		"fractional":       "  - {team: a, expiresAt: '2026-12-31T00:00:00.123456+02:00'}\n",
		"explicit null":    "  - {team: a, toolScope: null}\n",
		"deny all":         "  - {team: a, toolScope: {}}\n",
		"classes and tool": "  - {team: a, toolScope: {classes: [read, read], tools: [status__check]}}\n",
	}
	for name, grants := range ok {
		if _, err := ParseFile([]byte(head + grants)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	bad := map[string]struct{ grants, contain string }{
		"date only":            {"  - {team: a, expiresAt: 2026-12-31}\n", "RFC 3339"},
		"words":                {"  - {team: a, expiresAt: tomorrow}\n", "RFC 3339"},
		"null deadline":        {"  - {team: a, expiresAt: null}\n", "never makes an expiring grant permanent"},
		"glob tool":            {"  - {team: a, toolScope: {tools: ['status__*']}}\n", "glob"},
		"empty tool":           {"  - {team: a, toolScope: {tools: ['']}}\n", "exact names"},
		"four classes":         {"  - {team: a, toolScope: {classes: [read, read, read, read]}}\n", "more than 3"},
		"padded group":         {"  - {group: ' eng'}\n", "leading or trailing space"},
		"unknown scope field":  {"  - {team: a, toolScope: {all: true}}\n", "all"},
		"deadline is not text": {"  - {team: a, expiresAt: [1]}\n", "cannot unmarshal"},
	}
	for name, c := range bad {
		if _, err := ParseFile([]byte(head + c.grants)); err == nil || !strings.Contains(err.Error(), c.contain) {
			t.Errorf("%s: %v (want %q)", name, err, c.contain)
		}
	}
	// A scope the portal stores sorted and de-duplicated compares equal to one that is not.
	a := &ToolScope{Classes: &[]string{"write", "read", "read"}}
	b := &ToolScope{Classes: &[]string{"read", "write"}, Tools: &[]string{}}
	if scopeKey(a) != scopeKey(b) {
		t.Errorf("%s != %s", scopeKey(a), scopeKey(b))
	}
	if scopeKey(&ToolScope{}) == scopeKey(&ToolScope{Unrestricted: true}) {
		t.Error("an empty scope (no tools) must differ from an unrestricted one")
	}
}
