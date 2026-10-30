package ompcli

import (
	"strings"
	"testing"
	"time"

	"github.com/ncecere/open-mcp-portal/pkg/ompclient"
)

func TestGovernanceFileSchemaAndParserAgree(t *testing.T) {
	schema := compileSchema(t)
	head := "schema: omp/v1\nservers:\n- team: team\n  slug: jobs\n  name: Jobs\n  url: https://example.invalid/mcp\n"
	for _, tc := range []struct {
		name, suffix string
		ok           bool
	}{
		{"omitted", "", true},
		{"valid", "  governance: {sensitivity: confidential, lifecycle: active, sunsetAt: ''}\n", true},
		{"empty", "  governance: {}\n", false},
		{"null", "  governance: null\n", false},
		{"merged null", "  <<: {governance: null}\n", false},
		{"null deadline", "  governance: {sensitivity: internal, lifecycle: active, sunsetAt: null}\n", false},
		{"merged null owner", "  governance: {sensitivity: internal, lifecycle: active, sunsetAt: '', <<: {ownerUserId: null}}\n", false},
		{"bad label", "  governance: {sensitivity: secret, lifecycle: active, sunsetAt: ''}\n", false},
		{"bad lifecycle", "  governance: {sensitivity: internal, lifecycle: paused, sunsetAt: ''}\n", false},
		{"bad deadline", "  governance: {sensitivity: internal, lifecycle: sunset, sunsetAt: tomorrow}\n", false},
		{"missing deadline", "  governance: {sensitivity: internal, lifecycle: active}\n", false},
		{"unknown", "  governance: {sensitivity: internal, lifecycle: active, sunsetAt: '', confirmed: true}\n", false},
		{"null contact", "  governance: {sensitivity: internal, lifecycle: active, sunsetAt: '', oncallContact: null}\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseFile([]byte(head + tc.suffix))
			if (err == nil) != tc.ok {
				t.Fatalf("parser: %v", err)
			}
			if got := schemaAccepts(t, schema, head+tc.suffix); got != tc.ok {
				t.Fatalf("schema accepted=%v", got)
			}
		})
	}
	for _, value := range []string{"public", "internal", "confidential", "restricted", "null", "secret"} {
		doc := "schema: omp/v1\ngateways:\n- slug: g\n  name: G\n  maxSensitivity: " + value + "\n"
		_, err := ParseFile([]byte(doc))
		want := validSensitivity(value)
		if (err == nil) != want || schemaAccepts(t, schema, doc) != want {
			t.Errorf("ceiling %s: %v", value, err)
		}
	}
}

func TestGovernanceDeclarationExactReadOnlyComparison(t *testing.T) {
	deadline := time.Date(2027, 1, 2, 3, 4, 5, 123456000, time.UTC)
	g := &ompclient.McpServerGovernance{Sensitivity: "confidential", Lifecycle: "deprecated", SunsetAt: &deadline}
	policy, err := governanceFrom(g)
	if err != nil {
		t.Fatal(err)
	}
	d := Server{Slug: "jobs", Governance: policy}
	cur := &ompclient.McpServer{Governance: g}
	if err := checkGovernanceDeclaration(d, cur); err != nil {
		t.Fatal(err)
	}
	if err := checkGovernanceDeclaration(d, nil); err == nil || !strings.Contains(err.Error(), "comparison-only") {
		t.Fatalf("new-object policy was not refused: %v", err)
	}
	if err := checkGovernanceDeclaration(d, &ompclient.McpServer{}); err == nil {
		t.Fatal("unreadable governance accepted")
	}
	changed := deadline.Add(time.Nanosecond).Format(time.RFC3339Nano)
	d.Governance.SunsetAt = &changed
	if err := checkGovernanceDeclaration(d, cur); err == nil {
		t.Fatal("deadline rounded or widened")
	}
	d.Governance = nil
	if err := checkGovernanceDeclaration(d, cur); err != nil {
		t.Fatal("omission must preserve existing policy")
	}
	if _, err := governanceFrom(&ompclient.McpServerGovernance{Sensitivity: "unknown", Lifecycle: "active"}); err == nil {
		t.Fatal("unreadable policy exported")
	}
}

func TestCeilingDeclarationOnlyComparesAndNeverInfersUnreadable(t *testing.T) {
	for _, value := range []string{"public", "internal", "confidential", "restricted"} {
		d := Gateway{Slug: "g", MaxSensitivity: &value}
		actual := ompclient.Sensitivity(value)
		if err := checkCeilingDeclaration(d, &ompclient.Gateway{MaxSensitivity: &actual}); err != nil {
			t.Fatal(err)
		}
		if err := checkCeilingDeclaration(d, &ompclient.Gateway{}); err == nil {
			t.Fatal("missing ceiling treated as a default")
		}
		if err := checkCeilingDeclaration(d, nil); (err == nil) != (value == "restricted") {
			t.Fatalf("new ceiling %s: %v", value, err)
		}
	}
}
