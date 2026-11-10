package gateways

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/ncecere/open-mcp-portal/internal/gateways/curation"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

func policyOf(t *testing.T, row dbgen.GatewayCapability) *curation.Policy {
	t.Helper()
	p := &curation.Policy{NameOverride: row.NameOverride, DescriptionOverride: row.DescriptionOverride}
	_ = json.Unmarshal(row.Constraints, &p.Constraints)
	return p
}

// The memoised projection is curation.Project's result for every input,
// errors included, and a caller can't reach the cached copy through what it
// gets back.
func TestProjectMatchesCurationProject(t *testing.T) {
	def := benchDefinition("lookup")
	name, other := "renamed", "renamed"
	rows := map[string]dbgen.GatewayCapability{
		"constraints":      {NameOverride: &name, Constraints: []byte(`{"field_00":{"fixed":"alpha"},"field_01":{"allowed":["beta","nope","alpha"]}}`)},
		"rename only":      {NameOverride: &other},
		"description only": {DescriptionOverride: &name},
		"unknown argument": {Constraints: []byte(`{"missing":{"fixed":"alpha"}}`)},
		"invalid fixed":    {Constraints: []byte(`{"field_00":{"fixed":"not-in-enum"}}`)},
	}
	for label, row := range rows {
		t.Run(label, func(t *testing.T) {
			wantDef, wantPolicy, wantErr := curation.Project(def, policyOf(t, row))
			for pass := range 2 { // a miss, then a hit
				gotDef, gotPolicy, gotErr := project(def, row, policyOf(t, row))
				if !bytes.Equal(gotDef, wantDef) || !reflect.DeepEqual(gotPolicy, wantPolicy) || (gotErr == nil) != (wantErr == nil) ||
					(gotErr != nil && gotErr.Error() != wantErr.Error()) {
					t.Fatalf("pass %d: project = %s %+v %v, want %s %+v %v", pass, gotDef, gotPolicy, gotErr, wantDef, wantPolicy, wantErr)
				}
				// Scribble on what was returned: the next read must not see it.
				for i := range gotDef {
					gotDef[i] = 'x'
				}
				if gotPolicy != nil {
					for arg, c := range gotPolicy.Constraints {
						for i := range c.Fixed {
							c.Fixed[i] = 'x'
						}
						c.Allowed = append(c.Allowed, json.RawMessage(`"injected"`))
						gotPolicy.Constraints[arg] = c
					}
					if gotPolicy.Constraints != nil {
						gotPolicy.Constraints["added"] = curation.Constraint{}
					}
				}
			}
		})
	}

	// The key covers every input: a different definition or policy column
	// is a different projection, and an absent override is not an empty one.
	empty := ""
	a, _, _ := project(def, dbgen.GatewayCapability{NameOverride: &name}, &curation.Policy{NameOverride: &name})
	changed := bytes.Replace(def, []byte("Looks something up"), []byte("Finds something"), 1)
	b, _, _ := project(changed, dbgen.GatewayCapability{NameOverride: &name}, &curation.Policy{NameOverride: &name})
	if bytes.Equal(a, b) {
		t.Fatal("two definitions shared a projection")
	}
	if projectionKey(def, dbgen.GatewayCapability{}) == projectionKey(def, dbgen.GatewayCapability{NameOverride: &empty}) ||
		projectionKey(def, dbgen.GatewayCapability{NameOverride: &name}) == projectionKey(def, dbgen.GatewayCapability{DescriptionOverride: &name}) ||
		projectionKey([]byte("ab"), dbgen.GatewayCapability{Constraints: []byte("c")}) == projectionKey([]byte("a"), dbgen.GatewayCapability{Constraints: []byte("bc")}) {
		t.Fatal("distinct inputs share a cache key")
	}
}
