package httpapi_test

import (
	"testing"
)

func TestCurationPlatformAndMinimumRoles(t *testing.T) {
	e := newRuntimeEnv(t)
	setCuration(t, e.gwEnv, e.admin, e.shared, "whoami", map[string]any{"nameOverride": "shared_identity", "descriptionOverride": "Identity for shared callers"})
	for _, modern := range []bool{false, true} {
		p := map[string]any{"name": "shared_identity"}
		var out map[string]any
		if modern {
			_, _, out = rawModern(t, e.app, "shared", e.key.Secret, "tools/call", p, nil, nil)
		} else {
			_, _, out = rawMCP(t, e.app, "POST", "shared", e.key.Secret, rpc(1, "tools/call", p), nil)
		}
		if out["error"] != nil {
			t.Fatalf("platform curated call modern=%v: %v", modern, out)
		}
	}
	setCuration(t, e.gwEnv, e.owner, e.supportTeamPath, "whoami", map[string]any{"nameOverride": "team_identity"})
	c := selectedTool(t, e.owner, e.supportTeamPath, "whoami")
	e.mustSetCaps(e.owner, e.supportTeamPath, sel(c.CapabilityId.String()+":owner"))
	ownerKey := newKey(t, e.owner, "owner-curation").Secret
	sa := createSA(t, e.owner, map[string]any{"name": "curated-caller", "role": "editor"})
	sak := createSAKey(t, e.owner, sa.Id.String(), map[string]any{"name": "curated-service"})
	for _, tc := range []struct {
		secret  string
		allowed bool
	}{{e.key.Secret, false}, {ownerKey, true}, {sak.Secret, false}} {
		before := len(e.fake.ToolCalls())
		_, _, out := rawModern(t, e.app, "support", tc.secret, "tools/call", map[string]any{"name": "team_identity"}, nil, nil)
		if (out["error"] == nil) != tc.allowed {
			t.Fatalf("minimum role allowed=%v: %v", tc.allowed, out)
		}
		if !tc.allowed && len(e.fake.ToolCalls()) != before {
			t.Fatal("minimum-role refusal reached upstream")
		}
	}
}
