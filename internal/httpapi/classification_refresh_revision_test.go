package httpapi_test

import (
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// If-Match must bind a NEW classification to the definition the owner saw,
// not just the suggestion. Returning tools also need a fresh owner decision.
func TestToolClassificationRefreshInvalidatesStaleRevision(t *testing.T) {
	for _, bulk := range []bool{false, true} {
		name := "single"
		if bulk {
			name = "bulk"
		}
		t.Run(name, func(t *testing.T) {
			e := newRegistryEnv(t)
			e.fake.SetAnnotations("check_outage", &mcp.ToolAnnotations{ReadOnlyHint: true})
			sv := e.create(map[string]any{"slug": "status", "name": "Status", "url": e.fake.URL()}).Server
			id := sv.Id.String()
			tool := e.capabilities(e.owner, id)["check_outage"]
			path := toolsTeam + "/mcp-servers/" + id + "/capabilities/" + tool.Id.String() + "/class"
			body := func(class any, via bool) map[string]any {
				if bulk {
					return map[string]any{"items": []any{map[string]any{"capabilityId": tool.Id, "toolClass": class, "viaSuggestion": via}}}
				}
				return map[string]any{"toolClass": class, "viaSuggestion": via}
			}
			if bulk {
				path = toolsTeam + "/mcp-servers/" + id + "/capabilities/classes"
			}
			set := func(revision int64, class any, via bool, status int, errCode string) {
				t.Helper()
				code, ec := e.owner.call("PUT", path, body(class, via), nil, ifMatch(revision))
				mustCode(t, "classify", code, ec, status, errCode)
			}
			assertUnclassified := func() {
				t.Helper()
				c := e.capabilities(e.owner, id)["check_outage"]
				if c.ToolClass != nil || c.ClassDrift || c.Id != tool.Id {
					t.Fatalf("class changed or capability replaced: %+v", c)
				}
			}
			// Health-only refreshes do not invalidate an edit.
			unchanged := e.refresh(id)
			if unchanged.Added+unchanged.Changed+unchanged.Gone != 0 || e.server(e.owner, id).Revision != sv.Revision {
				t.Fatal("unchanged refresh bumped revision")
			}
			set(sv.Revision, nil, false, 200, "")
			before := e.server(e.owner, id).Revision
			audits := e.scalar(`SELECT count(*)::text FROM audit_log WHERE action='mcp_capability.class_set'`)
			// Description changes are security-significant even when the new hint
			// still suggests read, and viaSuggestion would match that suggestion.
			e.fake.SetDescription("check_outage", "Reads a different service.")
			refreshed := e.refresh(id)
			current := e.capabilities(e.owner, id)["check_outage"]
			if refreshed.Changed != 1 || current.Fingerprint == tool.Fingerprint || *current.SuggestedClass != *tool.SuggestedClass || e.server(e.owner, id).Revision != before+1 {
				t.Fatalf("changed refresh: %+v, capability %+v", refreshed, current)
			}
			set(before, "read", true, 412, "revision_conflict")
			assertUnclassified()
			if e.scalar(`SELECT count(*)::text FROM audit_log WHERE action='mcp_capability.class_set'`) != audits {
				t.Fatal("stale edit was audited")
			}
			set(e.server(e.owner, id).Revision, "read", true, 200, "")
			// Going gone withdraws the class; returning the same ID must not let
			// either the pre-disappearance or gone revision classify it again.
			beforeGone := e.server(e.owner, id).Revision
			e.fake.Hide("check_outage")
			gone := e.refresh(id)
			goneRevision := e.server(e.owner, id).Revision
			if gone.Gone != 1 || goneRevision != beforeGone+1 {
				t.Fatalf("gone revision %d -> %d", beforeGone, goneRevision)
			}
			assertUnclassified()
			e.fake.Show("check_outage")
			returned := e.refresh(id)
			if returned.Added != 1 || e.server(e.owner, id).Revision != goneRevision+1 {
				t.Fatalf("return revision: %+v", returned)
			}
			assertUnclassified()
			set(beforeGone, "read", true, 412, "revision_conflict")
			set(goneRevision, "read", true, 412, "revision_conflict")
			assertUnclassified()
			set(e.server(e.owner, id).Revision, "read", true, 200, "")
		})
	}
}
