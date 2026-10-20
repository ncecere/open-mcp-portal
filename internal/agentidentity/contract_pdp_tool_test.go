package agentidentity

// M-1 against PDP's real tokens: the tool claim is what the gateway binds a
// token to (internal/mcpgw toolBound). Every recorded token that PDP made
// for a tool call carries `tool`, exactly as PDP wrote it; the one it made
// with no tool (a personal workspace's handshake) has none. A token fits a
// tools/call for its own tool and nothing else, and fits a request of any
// other method only when it has no tool.
//
// What this does NOT show is which name PDP's gateway puts in `tool` for a
// real client call (the recorded tokens come from PDP's token function, not
// from its gateway end to end): docs/agent-platforms.md lists it as not
// checked.

import (
	"context"
	"encoding/json"
	"path"
	"strings"
	"testing"
	"time"
)

func TestPDPContractToolClaimBinding(t *testing.T) {
	e := newPDPEnv(t)
	entries, err := pdpFixtures.ReadDir("testdata/pdp/tokens")
	if err != nil {
		t.Fatal(err)
	}
	withTool, withoutTool := 0, 0
	for _, ent := range entries {
		if !strings.HasSuffix(ent.Name(), ".expected.json") {
			continue
		}
		name := strings.TrimSuffix(ent.Name(), ".expected.json")
		rawExp, _ := pdpFixtures.ReadFile(path.Join("testdata/pdp/tokens", ent.Name()))
		var exp pdpExpected
		if err := json.Unmarshal(rawExp, &exp); err != nil {
			t.Fatal(err)
		}
		rawTok, err := pdpFixtures.ReadFile("testdata/pdp/tokens/" + name + ".jwt")
		if err != nil {
			t.Fatal(err)
		}
		tok := strings.TrimSpace(string(rawTok))
		var accepting *pdpCheck
		for i := range exp.Checks {
			if exp.Checks[i].Accept {
				accepting = &exp.Checks[i]
				break
			}
		}
		if accepting == nil {
			t.Fatalf("%s: no accepted check", name)
		}
		t.Run(name, func(t *testing.T) {
			at, err := time.Parse(time.RFC3339, accepting.At)
			if err != nil {
				t.Fatal(err)
			}
			audience := pdpPortalAud
			if accepting.PlatformAudience != "" {
				audience = accepting.PlatformAudience
			}
			personIssuer := pdpPersonIssuer
			if accepting.PersonIssuer != "" {
				personIssuer = accepting.PersonIssuer
			}
			e.srv.load(t, accepting.JWKS)
			svc := e.mk(personIssuer, at)
			v, err := svc.Create(context.Background(), e.admin, Input{Name: pdpPtr("Pi Durable Platform"), Issuer: pdpPtr(pdpIssuer), Audience: pdpPtr(audience)})
			if err != nil {
				t.Fatal(err)
			}
			defer svc.Delete(context.Background(), e.admin, v.Platform.ID) //nolint:errcheck
			id, err := svc.Verify(context.Background(), tok)
			if err != nil {
				t.Fatal(err)
			}
			var claims struct {
				Tool *string `json:"tool"`
			}
			pdpSegment(t, tok, 1, &claims)
			if claims.Tool == nil {
				withoutTool++
				if id.ToolClaim != "" || !id.ToolMatches(false, "") || id.ToolMatches(true, "search_mail") || id.ToolMatches(true, "") {
					t.Fatalf("a token with no tool: claim %q, matches a non-call %v", id.ToolClaim, id.ToolMatches(false, ""))
				}
				return
			}
			withTool++
			if *claims.Tool == "" || id.ToolClaim != *claims.Tool {
				t.Fatalf("PDP's tool claim %q, the verifier's %q", *claims.Tool, id.ToolClaim)
			}
			if !id.ToolMatches(true, *claims.Tool) {
				t.Errorf("the token doesn't fit a tools/call of its own tool %q", *claims.Tool)
			}
			for _, other := range []string{"", *claims.Tool + "2", strings.ToUpper(*claims.Tool), "other_tool"} {
				if id.ToolMatches(true, other) {
					t.Errorf("the token for %q fits a tools/call of %q", *claims.Tool, other)
				}
			}
			if id.ToolMatches(false, "") || id.ToolMatches(false, *claims.Tool) {
				t.Errorf("the token for %q fits a request that is not a tool call", *claims.Tool)
			}
		})
	}
	// The recorded set has both kinds, or this proves nothing.
	if withTool < 5 || withoutTool < 1 {
		t.Fatalf("tokens with a tool %d, without %d", withTool, withoutTool)
	}
}
