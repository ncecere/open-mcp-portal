package gateways

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

// The two reasons of decision 88: a server above a gateway's ceiling
// (sensitivity_exceeds_gateway) and a retired server (sunset). The SQL mirrors
// (GatewayStats, ApprovalRequesterLive) are checked against this table by
// TestGatewayStatsMirrorsAvailability.
func TestAvailabilityGovernanceReasons(t *testing.T) {
	team, other := uuid.New(), uuid.New()
	now := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	before, after := now.Add(-time.Nanosecond), now.Add(time.Nanosecond)
	fp := "a"
	tool := dbgen.McpCapability{Kind: "tool", Fingerprint: fp, ApprovedFingerprint: &fp}
	gw := func(owner string, ceiling string) dbgen.Gateway {
		g := dbgen.Gateway{OwnerKind: owner, MaxSensitivity: ceiling}
		if owner == OwnerTeam {
			g.TeamID = uuid.NullUUID{UUID: team, Valid: true}
		}
		return g
	}
	srv := func(teamID uuid.UUID, sensitivity, lifecycle string, sunset *time.Time) dbgen.McpServer {
		return dbgen.McpServer{TeamID: teamID, Enabled: true, PublishState: "published", Sensitivity: sensitivity, Lifecycle: lifecycle, SunsetAt: sunset}
	}
	cases := []struct {
		name    string
		gw      dbgen.Gateway
		server  dbgen.McpServer
		ok      bool
		because string
	}{
		{"label at the ceiling is served", gw(OwnerPlatform, "internal"), srv(other, "internal", "active", nil), true, ""},
		{"label below the ceiling is served", gw(OwnerPlatform, "confidential"), srv(other, "public", "active", nil), true, ""},
		{"one above the ceiling", gw(OwnerPlatform, "internal"), srv(other, "confidential", "active", nil), false, ReasonSensitivityExceedsGateway},
		{"restricted above public", gw(OwnerPlatform, "public"), srv(other, "restricted", "active", nil), false, ReasonSensitivityExceedsGateway},
		{"restricted ceiling serves restricted", gw(OwnerPlatform, "restricted"), srv(other, "restricted", "active", nil), true, ""},
		{"a team gateway's own server is held to the ceiling too", gw(OwnerTeam, "public"), srv(team, "internal", "active", nil), false, ReasonSensitivityExceedsGateway},
		{"a team gateway's own private server under its ceiling", gw(OwnerTeam, "internal"),
			dbgen.McpServer{TeamID: team, Enabled: true, PublishState: "private", Sensitivity: "internal", Lifecycle: "active"}, true, ""},
		{"an empty label is the column default on both sides", gw(OwnerPlatform, ""), srv(other, "", "", nil), true, ""},
		{"an empty ceiling does not hide a restricted server", gw(OwnerPlatform, ""), srv(other, "restricted", "active", nil), true, ""},
		{"an unknown server label fails closed", gw(OwnerPlatform, "restricted"), srv(other, "secret", "active", nil), false, ReasonSensitivityExceedsGateway},
		{"an unknown ceiling fails closed", gw(OwnerPlatform, "none"), srv(other, "public", "active", nil), false, ReasonSensitivityExceedsGateway},

		{"deprecated is still served", gw(OwnerPlatform, "restricted"), srv(other, "internal", "deprecated", &after), true, ""},
		{"deprecated without a date is still served", gw(OwnerPlatform, "restricted"), srv(other, "internal", "deprecated", nil), true, ""},
		{"the sunset moment stops serving", gw(OwnerPlatform, "restricted"), srv(other, "internal", "deprecated", &now), false, ReasonSunset},
		{"a sunset date in the past stops serving", gw(OwnerPlatform, "restricted"), srv(other, "internal", "deprecated", &before), false, ReasonSunset},
		{"a sunset lifecycle stops serving", gw(OwnerPlatform, "restricted"), srv(other, "internal", "sunset", &before), false, ReasonSunset},
		{"a sunset lifecycle without a date stops serving", gw(OwnerPlatform, "restricted"), srv(other, "internal", "sunset", nil), false, ReasonSunset},
		{"a team's own private server is retired too", gw(OwnerTeam, "restricted"),
			dbgen.McpServer{TeamID: team, Enabled: true, PublishState: "private", Sensitivity: "internal", Lifecycle: "sunset", SunsetAt: &before}, false, ReasonSunset},

		{"sunset is reported before the ceiling", gw(OwnerPlatform, "public"), srv(other, "restricted", "sunset", &before), false, ReasonSunset},
		{"a disabled server is reported as disabled", gw(OwnerPlatform, "public"),
			dbgen.McpServer{TeamID: other, PublishState: "published", Sensitivity: "restricted", Lifecycle: "sunset", SunsetAt: &before}, false, ReasonServerDisabled},
		{"the ceiling is reported before publication", gw(OwnerPlatform, "public"),
			dbgen.McpServer{TeamID: other, Enabled: true, PublishState: "private", Sensitivity: "internal", Lifecycle: "active"}, false, ReasonSensitivityExceedsGateway},
	}
	for _, c := range cases {
		ok, why := AvailabilityAt(c.gw, tool, c.server, Archived{}, now)
		if ok != c.ok || why != c.because {
			t.Errorf("%s: %v %q, want %v %q", c.name, ok, why, c.ok, c.because)
		}
	}
	// Availability reads the clock itself: a date far in the past or future.
	past, future := time.Now().Add(-time.Hour), time.Now().Add(time.Hour)
	if ok, why := Availability(gw(OwnerPlatform, "restricted"), tool, srv(other, "internal", "deprecated", &past), Archived{}); ok || why != ReasonSunset {
		t.Errorf("Availability with a passed sunset: %v %q", ok, why)
	}
	if ok, why := Availability(gw(OwnerPlatform, "restricted"), tool, srv(other, "internal", "deprecated", &future), Archived{}); !ok || why != "" {
		t.Errorf("Availability before a sunset: %v %q", ok, why)
	}
}

// A retired server or one above the ceiling keeps its reason when its curation
// is also stale: nothing the owner does to the policy serves it.
func TestGovernanceReasonsOutrankStaleCuration(t *testing.T) {
	for _, reason := range []string{ReasonSunset, ReasonSensitivityExceedsGateway, ReasonServerDisabled} {
		fp, old := "new", "old"
		it := Selected{Capability: dbgen.McpCapability{Kind: "tool", Fingerprint: fp}, Available: false, Reason: reason}
		applyCuration(&it, dbgen.GatewayCapability{BaseFingerprint: &old, Constraints: []byte(`{}`)})
		if it.Reason != reason || it.Available {
			t.Errorf("%s was replaced by %q", reason, it.Reason)
		}
	}
	fp, old := "new", "old"
	it := Selected{Capability: dbgen.McpCapability{Kind: "tool", Fingerprint: fp}, Available: true}
	applyCuration(&it, dbgen.GatewayCapability{BaseFingerprint: &old, Constraints: []byte(`{}`)})
	if it.Reason != ReasonCurationStale || it.Available {
		t.Errorf("a served stale policy: %+v", it)
	}
}
