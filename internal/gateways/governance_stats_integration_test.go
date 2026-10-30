package gateways

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

// GatewayStats (SQL) and ApprovalRequesterLive (SQL, the final check of a
// spent approval) mirror Availability. Every combination of a server's
// sensitivity and lifecycle and a gateway's ceiling, on platform and team
// gateways, must count and decide the same in all three.
func TestGatewayStatsMirrorsAvailability(t *testing.T) {
	ctx := context.Background()
	pool, _ := testutil.NewDB(t)
	q := dbgen.New(pool)
	run := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	id := func(sql string, args ...any) uuid.UUID {
		t.Helper()
		var out uuid.UUID
		if err := pool.QueryRow(ctx, sql, args...).Scan(&out); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
		return out
	}
	owner := id(`INSERT INTO teams(slug,name) VALUES('owner','Owner') RETURNING id`)
	other := id(`INSERT INTO teams(slug,name) VALUES('other','Other') RETURNING id`)
	user := id(`INSERT INTO users(oidc_issuer,oidc_subject,email) VALUES('t','u','u@example.invalid') RETURNING id`)
	fp := fmt.Sprintf("%064d", 1)

	labels := []string{"public", "internal", "confidential", "restricted"}
	type variant struct{ name, lifecycle, sunset string }
	variants := []variant{
		{"active", "active", ""},
		{"deprecated-ahead", "deprecated", "now() + interval '1 hour'"},
		{"deprecated-past", "deprecated", "now() - interval '1 hour'"},
		{"sunset", "sunset", "now() - interval '1 hour'"},
	}
	var catalog, own []uuid.UUID // capability IDs
	for _, l := range labels {
		for _, v := range variants {
			dep, sun := "NULL", "NULL"
			if v.lifecycle != "active" {
				dep = "now() - interval '2 hours'"
			}
			if v.sunset != "" {
				sun = v.sunset
			}
			for _, side := range []struct {
				team  uuid.UUID
				state string
				list  *[]uuid.UUID
			}{{other, "published", &catalog}, {owner, "private", &own}} {
				slug := fmt.Sprintf("%s-%s-%s-%s", side.state, l, v.name, side.team.String()[:4])
				srv := id(fmt.Sprintf(`INSERT INTO mcp_servers(team_id,slug,name,url,publish_state,published_at,sensitivity,lifecycle,deprecated_at,sunset_at)
					VALUES($1,$2,$2,'https://x.example.com/mcp',$3,CASE WHEN $3::text = 'published' THEN now() END,$4,$5,%s,%s) RETURNING id`, dep, sun), side.team, slug, side.state, l, v.lifecycle)
				cap := id(`INSERT INTO mcp_capabilities(server_id,kind,name,definition,fingerprint,approved_fingerprint) VALUES($1,'tool','t','{}',$2,$2) RETURNING id`, srv, fp)
				*side.list = append(*side.list, cap)
			}
		}
	}
	type gw struct {
		id      uuid.UUID
		kind    string
		ceiling string
		caps    []uuid.UUID
	}
	var gws []gw
	for _, c := range labels {
		p := id(`INSERT INTO gateways(slug,name,owner_kind,max_sensitivity) VALUES($1,$1,'platform',$2) RETURNING id`, "platform-"+c, c)
		gws = append(gws, gw{p, OwnerPlatform, c, catalog})
		tm := id(`INSERT INTO gateways(slug,name,owner_kind,team_id,max_sensitivity) VALUES($1,$1,'team',$2,$3) RETURNING id`, "team-"+c, owner, c)
		gws = append(gws, gw{tm, OwnerTeam, c, append(append([]uuid.UUID{}, catalog...), own...)})
	}
	for _, g := range gws {
		for _, c := range g.caps {
			run(`INSERT INTO gateway_capabilities(gateway_id,capability_id) VALUES($1,$2)`, g.id, c)
		}
	}
	stats := map[uuid.UUID]dbgen.GatewayStatsRow{}
	ids := make([]uuid.UUID, len(gws))
	for i, g := range gws {
		ids[i] = g.id
	}
	rows, err := q.GatewayStats(ctx, ids)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		stats[r.GatewayID] = r
	}
	reasons := map[string]int{}
	for _, g := range gws {
		row, err := q.GetGateway(ctx, g.id)
		if err != nil {
			t.Fatal(err)
		}
		items, err := selection(ctx, q, row)
		if err != nil {
			t.Fatal(err)
		}
		unavailable := int64(0)
		for _, it := range items {
			ok, why := it.Available, it.Reason
			if !ok {
				unavailable++
				reasons[why]++
			}
			// The independent oracle: the rule written out again.
			rank := map[string]int{"public": 0, "internal": 1, "confidential": 2, "restricted": 3}
			retired := it.Server.Lifecycle == "sunset" || (it.Server.SunsetAt != nil && it.Server.SunsetAt.Before(time.Now()))
			want := !retired && rank[it.Server.Sensitivity] <= rank[row.MaxSensitivity] &&
				(it.Server.PublishState == "published" || (g.kind == OwnerTeam && it.Server.TeamID == owner))
			if ok != want {
				t.Errorf("%s: %s is available=%v (%q), the rule says %v", g.kind+"/"+g.ceiling, it.Server.Slug, ok, why, want)
			}
			live, err := q.ApprovalRequesterLive(ctx, dbgen.ApprovalRequesterLiveParams{GatewayID: g.id, CapabilityID: it.Capability.ID, ServerID: it.Server.ID,
				Fingerprint: it.Capability.Fingerprint, RequesterKind: "user", RequesterID: user})
			if err != nil {
				t.Fatal(err)
			}
			if live != ok {
				t.Errorf("%s/%s: ApprovalRequesterLive=%v but Availability=%v (%q) for %s", g.kind, g.ceiling, live, ok, why, it.Server.Slug)
			}
		}
		st := stats[g.id]
		if st.CapabilityCount != int64(len(g.caps)) || st.UnavailableCount != unavailable {
			t.Errorf("%s/%s: GatewayStats %d/%d, Availability %d/%d", g.kind, g.ceiling, st.UnavailableCount, st.CapabilityCount, unavailable, len(g.caps))
		}
	}
	// Both new reasons occurred, so the comparison above was not vacuous.
	if reasons[ReasonSunset] == 0 || reasons[ReasonSensitivityExceedsGateway] == 0 {
		t.Errorf("reasons seen: %v", reasons)
	}
}
