package gateways

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/uuid"

	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

// Whether a team confirmed a server's sensitivity label is bookkeeping: no
// gateway, ceiling or spent approval reads it. Servers that differ only in the
// marker are served, listed unavailable and counted identically in all three
// mirrors (Availability, GatewayStats, ApprovalRequesterLive), against every
// ceiling: a restricted server nobody confirmed is still above a lower ceiling,
// and a default-labelled one nobody confirmed is still below it.
func TestSensitivityConfirmationIsNotAuthorization(t *testing.T) {
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
	team := id(`INSERT INTO teams(slug,name) VALUES('c','C') RETURNING id`)
	user := id(`INSERT INTO users(oidc_issuer,oidc_subject,email) VALUES('t','c','c@example.invalid') RETURNING id`)
	fp := fmt.Sprintf("%064d", 2)
	labels := []string{"public", "internal", "confidential", "restricted"}
	rank := map[string]int{"public": 0, "internal": 1, "confidential": 2, "restricted": 3}

	type srvCap struct {
		capID     uuid.UUID
		label     string
		confirmed bool
	}
	var caps []srvCap
	var capIDs []uuid.UUID
	for _, l := range labels {
		for _, confirmed := range []bool{false, true} {
			srv := id(`INSERT INTO mcp_servers(team_id,slug,name,url,publish_state,published_at,sensitivity,sensitivity_confirmed_at)
				VALUES($1,$2,$2,'https://x.example.com/mcp','published',now(),$3,CASE WHEN $4::bool THEN now() END) RETURNING id`,
				team, fmt.Sprintf("%s-%v", l, confirmed), l, confirmed)
			c := id(`INSERT INTO mcp_capabilities(server_id,kind,name,definition,fingerprint,approved_fingerprint) VALUES($1,'tool','t','{}',$2,$2) RETURNING id`, srv, fp)
			caps = append(caps, srvCap{c, l, confirmed})
			capIDs = append(capIDs, c)
		}
	}
	for _, ceiling := range labels {
		gw := id(`INSERT INTO gateways(slug,name,owner_kind,max_sensitivity) VALUES($1,$1,'platform',$2) RETURNING id`, "ceiling-"+ceiling, ceiling)
		for _, c := range capIDs {
			run(`INSERT INTO gateway_capabilities(gateway_id,capability_id) VALUES($1,$2)`, gw, c)
		}
		row, err := q.GetGateway(ctx, gw)
		if err != nil {
			t.Fatal(err)
		}
		items, err := selection(ctx, q, row)
		if err != nil {
			t.Fatal(err)
		}
		byCap := map[uuid.UUID]srvCap{}
		for _, c := range caps {
			byCap[c.capID] = c
		}
		unavailable := int64(0)
		for _, it := range items {
			c := byCap[it.Capability.ID]
			want := rank[c.label] <= rank[ceiling] // only the label decides
			if it.Available != want {
				t.Errorf("ceiling %s, %s (confirmed %v): available=%v (%q), want %v", ceiling, c.label, c.confirmed, it.Available, it.Reason, want)
			}
			if !want {
				unavailable++
				if it.Reason != ReasonSensitivityExceedsGateway {
					t.Errorf("ceiling %s, %s (confirmed %v): reason %q", ceiling, c.label, c.confirmed, it.Reason)
				}
			}
			live, err := q.ApprovalRequesterLive(ctx, dbgen.ApprovalRequesterLiveParams{GatewayID: gw, CapabilityID: it.Capability.ID, ServerID: it.Server.ID,
				Fingerprint: it.Capability.Fingerprint, RequesterKind: "user", RequesterID: user})
			if err != nil {
				t.Fatal(err)
			}
			if live != want {
				t.Errorf("ceiling %s, %s (confirmed %v): ApprovalRequesterLive=%v, want %v", ceiling, c.label, c.confirmed, live, want)
			}
		}
		rows, err := q.GatewayStats(ctx, []uuid.UUID{gw})
		if err != nil || len(rows) != 1 || rows[0].CapabilityCount != int64(len(capIDs)) || rows[0].UnavailableCount != unavailable {
			t.Errorf("ceiling %s: stats %+v (%v), want %d unavailable of %d", ceiling, rows, err, unavailable, len(capIDs))
		}
	}
}
