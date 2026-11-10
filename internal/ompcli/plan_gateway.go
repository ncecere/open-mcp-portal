package ompcli

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/ncecere/open-mcp-portal/pkg/ompclient"
)

// Platform gateways: settings, the capability selection (with curation that
// omp preserves and compares but cannot write), and grants (with deadlines).
//
// Nothing here may lose or widen authority silently. Everything that can be
// refused is refused while planning, before the first write of any step:
// a curation the file declares and omp cannot make true, a grant deadline omp
// cannot keep or would have to extend, an expired grant it would have to
// recreate as permanent. docs/cli.md ("Curation", "Grant expiry") is the
// contract these rules implement.

// refuseErr is a change omp declines to make, because making it would lose or
// widen authority silently. Nothing has been written when it is returned.
func refuseErr(format string, args ...any) *Error {
	return &Error{Exit: ExitUsage, Code: "refused", Message: fmt.Sprintf(format, args...) + " Nothing was changed."}
}

// grantFrom and capFrom convert what the portal returns to the file's form. A
// grant without a ceiling is exported as explicitly unrestricted
// (`toolScope: null`), so the file states what the portal has and a later
// restriction made elsewhere shows as drift.
func grantFrom(g ompclient.GatewayGrant) Grant {
	out := Grant{}
	switch g.SubjectKind {
	case ompclient.GatewayGrantSubjectKindTeam:
		if g.Team != nil {
			out.Team = g.Team.Slug
		}
	case ompclient.GatewayGrantSubjectKindGroup:
		out.Group = deref(g.Group)
	case ompclient.GatewayGrantSubjectKindUser:
		if g.User != nil {
			out.UserEmail = g.User.Email
		}
	}
	out.ToolScope = &ToolScope{Unrestricted: true}
	if g.ToolScope != nil {
		ts := &ToolScope{}
		if g.ToolScope.Classes != nil {
			cl := make([]string, len(*g.ToolScope.Classes))
			for i, c := range *g.ToolScope.Classes {
				cl[i] = string(c)
			}
			ts.Classes = &cl
		}
		if g.ToolScope.Tools != nil {
			t := append([]string(nil), *g.ToolScope.Tools...)
			ts.Tools = &t
		}
		out.ToolScope = ts
	}
	if g.ExpiresAt != nil {
		out.ExpiresAt = g.ExpiresAt.UTC().Format(time.RFC3339Nano)
	}
	return out
}

func capFrom(c ompclient.GatewayCapability) CapabilityRef {
	return CapabilityRef{Server: c.ServerSlug, Kind: string(c.Kind), Name: c.Name}
}

// capExport is capFrom with the selection's curation, for export. A policy the
// read does not carry, or carries in a form this version cannot read, fails the
// export: a file that silently lacked it would widen the gateway when imported.
func capExport(gateway string, c ompclient.GatewayCapability, warnings *[]string) (CapabilityRef, error) {
	ref := capFrom(c)
	pol, err := readCuration(c)
	if err != nil {
		return ref, &Error{Exit: ExitFailure, Code: "curation_unreadable", Message: fmt.Sprintf("gateway %s: %s %s/%s: %v; export refuses to write a file without its policy", gateway, c.Kind, c.ServerSlug, c.Name, err)}
	}
	if pol != nil {
		ref.Curation = &Curation{Policy: pol}
		if curationStale(c) {
			*warnings = append(*warnings, fmt.Sprintf("gateway %s: the curation of tool %s/%s is stale (its definition changed after it was saved): it is exported as stored and the tool is not served until an owner saves it again", gateway, c.ServerSlug, c.Name))
		}
	}
	return ref, nil
}

func isCurated(c ompclient.GatewayCapability) bool {
	raw := strings.TrimSpace(string(c.Curation))
	return c.BaseFingerprint != nil || (raw != "" && raw != "null")
}

// scopeKey is a canonical text for a grant's tool ceiling, for comparing: the
// portal stores a ceiling sorted and without duplicates, and an empty list is
// the same as none.
func scopeKey(ts *ToolScope) string {
	if ts == nil || ts.Unrestricted {
		return "unrestricted"
	}
	list := func(v *[]string, quote bool) string {
		if v == nil || len(*v) == 0 {
			return "-"
		}
		s := append([]string(nil), *v...)
		sort.Strings(s)
		out := s[:0]
		for i, x := range s {
			if i == 0 || x != s[i-1] {
				out = append(out, x)
			}
		}
		if quote {
			// Exact tool names may contain commas. Delimiter joining would
			// confuse one tool named "a,b" with two tools named "a" and "b".
			raw, _ := json.Marshal(out)
			return string(raw)
		}
		return "[" + strings.Join(out, ",") + "]"
	}
	return "classes=" + list(ts.Classes, false) + " tools=" + list(ts.Tools, true)
}

// ---- gateways ----------------------------------------------------------------

// capabilityIDs resolves capability references to the IDs a selection needs,
// from the capabilities that can be selected (approved, listed tools and
// prompts of published, enabled servers).
func capabilityIDs(ctx context.Context, c *api, want map[string]bool) (map[string]uuid.UUID, error) {
	out := map[string]uuid.UUID{}
	var cursor *string
	limit := 500
	for {
		res, err := check(c.AdminListGatewayOptionsWithResponse(ctx, &ompclient.AdminListGatewayOptionsParams{Cursor: cursor, Limit: &limit}))
		if err != nil {
			return nil, err
		}
		if res.JSON200 == nil {
			return nil, badResponse()
		}
		page := res.JSON200.Data
		for _, o := range page.Items {
			k := CapabilityRef{Server: o.ServerSlug, Kind: string(o.Kind), Name: o.Name}.key()
			if want[k] {
				out[k] = o.CapabilityId
			}
		}
		if page.NextCursor == nil || *page.NextCursor == "" {
			return out, nil
		}
		cursor = page.NextCursor
	}
}

// gatewayPlan is one declared gateway compared with the portal: the change the
// plan shows, and everything its step needs to apply it.
type gatewayPlan struct {
	p  *planner
	d  Gateway
	ch Change

	create bool
	id     uuid.UUID
	rev    int64

	patch    ompclient.GatewayUpdate
	hasPatch bool

	capsChanged bool
	wantCaps    map[string]CapabilityRef
	haveCaps    map[string]uuid.UUID // by capability key: the selection, then the additions resolved
	haveItems   map[uuid.UUID]ompclient.GatewayCapability

	grantAdds, grantReplaces []grantWrite
	grantRemoves             []ompclient.GatewayGrant
}

func (g *gatewayPlan) add(field string, from, to any) {
	g.ch.Fields = append(g.ch.Fields, FieldChange{Field: field, From: from, To: to})
}

func (p *planner) planGateways(ctx context.Context, desired []Gateway) error {
	if len(desired) == 0 {
		return nil
	}
	current, err := listPlatformGateways(ctx, p.c)
	if err != nil {
		return err
	}
	by := map[string]ompclient.Gateway{}
	for _, g := range current {
		by[g.Slug] = g
	}
	sorted := append([]Gateway(nil), desired...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Slug < sorted[j].Slug })
	for _, d := range sorted {
		cur, exists := by[d.Slug]
		if err := p.planGateway(ctx, d, cur, exists); err != nil {
			return err
		}
	}
	return nil
}

// planGateway adds the step for one gateway, when anything about it differs.
// cur is the zero value when the gateway does not exist.
func (p *planner) planGateway(ctx context.Context, d Gateway, cur ompclient.Gateway, exists bool) error {
	var ceilingSnapshot *ompclient.Gateway
	if exists {
		ceilingSnapshot = &cur
	}
	if err := checkCeilingDeclaration(d, ceilingSnapshot); err != nil {
		return err
	}
	g := &gatewayPlan{
		p: p, d: d,
		ch:     Change{Kind: "gateway", Key: d.Slug, Action: "update"},
		create: !exists, id: cur.Id, rev: cur.Revision,
	}
	g.planSettings(cur)
	if d.Capabilities != nil {
		if err := g.planCapabilities(ctx, cur); err != nil {
			return err
		}
	}
	if d.Grants != nil {
		if err := g.planGrants(ctx, cur); err != nil {
			return err
		}
	}
	if len(g.ch.Fields) == 0 {
		return nil
	}
	p.steps = append(p.steps, &step{Change: g.ch, run: g.apply})
	return nil
}

// planSettings compares the gateway's own fields: all of them for a new
// gateway, the ones the file declares and the portal has differently otherwise.
func (g *gatewayPlan) planSettings(cur ompclient.Gateway) {
	d := &g.d
	if g.create {
		g.ch.Action = "create"
		g.add("name", nil, d.Name)
		if d.Description != nil {
			g.add("description", nil, *d.Description)
		}
		if d.Enabled != nil {
			g.add("enabled", nil, *d.Enabled)
		}
		return
	}
	if d.Name != cur.Name {
		g.add("name", cur.Name, d.Name)
		g.patch.Name, g.hasPatch = &d.Name, true
	}
	if d.Description != nil && *d.Description != cur.Description {
		g.add("description", cur.Description, *d.Description)
		g.patch.Description, g.hasPatch = d.Description, true
	}
	if d.Enabled != nil && *d.Enabled != cur.Enabled {
		g.add("enabled", cur.Enabled, *d.Enabled)
		g.patch.Enabled, g.hasPatch = d.Enabled, true
	}
}
