package ompcli

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/google/uuid"
	openapi_types "github.com/oapi-codegen/runtime/types"

	"github.com/ncecere/open-mcp-portal/pkg/ompclient"
)

func ifMatch(rev int64) string { return fmt.Sprintf(`"%d"`, rev) }

func badResponse() error {
	return &Error{Exit: ExitFailure, Code: "bad_response", Message: "the portal's reply was not the expected JSON"}
}

// ---- readers (shared with export) --------------------------------------------

func listTeams(ctx context.Context, c *api) ([]ompclient.Team, error) {
	var all []ompclient.Team
	for _, status := range []ompclient.TeamStatus{ompclient.TeamStatusActive, ompclient.TeamStatusArchived} {
		status := status
		var cursor *string
		limit := 200
		for {
			res, err := check(c.AdminListTeamsWithResponse(ctx, &ompclient.AdminListTeamsParams{Status: &status, Cursor: cursor, Limit: &limit}))
			if err != nil {
				return nil, err
			}
			page, err := dataOf(res.JSON200)
			if err != nil {
				return nil, err
			}
			for _, t := range page.Items {
				all = append(all, t.Team)
			}
			if page.NextCursor == nil || *page.NextCursor == "" {
				break
			}
			cursor = page.NextCursor
		}
	}
	sort.Slice(all, func(i, j int) bool { return all[i].Slug < all[j].Slug })
	return all, nil
}

func listPlatformGateways(ctx context.Context, c *api) ([]ompclient.Gateway, error) {
	var all []ompclient.Gateway
	var cursor *string
	limit := 200
	kind := ompclient.GatewayOwnerKindPlatform
	for {
		res, err := check(c.AdminListGatewaysWithResponse(ctx, &ompclient.AdminListGatewaysParams{OwnerKind: &kind, Cursor: cursor, Limit: &limit}))
		if err != nil {
			return nil, err
		}
		page, err := dataOf(res.JSON200)
		if err != nil {
			return nil, err
		}
		all = append(all, page.Items...)
		if page.NextCursor == nil || *page.NextCursor == "" {
			return all, nil
		}
		cursor = page.NextCursor
	}
}

func getGatewayCapabilities(ctx context.Context, c *api, id uuid.UUID) (ompclient.GatewayCapabilities, error) {
	res, err := check(c.AdminListGatewayCapabilitiesWithResponse(ctx, id))
	if err != nil {
		return ompclient.GatewayCapabilities{}, err
	}
	return dataOf(res.JSON200)
}

func getGatewayGrants(ctx context.Context, c *api, id uuid.UUID) ([]ompclient.GatewayGrant, error) {
	res, err := check(c.AdminListGatewayGrantsWithResponse(ctx, id))
	if err != nil {
		return nil, err
	}
	return dataOf(res.JSON200)
}

func getTeamLimits(ctx context.Context, c *api, team string) (map[string]*int64, error) {
	res, err := check(c.AdminGetTeamLimitsWithResponse(ctx, team))
	if err != nil {
		return nil, err
	}
	if res.JSON200 == nil {
		return nil, badResponse()
	}
	out := map[string]*int64{}
	for _, it := range res.JSON200.Data.Items {
		out[string(it.Key)] = it.Override
	}
	return out, nil
}

func getPlatformLimits(ctx context.Context, c *api) (ompclient.LimitSettings, error) {
	res, err := check(c.AdminGetLimitSettingsWithResponse(ctx))
	if err != nil {
		return ompclient.LimitSettings{}, err
	}
	if res.JSON200 == nil {
		return ompclient.LimitSettings{}, badResponse()
	}
	return res.JSON200.Data, nil
}

// grantFrom and capFrom convert what the portal returns to the file's form.
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
	return out
}

func capFrom(c ompclient.GatewayCapability) CapabilityRef {
	return CapabilityRef{Server: c.ServerSlug, Kind: string(c.Kind), Name: c.Name}
}

// scopeKey is a canonical text for a grant's tool ceiling, for comparing.
func scopeKey(ts *ToolScope) string {
	if ts == nil {
		return "unrestricted"
	}
	list := func(v *[]string) string {
		if v == nil {
			return "-"
		}
		s := append([]string(nil), *v...)
		sort.Strings(s)
		return "[" + strings.Join(s, ",") + "]"
	}
	return "classes=" + list(ts.Classes) + " tools=" + list(ts.Tools)
}

// ---- teams -------------------------------------------------------------------

func (p *planner) planTeams(ctx context.Context, desired []Team) error {
	if len(desired) == 0 {
		return nil
	}
	current, err := listTeams(ctx, p.c)
	if err != nil {
		return err
	}
	by := map[string]ompclient.Team{}
	for _, t := range current {
		by[t.Slug] = t
	}
	sorted := append([]Team(nil), desired...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Slug < sorted[j].Slug })
	for _, d := range sorted {
		d := d
		cur, exists := by[d.Slug]
		ch := Change{Kind: "team", Key: d.Slug, Action: "update"}
		add := func(field string, from, to any) {
			ch.Fields = append(ch.Fields, FieldChange{Field: field, From: from, To: to})
		}
		var patch ompclient.TeamUpdate
		hasPatch := false
		var limitChanges []ompclient.TeamLimitChange
		if !exists {
			ch.Action = "create"
			if d.OwnerEmail == "" {
				return usageErr("team %s does not exist: ownerEmail is required to create it", d.Slug)
			}
			add("name", nil, d.Name)
			if d.Description != nil {
				add("description", nil, *d.Description)
			}
			add("ownerEmail", nil, d.OwnerEmail)
			if d.Status == "archived" {
				add("status", nil, "archived")
				s := ompclient.TeamStatusArchived
				patch.Status, hasPatch = &s, true
			}
			for _, k := range sortedKeys(d.Limits) {
				if v := d.Limits[k]; v != nil {
					add("limits."+k, nil, *v)
					limitChanges = append(limitChanges, ompclient.TeamLimitChange{Key: ompclient.RateLimitKey(k), Value: v})
				}
			}
		} else {
			if d.Name != cur.Name {
				add("name", cur.Name, d.Name)
				patch.Name, hasPatch = &d.Name, true
			}
			if d.Description != nil && *d.Description != cur.Description {
				add("description", cur.Description, *d.Description)
				patch.Description, hasPatch = d.Description, true
			}
			if d.Status != "" && d.Status != string(cur.Status) {
				add("status", string(cur.Status), d.Status)
				s := ompclient.TeamStatus(d.Status)
				patch.Status, hasPatch = &s, true
			}
			if len(d.Limits) > 0 {
				have, err := getTeamLimits(ctx, p.c, d.Slug)
				if err != nil {
					return err
				}
				for _, k := range sortedKeys(d.Limits) {
					if !equalInt(have[k], d.Limits[k]) {
						add("limits."+k, intText(have[k]), intText(d.Limits[k]))
						limitChanges = append(limitChanges, ompclient.TeamLimitChange{Key: ompclient.RateLimitKey(k), Value: d.Limits[k]})
					}
				}
			}
		}
		if len(ch.Fields) == 0 {
			continue
		}
		create, rev := !exists, cur.Revision
		p.steps = append(p.steps, &step{Change: ch, run: func(ctx context.Context, r *runResult) error {
			if create {
				desc := d.Description
				res, err := check(p.c.AdminCreateTeamWithResponse(ctx, ompclient.TeamCreate{Slug: d.Slug, Name: d.Name, Description: desc, OwnerEmail: openapi_types.Email(d.OwnerEmail)}))
				if err != nil {
					return err
				}
				if res.JSON201 == nil {
					return badResponse()
				}
				rev = res.JSON201.Data.Team.Team.Revision
			}
			if hasPatch {
				res, err := check(p.c.AdminUpdateTeamWithResponse(ctx, d.Slug, &ompclient.AdminUpdateTeamParams{IfMatch: ifMatch(rev)}, patch))
				if err != nil {
					return withHint(err, "the team changed since the plan was read; run the command again")
				}
				sum, err := dataOf(res.JSON200)
				if err != nil {
					return err
				}
				rev = sum.Team.Revision
			}
			if len(limitChanges) > 0 {
				_, err := check(p.c.AdminUpdateTeamLimitsWithResponse(ctx, d.Slug, &ompclient.AdminUpdateTeamLimitsParams{IfMatch: ifMatch(rev)}, ompclient.TeamLimitsUpdate{Items: limitChanges}))
				return withHint(err, "the team changed since the plan was read; run the command again")
			}
			return nil
		}})
	}
	return nil
}

func equalInt(a, b *int64) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

func intText(v *int64) any {
	if v == nil {
		return nil
	}
	return *v
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
		d := d
		cur, exists := by[d.Slug]
		ch := Change{Kind: "gateway", Key: d.Slug, Action: "update"}
		add := func(field string, from, to any) {
			ch.Fields = append(ch.Fields, FieldChange{Field: field, From: from, To: to})
		}
		var patch ompclient.GatewayUpdate
		hasPatch := false

		var haveCaps map[string]uuid.UUID
		var wantCaps map[string]CapabilityRef
		capsChanged := false
		haveGrants := map[string]ompclient.GatewayGrant{}
		var grantAdd []Grant
		var grantRemove []ompclient.GatewayGrant

		if !exists {
			ch.Action = "create"
			add("name", nil, d.Name)
			if d.Description != nil {
				add("description", nil, *d.Description)
			}
			if d.Enabled != nil {
				add("enabled", nil, *d.Enabled)
			}
		} else {
			if d.Name != cur.Name {
				add("name", cur.Name, d.Name)
				patch.Name, hasPatch = &d.Name, true
			}
			if d.Description != nil && *d.Description != cur.Description {
				add("description", cur.Description, *d.Description)
				patch.Description, hasPatch = d.Description, true
			}
			if d.Enabled != nil && *d.Enabled != cur.Enabled {
				add("enabled", cur.Enabled, *d.Enabled)
				patch.Enabled, hasPatch = d.Enabled, true
			}
		}

		if d.Capabilities != nil {
			haveCaps = map[string]uuid.UUID{}
			haveRefs := map[string]CapabilityRef{}
			if exists {
				caps, err := getGatewayCapabilities(ctx, p.c, cur.Id)
				if err != nil {
					return err
				}
				for _, c := range caps.Items {
					ref := capFrom(c)
					haveCaps[ref.key()] = c.CapabilityId
					haveRefs[ref.key()] = ref
				}
			}
			wantCaps = map[string]CapabilityRef{}
			for _, c := range *d.Capabilities {
				wantCaps[c.key()] = c
			}
			var missing map[string]bool
			for _, k := range sortedKeys(wantCaps) {
				if _, ok := haveCaps[k]; !ok {
					c := wantCaps[k]
					add("capability", nil, fmt.Sprintf("%s %s/%s", c.Kind, c.Server, c.Name))
					capsChanged = true
					if missing == nil {
						missing = map[string]bool{}
					}
					missing[k] = true
				}
			}
			for _, k := range sortedKeys(haveRefs) {
				if _, ok := wantCaps[k]; !ok {
					c := haveRefs[k]
					add("capability", fmt.Sprintf("%s %s/%s", c.Kind, c.Server, c.Name), nil)
					capsChanged = true
				}
			}
			if len(missing) > 0 {
				ids, err := capabilityIDs(ctx, p.c, missing)
				if err != nil {
					return err
				}
				for k, id := range ids {
					haveCaps[k] = id // resolved: used by the PUT below with the ones kept
					delete(missing, k)
				}
				for _, k := range sortedKeys(missing) {
					c := wantCaps[k]
					p.warn("gateway %s: %s %s/%s is not selectable now (it must be an approved, listed tool or prompt of a published, enabled server); apply would fail", d.Slug, c.Kind, c.Server, c.Name)
				}
			}
		}

		if d.Grants != nil {
			if exists {
				grants, err := getGatewayGrants(ctx, p.c, cur.Id)
				if err != nil {
					return err
				}
				for _, g := range grants {
					haveGrants[grantFrom(g).subject()] = g
				}
			}
			wantGrants := map[string]Grant{}
			for _, g := range *d.Grants {
				wantGrants[g.subject()] = g
			}
			for _, k := range sortedKeys(wantGrants) {
				g := wantGrants[k]
				hg, ok := haveGrants[k]
				switch {
				case !ok:
					add("grant", nil, k)
					grantAdd = append(grantAdd, g)
				case scopeKey(grantFrom(hg).ToolScope) != scopeKey(g.ToolScope):
					add("grant "+k+" toolScope", scopeKey(grantFrom(hg).ToolScope), scopeKey(g.ToolScope))
					grantRemove = append(grantRemove, hg)
					grantAdd = append(grantAdd, g)
				}
			}
			for _, k := range sortedKeys(haveGrants) {
				if _, ok := wantGrants[k]; !ok {
					add("grant", k, nil)
					grantRemove = append(grantRemove, haveGrants[k])
				}
			}
		}

		if len(ch.Fields) == 0 {
			continue
		}
		create, id, rev := !exists, cur.Id, cur.Revision
		p.steps = append(p.steps, &step{Change: ch, run: func(ctx context.Context, r *runResult) error {
			if create {
				res, err := check(p.c.AdminCreateGatewayWithResponse(ctx, ompclient.GatewayCreate{Slug: d.Slug, Name: d.Name, Description: d.Description, Enabled: d.Enabled}))
				if err != nil {
					return err
				}
				gw, err := dataOf(res.JSON201)
				if err != nil {
					return err
				}
				id, rev = gw.Id, gw.Revision
			}
			if hasPatch {
				res, err := check(p.c.AdminUpdateGatewayWithResponse(ctx, id, &ompclient.AdminUpdateGatewayParams{IfMatch: ifMatch(rev)}, patch))
				if err != nil {
					return withHint(err, "the gateway changed since the plan was read; run the command again")
				}
				gw, err := dataOf(res.JSON200)
				if err != nil {
					return err
				}
				rev = gw.Revision
			}
			if capsChanged {
				items := make([]ompclient.GatewayCapabilitySelection, 0, len(wantCaps))
				for _, k := range sortedKeys(wantCaps) {
					capID, ok := haveCaps[k]
					if !ok {
						c := wantCaps[k]
						return &Error{Exit: ExitRejected, Code: "capability_not_found", Message: fmt.Sprintf("%s %s/%s is not selectable now (approved, listed tools and prompts of published, enabled servers only)", c.Kind, c.Server, c.Name)}
					}
					items = append(items, ompclient.GatewayCapabilitySelection{CapabilityId: capID})
				}
				if !create && !hasPatch {
					// The revision may have moved since the plan was read.
					caps, err := getGatewayCapabilities(ctx, p.c, id)
					if err != nil {
						return err
					}
					rev = caps.Revision
				}
				if _, err := check(p.c.AdminSetGatewayCapabilitiesWithResponse(ctx, id, &ompclient.AdminSetGatewayCapabilitiesParams{IfMatch: ifMatch(rev)}, ompclient.GatewayCapabilitiesUpdate{Items: items})); err != nil {
					return withHint(err, "the gateway changed since the plan was read; run the command again")
				}
			}
			for _, g := range grantRemove {
				if _, err := check(p.c.AdminRemoveGatewayGrantWithResponse(ctx, id, g.Id)); err != nil {
					return err
				}
			}
			for _, g := range grantAdd {
				body := ompclient.GatewayGrantCreate{}
				switch {
				case g.Team != "":
					body.SubjectKind, body.Team = ompclient.GatewayGrantSubjectKindTeam, &g.Team
				case g.Group != "":
					body.SubjectKind, body.Group = ompclient.GatewayGrantSubjectKindGroup, &g.Group
				default:
					body.SubjectKind, body.UserEmail = ompclient.GatewayGrantSubjectKindUser, &g.UserEmail
				}
				if g.ToolScope != nil {
					ts := ompclient.ToolScope{}
					if g.ToolScope.Classes != nil {
						cl := make([]ompclient.ToolClass, len(*g.ToolScope.Classes))
						for i, c := range *g.ToolScope.Classes {
							cl[i] = ompclient.ToolClass(c)
						}
						ts.Classes = &cl
					}
					ts.Tools = g.ToolScope.Tools
					body.ToolScope = &ts
				}
				if _, err := check(p.c.AdminAddGatewayGrantWithResponse(ctx, id, body)); err != nil {
					return err
				}
			}
			return nil
		}})
	}
	return nil
}

// ---- platform limits ---------------------------------------------------------

func (p *planner) planPlatformLimits(ctx context.Context, desired map[string]PlatformLimit) error {
	if len(desired) == 0 {
		return nil
	}
	cur, err := getPlatformLimits(ctx, p.c)
	if err != nil {
		return err
	}
	have := map[string]ompclient.PlatformRateLimit{}
	for _, it := range cur.Items {
		have[string(it.Key)] = it
	}
	ch := Change{Kind: "limits", Key: "platform", Action: "update"}
	var items []ompclient.PlatformRateLimitSetting
	for _, k := range sortedKeys(desired) {
		d := desired[k]
		h, ok := have[k]
		if !ok {
			return usageErr("limits.%s: the portal has no such rate-limit key", k)
		}
		changed := false
		if !equalInt(h.Default, d.Default) {
			ch.Fields = append(ch.Fields, FieldChange{Field: k + ".default", From: intText(h.Default), To: intText(d.Default)})
			changed = true
		}
		if !equalInt(h.Ceiling, d.Ceiling) {
			ch.Fields = append(ch.Fields, FieldChange{Field: k + ".ceiling", From: intText(h.Ceiling), To: intText(d.Ceiling)})
			changed = true
		}
		if changed {
			items = append(items, ompclient.PlatformRateLimitSetting{Key: ompclient.RateLimitKey(k), Default: d.Default, Ceiling: d.Ceiling})
		}
	}
	if len(items) == 0 {
		return nil
	}
	rev := cur.Revision
	p.steps = append(p.steps, &step{Change: ch, run: func(ctx context.Context, r *runResult) error {
		_, err := check(p.c.AdminUpdateLimitSettingsWithResponse(ctx, &ompclient.AdminUpdateLimitSettingsParams{IfMatch: ifMatch(rev)}, ompclient.LimitSettingsUpdate{Items: items}))
		return withHint(err, "the limits changed since the plan was read; run the command again")
	}})
	return nil
}
