package ompcli

import (
	"context"
	"fmt"
	"sort"

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
