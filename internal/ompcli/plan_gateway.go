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

// clock is the time omp measures grant deadlines against (tests replace it).
var clock = time.Now

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

// grantWrite is one permanent grant the step creates. A replacement removes
// old first; any non-nil deadline is refused while the plan is built.
type grantWrite struct {
	subject string
	body    ompclient.GatewayGrantCreate // without a deadline
	// deadline records a requested/retained absolute deadline. Non-nil values
	// are not writable through the relative-day API and always refuse.
	deadline *time.Time
	clamp    bool
	// old is the permanent grant a replacement removes before creating the new
	// one. Failed creation never restores it: another actor may have revoked it.
	old  *ompclient.GatewayGrant
	days *int32 // resolved when the step starts, before its first write
}

func grantBody(g Grant, scope *ToolScope) ompclient.GatewayGrantCreate {
	body := ompclient.GatewayGrantCreate{}
	switch {
	case g.Team != "":
		team := g.Team
		body.SubjectKind, body.Team = ompclient.GatewayGrantSubjectKindTeam, &team
	case g.Group != "":
		group := g.Group
		body.SubjectKind, body.Group = ompclient.GatewayGrantSubjectKindGroup, &group
	default:
		email := g.UserEmail
		body.SubjectKind, body.UserEmail = ompclient.GatewayGrantSubjectKindUser, &email
	}
	if scope != nil && !scope.Unrestricted {
		ts := ompclient.ToolScope{}
		if scope.Classes != nil {
			cl := make([]ompclient.ToolClass, len(*scope.Classes))
			for i, c := range *scope.Classes {
				cl[i] = ompclient.ToolClass(c)
			}
			ts.Classes = &cl
		}
		ts.Tools = scope.Tools
		body.ToolScope = &ts
	}
	return body
}

// daysFor refuses writes that would need an absolute deadline. The API only
// accepts a day count relative to its own authoritative clock; subtracting a
// guessed clock-skew allowance cannot guarantee the preserved deadline. Reading
// and comparing an unchanged expiring grant is safe; recreating one is not.
func daysFor(deadline *time.Time, _ bool) (*int32, error) {
	if deadline == nil {
		return nil, nil
	}
	return nil, fmt.Errorf("the portal accepts relative whole-day lifetimes, not an absolute expiresAt; omp cannot preserve this deadline independently of clock skew, so change this grant in the web UI")
}

func fmtTime(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// deadlineMet compares authoritative timestamps exactly. No allowance may
// treat a grant that lives beyond the declared deadline as compliant.
func deadlineMet(want, have time.Time) bool { return have.Equal(want) }

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
		var ceilingSnapshot *ompclient.Gateway
		if exists {
			ceilingSnapshot = &cur
		}
		if err := checkCeilingDeclaration(d, ceilingSnapshot); err != nil {
			return err
		}
		ch := Change{Kind: "gateway", Key: d.Slug, Action: "update"}
		add := func(field string, from, to any) {
			ch.Fields = append(ch.Fields, FieldChange{Field: field, From: from, To: to})
		}
		var patch ompclient.GatewayUpdate
		hasPatch := false

		var haveCaps map[string]uuid.UUID
		var wantCaps map[string]CapabilityRef
		var haveItems map[uuid.UUID]ompclient.GatewayCapability
		capsChanged := false
		haveGrants := map[string]ompclient.GatewayGrant{}
		var grantAdds, grantReplaces []grantWrite
		var grantRemoves []ompclient.GatewayGrant

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
			haveItems = map[uuid.UUID]ompclient.GatewayCapability{}
			haveRefs := map[string]CapabilityRef{}
			haveByKey := map[string]ompclient.GatewayCapability{}
			if exists {
				caps, err := getGatewayCapabilities(ctx, p.c, cur.Id)
				if err != nil {
					return err
				}
				// One snapshot: the gateway and its selection were read at the
				// same revision, and every write below is conditional on it.
				if caps.Revision != cur.Revision {
					return &Error{Exit: ExitConflict, Code: "revision_conflict", Status: 412, Message: fmt.Sprintf("gateway %s changed while the plan was being read (revision %d, then %d); run the command again", d.Slug, cur.Revision, caps.Revision)}
				}
				for _, c := range caps.Items {
					ref := capFrom(c)
					haveCaps[ref.key()] = c.CapabilityId
					haveRefs[ref.key()] = ref
					haveByKey[ref.key()] = c
					haveItems[c.CapabilityId] = c
				}
			}
			wantCaps = map[string]CapabilityRef{}
			for _, c := range *d.Capabilities {
				wantCaps[c.key()] = c
			}
			// A declared curation is compared with the portal's. omp can write
			// neither a new policy nor a cleared one (a token may not edit
			// curation), so anything that differs is refused now.
			for _, k := range sortedKeys(wantCaps) {
				c := wantCaps[k]
				if c.Curation == nil {
					continue
				}
				it, selected := haveByKey[k]
				if !selected {
					if c.Curation.Clear {
						continue
					}
					return refuseErr("gateway %s: tool %s/%s is not selected yet and the file gives it a curation (%s). omp cannot write curation (an automation token may not edit it, 403 session_required), so the tool would be selected without it. Select the tool without a curation key, then curate it in the web UI.",
						d.Slug, c.Server, c.Name, curationSummary(c.Curation.Policy))
				}
				same, err := curationMatches(it, c.Curation)
				if err != nil {
					return refuseErr("gateway %s: tool %s/%s: %v.", d.Slug, c.Server, c.Name, err)
				}
				if !same {
					have, _ := readCuration(it)
					return refuseErr("gateway %s: the curation of tool %s/%s in the file (%s) differs from the portal's (%s). omp cannot change curation: an automation token may not edit it (403 session_required). Change it in the web UI, or remove the curation key from the file to leave the policy alone.",
						d.Slug, c.Server, c.Name, curationSummary(c.Curation.Policy), curationSummary(have))
				}
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
					fc := FieldChange{Field: "capability", From: fmt.Sprintf("%s %s/%s", c.Kind, c.Server, c.Name)}
					if it := haveByKey[k]; isCurated(it) {
						// The portal deletes a selection's policy with the selection.
						fc.Note = "its curation is deleted with it and cannot be restored by omp"
						p.warn("gateway %s: removing %s %s/%s deletes its curation policy; selecting it again later would be uncurated until someone curates it in the web UI", d.Slug, c.Kind, c.Server, c.Name)
					}
					ch.Fields = append(ch.Fields, fc)
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
			now := clock()
			for _, k := range sortedKeys(wantGrants) {
				g := wantGrants[k]
				var want *time.Time
				if g.ExpiresAt != "" {
					t, _ := time.Parse(time.RFC3339, g.ExpiresAt) // validated by the file
					want = &t
				}
				hg, ok := haveGrants[k]
				if !ok {
					label := k
					if want != nil {
						if !want.After(now) {
							return refuseErr("gateway %s: grant %s expires at %s, which is already past: omp will not create a grant that has already expired.", d.Slug, k, fmtTime(*want))
						}
						if _, err := daysFor(want, false); err != nil {
							return refuseErr("gateway %s: grant %s: expiresAt %s: %v.", d.Slug, k, fmtTime(*want), err)
						}
						label += " (expires " + fmtTime(*want) + ")"
					}
					add("grant", nil, label)
					grantAdds = append(grantAdds, grantWrite{subject: k, body: grantBody(g, g.ToolScope), deadline: want})
					continue
				}
				have := grantFrom(hg)
				scopeDiffers := g.ToolScope != nil && scopeKey(g.ToolScope) != scopeKey(have.ToolScope)
				if hg.ExpiresAt != nil && !hg.ExpiresAt.After(now) {
					// Elapsed: it grants nothing now, whether or not it is still listed.
					expired := *hg.ExpiresAt
					switch {
					case want != nil && deadlineMet(*want, expired) && !scopeDiffers:
						continue // the file records the grant as expired: in sync
					case want != nil && want.After(now):
						if _, err := daysFor(want, false); err != nil {
							return refuseErr("gateway %s: grant %s: expiresAt %s: %v.", d.Slug, k, fmtTime(*want), err)
						}
						scope := g.ToolScope
						if scope == nil {
							scope = have.ToolScope // renewing never widens the ceiling
						}
						add("grant "+k, "expired "+fmtTime(expired), "expires "+fmtTime(*want))
						if scopeDiffers {
							add("grant "+k+" toolScope", scopeKey(have.ToolScope), scopeKey(g.ToolScope))
						}
						grantAdds = append(grantAdds, grantWrite{subject: k, body: grantBody(g, scope), deadline: want})
						continue
					default:
						return refuseErr("gateway %s: grant %s expired at %s and grants nothing now. omp will not recreate it as a permanent grant or with a past deadline. Renew temporary grants in the web UI; to drop it, leave it out of grants (it may stay listed until cleanup).", d.Slug, k, fmtTime(expired))
					}
				}
				// Active: keep its deadline unless the file asks for a shorter one.
				shorten := false
				if want != nil && (hg.ExpiresAt == nil || !deadlineMet(*want, *hg.ExpiresAt)) {
					if hg.ExpiresAt != nil && hg.ExpiresAt.Before(*want) {
						return refuseErr("gateway %s: grant %s expires at %s but the file says %s. omp never extends a grant (the portal cannot change a deadline, only create a grant with a new one). Change temporary grants in the web UI, or keep the portal's deadline by leaving expiresAt out.", d.Slug, k, fmtTime(*hg.ExpiresAt), fmtTime(*want))
					}
					shorten = true
				}
				if !scopeDiffers && !shorten {
					continue
				}
				deadline := hg.ExpiresAt // retained: same deadline, at most
				if shorten {
					deadline = want
				}
				w := grantWrite{subject: k, deadline: deadline, clamp: !shorten, old: &hg}
				scope := have.ToolScope
				if scopeDiffers {
					scope = g.ToolScope
					add("grant "+k+" toolScope", scopeKey(have.ToolScope), scopeKey(g.ToolScope))
				}
				if shorten {
					from := any("permanent")
					if hg.ExpiresAt != nil {
						from = fmtTime(*hg.ExpiresAt)
					}
					add("grant "+k+" expiresAt", from, fmtTime(*want))
				}
				if _, err := daysFor(deadline, w.clamp); err != nil {
					return refuseErr("gateway %s: grant %s cannot be changed in place (the portal has no update, only remove and create): %v. omp never makes a grant outlive its current deadline: change temporary grants in the web UI.", d.Slug, k, err)
				}
				w.body = grantBody(g, scope)
				grantReplaces = append(grantReplaces, w)
			}
			for _, k := range sortedKeys(haveGrants) {
				if _, ok := wantGrants[k]; !ok {
					hg := haveGrants[k]
					label := k
					if hg.ExpiresAt != nil && !hg.ExpiresAt.After(now) {
						label += " (expired " + fmtTime(*hg.ExpiresAt) + ")"
					}
					add("grant", label, nil)
					grantRemoves = append(grantRemoves, hg)
				}
			}
		}

		if len(ch.Fields) == 0 {
			continue
		}
		create, id, rev := !exists, cur.Id, cur.Revision
		p.steps = append(p.steps, &step{Change: ch, run: func(ctx context.Context, r *runResult) error {
			// Resolve every deadline before the first write, so a grant that cannot
			// be created as declared stops the step with nothing changed.
			for i := range grantAdds {
				if days, err := daysFor(grantAdds[i].deadline, grantAdds[i].clamp); err != nil {
					return refuseErr("gateway %s: grant %s: %v.", d.Slug, grantAdds[i].subject, err)
				} else {
					grantAdds[i].days = days
				}
			}
			for i := range grantReplaces {
				if days, err := daysFor(grantReplaces[i].deadline, grantReplaces[i].clamp); err != nil {
					return refuseErr("gateway %s: grant %s: %v.", d.Slug, grantReplaces[i].subject, err)
				} else {
					grantReplaces[i].days = days
				}
			}
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
				// rev is the revision the plan read, advanced only by this step's own
				// successful writes (the create, the PATCH): never a fresh read, which
				// would apply this plan over somebody else's concurrent edit.
				items := make([]ompclient.GatewayCapabilitySelection, 0, len(wantCaps))
				for _, k := range sortedKeys(wantCaps) {
					capID, ok := haveCaps[k]
					if !ok {
						c := wantCaps[k]
						return &Error{Exit: ExitRejected, Code: "capability_not_found", Message: fmt.Sprintf("%s %s/%s is not selectable now (approved, listed tools and prompts of published, enabled servers only)", c.Kind, c.Server, c.Name)}
					}
					// No curation and no expectedFingerprint: the portal preserves the
					// policy of a selection that stays (docs/gateway-curation.md).
					items = append(items, ompclient.GatewayCapabilitySelection{CapabilityId: capID})
				}
				res, err := check(p.c.AdminSetGatewayCapabilitiesWithResponse(ctx, id, &ompclient.AdminSetGatewayCapabilitiesParams{IfMatch: ifMatch(rev)}, ompclient.GatewayCapabilitiesUpdate{Items: items}))
				if err != nil {
					return withHint(err, "the gateway changed since the plan was read; run the command again")
				}
				after, err := dataOf(res.JSON200)
				if err != nil {
					return err
				}
				for _, it := range after.Items {
					if was, kept := haveItems[it.CapabilityId]; kept && curationSig(was) != curationSig(it) {
						return &Error{Exit: ExitFailure, Code: "curation_changed", Message: fmt.Sprintf("the portal reports a different curation for %s %s/%s after the selection was saved; check the gateway in the web UI before importing again", it.Kind, it.ServerSlug, it.Name)}
					}
				}
				rev = after.Revision
			}
			// Grants have no revision. Additions first (they only add), then
			// replacements (a removal and a creation back to back), then removals.
			for _, w := range grantAdds {
				if err := p.addGrant(ctx, id, w.body, w.days); err != nil {
					return err
				}
			}
			for _, w := range grantReplaces {
				if err := p.replaceGrant(ctx, id, w); err != nil {
					return err
				}
			}
			for _, g := range grantRemoves {
				if _, err := check(p.c.AdminRemoveGatewayGrantWithResponse(ctx, id, g.Id)); err != nil {
					return err
				}
			}
			return nil
		}})
	}
	return nil
}

func (p *planner) addGrant(ctx context.Context, gateway uuid.UUID, body ompclient.GatewayGrantCreate, days *int32) error {
	body.ExpiresInDays = days
	_, err := check(p.c.AdminAddGatewayGrantWithResponse(ctx, gateway, body))
	return err
}

// replaceGrant changes a permanent grant's ceiling. The API has no update:
// removal and creation are not atomic. A failed creation never restores the old
// grant automatically; that could resurrect a concurrent revocation.
func (p *planner) replaceGrant(ctx context.Context, gateway uuid.UUID, w grantWrite) error {
	if _, err := check(p.c.AdminRemoveGatewayGrantWithResponse(ctx, gateway, w.old.Id)); err != nil {
		return err // nothing was lost
	}
	err := p.addGrant(ctx, gateway, w.body, w.days)
	if err == nil {
		return nil
	}
	e := asError(err)
	c := *e
	c.Message = fmt.Sprintf("grant %s was removed to change it and the new grant could not be created: %s; no automatic rollback was attempted; inspect current grants in the web UI before retrying", w.subject, e.Message)
	return &c
}
