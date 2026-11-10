package ompcli

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/ncecere/open-mcp-portal/pkg/ompclient"
)

// apply is the gateway's step: the gateway itself, its settings, its selection
// and then its grants.
func (g *gatewayPlan) apply(ctx context.Context, r *runResult) error {
	// Resolve every deadline before the first write, so a grant that cannot
	// be created as declared stops the step with nothing changed.
	if err := g.resolveGrantDays(g.grantAdds); err != nil {
		return err
	}
	if err := g.resolveGrantDays(g.grantReplaces); err != nil {
		return err
	}
	if g.create {
		if err := g.createGateway(ctx); err != nil {
			return err
		}
	}
	if g.hasPatch {
		if err := g.updateSettings(ctx); err != nil {
			return err
		}
	}
	if g.capsChanged {
		if err := g.saveSelection(ctx); err != nil {
			return err
		}
	}
	return g.writeGrants(ctx)
}

func (g *gatewayPlan) resolveGrantDays(writes []grantWrite) error {
	for i := range writes {
		days, err := daysFor(writes[i].deadline, writes[i].clamp)
		if err != nil {
			return refuseErr("gateway %s: grant %s: %v.", g.d.Slug, writes[i].subject, err)
		}
		writes[i].days = days
	}
	return nil
}

func (g *gatewayPlan) createGateway(ctx context.Context) error {
	d := g.d
	res, err := check(g.p.c.AdminCreateGatewayWithResponse(ctx, ompclient.GatewayCreate{Slug: d.Slug, Name: d.Name, Description: d.Description, Enabled: d.Enabled}))
	if err != nil {
		return err
	}
	gw, err := dataOf(res.JSON201)
	if err != nil {
		return err
	}
	g.id, g.rev = gw.Id, gw.Revision
	return nil
}

func (g *gatewayPlan) updateSettings(ctx context.Context) error {
	res, err := check(g.p.c.AdminUpdateGatewayWithResponse(ctx, g.id, &ompclient.AdminUpdateGatewayParams{IfMatch: ifMatch(g.rev)}, g.patch))
	if err != nil {
		return withHint(err, "the gateway changed since the plan was read; run the command again")
	}
	gw, err := dataOf(res.JSON200)
	if err != nil {
		return err
	}
	g.rev = gw.Revision
	return nil
}

// saveSelection replaces the gateway's selection with the declared one and
// checks that no kept capability's curation changed with it.
func (g *gatewayPlan) saveSelection(ctx context.Context) error {
	// rev is the revision the plan read, advanced only by this step's own
	// successful writes (the create, the PATCH): never a fresh read, which
	// would apply this plan over somebody else's concurrent edit.
	items := make([]ompclient.GatewayCapabilitySelection, 0, len(g.wantCaps))
	for _, k := range sortedKeys(g.wantCaps) {
		capID, ok := g.haveCaps[k]
		if !ok {
			c := g.wantCaps[k]
			return &Error{Exit: ExitRejected, Code: "capability_not_found", Message: fmt.Sprintf("%s %s/%s is not selectable now (approved, listed tools and prompts of published, enabled servers only)", c.Kind, c.Server, c.Name)}
		}
		// No curation and no expectedFingerprint: the portal preserves the
		// policy of a selection that stays (docs/gateway-curation.md).
		items = append(items, ompclient.GatewayCapabilitySelection{CapabilityId: capID})
	}
	res, err := check(g.p.c.AdminSetGatewayCapabilitiesWithResponse(ctx, g.id, &ompclient.AdminSetGatewayCapabilitiesParams{IfMatch: ifMatch(g.rev)}, ompclient.GatewayCapabilitiesUpdate{Items: items}))
	if err != nil {
		return withHint(err, "the gateway changed since the plan was read; run the command again")
	}
	after, err := dataOf(res.JSON200)
	if err != nil {
		return err
	}
	for _, it := range after.Items {
		if was, kept := g.haveItems[it.CapabilityId]; kept && curationSig(was) != curationSig(it) {
			return &Error{Exit: ExitFailure, Code: "curation_changed", Message: fmt.Sprintf("the portal reports a different curation for %s %s/%s after the selection was saved; check the gateway in the web UI before importing again", it.Kind, it.ServerSlug, it.Name)}
		}
	}
	g.rev = after.Revision
	return nil
}

// Grants have no revision. Additions first (they only add), then
// replacements (a removal and a creation back to back), then removals.
func (g *gatewayPlan) writeGrants(ctx context.Context) error {
	for _, w := range g.grantAdds {
		if err := g.p.addGrant(ctx, g.id, w.body, w.days); err != nil {
			return err
		}
	}
	for _, w := range g.grantReplaces {
		if err := g.p.replaceGrant(ctx, g.id, w); err != nil {
			return err
		}
	}
	for _, rm := range g.grantRemoves {
		if _, err := check(g.p.c.AdminRemoveGatewayGrantWithResponse(ctx, g.id, rm.Id)); err != nil {
			return err
		}
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
