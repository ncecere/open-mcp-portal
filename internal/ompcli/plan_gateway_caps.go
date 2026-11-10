package ompcli

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/ncecere/open-mcp-portal/pkg/ompclient"
)

// selection is a gateway's capability selection as the portal has it, by
// capability key.
type selection struct {
	refs  map[string]CapabilityRef
	items map[string]ompclient.GatewayCapability
}

// planCapabilities compares the declared selection with the portal's: the
// declared curations first (refused when they differ), then what to select and
// what to drop.
func (g *gatewayPlan) planCapabilities(ctx context.Context, cur ompclient.Gateway) error {
	g.haveCaps = map[string]uuid.UUID{}
	g.haveItems = map[uuid.UUID]ompclient.GatewayCapability{}
	have := selection{refs: map[string]CapabilityRef{}, items: map[string]ompclient.GatewayCapability{}}
	if !g.create {
		if err := g.readSelection(ctx, cur, have); err != nil {
			return err
		}
	}
	g.wantCaps = map[string]CapabilityRef{}
	for _, c := range *g.d.Capabilities {
		g.wantCaps[c.key()] = c
	}
	if err := g.checkDeclaredCurations(have); err != nil {
		return err
	}
	missing := g.planCapabilityAdditions()
	g.planCapabilityRemovals(have)
	return g.resolveAdditions(ctx, missing)
}

func (g *gatewayPlan) readSelection(ctx context.Context, cur ompclient.Gateway, have selection) error {
	caps, err := getGatewayCapabilities(ctx, g.p.c, cur.Id)
	if err != nil {
		return err
	}
	// One snapshot: the gateway and its selection were read at the
	// same revision, and every write below is conditional on it.
	if caps.Revision != cur.Revision {
		return &Error{Exit: ExitConflict, Code: "revision_conflict", Status: 412, Message: fmt.Sprintf("gateway %s changed while the plan was being read (revision %d, then %d); run the command again", g.d.Slug, cur.Revision, caps.Revision)}
	}
	for _, c := range caps.Items {
		ref := capFrom(c)
		g.haveCaps[ref.key()] = c.CapabilityId
		have.refs[ref.key()] = ref
		have.items[ref.key()] = c
		g.haveItems[c.CapabilityId] = c
	}
	return nil
}

// A declared curation is compared with the portal's. omp can write
// neither a new policy nor a cleared one (a token may not edit
// curation), so anything that differs is refused now.
func (g *gatewayPlan) checkDeclaredCurations(have selection) error {
	for _, k := range sortedKeys(g.wantCaps) {
		c := g.wantCaps[k]
		if c.Curation == nil {
			continue
		}
		it, selected := have.items[k]
		if !selected {
			if c.Curation.Clear {
				continue
			}
			return refuseErr("gateway %s: tool %s/%s is not selected yet and the file gives it a curation (%s). omp cannot write curation (an automation token may not edit it, 403 session_required), so the tool would be selected without it. Select the tool without a curation key, then curate it in the web UI.",
				g.d.Slug, c.Server, c.Name, curationSummary(c.Curation.Policy))
		}
		if err := g.checkSelectedCuration(c, it); err != nil {
			return err
		}
	}
	return nil
}

// checkSelectedCuration refuses a declared curation that differs from the one
// the selected tool has.
func (g *gatewayPlan) checkSelectedCuration(c CapabilityRef, it ompclient.GatewayCapability) error {
	same, err := curationMatches(it, c.Curation)
	if err != nil {
		return refuseErr("gateway %s: tool %s/%s: %v.", g.d.Slug, c.Server, c.Name, err)
	}
	if !same {
		have, _ := readCuration(it)
		return refuseErr("gateway %s: the curation of tool %s/%s in the file (%s) differs from the portal's (%s). omp cannot change curation: an automation token may not edit it (403 session_required). Change it in the web UI, or remove the curation key from the file to leave the policy alone.",
			g.d.Slug, c.Server, c.Name, curationSummary(c.Curation.Policy), curationSummary(have))
	}
	return nil
}

// planCapabilityAdditions records the declared capabilities the gateway does
// not select yet, and returns their keys (nil when there are none).
func (g *gatewayPlan) planCapabilityAdditions() map[string]bool {
	var missing map[string]bool
	for _, k := range sortedKeys(g.wantCaps) {
		if _, ok := g.haveCaps[k]; ok {
			continue
		}
		c := g.wantCaps[k]
		g.add("capability", nil, fmt.Sprintf("%s %s/%s", c.Kind, c.Server, c.Name))
		g.capsChanged = true
		if missing == nil {
			missing = map[string]bool{}
		}
		missing[k] = true
	}
	return missing
}

// planCapabilityRemovals records the selected capabilities the file leaves out.
func (g *gatewayPlan) planCapabilityRemovals(have selection) {
	for _, k := range sortedKeys(have.refs) {
		if _, ok := g.wantCaps[k]; ok {
			continue
		}
		c := have.refs[k]
		fc := FieldChange{Field: "capability", From: fmt.Sprintf("%s %s/%s", c.Kind, c.Server, c.Name)}
		if it := have.items[k]; isCurated(it) {
			// The portal deletes a selection's policy with the selection.
			fc.Note = "its curation is deleted with it and cannot be restored by omp"
			g.p.warn("gateway %s: removing %s %s/%s deletes its curation policy; selecting it again later would be uncurated until someone curates it in the web UI", g.d.Slug, c.Kind, c.Server, c.Name)
		}
		g.ch.Fields = append(g.ch.Fields, fc)
		g.capsChanged = true
	}
}

// resolveAdditions looks up the IDs of the capabilities to select, and warns
// about the ones that cannot be selected now.
func (g *gatewayPlan) resolveAdditions(ctx context.Context, missing map[string]bool) error {
	if len(missing) == 0 {
		return nil
	}
	ids, err := capabilityIDs(ctx, g.p.c, missing)
	if err != nil {
		return err
	}
	for k, id := range ids {
		g.haveCaps[k] = id // resolved: used by the PUT below with the ones kept
		delete(missing, k)
	}
	for _, k := range sortedKeys(missing) {
		c := g.wantCaps[k]
		g.p.warn("gateway %s: %s %s/%s is not selectable now (it must be an approved, listed tool or prompt of a published, enabled server); apply would fail", g.d.Slug, c.Kind, c.Server, c.Name)
	}
	return nil
}
