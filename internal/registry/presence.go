package registry

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ncecere/open-mcp-portal/internal/apperr"
	"github.com/ncecere/open-mcp-portal/internal/audit"
	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/store"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

// Requires a present person (decision 66, docs/agent-platforms.md "Calls
// that need the person there"): a server, and each of its capabilities, may
// refuse calls that an agent platform relays for a person who is not
// present (the token's person_present is false: scheduled work, webhooks,
// other runs nobody watches). The server's switch (mcp_servers.
// requires_present_person, default off) applies to every capability unless
// the capability has an override (mcp_capabilities.requires_present_person:
// true requires, false doesn't even when the server does, NULL follows the
// server). Calls that aren't relayed for a person are never affected.
//
// Review: requiring a present person narrows what agents can do, so turning
// it on never needs review. Relaxing it (a capability that was effectively
// required no longer is, by switching the server off or by an override of
// false) sends a published server back to review under approval_required, as
// widening a requirement does (reason requirement_changed), because the
// approved configuration relied on it. Both changes are audited.

// Present-person modes of a capability's override.
const (
	PresenceInherit     = "inherit"
	PresenceRequired    = "required"
	PresenceNotRequired = "not_required"
)

// PresentPersonRequired is whether relayed calls of the capability need the
// person present.
func PresentPersonRequired(sv dbgen.McpServer, c dbgen.McpCapability) bool {
	if c.RequiresPresentPerson != nil {
		return *c.RequiresPresentPerson
	}
	return sv.RequiresPresentPerson
}

// PresenceMode is a capability's override as a mode.
func PresenceMode(c dbgen.McpCapability) string {
	switch {
	case c.RequiresPresentPerson == nil:
		return PresenceInherit
	case *c.RequiresPresentPerson:
		return PresenceRequired
	}
	return PresenceNotRequired
}

// presenceAll is every capability's effective value, by ID.
func presenceAll(ctx context.Context, q *dbgen.Queries, sv dbgen.McpServer) (map[uuid.UUID]bool, error) {
	rows, err := q.ListMCPCapabilities(ctx, dbgen.ListMCPCapabilitiesParams{ServerID: sv.ID})
	if err != nil {
		return nil, err
	}
	out := make(map[uuid.UUID]bool, len(rows))
	for _, r := range rows {
		out[r.McpCapability.ID] = PresentPersonRequired(sv, r.McpCapability)
	}
	return out, nil
}

// relaxed reports whether any capability that required a present person
// before doesn't after.
func relaxed(before, after map[uuid.UUID]bool) bool {
	for id, was := range before {
		if was && !after[id] {
			return true
		}
	}
	return false
}

const notePresenceRelaxed = "The server no longer requires a present person for some calls from agents; review it again."

// PresenceInput is a capability's present-person override: a Mode of
// PresenceInherit, PresenceRequired or PresenceNotRequired.
type PresenceInput struct{ Mode string }

// SetCapabilityPresence sets a capability's present-person override (team
// editors and above). expectedRevision is the server's, which this bumps.
// Relaxing it sends a published server back to review under
// approval_required. Audited as mcp_capability.presence_set.
func (s *Service) SetCapabilityPresence(ctx context.Context, a authz.Actor, ref string, serverID, capID uuid.UUID, in PresenceInput, expectedRevision int64) (CapabilityView, int64, error) {
	var value *bool
	switch in.Mode {
	case PresenceInherit:
	case PresenceRequired:
		t := true
		value = &t
	case PresenceNotRequired:
		f := false
		value = &f
	default:
		return CapabilityView{}, 0, apperr.Invalid("invalid_mode", "mode must be inherit, required or not_required")
	}
	var out CapabilityView
	var revision int64
	err := store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		ta, err := access(ctx, q, a, ref)
		if err != nil {
			return err
		}
		if err := ta.writable(authz.CheckServerEdit); err != nil {
			return err
		}
		sv, err := teamServer(ctx, q, ta.team.ID, serverID, true)
		if err != nil {
			return err
		}
		if sv.Revision != expectedRevision {
			return apperr.Stale()
		}
		cur, err := q.LockMCPCapability(ctx, dbgen.LockMCPCapabilityParams{ID: capID, ServerID: sv.ID})
		if store.NotFound(err) == store.ErrNotFound {
			return errNoCapability
		} else if err != nil {
			return err
		}
		row, err := q.SetMCPCapabilityPresentPerson(ctx, dbgen.SetMCPCapabilityPresentPersonParams{ID: capID, ServerID: sv.ID, RequiresPresentPerson: value})
		if err != nil {
			return err
		}
		bumped, err := q.BumpMCPServerRevision(ctx, dbgen.BumpMCPServerRevisionParams{ID: sv.ID, UpdatedBy: by(a)})
		if err != nil {
			return err
		}
		before, after := PresentPersonRequired(sv, cur), PresentPersonRequired(bumped, row)
		e := a.Audit("mcp_capability.presence_set", "mcp_capability", capID.String())
		e.TeamID = ta.team.ID
		e.Before = map[string]any{"mode": PresenceMode(cur), "effective": before}
		e.After = map[string]any{"mode": PresenceMode(row), "effective": after}
		e.Metadata = map[string]any{"serverId": sv.ID, "server": sv.Name, "kind": cur.Kind, "name": sv.Name + " · " + cur.Name,
			"capability": cur.Name, "relaxed": before && !after}
		if err := audit.Record(ctx, q, e); err != nil {
			return err
		}
		if before && !after {
			if err := s.resubmit(ctx, q, a, ta.team, bumped, "requirement_changed", notePresenceRelaxed); err != nil {
				return err
			}
			if bumped, err = q.GetMCPServer(ctx, sv.ID); err != nil {
				return err
			}
		}
		revision = bumped.Revision
		name := ""
		if r, err := q.ListMCPCapabilities(ctx, dbgen.ListMCPCapabilitiesParams{ServerID: sv.ID}); err == nil {
			for _, c := range r {
				if c.McpCapability.ID == capID {
					name = c.ApprovedByName
				}
			}
		}
		ps, err := LoadProviders(ctx, q)
		if err != nil {
			return err
		}
		out = CapabilityView{Capability: row, ApprovedByName: name, Published: bumped.PublishState == StatePublished,
			Requires: EffectiveFor(bumped, row, ps), EffectivePresentPerson: after}
		return nil
	})
	return out, revision, err
}
