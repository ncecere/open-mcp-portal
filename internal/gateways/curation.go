package gateways

import (
	"bytes"
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/ncecere/open-mcp-portal/internal/apperr"
	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/gateways/curation"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/internal/upstream"
)

func applyCuration(it *Selected, row dbgen.GatewayCapability) {
	it.EffectiveDefinition = bytes.Clone(it.Capability.Definition)
	it.BaseFingerprint, it.CuratedBy, it.CuratedAt = row.BaseFingerprint, row.CuratedBy, row.CuratedAt
	if row.BaseFingerprint == nil {
		return
	}
	p := &curation.Policy{NameOverride: row.NameOverride, DescriptionOverride: row.DescriptionOverride}
	err := json.Unmarshal(row.Constraints, &p.Constraints)
	it.Curation = p
	if p.NameOverride != nil {
		it.ExposedName = *p.NameOverride
	}
	projected, normalized, projectErr := curation.Project(it.Capability.Definition, p)
	it.CurationStale = it.Capability.Kind != upstream.KindTool || *row.BaseFingerprint != it.Capability.Fingerprint || err != nil || projectErr != nil
	if !it.CurationStale {
		it.EffectiveDefinition = projected
		it.Curation = normalized
	}
	if it.CurationStale && it.Reason != ReasonGone && it.Reason != ReasonTeamArchived && it.Reason != ReasonServerDisabled {
		it.Available, it.Reason = false, ReasonCurationStale
	}
}

// prepareCurations validates every policy and computes final names before any
// write, under the gateway lock. Omitted policy leaves even stale policy intact.
func prepareCurations(ctx context.Context, q *dbgen.Queries, a authz.Actor, items []SelectionInput, current map[uuid.UUID]Selected, names map[uuid.UUID]string) (map[uuid.UUID]dbgen.SetGatewayCapabilityCurationParams, error) {
	out := map[uuid.UUID]dbgen.SetGatewayCapabilityCurationParams{}
	for _, in := range items {
		old, exists := current[in.CapabilityID]
		if len(in.Curation) == 0 {
			if exists {
				names[in.CapabilityID] = old.ExposedName
			}
			continue
		}
		if a.IsToken() {
			return nil, apperr.New(403, "session_required", "Curation requires a browser session")
		}
		// Serialize review against discovery, not just other gateway edits.
		// A shared lock permits different gateways to curate the same tool.
		cap, err := q.LockCapabilityForCuration(ctx, in.CapabilityID)
		if err != nil {
			return nil, err
		}
		if cap.Kind != upstream.KindTool {
			return nil, apperr.Invalid("invalid_curation", "Only tools may be curated")
		}
		if in.ExpectedFingerprint == nil || *in.ExpectedFingerprint != cap.Fingerprint {
			return nil, apperr.Conflict("changed_since_review", "The tool definition changed; reload it before saving curation")
		}
		row := dbgen.SetGatewayCapabilityCurationParams{}
		if !bytes.Equal(bytes.TrimSpace(in.Curation), []byte("null")) {
			p, err := curation.Decode(in.Curation)
			if err != nil {
				return nil, apperr.Invalid("invalid_curation", err.Error())
			}
			_, p, err = curation.Project(cap.Definition, p)
			if err != nil {
				return nil, apperr.Invalid("invalid_curation", err.Error())
			}
			row.NameOverride, row.DescriptionOverride = p.NameOverride, p.DescriptionOverride
			if p.Constraints == nil {
				p.Constraints = map[string]curation.Constraint{}
			}
			row.Constraints, _ = json.Marshal(p.Constraints)
			row.BaseFingerprint = &cap.Fingerprint
			now := time.Now()
			row.CuratedAt = &now
			row.CuratedBy = uuid.NullUUID{UUID: a.UserID, Valid: a.UserID != uuid.Nil}
			if p.NameOverride != nil {
				names[in.CapabilityID] = *p.NameOverride
			}
		}
		out[in.CapabilityID] = row
	}
	return out, nil
}
