package gateways

import (
	"context"

	"github.com/google/uuid"

	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/internal/teams"
)

// Serving is a gateway as one MCP request serves it: the row with a team
// gateway's team. The request path reads the team once here and reuses it for
// the unserved check, the selection and the team's limits, instead of once
// for each.
type Serving struct {
	Gateway dbgen.Gateway
	// Team is a team gateway's team (nil for a platform gateway).
	Team *dbgen.Team
}

// Serving reads what serving g needs beyond its row.
func (s *Service) Serving(ctx context.Context, g dbgen.Gateway) (Serving, error) {
	sv := Serving{Gateway: g}
	if g.OwnerKind != OwnerTeam || !g.TeamID.Valid {
		return sv, nil
	}
	t, err := s.q.GetTeamByID(ctx, g.TeamID.UUID)
	if err != nil {
		return sv, err
	}
	sv.Team = &t
	return sv, nil
}

func (sv Serving) teamArchived() bool {
	return sv.Team != nil && sv.Team.Status != teams.StatusActive
}

// Unserved is Service.Unserved for a gateway already read for serving.
func (sv Serving) Unserved() string {
	switch {
	case !sv.Gateway.Enabled:
		return DeniedGatewayDisabled
	case sv.teamArchived():
		return ReasonTeamArchived
	}
	return ""
}

// ServingOffers is Offers for a gateway already read for serving.
func (s *Service) ServingOffers(ctx context.Context, sv Serving, c Caller) ([]Offer, error) {
	rows, err := s.q.ListGatewaySelection(ctx, sv.Gateway.ID)
	if err != nil {
		return nil, err
	}
	items, err := selected(ctx, s.q, sv.Gateway, sv.teamArchived(), rows)
	if err != nil {
		return nil, err
	}
	return Evaluate(sv.Gateway, items, c), nil
}

// ServingOffer is the one offer of ServingOffers for a capability (false: the
// gateway does not select it). Every rule ServingOffers applies to a row
// depends on that row alone, so this is the same offer without reading and
// projecting the rest of the selection.
func (s *Service) ServingOffer(ctx context.Context, sv Serving, c Caller, capabilityID uuid.UUID) (Offer, bool, error) {
	rows, err := s.q.GetGatewaySelectionItem(ctx, dbgen.GetGatewaySelectionItemParams{GatewayID: sv.Gateway.ID, CapabilityID: capabilityID})
	if err != nil || len(rows) == 0 {
		return Offer{}, false, err
	}
	items, err := selected(ctx, s.q, sv.Gateway, sv.teamArchived(), []dbgen.ListGatewaySelectionRow{dbgen.ListGatewaySelectionRow(rows[0])})
	if err != nil {
		return Offer{}, false, err
	}
	return Evaluate(sv.Gateway, items, c)[0], true, nil
}
