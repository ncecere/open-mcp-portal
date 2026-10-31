package registry

import (
	"context"

	"github.com/google/uuid"

	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/internal/teams"
)

// The company catalog: published, enabled servers of active teams, and only
// their listed capabilities whose current definition is approved. Any
// signed-in person (an active session) may browse it. Archiving a team takes
// its servers out of the catalog without changing them; unarchiving brings
// them back.

// ListCatalog lists published, enabled servers of active teams by (name,
// id). Their counts are of approved, listed capabilities
// (ServerView.Approved). Search additionally matches only the currently
// approved, listed capability metadata, in the same visibility-filtered query.
func (s *Service) ListCatalog(ctx context.Context, _ authz.Actor, p ListParams) ([]ServerView, error) {
	qp := p.query()
	qp.Catalog, qp.PublishState, qp.ChangesOnly = true, nil, false
	rows, err := s.q.ListMCPServers(ctx, qp)
	if err != nil {
		return nil, err
	}
	return views(ctx, s.q, rows)
}

// CatalogServer is a published server with its approved capabilities.
type CatalogServer struct {
	View         ServerView
	Capabilities []CatalogCapability
}

// CatalogCapability is an approved capability with its effective
// user-authorization requirement (nil: none).
type CatalogCapability struct {
	Capability dbgen.McpCapability
	Requires   *Requirement
}

// GetCatalog returns a published, enabled server of an active team; any
// other is not found.
func (s *Service) GetCatalog(ctx context.Context, _ authz.Actor, id uuid.UUID) (CatalogServer, error) {
	v, err := s.view(ctx, s.q, id)
	if err != nil {
		return CatalogServer{}, err
	}
	if v.Server.PublishState != StatePublished || !v.Server.Enabled || v.TeamStatus != teams.StatusActive {
		return CatalogServer{}, errNoServer
	}
	caps, err := s.q.ListApprovedMCPCapabilities(ctx, id)
	if err != nil {
		return CatalogServer{}, err
	}
	ps, err := LoadProviders(ctx, s.q)
	if err != nil {
		return CatalogServer{}, err
	}
	out := CatalogServer{View: v, Capabilities: make([]CatalogCapability, len(caps))}
	for i, c := range caps {
		out.Capabilities[i] = CatalogCapability{Capability: c, Requires: EffectiveFor(v.Server, c, ps)}
	}
	return out, nil
}
