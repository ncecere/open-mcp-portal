package providers

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/registry"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

// ServicePickable adds reachable server-bound providers to the shared-account
// picker. Platform providers are not gated by destination policy at connect time.
func (s *Service) ServicePickable(ctx context.Context, a authz.Actor, team string) ([]registry.Provider, error) {
	if _, e := serviceAccess(ctx, s.q, a, team, false); e != nil {
		return nil, e
	}
	out, e := s.List(ctx)
	if e != nil {
		return nil, e
	}
	if s.Reachable == nil {
		return out, nil
	}
	u, e := s.q.GetUser(ctx, a.UserID)
	if e != nil {
		return nil, e
	}
	rs, e := s.Reachable(ctx, u)
	if e != nil {
		return nil, e
	}
	for _, r := range rs {
		if r.Server.AuthMode != "oauth" {
			continue
		}
		p, e := s.q.GetServerProvider(ctx, uuid.NullUUID{UUID: r.Server.ID, Valid: true})
		if e != nil {
			return nil, e
		}
		if p.Enabled && s.linkUsable(ctx, p) == nil {
			out = append(out, registry.ProviderOf(p))
		}
	}
	return out, nil
}

// ServiceConnectionReady is a metadata-only live policy check. It never
// decrypts, refreshes, returns a token or creates a pending consent request.
func (s *Service) ServiceConnectionReady(ctx context.Context, req *registry.Requirement, account, team, server uuid.UUID, url string) (bool, error) {
	id, e := s.q.GetServiceConnectionAssignment(ctx, dbgen.GetServiceConnectionAssignmentParams{ServiceAccountID: account, ProviderID: req.Provider.ID})
	if errors.Is(e, pgx.ErrNoRows) {
		return false, nil
	}
	if e != nil {
		return false, e
	}
	c, e := s.q.GetServiceConnection(ctx, id)
	if errors.Is(e, pgx.ErrNoRows) {
		return false, nil
	}
	if e != nil {
		return false, e
	}
	_, e = s.serviceAuthorized(ctx, s.q, req, ServiceCallContext{Account: dbgen.ServiceAccount{ID: account}, Team: dbgen.Team{ID: team}, ServerID: server, ServerURL: url, ServerOrigin: registry.OriginOf(url)}, c)
	var refused *ServiceCredentialError
	if errors.As(e, &refused) || errors.Is(e, ErrProviderDisabled) || errors.Is(e, ErrProviderNotAllowed) {
		return false, nil
	}
	return e == nil, e
}

// ServiceAllowable lists only destinations reachable by the current browser
// user, never every catalog server. Saving rechecks these offers and locks the
// destination while checking the origin and scopes shown here.
func (s *Service) ServiceAllowable(ctx context.Context, a authz.Actor, team string, id uuid.UUID) ([]Allowable, error) {
	t, e := serviceAccess(ctx, s.q, a, team, false)
	if e != nil {
		return nil, e
	}
	c, e := s.q.GetServiceConnection(ctx, id)
	if e = serviceOwned(c, t, e); e != nil {
		return nil, e
	}
	p, e := s.q.GetAuthProvider(ctx, c.ProviderID)
	if e != nil {
		return nil, e
	}
	out := []Allowable{}
	if !p.Enabled || s.Reachable == nil {
		return out, nil
	}
	u, e := s.q.GetUser(ctx, a.UserID)
	if e != nil {
		return nil, e
	}
	reachable, e := s.Reachable(ctx, u)
	if e != nil {
		return nil, e
	}
	for _, r := range reachable {
		var scopes []string
		found := false
		if p.Kind == KindMCPServer {
			found = p.ServerID.Valid && p.ServerID.UUID == r.Server.ID
			scopes = p.DefaultScopes
		} else {
			ok, e := allowsServer(ctx, s.q, p.ID, r.Server.ID)
			if e != nil {
				return nil, e
			}
			if !ok {
				continue
			}
			for _, n := range r.Needs {
				if n.Provider.ID == p.ID {
					scopes = n.Scopes
					found = true
				}
			}
		}
		if !found {
			continue
		}
		origin := registry.OriginOf(r.Server.URL)
		g, e := s.q.GetServiceConnectionGrant(ctx, dbgen.GetServiceConnectionGrantParams{ConnectionID: c.ID, ServerID: r.Server.ID})
		allowed := e == nil && g.Origin == origin && Covers(g.Scopes, scopes)
		out = append(out, Allowable{Server: ServerRef{ID: r.Server.ID, Slug: r.Server.Slug, Name: r.Server.Name, TeamSlug: r.TeamSlug, TeamName: r.TeamName}, Origin: origin, Scopes: nonNil(scopes), Covered: c.Status == StatusActive && Covers(c.Scopes, scopes), Allowed: allowed})
	}
	return out, nil
}
