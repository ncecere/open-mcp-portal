package providers

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/ncecere/open-mcp-portal/internal/registry"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

// serviceAuthorized checks live policy for one service call, in this order:
// the provider, the destination server, the team and account, the assigned
// connection and its consent, and the connection's grant for the server. The
// first failing check decides the error.
func (s *Service) serviceAuthorized(ctx context.Context, q *dbgen.Queries, req *registry.Requirement, cc ServiceCallContext, c dbgen.ServiceConnection) (dbgen.AuthProvider, error) {
	p, e := serviceProviderUsable(ctx, q, req.Provider.ID)
	if e != nil {
		return p, e
	}
	sv, e := serviceDestination(ctx, q, p, cc, c)
	if e != nil {
		return p, e
	}
	t, e := serviceOwnerActive(ctx, q, cc)
	if e != nil {
		return p, e
	}
	if e := serviceConnectionCurrent(ctx, q, req, cc, p, t, c); e != nil {
		return p, e
	}
	g, e := q.GetServiceConnectionGrant(ctx, dbgen.GetServiceConnectionGrantParams{ConnectionID: c.ID, ServerID: sv.ID})
	if errors.Is(e, pgx.ErrNoRows) {
		return p, serviceRefused(ServiceConnectionNotAllowed)
	}
	if e != nil {
		return p, e
	}
	if g.Origin != cc.ServerOrigin || !Covers(g.Scopes, req.Scopes) {
		return p, serviceRefused(ServiceConnectionNotAllowed)
	}
	return p, nil
}

// serviceProviderUsable loads the provider: it must exist, be enabled and
// (for a server's own provider) still be usable with its link.
func serviceProviderUsable(ctx context.Context, q *dbgen.Queries, id uuid.UUID) (dbgen.AuthProvider, error) {
	p, e := q.GetAuthProvider(ctx, id)
	if errors.Is(e, pgx.ErrNoRows) || e == nil && !p.Enabled {
		return p, ErrProviderDisabled
	}
	if e != nil {
		return p, e
	}
	if e := linkUsableWith(ctx, q, p); e != nil {
		if errors.Is(e, errLinkMismatch) || errors.Is(e, pgx.ErrNoRows) {
			return p, ErrProviderDisabled
		}
		return p, e
	}
	return p, nil
}

// serviceDestination loads the server the call goes to: enabled, visible to
// the connection's team, at exactly the origin and URL the caller is about to
// use, and served by this provider.
func serviceDestination(ctx context.Context, q *dbgen.Queries, p dbgen.AuthProvider, cc ServiceCallContext, c dbgen.ServiceConnection) (dbgen.McpServer, error) {
	sv, e := q.GetMCPServer(ctx, cc.ServerID)
	if errors.Is(e, pgx.ErrNoRows) {
		return sv, serviceRefused(ServiceConnectionNotAllowed)
	}
	if e != nil {
		return sv, e
	}
	if !sv.Enabled || sv.TeamID != c.TeamID && sv.PublishState != "published" {
		return sv, serviceRefused(ServiceConnectionNotAllowed)
	}
	if cc.ServerOrigin == "" || cc.ServerOrigin != registry.OriginOf(sv.URL) || cc.ServerURL != sv.URL {
		return sv, serviceRefused(ServiceConnectionNotAllowed)
	}
	return sv, serviceProviderServes(ctx, q, p, sv, cc)
}

// serviceProviderServes: a server's own provider serves only that server, in
// OAuth mode, with the server's URL as its resource; any other provider must
// allow the server in its access list and be the one the server names.
func serviceProviderServes(ctx context.Context, q *dbgen.Queries, p dbgen.AuthProvider, sv dbgen.McpServer, cc ServiceCallContext) error {
	if p.Kind == KindMCPServer {
		if !p.ServerID.Valid || p.ServerID.UUID != sv.ID || sv.AuthMode != "oauth" || deref(p.Resource) != cc.ServerURL {
			return serviceRefused(ServiceConnectionNotAllowed)
		}
		return nil
	}
	allowed, e := allowsServer(ctx, q, p.ID, sv.ID)
	if e != nil {
		return e
	}
	if !allowed {
		return ErrProviderNotAllowed
	}
	if !sv.AuthProviderID.Valid || sv.AuthProviderID.UUID != p.ID {
		return serviceRefused(ServiceConnectionNotAllowed)
	}
	return nil
}

// serviceOwnerActive reloads the calling account's team (active) and the
// account itself (in that team, enabled).
func serviceOwnerActive(ctx context.Context, q *dbgen.Queries, cc ServiceCallContext) (dbgen.Team, error) {
	t, e := q.GetTeamByID(ctx, cc.Team.ID)
	if errors.Is(e, pgx.ErrNoRows) {
		return t, serviceRefused(ServiceConnectionNotAllowed)
	}
	if e != nil {
		return t, e
	}
	if t.Status != "active" {
		return t, serviceRefused(ServiceConnectionNotAllowed)
	}
	account, e := q.GetServiceAccountView(ctx, dbgen.GetServiceAccountViewParams{ID: cc.Account.ID, TeamID: t.ID})
	if errors.Is(e, pgx.ErrNoRows) {
		return t, serviceRefused(ServiceConnectionNotAllowed)
	}
	if e != nil {
		return t, e
	}
	if !account.ServiceAccount.Enabled {
		return t, serviceRefused(ServiceConnectionNotAllowed)
	}
	return t, nil
}

// serviceConnectionCurrent: c is the connection assigned to the account for
// this provider, the admin who connected it still administers the team, and
// its consent is active and covers the scopes asked for.
func serviceConnectionCurrent(ctx context.Context, q *dbgen.Queries, req *registry.Requirement, cc ServiceCallContext, p dbgen.AuthProvider, t dbgen.Team, c dbgen.ServiceConnection) error {
	assignment, e := q.GetServiceConnectionAssignment(ctx, dbgen.GetServiceConnectionAssignmentParams{ServiceAccountID: cc.Account.ID, ProviderID: p.ID})
	if errors.Is(e, pgx.ErrNoRows) {
		return serviceRefused(ServiceConnectionMissing)
	}
	if e != nil {
		return e
	}
	if c.ID != assignment || c.TeamID != t.ID || c.ProviderID != p.ID {
		return serviceRefused(ServiceConnectionNotAllowed)
	}
	active := false
	if c.ConnectedBy.Valid {
		active, e = q.ServiceConnectionAdminActive(ctx, dbgen.ServiceConnectionAdminActiveParams{UserID: c.ConnectedBy.UUID, TeamID: c.TeamID})
		if e != nil {
			return e
		}
	}
	if !active {
		return serviceRefused(ServiceConnectionLapsed)
	}
	if c.Status != StatusActive || !Covers(c.Scopes, req.Scopes) {
		return serviceRefused(ServiceConnectionNeedsReconsent)
	}
	return nil
}
