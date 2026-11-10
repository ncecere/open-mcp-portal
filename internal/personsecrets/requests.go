package personsecrets

import (
	"context"
	"errors"

	"github.com/google/uuid"

	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/registry"
	"github.com/ncecere/open-mcp-portal/internal/store"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

// RequestView is a link as its person's page sees it.
type RequestView struct {
	ID     string
	Reason string
	Server ServerRef
	Config registry.PersonSecretInput
	// Origin is the server's origin now (the request's, checked).
	Origin string
	// Mine describes the secret the person has now, if any.
	Mine Mine
	// The gateway as it is now (or as it was, when deleted), and the
	// capability that asked.
	GatewayID                uuid.UUID
	GatewaySlug, GatewayName string
	GatewayExists            bool
	CapabilityKind           string
	ExposedName, Title       string
}

func (s *Service) loadRequest(ctx context.Context, userID uuid.UUID, id string) (dbgen.SecretRequest, error) {
	if !requestIDRE.MatchString(id) {
		return dbgen.SecretRequest{}, errNoRequest
	}
	r, err := s.q.GetSecretRequest(ctx, requestDigest(id))
	if errors.Is(store.NotFound(err), store.ErrNotFound) || (err == nil && r.UserID != userID) {
		return r, errNoRequest
	} else if err != nil {
		return r, err
	}
	if r.UsedAt != nil || !s.now().Before(r.ExpiresAt) {
		return r, errRequestExpired
	}
	return r, nil
}

// GetRequest returns a link for the person it was made for: 404 for an
// unknown or another person's, 410 once expired or used, or when its server
// moved to another origin (or left person_secret mode) since it was made.
func (s *Service) GetRequest(ctx context.Context, a authz.Actor, id string) (RequestView, error) {
	r, err := s.loadRequest(ctx, a.UserID, id)
	if err != nil {
		return RequestView{}, err
	}
	sv, err := s.q.GetMCPServer(ctx, r.ServerID)
	if errors.Is(store.NotFound(err), store.ErrNotFound) {
		return RequestView{}, errRequestExpired
	} else if err != nil {
		return RequestView{}, err
	}
	cfg, ok := registry.PersonSecretConfig(sv)
	if !ok || registry.OriginOf(sv.URL) != r.ServerOrigin {
		return RequestView{}, errRequestExpired
	}
	u, err := s.q.GetUser(ctx, a.UserID)
	if err != nil {
		return RequestView{}, err
	}
	ref, err := s.serverRef(ctx, s.q, sv.ID)
	if err != nil {
		return RequestView{}, err
	}
	m, err := s.mine(ctx, u, sv, ref)
	if err != nil {
		return RequestView{}, err
	}
	v := RequestView{ID: id, Reason: r.Reason, Server: ref, Config: cfg, Origin: r.ServerOrigin, Mine: m, GatewayID: r.GatewayID, GatewaySlug: r.GatewaySlug,
		GatewayName: r.GatewayName, CapabilityKind: r.CapabilityKind, ExposedName: r.ExposedName, Title: r.CapabilityTitle}
	if g, err := s.q.GetGateway(ctx, r.GatewayID); err == nil {
		v.GatewaySlug, v.GatewayName, v.GatewayExists = g.Slug, g.Name, true
	} else if !errors.Is(store.NotFound(err), store.ErrNotFound) {
		return RequestView{}, err
	}
	return v, nil
}
