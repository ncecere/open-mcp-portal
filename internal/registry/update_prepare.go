package registry

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/ncecere/open-mcp-portal/internal/apperr"
	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/store"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

// updatePrep is what an update decided before its transaction.
type updatePrep struct {
	endpoints *[]EndpointInput // normalized outside the mutation transaction
	// mode is the auth mode after the update.
	mode string
	// provider is the server-bound provider before the update (nil: none).
	provider *dbgen.AuthProvider
	// plan is the new sign-in (nil: unchanged).
	plan *oauthPlan
	// revoked: leaving oauth, the connections were revoked (results).
	revoked map[uuid.UUID]any
	// secret is the person secret configuration after the update (nil: the
	// mode is not person_secret).
	secret *PersonSecretInput
}

// prepareUpdate runs what an update needs from the network: discovery and
// registration when the server is (or stays) in oauth mode and its URL or
// sign-in changes, and revoking connections when it leaves oauth.
func (s *Service) prepareUpdate(ctx context.Context, a authz.Actor, ref string, id uuid.UUID, in UpdateInput, expectedRevision int64) (updatePrep, error) {
	ta, err := s.authorizeUpdate(ctx, a, ref, in)
	if err != nil {
		return updatePrep{}, err
	}
	cur, err := teamServer(ctx, s.q, ta.team.ID, id, false)
	if err != nil {
		return updatePrep{}, err
	}
	if cur.Revision != expectedRevision {
		return updatePrep{}, apperr.Stale()
	}
	stored, err := loadStored(ctx, s.q, cur)
	if err != nil {
		return updatePrep{}, err
	}
	if err := checkUpdateCredentials(in, stored); err != nil {
		return updatePrep{}, err
	}
	out := updatePrep{}
	if out.mode, err = updateMode(cur, stored, in); err != nil {
		return out, err
	}
	if out.mode != AuthOAuth {
		// An oauth input without oauth mode is ignored (clients may always
		// send it with its defaults).
		in.OAuth = nil
	}
	if out.secret, err = updateSecretConfig(cur, stored, in, out.mode); err != nil {
		return out, err
	}
	if err := checkUpdateMachine(cur, in, out.mode); err != nil {
		return out, err
	}
	if out.provider, err = s.storedServerProvider(ctx, cur); err != nil {
		return out, err
	}
	newURL := cur.URL
	if in.URL != nil {
		if newURL, err = s.client.NormalizeURL(ctx, *in.URL); err != nil {
			return out, err
		}
	}
	// Refused before any network exchange with the new host (F-1); applyUpdate
	// checks again under the row lock.
	if err := requireValueForOrigin(cur, stored, newURL, in, out.mode); err != nil {
		return out, err
	}
	if out.endpoints, err = s.prepareUpdateEndpoints(ctx, ta.role, cur, newURL, in, out.mode); err != nil {
		return out, err
	}
	switch {
	case out.mode == AuthOAuth && (AuthModeOf(cur) != AuthOAuth || in.OAuth != nil || newURL != cur.URL || out.provider == nil):
		if out.plan, err = s.prepareUpdateOAuth(ctx, cur, stored, newURL, in, out.provider); err != nil {
			return out, err
		}
	case out.mode != AuthOAuth && out.provider != nil && s.oauth.Hooks != nil:
		out.revoked = s.oauth.Hooks.RevokeConnections(ctx, *out.provider)
	}
	return out, nil
}

// authorizeUpdate checks, before anything is read from the server or the
// network, that the actor may make the update: the team, the editor role, and
// the higher roles the protection limits and additional endpoints need.
func (s *Service) authorizeUpdate(ctx context.Context, a authz.Actor, ref string, in UpdateInput) (teamAccess, error) {
	if in.Endpoints != nil && a.IsToken() {
		return teamAccess{}, endpointTokenRefusal()
	}
	ta, err := access(ctx, s.q, a, ref)
	if err != nil {
		return teamAccess{}, err
	}
	if err := ta.writable(authz.CheckServerEdit); err != nil {
		return teamAccess{}, err
	}
	if err := s.checkProtection(ctx, s.q, ta.role, in.RateLimitPerMinute, in.MaxConcurrent, in.SetRateLimit || in.SetMaxConcurrent); err != nil {
		return teamAccess{}, err
	}
	if in.Endpoints != nil {
		if err := checkEndpointRole(ta.role); err != nil {
			return teamAccess{}, err
		}
	}
	return ta, nil
}

// updateMode is the auth mode after an update: the one asked for, or the
// stored one.
func updateMode(cur dbgen.McpServer, stored storedCredentials, in UpdateInput) (string, error) {
	mode := AuthModeOf(cur)
	if in.AuthMode != nil {
		switch *in.AuthMode {
		case AuthNone, AuthStaticHeader, AuthOAuth, AuthPersonSecret, AuthMachineOAuth:
			return *in.AuthMode, nil
		default:
			return mode, apperr.Invalid("invalid_auth_mode", "authMode must be none, static_header, oauth, person_secret or machine_oauth")
		}
	}
	if mode == AuthOAuth || mode == AuthPersonSecret || mode == AuthMachineOAuth {
		return mode, nil
	}
	// Without a mode, a credential added or removed decides it.
	if _, has := finalAuthorization(cur, stored, in); has {
		return AuthStaticHeader, nil
	}
	return AuthNone, nil
}

// requirementAfter reports whether the server has a user authorization
// requirement after the update.
func requirementAfter(cur dbgen.McpServer, in UpdateInput) bool {
	if in.SetRequirement {
		return in.Requirement != nil
	}
	return cur.AuthProviderID.Valid
}

// updateSecretConfig is the person secret configuration after an update
// (nil: the mode is not person_secret).
func updateSecretConfig(cur dbgen.McpServer, stored storedCredentials, in UpdateInput, mode string) (*PersonSecretInput, error) {
	if mode != AuthPersonSecret {
		return nil, nil
	}
	cfg, err := secretConfigFor(cur, in)
	if err != nil {
		return nil, err
	}
	if err := personSecretConflicts(cfg, finalViews(cur, stored, in), requirementAfter(cur, in)); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// checkUpdateMachine: a machine client carries a secret: it is refused, not
// ignored, outside machine_oauth mode, and the mode needs one the first time.
func checkUpdateMachine(cur dbgen.McpServer, in UpdateInput, mode string) error {
	if in.MachineOAuth != nil && mode != AuthMachineOAuth {
		return apperr.Invalid("invalid_machine_oauth", "machineOAuth is for authMode machine_oauth only")
	}
	if mode == AuthMachineOAuth && AuthModeOf(cur) != AuthMachineOAuth && in.MachineOAuth == nil {
		return errMachineRequired
	}
	return nil
}

// storedServerProvider is the server-bound provider of a server in oauth
// mode (nil: another mode, or none stored).
func (s *Service) storedServerProvider(ctx context.Context, cur dbgen.McpServer) (*dbgen.AuthProvider, error) {
	if AuthModeOf(cur) != AuthOAuth {
		return nil, nil
	}
	p, err := s.q.GetServerProvider(ctx, uuid.NullUUID{UUID: cur.ID, Valid: true})
	if err != nil {
		if errors.Is(store.NotFound(err), store.ErrNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &p, nil
}

// prepareUpdateEndpoints normalizes the additional endpoints against the
// server as the update would leave it (its URL, mode, requirement and TLS
// settings), outside the transaction.
func (s *Service) prepareUpdateEndpoints(ctx context.Context, role string, cur dbgen.McpServer, newURL string, in UpdateInput, mode string) (*[]EndpointInput, error) {
	curTLS, err := loadTLS(ctx, s.q, cur.ID)
	if err != nil {
		return nil, err
	}
	projectedTLS, err := s.planTLS(cur.ID, curTLS, in.TLS, !sameOrigin(cur.URL, newURL), time.Now())
	if err != nil {
		return nil, err
	}
	return s.prepareEndpointChange(ctx, s.q, cur, newURL, mode, requirementAfter(cur, in), !projectedTLS.next.empty(), role, in.Endpoints, false)
}

// prepareUpdateOAuth plans the sign-in of a server that is (or stays) in
// oauth mode: discovery and registration at newURL.
func (s *Service) prepareUpdateOAuth(ctx context.Context, cur dbgen.McpServer, stored storedCredentials, newURL string, in UpdateInput, provider *dbgen.AuthProvider) (*oauthPlan, error) {
	header, _ := finalAuthorization(cur, stored, in)
	if err := oauthConflicts(header, requirementAfter(cur, in)); err != nil {
		return nil, err
	}
	name := cur.Name
	if in.Name != nil {
		name = strings.TrimSpace(*in.Name)
	}
	return s.prepareOAuth(ctx, s.q, newURL, name, in.OAuth, provider)
}
