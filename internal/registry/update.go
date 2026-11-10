package registry

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ncecere/open-mcp-portal/internal/apperr"
	"github.com/ncecere/open-mcp-portal/internal/audit"
	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/store"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

// UpdateInput holds optional changes. AuthHeaderName "" removes the header
// and its value; AuthValue nil keeps the stored value. Credentials (nil keeps
// them) is the server's whole list of parts: each part keeps its stored values
// (Keep) or has new ones, and a part left out is removed; it replaces the
// single header, and a server that has several parts can't be changed with
// AuthHeaderName and AuthValue.
type UpdateInput struct {
	Name, Description, URL         *string
	AuthHeaderName, AuthValue      *string
	Credentials                    *[]CredentialInput
	Endpoints                      *[]EndpointInput // nil keeps, empty clears; null rejected by HTTP
	TimeoutSeconds                 *int32
	SetRateLimit, SetMaxConcurrent bool
	RateLimitPerMinute             *int64
	MaxConcurrent                  *int32
	Enabled                        *bool
	// SetRequirement changes the requirement to Requirement (nil removes
	// it); false keeps it.
	SetRequirement bool
	Requirement    *RequirementInput
	// CapturePayloads changes the capture switch (nil keeps it; only team
	// owners and admins may change it).
	CapturePayloads *bool
	// AuthMode changes the upstream auth mode (nil keeps it); OAuth changes
	// the sign-in (fields nil keep their values).
	AuthMode *string
	OAuth    *OAuthInput
	// MachineOAuth changes the machine client (fields nil keep their values;
	// a new token endpoint, client or server origin needs the secret again).
	MachineOAuth *MachineOAuthInput
	// SendIdentity changes whether the identity token is sent (nil keeps it).
	SendIdentity *bool
	// PersonSecret changes how each person's own secret is sent (nil keeps
	// it; only for a server in person_secret mode, which it is required for
	// when the mode is being chosen).
	PersonSecret *PersonSecretInput
	// TLS changes the server's CA bundle and client certificate (nil keeps
	// them; see TLSInput).
	TLS *TLSInput
	// Governance changes the server's owner, on-call contact, sensitivity,
	// lifecycle and replacement (nil keeps them; team owners and admins in a
	// browser session only, decision 88).
	Governance *GovernanceInput
}

// Update changes a server's settings (team editors and above); the slug
// never changes. A new URL or header forgets the stored health. A new URL
// also forgets when capabilities were read and reads them again from the new
// endpoint, so nothing is approved on the strength of the old one. A URL with
// another origin never keeps the stored header value (422 auth_value_required
// unless a new value comes with it, or the header goes). Audited as
// mcp_server.update with whether the header value changed (never the value)
// and, for another origin, the old and new one.
// A request that changes nothing (for example the capture switch resent at its
// current value) writes nothing: no revision bump and no audit entry, as a
// member role change to the same role.
func (s *Service) Update(ctx context.Context, a authz.Actor, ref string, id uuid.UUID, in UpdateInput, expectedRevision int64) (ServerView, error) {
	if in.Governance != nil && a.IsToken() {
		return ServerView{}, errGovernanceToken
	}
	// Upstream OAuth changes need the network (discovery, registration,
	// revocation): that happens first, against the server as read now; the
	// transaction then checks the revision again.
	pre, err := s.prepareUpdate(ctx, a, ref, id, in, expectedRevision)
	if err != nil {
		return ServerView{}, err
	}
	var moved, forgetMachine, tlsChanged bool
	err = store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		ta, err := access(ctx, q, a, ref)
		if err != nil {
			return err
		}
		if err := ta.writable(authz.CheckServerEdit); err != nil {
			return err
		}
		cur, err := teamServer(ctx, q, ta.team.ID, id, true)
		if err != nil {
			return err
		}
		if cur.Revision != expectedRevision {
			return apperr.Stale()
		}
		gp, err := planGovernance(ctx, q, a, ta.role, cur, in.Governance, s.clock())
		if err != nil {
			return err
		}
		if err := s.checkProtection(ctx, q, ta.role, in.RateLimitPerMinute, in.MaxConcurrent, in.SetRateLimit || in.SetMaxConcurrent); err != nil {
			return err
		}
		ap, err := s.applyUpdate(ctx, q, cur, in, pre.mode)
		if err != nil {
			return err
		}
		p, valueChanged := ap.p, ap.valueChanged
		curTLS, err := loadTLS(ctx, q, id)
		if err != nil {
			return err
		}
		tp, err := s.planTLS(id, curTLS, in.TLS, !sameOrigin(cur.URL, p.URL), time.Now())
		if err != nil {
			return err
		}
		if in.SetRequirement {
			if p.AuthProviderID, p.AuthScopes, err = checkRequirement(ctx, q, in.Requirement, cur.AuthProviderID, ta.team.ID, cur.ID); err != nil {
				return err
			}
		}
		if pre.mode == AuthOAuth {
			if err := oauthConflicts(firstNonEmpty(authorizationName(ap.views), deref(p.AuthHeaderName)), p.AuthProviderID.Valid); err != nil {
				return err
			}
		}
		if pre.secret != nil {
			if err := personSecretConflicts(*pre.secret, ap.views, p.AuthProviderID.Valid); err != nil {
				return err
			}
		}
		var machine *machinePlan
		if pre.mode == AuthMachineOAuth {
			if err := machineConflicts(firstNonEmpty(authorizationName(ap.views), deref(p.AuthHeaderName)), p.AuthProviderID.Valid); err != nil {
				return err
			}
			if machine, err = s.planMachine(ctx, q, cur, p.URL, in.MachineOAuth); err != nil {
				return err
			}
		}
		if in.SendIdentity != nil {
			p.SendIdentity = *in.SendIdentity
		}
		storedEndpoints, err := q.ListMCPServerEndpoints(ctx, id)
		if err != nil {
			return err
		}
		ep, err := s.planEndpointRows(endpointServerAfter(cur, p, pre.mode), storedEndpoints, !tp.next.empty(), ta.role, pre.endpoints, false)
		if err != nil {
			return err
		}
		curProv := pre.provider
		planChanged := pre.plan != nil && (curProv == nil || !planUnchanged(*curProv, pre.plan))
		secretChanged := pre.secret != nil && !samePersonSecret(cur, *pre.secret)
		machineChanged := machine != nil && machine.changed
		if unchanged(cur, p, valueChanged || ap.rewrites() || tp.changed(), in.CapturePayloads) && !planChanged && !machineChanged && pre.mode == AuthModeOf(cur) && !secretChanged && !ep.changed {
			if !gp.changed {
				return nil
			}
			// Only the governance changed: it moves the revision itself.
			row, err := s.applyGovernance(ctx, q, a, ta.team, cur, gp, true)
			if err != nil {
				return err
			}
			if gp.raised {
				return s.resubmit(ctx, q, a, ta.team, row, "sensitivity_raised", noteSensitivityRaised)
			}
			return nil
		}
		ps, err := LoadProviders(ctx, q)
		if err != nil {
			return err
		}
		before, err := effectiveAll(ctx, q, cur, ps)
		if err != nil {
			return err
		}
		p.UpdatedBy = by(a)
		row, err := q.UpdateMCPServer(ctx, p)
		if err != nil {
			return err
		}
		// A person secret server's settings, or none for another mode. The
		// setup person is kept only while nothing resets everyone's secrets.
		reason := secretResetReason(cur, withSecretConfig(row, pre.secret))
		if row, err = q.SetMCPServerSecretConfig(ctx, secretConfigParams(id, pre.secret, reason == "")); err != nil {
			return err
		}
		if reason != "" {
			if err := resetPersonSecrets(ctx, q, a, ta.team.ID, id, reason, originChange(cur.URL, row.URL)); err != nil {
				return err
			}
		}
		if ap.rewrites() {
			if err := storeCredentials(ctx, q, id, *ap.plan); err != nil {
				return err
			}
		}
		if in.CapturePayloads != nil {
			if err := setCapture(ctx, q, ta.role, &row, *in.CapturePayloads); err != nil {
				return err
			}
		}
		newTLS, err := storeTLS(ctx, q, id, tp)
		if err != nil {
			return err
		}
		tlsChanged = tp.changed()
		if err := storeEndpoints(ctx, q, id, ep); err != nil {
			return err
		}
		reset := int64(0)
		if row.AuthProviderID != cur.AuthProviderID {
			// Overrides with other scopes belong to the old provider.
			if reset, err = q.ResetMCPCapabilityScopeOverrides(ctx, id); err != nil {
				return err
			}
		}
		// People allowed this server to receive their provider token at the
		// origin and for the provider it had then (F-3): not for another.
		// A path-only edit keeps the grants.
		if reason := grantResetReason(cur, row); reason != "" {
			if err := resetProviderGrants(ctx, q, a, ta.team.ID, id, reason, originChange(cur.URL, row.URL)); err != nil {
				return err
			}
		}
		after, err := effectiveAll(ctx, q, row, ps)
		if err != nil {
			return err
		}
		e := a.Audit("mcp_server.update", "mcp_server", id.String())
		e.TeamID, e.Before, e.After = ta.team.ID, withEndpointAudit(withTLS(snapshot(cur, ap.before...), curTLS), ep.before), withEndpointAudit(withTLS(snapshot(row, ap.afterParts()...), newTLS), ep.after)
		e.Metadata = map[string]any{"authValueChanged": valueChanged}
		if tp.changed() {
			// Which part changed and whether the origin dropped the old settings;
			// the fingerprints are in the snapshots. Never a key, a ciphertext or a PEM.
			e.Metadata["tlsCaChanged"], e.Metadata["tlsClientCertChanged"] = tp.caChanged, tp.clientChanged
			if tp.droppedCA || tp.droppedClient {
				e.Metadata["tlsDroppedForOrigin"] = true
			}
		}
		for k, v := range originChange(cur.URL, row.URL) {
			e.Metadata[k] = v
		}
		if reset > 0 {
			e.Metadata["overridesReset"] = reset
		}
		if err := audit.Record(ctx, q, e); err != nil {
			return err
		}
		if gp.changed {
			if row, err = s.applyGovernance(ctx, q, a, ta.team, cur, gp, false); err != nil {
				return err
			}
		}
		authChanged, err := s.applyOAuth(ctx, q, a, cur, row, pre)
		if err != nil {
			return err
		}
		machineReview, err := s.applyMachine(ctx, q, a, cur, row, machine)
		if err != nil {
			return err
		}
		forgetMachine = machineChanged || (AuthModeOf(cur) == AuthMachineOAuth && AuthModeOf(row) != AuthMachineOAuth)
		switch {
		case row.URL != cur.URL:
			err = s.resubmit(ctx, q, a, ta.team, cur, "url_changed", "The server's URL changed; review it again.")
		case ep.review:
			err = s.resubmit(ctx, q, a, ta.team, cur, "endpoints_changed", "The server's additional destinations or credential placement changed; review them again.")
		case authChanged:
			err = s.resubmit(ctx, q, a, ta.team, cur, "upstream_auth_changed", noteUpstreamAuthChanged)
		case secretAuthChanged(cur, row):
			err = s.resubmit(ctx, q, a, ta.team, cur, "upstream_auth_changed", noteSecretChanged)
		case machineReview:
			err = s.resubmit(ctx, q, a, ta.team, cur, "upstream_auth_changed", noteMachineAuthChanged)
		case tp.caChanged:
			// The CA a server is trusted against is a trust setting; a new client
			// certificate is not (decision 74).
			err = s.resubmit(ctx, q, a, ta.team, cur, "upstream_tls_changed", noteUpstreamTLSChanged)
		case widened(before, after):
			err = s.resubmit(ctx, q, a, ta.team, cur, "requirement_changed", noteRequirementChanged)
		case gp.raised:
			err = s.resubmit(ctx, q, a, ta.team, cur, "sensitivity_raised", noteSensitivityRaised)
		}
		if err != nil {
			return err
		}
		if moved = row.URL != cur.URL; moved {
			if err := q.ClearMCPServerRefreshed(ctx, id); err != nil {
				return err
			}
		}
		// A new address or credentials make the stored health meaningless.
		if valueChanged || ap.rewrites() || machineChanged || tp.changed() || row.URL != cur.URL || !equalPtr(row.AuthHeaderName, cur.AuthHeaderName) ||
			AuthModeOf(row) != AuthModeOf(cur) {
			return q.ForgetMCPHealthChecks(ctx, id)
		}
		return nil
	})
	if err != nil {
		return ServerView{}, err
	}
	// A new client, secret or endpoint never reuses the token fetched for the
	// old one (the cache key covers it; this frees it at once), and a server
	// that left machine_oauth keeps none.
	if forgetMachine {
		s.machine.Forget(id.String())
	}
	if moved || tlsChanged {
		// Best effort, like Create: a failure is stored as the refresh error.
		sv, err := s.q.GetMCPServer(ctx, id)
		if err != nil {
			return ServerView{}, err
		}
		if sv.Enabled {
			if _, _, err := s.refresh(ctx, a, sv); err != nil {
				return ServerView{}, err
			}
		}
	}
	return s.view(ctx, s.q, id)
}

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
	if in.Endpoints != nil && a.IsToken() {
		return updatePrep{}, endpointTokenRefusal()
	}
	ta, err := access(ctx, s.q, a, ref)
	if err != nil {
		return updatePrep{}, err
	}
	if err := ta.writable(authz.CheckServerEdit); err != nil {
		return updatePrep{}, err
	}
	if err := s.checkProtection(ctx, s.q, ta.role, in.RateLimitPerMinute, in.MaxConcurrent, in.SetRateLimit || in.SetMaxConcurrent); err != nil {
		return updatePrep{}, err
	}
	if in.Endpoints != nil {
		if err := checkEndpointRole(ta.role); err != nil {
			return updatePrep{}, err
		}
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
	out := updatePrep{mode: AuthModeOf(cur)}
	if in.AuthMode != nil {
		switch *in.AuthMode {
		case AuthNone, AuthStaticHeader, AuthOAuth, AuthPersonSecret, AuthMachineOAuth:
			out.mode = *in.AuthMode
		default:
			return out, apperr.Invalid("invalid_auth_mode", "authMode must be none, static_header, oauth, person_secret or machine_oauth")
		}
	} else if out.mode != AuthOAuth && out.mode != AuthPersonSecret && out.mode != AuthMachineOAuth {
		// Without a mode, a credential added or removed decides it.
		out.mode = AuthNone
		if _, has := finalAuthorization(cur, stored, in); has {
			out.mode = AuthStaticHeader
		}
	}
	if out.mode != AuthOAuth {
		// An oauth input without oauth mode is ignored (clients may always
		// send it with its defaults).
		in.OAuth = nil
	}
	if out.mode == AuthPersonSecret {
		cfg, err := secretConfigFor(cur, in)
		if err != nil {
			return out, err
		}
		requirement := cur.AuthProviderID.Valid
		if in.SetRequirement {
			requirement = in.Requirement != nil
		}
		if err := personSecretConflicts(cfg, finalViews(cur, stored, in), requirement); err != nil {
			return out, err
		}
		out.secret = &cfg
	}
	// A machine client carries a secret: it is refused, not ignored, outside
	// machine_oauth mode, and the mode needs one the first time.
	if in.MachineOAuth != nil && out.mode != AuthMachineOAuth {
		return out, apperr.Invalid("invalid_machine_oauth", "machineOAuth is for authMode machine_oauth only")
	}
	if out.mode == AuthMachineOAuth && AuthModeOf(cur) != AuthMachineOAuth && in.MachineOAuth == nil {
		return out, errMachineRequired
	}
	if AuthModeOf(cur) == AuthOAuth {
		p, err := s.q.GetServerProvider(ctx, uuid.NullUUID{UUID: id, Valid: true})
		if err != nil && !errors.Is(store.NotFound(err), store.ErrNotFound) {
			return out, err
		} else if err == nil {
			out.provider = &p
		}
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
	curTLS, err := loadTLS(ctx, s.q, id)
	if err != nil {
		return out, err
	}
	projectedTLS, err := s.planTLS(id, curTLS, in.TLS, !sameOrigin(cur.URL, newURL), time.Now())
	if err != nil {
		return out, err
	}
	requirement := cur.AuthProviderID.Valid
	if in.SetRequirement {
		requirement = in.Requirement != nil
	}
	out.endpoints, err = s.prepareEndpointChange(ctx, s.q, cur, newURL, out.mode, requirement, !projectedTLS.next.empty(), ta.role, in.Endpoints, false)
	if err != nil {
		return out, err
	}
	switch {
	case out.mode == AuthOAuth && (AuthModeOf(cur) != AuthOAuth || in.OAuth != nil || newURL != cur.URL || out.provider == nil):
		header, _ := finalAuthorization(cur, stored, in)
		requirement := cur.AuthProviderID.Valid
		if in.SetRequirement {
			requirement = in.Requirement != nil
		}
		if err := oauthConflicts(header, requirement); err != nil {
			return out, err
		}
		name := cur.Name
		if in.Name != nil {
			name = strings.TrimSpace(*in.Name)
		}
		if out.plan, err = s.prepareOAuth(ctx, s.q, newURL, name, in.OAuth, out.provider); err != nil {
			return out, err
		}
	case out.mode != AuthOAuth && out.provider != nil && s.oauth.Hooks != nil:
		out.revoked = s.oauth.Hooks.RevokeConnections(ctx, *out.provider)
	}
	return out, nil
}
