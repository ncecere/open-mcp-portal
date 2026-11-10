package registry

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/ncecere/open-mcp-portal/internal/apperr"
	"github.com/ncecere/open-mcp-portal/internal/audit"
	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

// updateOutcome is what a committed update leaves to do outside its
// transaction.
type updateOutcome struct {
	// moved: the URL changed, so capabilities are read again.
	moved bool
	// forgetMachine: the machine client changed or the server left
	// machine_oauth, so the cached token is dropped.
	forgetMachine bool
	// tlsChanged: the stored TLS settings changed.
	tlsChanged bool
}

// updateChange is what an update decided under the server's row lock, before
// anything is written.
type updateChange struct {
	ap applied
	// p is the row to store: ap.p with the requirement and the identity
	// switch applied.
	p dbgen.UpdateMCPServerParams
	// curTLS is the stored TLS row (nil: none); tp what the request does to it.
	curTLS *dbgen.McpServerTl
	tp     tlsPlan
	// machine is the machine client after the update (nil: not machine_oauth).
	machine *machinePlan
	ep      endpointPlan
}

func (c updateChange) machineChanged() bool { return c.machine != nil && c.machine.changed }

// credentialsChanged: a header value, the list of parts or the TLS settings
// change.
func (c updateChange) credentialsChanged() bool {
	return c.ap.valueChanged || c.ap.rewrites() || c.tp.changed()
}

// nothing reports whether the update leaves the server's settings as they
// are (governance aside, which is planned on its own).
func (c updateChange) nothing(cur dbgen.McpServer, in UpdateInput, pre updatePrep) bool {
	curProv := pre.provider
	planChanged := pre.plan != nil && (curProv == nil || !planUnchanged(*curProv, pre.plan))
	secretChanged := pre.secret != nil && !samePersonSecret(cur, *pre.secret)
	return unchanged(cur, c.p, c.credentialsChanged(), in.CapturePayloads) && !planChanged && !c.machineChanged() &&
		pre.mode == AuthModeOf(cur) && !secretChanged && !c.ep.changed
}

// updateWritten is what an update stored, for its audit entry and the review
// decision.
type updateWritten struct {
	row    dbgen.McpServer
	newTLS *dbgen.McpServerTl
	// reset is how many capability scope overrides the update removed.
	reset int64
	// before and after are the effective requirements around the update.
	before, after map[uuid.UUID]*Requirement
}

// lockServer resolves the team, checks the actor's role rule, locks the
// server's row and checks its revision: the start of a change's transaction.
func lockServer(ctx context.Context, q *dbgen.Queries, a authz.Actor, ref string, id uuid.UUID, rule func(string) error, expectedRevision int64) (teamAccess, dbgen.McpServer, error) {
	ta, err := access(ctx, q, a, ref)
	if err != nil {
		return ta, dbgen.McpServer{}, err
	}
	if err := ta.writable(rule); err != nil {
		return ta, dbgen.McpServer{}, err
	}
	cur, err := teamServer(ctx, q, ta.team.ID, id, true)
	if err != nil {
		return ta, cur, err
	}
	if cur.Revision != expectedRevision {
		return ta, cur, apperr.Stale()
	}
	return ta, cur, nil
}

// updateTx is Update's transaction: it checks authority and the revision
// again under the row lock, plans the change, stores and audits it, and
// sends the server to review again when the change calls for it.
func (s *Service) updateTx(ctx context.Context, q *dbgen.Queries, a authz.Actor, ref string, id uuid.UUID, in UpdateInput, expectedRevision int64, pre updatePrep) (updateOutcome, error) {
	ta, cur, err := lockServer(ctx, q, a, ref, id, authz.CheckServerEdit, expectedRevision)
	if err != nil {
		return updateOutcome{}, err
	}
	gp, err := planGovernance(ctx, q, a, ta.role, cur, in.Governance, s.clock())
	if err != nil {
		return updateOutcome{}, err
	}
	if err := s.checkProtection(ctx, q, ta.role, in.RateLimitPerMinute, in.MaxConcurrent, in.SetRateLimit || in.SetMaxConcurrent); err != nil {
		return updateOutcome{}, err
	}
	ch, err := s.planUpdate(ctx, q, ta, cur, in, pre)
	if err != nil {
		return updateOutcome{}, err
	}
	if ch.nothing(cur, in, pre) {
		return updateOutcome{}, s.applyGovernanceOnly(ctx, q, a, ta.team, cur, gp)
	}
	w, err := s.storeUpdate(ctx, q, a, ta, cur, in, pre, ch)
	if err != nil {
		return updateOutcome{}, err
	}
	if err := recordUpdate(ctx, q, a, ta.team.ID, cur, ch, w); err != nil {
		return updateOutcome{}, err
	}
	row := w.row
	if gp.changed {
		if row, err = s.applyGovernance(ctx, q, a, ta.team, cur, gp, false); err != nil {
			return updateOutcome{}, err
		}
	}
	authChanged, err := s.applyOAuth(ctx, q, a, cur, row, pre)
	if err != nil {
		return updateOutcome{}, err
	}
	machineReview, err := s.applyMachine(ctx, q, a, cur, row, ch.machine)
	if err != nil {
		return updateOutcome{}, err
	}
	out := updateOutcome{moved: row.URL != cur.URL, tlsChanged: ch.tp.changed(),
		forgetMachine: ch.machineChanged() || (AuthModeOf(cur) == AuthMachineOAuth && AuthModeOf(row) != AuthMachineOAuth)}
	review := updateReview{endpoints: ch.ep.review, auth: authChanged, machine: machineReview, ca: ch.tp.caChanged, raised: gp.raised}
	if err := s.resubmitUpdated(ctx, q, a, ta.team, cur, row, w, review); err != nil {
		return updateOutcome{}, err
	}
	if out.moved {
		if err := q.ClearMCPServerRefreshed(ctx, id); err != nil {
			return updateOutcome{}, err
		}
	}
	// A new address or credentials make the stored health meaningless.
	if ch.ap.valueChanged || ch.ap.rewrites() || ch.machineChanged() || ch.tp.changed() || row.URL != cur.URL || !equalPtr(row.AuthHeaderName, cur.AuthHeaderName) ||
		AuthModeOf(row) != AuthModeOf(cur) {
		return out, q.ForgetMCPHealthChecks(ctx, id)
	}
	return out, nil
}

// planUpdate works out, under the row lock, the row, credentials, TLS
// settings, machine client and additional endpoints the update leaves.
// Nothing is written.
func (s *Service) planUpdate(ctx context.Context, q *dbgen.Queries, ta teamAccess, cur dbgen.McpServer, in UpdateInput, pre updatePrep) (updateChange, error) {
	var ch updateChange
	var err error
	if ch.ap, err = s.applyUpdate(ctx, q, cur, in, pre.mode); err != nil {
		return ch, err
	}
	ch.p = ch.ap.p
	if ch.curTLS, err = loadTLS(ctx, q, cur.ID); err != nil {
		return ch, err
	}
	if ch.tp, err = s.planTLS(cur.ID, ch.curTLS, in.TLS, !sameOrigin(cur.URL, ch.p.URL), time.Now()); err != nil {
		return ch, err
	}
	if in.SetRequirement {
		if ch.p.AuthProviderID, ch.p.AuthScopes, err = checkRequirement(ctx, q, in.Requirement, cur.AuthProviderID, ta.team.ID, cur.ID); err != nil {
			return ch, err
		}
	}
	if ch.machine, err = s.planUpdateAuth(ctx, q, cur, in, pre, ch); err != nil {
		return ch, err
	}
	if in.SendIdentity != nil {
		ch.p.SendIdentity = *in.SendIdentity
	}
	storedEndpoints, err := q.ListMCPServerEndpoints(ctx, cur.ID)
	if err != nil {
		return ch, err
	}
	ch.ep, err = s.planEndpointRows(endpointServerAfter(cur, ch.p, pre.mode), storedEndpoints, !ch.tp.next.empty(), ta.role, pre.endpoints, false)
	return ch, err
}

// planUpdateAuth refuses the credential combinations the mode after the
// update excludes and, for machine_oauth, plans the machine client.
func (s *Service) planUpdateAuth(ctx context.Context, q *dbgen.Queries, cur dbgen.McpServer, in UpdateInput, pre updatePrep, ch updateChange) (*machinePlan, error) {
	p := ch.p
	if pre.mode == AuthOAuth {
		if err := oauthConflicts(firstNonEmpty(authorizationName(ch.ap.views), deref(p.AuthHeaderName)), p.AuthProviderID.Valid); err != nil {
			return nil, err
		}
	}
	if pre.secret != nil {
		if err := personSecretConflicts(*pre.secret, ch.ap.views, p.AuthProviderID.Valid); err != nil {
			return nil, err
		}
	}
	if pre.mode != AuthMachineOAuth {
		return nil, nil
	}
	if err := machineConflicts(firstNonEmpty(authorizationName(ch.ap.views), deref(p.AuthHeaderName)), p.AuthProviderID.Valid); err != nil {
		return nil, err
	}
	return s.planMachine(ctx, q, cur, p.URL, in.MachineOAuth)
}

// applyGovernanceOnly handles an update whose settings stay as they are: it
// writes nothing unless the governance changed.
func (s *Service) applyGovernanceOnly(ctx context.Context, q *dbgen.Queries, a authz.Actor, team dbgen.Team, cur dbgen.McpServer, gp govPlan) error {
	if !gp.changed {
		return nil
	}
	// Only the governance changed: it moves the revision itself.
	row, err := s.applyGovernance(ctx, q, a, team, cur, gp, true)
	if err != nil {
		return err
	}
	if gp.raised {
		return s.resubmit(ctx, q, a, team, row, "sensitivity_raised", noteSensitivityRaised)
	}
	return nil
}

// storeUpdate writes the planned change: the server's row, its person secret
// settings, credential parts, capture switch, TLS settings and endpoints, and
// the resets a new provider or origin brings.
func (s *Service) storeUpdate(ctx context.Context, q *dbgen.Queries, a authz.Actor, ta teamAccess, cur dbgen.McpServer, in UpdateInput, pre updatePrep, ch updateChange) (updateWritten, error) {
	var w updateWritten
	id := cur.ID
	ps, err := LoadProviders(ctx, q)
	if err != nil {
		return w, err
	}
	if w.before, err = effectiveAll(ctx, q, cur, ps); err != nil {
		return w, err
	}
	p := ch.p
	p.UpdatedBy = by(a)
	row, err := q.UpdateMCPServer(ctx, p)
	if err != nil {
		return w, err
	}
	// A person secret server's settings, or none for another mode. The
	// setup person is kept only while nothing resets everyone's secrets.
	reason := secretResetReason(cur, withSecretConfig(row, pre.secret))
	if row, err = q.SetMCPServerSecretConfig(ctx, secretConfigParams(id, pre.secret, reason == "")); err != nil {
		return w, err
	}
	if reason != "" {
		if err := resetPersonSecrets(ctx, q, a, ta.team.ID, id, reason, originChange(cur.URL, row.URL)); err != nil {
			return w, err
		}
	}
	if ch.ap.rewrites() {
		if err := storeCredentials(ctx, q, id, *ch.ap.plan); err != nil {
			return w, err
		}
	}
	if in.CapturePayloads != nil {
		if err := setCapture(ctx, q, ta.role, &row, *in.CapturePayloads); err != nil {
			return w, err
		}
	}
	if w.newTLS, err = storeTLS(ctx, q, id, ch.tp); err != nil {
		return w, err
	}
	if err := storeEndpoints(ctx, q, id, ch.ep); err != nil {
		return w, err
	}
	if w.reset, err = resetForUpdate(ctx, q, a, ta.team.ID, cur, row); err != nil {
		return w, err
	}
	if w.after, err = effectiveAll(ctx, q, row, ps); err != nil {
		return w, err
	}
	w.row = row
	return w, nil
}

// resetForUpdate drops what belonged to the provider or origin an update
// left behind, and returns how many scope overrides went.
func resetForUpdate(ctx context.Context, q *dbgen.Queries, a authz.Actor, teamID uuid.UUID, cur, row dbgen.McpServer) (int64, error) {
	reset := int64(0)
	if row.AuthProviderID != cur.AuthProviderID {
		// Overrides with other scopes belong to the old provider.
		var err error
		if reset, err = q.ResetMCPCapabilityScopeOverrides(ctx, row.ID); err != nil {
			return reset, err
		}
	}
	// People allowed this server to receive their provider token at the
	// origin and for the provider it had then (F-3): not for another.
	// A path-only edit keeps the grants.
	if reason := grantResetReason(cur, row); reason != "" {
		if err := resetProviderGrants(ctx, q, a, teamID, row.ID, reason, originChange(cur.URL, row.URL)); err != nil {
			return reset, err
		}
	}
	return reset, nil
}

// recordUpdate writes the mcp_server.update audit entry.
func recordUpdate(ctx context.Context, q *dbgen.Queries, a authz.Actor, teamID uuid.UUID, cur dbgen.McpServer, ch updateChange, w updateWritten) error {
	ap, tp, row := ch.ap, ch.tp, w.row
	e := a.Audit("mcp_server.update", "mcp_server", cur.ID.String())
	e.TeamID, e.Before, e.After = teamID, withEndpointAudit(withTLS(snapshot(cur, ap.before...), ch.curTLS), ch.ep.before), withEndpointAudit(withTLS(snapshot(row, ap.afterParts()...), w.newTLS), ch.ep.after)
	e.Metadata = map[string]any{"authValueChanged": ap.valueChanged}
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
	if w.reset > 0 {
		e.Metadata["overridesReset"] = w.reset
	}
	return audit.Record(ctx, q, e)
}

// updateReview is what, besides the stored rows, decides whether an update
// sends the server to review again.
type updateReview struct {
	// endpoints: the additional destinations or their credential placement
	// changed; auth, machine: the sign-in or the machine client did.
	endpoints, auth, machine bool
	// ca: the trusted CA changed; raised: the sensitivity went up.
	ca, raised bool
}

// resubmitUpdated sends an updated server to review again for the first
// reason that applies (none: it stays as it is). row is the stored row.
func (s *Service) resubmitUpdated(ctx context.Context, q *dbgen.Queries, a authz.Actor, team dbgen.Team, cur, row dbgen.McpServer, w updateWritten, r updateReview) error {
	switch {
	case row.URL != cur.URL:
		return s.resubmit(ctx, q, a, team, cur, "url_changed", "The server's URL changed; review it again.")
	case r.endpoints:
		return s.resubmit(ctx, q, a, team, cur, "endpoints_changed", "The server's additional destinations or credential placement changed; review them again.")
	case r.auth:
		return s.resubmit(ctx, q, a, team, cur, "upstream_auth_changed", noteUpstreamAuthChanged)
	case secretAuthChanged(cur, row):
		return s.resubmit(ctx, q, a, team, cur, "upstream_auth_changed", noteSecretChanged)
	case r.machine:
		return s.resubmit(ctx, q, a, team, cur, "upstream_auth_changed", noteMachineAuthChanged)
	case r.ca:
		// The CA a server is trusted against is a trust setting; a new client
		// certificate is not (decision 74).
		return s.resubmit(ctx, q, a, team, cur, "upstream_tls_changed", noteUpstreamTLSChanged)
	case widened(w.before, w.after):
		return s.resubmit(ctx, q, a, team, cur, "requirement_changed", noteRequirementChanged)
	case r.raised:
		return s.resubmit(ctx, q, a, team, cur, "sensitivity_raised", noteSensitivityRaised)
	}
	return nil
}
