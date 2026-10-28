package registry

import (
	"context"
	"errors"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ncecere/open-mcp-portal/internal/apperr"
	"github.com/ncecere/open-mcp-portal/internal/audit"
	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/store"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/internal/teams"
)

// Publishing (docs/registry.md, "Publishing"): a team's owners and admins
// publish a server. Under approval_required it becomes pending until a
// platform admin approves (published, with its current capabilities
// approved) or rejects it; under self_publish it is published at once with
// its current capabilities approved. A published server's changed or new
// capabilities stay out of the catalog until approved: by a platform admin,
// or by the team's owners and admins under self_publish. Unpublishing
// makes a server private again; a platform admin's reject removes a
// published one from the catalog (rejected).

// Publish states.
const (
	StatePrivate   = "private"
	StatePending   = "pending"
	StatePublished = "published"
	StateRejected  = "rejected"
)

// F-2: an approval names what the approver saw.
var (
	errDigestRequired      = apperr.Invalid("expected_digest_required", "expectedDigest is required to approve: send the reviewDigest of the server as you reviewed it")
	errFingerprintRequired = apperr.Invalid("expected_fingerprint_required", "expectedFingerprint is required to approve: send the fingerprint of the capability as you reviewed it")
)

// changedSinceReview is a 409: what the approver reviewed isn't what is
// stored now. details has the current digest or fingerprint, so the client
// can reload; nothing was approved.
func changedSinceReview(details map[string]any) error {
	e := apperr.Conflict("changed_since_review", "This changed since you opened it. Reload and review it again.")
	e.Details = details
	return e
}

// checkDigest refuses an approval of a server whose reviewed digest isn't
// the current one (the caller holds the server's row lock).
func checkDigest(ctx context.Context, q *dbgen.Queries, sv dbgen.McpServer, expected string) error {
	cur, err := serverDigest(ctx, q, sv)
	if err != nil {
		return err
	}
	if cur != expected {
		return changedSinceReview(map[string]any{"currentDigest": cur})
	}
	return nil
}

// Review decisions.
const (
	DecisionApprove = "approve"
	DecisionReject  = "reject"
)

// PublishTransition is what publishing a server in state under policy does:
// the next state, and whether its current capabilities are approved.
func PublishTransition(state, policy string) (next string, approveAll bool, err error) {
	switch state {
	case StatePublished:
		return "", false, apperr.Conflict("already_published", "This server is already published")
	case StatePending:
		if policy != authz.PolicySelfPublish {
			return "", false, apperr.Conflict("already_pending", "This server is already waiting for a platform admin's review")
		}
	case StatePrivate, StateRejected:
	default:
		return "", false, apperr.Conflict("invalid_state", "This server can't be published from its current state")
	}
	if policy == authz.PolicySelfPublish {
		return StatePublished, true, nil
	}
	return StatePending, false, nil
}

// ReviewTransition is what a platform admin's decision does to a server in
// state: approve publishes a pending server (approving its current
// capabilities); reject sets a pending or published server rejected.
func ReviewTransition(state, decision string) (next string, approveAll bool, err error) {
	switch {
	case decision == DecisionApprove && state == StatePending:
		return StatePublished, true, nil
	case decision == DecisionReject && (state == StatePending || state == StatePublished):
		return StateRejected, false, nil
	case decision != DecisionApprove && decision != DecisionReject:
		return "", false, apperr.Invalid("invalid_decision", "decision must be approve or reject")
	}
	return "", false, apperr.Conflict("invalid_state", "Only pending servers can be approved, and only pending or published ones rejected")
}

// UnpublishTransition withdraws a request or a publication.
func UnpublishTransition(state string) (string, error) {
	switch state {
	case StatePending, StatePublished, StateRejected:
		return StatePrivate, nil
	}
	return "", apperr.Conflict("not_published", "This server is private already")
}

func checkNote(note *string) (*string, error) {
	if note == nil {
		return nil, nil
	}
	n := strings.TrimSpace(*note)
	if len([]rune(n)) > 2000 {
		return nil, errNoteTooLong
	}
	if n == "" {
		return nil, nil
	}
	return &n, nil
}

func platformDefault(ctx context.Context, q *dbgen.Queries) (string, error) {
	st, err := q.GetPlatformSettings(ctx)
	return st.PublishDefaultPolicy, err
}

// Publish publishes a server (team owners and admins). 409 not_refreshed
// when it was never read, 409 disabled when it is turned off. When
// expectedDigest is given (the reviewDigest the publisher saw) and the
// server's is another now, 409 changed_since_review and nothing happens: under
// self_publish the capabilities approved by publishing are the ones that were
// seen. Audited as mcp_server.publish_request (pending) or mcp_server.publish
// (self_publish).
func (s *Service) Publish(ctx context.Context, a authz.Actor, ref string, id uuid.UUID, note *string, expectedDigest *string) (ServerView, error) {
	note, err := checkNote(note)
	if err != nil {
		return ServerView{}, err
	}
	err = store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		ta, err := access(ctx, q, a, ref)
		if err != nil {
			return err
		}
		if err := ta.writable(authz.CheckServerManage); err != nil {
			return err
		}
		cur, err := teamServer(ctx, q, ta.team.ID, id, true)
		if err != nil {
			return err
		}
		def, err := platformDefault(ctx, q)
		if err != nil {
			return err
		}
		policy := authz.EffectivePolicy(ta.team.PublishPolicyOverride, def)
		next, approveAll, err := PublishTransition(cur.PublishState, policy)
		if err != nil {
			return err
		}
		switch {
		case !cur.Enabled:
			return apperr.Conflict("disabled", "Turn the server on before publishing it")
		case cur.RefreshedAt == nil:
			return apperr.Conflict("not_refreshed", "Read the server's capabilities (Refresh) before publishing it")
		}
		if expectedDigest != nil && *expectedDigest != "" {
			if err := checkDigest(ctx, q, cur, *expectedDigest); err != nil {
				return err
			}
		}
		row, err := q.SetMCPServerPublishState(ctx, dbgen.SetMCPServerPublishStateParams{
			ID: id, PublishState: next, Requested: true, Actor: by(a), Note: note,
		})
		if err != nil {
			return err
		}
		if next == StatePending {
			s.notifier().PublishRequested(ctx, q, id, "new", a)
		}
		var approved int64
		if approveAll {
			if approved, err = q.ApproveListedMCPCapabilities(ctx, dbgen.ApproveListedMCPCapabilitiesParams{ServerID: id, ApprovedBy: by(a)}); err != nil {
				return err
			}
		}
		action := "mcp_server.publish_request"
		if next == StatePublished {
			action = "mcp_server.publish"
		}
		e := a.Audit(action, "mcp_server", id.String())
		e.TeamID = ta.team.ID
		e.Before, e.After = map[string]any{"publishState": cur.PublishState}, map[string]any{"publishState": row.PublishState}
		e.Metadata = map[string]any{"name": cur.Name, "policy": policy, "approvedCapabilities": approved, "note": deref(note)}
		return audit.Record(ctx, q, e)
	})
	if err != nil {
		return ServerView{}, err
	}
	return s.view(ctx, s.q, id)
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// Unpublish withdraws a pending request, or removes a published (or
// rejected) server from the catalog (team owners and admins). Audited as
// mcp_server.unpublish.
func (s *Service) Unpublish(ctx context.Context, a authz.Actor, ref string, id uuid.UUID) (ServerView, error) {
	err := store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		ta, err := access(ctx, q, a, ref)
		if err != nil {
			return err
		}
		if err := ta.writable(authz.CheckServerManage); err != nil {
			return err
		}
		cur, err := teamServer(ctx, q, ta.team.ID, id, true)
		if err != nil {
			return err
		}
		next, err := UnpublishTransition(cur.PublishState)
		if err != nil {
			return err
		}
		if _, err := q.SetMCPServerPublishState(ctx, dbgen.SetMCPServerPublishStateParams{ID: id, PublishState: next, Actor: by(a)}); err != nil {
			return err
		}
		e := a.Audit("mcp_server.unpublish", "mcp_server", id.String())
		e.TeamID = ta.team.ID
		e.Before, e.After = map[string]any{"publishState": cur.PublishState}, map[string]any{"publishState": next}
		e.Metadata = map[string]any{"name": cur.Name}
		return audit.Record(ctx, q, e)
	})
	if err != nil {
		return ServerView{}, err
	}
	return s.view(ctx, s.q, id)
}

// Review approves or rejects a server (platform admins). An approval needs
// expectedDigest, the reviewDigest of the server as the admin read it (400
// expected_digest_required); when the server's is another now (a refresh, a
// new URL ...), 409 changed_since_review and nothing is approved. Rejecting
// needs no digest. Audited as mcp_server.publish (approve) or
// mcp_server.reject.
func (s *Service) Review(ctx context.Context, a authz.Actor, id uuid.UUID, decision string, note *string, expectedDigest string) (ServerView, error) {
	if !a.IsPlatformAdmin() {
		return ServerView{}, errAdminOnly
	}
	if decision == DecisionApprove && expectedDigest == "" {
		return ServerView{}, errDigestRequired
	}
	note, err := checkNote(note)
	if err != nil {
		return ServerView{}, err
	}
	err = store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		cur, err := anyServer(ctx, q, id, true)
		if err != nil {
			return err
		}
		next, approveAll, err := ReviewTransition(cur.PublishState, decision)
		if err != nil {
			return err
		}
		if approveAll {
			if err := checkDigest(ctx, q, cur, expectedDigest); err != nil {
				return err
			}
		}
		if next == StatePublished && cur.RefreshedAt == nil {
			return apperr.Conflict("not_refreshed",
				"The server's capabilities haven't been read from its current URL; refresh it before approving")
		}
		if _, err := q.SetMCPServerPublishState(ctx, dbgen.SetMCPServerPublishStateParams{
			ID: id, PublishState: next, Reviewed: true, Actor: by(a), Note: note,
		}); err != nil {
			return err
		}
		s.notifier().PublishDecided(ctx, q, id, next == StatePublished, a)
		var approved int64
		if approveAll {
			if approved, err = q.ApproveListedMCPCapabilities(ctx, dbgen.ApproveListedMCPCapabilitiesParams{ServerID: id, ApprovedBy: by(a)}); err != nil {
				return err
			}
		}
		action := "mcp_server.reject"
		if next == StatePublished {
			action = "mcp_server.publish"
		}
		e := a.Audit(action, "mcp_server", id.String())
		e.TeamID = cur.TeamID
		e.Before, e.After = map[string]any{"publishState": cur.PublishState}, map[string]any{"publishState": next}
		e.Metadata = map[string]any{"name": cur.Name, "decision": decision, "approvedCapabilities": approved, "note": deref(note)}
		if approveAll {
			e.Metadata["reviewDigest"] = expectedDigest
		}
		return audit.Record(ctx, q, e)
	})
	if err != nil {
		return ServerView{}, err
	}
	return s.view(ctx, s.q, id)
}

// ApproveTeamCapability approves a published server's unapproved
// capability (team owners and admins, only under self_publish).
// expectedFingerprint is the capability's fingerprint as the approver saw it
// (400 expected_fingerprint_required; 409 changed_since_review when it is
// another now).
func (s *Service) ApproveTeamCapability(ctx context.Context, a authz.Actor, ref string, serverID, capID uuid.UUID, expectedFingerprint string) (CapabilityView, error) {
	var out CapabilityView
	err := store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		ta, err := access(ctx, q, a, ref)
		if err != nil {
			return err
		}
		def, err := platformDefault(ctx, q)
		if err != nil {
			return err
		}
		policy := authz.EffectivePolicy(ta.team.PublishPolicyOverride, def)
		if err := ta.writable(func(role string) error { return authz.CheckCapabilityApproval(role, policy) }); err != nil {
			return err
		}
		if expectedFingerprint == "" {
			return errFingerprintRequired
		}
		sv, err := teamServer(ctx, q, ta.team.ID, serverID, true)
		if err != nil {
			return err
		}
		out, err = approve(ctx, q, a, sv, capID, policy, expectedFingerprint)
		return err
	})
	return out, err
}

// ApproveCapability approves any published server's unapproved capability
// (platform admins), bound to expectedFingerprint as ApproveTeamCapability.
func (s *Service) ApproveCapability(ctx context.Context, a authz.Actor, serverID, capID uuid.UUID, expectedFingerprint string) (CapabilityView, error) {
	if !a.IsPlatformAdmin() {
		return CapabilityView{}, errAdminOnly
	}
	if expectedFingerprint == "" {
		return CapabilityView{}, errFingerprintRequired
	}
	var out CapabilityView
	err := store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		sv, err := anyServer(ctx, q, serverID, true)
		if err != nil {
			return err
		}
		out, err = approve(ctx, q, a, sv, capID, "platform_admin", expectedFingerprint)
		return err
	})
	return out, err
}

// approve approves one capability of a locked server, if its current
// fingerprint is the one the approver saw. Audited as mcp_capability.approve.
func approve(ctx context.Context, q *dbgen.Queries, a authz.Actor, sv dbgen.McpServer, capID uuid.UUID, via, expectedFingerprint string) (CapabilityView, error) {
	cur, err := q.LockMCPCapability(ctx, dbgen.LockMCPCapabilityParams{ID: capID, ServerID: sv.ID})
	if errors.Is(store.NotFound(err), store.ErrNotFound) {
		return CapabilityView{}, errNoCapability
	} else if err != nil {
		return CapabilityView{}, err
	}
	switch {
	case cur.GoneAt != nil:
		return CapabilityView{}, apperr.Conflict("capability_gone", "The server no longer lists this capability. Refresh it first.")
	case sv.PublishState != StatePublished:
		return CapabilityView{}, apperr.Conflict("not_published",
			"Only a published server's capabilities are approved one by one; publishing approves them all")
	case cur.Fingerprint != expectedFingerprint:
		return CapabilityView{}, changedSinceReview(map[string]any{"currentFingerprint": cur.Fingerprint})
	case IsApproved(cur):
		return CapabilityView{}, apperr.Conflict("not_changed", "This capability has no unapproved change")
	}
	row, err := q.ApproveMCPCapability(ctx, dbgen.ApproveMCPCapabilityParams{ID: capID, ApprovedBy: by(a)})
	if err != nil {
		return CapabilityView{}, err
	}
	e := a.Audit("mcp_capability.approve", "mcp_capability", capID.String())
	e.TeamID = sv.TeamID
	e.Before = map[string]any{"approvedFingerprint": deref(cur.ApprovedFingerprint)}
	e.After = map[string]any{"approvedFingerprint": row.Fingerprint}
	e.Metadata = map[string]any{"serverId": sv.ID, "server": sv.Name, "kind": cur.Kind, "name": sv.Name + " · " + cur.Name,
		"capability": cur.Name, "via": via, "new": cur.ApprovedFingerprint == nil}
	if err := audit.Record(ctx, q, e); err != nil {
		return CapabilityView{}, err
	}
	name := ""
	if u, err := q.GetUser(ctx, a.UserID); err == nil {
		name = u.DisplayName
		if name == "" {
			name = u.Email
		}
	}
	return CapabilityView{Capability: row, ApprovedByName: name, Published: true}, nil
}

// Settings is the platform's default publishing policy.
type Settings = dbgen.PlatformSetting

// GetSettings returns the publishing settings (platform admins and auditors).
func (s *Service) GetSettings(ctx context.Context, a authz.Actor) (Settings, error) {
	if !a.CanReadPlatform() {
		return Settings{}, errPlatformRead
	}
	return s.q.GetPlatformSettings(ctx)
}

var errInvalidPolicy = apperr.Invalid("invalid_policy", "The policy must be approval_required or self_publish")

// UpdateSettings changes the default publishing policy (platform admins).
// Audited as settings.publishing_update.
func (s *Service) UpdateSettings(ctx context.Context, a authz.Actor, policy string, expectedRevision int64) (Settings, error) {
	if !a.IsPlatformAdmin() {
		return Settings{}, errAdminOnly
	}
	if !authz.ValidPolicy(policy) {
		return Settings{}, errInvalidPolicy
	}
	var out Settings
	err := store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		cur, err := q.LockPlatformSettings(ctx)
		if err != nil {
			return err
		}
		if cur.Revision != expectedRevision {
			return apperr.Stale()
		}
		if out, err = q.UpdatePublishDefaultPolicy(ctx, dbgen.UpdatePublishDefaultPolicyParams{Policy: policy, UpdatedBy: by(a)}); err != nil {
			return err
		}
		e := a.Audit("settings.publishing_update", "platform_settings", "publishing")
		e.Before, e.After = map[string]any{"defaultPolicy": cur.PublishDefaultPolicy}, map[string]any{"defaultPolicy": policy}
		return audit.Record(ctx, q, e)
	})
	return out, err
}

// TeamPublishing is a team's publishing policy.
type TeamPublishing struct {
	Override     *string
	Effective    string
	Default      string
	TeamRevision int64
}

func teamPublishing(ctx context.Context, q *dbgen.Queries, t dbgen.Team) (TeamPublishing, error) {
	st, err := q.GetPlatformSettings(ctx)
	if err != nil {
		return TeamPublishing{}, err
	}
	return TeamPublishing{Override: t.PublishPolicyOverride, Default: st.PublishDefaultPolicy,
		Effective: authz.EffectivePolicy(t.PublishPolicyOverride, st.PublishDefaultPolicy), TeamRevision: t.Revision}, nil
}

// GetTeamPublishing returns a team's policy (members; platform admins and
// auditors).
func (s *Service) GetTeamPublishing(ctx context.Context, a authz.Actor, ref string) (TeamPublishing, error) {
	ta, err := access(ctx, s.q, a, ref)
	if err != nil {
		return TeamPublishing{}, err
	}
	return teamPublishing(ctx, s.q, ta.team)
}

// AdminGetTeamPublishing returns any team's policy (platform admins and
// auditors).
func (s *Service) AdminGetTeamPublishing(ctx context.Context, a authz.Actor, ref string) (TeamPublishing, error) {
	if !a.CanReadPlatform() {
		return TeamPublishing{}, errPlatformRead
	}
	t, err := teams.Resolve(ctx, s.q, ref)
	if err != nil {
		return TeamPublishing{}, err
	}
	return teamPublishing(ctx, s.q, t)
}

// SetTeamOverride sets (or, with nil, clears) a team's publishing policy
// (platform admins). expectedRevision is the team's; the change bumps it.
// Audited as team.publishing_override.
func (s *Service) SetTeamOverride(ctx context.Context, a authz.Actor, ref string, override *string, expectedRevision int64) (TeamPublishing, error) {
	if !a.IsPlatformAdmin() {
		return TeamPublishing{}, errAdminOnly
	}
	if override != nil && !authz.ValidPolicy(*override) {
		return TeamPublishing{}, errInvalidPolicy
	}
	var out TeamPublishing
	err := store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		t, err := teams.Resolve(ctx, q, ref)
		if err != nil {
			return err
		}
		if t, err = q.LockTeam(ctx, t.ID); err != nil {
			return err
		}
		if t.Revision != expectedRevision {
			return apperr.Stale()
		}
		updated, err := q.SetTeamPublishOverride(ctx, dbgen.SetTeamPublishOverrideParams{ID: t.ID, Override: override})
		if err != nil {
			return err
		}
		e := a.Audit("team.publishing_override", "team", t.ID.String())
		e.TeamID = t.ID
		e.Before, e.After = map[string]any{"override": t.PublishPolicyOverride}, map[string]any{"override": override}
		e.Metadata = map[string]any{"name": t.Name}
		if err := audit.Record(ctx, q, e); err != nil {
			return err
		}
		out, err = teamPublishing(ctx, q, updated)
		return err
	})
	return out, err
}
