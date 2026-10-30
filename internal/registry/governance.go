package registry

import (
	"context"
	"errors"
	"net/mail"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ncecere/open-mcp-portal/internal/apperr"
	"github.com/ncecere/open-mcp-portal/internal/audit"
	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/store"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

// Server governance (decision 88, docs/registry.md "Governance"): who is
// accountable for a server, whom to page, how sensitive it is, when it is
// re-reviewed and whether it is being retired. Owner, on-call contact and
// dates are bookkeeping; the sensitivity (against a gateway's ceiling) and the
// lifecycle (a sunset stops serving) decide whether a capability is served,
// so they are authority inputs and are in the review digest.

// Sensitivity labels, lowest first (mcp_servers.sensitivity and
// gateways.max_sensitivity).
const (
	SensitivityPublic       = "public"
	SensitivityInternal     = "internal"
	SensitivityConfidential = "confidential"
	SensitivityRestricted   = "restricted"
)

// Sensitivities lists the labels from the least to the most sensitive.
var Sensitivities = []string{SensitivityPublic, SensitivityInternal, SensitivityConfidential, SensitivityRestricted}

// SensitivityRank orders the labels (public 0 .. restricted 3); ok is false
// for anything else, which callers treat as above every ceiling.
func SensitivityRank(s string) (rank int, ok bool) {
	for i, l := range Sensitivities {
		if l == s {
			return i, true
		}
	}
	return 0, false
}

// ValidSensitivity reports whether s is a label.
func ValidSensitivity(s string) bool { _, ok := SensitivityRank(s); return ok }

// ExceedsCeiling reports whether a server of sensitivity is above a gateway's
// ceiling. A label that is not one fails closed: above any ceiling, and a
// ceiling that is not a label is below any server. The empty string is the
// column's default (a server's internal, a ceiling's restricted), which the
// database never stores empty but a row built by hand may be.
func ExceedsCeiling(sensitivity, ceiling string) bool {
	if sensitivity == "" {
		sensitivity = SensitivityInternal
	}
	if ceiling == "" {
		ceiling = SensitivityRestricted
	}
	r, ok := SensitivityRank(sensitivity)
	c, cok := SensitivityRank(ceiling)
	return !ok || !cok || r > c
}

// Lifecycle states (mcp_servers.lifecycle).
const (
	LifecycleActive     = "active"
	LifecycleDeprecated = "deprecated"
	LifecycleSunset     = "sunset"
)

// SunsetReached reports whether a server is past its sunset: its lifecycle is
// sunset, or its sunset date has passed. It is the rule gateway availability
// uses (reason sunset) and what GatewayStats and the approval check mirror.
func SunsetReached(sv dbgen.McpServer, now time.Time) bool {
	return sv.Lifecycle == LifecycleSunset || (sv.SunsetAt != nil && !sv.SunsetAt.After(now))
}

// EffectiveLifecycle is the lifecycle as it is now: a deprecated server whose
// sunset date has passed is sunset even before anyone edits it.
func EffectiveLifecycle(sv dbgen.McpServer, now time.Time) string {
	if sv.Lifecycle != LifecycleActive && SunsetReached(sv, now) {
		return LifecycleSunset
	}
	return sv.Lifecycle
}

// ownerEligible reports whether a person may own a server of the team: active,
// and an editor or above of it.
func ownerEligible(ctx context.Context, q *dbgen.Queries, teamID, userID uuid.UUID) (bool, error) {
	return q.GovernanceOwnerEligible(ctx, dbgen.GovernanceOwnerEligibleParams{TeamID: teamID, UserID: userID})
}

// GovernanceInput is a change of a server's governance. Set* say that the
// field was sent (a nil value then clears it); omitted fields keep their
// values. Only a person who owns or administers the server's team may send it,
// never an automation token. Sending Sensitivity, even the label the server
// already has, is how a team confirms it (mcp_servers.sensitivity_confirmed_at);
// nothing else does.
type GovernanceInput struct {
	SetOwner            bool
	OwnerUserID         *uuid.UUID
	SetOncall           bool
	OncallContact       *string
	Sensitivity         *string
	Lifecycle           *string
	SetSunsetAt         bool
	SunsetAt            *time.Time
	SetReplacement      bool
	ReplacementServerID *uuid.UUID
}

var (
	errGovernanceToken = tokenRefusal("governance")
	errInvalidOwner    = apperr.New(422, "invalid_owner", "The owner must be an active person who is an editor, admin or owner of the server's team")
	errInvalidSens     = apperr.Invalid("invalid_sensitivity", "sensitivity must be public, internal, confidential or restricted")
	errInvalidLife     = apperr.Invalid("invalid_lifecycle", "lifecycle must be active, deprecated or sunset")
	errInvalidOncall   = apperr.New(422, "invalid_oncall_contact", "The on-call contact is an email address, an http(s) or tel link, or a channel such as #oncall or @team, at most 200 characters")
	errSunsetPast      = apperr.New(422, "sunset_in_past", "Choose a sunset date in the future, or clear it; the server stops being served at that date")
	errNeedsLifecycle  = apperr.New(422, "lifecycle_active", "A sunset date or a replacement belongs to a deprecated or sunset server: deprecate it first")
	errSunsetRequired  = apperr.New(422, "sunset_required", "A sunset server has a sunset date; clear nothing here or choose another lifecycle")
	errInvalidReplace  = apperr.New(422, "invalid_replacement", "The replacement must be another server that is published (or of this team), not itself retired and not pointing back at this one")
)

// tokenRefusal is the 403 an automation token gets for a field it may never
// change (the same shape as the HTTP layer's refusal: details.field).
func tokenRefusal(field string) *apperr.Error {
	e := apperr.New(403, "token_not_allowed", "An automation token can't change "+field+" of this server: sign in to do it")
	e.Details = map[string]any{"field": field}
	return e
}

var (
	channelRE = regexp.MustCompile(`^[#@][A-Za-z0-9][A-Za-z0-9._-]{0,80}$`)
	telRE     = regexp.MustCompile(`^tel:\+?[0-9()-]{3,30}$`)
)

// NormalizeOncall checks an on-call contact (an email address, an http or
// https link, a tel: number, or a channel such as #oncall or @team) and returns
// it trimmed; empty clears it (nil). No other scheme is accepted, because the
// contact may be shown as a link.
func NormalizeOncall(in string) (*string, error) {
	v := strings.TrimSpace(in)
	if v == "" {
		return nil, nil
	}
	if utf8.RuneCountInString(v) > 200 || strings.ContainsFunc(v, func(r rune) bool { return unicode.IsControl(r) || unicode.IsSpace(r) }) {
		return nil, errInvalidOncall
	}
	switch {
	case channelRE.MatchString(v), telRE.MatchString(v):
	case strings.Contains(v, "://"):
		u, err := url.Parse(v)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
			return nil, errInvalidOncall
		}
	default:
		a, err := mail.ParseAddress(v)
		if err != nil || a.Name != "" || a.Address != v || !strings.Contains(v[strings.LastIndex(v, "@"):], ".") {
			return nil, errInvalidOncall
		}
	}
	return &v, nil
}

// govPlan is a validated governance change of one server.
type govPlan struct {
	after dbgen.McpServer
	// changed: anything differs (including a first confirmation); raised: the
	// sensitivity went up; sensitivityChanged: either way; deprecated: the server
	// just left active.
	changed, raised, sensitivityChanged, deprecated bool
	ownerChanged, lifecycleChanged                  bool
	// confirm: this request sends a sensitivity and the label was not yet
	// confirmed. Bookkeeping: it moves the revision and is audited like any
	// governance change, but is not an authority input.
	confirm bool
}

// planGovernance validates in against cur (the locked row) for a person with
// role and returns the row as it would be. Nothing is written.
func planGovernance(ctx context.Context, q *dbgen.Queries, a authz.Actor, role string, cur dbgen.McpServer, in *GovernanceInput, now time.Time) (govPlan, error) {
	p := govPlan{after: cur}
	if in == nil {
		return p, nil
	}
	if a.IsToken() {
		return p, errGovernanceToken
	}
	if err := authz.CheckServerGovernance(role); err != nil {
		return p, err
	}
	next := &p.after
	if in.SetOwner {
		if in.OwnerUserID == nil {
			next.OwnerUserID = uuid.NullUUID{}
		} else if !(cur.OwnerUserID.Valid && cur.OwnerUserID.UUID == *in.OwnerUserID) {
			ok, err := ownerEligible(ctx, q, cur.TeamID, *in.OwnerUserID)
			if err != nil {
				return p, err
			}
			if !ok {
				return p, errInvalidOwner
			}
			next.OwnerUserID = uuid.NullUUID{UUID: *in.OwnerUserID, Valid: true}
		}
		p.ownerChanged = next.OwnerUserID != cur.OwnerUserID
	}
	if in.SetOncall {
		v := ""
		if in.OncallContact != nil {
			v = *in.OncallContact
		}
		var err error
		if next.OncallContact, err = NormalizeOncall(v); err != nil {
			return p, err
		}
	}
	if in.Sensitivity != nil {
		if !ValidSensitivity(*in.Sensitivity) {
			return p, errInvalidSens
		}
		next.Sensitivity = *in.Sensitivity
		curRank, _ := SensitivityRank(cur.Sensitivity)
		newRank, _ := SensitivityRank(next.Sensitivity)
		p.raised, p.sensitivityChanged = newRank > curRank, newRank != curRank
		// An explicit label confirms it, even the one it already has. Nothing
		// else does: no other field, no other edit, no inference.
		p.confirm = cur.SensitivityConfirmedAt == nil
	}
	if err := planLifecycle(ctx, q, cur, next, in, now); err != nil {
		return p, err
	}
	p.lifecycleChanged = next.Lifecycle != cur.Lifecycle
	p.deprecated = cur.Lifecycle == LifecycleActive && next.Lifecycle != LifecycleActive
	p.changed = p.confirm || p.ownerChanged || !equalPtr(next.OncallContact, cur.OncallContact) || next.Sensitivity != cur.Sensitivity ||
		next.Lifecycle != cur.Lifecycle || !equalTime(next.DeprecatedAt, cur.DeprecatedAt) || !equalTime(next.SunsetAt, cur.SunsetAt) ||
		next.ReplacementServerID != cur.ReplacementServerID
	return p, nil
}

func equalTime(a, b *time.Time) bool { return (a == nil) == (b == nil) && (a == nil || a.Equal(*b)) }

// planLifecycle applies the lifecycle, sunset date and replacement of in to
// next (a copy of cur). A deprecated server's sunset date must be in the
// future when it is set; the server stops being served at that date.
func planLifecycle(ctx context.Context, q *dbgen.Queries, cur dbgen.McpServer, next *dbgen.McpServer, in *GovernanceInput, now time.Time) error {
	if in.Lifecycle == nil && !in.SetSunsetAt && !in.SetReplacement {
		return nil
	}
	target := cur.Lifecycle
	if in.Lifecycle != nil {
		switch *in.Lifecycle {
		case LifecycleActive, LifecycleDeprecated, LifecycleSunset:
			target = *in.Lifecycle
		default:
			return errInvalidLife
		}
	}
	if target == LifecycleActive {
		if (in.SetSunsetAt && in.SunsetAt != nil) || (in.SetReplacement && in.ReplacementServerID != nil) {
			return errNeedsLifecycle
		}
		next.Lifecycle, next.DeprecatedAt, next.SunsetAt, next.ReplacementServerID = LifecycleActive, nil, nil, uuid.NullUUID{}
		return nil
	}
	if cur.Lifecycle == LifecycleActive && in.Lifecycle == nil {
		if (in.SetSunsetAt && in.SunsetAt != nil) || (in.SetReplacement && in.ReplacementServerID != nil) {
			return errNeedsLifecycle
		}
		return nil // clearing what is not set
	}
	next.Lifecycle = target
	if next.DeprecatedAt == nil {
		next.DeprecatedAt = &now
	}
	sunset := cur.SunsetAt
	if in.SetSunsetAt {
		sunset = in.SunsetAt
	} else if cur.Lifecycle == LifecycleSunset && target == LifecycleDeprecated {
		sunset = nil // coming back from a sunset: no date unless one is sent
	}
	switch target {
	case LifecycleDeprecated:
		// A date the request sends must lie ahead; a stored one that has
		// passed since (a derived sunset) is only refused when it is sent again.
		if in.SetSunsetAt && sunset != nil && !sunset.After(now) {
			return errSunsetPast
		}
	case LifecycleSunset:
		if sunset == nil {
			if in.SetSunsetAt {
				return errSunsetRequired
			}
			sunset = &now // sunset now
		}
	}
	next.SunsetAt = sunset
	if in.SetReplacement {
		if in.ReplacementServerID == nil {
			next.ReplacementServerID = uuid.NullUUID{}
		} else if err := checkReplacement(ctx, q, cur, *in.ReplacementServerID); err != nil {
			return err
		} else {
			next.ReplacementServerID = uuid.NullUUID{UUID: *in.ReplacementServerID, Valid: true}
		}
	}
	return nil
}

// maxReplacementChain bounds the walk that refuses a cycle of replacements.
const maxReplacementChain = 8

// checkReplacement: the replacement exists, is another server, is published
// (or of the same team, so a team can name its own private successor), is not
// sunset itself and does not lead back to the server.
func checkReplacement(ctx context.Context, q *dbgen.Queries, cur dbgen.McpServer, id uuid.UUID) error {
	if id == cur.ID {
		return errInvalidReplace
	}
	seen := id
	for i := 0; i < maxReplacementChain; i++ {
		r, err := q.GovernanceReplacement(ctx, seen)
		if err != nil {
			if errors.Is(store.NotFound(err), store.ErrNotFound) {
				return errInvalidReplace
			}
			return err
		}
		if i == 0 && ((r.PublishState != StatePublished && r.TeamID != cur.TeamID) || r.Lifecycle == LifecycleSunset) {
			return errInvalidReplace
		}
		if !r.ReplacementServerID.Valid {
			return nil
		}
		if r.ReplacementServerID.UUID == cur.ID {
			return errInvalidReplace
		}
		seen = r.ReplacementServerID.UUID
	}
	return errInvalidReplace
}

// governanceSnapshot is the audited governance of a server (the contact is
// the person's own choice to publish; no secret is in any of it).
func governanceSnapshot(sv dbgen.McpServer) map[string]any {
	out := map[string]any{"sensitivity": sv.Sensitivity, "sensitivityConfirmed": sv.SensitivityConfirmedAt != nil, "lifecycle": sv.Lifecycle, "oncallContact": sv.OncallContact}
	if sv.OwnerUserID.Valid {
		out["ownerUserId"] = sv.OwnerUserID.UUID.String()
	}
	if sv.DeprecatedAt != nil {
		out["deprecatedAt"] = sv.DeprecatedAt.UTC()
	}
	if sv.SunsetAt != nil {
		out["sunsetAt"] = sv.SunsetAt.UTC()
	}
	if sv.ReplacementServerID.Valid {
		out["replacementServerId"] = sv.ReplacementServerID.UUID.String()
	}
	return out
}

const noteSensitivityRaised = "The server's sensitivity was raised; review it again."

// applyGovernance writes a validated plan to the server (bump: it is the only
// change of the request, so its revision moves), recomputes the re-review
// date, audits mcp_server.governance_update in the same transaction and, when
// the server just left active, tells the owners of the gateways that select
// it. It returns the stored row. Under approval_required a published server
// whose sensitivity went up is sent back to review by the caller's switch.
func (s *Service) applyGovernance(ctx context.Context, q *dbgen.Queries, a authz.Actor, team dbgen.Team, cur dbgen.McpServer, p govPlan, bump bool) (dbgen.McpServer, error) {
	n := p.after
	row, err := q.SetMCPServerGovernance(ctx, dbgen.SetMCPServerGovernanceParams{
		ID: cur.ID, OwnerUserID: n.OwnerUserID, OncallContact: n.OncallContact, Sensitivity: n.Sensitivity, Lifecycle: n.Lifecycle,
		DeprecatedAt: n.DeprecatedAt, SunsetAt: n.SunsetAt, ReplacementServerID: n.ReplacementServerID, Bump: bump, UpdatedBy: by(a),
		ConfirmSensitivity: p.confirm,
	})
	if err != nil {
		return row, err
	}
	if p.sensitivityChanged {
		if _, err := q.RecomputeMCPServerReviewDue(ctx, uuid.NullUUID{UUID: cur.ID, Valid: true}); err != nil {
			return row, err
		}
	}
	e := a.Audit("mcp_server.governance_update", "mcp_server", cur.ID.String())
	e.TeamID = team.ID
	e.Before, e.After = governanceSnapshot(cur), governanceSnapshot(row)
	e.Metadata = map[string]any{"name": cur.Name, "sensitivityRaised": p.raised, "sensitivityConfirmed": p.confirm}
	if err := audit.Record(ctx, q, e); err != nil {
		return row, err
	}
	if p.deprecated {
		s.notifier().ServerDeprecated(ctx, q, cur.ID)
	}
	return row, nil
}

// ReviewOverdue reports whether a published server's re-review date has
// passed.
func ReviewOverdue(sv dbgen.McpServer, now time.Time) bool {
	return sv.PublishState == StatePublished && sv.ReviewDueAt != nil && !sv.ReviewDueAt.After(now)
}

// requestRereview is Publish for a published server whose re-review is due
// (the caller holds its row lock; team owners and admins, never a token): under
// approval_required the server goes back to review (reason review_due) and a
// platform admin approves it again; under self_publish the team confirms it in
// place. Either way the next review date is counted from the approval.
func (s *Service) requestRereview(ctx context.Context, q *dbgen.Queries, a authz.Actor, team dbgen.Team, cur dbgen.McpServer, policy string, note, expectedDigest *string) (err error) {
	if a.IsToken() {
		return tokenRefusal("review")
	}
	if expectedDigest != nil && *expectedDigest != "" {
		if err := checkDigest(ctx, q, cur, *expectedDigest); err != nil {
			return err
		}
	}
	next, action := StatePending, "mcp_server.publish_request"
	if policy == authz.PolicySelfPublish {
		next, action = StatePublished, "mcp_server.review_confirm"
	}
	row, err := q.SetMCPServerPublishState(ctx, dbgen.SetMCPServerPublishStateParams{ID: cur.ID, PublishState: next, Requested: true, Actor: by(a), Note: note})
	if err != nil {
		return err
	}
	if next == StatePending {
		s.notifier().PublishRequested(ctx, q, cur.ID, "review_due", a)
	}
	e := a.Audit(action, "mcp_server", cur.ID.String())
	e.TeamID = team.ID
	e.Before, e.After = map[string]any{"publishState": cur.PublishState}, map[string]any{"publishState": row.PublishState}
	e.Metadata = map[string]any{"name": cur.Name, "policy": policy, "reason": "review_due", "note": deref(note)}
	return audit.Record(ctx, q, e)
}

// MaxReviewIntervalDays bounds a re-review interval (10 years); 0 turns it off.
const MaxReviewIntervalDays = 3650

// GovernanceSettingsInput changes the platform's governance settings; nil
// fields keep their values.
type GovernanceSettingsInput struct {
	Public, Internal, Confidential, Restricted *int32
	ReturnOverdue                              *bool
}

var errInvalidInterval = apperr.Invalid("invalid_interval", "A review interval is 0 (none) to 3650 days")

func governanceSettingsSnapshot(st dbgen.PlatformSetting) map[string]any {
	return map[string]any{"reviewIntervalDays": map[string]any{"public": st.ReviewIntervalDaysPublic, "internal": st.ReviewIntervalDaysInternal,
		"confidential": st.ReviewIntervalDaysConfidential, "restricted": st.ReviewIntervalDaysRestricted},
		"returnOverdueToReview": st.GovernanceReturnOverdue}
}

// UpdateGovernanceSettings changes the days between re-reviews per sensitivity
// and whether an overdue re-review sends a published server back to review
// (platform admins, in a browser session). expectedRevision is the governance
// settings' own. Every published server's due date is counted again from its
// last approval in the same transaction. Audited as
// settings.governance_update.
func (s *Service) UpdateGovernanceSettings(ctx context.Context, a authz.Actor, in GovernanceSettingsInput, expectedRevision int64) (Settings, error) {
	if a.IsToken() || !a.IsPlatformAdmin() {
		return Settings{}, errAdminOnly
	}
	for _, d := range []*int32{in.Public, in.Internal, in.Confidential, in.Restricted} {
		if d != nil && (*d < 0 || *d > MaxReviewIntervalDays) {
			return Settings{}, errInvalidInterval
		}
	}
	var out Settings
	err := store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		cur, err := q.LockPlatformSettings(ctx)
		if err != nil {
			return err
		}
		if cur.GovernanceRevision != expectedRevision {
			return apperr.Stale()
		}
		p := dbgen.UpdateGovernanceSettingsParams{Public: cur.ReviewIntervalDaysPublic, Internal: cur.ReviewIntervalDaysInternal,
			Confidential: cur.ReviewIntervalDaysConfidential, Restricted: cur.ReviewIntervalDaysRestricted,
			ReturnOverdue: cur.GovernanceReturnOverdue, UpdatedBy: by(a)}
		setIf(&p.Public, in.Public)
		setIf(&p.Internal, in.Internal)
		setIf(&p.Confidential, in.Confidential)
		setIf(&p.Restricted, in.Restricted)
		setIf(&p.ReturnOverdue, in.ReturnOverdue)
		if out, err = q.UpdateGovernanceSettings(ctx, p); err != nil {
			return err
		}
		recomputed, err := q.RecomputeMCPServerReviewDue(ctx, uuid.NullUUID{})
		if err != nil {
			return err
		}
		e := a.Audit("settings.governance_update", "platform_settings", "governance")
		e.Before, e.After = governanceSettingsSnapshot(cur), governanceSettingsSnapshot(out)
		e.Metadata = map[string]any{"serversRecomputed": recomputed}
		return audit.Record(ctx, q, e)
	})
	return out, err
}
