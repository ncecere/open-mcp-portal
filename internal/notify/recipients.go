package notify

import (
	"context"
	"encoding/json"
	"slices"

	"github.com/google/uuid"

	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

// Who gets what (docs/notifications.md, "Events, recipients and dedup"):
// recipients are resolved at fan-out from live roles, never stored.
// Suspended people and archived teams get nothing, and the person who
// caused a manual event is skipped.

// editorsUp and adminsUp are the team roles of an event's audience.
var (
	editorsUp = []string{authz.RoleOwner, authz.RoleAdmin, authz.RoleEditor}
	adminsUp  = []string{authz.RoleOwner, authz.RoleAdmin}
)

// teamEvents are the non-personal team events: platform destinations get
// them only with teamEvents on.
var teamEvents = map[string]bool{ServerUnhealthy: true, ServerRecovered: true, CapabilityChanged: true, PublishDecided: true, UpstreamSigninLapsed: true}

// IsTeamEvent reports whether e is a non-personal team event (not
// publish.requested, key.expiring or connection.needs_reconsent).
func IsTeamEvent(e string) bool { return teamEvents[e] }

// TeamDestinationEvents are the events a team destination may subscribe to.
var TeamDestinationEvents = []string{ServerUnhealthy, ServerRecovered, CapabilityChanged, PublishDecided, UpstreamSigninLapsed, KeyExpiring}

// PlatformDestinationEvents are the events a platform destination may
// subscribe to: publish.requested and key.expiring always, the team events
// with teamEvents on.
func PlatformDestinationEvents(teamEventsOn bool) []string {
	out := []string{PublishRequested, KeyExpiring}
	if teamEventsOn {
		out = append(out, ServerUnhealthy, ServerRecovered, CapabilityChanged, PublishDecided, UpstreamSigninLapsed)
	}
	return out
}

type recipient struct {
	ID          uuid.UUID
	Email       string
	DisplayName string
	// Verified: the provider vouched for the address; email goes to
	// verified addresses only.
	Verified bool
}

func fromTeam(rows []dbgen.ListTeamRecipientsRow) []recipient {
	out := make([]recipient, len(rows))
	for i, r := range rows {
		out[i] = recipient{ID: r.ID, Email: r.Email, DisplayName: r.DisplayName, Verified: r.EmailVerified}
	}
	return out
}

func fromAdmins(rows []dbgen.ListPlatformAdminRecipientsRow) []recipient {
	out := make([]recipient, len(rows))
	for i, r := range rows {
		out[i] = recipient{ID: r.ID, Email: r.Email, DisplayName: r.DisplayName, Verified: r.EmailVerified}
	}
	return out
}

// keyKindOf is the keyKind of a key.expiring event.
func keyKindOf(ev dbgen.NotificationEvent) string {
	var d struct {
		KeyKind string `json:"keyKind"`
	}
	_ = json.Unmarshal(ev.Payload, &d)
	return d.KeyKind
}

// recipients resolves who an event is for (in-app and email).
func (s *Service) recipients(ctx context.Context, q *dbgen.Queries, ev dbgen.NotificationEvent) ([]recipient, error) {
	var out []recipient
	team := func(roles []string) error {
		if !ev.TeamID.Valid {
			return nil
		}
		rows, err := q.ListTeamRecipients(ctx, dbgen.ListTeamRecipientsParams{TeamID: ev.TeamID.UUID, Roles: roles})
		out = fromTeam(rows)
		return err
	}
	platform := func() error {
		rows, err := q.ListPlatformAdminRecipients(ctx)
		out = fromAdmins(rows)
		return err
	}
	person := func() error {
		if !ev.RecipientUserID.Valid {
			return nil
		}
		r, err := q.GetActiveRecipient(ctx, ev.RecipientUserID.UUID)
		if err != nil {
			return ignoreNoRows(err)
		}
		out = []recipient{{ID: r.ID, Email: r.Email, DisplayName: r.DisplayName, Verified: r.EmailVerified}}
		return nil
	}
	var err error
	switch ev.Event {
	case ApprovalRequested, ApprovalDecided:
		out, err = s.approvalRecipients(ctx, q, ev)
	case ServerUnhealthy, ServerRecovered, CapabilityChanged, UpstreamSigninLapsed:
		err = team(editorsUp)
	case PublishDecided:
		err = team(adminsUp)
	case PublishRequested:
		err = platform()
	case ConnectionNeedsReconsent:
		if ev.SubjectType == "service_connection" {
			err = team(adminsUp)
		} else {
			err = person()
		}
	case KeyExpiring:
		switch keyKindOf(ev) {
		case KeyPersonal:
			err = person()
		case KeyServiceAccount, KeyPublisherToken:
			err = team(adminsUp)
		case KeyServerCertificate:
			err = team(editorsUp)
		case KeyPlatformToken:
			err = platform()
		}
	}
	if err != nil {
		return nil, err
	}
	if ev.ActorUserID.Valid {
		out = slices.DeleteFunc(out, func(r recipient) bool { return r.ID == ev.ActorUserID.UUID })
	}
	return out, nil
}

// webhookRoute says which destinations an event goes to: the team's own,
// the platform's, and whether the platform's need teamEvents on.
func webhookRoute(ev dbgen.NotificationEvent) (team, platform, platformNeedsTeamEvents bool) {
	switch ev.Event {
	case ServerUnhealthy, ServerRecovered, CapabilityChanged, PublishDecided, UpstreamSigninLapsed:
		return true, true, true
	case PublishRequested:
		return false, true, false
	case KeyExpiring:
		switch keyKindOf(ev) {
		case KeyServiceAccount, KeyPublisherToken, KeyServerCertificate:
			return true, true, true
		case KeyPlatformToken:
			return false, true, false
		}
	}
	return false, false, false // private approvals, personal connections and keys never leave
}

// channelPrefs says, for each person, which channels they chose to receive
// an event on (defaults: in-app on, email on).
func (s *Service) channelPrefs(ctx context.Context, q *dbgen.Queries, event string, rs []recipient) (map[uuid.UUID]map[string]bool, error) {
	ids := make([]uuid.UUID, len(rs))
	prefs := make(map[uuid.UUID]map[string]bool, len(rs))
	for i, r := range rs {
		ids[i] = r.ID
		prefs[r.ID] = map[string]bool{ChannelInApp: true, ChannelEmail: true}
	}
	if len(ids) == 0 {
		return prefs, nil
	}
	rows, err := q.ListNotificationPreferencesForUsers(ctx, dbgen.ListNotificationPreferencesForUsersParams{UserIds: ids, Event: event})
	if err != nil {
		return nil, err
	}
	for _, p := range rows {
		prefs[p.UserID][p.Channel] = p.Enabled
	}
	return prefs, nil
}

// receivable lists the events a person can receive, from their live roles:
// team events for the roles they hold, publish.requested for platform
// admins; personal connection/key and private approval choices for everyone.
// Any human can be a named/group reviewer or requester. Listing a preference
// grants no receipt visibility; the live resolver controls actual fan-out.
func (s *Service) receivable(ctx context.Context, userID uuid.UUID, platformRole string) ([]string, error) {
	roles, err := s.q.ListUserTeamRoles(ctx, userID)
	if err != nil {
		return nil, err
	}
	held := func(want ...string) bool {
		for _, r := range roles {
			if slices.Contains(want, r) {
				return true
			}
		}
		return false
	}
	var out []string
	for _, e := range Events {
		switch e {
		case ServerUnhealthy, ServerRecovered, CapabilityChanged, UpstreamSigninLapsed:
			if !held(editorsUp...) {
				continue
			}
		case PublishDecided:
			if !held(adminsUp...) {
				continue
			}
		case PublishRequested:
			if platformRole != authz.PlatformAdmin {
				continue
			}
		}
		out = append(out, e)
	}
	return out, nil
}
