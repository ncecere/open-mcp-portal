package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/store"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

// Governance notices (decision 88, docs/notifications.md): a published
// server's re-review is overdue (server.review_due), a deprecated server's
// sunset is near (server.sunset_soon) and a server a gateway selects was
// deprecated (server.deprecated). They are in-app and email only, never
// webhooks, and are told once per server (or per gateway) and date: the
// governance loop records each notice in server_governance_notices in the
// transaction that stores its event, so a retry, another replica or a purged
// event never tells anyone twice.
//
// Audiences are resolved from live roles at fan-out and again when an email is
// sent: a server's notices go to its team's owners and admins and its named
// owner (while an active editor or above); a gateway's notices go to that
// gateway's team owners and admins, or to platform admins for a platform
// gateway. A gateway's notice names the server (published, so already in the
// catalog, or of the gateway's own team) and that gateway, and nothing of the
// server's team beyond what the catalog shows.

// sunsetSoonDays is the window of server.sunset_soon.
const sunsetSoonDays = 14

func isGovernanceEvent(event string) bool {
	return event == ServerReviewDue || event == ServerSunsetSoon || event == ServerDeprecated
}

// Subject types of governance events.
const (
	subjectServer  = "mcp_server"
	subjectGateway = "gateway"
)

func gatewayRef(g dbgen.Gateway) apitypes.NotificationGatewayRef {
	return apitypes.NotificationGatewayRef{Id: g.ID, Slug: g.Slug, Name: clip(g.Name, 100)}
}

// replacementRef is the server a retiring one points to, when the audience may
// be shown it: published (catalog-visible) or of the same team.
func replacementRef(ctx context.Context, q *dbgen.Queries, sv dbgen.McpServer, sameTeam uuid.NullUUID) *apitypes.NotificationServerRef {
	if !sv.ReplacementServerID.Valid {
		return nil
	}
	r, err := q.GetNotificationServer(ctx, sv.ReplacementServerID.UUID)
	if err != nil || (r.PublishState != "published" && !(sameTeam.Valid && sameTeam.UUID == r.TeamID)) {
		return nil
	}
	ref := serverRef(r.ID, r.Slug, r.Name)
	return &ref
}

// record stores that a notice was told. It reports whether this call was the
// first for the server (and gateway) and date.
func record(ctx context.Context, q *dbgen.Queries, kind string, serverID uuid.UUID, gateway uuid.NullUUID, stamp time.Time) (int64, bool, error) {
	id, err := q.GovernanceRecordNotice(ctx, dbgen.GovernanceRecordNoticeParams{Kind: kind, ServerID: serverID, GatewayID: gateway, Stamp: stamp})
	if errors.Is(store.NotFound(err), store.ErrNotFound) {
		return 0, false, nil
	} else if err != nil {
		return 0, false, err
	}
	return id, true, nil
}

// told records the notice and stores its event in the caller's transaction; an
// event that could not be stored takes the record back, so the next run tells
// the people instead of losing it.
func (s *Service) told(ctx context.Context, q *dbgen.Queries, kind string, serverID uuid.UUID, gateway uuid.NullUUID, stamp time.Time, ev Event) bool {
	id, first, err := record(ctx, q, kind, serverID, gateway, stamp)
	if err != nil {
		s.log.WarnContext(ctx, "notifications: recording a governance notice failed", "kind", kind, "server", serverID, "err", err)
		return false
	}
	if !first {
		return false
	}
	if !Emit(ctx, q, ev) {
		if err := q.GovernanceDeleteNotice(ctx, id); err != nil {
			s.log.WarnContext(ctx, "notifications: taking back a governance notice failed", "kind", kind, "server", serverID, "err", err)
		}
		return false
	}
	return true
}

// ReviewDue tells a published server's team that its re-review is overdue,
// once per due date. returned: the governance loop also sent it back to review.
func (s *Service) ReviewDue(ctx context.Context, q *dbgen.Queries, sv dbgen.McpServer, returned bool) bool {
	if sv.ReviewDueAt == nil {
		return false
	}
	due := sv.ReviewDueAt.UTC()
	return s.told(ctx, q, "review_due", sv.ID, uuid.NullUUID{}, due, Event{Type: ServerReviewDue,
		DedupKey: fmt.Sprintf("server.review_due:%s:%d", sv.ID, due.UnixMicro()), TeamID: sv.TeamID, SubjectType: subjectServer, SubjectID: sv.ID.String(),
		Data: apitypes.ServerReviewDueData{Server: serverRef(sv.ID, sv.Slug, sv.Name), Sensitivity: apitypes.Sensitivity(sv.Sensitivity), DueAt: due, ReturnedToReview: returned}})
}

// SunsetSoon tells a deprecated server's team (gateway nil) or the owners of a
// gateway that selects it, once per sunset date.
func (s *Service) SunsetSoon(ctx context.Context, q *dbgen.Queries, sv dbgen.McpServer, gateway *dbgen.Gateway) bool {
	if sv.SunsetAt == nil {
		return false
	}
	sunset := sv.SunsetAt.UTC()
	left := int32(max((sunset.Sub(s.now())+24*time.Hour-1)/(24*time.Hour), 0))
	d := apitypes.ServerSunsetSoonData{Server: serverRef(sv.ID, sv.Slug, sv.Name), SunsetAt: sunset, DaysLeft: left}
	ev := Event{Type: ServerSunsetSoon, TeamID: sv.TeamID, SubjectType: subjectServer, SubjectID: sv.ID.String()}
	gw := uuid.NullUUID{}
	if gateway == nil {
		d.Replacement = replacementRef(ctx, q, sv, uuid.NullUUID{UUID: sv.TeamID, Valid: true})
		ev.DedupKey = fmt.Sprintf("server.sunset_soon:%s:%d", sv.ID, sunset.UnixMicro())
	} else {
		ref := gatewayRef(*gateway)
		d.Gateway = &ref
		d.Replacement = replacementRef(ctx, q, sv, gateway.TeamID)
		gw = uuid.NullUUID{UUID: gateway.ID, Valid: true}
		ev.TeamID, ev.SubjectType, ev.SubjectID = gateway.TeamID.UUID, subjectGateway, gateway.ID.String()
		ev.DedupKey = fmt.Sprintf("server.sunset_soon:%s:%s:%d", sv.ID, gateway.ID, sunset.UnixMicro())
	}
	ev.Data = d
	return s.told(ctx, q, "sunset_soon", sv.ID, gw, sunset, ev)
}

// Deprecated tells the owners of a gateway that selects a deprecated server,
// once per gateway and deprecation.
func (s *Service) Deprecated(ctx context.Context, q *dbgen.Queries, sv dbgen.McpServer, gateway dbgen.Gateway) bool {
	if sv.DeprecatedAt == nil {
		return false
	}
	since := sv.DeprecatedAt.UTC()
	ref := gatewayRef(gateway)
	d := apitypes.ServerDeprecatedData{Server: serverRef(sv.ID, sv.Slug, sv.Name), DeprecatedAt: since, Gateway: ref,
		Replacement: replacementRef(ctx, q, sv, gateway.TeamID)}
	if sv.SunsetAt != nil {
		t := sv.SunsetAt.UTC()
		d.SunsetAt = &t
	}
	return s.told(ctx, q, "deprecated", sv.ID, uuid.NullUUID{UUID: gateway.ID, Valid: true}, since, Event{Type: ServerDeprecated,
		DedupKey: fmt.Sprintf("server.deprecated:%s:%s:%d", sv.ID, gateway.ID, since.UnixMicro()), TeamID: gateway.TeamID.UUID,
		SubjectType: subjectGateway, SubjectID: gateway.ID.String(), Data: d})
}

// ServerDeprecated runs in the transaction that deprecates a server: the owners
// of every enabled gateway that selects it are told at once. (A gateway that
// selects it later is told by the governance loop.)
func (s *Service) ServerDeprecated(ctx context.Context, q *dbgen.Queries, serverID uuid.UUID) {
	sv, err := q.GetMCPServer(ctx, serverID)
	if err != nil || sv.Lifecycle == "active" || sv.DeprecatedAt == nil {
		return
	}
	gws, err := q.GovernanceSelectingGateways(ctx, serverID)
	if err != nil {
		s.log.WarnContext(ctx, "notifications: listing the gateways of a deprecated server failed", "server", serverID, "err", err)
		return
	}
	for _, r := range gws {
		if r.OwnerKind == "team" && r.GatewayTeamID.Valid {
			t, err := q.GetTeamByID(ctx, r.GatewayTeamID.UUID)
			if err != nil || t.Status != "active" {
				continue
			}
		}
		// A server a gateway of another team selects is in the catalog.
		if sv.PublishState != "published" && !(r.GatewayTeamID.Valid && r.GatewayTeamID.UUID == sv.TeamID) {
			continue
		}
		g, err := q.GetGateway(ctx, r.GatewayID)
		if err != nil {
			continue
		}
		s.Deprecated(ctx, q, sv, g)
	}
}

// governanceRecipients resolves a governance event's audience from live roles.
func (s *Service) governanceRecipients(ctx context.Context, q *dbgen.Queries, ev dbgen.NotificationEvent) ([]recipient, error) {
	var out []recipient
	switch ev.SubjectType {
	case subjectServer:
		rows, err := q.ListTeamRecipients(ctx, dbgen.ListTeamRecipientsParams{TeamID: ev.TeamID.UUID, Roles: adminsUp})
		if err != nil {
			return nil, err
		}
		out = fromTeam(rows)
		id, err := uuid.Parse(ev.SubjectID)
		if err != nil {
			return out, nil
		}
		o, err := q.GovernanceOwnerRecipient(ctx, id)
		if err != nil {
			return out, ignoreNoRows(err)
		}
		for _, r := range out {
			if r.ID == o.ID {
				return out, nil
			}
		}
		out = append(out, recipient{ID: o.ID, Email: o.Email, DisplayName: o.DisplayName, Verified: o.EmailVerified})
	case subjectGateway:
		if ev.TeamID.Valid {
			rows, err := q.ListTeamRecipients(ctx, dbgen.ListTeamRecipientsParams{TeamID: ev.TeamID.UUID, Roles: adminsUp})
			if err != nil {
				return nil, err
			}
			return fromTeam(rows), nil
		}
		rows, err := q.ListPlatformAdminRecipients(ctx)
		if err != nil {
			return nil, err
		}
		return fromAdmins(rows), nil
	}
	return out, nil
}

// composeGovernance builds the message of a governance event.
func composeGovernance(ev dbgen.NotificationEvent, slug string) (Message, bool) {
	m := Message{Title: ev.Event}
	switch ev.Event {
	case ServerReviewDue:
		var d apitypes.ServerReviewDueData
		if json.Unmarshal(ev.Payload, &d) != nil {
			return m, false
		}
		m.Link = &Link{Type: LinkServer, ID: d.Server.Id.String(), TeamSlug: slug}
		m.Title = fmt.Sprintf("Review of %s is overdue", nm(d.Server.Name))
		m.Body = "It was due on " + d.DueAt.UTC().Format("2006-01-02") + " (" + string(d.Sensitivity) + " servers are reviewed again on a schedule)."
		if d.ReturnedToReview {
			m.Body += " It went back to review, so a platform admin approves it again."
		} else {
			m.Body += " Ask for a new review from the server's page."
		}
	case ServerSunsetSoon:
		var d apitypes.ServerSunsetSoonData
		if json.Unmarshal(ev.Payload, &d) != nil {
			return m, false
		}
		m.Title = fmt.Sprintf("%s stops being served in %s", nm(d.Server.Name), plural(int(d.DaysLeft), "day", "days"))
		m.Body = "It is deprecated and sunsets on " + d.SunsetAt.UTC().Format("2006-01-02 15:04 MST") + "; after that no gateway serves it."
		if d.Replacement != nil {
			m.Body += " Its replacement is " + nm(d.Replacement.Name) + "."
		}
		if d.Gateway != nil {
			m.Body += " Your gateway " + nm(d.Gateway.Name) + " selects it."
			m.Link = &Link{Type: LinkGateways, TeamSlug: slug}
		} else {
			m.Link = &Link{Type: LinkServer, ID: d.Server.Id.String(), TeamSlug: slug}
		}
	case ServerDeprecated:
		var d apitypes.ServerDeprecatedData
		if json.Unmarshal(ev.Payload, &d) != nil {
			return m, false
		}
		m.Link = &Link{Type: LinkGateways, TeamSlug: slug}
		m.Title = fmt.Sprintf("%s is deprecated", nm(d.Server.Name))
		m.Body = "Your gateway " + nm(d.Gateway.Name) + " selects it."
		if d.SunsetAt != nil {
			m.Body += " It stops being served on " + d.SunsetAt.UTC().Format("2006-01-02 15:04 MST") + "."
		}
		if d.Replacement != nil {
			m.Body += " Its replacement is " + nm(d.Replacement.Name) + "."
		}
	default:
		return m, false
	}
	return m, true
}
