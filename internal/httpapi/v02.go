package httpapi

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/ncecere/open-mcp-portal/internal/apperr"
	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/automation"
	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/httpx"
	"github.com/ncecere/open-mcp-portal/internal/notify"
	"github.com/ncecere/open-mcp-portal/internal/overview"
	"github.com/ncecere/open-mcp-portal/internal/registry"
)

// The v0.2 pilot-readiness operations: the admin overview and team
// attention (docs/admin-overview.md), notifications (docs/notifications.md)
// and automation tokens (docs/automation-tokens.md).

func (a *api) v02Routes() []route {
	const (
		teamDest  = "/v1/teams/{team}/notification-destinations"
		adminDest = "/v1/admin/notification-destinations"
	)
	routes := []route{
		{"GET", "/v1/admin/overview", a.admin(a.adminGetOverview)},
		{"GET", "/v1/teams/{team}/attention", a.session(a.getTeamAttention)},

		{"GET", "/v1/me/notifications", a.session(a.listMyNotifications)},
		{"GET", "/v1/me/notifications/unread-count", a.session(a.getMyUnreadNotificationCount)},
		{"POST", "/v1/me/notifications/read-all", a.session(a.markAllMyNotificationsRead)},
		{"POST", "/v1/me/notifications/{notificationId}/read", a.session(a.markMyNotificationRead)},
		{"GET", "/v1/me/notification-preferences", a.session(a.getMyNotificationPreferences)},
		{"PUT", "/v1/me/notification-preferences", a.session(a.updateMyNotificationPreferences)},

		{"GET", "/v1/admin/settings/notifications", a.admin(a.adminGetNotificationSettings)},
		{"POST", "/v1/admin/settings/notifications/test-email", a.admin(a.adminTestEmail)},

		{"GET", "/v1/token", a.tokenOnly(a.getToken)},
		{"GET", "/v1/admin/automation-tokens", a.admin(a.adminListAutomationTokens)},
		{"POST", "/v1/admin/automation-tokens", a.admin(a.adminCreateAutomationToken)},
		{"DELETE", "/v1/admin/automation-tokens/{tokenId}", a.admin(a.adminRevokeAutomationToken)},
		{"GET", "/v1/teams/{team}/automation-tokens", a.session(a.listTeamAutomationTokens)},
		{"POST", "/v1/teams/{team}/automation-tokens", a.session(a.createTeamAutomationToken)},
		{"DELETE", "/v1/teams/{team}/automation-tokens/{tokenId}", a.session(a.revokeTeamAutomationToken)},
	}
	dest := func(base string, wrap func(http.HandlerFunc) http.Handler, scope func(*http.Request) notify.Scope) []route {
		return []route{
			{"GET", base, wrap(a.listDestinations(scope))},
			{"POST", base, wrap(a.createDestination(scope))},
			{"GET", base + "/{destinationId}", wrap(a.getDestination(scope))},
			{"PATCH", base + "/{destinationId}", wrap(a.updateDestination(scope))},
			{"DELETE", base + "/{destinationId}", wrap(a.deleteDestination(scope))},
			{"POST", base + "/{destinationId}/test", wrap(a.testDestination(scope))},
			{"POST", base + "/{destinationId}/rotate-secret", wrap(a.rotateDestinationSecret(scope))},
			{"GET", base + "/{destinationId}/deliveries", wrap(a.listDeliveries(scope))},
		}
	}
	teamScope := func(r *http.Request) notify.Scope { return notify.Scope{TeamRef: r.PathValue("team")} }
	platformScope := func(*http.Request) notify.Scope { return notify.Scope{} }
	routes = append(routes, dest(teamDest, a.session, teamScope)...)
	return append(routes, dest(adminDest, a.admin, platformScope)...)
}

func teamRef(id uuid.UUID, slug, name string) *apitypes.TeamRef {
	return &apitypes.TeamRef{Id: id, Slug: slug, Name: name}
}

// ---- overview and attention

func toAPIItems(items []overview.Item) []apitypes.AttentionItem {
	out := make([]apitypes.AttentionItem, len(items))
	for i, it := range items {
		o := apitypes.AttentionItem{Kind: apitypes.AttentionKind(it.Kind), Severity: apitypes.AttentionSeverity(it.Severity), Summary: it.Summary,
			Count: it.Count, At: it.At}
		if it.Subject != nil {
			o.Subject = &apitypes.AttentionSubject{Id: it.Subject.ID, Name: it.Subject.Name, Slug: nonEmpty(it.Subject.Slug)}
		}
		if it.Team != nil {
			o.Team = teamRef(it.Team.ID, it.Team.Slug, it.Team.Name)
		}
		if it.Link != nil {
			l := &apitypes.LinkTarget{Type: apitypes.LinkTargetType(it.Link.Type), Id: nonEmpty(it.Link.ID), TeamSlug: nonEmpty(it.Link.TeamSlug)}
			o.Link = l
		}
		out[i] = o
	}
	return out
}

func (a *api) adminGetOverview(w http.ResponseWriter, r *http.Request) {
	o, err := a.Overview.Admin(r.Context(), a.actor(r))
	if failed(w, r, err) {
		return
	}
	httpx.JSON(w, http.StatusOK, apitypes.AdminOverview{
		GeneratedAt: o.GeneratedAt,
		Counts: apitypes.OverviewCounts{Users: o.Counts.Users, Teams: o.Counts.Teams, Servers: o.Counts.Servers, PublishedServers: o.Counts.PublishedServers,
			Gateways: o.Counts.Gateways, ServiceAccounts: o.Counts.ServiceAccounts, AutomationTokens: o.Counts.AutomationTokens},
		Last24h: apitypes.OverviewActivity{Calls: o.Last24h.Calls, Errors: o.Last24h.Errors, RateLimited: o.Last24h.RateLimited,
			ErrorRate: o.Last24h.ErrorRate, RolledUpTo: o.Last24h.RolledUpTo},
		Attention: toAPIItems(o.Attention), Totals: o.Totals, Truncated: o.Truncated,
	})
}

func (a *api) getTeamAttention(w http.ResponseWriter, r *http.Request) {
	t, err := a.Overview.Team(r.Context(), a.actor(r), r.PathValue("team"))
	if failed(w, r, err) {
		return
	}
	httpx.JSON(w, http.StatusOK, apitypes.TeamAttention{GeneratedAt: t.GeneratedAt, Attention: toAPIItems(t.Attention), Totals: t.Totals, Truncated: t.Truncated})
}

// ---- inbox and preferences

func (a *api) listMyNotifications(w http.ResponseWriter, r *http.Request) {
	limit, ok := pageLimit(w, r)
	if !ok {
		return
	}
	unread := false
	if v := r.URL.Query().Get("unread"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			httpx.Error(w, http.StatusBadRequest, "invalid_unread", "unread must be true or false")
			return
		}
		unread = b
	}
	keys, ok := decodeCursor(w, r, 1)
	if !ok {
		return
	}
	var before int64
	if keys != nil {
		var err error
		if before, err = strconv.ParseInt(keys[0], 10, 64); err != nil || before < 1 {
			httpx.Error(w, http.StatusBadRequest, "invalid_cursor", "Invalid cursor")
			return
		}
	}
	p, err := a.Notify.ListInbox(r.Context(), a.actor(r), unread, before, limit)
	if failed(w, r, err) {
		return
	}
	page := apitypes.NotificationPage{Items: make([]apitypes.NotificationItem, len(p.Items)), UnreadCount: p.UnreadCount}
	for i, it := range p.Items {
		row := it.Row
		item := apitypes.NotificationItem{Id: row.ID, Event: apitypes.NotificationEventType(row.Event), Title: row.Title, Body: row.Body,
			CreatedAt: row.CreatedAt, ReadAt: row.ReadAt, Link: nil}
		if it.Link != nil {
			l := apitypes.LinkTarget{Type: apitypes.LinkTargetType(it.Link.Type), Id: nonEmpty(it.Link.ID), TeamSlug: nonEmpty(it.Link.TeamSlug)}
			item.Link = &l
		}
		if it.Team != nil {
			item.Team = teamRef(it.Team.ID, it.Team.Slug, it.Team.Name)
		}
		page.Items[i] = item
	}
	if p.More && len(p.Items) > 0 {
		page.NextCursor = encodeCursor(strconv.FormatInt(p.Items[len(p.Items)-1].Row.ID, 10))
	}
	httpx.JSON(w, http.StatusOK, page)
}

func (a *api) getMyUnreadNotificationCount(w http.ResponseWriter, r *http.Request) {
	n, err := a.Notify.UnreadCount(r.Context(), a.actor(r))
	if failed(w, r, err) {
		return
	}
	httpx.JSON(w, http.StatusOK, apitypes.NotificationUnreadCount{Count: n})
}

func (a *api) markAllMyNotificationsRead(w http.ResponseWriter, r *http.Request) {
	n, err := a.Notify.MarkAllRead(r.Context(), a.actor(r))
	if failed(w, r, err) {
		return
	}
	httpx.JSON(w, http.StatusOK, apitypes.NotificationMarked{Marked: n})
}

func (a *api) markMyNotificationRead(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("notificationId"), 10, 64)
	if err != nil || id < 1 {
		httpx.Error(w, http.StatusBadRequest, "invalid_id", "Invalid notificationId")
		return
	}
	writeOK(w, r, a.Notify.MarkRead(r.Context(), a.actor(r), id))
}

func toAPIPreferences(p notify.Preferences) apitypes.NotificationPreferences {
	out := apitypes.NotificationPreferences{EmailAvailable: p.EmailAvailable, EmailAddress: p.EmailAddress, Items: make([]apitypes.NotificationPreference, len(p.Items))}
	for i, it := range p.Items {
		out.Items[i] = apitypes.NotificationPreference{Event: apitypes.NotificationEventType(it.Event), InApp: it.InApp, Email: it.Email, Custom: it.Custom}
	}
	return out
}

func (a *api) getMyNotificationPreferences(w http.ResponseWriter, r *http.Request) {
	p, err := a.Notify.GetPreferences(r.Context(), a.actor(r))
	if failed(w, r, err) {
		return
	}
	httpx.JSON(w, http.StatusOK, toAPIPreferences(p))
}

func (a *api) updateMyNotificationPreferences(w http.ResponseWriter, r *http.Request) {
	var in apitypes.NotificationPreferencesUpdate
	if !httpx.Decode(w, r, &in) {
		return
	}
	if len(in.Items) == 0 || len(in.Items) > len(notify.Events) {
		httpx.Error(w, http.StatusBadRequest, "invalid_items", "Send between 1 and 8 changes")
		return
	}
	changes := make([]notify.Change, len(in.Items))
	for i, c := range in.Items {
		changes[i] = notify.Change{Event: string(c.Event), InApp: c.InApp, Email: c.Email}
	}
	p, err := a.Notify.UpdatePreferences(r.Context(), a.actor(r), changes)
	if failed(w, r, err) {
		return
	}
	httpx.JSON(w, http.StatusOK, toAPIPreferences(p))
}

// ---- destinations

func errorClass(c string) *apitypes.NotificationErrorClass {
	if c == "" {
		return nil
	}
	e := apitypes.NotificationErrorClass(c)
	return &e
}

func toAPIDestination(d notify.Destination) apitypes.NotificationDestination {
	row := d.D
	events := make([]apitypes.NotificationEventType, len(row.Events))
	for i, e := range row.Events {
		events[i] = apitypes.NotificationEventType(e)
	}
	health := apitypes.NotificationDestinationHealth{State: apitypes.NotificationDestinationHealthState("unknown"), ConsecutiveFailures: row.ConsecutiveFailures,
		LastSuccessAt: row.LastSuccessAt, LastFailureAt: row.LastFailureAt}
	switch {
	case row.ConsecutiveFailures > 0:
		health.State = "failing"
	case row.LastSuccessAt != nil:
		health.State = "ok"
	}
	if row.LastErrorClass != nil {
		health.LastErrorClass = errorClass(*row.LastErrorClass)
	}
	out := apitypes.NotificationDestination{
		Id: row.ID, Scope: apitypes.NotificationDestinationScope(row.Scope), Name: row.Name, Format: apitypes.NotificationFormat(row.Format),
		UrlDisplay: row.UrlDisplay, Events: events, TeamEvents: row.TeamEvents, Enabled: row.Enabled, HasSecret: len(row.SecretCipher) > 0,
		SecretHint: row.SecretHint, SecretRotatedAt: row.SecretRotatedAt, Health: health, Revision: row.Revision,
		CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt, CreatedByName: row.CreatedByName,
	}
	if row.DisabledReason != nil {
		reason := apitypes.NotificationDestinationDisabledReason(*row.DisabledReason)
		out.DisabledReason = &reason
	}
	if row.SecretPreviousUntil != nil && row.SecretPreviousUntil.After(time.Now()) {
		out.PreviousSecretExpiresAt = row.SecretPreviousUntil
	}
	if row.TeamID.Valid {
		out.Team = teamRef(row.TeamID.UUID, d.TeamSlug, d.TeamName)
	}
	return out
}

type scopeFn func(*http.Request) notify.Scope

func (a *api) listDestinations(sc scopeFn) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ds, err := a.Notify.List(r.Context(), a.actor(r), sc(r))
		writeList(w, r, ds, err, toAPIDestination)
	}
}

func (a *api) getDestination(sc scopeFn) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := pathUUID(w, r, "destinationId")
		if !ok {
			return
		}
		d, err := a.Notify.Get(r.Context(), a.actor(r), sc(r), id)
		if failed(w, r, err) {
			return
		}
		writeRevised(w, http.StatusOK, d.D.Revision, toAPIDestination(d))
	}
}

func eventStrings(in []apitypes.NotificationEventType) []string {
	out := make([]string, len(in))
	for i, e := range in {
		out[i] = string(e)
	}
	return out
}

func (a *api) createDestination(sc scopeFn) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var in apitypes.NotificationDestinationCreate
		if !httpx.Decode(w, r, &in) {
			return
		}
		events := eventStrings(in.Events)
		d, secret, err := a.Notify.Create(r.Context(), a.actor(r), sc(r), notify.Input{Name: &in.Name, Format: string(in.Format), URL: &in.Url,
			Events: &events, TeamEvents: in.TeamEvents, Enabled: in.Enabled})
		if failed(w, r, err) {
			return
		}
		out := apitypes.NotificationDestinationCreated{Destination: toAPIDestination(d)}
		if secret != "" {
			out.Secret = &secret
		}
		writeRevised(w, http.StatusCreated, d.D.Revision, out)
	}
}

func (a *api) updateDestination(sc scopeFn) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := pathUUID(w, r, "destinationId")
		if !ok {
			return
		}
		in, rev, ok := decodeRevised[apitypes.NotificationDestinationUpdate](w, r)
		if !ok {
			return
		}
		up := notify.Input{Name: in.Name, URL: in.Url, TeamEvents: in.TeamEvents, Enabled: in.Enabled}
		if in.Events != nil {
			events := eventStrings(*in.Events)
			up.Events = &events
		}
		d, err := a.Notify.Update(r.Context(), a.actor(r), sc(r), id, up, rev)
		if failed(w, r, err) {
			return
		}
		writeRevised(w, http.StatusOK, d.D.Revision, toAPIDestination(d))
	}
}

func (a *api) deleteDestination(sc scopeFn) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := pathUUID(w, r, "destinationId")
		if !ok {
			return
		}
		writeOK(w, r, a.Notify.Delete(r.Context(), a.actor(r), sc(r), id))
	}
}

func toAPINotifyTest(t notify.TestResult) apitypes.NotificationTestResult {
	out := apitypes.NotificationTestResult{Ok: t.OK, DurationMs: int32(min(t.DurationMs, 1<<31-1)), Message: t.Message, ErrorClass: errorClass(t.ErrorClass)}
	if t.HTTPStatus > 0 {
		st := int32(t.HTTPStatus)
		out.HttpStatus = &st
	}
	return out
}

func (a *api) testDestination(sc scopeFn) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := pathUUID(w, r, "destinationId")
		if !ok {
			return
		}
		res, err := a.Notify.Test(r.Context(), a.actor(r), sc(r), id)
		if failed(w, r, err) {
			return
		}
		httpx.JSON(w, http.StatusOK, toAPINotifyTest(res))
	}
}

func (a *api) rotateDestinationSecret(sc scopeFn) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := pathUUID(w, r, "destinationId")
		if !ok {
			return
		}
		in, ok := decodeOptional[apitypes.NotificationSecretRotate](w, r)
		if !ok {
			return
		}
		grace := 24
		if in.GraceHours != nil {
			grace = int(*in.GraceHours)
		}
		d, secret, err := a.Notify.RotateSecret(r.Context(), a.actor(r), sc(r), id, grace)
		if failed(w, r, err) {
			return
		}
		writeRevised(w, http.StatusOK, d.D.Revision, apitypes.NotificationDestinationSecret{Destination: toAPIDestination(d), Secret: secret})
	}
}

func toAPIDelivery(d notify.Delivery) apitypes.NotificationDelivery {
	out := apitypes.NotificationDelivery{Id: d.ID, EventId: d.EventPublicID, Event: apitypes.NotificationEventType(d.Event),
		State: apitypes.NotificationDeliveryState(d.State), Attempts: d.Attempts, CreatedAt: d.CreatedAt, LastAttemptAt: d.LastAttemptAt,
		SentAt: d.SentAt, HttpStatus: d.HttpStatus}
	if d.State == notify.StatePending {
		next := d.NextAttemptAt
		out.NextAttemptAt = &next
	}
	if d.ErrorClass != nil {
		out.ErrorClass = errorClass(*d.ErrorClass)
	}
	return out
}

func (a *api) listDeliveries(sc scopeFn) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := pathUUID(w, r, "destinationId")
		if !ok {
			return
		}
		ds, err := a.Notify.Deliveries(r.Context(), a.actor(r), sc(r), id)
		writeList(w, r, ds, err, toAPIDelivery)
	}
}

func (a *api) adminGetNotificationSettings(w http.ResponseWriter, r *http.Request) {
	st, err := a.Notify.GetSettings(r.Context(), a.actor(r))
	if failed(w, r, err) {
		return
	}
	var out apitypes.NotificationSettings
	out.Email = apitypes.NotificationEmailStatus{Configured: st.Email.Configured, Authenticated: st.Email.Authenticated,
		SentLast24h: st.Email.SentLast24h, FailedLast24h: st.Email.FailedLast24h}
	if st.Email.Configured {
		port := int32(st.Email.Port)
		mode := apitypes.NotificationEmailStatusTls(st.Email.TLS)
		out.Email.From, out.Email.Host, out.Email.Port, out.Email.Tls = &st.Email.From, &st.Email.Host, &port, &mode
	}
	out.Webhooks.TeamDestinations, out.Webhooks.PlatformDestinations, out.Webhooks.Stopped = st.TeamDestinations, st.PlatformDestinations, st.Stopped
	out.Queue.Pending, out.Queue.FailedLast24h, out.Queue.IntervalSeconds = st.Pending, st.FailedLast24h, st.IntervalSeconds
	out.Queue.OldestPendingAt, out.Queue.LastRunAt = st.OldestPendingAt, st.LastRunAt
	httpx.JSON(w, http.StatusOK, out)
}

func (a *api) adminTestEmail(w http.ResponseWriter, r *http.Request) {
	res, err := a.Notify.TestEmail(r.Context(), a.actor(r))
	if failed(w, r, err) {
		return
	}
	httpx.JSON(w, http.StatusOK, toAPINotifyTest(res))
}

// ---- automation tokens

func toAPIToken(t automation.Token) apitypes.AutomationToken {
	now := time.Now()
	row := t.Row
	scopes := make([]apitypes.AutomationTokenScope, len(row.Scopes))
	for i, s := range row.Scopes {
		scopes[i] = apitypes.AutomationTokenScope(s)
	}
	out := apitypes.AutomationToken{Id: row.ID, Kind: apitypes.AutomationTokenKind(row.Kind), Name: row.Name, Prefix: row.Prefix, Scopes: scopes,
		Status: apitypes.AutomationTokenStatus(t.Status(now)), CreatedAt: row.CreatedAt, CreatedByName: row.CreatedByName, ExpiresAt: row.ExpiresAt,
		LastUsedAt: row.LastUsedAt, RevokedAt: row.RevokedAt}
	if row.TeamID.Valid {
		out.Team = teamRef(row.TeamID.UUID, t.TeamSlug, t.TeamName)
	}
	if t.BlockedReason(now) != "" {
		b := apitypes.AutomationTokenBlockedReason(t.BlockedReason(now))
		out.BlockedReason = &b
	}
	return out
}

func (a *api) getToken(w http.ResponseWriter, r *http.Request) {
	actor := a.actor(r)
	t, err := a.Automation.Get(r.Context(), actor.TokenID)
	if failed(w, r, err) {
		return
	}
	httpx.JSON(w, http.StatusOK, toAPIToken(t))
}

func (a *api) adminListAutomationTokens(w http.ResponseWriter, r *http.Request) {
	ts, err := a.Automation.ListPlatform(r.Context(), a.actor(r))
	writeList(w, r, ts, err, toAPIToken)
}

func (a *api) listTeamAutomationTokens(w http.ResponseWriter, r *http.Request) {
	ts, err := a.Automation.ListTeam(r.Context(), a.actor(r), r.PathValue("team"))
	writeList(w, r, ts, err, toAPIToken)
}

func tokenInput(in apitypes.AutomationTokenCreate) automation.CreateInput {
	ci := automation.CreateInput{Name: in.Name}
	for _, s := range in.Scopes {
		ci.Scopes = append(ci.Scopes, string(s))
	}
	if in.ExpiresInDays != nil {
		if *in.ExpiresInDays == 0 {
			ci.Days = -1 // an explicit 0 is not "the default": invalid_expiry
		} else {
			ci.Days = *in.ExpiresInDays
		}
	}
	return ci
}

func writeCreatedToken(w http.ResponseWriter, r *http.Request, c automation.Created, err error) {
	if failed(w, r, err) {
		return
	}
	httpx.JSON(w, http.StatusCreated, apitypes.AutomationTokenCreated{Token: toAPIToken(c.Token), Secret: c.Secret})
}

func (a *api) adminCreateAutomationToken(w http.ResponseWriter, r *http.Request) {
	var in apitypes.AutomationTokenCreate
	if !httpx.Decode(w, r, &in) {
		return
	}
	c, err := a.Automation.CreatePlatform(r.Context(), a.actor(r), tokenInput(in))
	writeCreatedToken(w, r, c, err)
}

func (a *api) createTeamAutomationToken(w http.ResponseWriter, r *http.Request) {
	var in apitypes.AutomationTokenCreate
	if !httpx.Decode(w, r, &in) {
		return
	}
	c, err := a.Automation.CreateTeam(r.Context(), a.actor(r), r.PathValue("team"), tokenInput(in))
	writeCreatedToken(w, r, c, err)
}

func (a *api) adminRevokeAutomationToken(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "tokenId")
	if !ok {
		return
	}
	writeOK(w, r, a.Automation.RevokePlatform(r.Context(), a.actor(r), id))
}

func (a *api) revokeTeamAutomationToken(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "tokenId")
	if !ok {
		return
	}
	writeOK(w, r, a.Automation.RevokeTeam(r.Context(), a.actor(r), r.PathValue("team"), id))
}

// tokenMayUpdateServer is the field rule of updateTeamMcpServer for
// automation tokens (docs/automation-tokens.md): a token is not a person who
// accepted the capture notice, so it may not change capturePayloads; and on a
// server that already holds credentials it may not re-point it or change what
// it sends: url, auth header or credential parts, auth mode, OAuth setup, requirement or
// sendIdentity (a leaked token could otherwise steal a header value or
// teammates' tokens). Refused with 403 token_not_allowed and details.field.
func (a *api) tokenMayUpdateServer(w http.ResponseWriter, r *http.Request, actor authz.Actor, id uuid.UUID, in apitypes.McpServerUpdate, keys map[string]json.RawMessage) bool {
	v, err := a.Registry.GetTeam(r.Context(), actor, r.PathValue("team"), id)
	if failed(w, r, err) {
		return false
	}
	sv := v.Server
	refuse := func(field string) bool {
		a.refuseToken(w, r, field)
		return false
	}
	// A client key and a CA are credentials and trust settings: a token never
	// sends them, whatever the server holds (decision 74).
	if _, ok := keys["tls"]; ok {
		return refuse("tls")
	}
	if in.CapturePayloads != nil && *in.CapturePayloads != sv.CapturePayloads {
		return refuse("capturePayloads")
	}
	if in.RequiresPresentPerson != nil && *in.RequiresPresentPerson != sv.RequiresPresentPerson {
		return refuse("requiresPresentPerson")
	}
	if in.AuthMode != nil && string(*in.AuthMode) == registry.AuthPersonSecret && registry.AuthModeOf(sv) != registry.AuthPersonSecret {
		// A token never switches a server to asking people for their own keys,
		// even one with nothing to steal yet: that sends their keys to its URL.
		return refuse("authMode")
	}
	if _, ok := keys["personSecret"]; ok {
		return refuse("personSecret")
	}
	// A machine client is a secret like no other the token could set: never
	// from an automation token, even on a server without credentials (a
	// token must not choose where a client secret goes; decision 73).
	if _, ok := keys["machineOAuth"]; ok {
		return refuse("machineOAuth")
	}
	if in.AuthMode != nil && string(*in.AuthMode) == registry.AuthMachineOAuth && sv.AuthMode != registry.AuthMachineOAuth {
		return refuse("authMode")
	}
	if !v.HasAuth() && sv.AuthMode == "none" && !sv.AuthProviderID.Valid && !(v.TLS != nil && v.TLS.Client != nil) {
		return true // no credentials yet: nothing to steal or redirect
	}
	for _, f := range []string{"authHeaderName", "authValue", "credentials", "authMode", "oauth", "requirement"} {
		if _, ok := keys[f]; ok {
			return refuse(f)
		}
	}
	if in.Url != nil && *in.Url != sv.URL {
		return refuse("url")
	}
	if in.SendIdentity != nil && *in.SendIdentity != sv.SendIdentity {
		return refuse("sendIdentity")
	}
	return true
}

// refuseToken answers an automation token that tried to change field: 403
// token_not_allowed with details.field.
func (a *api) refuseToken(w http.ResponseWriter, r *http.Request, field string) {
	a.Automation.Count(automation.ResultNotAllowed)
	e := apperr.New(http.StatusForbidden, "token_not_allowed", "An automation token can't change "+field+" of this server: sign in to do it")
	e.Details = map[string]any{"field": field}
	httpx.Fail(w, r, e)
}
