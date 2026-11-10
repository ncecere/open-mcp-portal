package httpapi

import (
	"net/http"
	"strconv"
	"time"

	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/httpx"
	"github.com/ncecere/open-mcp-portal/internal/notify"
)

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
