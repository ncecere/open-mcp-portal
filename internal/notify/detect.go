package notify

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/store"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

// The hooks of the registry and of delegated credentials: each is one call
// at the place the change happens, with the queries of its transaction (or
// of the pool), and reads what it needs from the database itself. None of
// them returns an error: a notification never fails what it reports on.

// UnhealthyAfter is how many failed checks in a row make a server
// unhealthy.
const UnhealthyAfter = 3

// ReminderEvery is how often an incident that still lasts is repeated.
const ReminderEvery = 24 * time.Hour

func serverRef(id uuid.UUID, slug, name string) apitypes.NotificationServerRef {
	return apitypes.NotificationServerRef{Id: id, Slug: slug, Name: clip(name, 200)}
}

func ptr[T any](v T) *T { return &v }

// ServerChecked runs after a health check is stored (scheduled or manual).
// A server whose last 3 checks failed is unhealthy: server.unhealthy once
// per incident (since = when the failing status began), then a reminder
// for every whole day it still fails. The first ok check after an incident
// that had an unhealthy event is server.recovered.
func (s *Service) ServerChecked(ctx context.Context, q *dbgen.Queries, serverID uuid.UUID) {
	if err := s.serverChecked(ctx, q, serverID); err != nil && ctx.Err() == nil {
		s.log.WarnContext(ctx, "notifications: evaluating a health check failed", "server", serverID, "err", err)
	}
}

func (s *Service) serverChecked(ctx context.Context, q *dbgen.Queries, serverID uuid.UUID) error {
	checks, err := q.LatestMCPHealthChecksOfServer(ctx, dbgen.LatestMCPHealthChecksOfServerParams{ServerID: serverID, PageSize: 100})
	if err != nil || len(checks) == 0 {
		return err
	}
	sv, err := q.GetNotificationServer(ctx, serverID)
	if errors.Is(store.NotFound(err), store.ErrNotFound) {
		return nil
	} else if err != nil {
		return err
	}
	latest := checks[0]
	ev := Event{TeamID: sv.TeamID, SubjectType: "mcp_server", SubjectID: serverID.String(), Actor: latest.TriggeredBy.UUID}
	if latest.Ok {
		if len(checks) < 2 || checks[1].Ok {
			return nil
		}
		since := checks[1].StatusSince
		_, err := q.FindNotificationEventByKeyPrefix(ctx, dbgen.FindNotificationEventByKeyPrefixParams{
			Event: ServerUnhealthy, SubjectID: serverID.String(), Prefix: store.EscapeLike(fmt.Sprintf("server.unhealthy:%s:%d:", serverID, since.UnixMicro()))})
		if errors.Is(store.NotFound(err), store.ErrNotFound) {
			return nil // no unhealthy event was sent for that incident
		} else if err != nil {
			return err
		}
		recovered := latest.CheckedAt
		ev.Type, ev.DedupKey = ServerRecovered, fmt.Sprintf("server.recovered:%s:%d", serverID, since.UnixMicro())
		ev.Data = apitypes.ServerRecoveredData{Server: serverRef(sv.ID, sv.Slug, sv.Name), Since: since.UTC(), RecoveredAt: recovered.UTC(),
			DowntimeSeconds: max(int64(recovered.Sub(since).Seconds()), 0)}
		Emit(ctx, q, ev)
		return nil
	}
	n := 0
	for _, c := range checks {
		if c.Ok {
			break
		}
		n++
	}
	if n < UnhealthyAfter {
		return nil
	}
	since := latest.StatusSince
	days := max(int(s.now().Sub(since)/ReminderEvery), 0)
	data := apitypes.ServerUnhealthyData{Server: serverRef(sv.ID, sv.Slug, sv.Name), Since: since.UTC(), ConsecutiveFailures: int32(n),
		ErrorClass: latest.ErrorClass, HttpStatus: latest.HttpStatus, Reminder: days > 0}
	if days > 0 {
		data.FailingHours = ptr(int32(s.now().Sub(since) / time.Hour))
	}
	ev.Type, ev.DedupKey, ev.Data = ServerUnhealthy, fmt.Sprintf("server.unhealthy:%s:%d:%d", serverID, since.UnixMicro(), days), data
	Emit(ctx, q, ev)
	return nil
}

// CapabilitiesRefreshed runs after a refresh stored a server's capabilities:
// a published server left with changed or new capabilities that aren't
// approved (held back from the catalog) is capability.changed, once for each
// distinct held set.
func (s *Service) CapabilitiesRefreshed(ctx context.Context, q *dbgen.Queries, serverID uuid.UUID) {
	if err := s.capabilitiesRefreshed(ctx, q, serverID); err != nil && ctx.Err() == nil {
		s.log.WarnContext(ctx, "notifications: evaluating a refresh failed", "server", serverID, "err", err)
	}
}

func (s *Service) capabilitiesRefreshed(ctx context.Context, q *dbgen.Queries, serverID uuid.UUID) error {
	sv, err := q.GetNotificationServer(ctx, serverID)
	if errors.Is(store.NotFound(err), store.ErrNotFound) || (err == nil && sv.PublishState != "published") {
		return nil
	} else if err != nil {
		return err
	}
	held, err := q.ListHeldCapabilities(ctx, serverID)
	if err != nil || len(held) == 0 {
		return err
	}
	h := sha256.New()
	d := apitypes.CapabilityChangedData{Server: serverRef(sv.ID, sv.Slug, sv.Name), Held: true}
	for _, c := range held {
		fmt.Fprintf(h, "%s\x00%s\x00%s\n", c.Kind, c.Name, c.Fingerprint)
		change := apitypes.CapabilityChangedDataCapabilitiesChange("new")
		if c.Changed {
			d.ChangedCount++
			change = "changed"
		} else {
			d.NewCount++
		}
		if len(d.Capabilities) < 10 {
			d.Capabilities = append(d.Capabilities, struct {
				Change apitypes.CapabilityChangedDataCapabilitiesChange `json:"change"`
				Kind   apitypes.CapabilityChangedDataCapabilitiesKind   `json:"kind"`
				Name   string                                           `json:"name"`
			}{Change: change, Kind: apitypes.CapabilityChangedDataCapabilitiesKind(c.Kind), Name: clip(c.Name, 100)})
		} else {
			d.MoreCount++
		}
	}
	Emit(ctx, q, Event{Type: CapabilityChanged, DedupKey: fmt.Sprintf("capability.changed:%s:%s", serverID, hex.EncodeToString(h.Sum(nil))[:16]),
		TeamID: sv.TeamID, SubjectType: "mcp_server", SubjectID: serverID.String(), Data: d})
	return nil
}

// actorName is the name of the person or token that acted.
func (s *Service) actorName(ctx context.Context, q *dbgen.Queries, a authz.Actor) (kind, name string) {
	if a.IsToken() {
		return "automation_token", a.TokenName
	}
	if a.UserID == uuid.Nil {
		return "system", "The portal" // the governance loop (an overdue re-review)
	}
	if n, err := q.GetNotificationActorName(ctx, a.UserID); err == nil {
		return "user", n
	}
	return "user", "someone"
}

// PublishRequested runs when a server enters review (pending): the first
// request, or sent back for review (reason new, url_changed,
// upstream_auth_changed, requirement_changed). Platform admins are told.
func (s *Service) PublishRequested(ctx context.Context, q *dbgen.Queries, serverID uuid.UUID, reason string, a authz.Actor) {
	sv, err := q.GetNotificationServer(ctx, serverID)
	if err != nil || sv.PublishRequestedAt == nil {
		if err != nil && !errors.Is(store.NotFound(err), store.ErrNotFound) {
			s.log.WarnContext(ctx, "notifications: reading a requested server failed", "server", serverID, "err", err)
		}
		return
	}
	d := apitypes.PublishRequestedData{Server: serverRef(sv.ID, sv.Slug, sv.Name), Reason: apitypes.PublishRequestedDataReason(reason)}
	if sv.PublishRequestNote != nil && strings.TrimSpace(*sv.PublishRequestNote) != "" {
		d.Note = ptr(clip(*sv.PublishRequestNote, 300))
	}
	kind, name := s.actorName(ctx, q, a)
	d.RequestedBy.Kind, d.RequestedBy.Name = apitypes.PublishRequestedDataRequestedByKind(kind), clip(name, 200)
	Emit(ctx, q, Event{Type: PublishRequested, DedupKey: fmt.Sprintf("publish.requested:%s:%d", serverID, sv.PublishRequestedAt.UnixMicro()),
		TeamID: sv.TeamID, SubjectType: "mcp_server", SubjectID: serverID.String(), Actor: a.UserID, Data: d})
}

// PublishDecided runs when a platform admin approves or rejects a server:
// the team's owners and admins are told.
func (s *Service) PublishDecided(ctx context.Context, q *dbgen.Queries, serverID uuid.UUID, approved bool, a authz.Actor) {
	sv, err := q.GetNotificationServer(ctx, serverID)
	if err != nil || sv.PublishReviewedAt == nil {
		if err != nil && !errors.Is(store.NotFound(err), store.ErrNotFound) {
			s.log.WarnContext(ctx, "notifications: reading a reviewed server failed", "server", serverID, "err", err)
		}
		return
	}
	d := apitypes.PublishDecidedData{Server: serverRef(sv.ID, sv.Slug, sv.Name), Decision: apitypes.PublishDecidedDataDecisionRejected}
	if approved {
		d.Decision = apitypes.PublishDecidedDataDecisionApproved
	}
	_, d.DecidedBy.Name = s.actorName(ctx, q, a)
	d.DecidedBy.Name = clip(d.DecidedBy.Name, 200)
	if sv.PublishReviewNote != nil && strings.TrimSpace(*sv.PublishReviewNote) != "" {
		d.Note = ptr(clip(*sv.PublishReviewNote, 300))
	}
	Emit(ctx, q, Event{Type: PublishDecided, DedupKey: fmt.Sprintf("publish.decided:%s:%d", serverID, sv.PublishReviewedAt.UnixMicro()),
		TeamID: sv.TeamID, SubjectType: "mcp_server", SubjectID: serverID.String(), Actor: a.UserID, Data: d})
}

// ConnectionReconsent runs when a connection to a provider turns
// needs_reconsent: for the setup sign-in of an oauth server it is
// upstream_signin.lapsed (the team's editors and above), otherwise
// connection.needs_reconsent (that person only, never to webhooks).
func (s *Service) ConnectionReconsent(ctx context.Context, q *dbgen.Queries, connectionID uuid.UUID, reason string) {
	if err := s.connectionReconsent(ctx, q, connectionID, reason); err != nil && ctx.Err() == nil {
		s.log.WarnContext(ctx, "notifications: evaluating a lapsed connection failed", "connection", connectionID, "err", err)
	}
}

func (s *Service) connectionReconsent(ctx context.Context, q *dbgen.Queries, connectionID uuid.UUID, reason string) error {
	c, err := q.GetNotificationConnection(ctx, connectionID)
	if errors.Is(store.NotFound(err), store.ErrNotFound) {
		return nil
	} else if err != nil {
		return err
	}
	why := apitypes.RefreshFailed
	if reason == "upstream_rejected" {
		why = apitypes.UpstreamRejected
	}
	d := apitypes.ConnectionNeedsReconsentData{Reason: why}
	d.Provider.Slug, d.Provider.Name = c.ProviderSlug, clip(c.ProviderName, 200)
	stamp := c.ConnectedAt.Unix()
	if c.ProviderServerID.Valid {
		sv, err := q.GetNotificationServer(ctx, c.ProviderServerID.UUID)
		if err != nil {
			return store.NotFound(err)
		}
		ref := serverRef(sv.ID, sv.Slug, sv.Name)
		if sv.OauthSetupUserID.Valid && sv.OauthSetupUserID.UUID == c.UserID {
			lapsed := apitypes.UpstreamSigninLapsedData{Server: ref, Since: s.now().UTC()}
			if sv.SetupName != "" {
				lapsed.ReadAsName = ptr(clip(sv.SetupName, 200))
			}
			Emit(ctx, q, Event{Type: UpstreamSigninLapsed, DedupKey: fmt.Sprintf("upstream_signin.lapsed:%s:%d", sv.ID, stamp),
				TeamID: sv.TeamID, SubjectType: "mcp_server", SubjectID: sv.ID.String(), Data: lapsed})
			return nil
		}
		d.Server = &ref
	}
	Emit(ctx, q, Event{Type: ConnectionNeedsReconsent, DedupKey: fmt.Sprintf("connection.needs_reconsent:%s:%d", connectionID, stamp),
		SubjectType: "provider_connection", SubjectID: connectionID.String(), Recipient: c.UserID, Data: d})
	return nil
}

// ScanKeys emits key.expiring for every active key or token that was made
// for more than 7 days and expires within 7 days: personal keys (to the
// person), service account keys and publisher tokens (the team's owners and
// admins) and platform tokens (platform admins); and for every enabled
// server whose mTLS client certificate expires within 14 days (keyKind
// server_certificate; the team's owners, admins and editors). The dedup key
// key.expiring:<kind>:<id> makes the scan idempotent. It reports how many
// events are new.
func (s *Service) ScanKeys(ctx context.Context) (int, error) {
	now := s.now()
	days := func(t time.Time) int32 { return int32(max((t.Sub(now)+24*time.Hour-1)/(24*time.Hour), 0)) }
	emitted := 0
	count := func(ok bool) {
		if ok {
			emitted++
		}
	}
	personal, err := s.q.ListExpiringPersonalKeys(ctx)
	if err != nil {
		return emitted, err
	}
	for _, k := range personal {
		count(Emit(ctx, s.q, Event{Type: KeyExpiring, DedupKey: "key.expiring:personal:" + k.ID.String(), SubjectType: "api_key", SubjectID: k.ID.String(), Recipient: k.UserID,
			Data: apitypes.KeyExpiringData{KeyKind: apitypes.KeyExpiringDataKeyKindPersonal, Name: clip(k.Name, 100), ExpiresAt: k.ExpiresAt.UTC(), DaysLeft: days(k.ExpiresAt)}}))
	}
	sas, err := s.q.ListExpiringServiceAccountKeys(ctx)
	if err != nil {
		return emitted, err
	}
	for _, k := range sas {
		d := apitypes.KeyExpiringData{KeyKind: apitypes.KeyExpiringDataKeyKindServiceAccount, Name: clip(k.Name, 100), ExpiresAt: k.ExpiresAt.UTC(), DaysLeft: days(k.ExpiresAt)}
		d.ServiceAccount = &struct {
			Id   uuid.UUID `json:"id"`
			Name string    `json:"name"`
		}{Id: k.ServiceAccountID, Name: clip(k.ServiceAccountName, 100)}
		count(Emit(ctx, s.q, Event{Type: KeyExpiring, DedupKey: "key.expiring:service_account:" + k.ID.String(), TeamID: k.TeamID, SubjectType: "service_account_key",
			SubjectID: k.ID.String(), Data: d}))
	}
	tokens, err := s.q.ListExpiringAutomationTokens(ctx)
	if err != nil {
		return emitted, err
	}
	for _, k := range tokens {
		kind, subject := apitypes.KeyExpiringDataKeyKindPlatformToken, "platform_token"
		if k.Kind == authz.TokenTeamPublisher {
			kind, subject = apitypes.KeyExpiringDataKeyKindPublisherToken, "publisher_token"
		}
		count(Emit(ctx, s.q, Event{Type: KeyExpiring, DedupKey: "key.expiring:" + subject + ":" + k.ID.String(), TeamID: k.TeamID.UUID, SubjectType: "automation_token",
			SubjectID: k.ID.String(), Data: apitypes.KeyExpiringData{KeyKind: kind, Name: clip(k.Name, 100), ExpiresAt: k.ExpiresAt.UTC(), DaysLeft: days(k.ExpiresAt)}}))
	}
	certs, err := s.q.ListExpiringServerCertificates(ctx)
	if err != nil {
		return emitted, err
	}
	for _, c := range certs {
		// 14 days ahead, once per certificate (a renewed one has its own
		// fingerprint, so it warns again when its turn comes): to the team's
		// owners, admins and editors.
		ref := serverRef(c.ID, c.Slug, c.Name)
		fp := ""
		if c.ClientCertSha256 != nil {
			fp = ":" + clip(*c.ClientCertSha256, 16)
		}
		count(Emit(ctx, s.q, Event{Type: KeyExpiring, DedupKey: "key.expiring:server_certificate:" + c.ID.String() + fp, TeamID: c.TeamID, SubjectType: "mcp_server",
			SubjectID: c.ID.String(), Data: apitypes.KeyExpiringData{KeyKind: apitypes.KeyExpiringDataKeyKindServerCertificate, Name: clip(c.Name, 100),
				ExpiresAt: c.ClientNotAfter.UTC(), DaysLeft: days(*c.ClientNotAfter), Server: &ref}}))
	}
	if emitted > 0 {
		slog.InfoContext(ctx, "notifications: expiring keys found", "events", emitted)
	}
	return emitted, nil
}
