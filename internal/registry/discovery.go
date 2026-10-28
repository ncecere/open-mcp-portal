package registry

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.opentelemetry.io/otel/trace"

	"github.com/ncecere/open-mcp-portal/internal/apperr"
	"github.com/ncecere/open-mcp-portal/internal/audit"
	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/identity"
	"github.com/ncecere/open-mcp-portal/internal/observability"
	"github.com/ncecere/open-mcp-portal/internal/store"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/internal/upstream"
)

// Discovery: Test reads a server's capabilities without storing them;
// Refresh stores them. A capability is new, unchanged (same fingerprint: its
// approval stands), changed (another fingerprint: unapproved by
// definition, since approved means approved_fingerprint = fingerprint) or
// gone (no longer listed: marked gone and its approval withdrawn). A
// refresh never approves anything. Both store a manual health check.

// Health check triggers.
const (
	TriggerManual    = "manual"
	TriggerScheduled = "scheduled"
)

// KeepChecks is how many health checks are kept per server.
const KeepChecks = 100

func timeout(sv dbgen.McpServer) time.Duration { return time.Duration(sv.TimeoutSeconds) * time.Second }

// TestResult is the outcome of reading a server's capabilities.
type TestResult struct {
	OK                                         bool
	Latency                                    time.Duration
	Counts                                     upstream.Counts
	ServerName, ServerVersion, ProtocolVersion string
	// Protocol is the era and version negotiated with the server (zero when
	// it wasn't read); a successful check stores it on the server.
	Protocol upstream.Protocol
	Err      *upstream.Error // nil when OK
	// ReadAs names the person whose sign-in (the setup connection) an
	// oauth server was read with; SetupRequired says there was none usable
	// (SetupStatus is missing or needs_reconsent).
	ReadAs        *string
	SetupRequired bool
	SetupStatus   string
	// SignInRequired: a scheduled check of an oauth server got the expected
	// 401 challenge (healthy). Note is stored as the message of a healthy
	// check.
	SignInRequired bool
	Note           string
	// SecretRequired: a person_secret server has no key to read it with (no
	// setup person, or theirs is rejected, for another origin or no longer
	// usable).
	SecretRequired bool
}

// probe discovers a server's capabilities (no storing), without an identity
// token: refresh, discovery and scheduled health checks never send one (see
// testIdentity for why). The secrets the exchange used (the credential parts
// and what they encode to) are returned so messages can be scrubbed of them. A server in oauth mode is read with the setup connection, except by
// scheduled checks, which use nobody's token (probeSignIn).
func (s *Service) probe(ctx context.Context, sv dbgen.McpServer, trigger string) (TestResult, upstream.Discovery, []string) {
	return s.probeAs(ctx, sv, trigger, "")
}

// probeAs is probe sending the signed identity token (the bare JWT) the way
// a forwarded call does, when token is not empty: as Authorization: Bearer,
// or as MCP-Gateway-Identity when one of the server's own credential parts is
// Authorization or it is read with its own sign-in (an oauth server).
func (s *Service) probeAs(ctx context.Context, sv dbgen.McpServer, trigger, token string) (TestResult, upstream.Discovery, []string) {
	// One span per probe (a scheduled check, a Test or a Refresh): the server's
	// slug, the trigger and how it ended. Nothing the server answered.
	ctx, sp := observability.Start(ctx, "registry.probe", trace.SpanKindInternal,
		observability.AttrServer.String(sv.Slug), observability.AttrTrigger.String(trigger))
	defer sp.End()
	res, d, tok := s.probeUntraced(ctx, sv, trigger, token)
	if res.OK {
		observability.Annotate(sp, observability.AttrResult.String("healthy"))
	} else {
		observability.Annotate(sp, observability.AttrResult.String("failing"))
		class := "error"
		if res.Err != nil && res.Err.Class != "" {
			class = res.Err.Class
		}
		observability.Annotate(sp, observability.AttrErrorClass.String(class))
		observability.Fail(sp, class)
	}
	return res, d, tok
}

func (s *Service) probeUntraced(ctx context.Context, sv dbgen.McpServer, trigger, token string) (TestResult, upstream.Discovery, []string) {
	t, err := s.target(ctx, sv)
	if err != nil {
		var e *upstream.Error
		errors.As(err, &e)
		return TestResult{Err: e}, upstream.Discovery{}, nil
	}
	var res TestResult
	if AuthModeOf(sv) == AuthOAuth {
		p, err := s.q.GetServerProvider(ctx, uuid.NullUUID{UUID: sv.ID, Valid: true})
		if err != nil {
			return TestResult{Err: &upstream.Error{Class: upstream.ClassConfig, Message: "The server's sign-in isn't configured."}},
				upstream.Discovery{}, nil
		}
		if trigger == TriggerScheduled {
			return s.probeSignIn(ctx, sv, p), upstream.Discovery{}, nil
		}
		if deref(p.Resource) != sv.URL {
			return TestResult{Err: &upstream.Error{Class: upstream.ClassConfig,
				Message: "The server's URL differs from its OAuth resource; save its sign-in again."}}, upstream.Discovery{}, nil
		}
		token, person, err := s.setupToken(ctx, sv, p)
		var se *SetupError
		switch {
		case errors.As(err, &se):
			return TestResult{SetupRequired: true, SetupStatus: se.Status, Err: &upstream.Error{Class: upstream.ClassAuth,
					Message: "No usable sign-in to read this server with: an editor signs in again (Sign in to read capabilities)."}},
				upstream.Discovery{}, nil
		case err != nil:
			return TestResult{Err: &upstream.Error{Class: upstream.ClassUnavailable, Message: upstream.SafeMessage(err.Error(), "")}},
				upstream.Discovery{}, nil
		}
		t.BearerToken, res.ReadAs = token, &person
	}
	var secretID uuid.UUID
	var secretSealed []byte
	if cfg, ok := PersonSecretConfig(sv); ok {
		// A person_secret server: scheduled checks send nobody's key (a 401 or
		// 403 is healthy, "requires a personal key"); a Test or Refresh reads
		// with the setup person's own key (decision 72).
		if trigger == TriggerScheduled {
			return s.probeSecretRequired(ctx, sv, t)
		}
		secret, person, id, sealed, fail := s.setupSecret(ctx, sv)
		if fail != nil {
			return *fail, upstream.Discovery{}, nil
		}
		if !t.WithPersonSecret(cfg.Placement, cfg.Name, cfg.Prefix, secret) {
			return TestResult{Err: &upstream.Error{Class: upstream.ClassConfig, Message: "The server's secret settings are incomplete."}}, upstream.Discovery{}, nil
		}
		res.ReadAs, secretID, secretSealed = &person, id, sealed
	}
	if token != "" {
		t.IdentityHeader, t.IdentityValue = identity.Header(t.AuthorizationHeader(), token)
		if t.BearerToken != "" {
			t.IdentityHeader, t.IdentityValue = identity.HeaderIdentity, token
		}
	}
	d, err := s.client.Discover(ctx, t)
	if ue, ok := err.(*upstream.Error); ok && ue.HTTPStatus == http.StatusUnauthorized && AuthModeOf(sv) == AuthMachineOAuth {
		// The server refused the machine token (a 401 means nothing ran): get
		// another and read once more; a second refusal is the result.
		if next, uerr := s.machineToken(ctx, sv, t.BearerToken); uerr != nil {
			err = uerr
		} else {
			t.BearerToken = next
			d, err = s.client.Discover(ctx, t)
		}
	}
	res.Latency, res.ServerName, res.ServerVersion, res.ProtocolVersion = d.Latency, d.ServerName, d.ServerVersion, d.ProtocolVersion
	res.Protocol = d.Protocol
	if err != nil {
		e, ok := err.(*upstream.Error)
		if !ok {
			e = &upstream.Error{Class: upstream.ClassUnavailable, Message: "The test failed."}
		}
		msg := upstream.SafeMessage(e.Message, append(t.Secrets(), token)...)
		if secretID != uuid.Nil && e.Class == upstream.ClassAuth && (e.HTTPStatus == http.StatusUnauthorized || e.HTTPStatus == http.StatusForbidden) {
			// The server refused the key it was read with: not sent again
			// until replaced (the value that was sent, not a newer one).
			if _, err := s.q.RejectPersonSecret(ctx, dbgen.RejectPersonSecretParams{ID: secretID, SecretCipher: secretSealed}); err != nil {
				s.log.WarnContext(ctx, "could not mark a rejected person secret", "server", sv.ID, "err", err)
			}
		}
		res.Err = &upstream.Error{Class: e.Class, HTTPStatus: e.HTTPStatus, Message: msg}
		return res, d, t.Secrets()
	}
	res.OK, res.Counts = true, upstream.CountKinds(d.Capabilities)
	return res, d, t.Secrets()
}

// setupToken is the setup connection's token (internal/providers).
func (s *Service) setupToken(ctx context.Context, sv dbgen.McpServer, p dbgen.AuthProvider) (string, string, error) {
	if s.oauth.Hooks == nil {
		return "", "", &SetupError{Status: SetupMissing}
	}
	return s.oauth.Hooks.SetupToken(ctx, sv, p)
}

// recordCheck stores a health check and prunes the server's history.
func recordCheck(ctx context.Context, q *dbgen.Queries, serverID uuid.UUID, res TestResult, trigger string, actor uuid.NullUUID) error {
	p := dbgen.InsertMCPHealthCheckParams{ServerID: serverID, Ok: res.OK, Trigger: trigger,
		LatencyMs: int32(min(max(res.Latency.Milliseconds(), 0), 1<<31-1)), SignInRequired: res.SignInRequired && res.OK}
	if res.OK {
		p.Message = res.Note
	}
	if trigger == TriggerManual {
		p.TriggeredBy = actor
	}
	if res.Err != nil {
		class := res.Err.Class
		p.Ok, p.ErrorClass, p.Message = false, &class, res.Err.Message
		if st := res.Err.HTTPStatus; st >= 100 && st <= 599 {
			v := int32(st)
			p.HttpStatus = &v
		}
	}
	if _, err := q.InsertMCPHealthCheck(ctx, p); err != nil {
		return err
	}
	// What the server speaks, as last negotiated by a check that read it.
	if res.OK && res.Protocol.Era != "" && res.Protocol.Version != "" {
		if err := q.SetMCPServerProtocol(ctx, dbgen.SetMCPServerProtocolParams{ID: serverID, Era: ptr(string(res.Protocol.Era)),
			Version: ptr(res.Protocol.Version)}); err != nil {
			return err
		}
	}
	_, err := q.PruneMCPHealthChecks(ctx, dbgen.PruneMCPHealthChecksParams{ServerID: serverID, Keep: KeepChecks})
	return err
}

// Test reads a server's capabilities without saving them (team editors and
// above; the server may be disabled) and stores the result as a manual
// health check. Like a call it sends the editor's identity token when the
// server's Send identity is on (testAs).
func (s *Service) Test(ctx context.Context, a authz.Actor, ref string, id uuid.UUID) (TestResult, error) {
	ta, err := access(ctx, s.q, a, ref)
	if err != nil {
		return TestResult{}, err
	}
	if err := authz.CheckServerEdit(ta.role); err != nil {
		return TestResult{}, err
	}
	sv, err := teamServer(ctx, s.q, ta.team.ID, id, false)
	if err != nil {
		return TestResult{}, err
	}
	res := s.testAs(ctx, a, sv)
	if err := recordCheck(context.WithoutCancel(ctx), s.q, id, res, TriggerManual, by(a)); err != nil {
		s.log.WarnContext(ctx, "could not store an MCP server test", "server", id, "err", err)
	} else {
		s.notifier().ServerChecked(ctx, s.q, id)
	}
	return res, nil
}

// RefreshResult counts what a refresh changed, with the capabilities after it.
type RefreshResult struct {
	Listed, Added, Changed, Gone int
	Capabilities                 []CapabilityView
}

// Refresh reads a server's capabilities again and stores them (team editors
// and above; the server may be disabled). When the server can't be read it
// is 502 discovery_failed with the test result as details. Audited as
// mcp_server.refresh with the counts.
func (s *Service) Refresh(ctx context.Context, a authz.Actor, ref string, id uuid.UUID) (RefreshResult, error) {
	ta, err := access(ctx, s.q, a, ref)
	if err != nil {
		return RefreshResult{}, err
	}
	if err := ta.writable(authz.CheckServerEdit); err != nil {
		return RefreshResult{}, err
	}
	sv, err := teamServer(ctx, s.q, ta.team.ID, id, false)
	if err != nil {
		return RefreshResult{}, err
	}
	res, fail, err := s.refresh(ctx, a, sv)
	if err != nil {
		return RefreshResult{}, err
	}
	if fail != nil {
		if fail.SecretRequired {
			return RefreshResult{}, errSecretSetupRequired
		}
		if fail.SetupRequired {
			e := apperr.Conflict("setup_reconsent_required", "The sign-in used to read this server's capabilities can't be used: an editor signs in again")
			e.Details = map[string]any{"status": fail.SetupStatus}
			return RefreshResult{}, e
		}
		return RefreshResult{}, &DiscoveryError{Result: *fail}
	}
	return *res, nil
}

// DiscoveryError is a refresh that couldn't read the server (502
// discovery_failed; the HTTP layer renders Result as details).
type DiscoveryError struct{ Result TestResult }

func (e *DiscoveryError) Error() string { return "discovery failed: " + e.Result.Err.Message }

// AsAppError is the error as the API renders it, with details filled by
// conv (the API's McpTestResult).
func (e *DiscoveryError) AsAppError(details any) *apperr.Error {
	out := apperr.New(http.StatusBadGateway, "discovery_failed", "The server's capabilities couldn't be read: "+e.Result.Err.Message)
	out.Details = details
	return out
}

// refresh discovers and stores a server's capabilities (authorization
// done). A discovery failure is returned as fail (and stored), not err.
func (s *Service) refresh(ctx context.Context, a authz.Actor, sv dbgen.McpServer) (*RefreshResult, *TestResult, error) {
	res, d, _ := s.probe(ctx, sv, TriggerManual)
	if !res.OK {
		err := store.InTx(context.WithoutCancel(ctx), s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
			if _, err := anyServer(ctx, q, sv.ID, true); err != nil {
				return err
			}
			msg := res.Err.Message
			if err := q.SetMCPServerRefreshError(ctx, dbgen.SetMCPServerRefreshErrorParams{ID: sv.ID, Message: &msg}); err != nil {
				return err
			}
			if err := recordCheck(ctx, q, sv.ID, res, TriggerManual, by(a)); err != nil {
				return err
			}
			s.notifier().ServerChecked(ctx, q, sv.ID)
			return nil
		})
		if err != nil {
			return nil, nil, err
		}
		return nil, &res, nil
	}
	var out RefreshResult
	err := store.InTx(context.WithoutCancel(ctx), s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		cur, err := anyServer(ctx, q, sv.ID, true)
		if err != nil {
			return err
		}
		if out, err = storeCapabilities(ctx, q, cur.ID, d.Capabilities); err != nil {
			return err
		}
		// If-Match on owner edits must bind the capability definitions the
		// owner read, even when a changed definition suggests the same class.
		// Unchanged refreshes only update health/discovery timestamps.
		if out.Added+out.Changed+out.Gone > 0 {
			cur, err = q.BumpMCPServerRevision(ctx, dbgen.BumpMCPServerRevisionParams{ID: cur.ID, UpdatedBy: by(a)})
			if err != nil {
				return err
			}
		}
		if err := q.SetMCPServerRefreshed(ctx, cur.ID); err != nil {
			return err
		}
		if err := recordCheck(ctx, q, cur.ID, res, TriggerManual, by(a)); err != nil {
			return err
		}
		s.notifier().ServerChecked(ctx, q, cur.ID)
		s.notifier().CapabilitiesRefreshed(ctx, q, cur.ID)
		e := a.Audit("mcp_server.refresh", "mcp_server", cur.ID.String())
		e.TeamID = cur.TeamID
		e.Metadata = map[string]any{"name": cur.Name, "listed": out.Listed, "added": out.Added, "changed": out.Changed, "gone": out.Gone}
		if err := audit.Record(ctx, q, e); err != nil {
			return err
		}
		out.Capabilities, err = capabilities(ctx, q, cur, nil)
		return err
	})
	if err != nil {
		return nil, nil, err
	}
	return &out, nil, nil
}

// storeCapabilities upserts the listed capabilities and marks the others
// gone.
func storeCapabilities(ctx context.Context, q *dbgen.Queries, serverID uuid.UUID, listed []upstream.Capability) (RefreshResult, error) {
	sum := RefreshResult{Listed: len(listed)}
	before, err := q.ListMCPCapabilities(ctx, dbgen.ListMCPCapabilitiesParams{ServerID: serverID})
	if err != nil {
		return sum, err
	}
	prev := make(map[string]dbgen.McpCapability, len(before))
	for _, c := range before {
		prev[c.McpCapability.Kind+" "+c.McpCapability.Name] = c.McpCapability
	}
	keys := make([]string, 0, len(listed))
	for _, cp := range listed {
		key := cp.Kind + " " + cp.Name
		keys = append(keys, key)
		old, existed := prev[key]
		switch {
		case !existed || old.GoneAt != nil:
			sum.Added++
		case old.Fingerprint != cp.Fingerprint:
			sum.Changed++
		}
		if err := q.UpsertMCPCapability(ctx, dbgen.UpsertMCPCapabilityParams{ServerID: serverID, Kind: cp.Kind, Name: cp.Name,
			Title: cp.Title, Description: cp.Description, Definition: cp.Definition, Fingerprint: cp.Fingerprint}); err != nil {
			return sum, err
		}
	}
	gone, err := q.MarkMCPCapabilitiesGone(ctx, dbgen.MarkMCPCapabilitiesGoneParams{ServerID: serverID, Listed: keys})
	if err != nil {
		return sum, err
	}
	sum.Gone = len(gone)
	return sum, nil
}

// CapabilityView is a capability as the API shows it.
type CapabilityView struct {
	Capability     dbgen.McpCapability
	ApprovedByName string
	// Published: the server is published (changed only applies then).
	Published bool
	// Requires is the effective user-authorization requirement (nil: calls
	// get no provider token).
	Requires *Requirement
}

// Approved reports whether the current definition is approved.
func (c CapabilityView) Approved() bool { return IsApproved(c.Capability) }

// Changed reports whether an approved capability of a published server
// changed since its approval.
func (c CapabilityView) Changed() bool { return IsChanged(c.Capability, c.Published) }

// IsApproved: the approved fingerprint is the current one, and the
// capability is listed. A gone capability is never approved.
func IsApproved(c dbgen.McpCapability) bool {
	return c.ApprovedFingerprint != nil && *c.ApprovedFingerprint == c.Fingerprint && c.GoneAt == nil
}

// IsChanged: approved once, but the definition differs now, on a published
// server.
func IsChanged(c dbgen.McpCapability, published bool) bool {
	return published && c.ApprovedFingerprint != nil && *c.ApprovedFingerprint != c.Fingerprint && c.GoneAt == nil
}

func capabilities(ctx context.Context, q *dbgen.Queries, sv dbgen.McpServer, kind *string) ([]CapabilityView, error) {
	rows, err := q.ListMCPCapabilities(ctx, dbgen.ListMCPCapabilitiesParams{ServerID: sv.ID, Kind: kind})
	if err != nil {
		return nil, err
	}
	ps, err := LoadProviders(ctx, q)
	if err != nil {
		return nil, err
	}
	out := make([]CapabilityView, len(rows))
	for i, r := range rows {
		out[i] = CapabilityView{Capability: r.McpCapability, ApprovedByName: r.ApprovedByName, Published: sv.PublishState == StatePublished,
			Requires: EffectiveFor(sv, r.McpCapability, ps)}
	}
	return out, nil
}

func checkKind(kind *string) error {
	if kind != nil && !upstream.ValidKind(*kind) {
		return errInvalidKind
	}
	return nil
}

// ListCapabilities lists a team server's capabilities, gone ones included
// (members; platform admins and auditors).
func (s *Service) ListCapabilities(ctx context.Context, a authz.Actor, ref string, id uuid.UUID, kind *string) ([]CapabilityView, error) {
	ta, err := access(ctx, s.q, a, ref)
	if err != nil {
		return nil, err
	}
	sv, err := teamServer(ctx, s.q, ta.team.ID, id, false)
	if err != nil {
		return nil, err
	}
	if err := checkKind(kind); err != nil {
		return nil, err
	}
	return capabilities(ctx, s.q, sv, kind)
}

// AdminListCapabilities lists any server's capabilities (platform admins
// and auditors).
func (s *Service) AdminListCapabilities(ctx context.Context, a authz.Actor, id uuid.UUID, kind *string) ([]CapabilityView, error) {
	if !a.CanReadPlatform() {
		return nil, errPlatformRead
	}
	sv, err := anyServer(ctx, s.q, id, false)
	if err != nil {
		return nil, err
	}
	if err := checkKind(kind); err != nil {
		return nil, err
	}
	return capabilities(ctx, s.q, sv, kind)
}

// maxHealthChecks is how many checks the API lists.
const maxHealthChecks = 50

// HealthChecks lists a team server's recent checks, newest first.
func (s *Service) HealthChecks(ctx context.Context, a authz.Actor, ref string, id uuid.UUID) ([]dbgen.McpHealthCheck, error) {
	ta, err := access(ctx, s.q, a, ref)
	if err != nil {
		return nil, err
	}
	if _, err := teamServer(ctx, s.q, ta.team.ID, id, false); err != nil {
		return nil, err
	}
	return s.q.ListMCPHealthChecks(ctx, dbgen.ListMCPHealthChecksParams{ServerID: id, PageSize: maxHealthChecks})
}

// AdminHealthChecks lists any server's recent checks, newest first
// (platform admins and auditors).
func (s *Service) AdminHealthChecks(ctx context.Context, a authz.Actor, id uuid.UUID) ([]dbgen.McpHealthCheck, error) {
	if !a.CanReadPlatform() {
		return nil, errPlatformRead
	}
	if _, err := anyServer(ctx, s.q, id, false); err != nil {
		return nil, err
	}
	return s.q.ListMCPHealthChecks(ctx, dbgen.ListMCPHealthChecksParams{ServerID: id, PageSize: maxHealthChecks})
}
