package registry

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ncecere/open-mcp-portal/internal/apperr"
	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/store"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

// CreateInput registers a server. AuthHeaderName and AuthValue are both
// empty (no credentials) or both set; Credentials is the list of parts of its
// own credential instead (not together with them, never Keep).
type CreateInput struct {
	Slug, Name, Description, URL string
	AuthHeaderName, AuthValue    string
	Credentials                  []CredentialInput
	Endpoints                    *[]EndpointInput // nil omitted; owner/admin sessions only
	TimeoutSeconds               int32            // 0: the default (30)
	RateLimitPerMinute           *int64
	MaxConcurrent                *int32
	Enabled                      bool
	// Requirement is the user-authorization requirement (nil: none).
	Requirement *RequirementInput
	// CapturePayloads records calls' contents (team owners and admins only).
	CapturePayloads bool
	// AuthMode is none, static_header or oauth ("": static_header with a
	// header, else none); OAuth configures oauth.
	AuthMode string
	OAuth    *OAuthInput
	// MachineOAuth configures machine_oauth (required with it, refused
	// without it: it carries a secret).
	MachineOAuth *MachineOAuthInput
	// SendIdentity sends the identity token (nil: true, except authMode none
	// on a public or unresolvable host: false; decisions 45 and 64).
	SendIdentity *bool
	// PersonSecret says how each person's own secret is sent (authMode
	// person_secret only; required there, decision 72).
	PersonSecret *PersonSecretInput
	// TLS is the server's CA bundle and client certificate (nil: none).
	TLS *TLSInput
}

// errCaptureRole: only the server team's owners and admins switch capture.
var errCaptureRole = apperr.New(403, "capture_role",
	"Only the team's owners and admins can choose whether calls' contents are recorded")

// setCapture applies a capture switch change (docs/phase6-operations.md
// "Payload capture"): team owners and admins only; not a review trigger.
func setCapture(ctx context.Context, q *dbgen.Queries, role string, row *dbgen.McpServer, on bool) error {
	if row.CapturePayloads == on {
		return nil
	}
	if !authz.RoleAtLeast(role, authz.RoleAdmin) {
		return errCaptureRole
	}
	if err := q.SetMCPServerCapture(ctx, dbgen.SetMCPServerCaptureParams{ID: row.ID, CapturePayloads: on}); err != nil {
		return err
	}
	row.CapturePayloads = on
	return nil
}

func checkFields(name, description string, timeout int32) error {
	if n := len([]rune(strings.TrimSpace(name))); n < 1 || n > 100 {
		return apperr.Invalid("invalid_name", "Name must be 1-100 characters")
	}
	if len([]rune(description)) > 2000 {
		return apperr.Invalid("invalid_description", "Description must be at most 2000 characters")
	}
	if timeout < 1 || timeout > 120 {
		return apperr.Invalid("invalid_timeout", "Timeout must be between 1 and 120 seconds")
	}
	return nil
}

func checkHeader(name, value string) error {
	if !headerNameRE.MatchString(name) || reservedHeaders[strings.ToLower(name)] {
		return apperr.Invalid("invalid_auth_header", "The header name must be a valid HTTP header such as Authorization or X-API-Key")
	}
	if value == "" || len(value) > 4096 || strings.ContainsAny(value, "\r\n\x00") {
		return apperr.Invalid("invalid_auth_value", "The header value must be 1-4096 characters on one line")
	}
	return nil
}

// valueHint is the last four characters of a value of at least eight.
func valueHint(v string) string {
	r := []rune(v)
	if len(r) < 8 {
		return ""
	}
	return string(r[len(r)-4:])
}

// snapshot is a server's audited configuration: never the header value or
// its ciphertext, only whether one is set.
func snapshot(s dbgen.McpServer, parts ...CredentialView) map[string]any {
	out := map[string]any{"slug": s.Slug, "name": s.Name, "description": s.Description, "url": s.URL,
		"timeoutSeconds": s.TimeoutSeconds, "enabled": s.Enabled, "hasAuth": s.AuthValueCipher != nil,
		"rateLimitPerMinute": s.RateLimitPerMinute, "maxConcurrent": s.MaxConcurrent,
		"publishState": s.PublishState, "requirement": requirementSnapshot(s), "capturePayloads": s.CapturePayloads,
		"authMode": AuthModeOf(s), "sendIdentity": s.SendIdentity}
	if s.AuthHeaderName != nil {
		out["authHeaderName"] = *s.AuthHeaderName
	}
	if ps := secretSnapshot(s); ps != nil {
		out["personSecret"] = ps
	}
	if len(parts) > 0 {
		out["hasAuth"] = true
		out["credentials"] = credentialSnapshot(parts)
	}
	return out
}

// Created is the outcome of registering a server: the server, and its
// first discovery (Refresh when it worked, Failure when not).
type Created struct {
	View    ServerView
	Refresh *RefreshResult
	Failure *TestResult
	// SetupRequired: created in oauth mode, so nobody has signed in yet and
	// capabilities weren't read.
	SetupRequired bool
}

// Create registers a server (team editors and above) and reads its
// capabilities at once. The server is created even when that fails.
// Audited as mcp_server.create (and mcp_server.refresh when discovery works).
func (s *Service) Create(ctx context.Context, a authz.Actor, ref string, in CreateInput) (Created, error) {
	if in.Endpoints != nil && a.IsToken() {
		return Created{}, endpointTokenRefusal()
	}
	in.Slug = strings.TrimSpace(in.Slug)
	in.Name = strings.TrimSpace(in.Name)
	if in.TimeoutSeconds == 0 {
		in.TimeoutSeconds = defaultTimeoutSec
	}
	if err := s.authorizeCreateExtras(ctx, a, ref, in); err != nil {
		return Created{}, err
	}
	if err := checkCreateCredentials(in); err != nil {
		return Created{}, err
	}
	mode, err := createMode(in)
	if err != nil {
		return Created{}, err
	}
	id := uuid.New()
	pre := createPrep{mode: mode}
	if pre.endpoints, err = s.prepareCreateEndpoints(ctx, a, ref, id, &in, mode); err != nil {
		return Created{}, err
	}
	if pre.secret, err = createSecretConfig(in, mode); err != nil {
		return Created{}, err
	}
	if pre.plan, err = s.prepareCreateOAuth(ctx, a, ref, in, mode); err != nil {
		return Created{}, err
	}
	pre.sendIdentity = s.createSendIdentity(ctx, in, mode)
	err = store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		return s.createTx(ctx, q, a, ref, id, in, pre)
	})
	if err != nil {
		return Created{}, err
	}
	return s.created(ctx, a, id, mode)
}

// createPrep is what a creation decided before its transaction.
type createPrep struct {
	// mode is the server's auth mode.
	mode string
	// endpoints are the additional endpoints, normalized (nil: none sent).
	endpoints *[]EndpointInput
	// secret is the person secret configuration (nil: another mode).
	secret *PersonSecretInput
	// plan is the sign-in of a server in oauth mode (nil: another mode).
	plan *oauthPlan
	// sendIdentity is whether the identity token is sent.
	sendIdentity bool
}

// authorizeCreateExtras checks, before anything else, the roles that
// protection limits and additional endpoints need beyond an editor's.
func (s *Service) authorizeCreateExtras(ctx context.Context, a authz.Actor, ref string, in CreateInput) error {
	if in.RateLimitPerMinute == nil && in.MaxConcurrent == nil && in.Endpoints == nil {
		return nil
	}
	ta, err := access(ctx, s.q, a, ref)
	if err != nil {
		return err
	}
	if err := ta.writable(authz.CheckServerEdit); err != nil {
		return err
	}
	if err := s.checkProtection(ctx, s.q, ta.role, in.RateLimitPerMinute, in.MaxConcurrent, in.RateLimitPerMinute != nil || in.MaxConcurrent != nil); err != nil {
		return err
	}
	if in.Endpoints != nil {
		return checkEndpointRole(ta.role)
	}
	return nil
}

// prepareCreateEndpoints normalizes a new server's additional endpoints
// outside the transaction (nil: none sent). It also replaces in.URL with its
// normalized form, which the endpoints are compared with.
func (s *Service) prepareCreateEndpoints(ctx context.Context, a authz.Actor, ref string, id uuid.UUID, in *CreateInput, mode string) (*[]EndpointInput, error) {
	if in.Endpoints == nil {
		return nil, nil
	}
	ta, err := access(ctx, s.q, a, ref)
	if err != nil {
		return nil, err
	}
	tp, err := s.planTLS(id, nil, in.TLS, false, time.Now())
	if err != nil {
		return nil, err
	}
	if len(*in.Endpoints) > 0 {
		if err := checkEndpointMode(mode, in.Requirement != nil, !tp.next.empty()); err != nil {
			return nil, err
		}
	}
	if in.URL, err = s.client.NormalizeURL(ctx, in.URL); err != nil {
		return nil, err
	}
	return s.prepareEndpointChange(ctx, s.q, dbgen.McpServer{ID: id}, in.URL, mode, in.Requirement != nil, !tp.next.empty(), ta.role, in.Endpoints, true)
}

// createSecretConfig is a new server's person secret configuration (nil: the
// mode is not person_secret).
func createSecretConfig(in CreateInput, mode string) (*PersonSecretInput, error) {
	if mode != AuthPersonSecret {
		return nil, nil
	}
	cfg, err := normalizePersonSecret(*in.PersonSecret)
	if err != nil {
		return nil, err
	}
	if err := personSecretConflicts(cfg, createViews(in), in.Requirement != nil); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// prepareCreateOAuth plans the sign-in of a new server in oauth mode (nil:
// another mode).
func (s *Service) prepareCreateOAuth(ctx context.Context, a authz.Actor, ref string, in CreateInput, mode string) (*oauthPlan, error) {
	if mode != AuthOAuth {
		return nil, nil
	}
	// Discovery and registration happen before the transaction: check
	// what can be checked first.
	ta, err := access(ctx, s.q, a, ref)
	if err != nil {
		return nil, err
	}
	if err := ta.writable(authz.CheckServerEdit); err != nil {
		return nil, err
	}
	if err := oauthConflicts(createAuthorization(in), in.Requirement != nil); err != nil {
		return nil, err
	}
	if !slugRE.MatchString(in.Slug) {
		return nil, apperr.Invalid("invalid_slug",
			"Slug must be 1-48 lowercase letters, digits or hyphens, and cannot start or end with a hyphen")
	}
	if err := checkFields(in.Name, in.Description, in.TimeoutSeconds); err != nil {
		return nil, err
	}
	u, err := s.client.NormalizeURL(ctx, in.URL)
	if err != nil {
		return nil, err
	}
	return s.prepareOAuth(ctx, s.q, u, in.Name, in.OAuth, nil)
}

// createSendIdentity decides whether a new server is sent the identity token.
func (s *Service) createSendIdentity(ctx context.Context, in CreateInput, mode string) bool {
	// Send identity token: an explicit value is kept; else on, except for a
	// server with no authentication on a public (or unresolvable) host
	// (decision 64). The host lookup happens here, outside the transaction.
	sendIdentity := in.SendIdentity == nil || *in.SendIdentity
	if in.SendIdentity == nil && mode == AuthNone {
		if u, err := s.client.NormalizeURL(ctx, in.URL); err == nil {
			sendIdentity = s.defaultSendIdentity(ctx, mode, u).SendIdentity
		}
	}
	return sendIdentity
}

// created is Create's outcome once the server is stored: its view, and its
// first discovery unless somebody has to sign in first.
func (s *Service) created(ctx context.Context, a authz.Actor, id uuid.UUID, mode string) (Created, error) {
	sv, err := s.q.GetMCPServer(ctx, id)
	if err != nil {
		return Created{}, err
	}
	var out Created
	if mode == AuthOAuth || mode == AuthPersonSecret {
		// Nobody has signed in (or entered a key) yet: capabilities are read
		// after the setup sign-in (authorize-setup), or after an editor enters
		// their own key and chooses to read the server with it.
		out.SetupRequired = true
		out.View, err = s.view(ctx, s.q, id)
		return out, err
	}
	res, fail, err := s.refresh(ctx, a, sv)
	if err != nil {
		return Created{}, err
	}
	out.Refresh, out.Failure = res, fail
	out.View, err = s.view(ctx, s.q, id)
	return out, err
}
