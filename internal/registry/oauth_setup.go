package registry

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/ncecere/open-mcp-portal/internal/apperr"
	"github.com/ncecere/open-mcp-portal/internal/audit"
	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/store"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/internal/teams"
	"github.com/ncecere/open-mcp-portal/internal/upstream"
	"github.com/ncecere/open-mcp-portal/internal/upstream/oauthmeta"
)

// OAuthView is an oauth server's sign-in as the API shows it: never the
// client secret.
type OAuthView struct {
	Provider dbgen.AuthProvider
	// Linked is the platform provider whose client it uses (nil: none).
	Linked          *Provider
	ConnectionCount int64
	Setup           SetupConnection
}

// SetupConnection is the setup connection's state (decision 42).
type SetupConnection struct {
	Status       string
	PersonID     uuid.NullUUID
	PersonName   *string
	AuthorizedAt *time.Time
}

// setupStatus is a server's setup connection now: it counts only while its
// person is active and an editor or above of the team.
func setupStatus(ctx context.Context, q *dbgen.Queries, sv dbgen.McpServer, providerID uuid.UUID) (SetupConnection, error) {
	out := SetupConnection{Status: SetupMissing}
	if !sv.OauthSetupUserID.Valid {
		return out, nil
	}
	uid := sv.OauthSetupUserID.UUID
	u, err := q.GetUser(ctx, uid)
	if errors.Is(store.NotFound(err), store.ErrNotFound) {
		return out, nil
	} else if err != nil {
		return out, err
	}
	name := u.DisplayName
	if name == "" {
		name = u.Email
	}
	out.PersonID, out.PersonName, out.AuthorizedAt = sv.OauthSetupUserID, &name, sv.OauthSetupAt
	role, err := teams.MemberRole(ctx, q, sv.TeamID, uid)
	if err != nil {
		return out, err
	}
	if u.Status != "active" || authz.CheckServerEdit(role) != nil {
		return out, nil
	}
	c, err := q.GetProviderConnection(ctx, dbgen.GetProviderConnectionParams{UserID: uid, ProviderID: providerID})
	switch {
	case errors.Is(store.NotFound(err), store.ErrNotFound):
		return out, nil
	case err != nil:
		return out, err
	case c.Status == "active":
		out.Status = SetupActive
	default:
		out.Status = SetupNeedsReconsent
	}
	return out, nil
}

// SetupStatus is a server's setup connection now (internal/providers).
func SetupStatus(ctx context.Context, q *dbgen.Queries, sv dbgen.McpServer, providerID uuid.UUID) (SetupConnection, error) {
	return setupStatus(ctx, q, sv, providerID)
}

// oauthViews completes oauth servers' views with their sign-in.
func oauthViews(ctx context.Context, q *dbgen.Queries, out []ServerView, index map[uuid.UUID]int, ps Providers) error {
	var ids []uuid.UUID
	for _, v := range out {
		if AuthModeOf(v.Server) == AuthOAuth {
			ids = append(ids, v.Server.ID)
		}
	}
	if len(ids) == 0 {
		return nil
	}
	rows, err := q.ServerProviders(ctx, ids)
	if err != nil {
		return err
	}
	for _, r := range rows {
		v := &out[index[r.AuthProvider.ServerID.UUID]]
		ov := &OAuthView{Provider: r.AuthProvider, ConnectionCount: r.ConnectionCount}
		if r.AuthProvider.LinkProviderID.Valid {
			if p, ok := ps.Get(r.AuthProvider.LinkProviderID.UUID); ok {
				ov.Linked = &p
			}
		}
		if ov.Setup, err = setupStatus(ctx, q, v.Server, r.AuthProvider.ID); err != nil {
			return err
		}
		v.OAuth = ov
	}
	return nil
}

// RefreshAsSetup reads an oauth server's capabilities with its (just made)
// setup connection, as actor. Audited as mcp_server.refresh; a failure is
// stored as the refresh error.
func (s *Service) RefreshAsSetup(ctx context.Context, a authz.Actor, serverID uuid.UUID) error {
	sv, err := s.q.GetMCPServer(ctx, serverID)
	if err != nil {
		return err
	}
	_, _, err = s.refresh(ctx, a, sv)
	return err
}

// SetSetupConnection makes a person's sign-in the server's setup
// connection, in the caller's transaction. Audited as mcp_server.auth_update
// with setupBy.
func SetSetupConnection(ctx context.Context, q *dbgen.Queries, a authz.Actor, serverID uuid.UUID, person string) (dbgen.McpServer, error) {
	cur, err := q.LockMCPServer(ctx, serverID)
	if err != nil {
		return cur, err
	}
	row, err := q.SetMCPServerOAuthSetup(ctx, dbgen.SetMCPServerOAuthSetupParams{ID: serverID, UserID: by(a)})
	if errors.Is(store.NotFound(err), store.ErrNotFound) {
		return cur, apperr.Conflict("not_oauth", "The server isn't in oauth mode")
	} else if err != nil {
		return cur, err
	}
	e := a.Audit("mcp_server.auth_update", "mcp_server", serverID.String())
	e.TeamID = row.TeamID
	before := map[string]any{"setupBy": nil}
	if cur.OauthSetupUserID.Valid {
		before["setupBy"] = cur.OauthSetupUserID.UUID.String()
	}
	e.Before, e.After = before, map[string]any{"setupBy": a.UserID.String()}
	e.Metadata = map[string]any{"name": row.Name, "setupBy": person}
	return row, audit.Record(ctx, q, e)
}

// OAuthServer returns a team server in oauth mode with its provider, for
// starting the setup sign-in (editors and above; 409 not_oauth).
func (s *Service) OAuthServer(ctx context.Context, a authz.Actor, ref string, id uuid.UUID) (dbgen.McpServer, dbgen.AuthProvider, string, error) {
	ta, err := access(ctx, s.q, a, ref)
	if err != nil {
		return dbgen.McpServer{}, dbgen.AuthProvider{}, "", err
	}
	if err := ta.writable(authz.CheckServerEdit); err != nil {
		return dbgen.McpServer{}, dbgen.AuthProvider{}, "", err
	}
	sv, err := teamServer(ctx, s.q, ta.team.ID, id, false)
	if err != nil {
		return dbgen.McpServer{}, dbgen.AuthProvider{}, "", err
	}
	if AuthModeOf(sv) != AuthOAuth {
		return sv, dbgen.AuthProvider{}, "", apperr.Conflict("not_oauth", "The server isn't in oauth mode")
	}
	p, err := s.q.GetServerProvider(ctx, uuid.NullUUID{UUID: sv.ID, Valid: true})
	if err != nil {
		return sv, p, "", err
	}
	return sv, p, ta.team.Slug, nil
}

// createMode is a new server's auth mode.
func createMode(in CreateInput) (string, error) {
	if in.MachineOAuth != nil && in.AuthMode != AuthMachineOAuth {
		return "", apperr.Invalid("invalid_machine_oauth", "machineOAuth is for authMode machine_oauth only")
	}
	has := in.AuthHeaderName != "" || in.AuthValue != "" || len(in.Credentials) > 0
	switch in.AuthMode {
	case "":
		if has {
			return AuthStaticHeader, nil
		}
		return AuthNone, nil
	case AuthNone:
		if has {
			return "", apperr.Invalid("invalid_auth_header", "authMode none has no static credential")
		}
	case AuthStaticHeader:
		if in.AuthHeaderName == "" && len(in.Credentials) == 0 {
			return "", apperr.Invalid("invalid_auth_header", "Enter the static header's name and value")
		}
	case AuthOAuth:
		return AuthOAuth, nil
	case AuthPersonSecret:
		if in.PersonSecret == nil {
			return "", invalidSecretConfig("placement", "Choose how each person's secret is sent: personSecret is required in person_secret mode")
		}
		return AuthPersonSecret, nil
	case AuthMachineOAuth:
		if in.MachineOAuth == nil {
			return "", errMachineRequired
		}
		return AuthMachineOAuth, nil
	default:
		return "", apperr.Invalid("invalid_auth_mode", "authMode must be none, static_header, oauth, person_secret or machine_oauth")
	}
	// An oauth input without oauth mode is ignored (clients may always send
	// it with its defaults).
	return in.AuthMode, nil
}

// checkCreateCredentials checks the parts of a new server: valid, none kept
// (nothing is stored yet) and not together with the single header's fields.
func checkCreateCredentials(in CreateInput) error {
	if len(in.Credentials) == 0 {
		return nil
	}
	if in.AuthHeaderName != "" || in.AuthValue != "" {
		return apperr.Invalid("invalid_auth_header", "Send either authHeaderName and authValue or credentials, not both")
	}
	for i, c := range in.Credentials {
		if c.Keep {
			return invalidCredential(i, "invalid_credential", "A new server has no stored part to keep")
		}
	}
	return checkCredentialShape(in.Credentials)
}

// createAuthorization is "Authorization" when a new server's credential sets
// that header, for oauthConflicts.
func createAuthorization(in CreateInput) string {
	for _, c := range in.Credentials {
		if occupiesAuthorization(c.Kind, c.Name) {
			return "Authorization"
		}
	}
	return in.AuthHeaderName
}

// oauthConflicts: oauth mode excludes a static Authorization header and a
// Phase 5 requirement (one credential per call; decision 39).
func oauthConflicts(header string, requirement bool) error {
	switch {
	case strings.EqualFold(header, "Authorization"):
		return unprocessable("auth_conflict", "A server in oauth mode can't also have a static Authorization header",
			map[string]any{"reason": "static_authorization"})
	case requirement:
		return unprocessable("auth_conflict", "A server in oauth mode can't also have a user authorization requirement",
			map[string]any{"reason": "requirement"})
	}
	return nil
}

// probeSignIn is a scheduled check of an oauth server: an unauthenticated
// initialize, using nobody's token. The expected 401 Bearer challenge for
// this resource counts as healthy (sign-in required).
func (s *Service) probeSignIn(ctx context.Context, sv dbgen.McpServer, p dbgen.AuthProvider) TestResult {
	if _, err := s.client.NormalizeURL(ctx, sv.URL); err != nil {
		return TestResult{Err: &upstream.Error{Class: upstream.ClassNotAllowed, Message: errNotAllowedNow.Message}}
	}
	ctx, cancel := context.WithTimeout(ctx, timeout(sv))
	defer cancel()
	pr := s.fetcher().Probe(ctx, sv.URL)
	res := TestResult{Latency: pr.Latency}
	fail := func(class, msg string) TestResult {
		res.Err = &upstream.Error{Class: class, HTTPStatus: pr.Status, Message: msg}
		return res
	}
	switch {
	case pr.Result == oauthmeta.StepNotAllowed:
		return fail(upstream.ClassNotAllowed, errNotAllowedNow.Message)
	case pr.Result == oauthmeta.StepTimeout:
		return fail(upstream.ClassTimeout, "The server didn't answer in time.")
	case pr.Status == 0:
		return fail(upstream.ClassUnavailable, "The server couldn't be reached.")
	case pr.Status >= 200 && pr.Status < 300:
		res.OK, res.Note = true, "The server answered without sign-in."
		return res
	case pr.Status == http.StatusUnauthorized && pr.Challenge != nil:
		rm := pr.Challenge.ResourceMetadata()
		if rm == "" || rm == deref(p.ResourceMetadataUrl) {
			res.OK, res.SignInRequired, res.Note = true, true, "The server requires sign-in."
			return res
		}
		return fail(upstream.ClassAuth, "The server's sign-in challenge points at other resource metadata ("+upstream.SafeMessage(rm, "")+").")
	case pr.Status == http.StatusUnauthorized || pr.Status == http.StatusForbidden:
		return fail(upstream.ClassAuth, "The server refused the request without an OAuth challenge.")
	case pr.Status == http.StatusNotFound:
		return fail(upstream.ClassNotFound, "The server answered 404: check the URL.")
	case pr.Status == http.StatusTooManyRequests:
		return fail(upstream.ClassRateLimited, "The server is rate limiting requests (HTTP 429).")
	}
	return fail(upstream.ClassUnavailable, "The server answered HTTP "+strconv.Itoa(pr.Status)+".")
}
