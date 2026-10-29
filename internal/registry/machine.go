package registry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"

	"github.com/google/uuid"

	"github.com/ncecere/open-mcp-portal/internal/apperr"
	"github.com/ncecere/open-mcp-portal/internal/audit"
	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/store"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/internal/upstream"
)

// Machine OAuth (decision 73, docs/machine-oauth.md): a server whose own
// authorization server authenticates the portal, not a person. The team enters
// the token endpoint, a client ID and secret, the scopes and optionally an
// audience or resource; the portal gets a token with the client credentials
// grant (internal/upstream, MachineTokens), keeps it in memory and sends it as
// Authorization: Bearer to the server's stored URL on every request to it:
// discovery, health checks, Test and forwarded calls, for every caller alike.
// The identity token moves to MCP-Gateway-Identity.
//
// The secret is sealed with ENCRYPTION_KEY (AAD machine_oauth:<server id>) and
// never shown, logged or audited. It goes to one place only, the token endpoint
// it was entered for (F-1): another token endpoint, another client or another
// origin of the server's URL needs it entered again in the same request.

// AuthMachineOAuth is the auth mode of a server that authenticates the portal
// with a token from the client credentials grant.
const AuthMachineOAuth = "machine_oauth"

// Token endpoint authentication methods of a machine client.
const (
	MachineAuthBasic = upstream.MachineAuthBasic
	MachineAuthPost  = upstream.MachineAuthPost
)

// MachineSecretAAD binds a machine client's sealed secret to its server.
func MachineSecretAAD(serverID uuid.UUID) []byte { return []byte("machine_oauth:" + serverID.String()) }

const noteMachineAuthChanged = "The portal's own OAuth client for this server changed; review it again."

// MachineOAuthInput configures a server's machine client; nil fields keep
// their stored values (update). ClientSecret is write-only. Audience and
// Resource: "" removes the stored value.
type MachineOAuthInput struct {
	TokenURL, ClientID, ClientSecret, TokenAuthMethod *string
	Scopes                                            *[]string
	Audience, Resource                                *string
}

// MachineOAuthView is a server's machine client as the API shows it: never
// the secret (only whether one is stored, and its hint).
type MachineOAuthView struct {
	TokenURL, ClientID, TokenAuthMethod string
	SecretHint                          string
	Scopes                              []string
	Audience, Resource                  string
}

func machineViewOf(r dbgen.McpServerMachineOauth) *MachineOAuthView {
	return &MachineOAuthView{TokenURL: r.TokenUrl, ClientID: r.ClientID, TokenAuthMethod: r.TokenAuthMethod, SecretHint: r.ClientSecretHint,
		Scopes: nonNil(r.Scopes), Audience: deref(r.Audience), Resource: deref(r.Resource)}
}

// machineViews are the machine clients of the listed servers in machine
// mode, by server ID.
func machineViews(ctx context.Context, q *dbgen.Queries, servers []dbgen.McpServer) (map[uuid.UUID]*MachineOAuthView, error) {
	var ids []uuid.UUID
	for _, sv := range servers {
		if AuthModeOf(sv) == AuthMachineOAuth {
			ids = append(ids, sv.ID)
		}
	}
	out := map[uuid.UUID]*MachineOAuthView{}
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := q.ListMachineOAuthFor(ctx, ids)
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		out[r.ServerID] = machineViewOf(r)
	}
	return out, nil
}

// machineSnapshot is a server's machine auth as audited: the mode, the token
// endpoint, the method, the scopes, the audience and resource. Never the
// secret, its hint or the client ID (decision 39 keeps client IDs out of the
// audit log; clientIdChanged says when one changed).
func machineSnapshot(sv dbgen.McpServer, m *MachineOAuthView) map[string]any {
	out := map[string]any{"authMode": AuthModeOf(sv), "machineOAuth": nil, "sendIdentity": sv.SendIdentity}
	if m == nil || AuthModeOf(sv) != AuthMachineOAuth {
		return out
	}
	o := map[string]any{"tokenUrl": m.TokenURL, "tokenAuthMethod": m.TokenAuthMethod, "scopes": nonNil(m.Scopes)}
	if m.Audience != "" {
		o["audience"] = m.Audience
	}
	if m.Resource != "" {
		o["resource"] = m.Resource
	}
	out["machineOAuth"] = o
	return out
}

func machineInvalid(field, code, msg string) error {
	e := apperr.Invalid(code, msg)
	e.Details = map[string]any{"field": "machineOAuth." + field}
	return e
}

var errMachineRequired = apperr.Invalid("invalid_machine_oauth",
	"Enter the token endpoint, the client ID and the client secret for authMode machine_oauth")

// errMachineSecretRequired is the F-1 refusal: the secret was entered for a
// token endpoint, a client and a server origin, and none of them changes
// without it entered again in the same request.
func errMachineSecretRequired(reason string) error {
	return unprocessable("client_secret_required",
		"The client secret was entered for another token endpoint, client or server host: enter it again.",
		map[string]any{"field": "machineOAuth.clientSecret", "reason": reason})
}

// machinePlan is a machine client change: the row to store and what the
// change means.
type machinePlan struct {
	row  dbgen.UpsertMachineOAuthParams
	view *MachineOAuthView
	// before is the stored client (nil: the server had none).
	before *MachineOAuthView
	// changed: anything about the client changes (a new secret included).
	changed bool
	// secretChanged: a new secret was entered.
	secretChanged bool
	// review: what the server sends or where changes (a new token endpoint,
	// client, scope, audience or resource, or the switch to this mode); a new
	// secret alone does not.
	review bool
	// tokenURLChanged, clientIDChanged say which of the two did.
	tokenURLChanged, clientIDChanged bool
}

// planMachine works out a server's machine client after an update (or its
// creation: stored is then nil) in the mode the server will have: the values
// that stay come from the stored row, the secret is sealed when entered, and
// the F-1 rule is applied: the secret must be entered again when the token
// endpoint, the client ID or the origin of the server's URL changes (nothing
// is sent anywhere; the refusal is before anything is stored). cur is the
// server as it is, newURL its URL after the change.
func (s *Service) planMachine(ctx context.Context, q *dbgen.Queries, cur dbgen.McpServer, newURL string, in *MachineOAuthInput) (*machinePlan, error) {
	var stored *dbgen.McpServerMachineOauth
	if AuthModeOf(cur) == AuthMachineOAuth {
		row, err := q.GetMachineOAuth(ctx, cur.ID)
		switch {
		case err == nil:
			stored = &row
		case !errors.Is(store.NotFound(err), store.ErrNotFound):
			return nil, err
		}
	}
	if in == nil {
		in = &MachineOAuthInput{}
	}
	if stored == nil && (in.TokenURL == nil || in.ClientID == nil) {
		return nil, errMachineRequired
	}
	p := &machinePlan{}
	if stored != nil {
		p.before = machineViewOf(*stored)
	}
	tokenURL, clientID, method, scopes := "", "", MachineAuthBasic, []string{}
	var audience, resource string
	if stored != nil {
		tokenURL, clientID, method, scopes = stored.TokenUrl, stored.ClientID, stored.TokenAuthMethod, nonNil(stored.Scopes)
		audience, resource = deref(stored.Audience), deref(stored.Resource)
	}
	if in.TokenURL != nil {
		raw := strings.TrimSpace(*in.TokenURL)
		if raw == "" {
			return nil, machineInvalid("tokenUrl", "invalid_token_url", "Enter the authorization server's token endpoint")
		}
		u, err := s.client.NormalizeURL(ctx, raw)
		if err != nil {
			if e, ok := apperr.As(err); ok {
				d, _ := e.Details.(map[string]any)
				e.Details = withField(d, "machineOAuth.tokenUrl")
			}
			return nil, err
		}
		tokenURL = u
	}
	if in.ClientID != nil {
		clientID = strings.TrimSpace(*in.ClientID)
		if n := len(clientID); n < 1 || n > 500 || strings.ContainsAny(clientID, "\r\n\x00") {
			return nil, machineInvalid("clientId", "invalid_client_id", "The client ID must be 1-500 characters on one line")
		}
	}
	if in.TokenAuthMethod != nil {
		method = *in.TokenAuthMethod
		if method != MachineAuthBasic && method != MachineAuthPost {
			return nil, machineInvalid("tokenAuthMethod", "invalid_token_auth_method", "tokenAuthMethod must be client_secret_basic or client_secret_post")
		}
	}
	if in.Scopes != nil {
		var err error
		if scopes, err = NormalizeScopes(*in.Scopes); err != nil {
			return nil, err
		}
	}
	if in.Audience != nil {
		audience = strings.TrimSpace(*in.Audience)
		if len(audience) > 500 || strings.ContainsAny(audience, "\r\n\x00") {
			return nil, machineInvalid("audience", "invalid_audience", "The audience must be at most 500 characters on one line")
		}
	}
	if in.Resource != nil {
		resource = strings.TrimSpace(*in.Resource)
		if err := checkMachineResource(resource); err != nil {
			return nil, err
		}
	}
	p.tokenURLChanged = stored != nil && stored.TokenUrl != tokenURL
	p.clientIDChanged = stored != nil && stored.ClientID != clientID
	// F-1: the secret belongs to the token endpoint and client it was entered
	// for and to the origin of the server the token is sent to.
	if in.ClientSecret == nil {
		switch {
		case stored == nil:
			return nil, errMachineSecretRequired("new")
		case p.tokenURLChanged:
			return nil, errMachineSecretRequired("token_url_changed")
		case p.clientIDChanged:
			return nil, errMachineSecretRequired("client_id_changed")
		case !sameOrigin(cur.URL, newURL):
			return nil, errMachineSecretRequired("origin_changed")
		}
	}
	row := dbgen.UpsertMachineOAuthParams{ServerID: cur.ID, TokenUrl: tokenURL, ClientID: clientID, TokenAuthMethod: method, Scopes: scopes,
		Audience: optString(audience), Resource: optString(resource)}
	if in.ClientSecret != nil {
		sec := *in.ClientSecret
		if sec == "" || len(sec) > 2000 || strings.ContainsAny(sec, "\r\n\x00") {
			return nil, machineInvalid("clientSecret", "invalid_client_secret", "The client secret must be 1-2000 characters on one line")
		}
		ct, err := s.box.Seal([]byte(sec), MachineSecretAAD(cur.ID))
		if err != nil {
			return nil, err
		}
		row.ClientSecretCipher, row.ClientSecretHint = ct, valueHint(sec)
		p.secretChanged = true
	} else {
		row.ClientSecretCipher, row.ClientSecretHint = stored.ClientSecretCipher, stored.ClientSecretHint
	}
	p.row = row
	p.view = &MachineOAuthView{TokenURL: tokenURL, ClientID: clientID, TokenAuthMethod: method, SecretHint: row.ClientSecretHint,
		Scopes: scopes, Audience: audience, Resource: resource}
	switch {
	case stored == nil:
		p.changed, p.review = true, true
	default:
		p.changed = p.secretChanged || p.tokenURLChanged || p.clientIDChanged || stored.TokenAuthMethod != method ||
			!slices.Equal(nonNil(stored.Scopes), scopes) || deref(stored.Audience) != audience || deref(stored.Resource) != resource
		p.review = p.tokenURLChanged || p.clientIDChanged || widensScopes(nonNil(stored.Scopes), scopes) ||
			deref(stored.Audience) != audience || deref(stored.Resource) != resource
	}
	return p, nil
}

func withField(d map[string]any, field string) map[string]any {
	out := map[string]any{}
	for k, v := range d {
		out[k] = v
	}
	out["field"] = field
	return out
}

// checkMachineResource: "" (none) or an absolute URI without a fragment (RFC
// 8707 section 2).
func checkMachineResource(v string) error {
	if v == "" {
		return nil
	}
	u, err := url.Parse(v)
	if len(v) > 500 || strings.ContainsAny(v, "\r\n\x00") || err != nil || u.Scheme == "" || u.Host == "" || u.Fragment != "" {
		return machineInvalid("resource", "invalid_resource", "The resource must be an absolute URI without a fragment, at most 500 characters")
	}
	return nil
}

// machineConflicts: machine_oauth mode excludes a static Authorization header
// and a user authorization requirement (one credential per call; the same
// rule as oauth mode).
func machineConflicts(header string, requirement bool) error {
	switch {
	case strings.EqualFold(header, "Authorization"):
		return unprocessable("auth_conflict", "A server in machine_oauth mode can't also have a static Authorization header",
			map[string]any{"reason": "static_authorization"})
	case requirement:
		return unprocessable("auth_conflict", "A server in machine_oauth mode can't also have a user authorization requirement",
			map[string]any{"reason": "requirement"})
	}
	return nil
}

// machineAuditMeta is mcp_server.auth_update's metadata for a machine client
// change.
func machineAuditMeta(sv dbgen.McpServer, p *machinePlan) map[string]any {
	meta := map[string]any{"name": sv.Name}
	if p != nil {
		meta["clientSecretChanged"] = p.secretChanged
		meta["clientIdChanged"] = p.clientIDChanged || p.before == nil
		meta["tokenUrlChanged"] = p.tokenURLChanged || p.before == nil
	}
	return meta
}

// applyMachine stores an update's machine client in its transaction and
// audits it (mcp_server.auth_update): the new client (plan), or none when the
// server leaves the mode. It reports whether the change needs review again.
func (s *Service) applyMachine(ctx context.Context, q *dbgen.Queries, a authz.Actor, cur, row dbgen.McpServer, plan *machinePlan) (bool, error) {
	before, after := AuthModeOf(cur), AuthModeOf(row)
	switch {
	case after == AuthMachineOAuth && plan != nil:
		if !plan.changed && before == after && cur.SendIdentity == row.SendIdentity {
			return false, nil
		}
		if plan.changed {
			p := plan.row
			p.By = by(a)
			if _, err := q.UpsertMachineOAuth(ctx, p); err != nil {
				return false, err
			}
		}
		e := a.Audit("mcp_server.auth_update", "mcp_server", row.ID.String())
		e.TeamID = row.TeamID
		e.Before, e.After = machineSnapshot(cur, plan.before), machineSnapshot(row, plan.view)
		e.Metadata = machineAuditMeta(row, plan)
		if err := audit.Record(ctx, q, e); err != nil {
			return false, err
		}
		return plan.review, nil
	case before == AuthMachineOAuth && after != AuthMachineOAuth:
		old, err := q.GetMachineOAuth(ctx, cur.ID)
		if err != nil && !errors.Is(store.NotFound(err), store.ErrNotFound) {
			return false, err
		}
		if err := q.DeleteMachineOAuth(ctx, cur.ID); err != nil {
			return false, err
		}
		e := a.Audit("mcp_server.auth_update", "mcp_server", row.ID.String())
		e.TeamID = row.TeamID
		var prev *MachineOAuthView
		if err == nil {
			prev = machineViewOf(old)
		}
		e.Before, e.After = machineSnapshot(cur, prev), machineSnapshot(row, nil)
		e.Metadata = map[string]any{"name": row.Name, "machineOAuthRemoved": true}
		return false, audit.Record(ctx, q, e)
	}
	return false, nil
}

// machineConfig opens a server's machine client for a token request: the
// secret is decrypted here, in memory, for the length of the request.
func (s *Service) machineConfig(ctx context.Context, sv dbgen.McpServer) (upstream.MachineConfig, *upstream.Error) {
	row, err := s.q.GetMachineOAuth(ctx, sv.ID)
	if err != nil {
		return upstream.MachineConfig{}, &upstream.Error{Class: upstream.ClassConfig, Message: "The server's machine OAuth client isn't configured."}
	}
	secret, err := s.box.Open(row.ClientSecretCipher, MachineSecretAAD(sv.ID))
	if err != nil {
		return upstream.MachineConfig{}, &upstream.Error{Class: upstream.ClassConfig,
			Message: "The stored client secret can't be decrypted with the current ENCRYPTION_KEY. Enter it again."}
	}
	return upstream.MachineConfig{ServerID: sv.ID.String(), TokenURL: row.TokenUrl, ClientID: row.ClientID, ClientSecret: string(secret),
		AuthMethod: row.TokenAuthMethod, Scopes: nonNil(row.Scopes), Audience: deref(row.Audience), Resource: deref(row.Resource)}, nil
}

// machineToken is the bearer token for a server in machine_oauth mode, from
// memory or from its authorization server. rejected is a token the server just
// refused with 401 ("": none): it is dropped and another one is fetched. A
// failure is an *upstream.Error: class auth when the authorization server
// refused the client, else (with Reason machine_auth_unavailable) its
// availability.
func (s *Service) machineToken(ctx context.Context, sv dbgen.McpServer, rejected string) (string, *upstream.Error) {
	cfg, uerr := s.machineConfig(ctx, sv)
	if uerr != nil {
		return "", uerr
	}
	tok, merr := s.machine.Renew(ctx, cfg, rejected)
	if merr != nil {
		return "", merr.AsError()
	}
	return tok, nil
}

// RenewMachineToken drops the bearer token a server in machine_oauth mode
// refused with 401 and returns another (or the one a concurrent call already
// fetched): one request to the token endpoint however many calls were
// refused. The call that was refused did not run, so it may be retried once.
func (s *Service) RenewMachineToken(ctx context.Context, sv dbgen.McpServer, rejected string) (string, error) {
	tok, err := s.machineToken(ctx, sv, rejected)
	if err != nil {
		return "", err
	}
	return tok, nil
}

// MachineIdentity is a digest of a machine_oauth server's NON-secret client
// identity and configuration (token endpoint, client ID, authentication method,
// scopes, audience and resource): never the client secret or a token. A task
// binds to it so a lifecycle operation notices a changed client, while a mere
// secret rotation or a fresh token does not.
func (s *Service) MachineIdentity(ctx context.Context, sv dbgen.McpServer) (string, error) {
	row, err := s.q.GetMachineOAuth(ctx, sv.ID)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	for _, part := range append([]string{row.TokenUrl, row.ClientID, row.TokenAuthMethod, deref(row.Audience), deref(row.Resource)}, row.Scopes...) {
		fmt.Fprintf(h, "%d:%s\n", len(part), part)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// MachineTokens is the token source (tests inspect and drive its clock).
func (s *Service) MachineTokens() *upstream.MachineTokens { return s.machine }

// MachineDetection is what detect-auth says about the client credentials
// grant at the authorization server it found.
type MachineDetection struct {
	// TokenEndpoint is the authorization server's token endpoint.
	TokenEndpoint string
	// GrantTypesListed says grant_types_supported was in its metadata; when it
	// was not, ClientCredentials is false only because nothing says it works
	// (RFC 8414 defaults the list to authorization_code and implicit).
	GrantTypesListed bool
	// ClientCredentials: client_credentials is in grant_types_supported.
	ClientCredentials bool
	// AuthMethods are the token endpoint authentication methods it lists that
	// the portal can use (client_secret_basic, client_secret_post).
	AuthMethods []string
	// Resource is the protected resource identifier its server's metadata
	// gave, to send as the resource parameter when the authorization server
	// supports it.
	Resource string
}
