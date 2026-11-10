package registry

import (
	"context"
	"errors"
	"net/url"
	"slices"
	"strings"

	"github.com/google/uuid"

	"github.com/ncecere/open-mcp-portal/internal/apperr"
	"github.com/ncecere/open-mcp-portal/internal/store"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

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
	stored, err := storedMachine(ctx, q, cur)
	if err != nil {
		return nil, err
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
	f, err := s.machineSettingsAfter(ctx, stored, in)
	if err != nil {
		return nil, err
	}
	p.tokenURLChanged = stored != nil && stored.TokenUrl != f.tokenURL
	p.clientIDChanged = stored != nil && stored.ClientID != f.clientID
	// F-1: the secret belongs to the token endpoint and client it was entered
	// for and to the origin of the server the token is sent to.
	if in.ClientSecret == nil {
		if err := machineSecretReusable(stored, p, cur.URL, newURL); err != nil {
			return nil, err
		}
	}
	row := dbgen.UpsertMachineOAuthParams{ServerID: cur.ID, TokenUrl: f.tokenURL, ClientID: f.clientID, TokenAuthMethod: f.method, Scopes: f.scopes,
		Audience: optString(f.audience), Resource: optString(f.resource)}
	if in.ClientSecret != nil {
		if row.ClientSecretCipher, row.ClientSecretHint, err = s.sealMachineSecret(cur.ID, *in.ClientSecret); err != nil {
			return nil, err
		}
		p.secretChanged = true
	} else {
		row.ClientSecretCipher, row.ClientSecretHint = stored.ClientSecretCipher, stored.ClientSecretHint
	}
	p.row = row
	p.view = &MachineOAuthView{TokenURL: f.tokenURL, ClientID: f.clientID, TokenAuthMethod: f.method, SecretHint: row.ClientSecretHint,
		Scopes: f.scopes, Audience: f.audience, Resource: f.resource}
	p.changed, p.review = machineChange(stored, p, f)
	return p, nil
}

// sealMachineSecret validates a client secret entered for a server and seals
// it for that server; it returns the ciphertext and the secret's hint.
func (s *Service) sealMachineSecret(serverID uuid.UUID, sec string) ([]byte, string, error) {
	if sec == "" || len(sec) > 2000 || strings.ContainsAny(sec, "\r\n\x00") {
		return nil, "", machineInvalid("clientSecret", "invalid_client_secret", "The client secret must be 1-2000 characters on one line")
	}
	ct, err := s.box.Seal([]byte(sec), MachineSecretAAD(serverID))
	if err != nil {
		return nil, "", err
	}
	return ct, valueHint(sec), nil
}

// machineChange reports whether anything about the client changes against
// the stored one (nil: none), and whether the change needs review again.
func machineChange(stored *dbgen.McpServerMachineOauth, p *machinePlan, f machineSettings) (changed, review bool) {
	if stored == nil {
		return true, true
	}
	changed = p.secretChanged || p.tokenURLChanged || p.clientIDChanged || stored.TokenAuthMethod != f.method ||
		!slices.Equal(nonNil(stored.Scopes), f.scopes) || deref(stored.Audience) != f.audience || deref(stored.Resource) != f.resource
	review = p.tokenURLChanged || p.clientIDChanged || widensScopes(nonNil(stored.Scopes), f.scopes) ||
		deref(stored.Audience) != f.audience || deref(stored.Resource) != f.resource
	return changed, review
}

// storedMachine is the machine client stored for a server in machine_oauth
// mode (nil: another mode, or none stored).
func storedMachine(ctx context.Context, q *dbgen.Queries, cur dbgen.McpServer) (*dbgen.McpServerMachineOauth, error) {
	if AuthModeOf(cur) != AuthMachineOAuth {
		return nil, nil
	}
	row, err := q.GetMachineOAuth(ctx, cur.ID)
	switch {
	case err == nil:
		return &row, nil
	case !errors.Is(store.NotFound(err), store.ErrNotFound):
		return nil, err
	}
	return nil, nil
}

// machineSettings are a machine client's settings, the secret aside.
type machineSettings struct {
	tokenURL, clientID, method string
	scopes                     []string
	audience, resource         string
}

// machineSettingsAfter is the stored settings (nil: the defaults) with the
// request's applied, each one validated.
func (s *Service) machineSettingsAfter(ctx context.Context, stored *dbgen.McpServerMachineOauth, in *MachineOAuthInput) (machineSettings, error) {
	f := machineSettings{method: MachineAuthBasic, scopes: []string{}}
	if stored != nil {
		f.tokenURL, f.clientID, f.method, f.scopes = stored.TokenUrl, stored.ClientID, stored.TokenAuthMethod, nonNil(stored.Scopes)
		f.audience, f.resource = deref(stored.Audience), deref(stored.Resource)
	}
	if in.TokenURL != nil {
		u, err := s.machineTokenURL(ctx, *in.TokenURL)
		if err != nil {
			return f, err
		}
		f.tokenURL = u
	}
	if in.ClientID != nil {
		f.clientID = strings.TrimSpace(*in.ClientID)
		if n := len(f.clientID); n < 1 || n > 500 || strings.ContainsAny(f.clientID, "\r\n\x00") {
			return f, machineInvalid("clientId", "invalid_client_id", "The client ID must be 1-500 characters on one line")
		}
	}
	if in.TokenAuthMethod != nil {
		f.method = *in.TokenAuthMethod
		if f.method != MachineAuthBasic && f.method != MachineAuthPost {
			return f, machineInvalid("tokenAuthMethod", "invalid_token_auth_method", "tokenAuthMethod must be client_secret_basic or client_secret_post")
		}
	}
	if in.Scopes != nil {
		var err error
		if f.scopes, err = NormalizeScopes(*in.Scopes); err != nil {
			return f, err
		}
	}
	if in.Audience != nil {
		f.audience = strings.TrimSpace(*in.Audience)
		if len(f.audience) > 500 || strings.ContainsAny(f.audience, "\r\n\x00") {
			return f, machineInvalid("audience", "invalid_audience", "The audience must be at most 500 characters on one line")
		}
	}
	if in.Resource != nil {
		f.resource = strings.TrimSpace(*in.Resource)
		if err := checkMachineResource(f.resource); err != nil {
			return f, err
		}
	}
	return f, nil
}

// machineTokenURL validates and normalizes a token endpoint entered for a
// machine client.
func (s *Service) machineTokenURL(ctx context.Context, in string) (string, error) {
	raw := strings.TrimSpace(in)
	if raw == "" {
		return "", machineInvalid("tokenUrl", "invalid_token_url", "Enter the authorization server's token endpoint")
	}
	u, err := s.client.NormalizeURL(ctx, raw)
	if err != nil {
		if e, ok := apperr.As(err); ok {
			d, _ := e.Details.(map[string]any)
			e.Details = withField(d, "machineOAuth.tokenUrl")
		}
		return "", err
	}
	return u, nil
}

// machineSecretReusable applies F-1 to a request without a secret: the
// stored one stays only for the same token endpoint, client and server origin.
func machineSecretReusable(stored *dbgen.McpServerMachineOauth, p *machinePlan, curURL, newURL string) error {
	switch {
	case stored == nil:
		return errMachineSecretRequired("new")
	case p.tokenURLChanged:
		return errMachineSecretRequired("token_url_changed")
	case p.clientIDChanged:
		return errMachineSecretRequired("client_id_changed")
	case !sameOrigin(curURL, newURL):
		return errMachineSecretRequired("origin_changed")
	}
	return nil
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
