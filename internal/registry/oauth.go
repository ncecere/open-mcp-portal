package registry

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/ncecere/open-mcp-portal/internal/apperr"
	"github.com/ncecere/open-mcp-portal/internal/audit"
	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/netpolicy"
	"github.com/ncecere/open-mcp-portal/internal/store"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/internal/teams"
	"github.com/ncecere/open-mcp-portal/internal/upstream"
	"github.com/ncecere/open-mcp-portal/internal/upstream/oauthmeta"
)

// Upstream OAuth (docs/phase7-upstream-oauth.md; decisions 39-45): a server
// in oauth mode is an OAuth resource server itself. The gateway discovers
// how it signs people in (internal/upstream/oauthmeta, through the address
// guard), keeps the server's OAuth client in a server-bound provider row
// (auth_providers kind mcp_server, never a platform provider), and every
// person signs in to it with their own connection (internal/providers).
// Capabilities are read and manual tests run with the setup connection: the
// sign-in of the editor who set the server up (decision 42).

// Upstream auth modes (mcp_servers.auth_mode).
const (
	AuthNone         = "none"
	AuthStaticHeader = "static_header"
	AuthOAuth        = "oauth"
)

// Registrations of a server's OAuth client.
const (
	RegistrationAuto             = "auto"
	RegistrationDCR              = "dcr"
	RegistrationCIMD             = "cimd"
	RegistrationManual           = "manual"
	RegistrationPlatformProvider = "platform_provider"
)

// Setup connection statuses (McpServerOAuthSetupConnection.status).
const (
	SetupActive         = "active"
	SetupNeedsReconsent = "needs_reconsent"
	SetupMissing        = "missing"
)

// CIMDPath is where the gateway serves its Client ID Metadata Document as
// an OAuth client of upstream servers (outside the API contract).
const CIMDPath = "/oauth/upstream-client-metadata.json"

// callbackPath is the redirect URI's path (internal/providers.CallbackPath).
const callbackPath = "/connect/callback"

// ProviderSecretAAD binds a provider's sealed client secret to its row
// (platform and server-bound providers alike).
func ProviderSecretAAD(id uuid.UUID) []byte { return []byte("auth_provider:" + id.String()) }

// AuthModeOf is a server's upstream auth mode. Rows written before Phase 7
// (or by the previous release) have none with a static header: that is
// static_header. A server whose credential is a list of parts has no header in
// its row and is static_header by its stored mode.
func AuthModeOf(sv dbgen.McpServer) string {
	switch {
	case sv.AuthMode == AuthOAuth:
		return AuthOAuth
	case sv.AuthMode == AuthStaticHeader || sv.AuthHeaderName != nil:
		return AuthStaticHeader
	}
	return AuthNone
}

// OAuthHooks are the parts of internal/providers the registry needs (that
// package imports this one): the setup connection's token, and revoking and
// deleting a server's connections.
type OAuthHooks interface {
	// SetupToken returns the setup connection's access token (refreshed
	// first when it expires soon) and its person's name, or a *SetupError.
	SetupToken(ctx context.Context, sv dbgen.McpServer, p dbgen.AuthProvider) (token, person string, err error)
	// RevokeConnections revokes every connection to a server-bound provider
	// at its authorization server (best effort, bounded); the result per
	// connection is true, false or "not_supported".
	RevokeConnections(ctx context.Context, p dbgen.AuthProvider) map[uuid.UUID]any
	// DeleteConnections deletes every connection to a server-bound provider
	// in the caller's transaction, auditing provider_connection.revoke with
	// reason and the revocation results.
	DeleteConnections(ctx context.Context, q *dbgen.Queries, a authz.Actor, p dbgen.AuthProvider, results map[uuid.UUID]any, reason string) error
}

// SetupError: the setup connection can't be used (Status missing or
// needs_reconsent).
type SetupError struct{ Status string }

func (e *SetupError) Error() string { return "the setup sign-in can't be used (" + e.Status + ")" }

// OAuthSettings configure upstream OAuth (set by the application).
type OAuthSettings struct {
	// AppURL is the gateway's own URL (redirect URI, CIMD).
	AppURL string
	// InstanceName names the gateway's registered clients.
	InstanceName string
	Hooks        OAuthHooks
	// TLS is used for discovery and registration requests (tests).
	TLS *tls.Config
}

// SetOAuth configures upstream OAuth.
func (s *Service) SetOAuth(o OAuthSettings) {
	o.AppURL = strings.TrimRight(o.AppURL, "/")
	if o.InstanceName == "" {
		o.InstanceName = "Open MCP Portal"
	}
	s.oauth = o
}

// RedirectURI is the callback every upstream client registers.
func (s *Service) RedirectURI() string { return s.oauth.AppURL + callbackPath }

// ClientMetadataURL is the gateway's Client ID Metadata Document.
func (s *Service) ClientMetadataURL() string { return s.oauth.AppURL + CIMDPath }

// InstanceName is the gateway's name as an OAuth client.
func (s *Service) InstanceName() string { return s.oauth.InstanceName }

func (s *Service) fetcher() *oauthmeta.Fetcher {
	return &oauthmeta.Fetcher{Client: s.client, TLS: s.oauth.TLS}
}

// appURLPublic reports whether APP_URL is public https (CIMD needs the
// authorization server to fetch the document).
func (s *Service) appURLPublic() bool {
	u, err := url.Parse(s.oauth.AppURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return false
	}
	h := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if h == "localhost" || strings.HasSuffix(h, ".localhost") || !strings.Contains(h, ".") {
		return false
	}
	if ip, err := netip.ParseAddr(h); err == nil {
		return netpolicy.PublicAddr(ip)
	}
	return true
}

// RegistrationOptions say how the gateway can get a client at a discovered
// authorization server.
type RegistrationOptions struct {
	Options     []string
	Recommended string
	// CIMDUnavailable is why cimd isn't offered ("": it is): not_supported
	// or app_url_not_public.
	CIMDUnavailable string
	// Matching are the enabled platform providers whose authorization and
	// token endpoints equal the discovered ones.
	Matching                       []Provider
	RedirectURI, ClientMetadataURL string
}

func (s *Service) registrationOptions(ctx context.Context, q *dbgen.Queries, md *oauthmeta.ServerMetadata) (RegistrationOptions, error) {
	out := RegistrationOptions{Options: []string{}, Matching: []Provider{}, RedirectURI: s.RedirectURI(), ClientMetadataURL: s.ClientMetadataURL()}
	switch {
	case !md.CIMDSupported:
		out.CIMDUnavailable = "not_supported"
	case !s.appURLPublic():
		out.CIMDUnavailable = "app_url_not_public"
	default:
		out.Options = append(out.Options, RegistrationCIMD)
	}
	if md.RegistrationEndpoint != "" {
		out.Options = append(out.Options, RegistrationDCR)
	}
	rows, err := q.ListPlatformAuthProviders(ctx)
	if err != nil {
		return out, err
	}
	for _, p := range rows {
		if p.Enabled && p.AuthorizationUrl == md.AuthorizationEndpoint && p.TokenUrl == md.TokenEndpoint {
			out.Matching = append(out.Matching, ProviderOf(p))
		}
	}
	if len(out.Matching) > 0 {
		out.Options = append(out.Options, RegistrationPlatformProvider)
	}
	out.Options = append(out.Options, RegistrationManual)
	out.Recommended = RegistrationManual
	switch {
	case slices.Contains(out.Options, RegistrationCIMD):
		out.Recommended = RegistrationCIMD
	case slices.Contains(out.Options, RegistrationDCR):
		out.Recommended = RegistrationDCR
	}
	return out, nil
}

// Detection is detect-auth's answer.
type Detection struct {
	Result       oauthmeta.Result
	Registration *RegistrationOptions
}

// DetectAuth probes a URL and reports how its server wants clients to
// sign in (team editors and above). It changes nothing and isn't audited.
func (s *Service) DetectAuth(ctx context.Context, a authz.Actor, ref, rawURL string) (Detection, error) {
	ta, err := access(ctx, s.q, a, ref)
	if err != nil {
		return Detection{}, err
	}
	if err := ta.writable(authz.CheckServerEdit); err != nil {
		return Detection{}, err
	}
	u, err := s.client.NormalizeURL(ctx, rawURL)
	if err != nil {
		return Detection{}, err
	}
	out := Detection{Result: s.fetcher().Discover(ctx, u, oauthmeta.Options{})}
	if md := out.Result.Server; md != nil {
		reg, err := s.registrationOptions(ctx, s.q, md)
		if err != nil {
			return Detection{}, err
		}
		out.Registration = &reg
	}
	return out, nil
}

// IdentityDefault is the default of "Send identity token" for a URL when
// the server has no authentication (decision 64), and why.
type IdentityDefault struct {
	// Basis is upstream.BasisPublicHost, BasisInternalHost or
	// BasisUnresolvedHost.
	Basis string
	// SendIdentity is the default: false for a public or unresolved host.
	SendIdentity bool
}

// defaultSendIdentity is the default of Send identity token when the form
// does not say: off only for authMode none on a public (or unresolvable)
// host; on for every other mode and for internal hosts.
func (s *Service) defaultSendIdentity(ctx context.Context, mode, rawURL string) IdentityDefault {
	if mode != AuthNone {
		return IdentityDefault{SendIdentity: true}
	}
	b := s.client.HostBasis(ctx, rawURL)
	return IdentityDefault{Basis: b, SendIdentity: b == upstream.BasisInternalHost}
}

// IdentityDefault reports the default of Send identity token for a server
// with no authentication at url, so the add form can show it before saving
// (editors and above; changes nothing; decision 64).
func (s *Service) IdentityDefault(ctx context.Context, a authz.Actor, ref, rawURL string) (IdentityDefault, error) {
	ta, err := access(ctx, s.q, a, ref)
	if err != nil {
		return IdentityDefault{}, err
	}
	if err := ta.writable(authz.CheckServerEdit); err != nil {
		return IdentityDefault{}, err
	}
	u, err := s.client.NormalizeURL(ctx, rawURL)
	if err != nil {
		return IdentityDefault{}, err
	}
	return s.defaultSendIdentity(ctx, AuthNone, u), nil
}

// OAuthInput configures a server's sign-in; nil fields keep their stored
// values (update) or take their defaults.
type OAuthInput struct {
	AuthorizationServer *string
	Registration        *string
	ClientID            *string
	ClientSecret        *string
	TokenAuthMethod     *string
	PlatformProviderID  *uuid.UUID
	Scopes              *[]string
	SendResource        *bool
}

// oauthPlan is a server's sign-in configuration as it will be stored.
type oauthPlan struct {
	disc         oauthmeta.Result
	registration string
	clientID     string
	// secret is a new client secret (nil: keep the stored one, or none).
	secret       *string
	clearSecret  bool
	method       string
	link         *dbgen.AuthProvider
	scopes       []string
	sendResource bool
	secretExpiry *time.Time
	registered   bool
}

func unprocessable(code, msg string, details any) error {
	e := apperr.New(http.StatusUnprocessableEntity, code, msg)
	e.Details = details
	return e
}

func problemDetails(r oauthmeta.Result) map[string]any {
	ps := []map[string]any{}
	for _, p := range r.Problems {
		ps = append(ps, map[string]any{"code": p.Code, "blocking": p.Blocking, "message": p.Message})
	}
	d := map[string]any{"outcome": r.Outcome, "problems": ps}
	if r.SuggestedURL != "" {
		d["suggestedUrl"] = r.SuggestedURL
	}
	return d
}

var tokenMethods = []string{"client_secret_post", "client_secret_basic", "none"}

// prepareOAuth runs discovery again (the gateway never trusts endpoints sent
// by the browser), resolves the registration and, for dcr, registers the
// gateway's client: all before any transaction. cur is the server's current
// server-bound provider (nil: none).
func (s *Service) prepareOAuth(ctx context.Context, q *dbgen.Queries, serverURL, serverName string, in *OAuthInput, cur *dbgen.AuthProvider) (*oauthPlan, error) {
	if in == nil {
		in = &OAuthInput{}
	}
	opt := oauthmeta.Options{}
	switch {
	case in.AuthorizationServer != nil:
		opt.AuthorizationServer = *in.AuthorizationServer
	case cur != nil && cur.AuthorizationServer != nil:
		opt.AuthorizationServer = *cur.AuthorizationServer
	}
	disc := s.fetcher().Discover(ctx, serverURL, opt)
	if cur != nil && in.AuthorizationServer == nil && disc.Resource != nil && !slices.Contains(disc.Resource.AuthorizationServers, opt.AuthorizationServer) {
		// The stored authorization server is no longer listed: the first is.
		disc = s.fetcher().Discover(ctx, serverURL, oauthmeta.Options{})
	}
	if !disc.Usable() {
		return nil, unprocessable("oauth_discovery_failed", "The server's sign-in can't be used: "+discoveryProblem(disc), problemDetails(disc))
	}
	md := disc.Server
	opts, err := s.registrationOptions(ctx, q, md)
	if err != nil {
		return nil, err
	}
	sameIssuer := cur != nil && cur.Issuer != nil && *cur.Issuer == md.Issuer
	choice := RegistrationAuto
	switch {
	case in.Registration != nil:
		choice = *in.Registration
	case cur != nil && cur.Registration != nil:
		choice = *cur.Registration
		if choice == RegistrationDCR && !sameIssuer {
			// A client registered at another authorization server is no use
			// here (credentials belong to one issuer, SEP-2352): choose again,
			// preferring a Client ID Metadata Document where it is offered.
			choice = RegistrationAuto
		}
	}
	if choice == RegistrationAuto {
		switch {
		case slices.Contains(opts.Options, RegistrationCIMD):
			choice = RegistrationCIMD
		case slices.Contains(opts.Options, RegistrationDCR):
			choice = RegistrationDCR
		default:
			return nil, unprocessable("registration_unavailable", "The authorization server offers no automatic registration: enter a client",
				map[string]any{"options": opts.Options})
		}
	}
	switch choice {
	case RegistrationDCR, RegistrationCIMD, RegistrationManual, RegistrationPlatformProvider:
	default:
		return nil, apperr.Invalid("invalid_registration", "registration must be auto, dcr, cimd, manual or platform_provider")
	}
	if !slices.Contains(opts.Options, choice) {
		if choice == RegistrationPlatformProvider {
			return nil, unprocessable("provider_mismatch", "No enabled platform provider has the discovered authorization and token endpoints",
				map[string]any{"options": opts.Options})
		}
		return nil, unprocessable("registration_unavailable", "This registration isn't offered by the authorization server",
			map[string]any{"options": opts.Options})
	}
	plan := &oauthPlan{disc: disc, registration: choice, sendResource: true}
	if cur != nil {
		plan.sendResource = cur.SendResource
	}
	if in.SendResource != nil {
		plan.sendResource = *in.SendResource
	}
	scopes := disc.SuggestedScopes
	if cur != nil {
		scopes = nonNil(cur.DefaultScopes)
	}
	if in.Scopes != nil {
		scopes = *in.Scopes
	}
	if plan.scopes, err = NormalizeScopes(scopes); err != nil {
		return nil, err
	}
	curIs := func(r string) bool { return cur != nil && cur.Registration != nil && *cur.Registration == r }
	if choice != RegistrationManual && (in.ClientID != nil || in.ClientSecret != nil || in.TokenAuthMethod != nil) {
		return nil, apperr.Invalid("invalid_oauth", "clientId, clientSecret and tokenAuthMethod are for registration manual only")
	}
	if choice != RegistrationPlatformProvider && in.PlatformProviderID != nil {
		return nil, apperr.Invalid("invalid_oauth", "platformProviderId is for registration platform_provider only")
	}
	switch choice {
	case RegistrationCIMD:
		plan.clientID, plan.method, plan.clearSecret = s.ClientMetadataURL(), "none", true
	case RegistrationDCR:
		if curIs(RegistrationDCR) && sameIssuer {
			// Keep the client registered before.
			plan.clientID, plan.method, plan.secretExpiry = cur.ClientID, cur.TokenAuthMethod, cur.ClientSecretExpiresAt
			break
		}
		if err := s.register(ctx, plan, serverName, md); err != nil {
			return nil, err
		}
	case RegistrationManual:
		keep := curIs(RegistrationManual) && sameIssuer
		plan.clientID = ""
		if keep {
			plan.clientID, plan.method = cur.ClientID, cur.TokenAuthMethod
		}
		if in.ClientID != nil {
			plan.clientID = strings.TrimSpace(*in.ClientID)
		}
		if n := len(plan.clientID); n < 1 || n > 500 || strings.ContainsAny(plan.clientID, "\r\n") {
			return nil, unprocessable("client_required", "Enter the client ID you created at the authorization server", nil)
		}
		if in.TokenAuthMethod != nil {
			plan.method = *in.TokenAuthMethod
		}
		if plan.method == "" {
			plan.method = defaultMethod(md.TokenEndpointAuthMethods)
		}
		if !slices.Contains(tokenMethods, plan.method) {
			return nil, apperr.Invalid("invalid_token_auth_method", "tokenAuthMethod must be client_secret_post, client_secret_basic or none")
		}
		hasSecret := keep && cur.ClientSecretCipher != nil && cur.ClientID == plan.clientID
		if in.ClientSecret != nil {
			v := *in.ClientSecret
			if len(v) > 2000 || strings.ContainsAny(v, "\r\n\x00") {
				return nil, apperr.Invalid("invalid_client_secret", "The client secret must be at most 2000 characters on one line")
			}
			plan.secret, hasSecret = &v, v != ""
		}
		if plan.method == "none" {
			plan.clearSecret, plan.secret = true, nil
		} else if !hasSecret {
			return nil, unprocessable("client_required", "Enter the client secret (or use tokenAuthMethod none)", nil)
		} else if plan.secret == nil && !keep {
			return nil, unprocessable("client_required", "Enter the client secret", nil)
		} else if plan.secret == nil && cur.ClientID != plan.clientID {
			return nil, unprocessable("client_required", "Enter the new client's secret", nil)
		}
	case RegistrationPlatformProvider:
		var pid uuid.UUID
		switch {
		case in.PlatformProviderID != nil:
			pid = *in.PlatformProviderID
		case cur != nil && cur.LinkProviderID.Valid:
			pid = cur.LinkProviderID.UUID
		default:
			return nil, unprocessable("provider_mismatch", "Choose the platform provider to use", map[string]any{"options": opts.Options})
		}
		var link *Provider
		for i := range opts.Matching {
			if opts.Matching[i].ID == pid {
				link = &opts.Matching[i]
			}
		}
		if link == nil {
			return nil, unprocessable("provider_mismatch", "That platform provider is turned off or its endpoints differ from the discovered ones", nil)
		}
		row, err := q.GetAuthProvider(ctx, pid)
		if err != nil {
			return nil, err
		}
		plan.link, plan.clientID, plan.method, plan.clearSecret = &row, row.ClientID, row.TokenAuthMethod, true
	}
	return plan, nil
}

func discoveryProblem(r oauthmeta.Result) string {
	if b := r.Blocking(); len(b) > 0 {
		return b[0].Message
	}
	switch r.Outcome {
	case oauthmeta.OutcomeNoAuth:
		return "it answers without sign-in (use authMode none)."
	case oauthmeta.OutcomeOtherAuth:
		return "it asks for credentials without OAuth metadata (use a static header)."
	case oauthmeta.OutcomeUnreachable:
		return "it couldn't be reached."
	}
	return "its metadata is incomplete."
}

// defaultMethod is a manual client's token endpoint authentication:
// client_secret_post, or the first the authorization server lists.
func defaultMethod(listed []string) string {
	if len(listed) == 0 || slices.Contains(listed, "client_secret_post") {
		return "client_secret_post"
	}
	for _, m := range listed {
		if slices.Contains(tokenMethods, m) {
			return m
		}
	}
	return "client_secret_post"
}

// register registers the gateway's client (RFC 7591) for a server.
func (s *Service) register(ctx context.Context, plan *oauthPlan, serverName string, md *oauthmeta.ServerMetadata) error {
	method := "none"
	switch {
	case len(md.TokenEndpointAuthMethods) == 0 || slices.Contains(md.TokenEndpointAuthMethods, "client_secret_basic"):
		method = "client_secret_basic"
	case slices.Contains(md.TokenEndpointAuthMethods, "client_secret_post"):
		method = "client_secret_post"
	}
	reg, err := s.fetcher().Register(ctx, md.RegistrationEndpoint, oauthmeta.RegistrationRequest{
		ClientName: clipName(s.oauth.InstanceName + " · " + serverName), RedirectURIs: []string{s.RedirectURI()},
		GrantTypes: []string{"authorization_code", "refresh_token"}, ResponseTypes: []string{"code"}, TokenEndpointAuthMethod: method,
		Scope: strings.Join(plan.scopes, " "), ClientURI: s.oauth.AppURL, ApplicationType: "web",
	})
	if err != nil {
		code := "error"
		var re *oauthmeta.RegistrationError
		if errors.As(err, &re) {
			code = re.Code
		}
		s.log.InfoContext(ctx, "upstream client registration failed", "endpoint", md.RegistrationEndpoint, "error", code)
		e := apperr.New(http.StatusBadGateway, "oauth_registration_failed", "The authorization server refused to register the portal's client ("+code+")")
		e.Details = map[string]any{"code": code}
		return e
	}
	if !slices.Contains(tokenMethods, reg.TokenEndpointAuthMethod) {
		reg.TokenEndpointAuthMethod = method
	}
	plan.clientID, plan.method, plan.secretExpiry, plan.registered = reg.ClientID, reg.TokenEndpointAuthMethod, reg.SecretExpiresAt, true
	if reg.ClientSecret != "" {
		v := reg.ClientSecret
		plan.secret = &v
	} else {
		plan.clearSecret = true
		if plan.method != "none" {
			plan.method = "none"
		}
	}
	return nil
}

func clipName(s string) string {
	r := []rune(s)
	if len(r) > 100 {
		return string(r[:100])
	}
	return s
}

// newProviderSlug is a server-bound provider's generated slug.
func newProviderSlug() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return "mcp-" + hex.EncodeToString(b)
}

// secretHint is the last four characters of a secret of at least eight.
func secretHint(v string) string { return valueHint(v) }

// providerParams are a plan's provider columns; the secret is sealed for id.
func (s *Service) planColumns(id uuid.UUID, plan *oauthPlan, cur *dbgen.AuthProvider) (cipher []byte, hint string, err error) {
	switch {
	case plan.secret != nil && *plan.secret != "":
		ct, err := s.box.Seal([]byte(*plan.secret), ProviderSecretAAD(id))
		if err != nil {
			return nil, "", err
		}
		return ct, secretHint(*plan.secret), nil
	case plan.clearSecret || (plan.secret != nil && *plan.secret == "") || cur == nil:
		return nil, "", nil
	}
	return cur.ClientSecretCipher, cur.ClientSecretHint, nil
}

func linkID(plan *oauthPlan) uuid.NullUUID {
	if plan.link == nil {
		return uuid.NullUUID{}
	}
	return uuid.NullUUID{UUID: plan.link.ID, Valid: true}
}

func optString(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// insertProvider stores a new server-bound provider for a server.
func (s *Service) insertProvider(ctx context.Context, q *dbgen.Queries, a authz.Actor, sv dbgen.McpServer, plan *oauthPlan) (dbgen.AuthProvider, error) {
	id := uuid.New()
	ct, hint, err := s.planColumns(id, plan, nil)
	if err != nil {
		return dbgen.AuthProvider{}, err
	}
	md, prm := plan.disc.Server, plan.disc.Resource
	return q.InsertServerProvider(ctx, dbgen.InsertServerProviderParams{
		ID: id, Slug: newProviderSlug(), Name: sv.Name, ClientID: plan.clientID, ClientSecretCipher: ct, ClientSecretHint: hint,
		TokenAuthMethod: plan.method, AuthorizationUrl: md.AuthorizationEndpoint, TokenUrl: md.TokenEndpoint,
		RevocationUrl: optString(md.RevocationEndpoint), DefaultScopes: plan.scopes, ServerID: uuid.NullUUID{UUID: sv.ID, Valid: true},
		LinkProviderID: linkID(plan), Registration: &plan.registration, Resource: &prm.Resource, ResourceMetadataUrl: &prm.URL,
		AuthorizationServer: &md.Identifier, Issuer: &md.Issuer, ScopesSupported: nonNil(prm.ScopesSupported),
		SendResource: plan.sendResource, IssParamSupported: md.IssParameterSupported, ClientSecretExpiresAt: plan.secretExpiry,
		CreatedBy: by(a),
	})
}

// updateProvider stores a plan over a server's provider.
func (s *Service) updateProvider(ctx context.Context, q *dbgen.Queries, a authz.Actor, name string, cur dbgen.AuthProvider, plan *oauthPlan) (dbgen.AuthProvider, error) {
	ct, hint, err := s.planColumns(cur.ID, plan, &cur)
	if err != nil {
		return dbgen.AuthProvider{}, err
	}
	md, prm := plan.disc.Server, plan.disc.Resource
	return q.UpdateServerProvider(ctx, dbgen.UpdateServerProviderParams{
		ID: cur.ID, Name: name, ClientID: plan.clientID, ClientSecretCipher: ct, ClientSecretHint: hint, TokenAuthMethod: plan.method,
		AuthorizationUrl: md.AuthorizationEndpoint, TokenUrl: md.TokenEndpoint, RevocationUrl: optString(md.RevocationEndpoint),
		DefaultScopes: plan.scopes, LinkProviderID: linkID(plan), Registration: &plan.registration, Resource: &prm.Resource,
		ResourceMetadataUrl: &prm.URL, AuthorizationServer: &md.Identifier, Issuer: &md.Issuer, ScopesSupported: nonNil(prm.ScopesSupported),
		SendResource: plan.sendResource, IssParamSupported: md.IssParameterSupported, ClientSecretExpiresAt: plan.secretExpiry,
		UpdatedBy: by(a),
	})
}

// planUnchanged reports whether a plan would store what cur already holds.
func planUnchanged(cur dbgen.AuthProvider, plan *oauthPlan) bool {
	md, prm := plan.disc.Server, plan.disc.Resource
	return deref(cur.Registration) == plan.registration && cur.ClientID == plan.clientID && cur.TokenAuthMethod == plan.method &&
		plan.secret == nil && (!plan.clearSecret || cur.ClientSecretCipher == nil) && cur.LinkProviderID == linkID(plan) &&
		slices.Equal(nonNil(cur.DefaultScopes), plan.scopes) && cur.SendResource == plan.sendResource &&
		deref(cur.Issuer) == md.Issuer && deref(cur.AuthorizationServer) == md.Identifier && cur.AuthorizationUrl == md.AuthorizationEndpoint &&
		cur.TokenUrl == md.TokenEndpoint && deref(cur.RevocationUrl) == md.RevocationEndpoint && deref(cur.Resource) == prm.Resource &&
		deref(cur.ResourceMetadataUrl) == prm.URL && slices.Equal(nonNil(cur.ScopesSupported), nonNil(prm.ScopesSupported)) &&
		cur.IssParamSupported == md.IssParameterSupported
}

// authSnapshot is a server's upstream auth as audited:
// {authMode, oauth: {registration, scopes, sendResource, issuer, ...} or
// null, sendIdentity}. Never a secret or a client ID.
func authSnapshot(sv dbgen.McpServer, p *dbgen.AuthProvider) map[string]any {
	out := map[string]any{"authMode": AuthModeOf(sv), "oauth": nil, "sendIdentity": sv.SendIdentity}
	if p == nil || AuthModeOf(sv) != AuthOAuth {
		return out
	}
	o := map[string]any{"registration": deref(p.Registration), "scopes": nonNil(p.DefaultScopes), "sendResource": p.SendResource,
		"issuer": deref(p.Issuer), "authorizationServer": deref(p.AuthorizationServer), "resource": deref(p.Resource)}
	if p.LinkProviderID.Valid {
		o["platformProviderId"] = p.LinkProviderID.UUID.String()
	}
	out["oauth"] = o
	return out
}

// authUpdateAudit records mcp_server.auth_update (before nil: a new server).
func authUpdateAudit(ctx context.Context, q *dbgen.Queries, a authz.Actor, beforeSv *dbgen.McpServer, before *dbgen.AuthProvider,
	sv dbgen.McpServer, after *dbgen.AuthProvider, meta map[string]any) error {
	e := a.Audit("mcp_server.auth_update", "mcp_server", sv.ID.String())
	e.TeamID = sv.TeamID
	if beforeSv != nil {
		e.Before = authSnapshot(*beforeSv, before)
	}
	e.After = authSnapshot(sv, after)
	if meta == nil {
		meta = map[string]any{}
	}
	meta["name"] = sv.Name
	e.Metadata = meta
	return audit.Record(ctx, q, e)
}

// widensScopes reports whether after asks for a scope before didn't.
func widensScopes(before, after []string) bool {
	for _, sc := range after {
		if !slices.Contains(before, sc) {
			return true
		}
	}
	return false
}

const noteUpstreamAuthChanged = "The server's sign-in (OAuth) changed; review it again."

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
	default:
		return "", apperr.Invalid("invalid_auth_mode", "authMode must be none, static_header or oauth")
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
