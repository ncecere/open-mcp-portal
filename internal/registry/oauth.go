package registry

import (
	"context"
	"crypto/tls"
	"net/netip"
	"net/url"
	"slices"
	"strings"

	"github.com/google/uuid"

	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/netpolicy"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
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
	case sv.AuthMode == AuthPersonSecret:
		return AuthPersonSecret
	case sv.AuthMode == AuthMachineOAuth:
		return AuthMachineOAuth
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
	// Machine says whether the authorization server it found offers the
	// client credentials grant (nil: no authorization server metadata).
	Machine *MachineDetection
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
		out.Machine = machineDetection(md, out.Result.Resource)
	}
	return out, nil
}

// machineDetection reads the client credentials grant from an authorization
// server's metadata (RFC 8414 grant_types_supported and
// token_endpoint_auth_methods_supported).
func machineDetection(md *oauthmeta.ServerMetadata, res *oauthmeta.ResourceMetadata) *MachineDetection {
	out := &MachineDetection{TokenEndpoint: md.TokenEndpoint, GrantTypesListed: len(md.GrantTypesSupported) > 0,
		ClientCredentials: slices.Contains(md.GrantTypesSupported, "client_credentials"), AuthMethods: []string{}}
	for _, m := range md.TokenEndpointAuthMethods {
		if (m == MachineAuthBasic || m == MachineAuthPost) && !slices.Contains(out.AuthMethods, m) {
			out.AuthMethods = append(out.AuthMethods, m)
		}
	}
	if res != nil {
		out.Resource = res.Resource
	}
	return out
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
