package httpapi

import (
	"bytes"
	"encoding/json"

	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/netpolicy"
	"github.com/ncecere/open-mcp-portal/internal/registry"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/internal/upstream"
)

// Conversions of the registry's views to API types. The header value and
// its ciphertext have no field here: only whether one is set, the header's
// name and the value's hint.

func toAPICounts(c registry.Counts) apitypes.CapabilityCounts {
	return apitypes.CapabilityCounts{Tools: c.Tools, Resources: c.Resources, ResourceTemplates: c.ResourceTemplates, Prompts: c.Prompts}
}

// toAPIHealth is the latest check as a status. withMessage is false in the
// catalog, where any signed-in person reads it.
func toAPIHealth(h *dbgen.McpHealthCheck, withMessage bool) apitypes.ServerHealth {
	if h == nil {
		return apitypes.ServerHealth{Status: "unknown"}
	}
	out := apitypes.ServerHealth{Status: "healthy", CheckedAt: &h.CheckedAt, StatusSince: &h.StatusSince, LatencyMs: &h.LatencyMs}
	if h.SignInRequired {
		yes := true
		out.SignInRequired = &yes
	}
	if !h.Ok {
		out.Status = "failing"
		if h.ErrorClass != nil {
			c := apitypes.McpErrorClass(*h.ErrorClass)
			out.ErrorClass = &c
		}
		if withMessage && h.Message != "" {
			msg := h.Message
			out.Message = &msg
		}
	}
	return out
}

func nonEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func (a *api) toAPIServer(v registry.ServerView) apitypes.McpServer {
	s := v.Server
	return apitypes.McpServer{
		Id: s.ID, TeamId: s.TeamID, TeamSlug: v.TeamSlug, TeamName: v.TeamName,
		Slug: s.Slug, Name: s.Name, Description: s.Description, Url: s.URL,
		Transport:      apitypes.McpServerTransport(s.Transport),
		AuthHeaderName: s.AuthHeaderName, HasAuth: v.HasAuth(), AuthValueHint: s.AuthValueHint, Credentials: toAPICredentials(v.Credentials), Endpoints: toAPIEndpoints(v.Endpoints),
		TimeoutSeconds: s.TimeoutSeconds, Enabled: s.Enabled,
		RateLimitPerMinute: s.RateLimitPerMinute, MaxConcurrent: s.MaxConcurrent,
		PublishState:           apitypes.PublishState(s.PublishState),
		EffectivePublishPolicy: apitypes.PublishPolicy(v.EffectivePolicy),
		PublishRequestedAt:     s.PublishRequestedAt, PublishRequestNote: s.PublishRequestNote,
		PublishReviewedAt: s.PublishReviewedAt, PublishReviewedByName: nonEmpty(v.ReviewedByName), PublishReviewNote: s.PublishReviewNote,
		Counts: toAPICounts(v.Counts), PendingChanges: v.PendingChanges, Health: withWarnings(toAPIHealth(v.Health, true), v.Warnings), Tls: toAPITLS(v.TLS),
		RefreshedAt: s.RefreshedAt, LastRefreshError: s.LastRefreshError,
		Requirement: toAPIServerRequirement(v.Requirement), CapturePayloads: &s.CapturePayloads,
		AuthMode: authModePtr(s), Oauth: a.toAPIServerOAuth(v), PersonSecret: toAPIPersonSecretSettings(v.PersonSecret), MachineOAuth: toAPIMachineOAuth(v), SendIdentity: &s.SendIdentity, Protocol: toAPIProtocol(s), ReviewDigest: nonEmpty(v.ReviewDigest),
		SupportsTasks: &s.SupportsTasks, Governance: toAPIGovernance(v),
		Revision: s.Revision, CreatedAt: s.CreatedAt, UpdatedAt: s.UpdatedAt,
	}
}

// toAPICredentials are a server's credential parts without their values.
func toAPICredentials(parts []registry.CredentialView) *[]apitypes.McpServerCredential {
	out := make([]apitypes.McpServerCredential, len(parts))
	for i, c := range parts {
		out[i] = apitypes.McpServerCredential{Kind: apitypes.McpServerCredentialKind(c.Kind), Name: nonEmpty(c.Name), Hint: c.Hint}
	}
	return &out
}

// toAPIProtocol is the era and version last negotiated with the server (nil
// until a refresh, test or health check has read it).
func toAPIProtocol(s dbgen.McpServer) *apitypes.McpServerProtocol {
	if s.ProtocolEra == nil || s.ProtocolVersion == nil || s.ProtocolNegotiatedAt == nil {
		return nil
	}
	return &apitypes.McpServerProtocol{Era: apitypes.McpServerProtocolEra(*s.ProtocolEra), Version: *s.ProtocolVersion,
		NegotiatedAt: *s.ProtocolNegotiatedAt}
}

func authModePtr(s dbgen.McpServer) *apitypes.McpServerAuthMode {
	m := apitypes.McpServerAuthMode(registry.AuthModeOf(s))
	return &m
}

// clientIDHint is the last six characters of a client ID (a CIMD URL in
// full).
func clientIDHint(p dbgen.AuthProvider) string {
	if p.Registration != nil && *p.Registration == registry.RegistrationCIMD {
		return p.ClientID
	}
	r := []rune(p.ClientID)
	if len(r) <= 6 {
		return p.ClientID
	}
	return string(r[len(r)-6:])
}

// toAPIServerOAuth is an oauth server's sign-in (nil for other modes):
// never the client secret.
func (a *api) toAPIServerOAuth(v registry.ServerView) *apitypes.McpServerOAuth {
	o := v.OAuth
	if o == nil {
		return nil
	}
	p := o.Provider
	out := &apitypes.McpServerOAuth{
		ProviderId: p.ID, ProviderSlug: p.Slug, Resource: deref(p.Resource), ResourceMetadataUrl: deref(p.ResourceMetadataUrl),
		AuthorizationServer: deref(p.AuthorizationServer), Issuer: deref(p.Issuer), AuthorizationEndpoint: p.AuthorizationUrl,
		TokenEndpoint: p.TokenUrl, RevocationEndpoint: p.RevocationUrl, Scopes: nonNilStrings(p.DefaultScopes),
		ScopesSupported: nonNilStrings(p.ScopesSupported), Registration: apitypes.McpServerOAuthRegistration(deref(p.Registration)),
		ClientIdHint: clientIDHint(p), HasClientSecret: p.ClientSecretCipher != nil, ClientSecretExpiresAt: p.ClientSecretExpiresAt,
		TokenAuthMethod: apitypes.AuthProviderTokenAuthMethod(p.TokenAuthMethod), SendResource: p.SendResource,
		IssParameterSupported: p.IssParamSupported, ConnectionCount: o.ConnectionCount,
		SetupConnection: apitypes.McpServerOAuthSetupConnection{Status: apitypes.McpServerOAuthSetupConnectionStatus(o.Setup.Status),
			PersonName: o.Setup.PersonName, AuthorizedAt: o.Setup.AuthorizedAt},
	}
	redirect := a.Registry.RedirectURI()
	out.RedirectUri = &redirect
	if o.Setup.PersonID.Valid {
		id := o.Setup.PersonID.UUID
		out.SetupConnection.PersonId = &id
	}
	if p.DiscoveredAt != nil {
		out.DiscoveredAt = *p.DiscoveredAt
	}
	if o.Linked != nil {
		ref := toAPIRegistryProviderRef(*o.Linked)
		out.PlatformProvider = &ref
	}
	return out
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// toAPIOverride is a capability's requirement override.
func toAPIOverride(c dbgen.McpCapability) apitypes.CapabilityRequirementOverride {
	out := apitypes.CapabilityRequirementOverride{Mode: apitypes.CapabilityRequirementOverrideMode(c.RequirementMode)}
	if out.Mode == "" {
		out.Mode = apitypes.CapabilityRequirementOverrideModeInherit
	}
	if out.Mode == apitypes.CapabilityRequirementOverrideModeScopes {
		scopes := nonNilStrings(c.RequirementScopes)
		out.Scopes = &scopes
	}
	return out
}

// definitionMap decodes a stored definition, keeping numbers exactly.
func definitionMap(raw json.RawMessage) map[string]any {
	out := map[string]any{}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	_ = dec.Decode(&out)
	return out
}

func toAPICapability(c registry.CapabilityView) apitypes.McpCapability {
	cp := c.Capability
	out := apitypes.McpCapability{
		Id: cp.ID, ServerId: cp.ServerID, Kind: apitypes.CapabilityKind(cp.Kind), Name: cp.Name, Title: cp.Title,
		Description: cp.Description, Definition: definitionMap(cp.Definition), Fingerprint: cp.Fingerprint,
		Approved: c.Approved(), Changed: c.Changed(), ToolClass: (*apitypes.ToolClass)(cp.ToolClass), ClassDrift: registry.ClassDrift(cp),
		FirstSeenAt: cp.FirstSeenAt, LastSeenAt: cp.LastSeenAt, GoneAt: cp.GoneAt,
		RequirementOverride: toAPIOverride(cp), Requires: toAPIRequirement(c.Requires, nil),
	}
	if cp.Kind == "tool" {
		suggestion := apitypes.ToolClass(registry.SuggestedClass(cp.Definition))
		out.SuggestedClass = &suggestion
	}
	if cp.ApprovedFingerprint != nil {
		out.ApprovedAt, out.ApprovedByName = cp.ApprovedAt, nonEmpty(c.ApprovedByName)
	}
	return out
}

func toAPICapabilities(cs []registry.CapabilityView) []apitypes.McpCapability {
	out := make([]apitypes.McpCapability, len(cs))
	for i, c := range cs {
		out[i] = toAPICapability(c)
	}
	return out
}

func toAPITestResult(r registry.TestResult) apitypes.McpTestResult {
	out := apitypes.McpTestResult{Ok: r.OK, LatencyMs: r.Latency.Milliseconds(),
		ServerName: nonEmpty(r.ServerName), ServerVersion: nonEmpty(r.ServerVersion), ProtocolVersion: nonEmpty(r.ProtocolVersion),
		ReadAs: r.ReadAs}
	if r.SetupRequired {
		yes := true
		out.SetupRequired = &yes
	}
	if r.OK {
		out.Counts = &apitypes.CapabilityCounts{Tools: int64(r.Counts.Tools), Resources: int64(r.Counts.Resources),
			ResourceTemplates: int64(r.Counts.ResourceTemplates), Prompts: int64(r.Counts.Prompts)}
	}
	if r.Err != nil {
		class := apitypes.McpErrorClass(r.Err.Class)
		out.ErrorClass, out.Message = &class, nonEmpty(r.Err.Message)
		if r.Err.HTTPStatus > 0 {
			st := int32(r.Err.HTTPStatus)
			out.HttpStatus = &st
		}
	}
	return out
}

func toAPIRefresh(r registry.RefreshResult) apitypes.McpRefreshResult {
	return apitypes.McpRefreshResult{Listed: r.Listed, Added: r.Added, Changed: r.Changed, Gone: r.Gone,
		Capabilities: toAPICapabilities(r.Capabilities)}
}

func toAPIHealthCheck(h dbgen.McpHealthCheck) apitypes.McpHealthCheck {
	out := apitypes.McpHealthCheck{CheckedAt: h.CheckedAt, Ok: h.Ok, LatencyMs: h.LatencyMs,
		Trigger: apitypes.McpHealthCheckTrigger(h.Trigger), HttpStatus: h.HttpStatus, Message: nonEmpty(h.Message)}
	position := int32(h.EndpointPosition)
	out.EndpointPosition = &position
	if h.EndpointID.Valid {
		out.EndpointId = &h.EndpointID.UUID
	}
	if h.SignInRequired {
		yes := true
		out.SignInRequired = &yes
	}
	if h.ErrorClass != nil {
		c := apitypes.McpErrorClass(*h.ErrorClass)
		out.ErrorClass = &c
	}
	return out
}

func toAPICatalogServer(v registry.ServerView) apitypes.CatalogServer {
	s := v.Server
	out := apitypes.CatalogServer{Id: s.ID, Slug: s.Slug, Name: s.Name, Description: s.Description,
		TeamSlug: v.TeamSlug, TeamName: v.TeamName, Counts: toAPICounts(v.Approved), Health: toAPIHealth(v.Health, false),
		CapturePayloads: &s.CapturePayloads, AuthMode: authModePtr(s), Governance: toAPICatalogGovernance(v)}
	if s.PublishedAt != nil {
		out.PublishedAt = *s.PublishedAt
	}
	return out
}

func toAPICatalogCapability(cc registry.CatalogCapability) apitypes.CatalogCapability {
	c := cc.Capability
	return apitypes.CatalogCapability{Id: c.ID, Kind: apitypes.CapabilityKind(c.Kind), Name: c.Name, Title: c.Title,
		Description: c.Description, Definition: definitionMap(c.Definition), Requires: toAPIRequirement(cc.Requires, nil), ToolClass: (*apitypes.ToolClass)(c.ToolClass)}
}

func toAPITeamPublishing(p registry.TeamPublishing) apitypes.TeamPublishing {
	out := apitypes.TeamPublishing{Effective: apitypes.PublishPolicy(p.Effective), DefaultPolicy: apitypes.PublishPolicy(p.Default),
		Revision: p.TeamRevision}
	if p.Override != nil {
		o := apitypes.PublishPolicy(*p.Override)
		out.Override = &o
	}
	return out
}

func toAPISettings(s registry.Settings) apitypes.PublishingSettings {
	return apitypes.PublishingSettings{DefaultPolicy: apitypes.PublishPolicy(s.PublishDefaultPolicy), Revision: s.Revision, UpdatedAt: s.UpdatedAt}
}

func toAPINetworkEntries(in []netpolicy.Entry) []apitypes.NetworkEntry {
	out := make([]apitypes.NetworkEntry, len(in))
	for i, e := range in {
		out[i] = toAPINetworkEntry(e)
	}
	return out
}

func toAPINetworkEntry(e netpolicy.Entry) apitypes.NetworkEntry {
	out := apitypes.NetworkEntry{Kind: apitypes.NetworkEntryKind(e.Kind), Value: e.Value, AllowHttp: e.AllowHTTP}
	if e.Note != "" {
		note := e.Note
		out.Note = &note
	}
	return out
}

func fromAPINetworkEntries(in []apitypes.NetworkEntry) []netpolicy.Entry {
	out := make([]netpolicy.Entry, len(in))
	for i, e := range in {
		out[i] = netpolicy.Entry{Kind: string(e.Kind), Value: e.Value, AllowHTTP: e.AllowHttp}
		if e.Note != nil {
			out[i].Note = *e.Note
		}
	}
	return out
}

func toAPINetworkSettings(s registry.NetworkSettings) apitypes.NetworkSettings {
	return apitypes.NetworkSettings{Entries: toAPINetworkEntries(s.Entries), DeploymentEntries: toAPINetworkEntries(s.Deployment),
		Revision: s.Revision, UpdatedAt: s.UpdatedAt}
}

func toAPINetworkCheck(r upstream.CheckResult) apitypes.NetworkCheckResult {
	out := apitypes.NetworkCheckResult{Allowed: r.Allowed, Reason: apitypes.NetworkCheckReason(r.Reason), Message: r.Message}
	if r.Matched != nil {
		e := toAPINetworkEntry(*r.Matched)
		out.MatchedEntry = &e
	}
	if r.Addresses != nil {
		addrs := make([]apitypes.NetworkCheckAddress, len(r.Addresses))
		for i, a := range r.Addresses {
			addrs[i] = apitypes.NetworkCheckAddress{Address: a.Address, Allowed: a.Allowed, Reason: apitypes.NetworkCheckAddressReason(a.Reason)}
		}
		out.ResolvedAddresses = &addrs
	}
	return out
}

// withWarnings adds a server's warnings (an expiring client certificate) to
// its health.
func withWarnings(h apitypes.ServerHealth, ws []registry.HealthWarning) apitypes.ServerHealth {
	if len(ws) == 0 {
		return h
	}
	out := make([]apitypes.ServerWarning, len(ws))
	for i, w := range ws {
		at := w.At
		out[i] = apitypes.ServerWarning{Code: apitypes.ServerWarningCode(w.Code), Message: w.Message, At: &at}
	}
	h.Warnings = &out
	return h
}

func toAPICert(c upstream.CertInfo) apitypes.TlsCertificate {
	out := apitypes.TlsCertificate{Subject: c.Subject, Issuer: c.Issuer, Sha256: c.SHA256, NotBefore: c.NotBefore, NotAfter: c.NotAfter}
	if len(c.Names) > 0 {
		out.Names = &c.Names
	}
	return out
}

// toAPITLS is a server's TLS settings as facts about its certificates: never
// the key or any PEM (nil when it has none).
func toAPITLS(v *registry.TLSView) *apitypes.McpServerTls {
	if v == nil {
		return nil
	}
	out := &apitypes.McpServerTls{}
	if v.CA != nil {
		ca := &apitypes.McpServerTlsCa{Sha256: v.CA.SHA256, Certificates: make([]apitypes.TlsCertificate, len(v.CA.Certificates))}
		for i, c := range v.CA.Certificates {
			ca.Certificates[i] = toAPICert(c)
		}
		out.Ca = ca
	}
	if c := v.Client; c != nil {
		out.Client = &apitypes.McpServerTlsClient{Certificate: toAPICert(c.Leaf), ChainLength: int32(c.ChainLength), HasKey: c.HasKey,
			Status: apitypes.McpServerTlsClientStatus(c.Status), DaysLeft: int32(c.DaysLeft)}
	}
	return out
}

// fromAPITLS reads a request's tls object (nil: absent).
func fromAPITLS(in *apitypes.McpServerTlsInput) *registry.TLSInput {
	if in == nil {
		return nil
	}
	out := &registry.TLSInput{CAPEM: in.CaPem, ClientCertPEM: in.ClientCertPem, ClientKeyPEM: in.ClientKeyPem}
	if in.Clear != nil {
		out.Clear = *in.Clear
	}
	return out
}
