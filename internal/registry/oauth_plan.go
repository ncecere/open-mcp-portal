package registry

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/ncecere/open-mcp-portal/internal/apperr"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/internal/upstream/oauthmeta"
)

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
