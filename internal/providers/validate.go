package providers

import (
	"context"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"unicode"

	"github.com/ncecere/open-mcp-portal/internal/apperr"
	"github.com/ncecere/open-mcp-portal/internal/registry"
)

// fields are a provider's settings while validating.
type fields struct {
	name, clientID, method              string
	preset                              *string
	enabled, pkce                       bool
	secret                              *string // a new secret ("" removes it)
	storedSecret                        bool
	authorizationURL, tokenURL          string
	revocationURL, userinfoURL, logoURL *string
	scopes                              []string
	scopeParam, separator, format       string
	params                              map[string]string
}

func invalidURL(field string, err error) error {
	e, ok := apperr.As(err)
	if !ok {
		return err
	}
	out := apperr.New(e.Status, e.Code, e.Message)
	details := map[string]any{"field": field}
	if d, ok := e.Details.(map[string]any); ok {
		for k, v := range d {
			details[k] = v
		}
	}
	out.Details = details
	return out
}

func unprocessable(code, msg string, details any) error {
	e := apperr.New(http.StatusUnprocessableEntity, code, msg)
	e.Details = details
	return e
}

func oneLine(s string) bool { return strings.IndexFunc(s, unicode.IsControl) < 0 }

// checkLogo: an https URL or a same-origin path.
func checkLogo(raw string) error {
	bad := func(reason string) error {
		return unprocessable("url_not_allowed", "The logo must be an https URL or a path on this site", map[string]any{"field": "logoUrl", "reason": reason})
	}
	if len(raw) > maxURL || !oneLine(raw) {
		return bad("invalid")
	}
	if SafeReturnPath(raw) {
		return nil
	}
	u, err := url.Parse(raw)
	switch {
	case err != nil || u.Host == "":
		return bad("invalid")
	case u.User != nil:
		return bad("userinfo")
	case u.Scheme != "https":
		return bad("scheme")
	}
	return nil
}

// validate checks a provider's settings and normalizes them.
func (s *Service) validate(ctx context.Context, f *fields) error {
	f.name = strings.TrimSpace(f.name)
	if n := len([]rune(f.name)); n < 1 || n > 100 {
		return apperr.Invalid("invalid_name", "Name must be 1-100 characters")
	}
	f.clientID = strings.TrimSpace(f.clientID)
	if n := len(f.clientID); n < 1 || n > 500 || !oneLine(f.clientID) {
		return apperr.Invalid("invalid_client_id", "The client ID must be 1-500 characters on one line")
	}
	if f.preset != nil && !ValidPreset(*f.preset) {
		return apperr.Invalid("invalid_preset", "preset must be github, google, microsoft, atlassian, slack or gitlab")
	}
	switch f.method {
	case AuthClientSecretPost, AuthClientSecretBasic, AuthNone:
	default:
		return apperr.Invalid("invalid_token_auth_method", "tokenAuthMethod must be client_secret_post, client_secret_basic or none")
	}
	if f.method == AuthNone && !f.pkce {
		return unprocessable("pkce_required", "A public client (tokenAuthMethod none) must use PKCE", nil)
	}
	if f.secret != nil {
		if len(*f.secret) > maxSecret || !oneLine(*f.secret) {
			return apperr.Invalid("invalid_client_secret", "The client secret must be at most 2000 characters on one line")
		}
	}
	hasSecret := f.storedSecret
	if f.secret != nil {
		hasSecret = *f.secret != ""
	}
	if f.method != AuthNone && !hasSecret {
		return unprocessable("client_secret_required", "Enter the client secret (or use tokenAuthMethod none with PKCE)", nil)
	}
	for _, u := range []struct {
		field string
		raw   *string
	}{{"authorizationUrl", &f.authorizationURL}, {"tokenUrl", &f.tokenURL}, {"revocationUrl", f.revocationURL}, {"userinfoUrl", f.userinfoURL}} {
		if u.raw == nil {
			continue
		}
		norm, err := s.up.NormalizeURL(ctx, *u.raw)
		if err != nil {
			return invalidURL(u.field, err)
		}
		*u.raw = norm
	}
	if f.logoURL != nil {
		if err := checkLogo(*f.logoURL); err != nil {
			return err
		}
	}
	scopes, err := registry.NormalizeScopes(f.scopes)
	if err != nil {
		return err
	}
	f.scopes = scopes
	if !paramKeyRE.MatchString(f.scopeParam) || (f.scopeParam != "scope" && slices.Contains(reservedParamKeys, f.scopeParam)) {
		return apperr.Invalid("invalid_scope_param", "scopeParam must be a parameter name such as scope or user_scope")
	}
	if f.separator != " " && f.separator != "," {
		return apperr.Invalid("invalid_scope_separator", "scopeSeparator must be a space or a comma")
	}
	if f.format != FormatStandard && f.format != FormatSlackAuthedUser {
		return apperr.Invalid("invalid_token_response_format", "tokenResponseFormat must be standard or slack_authed_user")
	}
	if len(f.params) > maxExtraParams {
		return unprocessable("invalid_param", "At most 10 extra authorization parameters", map[string]any{"reason": "too_many"})
	}
	for k, v := range f.params {
		switch {
		case !paramKeyRE.MatchString(k):
			return unprocessable("invalid_param", "Parameter names are 1-64 letters, digits, _, . or -", map[string]any{"key": k, "reason": "invalid"})
		case slices.Contains(reservedParamKeys, k) || k == f.scopeParam:
			return unprocessable("invalid_param", "The portal sets this parameter itself", map[string]any{"key": k, "reason": "reserved"})
		case len(v) > maxParamValue || !oneLine(v):
			return unprocessable("invalid_param", "Parameter values are at most 500 characters on one line", map[string]any{"key": k, "reason": "invalid"})
		}
	}
	return nil
}
