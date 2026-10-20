package testutil

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// WhoamiResult is what the fake's whoami tool reports.
type WhoamiResult struct {
	// Header is the header that carried the token ("" when none did).
	Header string `json:"header"`
	// Claims are the token's claims (decoded even when not verified).
	Claims map[string]any `json:"claims,omitempty"`
	// Verified: the signature verified against the JWKS, the audience
	// matched and the token is current.
	Verified bool   `json:"verified"`
	Error    string `json:"error,omitempty"`
	// BearerSHA256 is TokenDigest of the bearer token a protected fake
	// received (an oauth server's person token; never the token).
	BearerSHA256 string `json:"bearerSha256,omitempty"`
	// Act is the token's act claim: the agent that called for the person
	// (docs/upstream-identity.md "Calls from agents"); nil when the token has
	// none. ActedBy says it in words, for a person reading the tool's output.
	Act     map[string]any `json:"act,omitempty"`
	ActedBy string         `json:"actedBy,omitempty"`
}

// IdentityToken finds the gateway's identity token in a request's headers:
// MCP-Gateway-Identity, else a Bearer Authorization header.
func IdentityToken(h http.Header) (header, token string) {
	if v := h.Get("MCP-Gateway-Identity"); v != "" {
		return "MCP-Gateway-Identity", v
	}
	if v := h.Get("Authorization"); strings.HasPrefix(v, "Bearer ") {
		return "Authorization", strings.TrimPrefix(v, "Bearer ")
	}
	return "", ""
}

// Whoami reads the identity token from h and, when jwksURL is set,
// verifies it for audience.
func Whoami(ctx context.Context, h http.Header, jwksURL, audience string) WhoamiResult {
	header, token := IdentityToken(h)
	out := WhoamiResult{Header: header}
	if token == "" {
		out.Error = "no identity token"
		return out
	}
	tok, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		out.Error = "not a JWT: " + err.Error()
		return out
	}
	if err := tok.UnsafeClaimsWithoutVerification(&out.Claims); err != nil {
		out.Error = err.Error()
		return out
	}
	if act, ok := out.Claims["act"].(map[string]any); ok {
		out.Act, out.ActedBy = act, actedBy(act)
	}
	if jwksURL == "" {
		return out
	}
	if err := VerifyIdentity(ctx, token, jwksURL, audience, nil); err != nil {
		out.Error = err.Error()
		return out
	}
	out.Verified = true
	return out
}

// VerifyIdentity verifies an identity token against the key set at
// jwksURL: ES256 signature by a published key, aud = audience, current
// iat/nbf/exp. claims (optional) receives the claims.
func VerifyIdentity(ctx context.Context, token, jwksURL, audience string, claims any) error {
	tok, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		return err
	}
	if len(tok.Headers) != 1 || tok.Headers[0].KeyID == "" {
		return errors.New("token has no kid")
	}
	set, err := FetchJWKS(ctx, jwksURL)
	if err != nil {
		return err
	}
	keys := set.Key(tok.Headers[0].KeyID)
	if len(keys) == 0 {
		return fmt.Errorf("kid %s is not published", tok.Headers[0].KeyID)
	}
	var std jwt.Claims
	dst := []any{&std}
	if claims != nil {
		dst = append(dst, claims)
	}
	if err := tok.Claims(keys[0].Key, dst...); err != nil {
		return err
	}
	return std.ValidateWithLeeway(jwt.Expected{AnyAudience: jwt.Audience{audience}, Time: time.Now()}, 30*time.Second)
}

// FetchJWKS reads a JSON Web Key Set.
func FetchJWKS(ctx context.Context, url string) (jose.JSONWebKeySet, error) {
	var set jose.JSONWebKeySet
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return set, err
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return set, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return set, fmt.Errorf("JWKS: HTTP %d", res.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return set, err
	}
	return set, json.Unmarshal(body, &set)
}

// ProviderReport is what the fake's provider_token tool reports about a
// call's delegated credential: never the token itself.
type ProviderReport struct {
	// Provider is the MCP-Gateway-Provider header ("" when absent).
	Provider string `json:"provider"`
	// Received: an MCP-Gateway-Provider-Token header was present.
	Received bool `json:"received"`
	// TokenSHA256 is the first 16 hex characters of the token's SHA-256
	// (TokenDigest), to compare with the token a test issued.
	TokenSHA256 string `json:"tokenSha256,omitempty"`
	// Claim is the identity token's provider claim, and ClaimMatches whether
	// it equals Provider (the check server authors must make). Verified
	// says the identity token verified against the JWKS (with SetJWKS).
	Claim        string `json:"claim"`
	ClaimMatches bool   `json:"claimMatches"`
	Verified     bool   `json:"verified"`
	Error        string `json:"error,omitempty"`
}

// ProviderTokenReport reads a call's provider headers and identity token.
func ProviderTokenReport(ctx context.Context, h http.Header, jwksURL, audience string) ProviderReport {
	token := h.Get("MCP-Gateway-Provider-Token")
	out := ProviderReport{Provider: h.Get("MCP-Gateway-Provider"), Received: token != ""}
	if token != "" {
		out.TokenSHA256 = TokenDigest(token)
	}
	who := Whoami(ctx, h, jwksURL, audience)
	out.Verified, out.Error = who.Verified, who.Error
	out.Claim, _ = who.Claims["provider"].(string)
	out.ClaimMatches = out.Claim != "" && out.Claim == out.Provider
	return out
}

// actedBy describes an act claim: the agent, its platform and whether the
// person was present.
func actedBy(act map[string]any) string {
	name, _ := act["name"].(string)
	sub, _ := act["sub"].(string)
	iss, _ := act["iss"].(string)
	present, _ := act["person_present"].(bool)
	if name == "" {
		name = sub
	}
	when := "while the person was present"
	if !present {
		when = "while the person was not present"
	}
	return fmt.Sprintf("agent %q (%s) of %s, %s", name, sub, iss, when)
}
