package agentidentity

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/go-jose/go-jose/v4"

	"github.com/ncecere/open-mcp-portal/internal/store"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

// The verifier (decisions 65 and 66; docs/agent-platforms.md "The token"). It
// accepts exactly what Pi Durable Platform's design note says it sends
// (docs/mcp-identity.md there): a compact JWS with the header
// {"alg":"ES256","kid":...,"typ":"JWT"} and the claims iss, aud, sub,
// principal_type "agent", name, team {id, slug, kind}, thread_visibility,
// person {iss, sub, email}, person_present, tool, jti, iat, nbf and exp.
//
// A token is accepted only when every check passes, in this order:
//
//  1. shape: at most maxTokenBytes, compact serialization, a header that is
//     exactly ES256 (never none, HS*, RS*; the key is never taken from the
//     token), has a kid and typ JWT and no crit/jwk/jku/x5* members;
//  2. the issuer: an exact match of iss with a platform a platform admin
//     added and enabled (an unknown or disabled issuer is refused before any
//     fetch);
//  3. the signature, with the key the platform's JWKS publishes for the kid
//     (jwks.go: guarded fetch, cache, one refetch for an unknown kid);
//  4. aud (a string or an array) contains the audience the platform is
//     configured with; iss; principal_type agent; sub, team.id and jti; a
//     person, when there is one, has iss and sub and its iss is the portal's
//     own sign-in issuer (PersonIssuer);
//  5. time, with Skew either way: exp, nbf and iat as plain numbers in a sane
//     range, and a lifetime (exp - iat) of at most MaxLifetime;
//  6. the jti was never accepted before (agent_token_jtis, shared by every
//     replica, kept until exp + Skew + a minute).
//
// A token that fails any check is a *Rejection and changes nothing.

// Bounds.
const (
	// Skew is the clock skew allowed either way (the platform's tokens are
	// valid from 30 s before their issue time).
	Skew = 30 * time.Second
	// MaxLifetime is the longest exp - iat accepted (the platform's tokens
	// live five minutes); it bounds how long a jti is remembered.
	MaxLifetime = 10 * time.Minute
	// maxTokenBytes bounds the header value.
	maxTokenBytes = 8 << 10
	maxClaimLen   = 128
	maxNameLen    = 200
	maxEmailLen   = 320
	// maxDate is 2100-01-01 (UTC): later numbers are not dates.
	maxDate = 4102444800
)

// Rejection reasons (bounded: they are metric labels and log fields).
const (
	ReasonMalformed       = "malformed"
	ReasonAlgorithm       = "algorithm"
	ReasonKeyID           = "key_id"
	ReasonType            = "type"
	ReasonUntrustedIssuer = "untrusted_issuer"
	ReasonDisabledIssuer  = "disabled_issuer"
	ReasonUnknownKid      = "unknown_kid"
	ReasonJWKSUnavailable = "jwks_unavailable"
	ReasonSignature       = "signature"
	ReasonAudience        = "audience"
	ReasonPrincipalType   = "principal_type"
	ReasonClaims          = "claims"
	ReasonPersonIssuer    = "person_issuer"
	ReasonExpired         = "expired"
	ReasonNotYetValid     = "not_yet_valid"
	ReasonLifetime        = "lifetime"
	ReasonReplay          = "replay"
	// ReasonOtherPlatform: a valid token of a platform this credential is
	// not a relay for (set by the caller).
	ReasonOtherPlatform = "other_platform"
	// ReasonToolMismatch: a valid token whose tool claim doesn't fit the
	// request it came with (set by the caller, which knows the request): on a
	// tools/call it must be the called tool's name, on any other method it
	// must be absent (M-1 of the security review).
	ReasonToolMismatch = "tool_mismatch"
)

// Rejection is a token that failed a check. Detail is for logs and
// administrators: it never holds a token, a key or a claim's value beyond a
// claim's name.
type Rejection struct {
	Reason string
	Detail string
}

func (r *Rejection) Error() string { return "agent token refused (" + r.Reason + "): " + r.Detail }

func reject(reason, detail string) *Rejection { return &Rejection{Reason: reason, Detail: detail} }

// Person is who the platform says the agent acts for: the person's sign-in
// issuer and subject at the identity provider both products share.
type Person struct {
	Issuer, Subject string
	// Email is informational (never used to find the person); empty when
	// the platform doesn't send it.
	Email string
}

// Identity is a verified token.
type Identity struct {
	Platform dbgen.AgentPlatform
	// AgentID and AgentName are the calling agent (sub, name).
	AgentID, AgentName         string
	TeamID, TeamSlug, TeamKind string
	ThreadVisibility           string
	// Tool is the tool claim cleaned for display (informational).
	Tool string
	// ToolClaim is the tool claim exactly as signed ("" when absent): the
	// only form to compare with the name a client called (ToolMatches).
	ToolClaim                      string
	Person                         *Person
	PersonPresent                  bool
	JTI                            string
	IssuedAt, NotBefore, ExpiresAt time.Time
}

type teamClaim struct {
	ID   string `json:"id"`
	Slug string `json:"slug"`
	Kind string `json:"kind"`
}

type personClaim struct {
	Iss   string `json:"iss"`
	Sub   string `json:"sub"`
	Email string `json:"email"`
}

type claimSet struct {
	Iss              string          `json:"iss"`
	Aud              json.RawMessage `json:"aud"`
	Sub              string          `json:"sub"`
	PrincipalType    string          `json:"principal_type"`
	Name             string          `json:"name"`
	Team             *teamClaim      `json:"team"`
	ThreadVisibility string          `json:"thread_visibility"`
	Person           json.RawMessage `json:"person"`
	PersonPresent    *bool           `json:"person_present"`
	Tool             string          `json:"tool"`
	JTI              string          `json:"jti"`
	IAT              json.RawMessage `json:"iat"`
	NBF              json.RawMessage `json:"nbf"`
	EXP              json.RawMessage `json:"exp"`
}

// header is a token's protected header, as the verifier reads it.
type header struct {
	Alg  string          `json:"alg"`
	Kid  string          `json:"kid"`
	Typ  string          `json:"typ"`
	Crit json.RawMessage `json:"crit"`
	JWK  json.RawMessage `json:"jwk"`
	JKU  json.RawMessage `json:"jku"`
	X5U  json.RawMessage `json:"x5u"`
	X5C  json.RawMessage `json:"x5c"`
}

func decodeSegment(seg string, v any) error {
	b, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// Verify checks an MCP-Gateway-Identity token. It returns the verified
// identity, a *Rejection, or another error when something the verifier needs
// (the database) failed (the caller refuses the request either way).
func (s *Service) Verify(ctx context.Context, raw string) (Identity, error) {
	if raw == "" || len(raw) > maxTokenBytes || strings.ContainsFunc(raw, func(r rune) bool { return r == '{' || r == ' ' || r <= 0x20 || r >= 0x7f }) {
		return Identity{}, reject(ReasonMalformed, "not a compact JWS")
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" {
		return Identity{}, reject(ReasonMalformed, "not a compact JWS")
	}
	var h header
	if err := decodeSegment(parts[0], &h); err != nil {
		return Identity{}, reject(ReasonMalformed, "the header isn't JSON")
	}
	switch {
	case h.Alg != string(jose.ES256):
		return Identity{}, reject(ReasonAlgorithm, "only ES256 is accepted")
	case h.Kid == "" || len(h.Kid) > maxKidLen:
		return Identity{}, reject(ReasonKeyID, "the header has no usable kid")
	case !strings.EqualFold(h.Typ, "JWT"):
		return Identity{}, reject(ReasonType, "typ must be JWT")
	case parts[2] == "":
		return Identity{}, reject(ReasonMalformed, "the token is not signed")
	case h.Crit != nil || h.JWK != nil || h.JKU != nil || h.X5U != nil || h.X5C != nil:
		return Identity{}, reject(ReasonMalformed, "the header names keys or critical extensions")
	}
	// The issuer, read before the signature only to choose which platform's
	// keys to try (and to refuse unknown issuers without any fetch).
	var unverified struct {
		Iss string `json:"iss"`
	}
	if err := decodeSegment(parts[1], &unverified); err != nil || unverified.Iss == "" {
		return Identity{}, reject(ReasonMalformed, "the claims aren't JSON with an iss")
	}
	p, err := s.q.GetAgentPlatformByIssuer(ctx, unverified.Iss)
	if errors.Is(store.NotFound(err), store.ErrNotFound) {
		return Identity{}, reject(ReasonUntrustedIssuer, "no trusted platform has this issuer")
	} else if err != nil {
		return Identity{}, err
	}
	if !p.Enabled {
		return Identity{}, reject(ReasonDisabledIssuer, "the platform is turned off")
	}
	key, err := s.keyFor(ctx, p, h.Kid)
	if err != nil {
		var rj *Rejection
		if errors.As(err, &rj) {
			return Identity{}, rj
		}
		return Identity{}, err
	}
	jws, err := jose.ParseSigned(raw, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil || len(jws.Signatures) != 1 {
		return Identity{}, reject(ReasonMalformed, "not a JWS signed with ES256")
	}
	payload, err := jws.Verify(key)
	if err != nil {
		return Identity{}, reject(ReasonSignature, "the signature doesn't verify")
	}
	id, err := s.check(p, payload)
	if err != nil {
		return Identity{}, err
	}
	// Last: the jti, so only a fully valid token is ever recorded, and it
	// stays recorded until it can no longer pass the time checks.
	n, err := s.q.InsertAgentTokenJTI(ctx, dbgen.InsertAgentTokenJTIParams{PlatformID: p.ID, Jti: id.JTI,
		ExpiresAt: id.ExpiresAt.Add(Skew + time.Minute)})
	if err != nil {
		return Identity{}, err
	}
	if n == 0 {
		return Identity{}, reject(ReasonReplay, "the token was used before")
	}
	return id, nil
}

// check applies the claim and time rules to a verified payload.
func (s *Service) check(p dbgen.AgentPlatform, payload []byte) (Identity, error) {
	var c claimSet
	dec := json.NewDecoder(bytes.NewReader(payload))
	if err := dec.Decode(&c); err != nil {
		return Identity{}, reject(ReasonMalformed, "the claims don't match the token format")
	}
	if c.Iss != p.Issuer {
		return Identity{}, reject(ReasonUntrustedIssuer, "iss changed")
	}
	if !audienceHas(c.Aud, p.Audience) {
		return Identity{}, reject(ReasonAudience, "aud doesn't contain the expected audience")
	}
	if c.PrincipalType != "agent" {
		return Identity{}, reject(ReasonPrincipalType, "principal_type must be agent")
	}
	if !plain(c.Sub, maxClaimLen) || c.Team == nil || !plain(c.Team.ID, maxClaimLen) || !plain(c.JTI, maxClaimLen) {
		return Identity{}, reject(ReasonClaims, "sub, team.id and jti are required")
	}
	id := Identity{Platform: p, AgentID: c.Sub, AgentName: tidy(c.Name, maxNameLen), TeamID: c.Team.ID, TeamSlug: tidy(c.Team.Slug, maxClaimLen),
		TeamKind: tidy(c.Team.Kind, 32), ThreadVisibility: tidy(c.ThreadVisibility, 32), Tool: tidy(c.Tool, 1100), ToolClaim: c.Tool, JTI: c.JTI}
	if raw := bytes.TrimSpace(c.Person); len(raw) > 0 && !bytes.Equal(raw, []byte("null")) {
		var pc personClaim
		if raw[0] != '{' || json.Unmarshal(raw, &pc) != nil || !plain(pc.Iss, 500) || !plain(pc.Sub, 500) {
			return Identity{}, reject(ReasonClaims, "person needs an iss and a sub")
		}
		if s.PersonIssuer == "" || pc.Iss != s.PersonIssuer {
			return Identity{}, reject(ReasonPersonIssuer, "person.iss isn't this portal's sign-in issuer")
		}
		id.Person = &Person{Issuer: pc.Iss, Subject: pc.Sub, Email: tidy(pc.Email, maxEmailLen)}
		id.PersonPresent = c.PersonPresent != nil && *c.PersonPresent
	}
	iat, ok1 := numericDate(c.IAT)
	exp, ok2 := numericDate(c.EXP)
	if !ok1 || !ok2 {
		return Identity{}, reject(ReasonClaims, "iat and exp are required numbers")
	}
	id.IssuedAt, id.ExpiresAt = iat, exp
	if len(bytes.TrimSpace(c.NBF)) > 0 {
		nbf, ok := numericDate(c.NBF)
		if !ok {
			return Identity{}, reject(ReasonClaims, "nbf isn't a number")
		}
		id.NotBefore = nbf
	}
	now := s.now()
	switch {
	case !exp.After(iat) || exp.Sub(iat) > MaxLifetime:
		return Identity{}, reject(ReasonLifetime, "exp - iat must be positive and at most 10 minutes")
	case now.After(exp.Add(Skew)):
		return Identity{}, reject(ReasonExpired, "the token has expired")
	case iat.After(now.Add(Skew)) || (!id.NotBefore.IsZero() && id.NotBefore.After(now.Add(Skew))):
		return Identity{}, reject(ReasonNotYetValid, "the token isn't valid yet")
	}
	return id, nil
}

// ToolMatches reports whether the token's tool claim fits a request (M-1): on
// a tools/call (call true) the claim must be present and equal name, the tool
// the client called (the name the portal exposes); on any other method (call
// false) the claim must be absent. The comparison is exact, on the claim as
// signed. PDP's tokens carry tool when the request is for a tool and not
// otherwise (the recorded tokens in testdata/pdp), so a token minted for one
// tool can't be used for another tool or another kind of request.
func (id Identity) ToolMatches(call bool, name string) bool {
	if !call {
		return id.ToolClaim == ""
	}
	return id.ToolClaim != "" && id.ToolClaim == name
}

// audienceHas reports whether aud (a JSON string or array of strings)
// contains want.
func audienceHas(aud json.RawMessage, want string) bool {
	aud = bytes.TrimSpace(aud)
	if len(aud) == 0 || want == "" {
		return false
	}
	var one string
	if aud[0] == '"' {
		return json.Unmarshal(aud, &one) == nil && one == want
	}
	var many []string
	if aud[0] != '[' || json.Unmarshal(aud, &many) != nil {
		return false
	}
	for _, a := range many {
		if a == want {
			return true
		}
	}
	return false
}

// numericDate reads a JWT NumericDate: a JSON number (never a string),
// between 0 and 2100-01-01.
func numericDate(raw json.RawMessage) (time.Time, bool) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || raw[0] == '"' {
		return time.Time{}, false
	}
	var f float64
	if json.Unmarshal(raw, &f) != nil || math.IsNaN(f) || math.IsInf(f, 0) || f < 0 || f > maxDate {
		return time.Time{}, false
	}
	sec := math.Floor(f)
	return time.Unix(int64(sec), int64((f-sec)*1e9)), true
}

// plain reports whether s is a non-empty value of at most max bytes without
// control characters or surrounding space: a stable identifier.
func plain(s string, max int) bool {
	return s != "" && len(s) <= max && utf8.ValidString(s) && s == strings.TrimSpace(s) && !strings.ContainsFunc(s, unicode.IsControl)
}

// tidy makes an informational claim safe to store and show: invalid UTF-8
// and control characters removed, at most max bytes.
func tidy(s string, max int) string {
	s = strings.ToValidUTF8(s, "")
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if len(s) > max {
		s = s[:max]
		for !utf8.ValidString(s) {
			s = s[:len(s)-1]
		}
	}
	return s
}
