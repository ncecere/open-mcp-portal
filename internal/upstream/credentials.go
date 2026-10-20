package upstream

import (
	"encoding/base64"
	"net/http"
	"net/url"
	"slices"
	"strings"
)

// Kinds of a server's own credential part (docs/registry.md, "A server's own
// credential").
const (
	CredHeader = "header" // Name: Value
	CredBearer = "bearer" // Authorization: Bearer Value
	CredBasic  = "basic"  // Authorization: Basic base64(Value:Secondary)
	CredQuery  = "query"  // ?Name=Value, added to each request and never to the saved URL
)

// Credential is one part of a server's own static credential. Value (and
// Secondary, the Basic password) are plain here: they live only in memory,
// for the length of an exchange.
type Credential struct {
	Kind, Name, Value, Secondary string
}

// authorization is the header that bearer and basic parts, and the identity
// token when no part uses it, occupy.
const authorization = "Authorization"

// AuthorizationHeader is "Authorization" when one of the credential parts
// sets that header (a header part with that name, a bearer or a basic part),
// else "". The caller picks where the identity token goes with it
// (identity.Header): the token never replaces the server's own header.
func (t Target) AuthorizationHeader() string {
	for _, c := range t.Credentials {
		if c.occupies(authorization) {
			return authorization
		}
	}
	return ""
}

func (c Credential) occupies(header string) bool {
	switch c.Kind {
	case CredHeader:
		return strings.EqualFold(c.Name, header)
	case CredBearer, CredBasic:
		return strings.EqualFold(header, authorization)
	}
	return false
}

// Secrets lists every secret value a message or a recorded payload about
// this target must not contain: the credential parts' values, the Basic
// password and the base64 form a Basic header carries, the identity token,
// the provider token and the person's bearer token. (SafeMessage and the
// payload redactor add the URL-encoded form of each.)
func (t Target) Secrets() []string {
	var out []string
	add := func(s string) {
		if s != "" && !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	for _, c := range t.Credentials {
		if c.Kind != CredBasic || len(c.Value) >= 4 {
			add(c.Value) // a Basic user name shorter than that would redact ordinary words
		}
		if c.Kind == CredBasic {
			add(c.Secondary)
			add(base64.StdEncoding.EncodeToString([]byte(c.Value + ":" + c.Secondary)))
			add(base64.RawStdEncoding.EncodeToString([]byte(c.Value + ":" + c.Secondary)))
		}
	}
	add(t.IdentityValue)
	add(t.ProviderToken)
	add(t.BearerToken)
	return out
}

// expandSecrets adds each secret's URL-encoded forms (what a query string or a
// path shows) and sorts them longest first, so a value that contains another
// is replaced whole. Empty values are dropped.
func expandSecrets(secrets []string) []string {
	var out []string
	add := func(s string) {
		if s != "" && !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	for _, s := range secrets {
		add(s)
		add(url.QueryEscape(s))
		add(strings.ReplaceAll(url.QueryEscape(s), "+", "%20")) // percent-encoded, as strict encoders write a space
		add(url.PathEscape(s))
	}
	slices.SortStableFunc(out, func(a, b string) int { return len(b) - len(a) })
	return out
}

// applyCredentials sets the credential parts on a request that is already a
// private copy: headers, Authorization for bearer and basic, and the query
// parameters merged into the request's own query (a parameter of the same name
// is replaced, the others are kept as they are).
func applyCredentials(req *http.Request, creds []Credential) {
	var query []Credential
	for _, c := range creds {
		switch c.Kind {
		case CredHeader:
			req.Header.Set(c.Name, c.Value)
		case CredBearer:
			req.Header.Set(authorization, "Bearer "+c.Value)
		case CredBasic:
			// The same encoding as net/http's SetBasicAuth.
			req.Header.Set(authorization, "Basic "+base64.StdEncoding.EncodeToString([]byte(c.Value+":"+c.Secondary)))
		case CredQuery:
			query = append(query, c)
		}
	}
	if len(query) > 0 {
		u := *req.URL
		u.RawQuery = MergeQuery(u.RawQuery, query)
		req.URL = &u
	}
}

// MergeQuery adds the query parts to a raw query string. A parameter of the
// same name already in raw is dropped; everything else in raw stays exactly as
// it was, in its order, and the new parameters follow in the order given.
func MergeQuery(raw string, parts []Credential) string {
	drop := make(map[string]bool, len(parts))
	for _, c := range parts {
		drop[c.Name] = true
	}
	var pieces []string
	for _, piece := range strings.Split(raw, "&") {
		if piece == "" {
			continue
		}
		key, _, _ := strings.Cut(piece, "=")
		if k, err := url.QueryUnescape(key); err == nil && drop[k] {
			continue
		}
		pieces = append(pieces, piece)
	}
	for _, c := range parts {
		pieces = append(pieces, url.QueryEscape(c.Name)+"="+url.QueryEscape(c.Value))
	}
	return strings.Join(pieces, "&")
}
