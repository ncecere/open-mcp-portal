package registry

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/ncecere/open-mcp-portal/internal/apperr"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/internal/upstream"
)

// A server's own credential is a list of at most eight parts (decision 70,
// docs/registry.md "A server's own credential"): header, bearer, basic and
// query. A server that has never had its credential saved with the list keeps
// its one static header in the legacy columns of mcp_servers, which read as a
// single header part; saving the list moves the credential into
// mcp_server_credentials and clears the legacy columns in the same
// transaction, so it is in one place or the other, never both.

// MaxCredentials is the most parts a server can have.
const MaxCredentials = 8

// Kinds of credential part (the API's values).
const (
	CredHeader = upstream.CredHeader
	CredBearer = upstream.CredBearer
	CredBasic  = upstream.CredBasic
	CredQuery  = upstream.CredQuery
)

// queryNameRE is a query parameter name: plain characters, so no encoding
// question arises, and never an mcp-* name (those are the gateway's).
var queryNameRE = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)

// CredentialAAD binds a part's sealed value to its row.
func CredentialAAD(id uuid.UUID) []byte { return []byte("mcp_server_credential:" + id.String()) }

// CredentialSecondaryAAD binds a Basic part's sealed password to its row, apart
// from the user name's AAD so the two can't be swapped.
func CredentialSecondaryAAD(id uuid.UUID) []byte {
	return []byte("mcp_server_credential:" + id.String() + ":secondary")
}

// CredentialInput is one part as a client sends it. Keep keeps the stored
// part of that kind and name (and its values) as it is; otherwise Value (and
// Secondary, the Basic password) are the new values, entered again.
type CredentialInput struct {
	Kind, Name, Value, Secondary string
	Keep                         bool
}

// CredentialView is a part as the API shows it: never its values.
type CredentialView struct {
	Kind string
	Name string // "" for bearer and basic
	Hint string
}

func (c CredentialView) key() string { return credKey(c.Kind, c.Name) }

func credKey(kind, name string) string { return kind + ":" + strings.ToLower(name) }

// occupiesAuthorization reports whether the part sets the Authorization header
// (a header part named so, a bearer, a basic).
func occupiesAuthorization(kind, name string) bool {
	return kind == CredBearer || kind == CredBasic || (kind == CredHeader && strings.EqualFold(name, "Authorization"))
}

// authorizationName is "Authorization" when any of the parts sets it, for
// oauthConflicts (a server in oauth mode can't have a static Authorization).
func authorizationName(views []CredentialView) string {
	for _, v := range views {
		if occupiesAuthorization(v.Kind, v.Name) {
			return "Authorization"
		}
	}
	return ""
}

func invalidCredential(i int, code, msg string) error {
	e := apperr.Invalid(code, msg)
	e.Details = map[string]any{"field": fmt.Sprintf("credentials[%d]", i)}
	return e
}

// checkSecret checks a credential value: 1-4096 characters on one line.
func checkSecret(i int, what, v string) error {
	if v == "" || len(v) > 4096 || strings.ContainsAny(v, "\r\n\x00") {
		return invalidCredential(i, "invalid_auth_value", "The "+what+" must be 1-4096 characters on one line")
	}
	return nil
}

// checkCredentialShape checks the parts of a request: how many, their kinds,
// names, values (for the ones with new values) and that no two share a kind
// and name or set Authorization twice. Keep entries carry no values.
func checkCredentialShape(items []CredentialInput) error {
	if len(items) > MaxCredentials {
		e := apperr.Invalid("too_many_credentials", fmt.Sprintf("A server can have at most %d credential parts", MaxCredentials))
		e.Details = map[string]any{"field": "credentials", "max": MaxCredentials}
		return e
	}
	seen := map[string]bool{}
	authz := 0
	for i, c := range items {
		switch c.Kind {
		case CredHeader:
			if !headerNameRE.MatchString(c.Name) || reservedHeaders[strings.ToLower(c.Name)] {
				return invalidCredential(i, "invalid_auth_header", "The header name must be a valid HTTP header such as Authorization or X-API-Key")
			}
		case CredQuery:
			if !queryNameRE.MatchString(c.Name) || strings.HasPrefix(strings.ToLower(c.Name), "mcp-") {
				return invalidCredential(i, "invalid_auth_query",
					"The query parameter name must be 1-64 letters, digits, dots, hyphens or underscores, and can't start with mcp-")
			}
		case CredBearer, CredBasic:
			if c.Name != "" {
				return invalidCredential(i, "invalid_credential", "A "+c.Kind+" part has no name")
			}
		default:
			return invalidCredential(i, "invalid_credential_kind", "kind must be header, bearer, basic or query")
		}
		if seen[credKey(c.Kind, c.Name)] {
			return invalidCredential(i, "invalid_credential", "Two parts have the same kind and name")
		}
		seen[credKey(c.Kind, c.Name)] = true
		if occupiesAuthorization(c.Kind, c.Name) {
			if authz++; authz > 1 {
				return unprocessable("auth_conflict", "Only one part can set the Authorization header (a header named Authorization, a bearer or a basic part)",
					map[string]any{"reason": "authorization_twice", "field": fmt.Sprintf("credentials[%d]", i)})
			}
		}
		if c.Keep {
			if c.Value != "" || c.Secondary != "" {
				return invalidCredential(i, "invalid_credential", "A part that is kept has no new value")
			}
			continue
		}
		switch c.Kind {
		case CredBasic:
			if strings.Contains(c.Value, ":") {
				return invalidCredential(i, "invalid_auth_value", "A Basic user name can't contain a colon")
			}
			if err := checkSecret(i, "Basic user name", c.Value); err != nil {
				return err
			}
			if err := checkSecret(i, "Basic password", c.Secondary); err != nil {
				return err
			}
		default:
			if c.Secondary != "" {
				return invalidCredential(i, "invalid_credential", "Only a basic part has a second value")
			}
			if err := checkSecret(i, "value", c.Value); err != nil {
				return err
			}
		}
	}
	return nil
}

// credentialPlan is the outcome of a credential change: the parts to store
// (in order), and what the change means.
type credentialPlan struct {
	// rows are the parts to insert, in order, after the old ones are deleted.
	rows []dbgen.InsertMCPServerCredentialParams
	// views are the parts as shown (the audit and the digest cover them).
	views []CredentialView
	// write: the stored parts (the table, or the legacy columns) change.
	write bool
	// valueChanged: a new value was entered, or a part was added or removed.
	valueChanged bool
}

// storedCredentials is a server's parts as stored: the table's rows in order,
// or else its legacy header.
type storedCredentials struct {
	rows []dbgen.McpServerCredential
	// legacy is the one header in the mcp_servers columns (nil: none).
	legacy *CredentialView
}

func loadStored(ctx context.Context, q *dbgen.Queries, sv dbgen.McpServer) (storedCredentials, error) {
	rows, err := q.ListMCPServerCredentials(ctx, sv.ID)
	if err != nil {
		return storedCredentials{}, err
	}
	out := storedCredentials{rows: rows}
	if len(rows) == 0 && sv.AuthHeaderName != nil && sv.AuthValueCipher != nil {
		out.legacy = &CredentialView{Kind: CredHeader, Name: *sv.AuthHeaderName, Hint: sv.AuthValueHint}
	}
	return out, nil
}

func (s storedCredentials) views() []CredentialView {
	if s.legacy != nil {
		return []CredentialView{*s.legacy}
	}
	return rowViews(s.rows)
}

func (s storedCredentials) any() bool { return s.legacy != nil || len(s.rows) > 0 }

func rowViews(rows []dbgen.McpServerCredential) []CredentialView {
	out := make([]CredentialView, len(rows))
	for i, r := range rows {
		out[i] = CredentialView{Kind: r.Kind, Name: deref(r.Name), Hint: r.Hint}
	}
	return out
}

// credentialViews are every listed server's parts, by server ID: the table's
// rows, else the legacy header.
func credentialViews(ctx context.Context, q *dbgen.Queries, servers []dbgen.McpServer) (map[uuid.UUID][]CredentialView, error) {
	ids := make([]uuid.UUID, len(servers))
	for i, sv := range servers {
		ids[i] = sv.ID
	}
	rows, err := q.ListMCPServerCredentialsFor(ctx, ids)
	if err != nil {
		return nil, err
	}
	by := map[uuid.UUID][]dbgen.McpServerCredential{}
	for _, r := range rows {
		by[r.ServerID] = append(by[r.ServerID], r)
	}
	out := make(map[uuid.UUID][]CredentialView, len(servers))
	for _, sv := range servers {
		switch {
		case len(by[sv.ID]) > 0:
			out[sv.ID] = rowViews(by[sv.ID])
		case sv.AuthHeaderName != nil && sv.AuthValueCipher != nil:
			out[sv.ID] = []CredentialView{{Kind: CredHeader, Name: *sv.AuthHeaderName, Hint: sv.AuthValueHint}}
		default:
			out[sv.ID] = []CredentialView{}
		}
	}
	return out, nil
}

// planCredentials works out a request's new list of parts for server cur: every
// part either keeps a stored one (nothing sealed again, except a legacy
// header, which moves to a row of its own) or has its values sealed now. The
// caller has run checkCredentialShape.
func (s *Service) planCredentials(cur dbgen.McpServer, stored storedCredentials, items []CredentialInput) (credentialPlan, error) {
	var plan credentialPlan
	old := stored.views()
	oldKeys := map[string]bool{}
	for _, v := range old {
		oldKeys[v.key()] = true
	}
	// same: every part is kept, in the order it had, and none is added or
	// dropped: nothing to write.
	same := len(items) == len(old)
	newKeys := map[string]bool{}
	for i, c := range items {
		key := credKey(c.Kind, c.Name)
		newKeys[key] = true
		part := dbgen.InsertMCPServerCredentialParams{ID: uuid.New(), ServerID: cur.ID, Position: int16(i), Kind: c.Kind, CreatedAt: time.Now()}
		if c.Kind == CredHeader || c.Kind == CredQuery {
			name := c.Name
			part.Name = &name
		}
		if i >= len(old) || old[i].key() != key || !c.Keep {
			same = false
		}
		if c.Keep {
			if !oldKeys[key] {
				return plan, invalidCredential(i, "invalid_credential", "There is no stored "+c.Kind+" part to keep: enter its value")
			}
			if err := s.keepPart(cur, stored, &part, c); err != nil {
				return plan, err
			}
		} else {
			plan.valueChanged = true
			var err error
			if part.ValueCipher, err = s.box.Seal([]byte(c.Value), CredentialAAD(part.ID)); err != nil {
				return plan, err
			}
			hintOf := c.Value
			if c.Kind == CredBasic {
				if part.SecondaryCipher, err = s.box.Seal([]byte(c.Secondary), CredentialSecondaryAAD(part.ID)); err != nil {
					return plan, err
				}
				hintOf = c.Secondary
			}
			part.Hint = valueHint(hintOf)
		}
		plan.rows = append(plan.rows, part)
		plan.views = append(plan.views, CredentialView{Kind: c.Kind, Name: c.Name, Hint: part.Hint})
	}
	for k := range oldKeys {
		if !newKeys[k] {
			plan.valueChanged = true // a part was removed
		}
	}
	plan.valueChanged = plan.valueChanged || len(newKeys) != len(oldKeys)
	plan.write = !same
	return plan, nil
}

// keepPart fills part with the stored part it keeps: a row's own sealed
// values (the same row ID, so their AAD still holds), or the legacy header
// opened and sealed again under the new row.
func (s *Service) keepPart(cur dbgen.McpServer, stored storedCredentials, part *dbgen.InsertMCPServerCredentialParams, c CredentialInput) error {
	if stored.legacy != nil {
		plain, err := s.box.Open(cur.AuthValueCipher, ServerAAD(cur.ID))
		if err != nil {
			return errUndecryptable
		}
		if part.ValueCipher, err = s.box.Seal(plain, CredentialAAD(part.ID)); err != nil {
			return err
		}
		part.Hint = cur.AuthValueHint
		return nil
	}
	for _, r := range stored.rows {
		if credKey(r.Kind, deref(r.Name)) == credKey(c.Kind, c.Name) {
			part.ID, part.ValueCipher, part.SecondaryCipher, part.Hint, part.CreatedAt = r.ID, r.ValueCipher, r.SecondaryCipher, r.Hint, r.CreatedAt
			return nil
		}
	}
	return nil
}

// storeCredentials writes a plan's parts: the old rows go and the new ones
// are inserted, in the caller's transaction.
func storeCredentials(ctx context.Context, q *dbgen.Queries, serverID uuid.UUID, plan credentialPlan) error {
	if err := q.DeleteMCPServerCredentials(ctx, serverID); err != nil {
		return err
	}
	for _, r := range plan.rows {
		if _, err := q.InsertMCPServerCredential(ctx, r); err != nil {
			return err
		}
	}
	return nil
}

// openCredentials decrypts a server's parts for a request to it.
func (s *Service) openCredentials(ctx context.Context, sv dbgen.McpServer) ([]upstream.Credential, error) {
	rows, err := s.q.ListMCPServerCredentials(ctx, sv.ID)
	if err != nil {
		return nil, err
	}
	var out []upstream.Credential
	if len(rows) == 0 {
		if sv.AuthHeaderName != nil && sv.AuthValueCipher != nil {
			plain, err := s.box.Open(sv.AuthValueCipher, ServerAAD(sv.ID))
			if err != nil {
				return nil, errUndecryptable
			}
			out = append(out, upstream.Credential{Kind: CredHeader, Name: *sv.AuthHeaderName, Value: string(plain)})
		}
		return out, nil
	}
	for _, r := range rows {
		plain, err := s.box.Open(r.ValueCipher, CredentialAAD(r.ID))
		if err != nil {
			return nil, errUndecryptable
		}
		c := upstream.Credential{Kind: r.Kind, Name: deref(r.Name), Value: string(plain)}
		if r.SecondaryCipher != nil {
			second, err := s.box.Open(r.SecondaryCipher, CredentialSecondaryAAD(r.ID))
			if err != nil {
				return nil, errUndecryptable
			}
			c.Secondary = string(second)
		}
		out = append(out, c)
	}
	return out, nil
}

// credentialSnapshot is the parts as audited: kind and name only.
func credentialSnapshot(views []CredentialView) []map[string]any {
	out := make([]map[string]any, len(views))
	for i, v := range views {
		out[i] = map[string]any{"kind": v.Kind}
		if v.Name != "" {
			out[i]["name"] = v.Name
		}
	}
	return out
}

// errCredentialsInUse: the old single-header fields can't edit a credential
// that has been saved as a list of parts.
var errCredentialsInUse = unprocessable("credentials_in_use",
	"This server's credential is a list of parts: change it with credentials, not authHeaderName and authValue.",
	map[string]any{"field": "credentials"})

// checkUpdateCredentials checks how a request names the credential: the list
// (valid, and not together with the single header's fields), or the single
// header's fields (only while the credential is not a list of parts).
func checkUpdateCredentials(in UpdateInput, stored storedCredentials) error {
	if in.Credentials != nil {
		if in.AuthHeaderName != nil || in.AuthValue != nil {
			return apperr.Invalid("invalid_auth_header", "Send either authHeaderName and authValue or credentials, not both")
		}
		return checkCredentialShape(*in.Credentials)
	}
	if len(stored.rows) > 0 && (in.AuthHeaderName != nil || in.AuthValue != nil) {
		return errCredentialsInUse
	}
	return nil
}

// finalAuthorization is "Authorization" when the credential after the update
// sets that header (else the legacy header's name, which oauthConflicts
// compares), and whether the server has any credential then.
func finalAuthorization(cur dbgen.McpServer, stored storedCredentials, in UpdateInput) (header string, has bool) {
	switch {
	case in.Credentials != nil:
		for _, c := range *in.Credentials {
			has = true
			if occupiesAuthorization(c.Kind, c.Name) {
				header = "Authorization"
			}
		}
		return header, has
	case len(stored.rows) > 0:
		return authorizationName(rowViews(stored.rows)), true
	}
	header = deref(cur.AuthHeaderName)
	if in.AuthHeaderName != nil {
		header = *in.AuthHeaderName
	}
	return header, header != ""
}
