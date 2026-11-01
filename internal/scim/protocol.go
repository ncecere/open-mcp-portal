package scim

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ncecere/open-mcp-portal/internal/apperr"
	"github.com/ncecere/open-mcp-portal/internal/httpx"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

// SCIM schema and message URNs (RFC 7643/7644).
const (
	SchemaUser      = "urn:ietf:params:scim:schemas:core:2.0:User"
	SchemaGroup     = "urn:ietf:params:scim:schemas:core:2.0:Group"
	schemaError     = "urn:ietf:params:scim:api:messages:2.0:Error"
	schemaList      = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	schemaPatch     = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	schemaSPC       = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"
	schemaResType   = "urn:ietf:params:scim:schemas:core:2.0:ResourceType"
	schemaSchema    = "urn:ietf:params:scim:schemas:core:2.0:Schema"
	contentTypeSCIM = "application/scim+json"
	// Bounds.
	maxBody      = 1 << 20
	maxPageSize  = 200
	defaultPage  = 100
	maxPatchOps  = 100
	maxMemberOps = 1000
)

// Prefix is where the protocol is served.
const Prefix = "/scim/v2"

// scimError is an RFC 7644 3.12 error.
type scimError struct {
	Status   int
	ScimType string
	Detail   string
}

func (e *scimError) Error() string { return e.Detail }

func badRequest(scimType, detail string) error {
	return &scimError{Status: http.StatusBadRequest, ScimType: scimType, Detail: detail}
}

var (
	errNotFoundResource = &scimError{Status: http.StatusNotFound, Detail: "Resource not found"}
	errPrecondition     = &scimError{Status: http.StatusPreconditionFailed, Detail: "The resource changed: its version doesn't match If-Match"}
)

// Allow rate-limits a token; nil allows everything.
type Allow func(ctx context.Context, key string) (bool, time.Duration, error)

// Handler serves /scim/v2. Every request authenticates a directory token;
// nothing here accepts browser sessions, automation tokens or MCP
// credentials.
func (s *Service) Handler(allow Allow) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		secret, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || secret == "" {
			w.Header().Set("WWW-Authenticate", `Bearer realm="scim"`)
			writeError(w, &scimError{Status: http.StatusUnauthorized, Detail: "Send a provisioning token as Authorization: Bearer <token>"})
			return
		}
		p, err := s.Authenticate(r.Context(), strings.TrimSpace(secret))
		if errors.Is(err, ErrInvalid) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="scim", error="invalid_token"`)
			writeError(w, &scimError{Status: http.StatusUnauthorized, Detail: "Invalid provisioning token"})
			return
		} else if err != nil {
			s.internal(w, r, err)
			return
		}
		if allow != nil {
			ok, wait, err := allow(r.Context(), "scim:"+p.TokenID.String())
			if err != nil {
				s.internal(w, r, err)
				return
			}
			if !ok {
				w.Header().Set("Retry-After", strconv.Itoa(max(1, int((wait+time.Second-1)/time.Second))))
				writeError(w, &scimError{Status: http.StatusTooManyRequests, Detail: "Too many requests"})
				return
			}
		}
		s.route(w, r, p)
	})
}

func (s *Service) internal(w http.ResponseWriter, r *http.Request, err error) {
	slog.ErrorContext(r.Context(), "scim internal error", "err", err, "request_id", httpx.RequestID(r.Context()), "path", r.URL.Path)
	writeError(w, &scimError{Status: http.StatusInternalServerError, Detail: "Internal error"})
}

func (s *Service) route(w http.ResponseWriter, r *http.Request, p Principal) {
	path := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, Prefix), "/")
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(parts) > 2 || parts[0] == "" {
		writeError(w, errNotFoundResource)
		return
	}
	var id string
	if len(parts) == 2 {
		id = parts[1]
	}
	base := s.baseURL(r)
	var (
		status = http.StatusOK
		out    any
		err    error
	)
	switch parts[0] {
	case "ServiceProviderConfig":
		out, err = onlyGet(r, id, func() any { return serviceProviderConfig(base) })
	case "ResourceTypes":
		out, err = onlyGet(r, "", func() any { return resourceTypes(base, id) })
		if out == nil && err == nil {
			err = errNotFoundResource
		}
	case "Schemas":
		out, err = onlyGet(r, "", func() any { return schemas(id) })
		if out == nil && err == nil {
			err = errNotFoundResource
		}
	case "Users":
		status, out, err = s.users(r, p, id, base)
	case "Groups":
		status, out, err = s.groups(r, p, id, base)
	default:
		err = errNotFoundResource
	}
	if err != nil {
		var se *scimError
		var ae *apperr.Error
		switch {
		case errors.As(err, &se):
			writeError(w, se)
		case errors.As(err, &ae):
			writeError(w, &scimError{Status: ae.Status, Detail: ae.Message, ScimType: scimTypeOf(ae)})
		default:
			s.internal(w, r, err)
		}
		return
	}
	if status == http.StatusNoContent {
		w.WriteHeader(status)
		return
	}
	if v, ok := out.(versioned); ok {
		w.Header().Set("ETag", v.etag())
		if status == http.StatusCreated {
			w.Header().Set("Location", v.location())
		}
	}
	writeJSON(w, status, out)
}

func scimTypeOf(e *apperr.Error) string {
	switch e.Code {
	case "protected_principal", "cleanup_pending":
		return "mutability"
	}
	return ""
}

func onlyGet(r *http.Request, id string, f func() any) (any, error) {
	if r.Method != http.MethodGet {
		return nil, &scimError{Status: http.StatusMethodNotAllowed, Detail: "Method not allowed"}
	}
	if id != "" {
		return nil, errNotFoundResource
	}
	return f(), nil
}

func (s *Service) baseURL(r *http.Request) string {
	if s.AppURL != "" {
		return strings.TrimSuffix(s.AppURL, "/") + Prefix
	}
	return Prefix
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", contentTypeSCIM)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, e *scimError) {
	body := map[string]any{"schemas": []string{schemaError}, "status": strconv.Itoa(e.Status), "detail": e.Detail}
	if e.ScimType != "" {
		body["scimType"] = e.ScimType
	}
	writeJSON(w, e.Status, body)
}

// decode reads a bounded JSON object body.
func decode(r *http.Request, v any) error {
	ct := strings.ToLower(strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0]))
	if ct != "" && ct != contentTypeSCIM && ct != "application/json" {
		return &scimError{Status: http.StatusUnsupportedMediaType, Detail: "Send application/scim+json"}
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
	if err != nil {
		return badRequest("invalidSyntax", "Unreadable request body")
	}
	if len(body) > maxBody {
		return &scimError{Status: http.StatusRequestEntityTooLarge, Detail: "Request body too large"}
	}
	if err := json.Unmarshal(body, v); err != nil {
		return badRequest("invalidSyntax", "Request body is not a valid JSON object")
	}
	return nil
}

// versioned is a resource with an ETag and location.
type versioned interface {
	etag() string
	location() string
}

func etag(version int64) string { return `W/"` + strconv.FormatInt(version, 10) + `"` }

// checkIfMatch enforces an If-Match header when one is sent.
func checkIfMatch(r *http.Request, version int64) error {
	h := strings.TrimSpace(r.Header.Get("If-Match"))
	if h == "" || h == "*" {
		return nil
	}
	for _, v := range strings.Split(h, ",") {
		if strings.TrimSpace(v) == etag(version) {
			return nil
		}
	}
	return errPrecondition
}

// listParams are RFC 7644 3.4.2.4 pagination: startIndex < 1 is 1, count < 0
// is 0, count is capped.
type listParams struct {
	start, count int
}

func pagination(r *http.Request) (listParams, error) {
	p := listParams{start: 1, count: defaultPage}
	q := r.URL.Query()
	if v := q.Get("startIndex"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return p, badRequest("invalidValue", "startIndex must be an integer")
		}
		p.start = max(n, 1)
	}
	if v := q.Get("count"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return p, badRequest("invalidValue", "count must be an integer")
		}
		p.count = min(max(n, 0), maxPageSize)
	}
	if q.Get("sortBy") != "" {
		return p, badRequest("invalidValue", "Sorting is not supported")
	}
	return p, nil
}

type listResponse struct {
	Schemas      []string `json:"schemas"`
	TotalResults int64    `json:"totalResults"`
	StartIndex   int      `json:"startIndex"`
	ItemsPerPage int      `json:"itemsPerPage"`
	Resources    []any    `json:"Resources"`
}

// filterRE is the supported filter grammar: one attribute, eq, a string.
var filterRE = regexp.MustCompile(`^\s*([A-Za-z][A-Za-z0-9.:_-]*)\s+(?i:eq)\s+"((?:[^"\\]|\\.)*)"\s*$`)

// parseFilter accepts `attr eq "value"` for the given attributes
// (case-insensitive names, RFC 7644 3.4.2.2). Anything else is invalidFilter.
func parseFilter(raw string, allowed ...string) (attr, value string, err error) {
	if raw == "" {
		return "", "", nil
	}
	m := filterRE.FindStringSubmatch(raw)
	if m == nil {
		return "", "", badRequest("invalidFilter", "Only `attribute eq \"value\"` filters are supported")
	}
	name := strings.ToLower(m[1])
	for _, prefix := range []string{strings.ToLower(SchemaUser) + ":", strings.ToLower(SchemaGroup) + ":"} {
		name = strings.TrimPrefix(name, prefix)
	}
	for _, a := range allowed {
		if name == strings.ToLower(a) {
			var v string
			if err := json.Unmarshal([]byte(`"`+m[2]+`"`), &v); err != nil {
				return "", "", badRequest("invalidFilter", "Invalid filter value")
			}
			return a, v, nil
		}
	}
	return "", "", badRequest("invalidFilter", fmt.Sprintf("Filtering on %q is not supported", m[1]))
}

func parseID(id string) (uuid.UUID, error) {
	u, err := uuid.Parse(id)
	if err != nil {
		return uuid.Nil, errNotFoundResource
	}
	return u, nil
}

func notFound(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return errNotFoundResource
	}
	return err
}

func (s *Service) directory(ctx context.Context, q *dbgen.Queries, p Principal) (dbgen.ScimDirectory, error) {
	d, err := q.LockSCIMDirectoryShare(ctx)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && (d.ID != p.DirectoryID || !d.Enabled) {
		return d, &scimError{Status: http.StatusUnauthorized, Detail: "Provisioning is off"}
	}
	return d, err
}

func meta(resourceType string, created, modified time.Time, location string, version int64) map[string]any {
	return map[string]any{"resourceType": resourceType, "created": created.UTC().Format(time.RFC3339), "lastModified": modified.UTC().Format(time.RFC3339),
		"location": location, "version": etag(version)}
}

func serviceProviderConfig(base string) any {
	return map[string]any{
		"schemas":               []string{schemaSPC},
		"documentationUri":      "https://github.com/ncecere/open-mcp-portal/blob/main/docs/scim.md",
		"patch":                 map[string]any{"supported": true},
		"bulk":                  map[string]any{"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
		"filter":                map[string]any{"supported": true, "maxResults": maxPageSize},
		"changePassword":        map[string]any{"supported": false},
		"sort":                  map[string]any{"supported": false},
		"etag":                  map[string]any{"supported": true},
		"authenticationSchemes": []any{map[string]any{"type": "oauthbearertoken", "name": "Provisioning token", "description": "A directory token created by a platform admin (ompscim_)", "primary": true}},
		"meta":                  map[string]any{"resourceType": "ServiceProviderConfig", "location": base + "/ServiceProviderConfig"},
	}
}

func resourceType(base, name, endpoint, schema string) map[string]any {
	return map[string]any{"schemas": []string{schemaResType}, "id": name, "name": name, "endpoint": endpoint, "schema": schema,
		"meta": map[string]any{"resourceType": "ResourceType", "location": base + "/ResourceTypes/" + name}}
}

func resourceTypes(base, id string) any {
	user := resourceType(base, "User", "/Users", SchemaUser)
	group := resourceType(base, "Group", "/Groups", SchemaGroup)
	switch id {
	case "":
		return listResponse{Schemas: []string{schemaList}, TotalResults: 2, StartIndex: 1, ItemsPerPage: 2, Resources: []any{user, group}}
	case "User":
		return user
	case "Group":
		return group
	}
	return nil
}

func attribute(name, typ string, required bool, mutability, uniqueness string, caseExact bool) map[string]any {
	return map[string]any{"name": name, "type": typ, "multiValued": false, "required": required, "caseExact": caseExact,
		"mutability": mutability, "returned": "default", "uniqueness": uniqueness}
}

func schemas(id string) any {
	name := attribute("name", "complex", false, "readWrite", "none", false)
	name["subAttributes"] = []any{attribute("givenName", "string", false, "readWrite", "none", false),
		attribute("familyName", "string", false, "readWrite", "none", false), attribute("formatted", "string", false, "readOnly", "none", false)}
	emails := attribute("emails", "complex", false, "readWrite", "none", false)
	emails["multiValued"] = true
	emails["subAttributes"] = []any{attribute("value", "string", false, "readWrite", "none", false),
		attribute("type", "string", false, "readWrite", "none", false), attribute("primary", "boolean", false, "readWrite", "none", false)}
	groups := attribute("groups", "complex", false, "readOnly", "none", false)
	groups["multiValued"] = true
	user := map[string]any{"schemas": []string{schemaSchema}, "id": SchemaUser, "name": "User", "description": "Portal person (provisioned)",
		"attributes": []any{attribute("userName", "string", true, "readWrite", "server", false), attribute("externalId", "string", false, "readWrite", "none", true),
			name, attribute("displayName", "string", false, "readWrite", "none", false), attribute("active", "boolean", false, "readWrite", "none", false), emails, groups},
		"meta": map[string]any{"resourceType": "Schema", "location": "/Schemas/" + SchemaUser}}
	members := attribute("members", "complex", false, "readWrite", "none", false)
	members["multiValued"] = true
	members["subAttributes"] = []any{attribute("value", "string", false, "immutable", "none", true), attribute("display", "string", false, "readOnly", "none", false)}
	group := map[string]any{"schemas": []string{schemaSchema}, "id": SchemaGroup, "name": "Group", "description": "Directory group",
		"attributes": []any{attribute("displayName", "string", true, "readWrite", "none", false), attribute("externalId", "string", false, "readWrite", "none", true), members},
		"meta":       map[string]any{"resourceType": "Schema", "location": "/Schemas/" + SchemaGroup}}
	switch id {
	case "":
		return listResponse{Schemas: []string{schemaList}, TotalResults: 2, StartIndex: 1, ItemsPerPage: 2, Resources: []any{user, group}}
	case SchemaUser:
		return user
	case SchemaGroup:
		return group
	}
	return nil
}
