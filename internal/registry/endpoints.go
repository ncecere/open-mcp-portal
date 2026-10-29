package registry

import (
	"context"
	"encoding/json"
	"net/url"
	"reflect"
	"time"

	"github.com/google/uuid"
	"github.com/ncecere/open-mcp-portal/internal/apperr"
	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

const MaxExtraEndpoints = 2

// EndpointInput is an extra replica, never the primary. Values are independent;
// nil Credentials retains only an existing unchanged-origin entry.
type EndpointInput struct {
	ID          uuid.UUID
	URL         string
	Enabled     *bool
	Credentials *[]CredentialInput
}

type EndpointView struct {
	ID          uuid.UUID
	Position    int32
	URL         string
	Enabled     bool
	AuthMode    string
	Credentials []CredentialView
}

type endpointPlan struct {
	before, after   []EndpointView
	rows            []dbgen.InsertMCPServerEndpointParams
	changed, review bool
}

func unsupportedFailover() error {
	return unprocessable("failover_not_supported", "Additional endpoints require no-auth or static credentials, without provider requirements or TLS settings. Remove the additional endpoints before choosing another credential mode.", nil)
}

func checkEndpointMode(mode string, provider, tls bool) error {
	if (mode != AuthNone && mode != AuthStaticHeader) || provider || tls {
		return unsupportedFailover()
	}
	return nil
}

func checkEndpointServer(sv dbgen.McpServer, tls bool) error {
	if sv.AuthMode != "" && sv.AuthMode != AuthNone && sv.AuthMode != AuthStaticHeader {
		return unsupportedFailover()
	}
	return checkEndpointMode(AuthModeOf(sv), sv.AuthProviderID.Valid, tls)
}

func checkEndpointRole(role string) error {
	if !authz.RoleAtLeast(role, authz.RoleAdmin) {
		return apperr.Forbidden("Only the server team's owners and admins can change additional endpoints")
	}
	return nil
}

// normalizeEndpoints may resolve destinations: call outside any mutation
// transaction/authority lock, after the initial role/revision checks.
func (s *Service) normalizeEndpoints(ctx context.Context, items []EndpointInput) ([]EndpointInput, error) {
	if len(items) > MaxExtraEndpoints {
		return nil, apperr.Invalid("too_many_endpoints", "A server can have at most two additional endpoints")
	}
	out := make([]EndpointInput, len(items))
	copy(out, items)
	for i := range out {
		normalized, err := s.client.NormalizeURL(ctx, out[i].URL)
		if err != nil {
			return nil, err
		}
		out[i].URL = normalized
	}
	return out, nil
}

func endpointURLKey(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "invalid:" + raw
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	return originOf(raw) + path + "?" + u.RawQuery
}

func endpointRowView(row dbgen.McpServerEndpoint) (EndpointView, error) {
	var parts []CredentialView
	if err := json.Unmarshal(row.CredentialShapes, &parts); err != nil {
		return EndpointView{}, endpointCredentialFailure()
	}
	if parts == nil {
		parts = []CredentialView{}
	}
	if row.ID == uuid.Nil || row.ServerID == uuid.Nil || row.Position < 1 || row.Position > MaxExtraEndpoints || len(parts) > MaxCredentials ||
		row.CredentialOrigin != originOf(row.URL) || (row.AuthMode != AuthNone && row.AuthMode != AuthStaticHeader) {
		return EndpointView{}, endpointCredentialFailure()
	}
	if row.AuthMode == AuthNone && (len(parts) != 0 || len(row.CredentialsCipher) != 0) || row.AuthMode == AuthStaticHeader && (len(parts) == 0 || len(row.CredentialsCipher) == 0) {
		return EndpointView{}, endpointCredentialFailure()
	}
	return EndpointView{ID: row.ID, Position: int32(row.Position), URL: row.URL, Enabled: row.Enabled, AuthMode: row.AuthMode, Credentials: parts}, nil
}

// planEndpointRows is pure control-plane work: no SQL, resolver or HTTP call.
// Its caller rechecks authority under the server row lock and supplies URLs
// normalized in the preparation phase. The envelope verifies server/origin.
func (s *Service) planEndpointRows(sv dbgen.McpServer, stored []dbgen.McpServerEndpoint, tls bool, role string, input *[]EndpointInput, create bool) (endpointPlan, error) {
	p := endpointPlan{before: []EndpointView{}, after: []EndpointView{}}
	if input != nil {
		if err := checkEndpointRole(role); err != nil {
			return p, err
		}
	}
	if input != nil && len(*input) == 0 {
		// An owner may remove corrupt/incompatible endpoint state without
		// opening its ciphertext. Never require a broken secret to delete it.
		for _, row := range stored {
			if row.ServerID != sv.ID {
				return p, endpointCredentialFailure()
			}
			v, err := endpointRowView(row)
			if err != nil {
				v = EndpointView{ID: row.ID, Position: int32(row.Position), URL: row.URL, Enabled: row.Enabled, AuthMode: row.AuthMode, Credentials: []CredentialView{}}
			}
			p.before = append(p.before, v)
		}
		p.changed, p.review = len(stored) > 0, len(stored) > 0
		return p, nil
	}
	byID := map[uuid.UUID]dbgen.McpServerEndpoint{}
	for _, row := range stored {
		v, err := endpointRowView(row)
		if err != nil {
			return p, err
		}
		if row.ServerID != sv.ID {
			return p, endpointCredentialFailure()
		}
		p.before = append(p.before, v)
		byID[row.ID] = row
	}
	count := len(stored)
	if input != nil {
		count = len(*input)
	}
	if count > MaxExtraEndpoints {
		return p, apperr.Invalid("too_many_endpoints", "A server can have at most two additional endpoints")
	}
	if count > 0 {
		if err := checkEndpointServer(sv, tls); err != nil {
			return p, err
		}
	}
	if input == nil {
		for _, row := range stored {
			if row.AuthMode != AuthModeOf(sv) || endpointURLKey(row.URL) == endpointURLKey(sv.URL) {
				return p, unsupportedFailover()
			}
		}
		p.after = p.before
		return p, nil
	}
	seenID := map[uuid.UUID]bool{}
	seenURL := map[string]bool{endpointURLKey(sv.URL): true}
	for i, item := range *input {
		if item.URL == "" || len(item.URL) > 500 {
			return p, apperr.Invalid("invalid_endpoint", "The endpoint URL must be 1-500 characters")
		}
		key := endpointURLKey(item.URL)
		if seenURL[key] {
			return p, apperr.Invalid("duplicate_endpoint", "The primary and additional endpoint URLs must be distinct")
		}
		seenURL[key] = true
		old, exists := byID[item.ID]
		if item.ID != uuid.Nil && (!exists || create || seenID[item.ID]) {
			return p, apperr.Invalid("invalid_endpoint", "The endpoint ID is not a unique entry of this server")
		}
		id := item.ID
		if id == uuid.Nil {
			id = uuid.New()
		}
		seenID[id] = true
		enabled := true
		if exists {
			enabled = old.Enabled
		}
		if item.Enabled != nil {
			enabled = *item.Enabled
		}
		origin := originOf(item.URL)
		mode := AuthModeOf(sv)
		cipher, views, valueChanged, err := s.planEndpointCredential(sv.ID, id, mode, origin, old, exists, item.Credentials)
		if err != nil {
			return p, err
		}
		shape, err := json.Marshal(views)
		if err != nil {
			return p, err
		}
		now := time.Now()
		created := now
		if exists {
			created = old.CreatedAt
		}
		row := dbgen.InsertMCPServerEndpointParams{ID: id, ServerID: sv.ID, Position: int16(i + 1), URL: item.URL, Enabled: enabled, AuthMode: mode, CredentialOrigin: origin, CredentialsCipher: cipher, CredentialShapes: shape, CreatedAt: created, UpdatedAt: now}
		p.rows = append(p.rows, row)
		v := EndpointView{ID: id, Position: int32(i + 1), URL: item.URL, Enabled: enabled, AuthMode: mode, Credentials: views}
		p.after = append(p.after, v)
		if !exists || valueChanged || old.Position != row.Position || old.URL != row.URL || old.Enabled != row.Enabled || old.AuthMode != row.AuthMode {
			p.changed = true
		}
		if !exists || old.Position != row.Position || old.URL != row.URL || old.Enabled != row.Enabled || old.AuthMode != row.AuthMode || !sameEndpointShape(p.beforeFor(id), v) {
			p.review = true
		}
	}
	if len(stored) != len(*input) {
		p.changed, p.review = true, true
	}
	if !reflect.DeepEqual(endpointIDs(p.before), endpointIDs(p.after)) {
		p.changed, p.review = true, true
	}
	return p, nil
}

func endpointIDs(v []EndpointView) []uuid.UUID {
	out := make([]uuid.UUID, len(v))
	for i, e := range v {
		out[i] = e.ID
	}
	return out
}
func (p endpointPlan) beforeFor(id uuid.UUID) EndpointView {
	for _, v := range p.before {
		if v.ID == id {
			return v
		}
	}
	return EndpointView{}
}
func sameEndpointShape(a, b EndpointView) bool {
	if len(a.Credentials) != len(b.Credentials) {
		return false
	}
	for i, c := range a.Credentials {
		if c.Kind != b.Credentials[i].Kind || c.Name != b.Credentials[i].Name {
			return false
		}
	}
	return true
}

func storeEndpoints(ctx context.Context, q *dbgen.Queries, serverID uuid.UUID, p endpointPlan) error {
	if !p.changed {
		return nil
	}
	// Reinsert stable IDs atomically so ordered swaps cannot collide with the
	// two-position unique constraint. Historical checks have no deletion FK.
	if err := q.DeleteMCPServerEndpoints(ctx, serverID); err != nil {
		return err
	}
	for _, row := range p.rows {
		if _, err := q.InsertMCPServerEndpoint(ctx, row); err != nil {
			return err
		}
	}
	return nil
}
