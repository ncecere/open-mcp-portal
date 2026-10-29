package ompcli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ncecere/open-mcp-portal/pkg/ompclient"
)

// fakePortal is an in-memory portal that speaks the token-callable part of the
// /v1 contract, built from the generated client's own types so a response the
// CLI cannot decode fails here too. It enforces token kinds, scopes, If-Match
// and the rules the CLI relies on, and records every request.
type fakePortal struct {
	t   *testing.T
	srv *httptest.Server
	mu  sync.Mutex

	tokens   map[string]ompclient.AutomationToken
	servers  map[string]*fakeServer // by slug
	teams    map[string]*fakeTeam
	gateways map[string]*fakeGateway
	options  []ompclient.GatewayOption
	limits   []ompclient.PlatformRateLimit
	limitRev int64

	policy          string                         // self_publish or approval_required
	discover        func(url string) (int, string) // tools, error message
	testOK          bool
	refreshChanged  int
	requests        []recordedRequest
	forceStatus     map[string]int // "METHOD path-suffix" -> status, for error mapping tests
	echoAuthInError bool           // a hostile portal that repeats the Authorization header in an error
}

type recordedRequest struct {
	Method, Path, Auth string
	Body               []byte
	IfMatch            string
}

type fakeServer struct {
	ompclient.McpServer
	secret    string
	refreshed bool
}

type fakeTeam struct {
	ompclient.Team
	limits map[string]*int64
}

type fakeGateway struct {
	ompclient.Gateway
	caps   []ompclient.GatewayCapability
	grants []ompclient.GatewayGrant
}

const tokenBody = "0123456789012345678901234567890123456789012" // 43 characters

func newFakePortal(t *testing.T) *fakePortal {
	t.Helper()
	f := &fakePortal{
		t: t, tokens: map[string]ompclient.AutomationToken{}, servers: map[string]*fakeServer{},
		teams: map[string]*fakeTeam{}, gateways: map[string]*fakeGateway{},
		policy: "self_publish", testOK: true, limitRev: 1, forceStatus: map[string]int{},
		discover: func(string) (int, string) { return 3, "" },
	}
	for _, k := range []string{"person_per_minute", "credential_per_minute", "service_account_per_minute", "gateway_per_minute", "server_per_minute"} {
		d := int64(600)
		f.limits = append(f.limits, ompclient.PlatformRateLimit{Key: ompclient.RateLimitKey(k), Default: &d})
	}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakePortal) URL() string { return f.srv.URL }

// addToken registers a token and returns its secret. team is the publisher's team slug.
func (f *fakePortal) addToken(kind ompclient.AutomationTokenKind, team string, scopes ...string) string {
	prefix := "ompadm_"
	if kind == ompclient.AutomationTokenKindTeamPublisher {
		prefix = "omppub_"
	}
	secret := prefix + fmt.Sprintf("%02d", len(f.tokens)) + tokenBody[2:]
	tok := ompclient.AutomationToken{
		Id: uuid.New(), Kind: kind, Name: "ci", Prefix: secret[:15], Status: "active",
		CreatedAt: time.Now(), ExpiresAt: time.Date(2027, 1, 2, 3, 4, 5, 0, time.UTC),
	}
	for _, s := range scopes {
		tok.Scopes = append(tok.Scopes, ompclient.AutomationTokenScope(s))
	}
	if team != "" {
		tok.Team = &ompclient.TeamRef{Id: uuid.New(), Slug: team, Name: team}
	}
	f.tokens[secret] = tok
	return secret
}

func (f *fakePortal) publisher(team string) string {
	return f.addToken(ompclient.AutomationTokenKindTeamPublisher, team, "servers:read", "servers:write")
}

func (f *fakePortal) platformAdmin() string {
	return f.addToken(ompclient.AutomationTokenKindPlatformAdmin, "", "platform:read", "platform:write")
}

func (f *fakePortal) lastRequests(n int) []recordedRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	if n > len(f.requests) {
		n = len(f.requests)
	}
	return append([]recordedRequest(nil), f.requests[len(f.requests)-n:]...)
}

func (f *fakePortal) countRequests(method, pathPrefix string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, r := range f.requests {
		if r.Method == method && strings.HasPrefix(r.Path, pathPrefix) {
			n++
		}
	}
	return n
}

// ---- responses ---------------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeData(w http.ResponseWriter, status int, v any) {
	writeJSON(w, status, map[string]any{"data": v})
}

func writeErr(w http.ResponseWriter, status int, code, msg string, details map[string]any) {
	e := map[string]any{"code": code, "message": msg}
	if details != nil {
		e["details"] = details
	}
	writeJSON(w, status, map[string]any{"error": e})
}

func etag(w http.ResponseWriter, rev int64) {
	w.Header().Set("ETag", `"`+strconv.FormatInt(rev, 10)+`"`)
}

func (f *fakePortal) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := readAll(r)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, recordedRequest{r.Method, r.URL.Path, r.Header.Get("Authorization"), body, r.Header.Get("If-Match")})
	if st, ok := f.forceStatus[r.Method+" "+r.URL.Path]; ok {
		writeErr(w, st, "forced_"+strconv.Itoa(st), "forced "+strconv.Itoa(st), map[string]any{"field": "x"})
		return
	}
	auth := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	tok, ok := f.tokens[auth]
	if !ok {
		msg := "invalid token"
		if f.echoAuthInError {
			msg = "bad credentials: " + r.Header.Get("Authorization")
		}
		writeErr(w, 401, "invalid_token", msg, nil)
		return
	}
	path := r.URL.Path
	switch {
	case path == "/v1/token" && r.Method == "GET":
		writeData(w, 200, tok)
	case strings.HasPrefix(path, "/v1/teams/"):
		f.serveTeamRoute(w, r, body, tok)
	case strings.HasPrefix(path, "/v1/admin/"):
		f.serveAdmin(w, r, body, tok)
	default:
		writeErr(w, 404, "not_found", "no such route", nil)
	}
}

func readAll(r *http.Request) ([]byte, error) {
	var b bytes.Buffer
	_, err := b.ReadFrom(r.Body)
	return b.Bytes(), err
}

func hasTokenScope(tok ompclient.AutomationToken, want string) bool {
	for _, s := range tok.Scopes {
		if string(s) == want {
			return true
		}
	}
	return false
}

func denyScope(w http.ResponseWriter, tok ompclient.AutomationToken, want string) {
	scopes := []any{}
	for _, s := range tok.Scopes {
		scopes = append(scopes, string(s))
	}
	writeErr(w, 403, "token_not_allowed", "this token may not do that", map[string]any{"requiredScopes": []any{want}, "tokenScopes": scopes})
}

// ---- team routes (servers) ---------------------------------------------------

func (f *fakePortal) serveTeamRoute(w http.ResponseWriter, r *http.Request, body []byte, tok ompclient.AutomationToken) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/v1/teams/"), "/")
	team := parts[0]
	if tok.Kind != ompclient.AutomationTokenKindTeamPublisher {
		writeErr(w, 403, "token_not_allowed", "a platform token never reaches team routes", nil)
		return
	}
	if tok.Team.Slug != team {
		writeErr(w, 404, "team_not_found", "team not found", nil)
		return
	}
	write := r.Method != "GET"
	if write && !hasTokenScope(tok, "servers:write") {
		denyScope(w, tok, "servers:write")
		return
	}
	if len(parts) < 2 || parts[1] != "mcp-servers" {
		writeErr(w, 404, "not_found", "no such route", nil)
		return
	}
	switch {
	case len(parts) == 2 && r.Method == "GET":
		q := strings.ToLower(r.URL.Query().Get("q"))
		var items []ompclient.McpServer
		for _, s := range f.sortedServers() {
			if s.TeamSlug == team && (q == "" || strings.Contains(s.Slug, q) || strings.Contains(strings.ToLower(s.Name), q)) {
				items = append(items, s.McpServer)
			}
		}
		if items == nil {
			items = []ompclient.McpServer{}
		}
		writeData(w, 200, ompclient.McpServerPage{Items: items})
	case len(parts) == 2 && r.Method == "POST":
		f.createServer(w, body, team)
	default:
		id, err := uuid.Parse(parts[2])
		var sv *fakeServer
		for _, s := range f.servers {
			if err == nil && s.Id == id && s.TeamSlug == team {
				sv = s
			}
		}
		if sv == nil {
			writeErr(w, 404, "server_not_found", "server not found", nil)
			return
		}
		f.serveServer(w, r, body, sv, parts[3:])
	}
}

func (f *fakePortal) sortedServers() []*fakeServer {
	out := make([]*fakeServer, 0, len(f.servers))
	for _, s := range f.servers {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Slug < out[j].Slug })
	return out
}

func origin(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	return u.Scheme + "://" + u.Host
}

func (f *fakePortal) createServer(w http.ResponseWriter, body []byte, team string) {
	var in ompclient.McpServerCreate
	if err := json.Unmarshal(body, &in); err != nil {
		writeErr(w, 400, "invalid_json", err.Error(), nil)
		return
	}
	if _, taken := f.servers[in.Slug]; taken {
		writeErr(w, 409, "slug_taken", "another server uses this slug", nil)
		return
	}
	mode := ompclient.McpServerAuthModeNone
	if in.AuthMode != nil {
		mode = *in.AuthMode
	}
	sv := &fakeServer{McpServer: ompclient.McpServer{
		Id: uuid.New(), Slug: in.Slug, Name: in.Name, Url: in.Url, Description: deref(in.Description),
		Enabled: in.Enabled == nil || *in.Enabled, TimeoutSeconds: 30, TeamSlug: team, TeamName: team,
		AuthMode: &mode, PublishState: ompclient.PublishStatePrivate, Revision: 1,
		EffectivePublishPolicy: ompclient.PublishPolicy(f.policy),
		Health:                 ompclient.ServerHealth{Status: ompclient.ServerHealthStatusUnknown},
		CreatedAt:              time.Now(), UpdatedAt: time.Now(),
	}}
	if in.TimeoutSeconds != nil {
		sv.TimeoutSeconds = *in.TimeoutSeconds
	}
	if in.AuthValue != nil {
		sv.secret = *in.AuthValue
		sv.HasAuth = true
		sv.AuthHeaderName = in.AuthHeaderName
		sv.AuthValueHint = (*in.AuthValue)[max(0, len(*in.AuthValue)-4):]
	}
	f.servers[in.Slug] = sv
	created := ompclient.McpServerCreated{}
	tools, errMsg := f.discover(in.Url)
	if errMsg != "" {
		msg, class := errMsg, ompclient.McpErrorClass("connect")
		created.RefreshError = &ompclient.McpTestResult{Ok: false, Message: &msg, ErrorClass: &class}
	} else {
		sv.refreshed = true
		sv.Counts.Tools = int64(tools)
		created.Refresh = &ompclient.McpRefreshResult{Listed: tools, Added: tools, Capabilities: []ompclient.McpCapability{}}
	}
	created.Server = sv.McpServer
	writeData(w, 201, created)
}

func (f *fakePortal) serveServer(w http.ResponseWriter, r *http.Request, body []byte, sv *fakeServer, rest []string) {
	action := ""
	if len(rest) > 0 {
		action = rest[0]
	}
	switch {
	case action == "" && r.Method == "GET":
		etag(w, sv.Revision)
		writeData(w, 200, sv.McpServer)
	case action == "" && r.Method == "PATCH":
		im := strings.Trim(r.Header.Get("If-Match"), `"`)
		if im == "" {
			writeErr(w, 428, "revision_required", "send If-Match", nil)
			return
		}
		if im != strconv.FormatInt(sv.Revision, 10) {
			writeErr(w, 412, "revision_conflict", "the server changed", nil)
			return
		}
		var in ompclient.McpServerUpdate
		if err := json.Unmarshal(body, &in); err != nil {
			writeErr(w, 400, "invalid_json", err.Error(), nil)
			return
		}
		if in.Url != nil && origin(*in.Url) != origin(sv.Url) && sv.HasAuth && in.AuthValue == nil && (in.AuthMode == nil || *in.AuthMode != ompclient.McpServerAuthModeNone) {
			writeErr(w, 422, "auth_value_required", "a URL on another origin needs a new secret", map[string]any{"field": "authValue"})
			return
		}
		if in.Name != nil {
			sv.Name = *in.Name
		}
		if in.Description != nil {
			sv.Description = *in.Description
		}
		if in.Url != nil {
			sv.Url = *in.Url
		}
		if in.Enabled != nil {
			sv.Enabled = *in.Enabled
		}
		if in.TimeoutSeconds != nil {
			sv.TimeoutSeconds = *in.TimeoutSeconds
		}
		if in.AuthMode != nil {
			m := *in.AuthMode
			sv.AuthMode = &m
			if m == ompclient.McpServerAuthModeNone {
				sv.HasAuth, sv.AuthHeaderName, sv.secret, sv.AuthValueHint = false, nil, "", ""
			}
		}
		if in.AuthHeaderName != nil {
			sv.AuthHeaderName = in.AuthHeaderName
			sv.HasAuth = true
		}
		if in.AuthValue != nil {
			sv.secret = *in.AuthValue
			sv.HasAuth = true
			sv.AuthValueHint = (*in.AuthValue)[max(0, len(*in.AuthValue)-4):]
		}
		if in.Url != nil && sv.PublishState != ompclient.PublishStatePrivate && f.policy == "approval_required" {
			sv.PublishState = ompclient.PublishStatePending
		}
		sv.Revision++
		etag(w, sv.Revision)
		writeData(w, 200, sv.McpServer)
	case action == "test" && r.Method == "POST":
		res := ompclient.McpTestResult{Ok: f.testOK, LatencyMs: 12}
		if f.testOK {
			res.Counts = &ompclient.CapabilityCounts{Tools: 3}
		} else {
			m, c := "connection refused", ompclient.McpErrorClass("connect")
			res.Message, res.ErrorClass = &m, &c
		}
		writeData(w, 200, res)
	case action == "refresh" && r.Method == "POST":
		tools, errMsg := f.discover(sv.Url)
		if errMsg != "" {
			writeErr(w, 502, "discovery_failed", errMsg, map[string]any{"ok": false})
			return
		}
		sv.refreshed = true
		writeData(w, 200, ompclient.McpRefreshResult{Listed: tools, Changed: f.refreshChanged, Capabilities: []ompclient.McpCapability{}})
	case action == "publish" && r.Method == "POST":
		switch {
		case !sv.refreshed:
			writeErr(w, 409, "not_refreshed", "read the server first", nil)
		case sv.PublishState == ompclient.PublishStatePublished || sv.PublishState == ompclient.PublishStatePending:
			writeErr(w, 409, "already_published", "already published", nil)
		default:
			sv.PublishState = ompclient.PublishStatePending
			if f.policy == "self_publish" {
				sv.PublishState = ompclient.PublishStatePublished
			}
			sv.Revision++
			writeData(w, 200, sv.McpServer)
		}
	case action == "unpublish" && r.Method == "POST":
		sv.PublishState = ompclient.PublishStatePrivate
		sv.Revision++
		writeData(w, 200, sv.McpServer)
	default:
		writeErr(w, 404, "not_found", "no such route", nil)
	}
}

// ---- admin routes (platform) -------------------------------------------------

func (f *fakePortal) serveAdmin(w http.ResponseWriter, r *http.Request, body []byte, tok ompclient.AutomationToken) {
	if tok.Kind != ompclient.AutomationTokenKindPlatformAdmin {
		writeErr(w, 403, "token_not_allowed", "a publisher token never reaches admin routes", nil)
		return
	}
	if r.Method != "GET" && !hasTokenScope(tok, "platform:write") {
		denyScope(w, tok, "platform:write")
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/v1/admin/"), "/")
	im := strings.Trim(r.Header.Get("If-Match"), `"`)
	checkRev := func(rev int64) bool {
		if im == "" {
			writeErr(w, 428, "revision_required", "send If-Match", nil)
			return false
		}
		if im != strconv.FormatInt(rev, 10) {
			writeErr(w, 412, "revision_conflict", "changed", nil)
			return false
		}
		return true
	}
	switch {
	case parts[0] == "teams" && len(parts) == 1 && r.Method == "GET":
		status := r.URL.Query().Get("status")
		var names []string
		for slug, t := range f.teams {
			if status == "" || string(t.Status) == status {
				names = append(names, slug)
			}
		}
		sort.Strings(names)
		items := []ompclient.TeamSummary{}
		for _, n := range names {
			items = append(items, ompclient.TeamSummary{Team: f.teams[n].Team})
		}
		writeData(w, 200, ompclient.TeamPage{Items: items})
	case parts[0] == "teams" && len(parts) == 1 && r.Method == "POST":
		var in ompclient.TeamCreate
		_ = json.Unmarshal(body, &in)
		if _, ok := f.teams[in.Slug]; ok {
			writeErr(w, 409, "slug_taken", "taken", nil)
			return
		}
		t := &fakeTeam{Team: ompclient.Team{Id: uuid.New(), Slug: in.Slug, Name: in.Name, Description: deref(in.Description), Status: ompclient.TeamStatusActive, Revision: 1}, limits: map[string]*int64{}}
		f.teams[in.Slug] = t
		writeData(w, 201, ompclient.TeamCreated{Team: ompclient.TeamSummary{Team: t.Team}})
	case parts[0] == "teams" && len(parts) == 2 && r.Method == "PATCH":
		t := f.teams[parts[1]]
		if t == nil {
			writeErr(w, 404, "team_not_found", "no team", nil)
			return
		}
		if !checkRev(t.Revision) {
			return
		}
		var in ompclient.TeamUpdate
		_ = json.Unmarshal(body, &in)
		if in.Name != nil {
			t.Name = *in.Name
		}
		if in.Description != nil {
			t.Description = *in.Description
		}
		if in.Status != nil {
			t.Status = *in.Status
		}
		t.Revision++
		writeData(w, 200, ompclient.TeamSummary{Team: t.Team})
	case parts[0] == "teams" && len(parts) == 3 && parts[2] == "limits":
		t := f.teams[parts[1]]
		if t == nil {
			writeErr(w, 404, "team_not_found", "no team", nil)
			return
		}
		if r.Method == "GET" {
			items := []ompclient.TeamRateLimit{}
			for _, k := range []string{"service_account_per_minute", "gateway_per_minute", "server_per_minute"} {
				items = append(items, ompclient.TeamRateLimit{Key: ompclient.RateLimitKey(k), Override: t.limits[k], TeamOverridable: true})
			}
			writeData(w, 200, ompclient.TeamLimits{Items: items, Revision: t.Revision, TeamSlug: t.Slug})
			return
		}
		if !checkRev(t.Revision) {
			return
		}
		var in ompclient.TeamLimitsUpdate
		_ = json.Unmarshal(body, &in)
		for _, it := range in.Items {
			t.limits[string(it.Key)] = it.Value
		}
		t.Revision++
		writeData(w, 200, ompclient.TeamLimits{Items: []ompclient.TeamRateLimit{}, Revision: t.Revision, TeamSlug: t.Slug})
	case parts[0] == "settings" && len(parts) == 2 && parts[1] == "limits":
		if r.Method == "GET" {
			etag(w, f.limitRev)
			writeData(w, 200, ompclient.LimitSettings{Items: f.limits, Revision: f.limitRev})
			return
		}
		if !checkRev(f.limitRev) {
			return
		}
		var in ompclient.LimitSettingsUpdate
		_ = json.Unmarshal(body, &in)
		for _, it := range in.Items {
			for i := range f.limits {
				if f.limits[i].Key == it.Key {
					f.limits[i].Default, f.limits[i].Ceiling = it.Default, it.Ceiling
				}
			}
		}
		f.limitRev++
		writeData(w, 200, ompclient.LimitSettings{Items: f.limits, Revision: f.limitRev})
	case parts[0] == "gateway-options" && r.Method == "GET":
		items := f.options
		if items == nil {
			items = []ompclient.GatewayOption{}
		}
		writeData(w, 200, ompclient.GatewayOptionPage{Items: items})
	case parts[0] == "gateways":
		f.serveGateways(w, r, body, parts, checkRev)
	default:
		writeErr(w, 404, "not_found", "no such route", nil)
	}
}

func (f *fakePortal) serveGateways(w http.ResponseWriter, r *http.Request, body []byte, parts []string, checkRev func(int64) bool) {
	if len(parts) == 1 {
		if r.Method == "GET" {
			var names []string
			for s := range f.gateways {
				names = append(names, s)
			}
			sort.Strings(names)
			items := []ompclient.Gateway{}
			for _, n := range names {
				g := f.gateways[n]
				g.CapabilityCount = int64(len(g.caps))
				items = append(items, g.Gateway)
			}
			writeData(w, 200, ompclient.GatewayPage{Items: items})
			return
		}
		var in ompclient.GatewayCreate
		_ = json.Unmarshal(body, &in)
		if _, ok := f.gateways[in.Slug]; ok {
			writeErr(w, 409, "slug_taken", "taken", nil)
			return
		}
		g := &fakeGateway{Gateway: ompclient.Gateway{Id: uuid.New(), Slug: in.Slug, Name: in.Name, Description: deref(in.Description), Enabled: in.Enabled == nil || *in.Enabled, OwnerKind: ompclient.GatewayOwnerKindPlatform, Revision: 1}}
		f.gateways[in.Slug] = g
		writeData(w, 201, g.Gateway)
		return
	}
	id, _ := uuid.Parse(parts[1])
	var g *fakeGateway
	for _, x := range f.gateways {
		if x.Id == id {
			g = x
		}
	}
	if g == nil {
		writeErr(w, 404, "gateway_not_found", "no gateway", nil)
		return
	}
	sub := ""
	if len(parts) > 2 {
		sub = parts[2]
	}
	switch {
	case sub == "" && r.Method == "PATCH":
		if !checkRev(g.Revision) {
			return
		}
		var in ompclient.GatewayUpdate
		_ = json.Unmarshal(body, &in)
		if in.Name != nil {
			g.Name = *in.Name
		}
		if in.Description != nil {
			g.Description = *in.Description
		}
		if in.Enabled != nil {
			g.Enabled = *in.Enabled
		}
		g.Revision++
		writeData(w, 200, g.Gateway)
	case sub == "capabilities" && r.Method == "GET":
		etag(w, g.Revision)
		items := g.caps
		if items == nil {
			items = []ompclient.GatewayCapability{}
		}
		writeData(w, 200, ompclient.GatewayCapabilities{Items: items, Revision: g.Revision})
	case sub == "capabilities" && r.Method == "PUT":
		if !checkRev(g.Revision) {
			return
		}
		var in ompclient.GatewayCapabilitiesUpdate
		_ = json.Unmarshal(body, &in)
		var caps []ompclient.GatewayCapability
		for _, it := range in.Items {
			found := false
			for _, o := range f.options {
				if o.CapabilityId == it.CapabilityId {
					caps = append(caps, ompclient.GatewayCapability{CapabilityId: o.CapabilityId, Kind: o.Kind, Name: o.Name, ServerSlug: o.ServerSlug, ExposedName: o.ExposedName})
					found = true
				}
			}
			for _, c := range g.caps {
				if c.CapabilityId == it.CapabilityId {
					caps = append(caps, c)
					found = true
				}
			}
			if !found {
				writeErr(w, 422, "capability_not_selectable", "not selectable", nil)
				return
			}
		}
		g.caps = caps
		g.Revision++
		writeData(w, 200, ompclient.GatewayCapabilities{Items: caps, Revision: g.Revision})
	case sub == "grants" && r.Method == "GET":
		items := g.grants
		if items == nil {
			items = []ompclient.GatewayGrant{}
		}
		writeData(w, 200, items)
	case sub == "grants" && r.Method == "POST":
		var in ompclient.GatewayGrantCreate
		_ = json.Unmarshal(body, &in)
		gr := ompclient.GatewayGrant{Id: uuid.New(), SubjectKind: in.SubjectKind, Group: in.Group, ToolScope: in.ToolScope}
		if in.Team != nil {
			gr.Team = &ompclient.GrantTeam{Id: uuid.New(), Slug: *in.Team, Name: *in.Team}
		}
		if in.UserEmail != nil {
			gr.User = &ompclient.MemberUser{Email: *in.UserEmail}
		}
		g.grants = append(g.grants, gr)
		writeData(w, 201, gr)
	case sub == "grants" && r.Method == "DELETE":
		gid, _ := uuid.Parse(parts[3])
		kept := g.grants[:0:0]
		for _, gr := range g.grants {
			if gr.Id != gid {
				kept = append(kept, gr)
			}
		}
		g.grants = kept
		writeJSON(w, 200, map[string]any{"ok": true})
	default:
		writeErr(w, 404, "not_found", "no such route", nil)
	}
}

// ---- the CLI under test ------------------------------------------------------

// harness runs the CLI against a portal with a private environment, home and
// config file (never the real ones).
type harness struct {
	t      *testing.T
	env    map[string]string
	home   string
	stdin  string
	stdout bytes.Buffer
	stderr bytes.Buffer
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	home := t.TempDir()
	return &harness{t: t, home: home, env: map[string]string{}}
}

// run executes the command line and returns the exit code and the output.
func (h *harness) run(args ...string) (code int, stdout, stderr string) {
	h.t.Helper()
	h.stdout.Reset()
	h.stderr.Reset()
	app := &App{
		Stdin: strings.NewReader(h.stdin), Stdout: &h.stdout, Stderr: &h.stderr,
		Getenv:  func(k string) string { return h.env[k] },
		HomeDir: func() (string, error) { return h.home, nil },
		Version: "test", Commit: "abc123",
	}
	code = app.Run(context.Background(), args)
	return code, h.stdout.String(), h.stderr.String()
}

// connect points the harness at a portal with a token.
func (h *harness) connect(f *fakePortal, token string) {
	h.env["OMP_URL"] = f.URL()
	h.env["OMP_TOKEN"] = token
}

func writeTempFile(t *testing.T, name, content string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	return p
}

// nilBodyHandler answers every request with a bare status and no JSON.
func nilBodyHandler(status int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status) })
}

// tagNames lists the json field names of a struct.
func tagNames(v any) []string {
	t := reflect.TypeOf(v)
	var out []string
	for i := 0; i < t.NumField(); i++ {
		name := strings.Split(t.Field(i).Tag.Get("json"), ",")[0]
		if name != "" && name != "-" {
			out = append(out, name)
		}
	}
	return out
}

// bumpOnGet makes another writer change the server between the CLI's read and
// its PATCH: the first PATCH sees a newer revision than the GET returned.
func bumpOnGet(f *fakePortal, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
		if r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/v1/teams/bravo/mcp-servers") && r.URL.Query().Get("limit") != "" {
			f.mu.Lock()
			for _, s := range f.servers {
				s.Revision++
			}
			f.mu.Unlock()
		}
	})
}
