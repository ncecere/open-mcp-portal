package ompcli

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/google/uuid"

	"github.com/ncecere/open-mcp-portal/pkg/ompclient"
)

// FieldChange is one field of a change. Secrets never appear in From, To or
// Note: a secret's change says only which environment variable supplies it.
type FieldChange struct {
	Field string `json:"field"`
	From  any    `json:"from"`
	To    any    `json:"to"`
	Note  string `json:"note,omitempty"`
}

// Change is one object a plan would create or update.
type Change struct {
	Kind   string        `json:"kind"` // server, team, gateway, limits
	Key    string        `json:"key"`  // team/slug, slug
	Action string        `json:"action"`
	Fields []FieldChange `json:"fields,omitempty"`
}

// Plan is the difference between a file and the portal.
type Plan struct {
	Changes  []Change `json:"changes"`
	Warnings []string `json:"warnings,omitempty"`
}

// Drift is whether applying the file would change anything.
func (p *Plan) Drift() bool { return len(p.Changes) > 0 }

// step is a change with the code that applies it.
type step struct {
	Change
	needsEnv []string // environment variables that must be set to apply it
	run      func(ctx context.Context, r *runResult) error
}

// runResult collects what an apply learned beyond success or failure.
type runResult struct {
	failures []*Error // problems that do not stop the run but make it fail
	changed  int      // capabilities that changed on refresh
	notes    []string
}

type importOpts struct {
	apply          bool // false: plan only (no refresh steps)
	replaceSecrets bool
	refresh        bool
	only           string // "", servers or platform
}

// planner builds the steps for a file against the portal.
type planner struct {
	a        *App
	c        *api
	opts     importOpts
	token    ompclient.AutomationToken
	steps    []*step
	warnings []string
}

func jsonVal(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func (p *planner) warn(format string, args ...any) {
	p.warnings = append(p.warnings, fmt.Sprintf(format, args...))
}

// ---- sections ----------------------------------------------------------------

// canManageServers and canManagePlatform say what the token's kind reaches
// (docs/automation-tokens.md): a team publisher token reaches its team's
// servers; a platform token reaches platform objects, and never team routes.
func (p *planner) canManageServers() bool {
	return p.token.Kind == ompclient.AutomationTokenKindTeamPublisher
}

func (p *planner) canManagePlatform() bool {
	return p.token.Kind == ompclient.AutomationTokenKindPlatformAdmin
}

func hasScope(t ompclient.AutomationToken, want ompclient.AutomationTokenScope) bool {
	for _, s := range t.Scopes {
		if s == want {
			return true
		}
	}
	return false
}

// build checks the file's sections against the token and builds the steps.
func (p *planner) build(ctx context.Context, f *File) error {
	wantServers := len(f.Servers) > 0 && p.opts.only != "platform"
	wantPlatform := (len(f.Teams) > 0 || len(f.Gateways) > 0 || len(f.Limits) > 0) && p.opts.only != "servers"
	if wantServers && !p.canManageServers() {
		return usageErr("the file has servers, which need a team publisher token (omppub_); this token is %s. Use --only platform to apply only the platform objects, or another token", p.token.Kind)
	}
	if wantPlatform && !p.canManagePlatform() {
		return usageErr("the file has teams, gateways or limits, which need a platform-admin token (ompadm_); this token is %s. Use --only servers to apply only the servers, or another token", p.token.Kind)
	}
	if wantServers {
		if err := p.planServers(ctx, f.Servers); err != nil {
			return err
		}
	}
	if wantPlatform {
		if p.opts.apply && !hasScope(p.token, "platform:write") {
			return &Error{Exit: ExitForbidden, Code: "token_not_allowed", Message: "applying platform objects needs the platform:write scope; this token has " + scopesText(p.token), Details: map[string]any{"requiredScopes": []any{"platform:write"}}}
		}
		if err := p.planTeams(ctx, f.Teams); err != nil {
			return err
		}
		if err := p.planGateways(ctx, f.Gateways); err != nil {
			return err
		}
		if err := p.planPlatformLimits(ctx, f.Limits); err != nil {
			return err
		}
	}
	return nil
}

func scopesText(t ompclient.AutomationToken) string {
	s := make([]string, len(t.Scopes))
	for i, v := range t.Scopes {
		s[i] = string(v)
	}
	return strings.Join(s, ", ")
}

func (p *planner) plan() *Plan {
	pl := &Plan{Changes: []Change{}, Warnings: p.warnings}
	for _, s := range p.steps {
		if s.Action != "refresh" {
			pl.Changes = append(pl.Changes, s.Change)
		}
	}
	return pl
}

// ---- servers -----------------------------------------------------------------

func serverMode(s *ompclient.McpServer) string {
	if s.AuthMode == nil {
		return "none"
	}
	return string(*s.AuthMode)
}

// manageable reports why omp cannot manage a server, or "".
func manageable(s *ompclient.McpServer) string {
	switch m := serverMode(s); m {
	case "none", "static_header":
	default:
		return "uses authMode " + m + ", which needs a browser session"
	}
	if s.Credentials != nil && len(*s.Credentials) > 0 && s.AuthHeaderName == nil && s.HasAuth {
		return "uses a list of credential parts, which omp v1 does not manage"
	}
	return ""
}

func (p *planner) planServers(ctx context.Context, desired []Server) error {
	team := p.token.Team.Slug
	for _, d := range desired {
		if d.Team != team {
			return usageErr("server %s is in team %q but this token belongs to team %q", d.Slug, d.Team, team)
		}
	}
	current, err := listServers(ctx, p.c, team, "")
	if err != nil {
		return err
	}
	bySlug := map[string]*ompclient.McpServer{}
	for i := range current {
		bySlug[current[i].Slug] = &current[i]
	}
	sorted := append([]Server(nil), desired...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Slug < sorted[j].Slug })
	for _, d := range sorted {
		d := d
		cur := bySlug[d.Slug]
		if err := checkGovernanceDeclaration(d, cur); err != nil {
			return err
		}
		// An absent env name is permitted when preserving an existing static
		// credential, not when creating one. Validate the entire plan before
		// any step is applied so a later bad declaration cannot partially apply.
		if p.opts.apply && d.AuthMode == "static_header" && d.AuthValueEnv == "" && (cur == nil || serverMode(cur) != "static_header") {
			return usageErr("server %s: creating or switching to static_header needs authValueEnv", d.Slug)
		}
		if cur == nil {
			p.planServerCreate(d)
			continue
		}
		if why := manageable(cur); why != "" {
			return usageErr("server %s %s; remove it from the file (omp export skips such servers)", d.Slug, why)
		}
		p.planServerUpdate(d, cur)
	}
	return nil
}

func (p *planner) planServerCreate(d Server) {
	ch := Change{Kind: "server", Key: d.Team + "/" + d.Slug, Action: "create"}
	add := func(field string, to any) { ch.Fields = append(ch.Fields, FieldChange{Field: field, To: to}) }
	add("name", d.Name)
	if d.Description != nil {
		add("description", *d.Description)
	}
	add("url", d.URL)
	if d.Enabled != nil {
		add("enabled", *d.Enabled)
	}
	if d.TimeoutSeconds != nil {
		add("timeoutSeconds", *d.TimeoutSeconds)
	}
	var needsEnv []string
	if d.AuthMode == "static_header" {
		add("authMode", "static_header")
		add("authHeaderName", d.AuthHeaderName)
		ch.Fields = append(ch.Fields, FieldChange{Field: "authValue", To: "(secret)", Note: "read from $" + d.AuthValueEnv})
		if d.AuthValueEnv == "" {
			p.warn("server %s: static_header needs authValueEnv to be created", d.Slug)
		} else {
			needsEnv = []string{d.AuthValueEnv}
			if p.a.Getenv(d.AuthValueEnv) == "" {
				p.warn("server %s: $%s is not set; apply would fail", d.Slug, d.AuthValueEnv)
			}
		}
	}
	if d.Publish == "request" {
		add("publish", "request")
	}
	p.steps = append(p.steps, &step{
		Change:   ch,
		needsEnv: needsEnv,
		run:      func(ctx context.Context, r *runResult) error { return p.createServer(ctx, d, r) },
	})
	p.addRefresh(d)
}

// serverUpdate is one existing server compared with the file: the step the
// plan shows and the patch it sends.
type serverUpdate struct {
	p     *planner
	d     Server
	cur   *ompclient.McpServer
	st    *step
	patch ompclient.McpServerUpdate
}

func (u *serverUpdate) diff(field string, from, to any) {
	u.st.Fields = append(u.st.Fields, FieldChange{Field: field, From: from, To: to})
}

func (p *planner) planServerUpdate(d Server, cur *ompclient.McpServer) {
	u := &serverUpdate{p: p, d: d, cur: cur}
	u.st = &step{Change: Change{Kind: "server", Key: d.Team + "/" + d.Slug, Action: "update"}}
	u.diffSettings()
	u.diffAuth()
	u.diffPublish()
	if len(u.st.Fields) > 0 {
		revision, id := cur.Revision, cur.Id
		u.st.run = func(ctx context.Context, r *runResult) error { return u.apply(ctx, id, revision, r) }
		p.steps = append(p.steps, u.st)
	}
	p.addRefresh(d)
}

func (u *serverUpdate) diffSettings() {
	d, cur := &u.d, u.cur
	if d.Name != cur.Name {
		u.diff("name", cur.Name, d.Name)
		u.patch.Name = &d.Name
	}
	if d.Description != nil && *d.Description != cur.Description {
		u.diff("description", cur.Description, *d.Description)
		u.patch.Description = d.Description
	}
	if d.URL != cur.Url {
		u.diff("url", cur.Url, d.URL)
		u.patch.Url = &d.URL
	}
	if d.Enabled != nil && *d.Enabled != cur.Enabled {
		u.diff("enabled", cur.Enabled, *d.Enabled)
		u.patch.Enabled = d.Enabled
	}
	if d.TimeoutSeconds != nil && *d.TimeoutSeconds != cur.TimeoutSeconds {
		u.diff("timeoutSeconds", cur.TimeoutSeconds, *d.TimeoutSeconds)
		u.patch.TimeoutSeconds = d.TimeoutSeconds
	}
}

// diffAuth compares the declared authMode; an absent one leaves the mode alone.
func (u *serverUpdate) diffAuth() {
	curMode := serverMode(u.cur)
	switch u.d.AuthMode {
	case "none":
		if curMode != "none" {
			u.diff("authMode", curMode, "none")
			m := ompclient.McpServerAuthModeNone
			u.patch.AuthMode = &m
		}
	case "static_header":
		u.diffStaticHeader(curMode)
	}
}

// diffStaticHeader compares a declared static_header: the mode, the header's
// name, and whether the header's value has to be sent (never compared).
func (u *serverUpdate) diffStaticHeader(curMode string) {
	d := &u.d
	sendValue := false
	if curMode != "static_header" {
		u.diff("authMode", curMode, "static_header")
		m := ompclient.McpServerAuthModeStaticHeader
		u.patch.AuthMode = &m
		sendValue = true
	}
	if curHeader := deref(u.cur.AuthHeaderName); curMode != "static_header" || curHeader != d.AuthHeaderName {
		if curMode == "static_header" {
			u.diff("authHeaderName", curHeader, d.AuthHeaderName)
			sendValue = sendValue || d.AuthValueEnv != ""
		} else {
			u.diff("authHeaderName", nil, d.AuthHeaderName)
		}
		u.patch.AuthHeaderName = &d.AuthHeaderName
	}
	if u.p.opts.replaceSecrets && d.AuthValueEnv != "" {
		sendValue = true
	}
	if !sendValue {
		return
	}
	u.st.Fields = append(u.st.Fields, FieldChange{Field: "authValue", From: "(not shown)", To: "(secret)", Note: "read from $" + d.AuthValueEnv})
	if d.AuthValueEnv == "" {
		u.p.warn("server %s: switching to static_header needs authValueEnv", d.Slug)
		return
	}
	u.st.needsEnv = []string{d.AuthValueEnv}
	if u.p.a.Getenv(d.AuthValueEnv) == "" {
		u.p.warn("server %s: $%s is not set; apply would fail", d.Slug, d.AuthValueEnv)
	}
}

func (u *serverUpdate) diffPublish() {
	d, cur := u.d, u.cur
	wantPublish := ""
	switch {
	case d.Publish == "request" && (cur.PublishState == ompclient.PublishStatePrivate || cur.PublishState == ompclient.PublishStateRejected):
		wantPublish = "request"
	case d.Publish == "none" && (cur.PublishState == ompclient.PublishStatePending || cur.PublishState == ompclient.PublishStatePublished):
		wantPublish = "none"
	}
	if wantPublish != "" {
		u.diff("publish", string(cur.PublishState), map[string]string{"request": "request", "none": "private"}[wantPublish])
	}
}

// apply is the server's step: the patch when anything but the publication
// changed, then the publication from the state the patch returned.
func (u *serverUpdate) apply(ctx context.Context, id uuid.UUID, revision int64, r *runResult) error {
	p, d := u.p, u.d
	state := u.cur.PublishState
	if hasPatch(u.st) {
		if u.st.needsEnv != nil {
			v, err := p.a.secretFromEnv(u.st.needsEnv[0])
			if err != nil {
				return err
			}
			u.patch.AuthValue = &v
		}
		res, err := check(p.c.UpdateTeamMcpServerWithResponse(ctx, d.Team, id,
			&ompclient.UpdateTeamMcpServerParams{IfMatch: fmt.Sprintf(`"%d"`, revision)}, u.patch))
		if err != nil {
			return withHint(err, "the server changed since the plan was read; run the command again")
		}
		sv, err := dataOf(res.JSON200)
		if err != nil {
			return err
		}
		state = sv.PublishState
	}
	return p.reconcilePublish(ctx, d, id, state, r)
}

// hasPatch is whether the step changes more than the publication.
func hasPatch(st *step) bool {
	for _, f := range st.Fields {
		if f.Field != "publish" {
			return true
		}
	}
	return false
}

func withHint(err error, hint string) error {
	if err == nil {
		return nil
	}
	e := asError(err)
	if e.Exit == ExitConflict && e.Status == 412 {
		c := *e
		c.Message += " (" + hint + ")"
		return &c
	}
	return err
}

// addRefresh adds a refresh step for --refresh (apply only; a refresh is not drift).
func (p *planner) addRefresh(d Server) {
	if !p.opts.apply || !p.opts.refresh {
		return
	}
	p.steps = append(p.steps, &step{
		Change: Change{Kind: "server", Key: d.Team + "/" + d.Slug, Action: "refresh"},
		run: func(ctx context.Context, r *runResult) error {
			sv, err := findServer(ctx, p.c, d.Team, d.Slug)
			if err != nil {
				return err
			}
			res, err := check(p.c.RefreshTeamMcpServerWithResponse(ctx, d.Team, sv.Id))
			if err != nil {
				return err
			}
			rr, err := dataOf(res.JSON200)
			if err != nil {
				return err
			}
			r.changed += rr.Changed
			r.notes = append(r.notes, fmt.Sprintf("refreshed %s: %d listed, %d added, %d changed, %d gone", d.Slug, rr.Listed, rr.Added, rr.Changed, rr.Gone))
			return nil
		},
	})
}

func (p *planner) createServer(ctx context.Context, d Server, r *runResult) error {
	body := ompclient.McpServerCreate{Slug: d.Slug, Name: d.Name, Url: d.URL, Description: d.Description, Enabled: d.Enabled, TimeoutSeconds: d.TimeoutSeconds}
	if d.AuthMode == "static_header" {
		v, err := p.a.secretFromEnv(d.AuthValueEnv)
		if err != nil {
			return err
		}
		m := ompclient.McpServerAuthModeStaticHeader
		body.AuthMode, body.AuthHeaderName, body.AuthValue = &m, &d.AuthHeaderName, &v
	}
	res, err := check(p.c.CreateTeamMcpServerWithResponse(ctx, d.Team, body))
	if err != nil {
		return err
	}
	created, err := dataOf(res.JSON201)
	if err != nil {
		return err
	}
	if created.RefreshError != nil {
		r.failures = append(r.failures, &Error{Exit: ExitCheckFailed, Code: "discovery_failed", Message: fmt.Sprintf("server %s was created but its capabilities could not be read: %s", d.Slug, deref(created.RefreshError.Message))})
	}
	return p.reconcilePublish(ctx, d, created.Server.Id, created.Server.PublishState, r)
}

// reconcilePublish publishes or withdraws a server to match the file, from the
// state the last call returned.
func (p *planner) reconcilePublish(ctx context.Context, d Server, id uuid.UUID, state ompclient.PublishState, r *runResult) error {
	switch {
	case d.Publish == "request" && (state == ompclient.PublishStatePrivate || state == ompclient.PublishStateRejected):
		_, err := check(p.c.PublishTeamMcpServerWithResponse(ctx, d.Team, id, ompclient.McpPublishRequest{}))
		return err
	case d.Publish == "none" && (state == ompclient.PublishStatePending || state == ompclient.PublishStatePublished):
		_, err := check(p.c.UnpublishTeamMcpServerWithResponse(ctx, d.Team, id))
		return err
	}
	return nil
}
