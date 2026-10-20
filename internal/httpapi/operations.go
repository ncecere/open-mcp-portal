package httpapi

import (
	"net/http"
	"slices"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/ncecere/open-mcp-portal/internal/capture"
	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/httpx"
	"github.com/ncecere/open-mcp-portal/internal/limits"
	"github.com/ncecere/open-mcp-portal/internal/retention"
	"github.com/ncecere/open-mcp-portal/internal/usage"
)

// Phase 6 operations (docs/phase6-operations.md): rate limits, payload
// capture, retention, call details and payloads, usage.

// operationsRoutes: a team's limits, retention, call detail, payloads and
// usage.
func (a *api) operationsRoutes() []route {
	return []route{
		{"GET", "/v1/teams/{team}/limits", a.session(a.getTeamLimits)},
		{"GET", "/v1/teams/{team}/retention", a.session(a.getTeamRetention)},
		{"GET", "/v1/teams/{team}/calls/{callId}", a.session(a.getTeamCall)},
		{"GET", "/v1/teams/{team}/calls/{callId}/payload", a.session(a.getTeamCallPayload)},
		{"GET", "/v1/teams/{team}/usage", a.session(a.getTeamUsage)},
	}
}

// operationsAdminRoutes: platform settings, team overrides, any call and
// payload, and usage across the platform.
func (a *api) operationsAdminRoutes() []route {
	return []route{
		{"GET", "/v1/admin/settings/limits", a.admin(a.adminGetLimitSettings)},
		{"PUT", "/v1/admin/settings/limits", a.admin(a.adminUpdateLimitSettings)},
		{"GET", "/v1/admin/teams/{team}/limits", a.admin(a.adminGetTeamLimits)},
		{"PUT", "/v1/admin/teams/{team}/limits", a.admin(a.adminUpdateTeamLimits)},
		{"GET", "/v1/admin/settings/capture", a.admin(a.adminGetCaptureSettings)},
		{"PUT", "/v1/admin/settings/capture", a.admin(a.adminUpdateCaptureSettings)},
		{"POST", "/v1/admin/settings/capture/test", a.admin(a.adminTestRedaction)},
		{"GET", "/v1/admin/settings/retention", a.admin(a.adminGetRetentionSettings)},
		{"PUT", "/v1/admin/settings/retention", a.admin(a.adminUpdateRetentionSettings)},
		{"GET", "/v1/admin/teams/{team}/retention", a.admin(a.adminGetTeamRetention)},
		{"PUT", "/v1/admin/teams/{team}/retention", a.admin(a.adminUpdateTeamRetention)},
		{"GET", "/v1/admin/calls/{callId}", a.admin(a.adminGetCall)},
		{"GET", "/v1/admin/calls/{callId}/payload", a.admin(a.adminGetCallPayload)},
		{"GET", "/v1/admin/usage", a.admin(a.adminGetUsage)},
	}
}

// Rate limits.

func toAPIPlatformLimits(v limits.PlatformView) apitypes.LimitSettings {
	out := apitypes.LimitSettings{Revision: v.Revision, UpdatedAt: v.UpdatedAt, Items: make([]apitypes.PlatformRateLimit, len(v.Items))}
	for i, it := range v.Items {
		out.Items[i] = apitypes.PlatformRateLimit{
			Key: apitypes.RateLimitKey(it.Key), Label: it.Label, Description: it.Description, TeamOverridable: it.Overridable,
			Default: it.Default, Ceiling: it.Ceiling, BuiltInDefault: it.BuiltIn, Max: limits.Max,
			CappedTeams: it.CappedTeams, CappedGateways: it.CappedGateways,
		}
	}
	return out
}

func toAPITeamLimits(v limits.TeamView) apitypes.TeamLimits {
	out := apitypes.TeamLimits{TeamId: v.TeamID, TeamSlug: v.TeamSlug, Revision: v.Revision, Items: make([]apitypes.TeamRateLimit, len(v.Items))}
	for i, it := range v.Items {
		out.Items[i] = apitypes.TeamRateLimit{
			Key: apitypes.RateLimitKey(it.Key), Label: it.Label, Description: it.Description, TeamOverridable: it.Overridable,
			Override: it.Override, Default: it.Default, Ceiling: it.Ceiling, Effective: it.Effective,
		}
	}
	return out
}

func (a *api) adminGetLimitSettings(w http.ResponseWriter, r *http.Request) {
	v, err := a.Limits.Get(r.Context(), a.actor(r))
	if failed(w, r, err) {
		return
	}
	writeRevised(w, http.StatusOK, v.Revision, toAPIPlatformLimits(v))
}

func (a *api) adminUpdateLimitSettings(w http.ResponseWriter, r *http.Request) {
	in, rev, ok := decodeRevised[apitypes.LimitSettingsUpdate](w, r)
	if !ok {
		return
	}
	changes := make([]limits.Change, len(in.Items))
	for i, it := range in.Items {
		changes[i] = limits.Change{Key: string(it.Key), Default: it.Default, Ceiling: it.Ceiling}
	}
	v, err := a.Limits.Update(r.Context(), a.actor(r), changes, rev)
	if failed(w, r, err) {
		return
	}
	writeRevised(w, http.StatusOK, v.Revision, toAPIPlatformLimits(v))
}

func (a *api) getTeamLimits(w http.ResponseWriter, r *http.Request) {
	v, err := a.Limits.GetTeam(r.Context(), a.actor(r), r.PathValue("team"))
	if failed(w, r, err) {
		return
	}
	writeRevised(w, http.StatusOK, v.Revision, toAPITeamLimits(v))
}

func (a *api) adminGetTeamLimits(w http.ResponseWriter, r *http.Request) {
	v, err := a.Limits.AdminGetTeam(r.Context(), a.actor(r), r.PathValue("team"))
	if failed(w, r, err) {
		return
	}
	writeRevised(w, http.StatusOK, v.Revision, toAPITeamLimits(v))
}

func (a *api) adminUpdateTeamLimits(w http.ResponseWriter, r *http.Request) {
	in, rev, ok := decodeRevised[apitypes.TeamLimitsUpdate](w, r)
	if !ok {
		return
	}
	changes := make([]limits.TeamChange, len(in.Items))
	for i, it := range in.Items {
		changes[i] = limits.TeamChange{Key: string(it.Key), Value: it.Value}
	}
	v, err := a.Limits.UpdateTeam(r.Context(), a.actor(r), r.PathValue("team"), changes, rev)
	if failed(w, r, err) {
		return
	}
	writeRevised(w, http.StatusOK, v.Revision, toAPITeamLimits(v))
}

// Payload capture.

func toAPICaptureSettings(s capture.Settings) apitypes.CaptureSettings {
	out := apitypes.CaptureSettings{
		BuiltInRules: make([]apitypes.CaptureRule, len(capture.BuiltInRules)), SensitiveKeys: append([]string{}, capture.SensitiveKeys...),
		Patterns: make([]apitypes.RedactionPattern, len(s.Patterns)), MaxPartBytes: capture.MaxPartBytes,
		Revision: s.Revision, UpdatedAt: s.UpdatedAt,
	}
	for i, rule := range capture.BuiltInRules {
		out.BuiltInRules[i] = apitypes.CaptureRule{Name: rule.Name, Description: rule.Description}
	}
	for i, p := range s.Patterns {
		out.Patterns[i] = apitypes.RedactionPattern{Pattern: p.Pattern, Note: nonEmpty(p.Note)}
	}
	return out
}

func fromAPIPatterns(in []apitypes.RedactionPattern) []capture.Pattern {
	out := make([]capture.Pattern, len(in))
	for i, p := range in {
		out[i] = capture.Pattern{Pattern: p.Pattern}
		if p.Note != nil {
			out[i].Note = *p.Note
		}
	}
	return out
}

func (a *api) adminGetCaptureSettings(w http.ResponseWriter, r *http.Request) {
	s, err := a.Capture.Get(r.Context(), a.actor(r))
	if failed(w, r, err) {
		return
	}
	writeRevised(w, http.StatusOK, s.Revision, toAPICaptureSettings(s))
}

func (a *api) adminUpdateCaptureSettings(w http.ResponseWriter, r *http.Request) {
	in, rev, ok := decodeRevised[apitypes.CaptureSettingsUpdate](w, r)
	if !ok {
		return
	}
	s, err := a.Capture.Update(r.Context(), a.actor(r), fromAPIPatterns(in.Patterns), rev)
	if failed(w, r, err) {
		return
	}
	writeRevised(w, http.StatusOK, s.Revision, toAPICaptureSettings(s))
}

// adminTestRedaction never stores, logs or audits the sample.
func (a *api) adminTestRedaction(w http.ResponseWriter, r *http.Request) {
	var in apitypes.RedactionTestRequest
	if !httpx.Decode(w, r, &in) {
		return
	}
	if len(in.Sample) > 65536 {
		httpx.Error(w, http.StatusBadRequest, "invalid_sample", "The sample can be at most 64 KiB")
		return
	}
	var patterns []capture.Pattern
	if in.Patterns != nil {
		patterns = fromAPIPatterns(*in.Patterns)
	}
	res, err := a.Capture.Test(r.Context(), a.actor(r), in.Sample, patterns)
	if failed(w, r, err) {
		return
	}
	out := apitypes.RedactionTestResult{Redacted: res.Redacted, Redactions: int32(res.Redactions), Truncated: res.Truncated,
		Rules: []apitypes.RedactionRuleCount{}}
	for rule, n := range res.Rules {
		out.Rules = append(out.Rules, apitypes.RedactionRuleCount{Rule: rule, Count: int32(n)})
	}
	slices.SortFunc(out.Rules, func(x, y apitypes.RedactionRuleCount) int {
		if x.Rule < y.Rule {
			return -1
		}
		return 1
	})
	w.Header().Set("Cache-Control", "no-store")
	httpx.JSON(w, http.StatusOK, out)
}

// Retention.

func toAPIRetentionSettings(s retention.Settings) apitypes.RetentionSettings {
	out := apitypes.RetentionSettings{Revision: s.Revision, UpdatedAt: s.UpdatedAt, Periods: make([]apitypes.RetentionPeriod, len(retention.Kinds))}
	for i, k := range retention.Kinds {
		out.Periods[i] = apitypes.RetentionPeriod{Kind: apitypes.RetentionKind(k.Kind), Days: s.Periods[k.Kind], BuiltInDays: k.BuiltIn,
			MinDays: k.MinDays, MaxDays: k.MaxDays, TeamOverridable: k.Overridable}
	}
	if run := s.LastRun; run != nil {
		out.LastRun = &apitypes.RetentionRun{StartedAt: run.StartedAt, FinishedAt: run.FinishedAt, Deleted: run.Deleted, Errors: run.Errors}
		if out.LastRun.Deleted == nil {
			out.LastRun.Deleted = map[string]int64{}
		}
		if out.LastRun.Errors == nil {
			out.LastRun.Errors = map[string]string{}
		}
	}
	return out
}

func toAPITeamRetention(v retention.TeamView) apitypes.TeamRetention {
	out := apitypes.TeamRetention{TeamId: v.TeamID, TeamSlug: v.TeamSlug, Revision: v.Revision, Periods: make([]apitypes.TeamRetentionPeriod, len(v.Periods))}
	for i, p := range v.Periods {
		out.Periods[i] = apitypes.TeamRetentionPeriod{Kind: apitypes.RetentionKind(p.Kind.Kind), Override: p.Override, Default: p.Default,
			Effective: p.Effective, MinDays: p.MinDays, MaxDays: p.MaxDays}
	}
	return out
}

func (a *api) adminGetRetentionSettings(w http.ResponseWriter, r *http.Request) {
	s, err := a.Retention.Get(r.Context(), a.actor(r))
	if failed(w, r, err) {
		return
	}
	writeRevised(w, http.StatusOK, s.Revision, toAPIRetentionSettings(s))
}

func (a *api) adminUpdateRetentionSettings(w http.ResponseWriter, r *http.Request) {
	in, rev, ok := decodeRevised[apitypes.RetentionSettingsUpdate](w, r)
	if !ok {
		return
	}
	changes := make([]retention.Change, len(in.Periods))
	for i, p := range in.Periods {
		changes[i] = retention.Change{Kind: string(p.Kind), Days: p.Days}
	}
	s, err := a.Retention.Update(r.Context(), a.actor(r), changes, rev)
	if failed(w, r, err) {
		return
	}
	writeRevised(w, http.StatusOK, s.Revision, toAPIRetentionSettings(s))
}

func (a *api) getTeamRetention(w http.ResponseWriter, r *http.Request) {
	v, err := a.Retention.GetTeam(r.Context(), a.actor(r), r.PathValue("team"))
	if failed(w, r, err) {
		return
	}
	writeRevised(w, http.StatusOK, v.Revision, toAPITeamRetention(v))
}

func (a *api) adminGetTeamRetention(w http.ResponseWriter, r *http.Request) {
	v, err := a.Retention.AdminGetTeam(r.Context(), a.actor(r), r.PathValue("team"))
	if failed(w, r, err) {
		return
	}
	writeRevised(w, http.StatusOK, v.Revision, toAPITeamRetention(v))
}

func (a *api) adminUpdateTeamRetention(w http.ResponseWriter, r *http.Request) {
	in, rev, ok := decodeRevised[apitypes.TeamRetentionUpdate](w, r)
	if !ok {
		return
	}
	changes := make([]retention.TeamChange, len(in.Periods))
	for i, p := range in.Periods {
		changes[i] = retention.TeamChange{Kind: string(p.Kind), Days: p.Days}
	}
	v, err := a.Retention.UpdateTeam(r.Context(), a.actor(r), r.PathValue("team"), changes, rev)
	if failed(w, r, err) {
		return
	}
	writeRevised(w, http.StatusOK, v.Revision, toAPITeamRetention(v))
}

// Calls and payloads.

func pathCallID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("callId"), 10, 64)
	if err != nil || id < 1 {
		httpx.Error(w, http.StatusBadRequest, "invalid_id", "Invalid callId")
		return 0, false
	}
	return id, true
}

func (a *api) getTeamCall(w http.ResponseWriter, r *http.Request) {
	id, ok := pathCallID(w, r)
	if !ok {
		return
	}
	row, _, err := a.Calls.TeamCall(r.Context(), a.actor(r), r.PathValue("team"), id)
	if failed(w, r, err) {
		return
	}
	httpx.JSON(w, http.StatusOK, a.toAPICall(row))
}

func (a *api) adminGetCall(w http.ResponseWriter, r *http.Request) {
	id, ok := pathCallID(w, r)
	if !ok {
		return
	}
	row, err := a.Calls.AdminCall(r.Context(), a.actor(r), id)
	if failed(w, r, err) {
		return
	}
	httpx.JSON(w, http.StatusOK, a.toAPICall(row))
}

func toAPIPayloadPart(p capture.PayloadPart) apitypes.CallPayloadPart {
	return apitypes.CallPayloadPart{Content: p.Content, Bytes: p.Bytes, Truncated: p.Truncated, Redactions: p.Redactions}
}

func writePayload(w http.ResponseWriter, r *http.Request, p capture.Payload, err error) {
	w.Header().Set("Cache-Control", "no-store")
	if failed(w, r, err) {
		return
	}
	out := apitypes.CallPayload{CallId: p.CallID, CapturedAt: p.CapturedAt, ExpiresAt: p.ExpiresAt, Arguments: toAPIPayloadPart(p.Arguments),
		CapturedBy: make([]apitypes.CallPayloadCapturedBy, len(p.CapturedBy)), Redactions: p.Arguments.Redactions,
		Truncated: p.Arguments.Truncated}
	for i, c := range p.CapturedBy {
		out.CapturedBy[i] = apitypes.CallPayloadCapturedBy(c)
	}
	if p.Result != nil {
		res := toAPIPayloadPart(*p.Result)
		out.Result = &res
		out.Redactions += res.Redactions
		out.Truncated = out.Truncated || res.Truncated
	}
	httpx.JSON(w, http.StatusOK, out)
}

func (a *api) getTeamCallPayload(w http.ResponseWriter, r *http.Request) {
	id, ok := pathCallID(w, r)
	if !ok {
		return
	}
	p, err := a.Capture.TeamPayload(r.Context(), a.actor(r), r.PathValue("team"), id)
	writePayload(w, r, p, err)
}

func (a *api) adminGetCallPayload(w http.ResponseWriter, r *http.Request) {
	id, ok := pathCallID(w, r)
	if !ok {
		return
	}
	p, err := a.Capture.AdminPayload(r.Context(), a.actor(r), id)
	writePayload(w, r, p, err)
}

// Usage.

var usageMethods = []string{"tools/list", "tools/call", "prompts/list", "prompts/get", "resources/list", "resources/templates/list", "resources/read"}

// usageQuery reads the report parameters.
func usageQuery(w http.ResponseWriter, r *http.Request) (usage.Query, bool) {
	var q usage.Query
	v := r.URL.Query()
	for _, p := range []struct {
		name string
		dst  **time.Time
	}{{"from", &q.From}, {"to", &q.To}} {
		if raw := v.Get(p.name); raw != "" {
			t, err := time.Parse(time.RFC3339Nano, raw)
			if err != nil {
				httpx.Error(w, http.StatusBadRequest, "invalid_range", p.name+" must be an RFC 3339 date-time")
				return q, false
			}
			*p.dst = &t
		}
	}
	if g := v.Get("groupBy"); g != "" {
		if !usage.ValidGroupBy(g) {
			httpx.Error(w, http.StatusBadRequest, "invalid_group_by", "groupBy must be gateway, server, capability, team, principalKind, day or hour")
			return q, false
		}
		q.GroupBy = g
	}
	for _, p := range []struct {
		name string
		dst  **uuid.UUID
	}{{"gateway", &q.Gateway}, {"server", &q.Server}, {"capability", &q.Capability}} {
		if raw := v.Get(p.name); raw != "" {
			id, err := uuid.Parse(raw)
			if err != nil {
				httpx.Error(w, http.StatusBadRequest, "invalid_"+p.name, p.name+" must be an ID")
				return q, false
			}
			*p.dst = &id
		}
	}
	if k := v.Get("principalKind"); k != "" {
		if k != "api_key" && k != "oauth" && k != "service_account" {
			httpx.Error(w, http.StatusBadRequest, "invalid_principal_kind", "principalKind must be api_key, oauth or service_account")
			return q, false
		}
		q.PrincipalKind = &k
	}
	if m := v.Get("method"); m != "" {
		if !slices.Contains(usageMethods, m) {
			httpx.Error(w, http.StatusBadRequest, "invalid_method", "method must be an MCP list or call method")
			return q, false
		}
		q.Method = &m
	}
	if s := v.Get("series"); s != "" {
		b, err := strconv.ParseBool(s)
		if err != nil {
			httpx.Error(w, http.StatusBadRequest, "invalid_series", "series must be true or false")
			return q, false
		}
		q.Series = b
	}
	if l := v.Get("limit"); l != "" {
		n, err := strconv.Atoi(l)
		if err != nil || n < 1 || n > usage.MaxRows {
			httpx.Error(w, http.StatusBadRequest, "invalid_limit", "limit must be between 1 and 200")
			return q, false
		}
		q.Limit = n
	}
	return q, true
}

func toAPIUsageMetrics(m *usage.Metrics) apitypes.UsageMetrics {
	return apitypes.UsageMetrics{Calls: m.Calls, Errors: m.Errors, Outcomes: m.Outcomes, P50LatencyMs: m.P50, P95LatencyMs: m.P95,
		RequestBytes: m.RequestBytes, ResponseBytes: m.ResponseBytes}
}

func toAPIUsageRef(r *usage.Ref) *apitypes.CallRef {
	if r == nil {
		return nil
	}
	return &apitypes.CallRef{Id: r.ID, Slug: r.Slug, Name: r.Name, Exists: r.Exists}
}

func toAPIUsageReport(rep usage.Report) apitypes.UsageReport {
	out := apitypes.UsageReport{From: rep.From, To: rep.To, GroupBy: apitypes.UsageGroupBy(rep.GroupBy), RolledUpTo: rep.RolledUpTo,
		Totals: toAPIUsageMetrics(rep.Totals), Truncated: rep.Truncated, Rows: make([]apitypes.UsageRow, len(rep.Rows))}
	for i, r := range rep.Rows {
		row := apitypes.UsageRow{Key: r.Key, Label: r.Label, Ref: toAPIUsageRef(r.Ref), Start: r.Start, Metrics: toAPIUsageMetrics(r.Metrics)}
		if r.PrincipalKind != "" {
			k := apitypes.UsagePrincipalKind(r.PrincipalKind)
			row.PrincipalKind = &k
		}
		if c := r.Capability; c != nil {
			row.Capability = &struct {
				ExposedName string            `json:"exposedName"`
				Id          *uuid.UUID        `json:"id,omitempty"`
				Server      *apitypes.CallRef `json:"server,omitempty"`
			}{ExposedName: c.ExposedName, Id: c.ID, Server: toAPIUsageRef(c.Server)}
		}
		if r.Series != nil {
			series := make([]apitypes.UsageBucket, len(r.Series))
			for j, b := range r.Series {
				series[j] = apitypes.UsageBucket{Start: b.Start, Metrics: toAPIUsageMetrics(b.Metrics)}
			}
			row.Series = &series
		}
		out.Rows[i] = row
	}
	return out
}

func (a *api) getTeamUsage(w http.ResponseWriter, r *http.Request) {
	q, ok := usageQuery(w, r)
	if !ok {
		return
	}
	rep, err := a.Usage.TeamReport(r.Context(), a.actor(r), r.PathValue("team"), q)
	if failed(w, r, err) {
		return
	}
	httpx.JSON(w, http.StatusOK, toAPIUsageReport(rep))
}

func (a *api) adminGetUsage(w http.ResponseWriter, r *http.Request) {
	q, ok := usageQuery(w, r)
	if !ok {
		return
	}
	if t := r.URL.Query().Get("team"); t != "" {
		if len(t) > 100 {
			httpx.Error(w, http.StatusBadRequest, "invalid_team", "team must be a team slug or ID")
			return
		}
		q.Team = t
	}
	rep, err := a.Usage.AdminReport(r.Context(), a.actor(r), q)
	if failed(w, r, err) {
		return
	}
	httpx.JSON(w, http.StatusOK, toAPIUsageReport(rep))
}
