package ompcli

import (
	"fmt"
	"net/mail"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

var (
	serverSlugRE  = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,46}[a-z0-9])?$`)
	teamSlugRE    = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	gatewaySlugRE = serverSlugRE
	envNameRE     = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
)

var rateLimitKeys = map[string]bool{
	"person_per_minute": true, "credential_per_minute": true, "service_account_per_minute": true,
	"gateway_per_minute": true, "server_per_minute": true,
}

var capabilityKinds = map[string]bool{"tool": true, "prompt": true, "resource": true, "resource_template": true}

// problems collects what is wrong with a document, in the order it is found.
type problems []string

func (p *problems) add(format string, args ...any) {
	*p = append(*p, fmt.Sprintf(format, args...))
}

// Validate lists everything wrong with the document, without any network.
func (f *File) Validate() []string {
	var p problems
	if f.Schema != SchemaID {
		p.add("schema must be %q (got %q)", SchemaID, f.Schema)
	}
	// seen holds the slugs listed so far, as kind/slug.
	seen := map[string]bool{}
	for i, s := range f.Servers {
		validateServer(&p, fmt.Sprintf("servers[%d] (%s)", i, s.Slug), s, seen)
	}
	for i, t := range f.Teams {
		validateTeam(&p, fmt.Sprintf("teams[%d] (%s)", i, t.Slug), t, seen)
	}
	for i, g := range f.Gateways {
		validateGateway(&p, fmt.Sprintf("gateways[%d] (%s)", i, g.Slug), g, seen)
	}
	validatePlatformLimits(&p, f.Limits)
	return p
}

func validateServer(p *problems, at string, s Server, seen map[string]bool) {
	if !teamSlugRE.MatchString(s.Team) {
		p.add("%s: team must be a team slug", at)
	}
	if !serverSlugRE.MatchString(s.Slug) {
		p.add("%s: slug must be lowercase letters, digits and hyphens, up to 48 characters", at)
	}
	if seen["server/"+s.Slug] {
		p.add("%s: duplicate server slug (slugs are unique across the portal)", at)
	}
	seen["server/"+s.Slug] = true
	if strings.TrimSpace(s.Name) == "" {
		p.add("%s: name is required", at)
	}
	if u, err := url.Parse(s.URL); err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		p.add("%s: url must be an absolute http(s) URL", at)
	}
	validateServerAuth(p, at, s)
	switch s.Publish {
	case "", "none", "request":
	default:
		p.add("%s: publish must be none or request", at)
	}
	if s.Governance != nil {
		if err := s.Governance.validate(); err != nil {
			p.add("%s: governance: %v", at, err)
		}
	}
	if s.TimeoutSeconds != nil && (*s.TimeoutSeconds < 1 || *s.TimeoutSeconds > 600) {
		p.add("%s: timeoutSeconds must be between 1 and 600", at)
	}
}

func validateServerAuth(p *problems, at string, s Server) {
	switch s.AuthMode {
	case "", "none":
		if s.AuthHeaderName != "" || s.AuthValueEnv != "" {
			p.add("%s: authHeaderName and authValueEnv need authMode: static_header", at)
		}
	case "static_header":
		if s.AuthHeaderName == "" {
			p.add("%s: authMode static_header needs authHeaderName", at)
		}
		if s.AuthValueEnv != "" && !envNameRE.MatchString(s.AuthValueEnv) {
			p.add("%s: authValueEnv must be the NAME of an environment variable, never the secret itself", at)
		}
	default:
		p.add("%s: authMode %q is not manageable by omp (use none or static_header; oauth, machine_oauth and person_secret need a browser session)", at, s.AuthMode)
	}
}

func validateTeam(p *problems, at string, t Team, seen map[string]bool) {
	if !teamSlugRE.MatchString(t.Slug) {
		p.add("%s: slug must be lowercase letters, digits and hyphens", at)
	}
	if seen["team/"+t.Slug] {
		p.add("%s: duplicate team slug", at)
	}
	seen["team/"+t.Slug] = true
	if strings.TrimSpace(t.Name) == "" {
		p.add("%s: name is required", at)
	}
	switch t.Status {
	case "", "active", "archived":
	default:
		p.add("%s: status must be active or archived", at)
	}
	if t.OwnerEmail != "" {
		if _, err := mail.ParseAddress(t.OwnerEmail); err != nil {
			p.add("%s: ownerEmail is not an email address", at)
		}
	}
	for _, k := range sortedKeys(t.Limits) {
		if !rateLimitKeys[k] {
			p.add("%s: limits.%s is not a rate-limit key", at, k)
		}
		if v := t.Limits[k]; v != nil && !validLimit(*v) {
			p.add("%s: limits.%s must be between 1 and 1000000, or null", at, k)
		}
	}
}

func validLimit(v int64) bool { return v >= 1 && v <= 1_000_000 }

func validateGateway(p *problems, at string, g Gateway, seen map[string]bool) {
	if !gatewaySlugRE.MatchString(g.Slug) {
		p.add("%s: slug must be lowercase letters, digits and hyphens, up to 48 characters", at)
	}
	if seen["gateway/"+g.Slug] {
		p.add("%s: duplicate gateway slug", at)
	}
	seen["gateway/"+g.Slug] = true
	if strings.TrimSpace(g.Name) == "" {
		p.add("%s: name is required", at)
	}
	if g.MaxSensitivity != nil && !validSensitivity(*g.MaxSensitivity) {
		p.add("%s: maxSensitivity must be public, internal, confidential or restricted", at)
	}
	if g.Capabilities != nil {
		validateCapabilities(p, at, *g.Capabilities)
	}
	if g.Grants != nil {
		validateGrants(p, at, *g.Grants)
	}
}

func validateCapabilities(p *problems, at string, caps []CapabilityRef) {
	keys := map[string]bool{}
	for j, c := range caps {
		if c.Server == "" || c.Name == "" || !capabilityKinds[c.Kind] {
			p.add("%s: capabilities[%d] needs server, name and a kind of tool, prompt, resource or resource_template", at, j)
		}
		if keys[c.key()] {
			p.add("%s: capabilities[%d] is listed twice", at, j)
		}
		keys[c.key()] = true
		if c.Curation == nil {
			continue
		}
		if c.Kind != "tool" {
			p.add("%s: capabilities[%d].curation: only tools can be curated", at, j)
		} else if err := c.Curation.validate(); err != nil {
			p.add("%s: capabilities[%d].curation: %v", at, j, err)
		}
	}
}

func validateGrants(p *problems, at string, grants []Grant) {
	keys := map[string]bool{}
	for j, gr := range grants {
		subjects := 0
		for _, v := range []string{gr.Team, gr.Group, gr.UserEmail} {
			if v != "" {
				subjects++
			}
		}
		if subjects != 1 {
			p.add("%s: grants[%d] needs exactly one of team, group and userEmail", at, j)
			continue
		}
		if keys[gr.subject()] {
			p.add("%s: grants[%d] repeats %s", at, j, gr.subject())
		}
		keys[gr.subject()] = true
		if gr.Group != "" && !validGroupName(gr.Group) {
			p.add("%s: grants[%d].group must be 1-256 characters on one line without leading or trailing space (the portal trims it)", at, j)
		}
		if gr.ExpiresAt != "" {
			if _, err := time.Parse(time.RFC3339, gr.ExpiresAt); err != nil {
				p.add("%s: grants[%d].expiresAt must be an RFC 3339 timestamp such as 2026-12-31T00:00:00Z", at, j)
			}
		}
		if ts := gr.ToolScope; ts != nil {
			for _, m := range validateToolScope(ts) {
				p.add("%s: grants[%d].toolScope: %s", at, j, m)
			}
		}
	}
}

// validGroupName is whether the portal would store an SSO group's name as written.
func validGroupName(group string) bool {
	return group == strings.TrimSpace(group) && len(group) <= 256 && utf8.ValidString(group) && strings.IndexFunc(group, unicode.IsControl) < 0
}

func validatePlatformLimits(p *problems, limits map[string]PlatformLimit) {
	for _, k := range sortedKeys(limits) {
		if !rateLimitKeys[k] {
			p.add("limits.%s is not a rate-limit key", k)
		}
		l := limits[k]
		for name, v := range map[string]*int64{"default": l.Default, "ceiling": l.Ceiling} {
			if v != nil && !validLimit(*v) {
				p.add("limits.%s.%s must be between 1 and 1000000, or null", k, name)
			}
		}
		if l.Default != nil && l.Ceiling != nil && *l.Default > *l.Ceiling {
			p.add("limits.%s: default is above the ceiling", k)
		}
	}
}

// validateToolScope applies the portal's tool-scope rules (internal/toolscope)
// so a bad ceiling is refused before any request.
func validateToolScope(ts *ToolScope) []string {
	var p []string
	if ts.Classes != nil {
		if len(*ts.Classes) > 3 {
			p = append(p, "has more than 3 classes")
		}
		for _, c := range *ts.Classes {
			if c != "read" && c != "write" && c != "destructive" {
				p = append(p, fmt.Sprintf("classes has %q (read, write or destructive)", c))
			}
		}
	}
	if ts.Tools != nil {
		if len(*ts.Tools) > 500 {
			p = append(p, "has more than 500 tools")
		}
		for _, n := range *ts.Tools {
			if len(n) == 0 || len(n) > 1100 || !utf8.ValidString(n) || strings.ContainsAny(n, `*?[]{}\`) || strings.IndexFunc(n, unicode.IsControl) >= 0 {
				p = append(p, "tools must be exact names of 1-1100 bytes without control characters or the glob characters * ? [ ] { } \\")
				break
			}
		}
	}
	return p
}
