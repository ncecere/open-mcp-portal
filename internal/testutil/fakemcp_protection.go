package testutil

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
)

// Protection makes the fake an OAuth-protected MCP server (Phase 7): it
// answers 401 with a Bearer challenge naming its protected-resource
// metadata, serves that metadata, and accepts only bearer tokens its
// authorization server says are active and bound to this server's URL.
type Protection struct {
	// Issuer is the authorization server listed in the metadata.
	Issuer string
	// Introspect asks the authorization server about a token.
	Introspect func(ctx context.Context, token string) Introspection
	// ScopesSupported are listed in the metadata; ChallengeScope is the
	// 401 challenge's scope ("": none).
	ScopesSupported []string
	ChallengeScope  string
	// Resource overrides the metadata's resource ("": this server's URL).
	Resource string
	// NoResourceMetadataParam leaves resource_metadata out of the 401 (the
	// metadata is then found at the well-known URI).
	NoResourceMetadataParam bool
	// WriteScope is the scope the write tool needs (403 insufficient_scope
	// without it; default "write").
	WriteScope string
	// IgnoreResource accepts tokens bound to another resource (or none).
	IgnoreResource bool
}

// Protect makes the fake an OAuth resource server, and adds the write tool.
func (f *FakeMCP) Protect(p Protection) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if p.WriteScope == "" {
		p.WriteScope = "write"
	}
	f.protect = &p
}

// SetProtection changes the protection under the fake's lock.
func (f *FakeMCP) SetProtection(change func(p *Protection)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	change(f.protect)
}

func (f *FakeMCP) protection() *Protection {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.protect == nil {
		return nil
	}
	p := *f.protect
	return &p
}

// selfURL is the fake's endpoint as a request reached it.
func selfURL(r *http.Request) string { return "http://" + r.Host + "/mcp" }

func metadataURL(r *http.Request) string {
	return "http://" + r.Host + "/.well-known/oauth-protected-resource/mcp"
}

// guard enforces Protection on an MCP request; false when it answered.
func (f *FakeMCP) guard(w http.ResponseWriter, r *http.Request, p *Protection) bool {
	challenge := func(status int, errCode, scope string) bool {
		parts := []string{}
		if errCode != "" {
			parts = append(parts, `error="`+errCode+`"`)
		}
		if scope != "" {
			parts = append(parts, `scope="`+scope+`"`)
		}
		if !p.NoResourceMetadataParam {
			parts = append(parts, `resource_metadata="`+metadataURL(r)+`"`)
		}
		w.Header().Set("WWW-Authenticate", "Bearer "+strings.Join(parts, ", "))
		http.Error(w, http.StatusText(status), status)
		return false
	}
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || token == "" {
		return challenge(http.StatusUnauthorized, "", p.ChallengeScope)
	}
	in := p.Introspect(r.Context(), token)
	resource := p.Resource
	if resource == "" {
		resource = selfURL(r)
	}
	if !in.Active || (!p.IgnoreResource && in.Resource != resource) {
		return challenge(http.StatusUnauthorized, "invalid_token", p.ChallengeScope)
	}
	// The write tool needs WriteScope (a step-up).
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	r.Body = io.NopCloser(bytes.NewReader(body))
	var msg struct {
		Method string `json:"method"`
		Params struct {
			Name string `json:"name"`
		} `json:"params"`
	}
	_ = json.Unmarshal(body, &msg)
	if msg.Method == "tools/call" && msg.Params.Name == "write" && !slices.Contains(in.Scopes, p.WriteScope) {
		return challenge(http.StatusForbidden, "insufficient_scope", strings.Join(append(append([]string{}, in.Scopes...), p.WriteScope), " "))
	}
	return true
}

func (f *FakeMCP) serveResourceMetadata(w http.ResponseWriter, r *http.Request, p *Protection) {
	resource := p.Resource
	if resource == "" {
		resource = selfURL(r)
	}
	scopes := p.ScopesSupported
	if scopes == nil {
		scopes = []string{}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"resource": resource, "authorization_servers": []string{p.Issuer},
		"scopes_supported": scopes, "bearer_methods_supported": []string{"header"}, "resource_name": "Fake protected MCP"})
}

// IntrospectAt asks a fake OAuth provider's /introspect over HTTP
// (cmd/fakemcp -protect).
func IntrospectAt(endpoint string) func(ctx context.Context, token string) Introspection {
	return func(ctx context.Context, token string) Introspection {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(url.Values{"token": {token}}.Encode()))
		if err != nil {
			return Introspection{}
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			return Introspection{}
		}
		defer res.Body.Close()
		var out Introspection
		_ = json.NewDecoder(io.LimitReader(res.Body, 64<<10)).Decode(&out)
		return out
	}
}
