package testutil

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func fakeText(s string) *mcp.CallToolResult {
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: s}}}
}

func stringArg(name, description string) map[string]any {
	return map[string]any{"type": "object", "required": []string{name},
		"properties": map[string]any{name: map[string]any{"type": "string", "description": description}}}
}

// server builds the MCP server of one request from the current state.
func (f *FakeMCP) server() *mcp.Server {
	f.mu.Lock()
	defer f.mu.Unlock()
	opts := &mcp.ServerOptions{PageSize: f.pageSize}
	switch f.protocol {
	case ProtocolLegacy:
		for _, v := range mcp.SupportedProtocolVersions() {
			if v < modernVersion {
				opts.SupportedProtocolVersions = append(opts.SupportedProtocolVersions, v)
			}
		}
	case ProtocolModern:
		opts.SupportedProtocolVersions = []string{modernVersion}
	}
	s := mcp.NewServer(&mcp.Implementation{Name: "fake-status", Version: "1.0.0"}, opts)
	yes := true
	tools := []*mcp.Tool{
		{Name: "check_outage", Title: "Check outage", Description: "Reports whether a company service has an outage right now.",
			InputSchema: stringArg("service", "The service, for example email")},
		{Name: "search_tickets", Title: "Search tickets", Description: "Searches open support tickets.",
			InputSchema: stringArg("query", "Words to look for")},
		{Name: "create_ticket", Title: "Create ticket", Description: "Opens a support ticket.",
			InputSchema: stringArg("title", "The ticket's title"), Annotations: &mcp.ToolAnnotations{DestructiveHint: &yes}},
	}
	for _, name := range f.extra {
		tools = append(tools, &mcp.Tool{Name: name, Description: "An added tool.", InputSchema: map[string]any{"type": "object"}})
	}
	for _, t := range tools {
		if f.hidden[t.Name] {
			continue
		}
		if d, ok := f.descriptions[t.Name]; ok {
			t.Description = d
		}
		if annotations, ok := f.annotations[t.Name]; ok {
			t.Annotations = annotations
		}
		name := t.Name
		s.AddTool(t, func(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			f.sawCall(name, headerOf(req))
			return fakeText(fmt.Sprintf("%s: ok", name)), nil
		})
	}
	if f.gatewayTools {
		jwksURL, audience := f.jwksURL, f.audience
		describe := func(name, d string) string {
			if v, ok := f.descriptions[name]; ok {
				return v
			}
			return d
		}
		protected := f.protect != nil
		s.AddTool(&mcp.Tool{Name: "whoami", Title: "Who am I", Description: describe("whoami", "Shows the identity the portal sent with this call."),
			InputSchema: map[string]any{"type": "object"}}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			h := headerOf(req)
			f.sawCall("whoami", h)
			if !protected {
				out, _ := json.Marshal(Whoami(ctx, h, jwksURL, audience))
				return fakeText(string(out)), nil
			}
			// Protected: Authorization holds the person's token, never shown;
			// the identity token can only be in MCP-Gateway-Identity.
			bearer := strings.TrimPrefix(h.Get("Authorization"), "Bearer ")
			only := h.Clone()
			only.Del("Authorization")
			who := Whoami(ctx, only, jwksURL, audience)
			if bearer != "" {
				who.BearerSHA256 = TokenDigest(bearer)
			}
			out, _ := json.Marshal(who)
			return fakeText(string(out)), nil
		})
		s.AddTool(&mcp.Tool{Name: "provider_token", Title: "Provider token",
			Description: describe("provider_token", "Reports whether the portal sent a provider token with this call (never the token itself)."),
			InputSchema: map[string]any{"type": "object"}}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			h := headerOf(req)
			f.sawCall("provider_token", h)
			out, _ := json.Marshal(ProviderTokenReport(ctx, h, jwksURL, audience))
			return fakeText(string(out)), nil
		})
		s.AddTool(&mcp.Tool{Name: "echo", Title: "Echo", Description: describe("echo", "Returns its text."), InputSchema: stringArg("text", "Any text")},
			func(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				f.sawFull("echo", req)
				var args struct {
					Text string `json:"text"`
				}
				_ = json.Unmarshal(req.Params.Arguments, &args)
				return fakeText(args.Text), nil
			})
	}
	if f.schemaTools {
		description := "Looks something up (arrays, parameter headers)."
		if d, ok := f.descriptions["lookup"]; ok {
			description = d
		}
		s.AddTool(&mcp.Tool{Name: "lookup", Title: "Lookup", Description: description,
			InputSchema: map[string]any{"type": "object", "properties": map[string]any{
				"region": map[string]any{"type": "string", "x-mcp-header": "Region"},
				"limit":  map[string]any{"type": "integer", "x-mcp-header": "Limit"},
				"note":   map[string]any{"type": "string"},
			}},
			OutputSchema: map[string]any{"type": []string{"null", "array"}}},
			func(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				f.sawFull("lookup", req)
				var args struct {
					Region string `json:"region"`
					Limit  int    `json:"limit"`
				}
				_ = json.Unmarshal(req.Params.Arguments, &args)
				return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "lookup: ok"}},
					StructuredContent: []any{map[string]any{"region": args.Region, "limit": args.Limit}}}, nil
			})
	}
	if f.mrtrTools {
		f.addMRTRTools(s)
	}
	if f.streamTools {
		f.addStreamTools(s)
	}
	if f.protect != nil {
		s.AddTool(&mcp.Tool{Name: "write", Title: "Write", Description: "Needs the write scope.", InputSchema: map[string]any{"type": "object"}},
			func(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				f.sawCall("write", headerOf(req))
				return fakeText("written"), nil
			})
	}
	if f.echoSecrets {
		s.AddTool(&mcp.Tool{Name: "echo_secrets", Title: "Echo secrets", Description: "Returns the credentials it received.",
			InputSchema: map[string]any{"type": "object"}}, func(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			h := headerOf(req)
			f.sawCall("echo_secrets", h)
			_, id := IdentityToken(h)
			return &mcp.CallToolResult{Content: []mcp.Content{
				&mcp.TextContent{Text: fmt.Sprintf("identity=%s provider=%s authorization=%s apikey=%s query=%s ", id,
					h.Get("MCP-Gateway-Provider-Token"), h.Get("Authorization"), h.Get("X-Api-Key"), h.Get(QueryHeader))},
				&mcp.TextContent{Text: string(req.Params.Arguments)},
			}}, nil
		})
		s.AddTool(&mcp.Tool{Name: "echo_tokens", Title: "Echo tokens", Description: "Returns the provider token and the bearer token it received, verbatim.",
			InputSchema: map[string]any{"type": "object"}}, func(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			h := headerOf(req)
			f.sawCall("echo_tokens", h)
			return fakeText(fmt.Sprintf("provider_token=%s oauth_token=%s end", h.Get("MCP-Gateway-Provider-Token"),
				strings.TrimPrefix(h.Get("Authorization"), "Bearer "))), nil
		})
		s.AddTool(&mcp.Tool{Name: "image", Title: "Image", Description: "Returns an image.", InputSchema: map[string]any{"type": "object"}},
			func(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				f.sawCall("image", headerOf(req))
				return &mcp.CallToolResult{Content: []mcp.Content{&mcp.ImageContent{Data: []byte("0123456789abcdef0123456789abcdef"), MIMEType: "image/png"}}}, nil
			})
	}
	if !f.hidden["status://services"] {
		s.AddResource(&mcp.Resource{URI: "status://services", Name: "services", Title: "Services", Description: "Every monitored service.",
			MIMEType: "text/plain"}, func(_ context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
			f.sawRead(req)
			return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{URI: req.Params.URI, MIMEType: "text/plain", Text: "email\nvpn"}}}, nil
		})
	}
	if !f.hidden["status://services/{service}"] {
		s.AddResourceTemplate(&mcp.ResourceTemplate{URITemplate: "status://services/{service}", Name: "service", Title: "Service status",
			Description: "The status of one service.", MIMEType: "text/plain"},
			func(_ context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
				f.sawRead(req)
				return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{URI: req.Params.URI, MIMEType: "text/plain", Text: "operating normally"}}}, nil
			})
	}
	if !f.hidden["incident_summary"] {
		s.AddPrompt(&mcp.Prompt{Name: "incident_summary", Title: "Incident summary", Description: "Summarise an incident for a service.",
			Arguments: []*mcp.PromptArgument{{Name: "service", Description: "The affected service", Required: true}}},
			func(_ context.Context, req *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
				return &mcp.GetPromptResult{Messages: []*mcp.PromptMessage{{Role: "user",
					Content: &mcp.TextContent{Text: "Summarise the incident for " + req.Params.Arguments["service"]}}}}, nil
			})
	}
	return s
}
