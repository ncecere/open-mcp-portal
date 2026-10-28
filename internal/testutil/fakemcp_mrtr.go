package testutil

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// The fake's tools for MCP 2026-07-28 behaviours: multi round-trip input
// requests, progress and cancellation (FakeMCP.EnableMRTRTools and
// EnableStreamTools).

// sawFull records a tool call with everything the fake received: headers
// and the _meta, requestState and inputResponses of the params.
func (f *FakeMCP) sawFull(tool string, req *mcp.CallToolRequest) {
	h := headerOf(req)
	c := ToolCall{Tool: tool, Authorization: h.Get("Authorization"), Identity: h.Get("MCP-Gateway-Identity"), Header: h.Clone()}
	if p := req.Params; p != nil {
		c.Arguments = append(json.RawMessage(nil), p.Arguments...)
		c.RequestState = p.RequestState
		c.Meta = map[string]any(p.Meta)
		if len(p.InputResponses) > 0 {
			raw, _ := json.Marshal(p.InputResponses)
			_ = json.Unmarshal(raw, &c.InputResponses)
		}
	}
	f.mu.Lock()
	f.toolCalls = append(f.toolCalls, c)
	hook := f.OnToolCall
	f.mu.Unlock()
	if hook != nil {
		hook(c)
	}
}

func objectSchemaOf(props map[string]any) map[string]any {
	return map[string]any{"type": "object", "properties": props}
}

func (f *FakeMCP) addMRTRTools(s *mcp.Server) {
	f.addMRTRPromptAndResource(s)
	s.AddTool(&mcp.Tool{Name: "ask_form", Title: "Ask (form)", Description: "Asks for a region with a form elicitation, then answers.",
		InputSchema: map[string]any{"type": "object"}},
		func(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			f.sawFull("ask_form", req)
			if r, ok := req.Params.InputResponses["region"].(*mcp.ElicitResult); ok {
				if r.Action != "accept" {
					return fakeText("ask_form: " + r.Action), nil
				}
				return fakeText(fmt.Sprintf("ask_form: region=%v upstream-state=%s", r.Content["region"], req.Params.RequestState)), nil
			}
			return &mcp.CallToolResult{
				InputRequests: mcp.InputRequestMap{"region": &mcp.ElicitParams{Mode: "form", Message: "Which region?",
					RequestedSchema: map[string]any{"type": "object", "required": []string{"region"},
						"properties": map[string]any{"region": map[string]any{"type": "string", "title": "Region"}}}}},
				RequestState: "form-state-1"}, nil
		})
	s.AddTool(&mcp.Tool{Name: "ask_url", Title: "Ask (URL)", Description: "Sends the person to a URL, then answers. The URL is the argument url.",
		InputSchema: objectSchemaOf(map[string]any{"url": map[string]any{"type": "string"}})},
		func(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			f.sawFull("ask_url", req)
			if r, ok := req.Params.InputResponses["approve"].(*mcp.ElicitResult); ok {
				return fakeText(fmt.Sprintf("ask_url: %s upstream-state=%s", r.Action, req.Params.RequestState)), nil
			}
			var args struct {
				URL string `json:"url"`
			}
			_ = json.Unmarshal(req.Params.Arguments, &args)
			if args.URL == "" {
				args.URL = "https://auth.example.com/approve?id=abc"
			}
			return &mcp.CallToolResult{
				InputRequests: mcp.InputRequestMap{"approve": &mcp.ElicitParams{Mode: "url", Message: "Approve this in your browser.", URL: args.URL}},
				RequestState:  "url-state-1"}, nil
		})
	s.AddTool(&mcp.Tool{Name: "ask_sampling", Title: "Ask (sampling)", Description: "Asks the client to sample (not relayed by the portal); with mixed, also a form.",
		InputSchema: objectSchemaOf(map[string]any{"mixed": map[string]any{"type": "boolean"}})},
		func(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			f.sawFull("ask_sampling", req)
			var args struct {
				Mixed bool `json:"mixed"`
			}
			_ = json.Unmarshal(req.Params.Arguments, &args)
			in := mcp.InputRequestMap{"draft": &mcp.CreateMessageParams{
				Messages:  []*mcp.SamplingMessage{{Role: "user", Content: &mcp.TextContent{Text: "write a haiku"}}},
				MaxTokens: 20}}
			if args.Mixed {
				in["region"] = &mcp.ElicitParams{Mode: "form", Message: "Which region?",
					RequestedSchema: map[string]any{"type": "object", "properties": map[string]any{"region": map[string]any{"type": "string"}}}}
			}
			return &mcp.CallToolResult{InputRequests: in, RequestState: "sampling-state-1"}, nil
		})
}

// addMRTRPromptAndResource adds the prompt ask_prompt and the resource
// status://ask, which also answer input_required until the retry.
func (f *FakeMCP) addMRTRPromptAndResource(s *mcp.Server) {
	s.AddPrompt(&mcp.Prompt{Name: "ask_prompt", Title: "Ask prompt", Description: "Asks who it is for with a form, then answers."},
		func(_ context.Context, req *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
			if r, ok := req.Params.InputResponses["who"].(*mcp.ElicitResult); ok {
				return &mcp.GetPromptResult{Messages: []*mcp.PromptMessage{{Role: "user",
					Content: &mcp.TextContent{Text: fmt.Sprintf("for %v upstream-state=%s", r.Content["who"], req.Params.RequestState)}}}}, nil
			}
			return &mcp.GetPromptResult{
				InputRequests: mcp.InputRequestMap{"who": &mcp.ElicitParams{Mode: "form", Message: "Who is it for?",
					RequestedSchema: map[string]any{"type": "object", "properties": map[string]any{"who": map[string]any{"type": "string"}}}}},
				RequestState: "prompt-state-1"}, nil
		})
	s.AddResource(&mcp.Resource{URI: "status://ask", Name: "ask", Title: "Ask", Description: "Sends the person to a URL, then answers.", MIMEType: "text/plain"},
		func(_ context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
			if r, ok := req.Params.InputResponses["approve"].(*mcp.ElicitResult); ok {
				return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{URI: req.Params.URI, MIMEType: "text/plain",
					Text: fmt.Sprintf("%s upstream-state=%s", r.Action, req.Params.RequestState)}}}, nil
			}
			return &mcp.ReadResourceResult{
				InputRequests: mcp.InputRequestMap{"approve": &mcp.ElicitParams{Mode: "url", Message: "Approve the read.", URL: "https://auth.example.com/read"}},
				RequestState:  "read-state-1"}, nil
		})
}

func (f *FakeMCP) addStreamTools(s *mcp.Server) {
	s.AddTool(&mcp.Tool{Name: "progress", Title: "Progress", Description: "Reports progress count times, delay_ms apart, then answers.",
		InputSchema: objectSchemaOf(map[string]any{"count": map[string]any{"type": "integer"}, "delay_ms": map[string]any{"type": "integer"}})},
		func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			f.sawFull("progress", req)
			args := struct {
				Count   int `json:"count"`
				DelayMS int `json:"delay_ms"`
			}{Count: 3, DelayMS: 10}
			_ = json.Unmarshal(req.Params.Arguments, &args)
			token := req.Params.GetProgressToken()
			for i := 1; i <= args.Count && token != nil; i++ {
				select {
				case <-time.After(time.Duration(args.DelayMS) * time.Millisecond):
				case <-ctx.Done():
					return nil, ctx.Err()
				}
				if err := req.Session.NotifyProgress(ctx, &mcp.ProgressNotificationParams{ProgressToken: token, Progress: float64(i),
					Total: float64(args.Count), Message: fmt.Sprintf("step %d", i)}); err != nil {
					return nil, err
				}
			}
			return fakeText(fmt.Sprintf("progress: %d steps", args.Count)), nil
		})
	s.AddTool(&mcp.Tool{Name: "block", Title: "Block", Description: "Waits until the request is cancelled.",
		InputSchema: map[string]any{"type": "object"}},
		func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			f.sawFull("block", req)
			f.blocked <- struct{}{}
			select {
			case <-ctx.Done():
				f.cancelled.Add(1)
				return nil, ctx.Err()
			case <-f.release:
				f.cancelled.Add(1)
				return nil, context.Canceled
			case <-time.After(60 * time.Second):
				return fakeText("block: timed out"), nil
			}
		})
}
