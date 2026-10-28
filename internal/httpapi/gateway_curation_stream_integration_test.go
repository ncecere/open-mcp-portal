package httpapi_test

import (
	"context"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestCurationStreamAndRelayKeepMergedArguments(t *testing.T) {
	e := newRelayEnv(t, nil)
	setCuration(t, e.gwEnv, e.owner, e.path, "progress", map[string]any{"constraints": map[string]any{"count": map[string]any{"fixed": 2}, "delay_ms": map[string]any{"fixed": 0}}})
	for _, modern := range []bool{false, true} {
		body, headers := toolRequest(modern, "status__progress", map[string]any{}, map[string]any{"progressToken": "curated-progress"})
		res := e.post(context.Background(), body, headers)
		events := readSSE(res.Body)
		res.Body.Close()
		progress := 0
		for _, ev := range events {
			if strings.Contains(ev.data, "notifications/progress") {
				progress++
			}
		}
		if progress != 2 {
			t.Fatalf("modern=%v: %d progress notifications in %+v", modern, progress, events)
		}
	}
	const pinned = "https://auth.example.com/curated-approval"
	setCuration(t, e.gwEnv, e.owner, e.path, "ask_url", map[string]any{"constraints": map[string]any{"url": map[string]any{"fixed": pinned}}})
	cs := e.elicitor(func(r *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
		if r.Params.URL != pinned {
			t.Errorf("relay URL: %s", r.Params.URL)
		}
		return &mcp.ElicitResult{Action: "accept"}, nil
	})
	result, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "status__ask_url"})
	if err != nil || result.IsError || resultText(t, result) != "ask_url: accept upstream-state=url-state-1" {
		t.Fatalf("curated relay: %+v %v", result, err)
	}
	count := 0
	for _, c := range e.fake.ToolCalls() {
		if c.Tool != "ask_url" {
			continue
		}
		count++
		if !strings.Contains(string(c.Arguments), pinned) {
			t.Fatalf("relay lost merged argument: %+v", c)
		}
		if count == 2 && (c.RequestState != "url-state-1" || c.InputResponses == nil) {
			t.Fatalf("relay lost retry fields: %+v", c)
		}
	}
	if count != 2 {
		t.Fatalf("relay calls: %d", count)
	}
}
