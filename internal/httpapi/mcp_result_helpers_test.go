package httpapi_test

import (
	"encoding/json"
	"strings"
	"testing"
)

func toolText(t *testing.T, out map[string]any) (text string, isError bool) {
	t.Helper()
	res, ok := out["result"].(map[string]any)
	if !ok {
		t.Fatalf("no result in %v", out)
	}
	content, _ := res["content"].([]any)
	if len(content) == 0 {
		t.Fatalf("no content in %v", out)
	}
	text, _ = content[0].(map[string]any)["text"].(string)
	isError, _ = res["isError"].(bool)
	return text, isError
}

func noLink(t *testing.T, out map[string]any, what string) {
	t.Helper()
	b, _ := json.Marshal(out)
	s := string(b)
	for _, bad := range []string{"/connect/", "-32042", "input_required", "elicitation", "requestState", "http://", "https://"} {
		if strings.Contains(s, bad) {
			t.Fatalf("%s: the answer holds %q: %s", what, bad, s)
		}
	}
	if out["error"] != nil && rpcErrorCode(out) == -32042 {
		t.Fatalf("%s: -32042: %s", what, s)
	}
}

func (e *provEnv) connectRequests() string {
	return e.scalar(`SELECT count(*)::text FROM provider_connect_requests`)
}
