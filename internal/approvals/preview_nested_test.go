package approvals

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestPreviewMasksEscapedNestedCredentialsAndKeys(t *testing.T) {
	for _, tc := range []struct{ name, nested, secret string }{
		{"short escaped value", `{"ordinary":"\u0061\u0062\u0063"}`, "abc"},
		{"escaped member name", `{"\u0073ecret-value":"visible"}`, "secret-value"},
		{"nested array", `[{"ordinary":"\u0061\u0062\u0063"}]`, "abc"},
		{"deep string wrapper", `{"inside":"{\"ordinary\":\"abc\"}"}`, "abc"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := json.Marshal(map[string]string{"nested": tc.nested, "safe": "unchanged"})
			if err != nil {
				t.Fatal(err)
			}
			clean, truncated, redacted, err := (&Service{}).capturePreview(context.Background(), raw, []string{tc.secret})
			if err != nil || truncated || !redacted {
				t.Fatalf("flags: truncated=%v redacted=%v err=%v", truncated, redacted, err)
			}
			if strings.Contains(clean, tc.secret) || strings.Contains(clean, `\u0061`) || strings.Contains(clean, `\u0073`) || !strings.Contains(clean, "unchanged") {
				t.Fatalf("unsafe nested preview: %q", clean)
			}
			var obj map[string]string
			if err := json.Unmarshal([]byte(clean), &obj); err != nil {
				t.Fatal(err)
			}
			if obj["nested"] != "[REDACTED]" {
				t.Fatalf("nested JSON was not masked: %q", obj["nested"])
			}
		})
	}
}
