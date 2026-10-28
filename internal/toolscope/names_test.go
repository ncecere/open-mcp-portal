package toolscope

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestScopeExactFutureNames(t *testing.T) {
	for _, name := range []string{"create_issue_internal", "CreateIssue", "工单_创建", "s__" + strings.Repeat("界", 365) + "xy", strings.Repeat("x", 1100)} {
		raw, _ := json.Marshal(Scope{Tools: []string{name}})
		s, err := Parse(raw)
		if err != nil || !Allows(s, "", name) || Allows(s, "read", name+"x") {
			t.Fatalf("exact name %q: %v", name, err)
		}
		if name == "CreateIssue" && Allows(s, "", "createissue") {
			t.Fatal("normalized exact case")
		}
	}
	for _, name := range []string{strings.Repeat("界", 367), "x\x7f", "工单\u0085", "x\u0000"} {
		raw, _ := json.Marshal(Scope{Tools: []string{name}})
		if _, err := Parse(raw); err == nil {
			t.Fatalf("accepted invalid name %q", name)
		}
	}
	// Invalid raw UTF-8 must fail before JSON replacement could mask it.
	raw := append([]byte(`{"tools":["`), 0xff)
	raw = append(raw, []byte(`"]}`)...)
	if _, err := Parse(raw); err == nil {
		t.Fatal("accepted invalid raw UTF-8")
	}
	if Allows(Stored(raw), "read", "anything") {
		t.Fatal("corrupt UTF-8 widened access")
	}
}
