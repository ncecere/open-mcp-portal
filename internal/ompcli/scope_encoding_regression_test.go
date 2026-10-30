package ompcli

import "testing"

func TestScopeKeyDoesNotConfuseCommasInExactToolNames(t *testing.T) {
	one, two := []string{"a,b"}, []string{"a", "b"}
	if scopeKey(&ToolScope{Tools: &one}) == scopeKey(&ToolScope{Tools: &two}) {
		t.Fatal("one exact tool name was confused with two different tools")
	}
	reordered := []string{"b", "a", "a"}
	if scopeKey(&ToolScope{Tools: &two}) != scopeKey(&ToolScope{Tools: &reordered}) {
		t.Fatal("scope keys must remain order independent and deduplicated")
	}
}
