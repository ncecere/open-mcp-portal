package registry

import (
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"testing"
)

func TestSuggestedClass(t *testing.T) {
	for _, tc := range []struct{ def, want string }{
		{`{}`, ClassDestructive}, {`null`, ClassDestructive}, {`broken`, ClassDestructive},
		{`{"annotations":null}`, ClassDestructive}, {`{"annotations":42}`, ClassDestructive},
		{`{"annotations":{"readOnlyHint":true}}`, ClassRead},
		{`{"annotations":{"readOnlyHint":true,"destructiveHint":true}}`, ClassRead},
		{`{"annotations":{"readOnlyHint":true,"destructiveHint":false}}`, ClassRead},
		{`{"annotations":{"readOnlyHint":false,"destructiveHint":true}}`, ClassDestructive},
		{`{"annotations":{"readOnlyHint":false,"destructiveHint":false}}`, ClassWrite},
		{`{"annotations":{"readOnlyHint":false}}`, ClassDestructive},
		{`{"annotations":{"destructiveHint":false}}`, ClassWrite},
		{`{"annotations":{"destructiveHint":true}}`, ClassDestructive},
		{`{"annotations":{"destructiveHint":null}}`, ClassDestructive},
		{`{"annotations":{"destructiveHint":"false"}}`, ClassDestructive},
		{`{"annotations":{"readOnlyHint":"true","destructiveHint":false}}`, ClassWrite},
		{`{"annotations":{"readOnlyHint":true,"destructiveHint":"invalid"}}`, ClassRead},
		{`{"annotations":{"readOnlyHint":1}}`, ClassDestructive},
	} {
		if got := SuggestedClass([]byte(tc.def)); got != tc.want {
			t.Errorf("%s: %s, want %s", tc.def, got, tc.want)
		}
	}
}

func TestClassDriftAndRank(t *testing.T) {
	read, write, destructive := ClassRead, ClassWrite, ClassDestructive
	for _, tc := range []struct {
		kind  string
		class *string
		want  bool
	}{
		{"tool", nil, false}, {"tool", &read, false}, {"tool", &write, true}, {"tool", &destructive, true}, {"prompt", &write, false},
	} {
		c := dbgen.McpCapability{Kind: tc.kind, ToolClass: tc.class, Definition: []byte(`{"annotations":{"readOnlyHint":true}}`)}
		if got := ClassDrift(c); got != tc.want {
			t.Errorf("drift(%s, %v)=%v", tc.kind, tc.class, got)
		}
	}
	if classRank(nil) != classRank(&destructive) || classRank(nil) <= classRank(&write) || classRank(&write) <= classRank(&read) {
		t.Fatal("unclassified must rank conservatively")
	}
}

func TestReviewDigestToolClasses(t *testing.T) {
	sv := dbgen.McpServer{URL: "https://example.org/mcp"}
	seen := map[string]bool{}
	for _, class := range []*string{nil, ptr(ClassRead), ptr(ClassWrite), ptr(ClassDestructive)} {
		ref := CapabilityRefOf(sv, "tool", "x", "fingerprint", nil, class)
		digest := ReviewDigest(sv, []CapabilityRef{ref})
		if seen[digest] {
			t.Fatal("class does not change digest")
		}
		seen[digest] = true
	}
	a := CapabilityRefOf(sv, "prompt", "x", "fingerprint", nil, nil)
	b := a
	b.ToolClass = ptr(ClassRead)
	if ReviewDigest(sv, []CapabilityRef{a}) != ReviewDigest(sv, []CapabilityRef{b}) {
		t.Fatal("non-tool class must not affect digest")
	}
}
