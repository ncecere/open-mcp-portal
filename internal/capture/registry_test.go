package capture

import (
	"reflect"
	"strings"
	"testing"

	"github.com/ncecere/open-mcp-portal/internal/secretrules"
)

func TestRegistryCompatibilityWrappers(t *testing.T) {
	patterns, err := Compile([]Pattern{{Pattern: "EMP-[0-9]{6}"}})
	if err != nil {
		t.Fatal(err)
	}
	a, b := NewRedactor(patterns, "known-sentinel"), secretrules.NewRedactor(patterns, "known-sentinel")
	for _, text := range []string{`{"password":"p","text":"EMP-123456 known-sentinel"}`, "Bearer abcdefgh", "ghp_" + strings.Repeat("aB3z", 9), strings.Repeat("é", MaxPartBytes)} {
		if !reflect.DeepEqual(a.Redact([]byte(text)), b.Redact([]byte(text))) || !reflect.DeepEqual(a.Text(text), b.Text(text)) {
			t.Fatal("wrapper differs")
		}
	}
	if !reflect.DeepEqual(BuiltInRules, secretrules.BuiltInRules) || !reflect.DeepEqual(SensitiveKeys, secretrules.SensitiveKeys) {
		t.Fatal("catalog differs")
	}
}
