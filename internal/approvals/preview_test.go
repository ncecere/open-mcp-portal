package approvals

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestPreviewRedactsBeforeTruncation(t *testing.T) {
	s := &Service{patterns: func(context.Context) ([]*regexp.Regexp, error) {
		return []*regexp.Regexp{regexp.MustCompile(`CLASSIFIED-[A-Z]+`)}, nil
	}}
	raw, _ := json.Marshal(map[string]any{
		"password": "password-sentinel",
		"ordinary": "short CLASSIFIED-SENTINEL long-secret-sentinel",
		strings.Repeat("z", 16378) + "long-secret-sentinel": "also-private",
		"large": strings.Repeat("é", 9000) + "long-secret-sentinel",
	})
	clean, truncated, redacted, e := s.capturePreview(context.Background(), raw, []string{"short", "long-secret-sentinel"})
	if e != nil {
		t.Fatal(e)
	}
	if !truncated || !redacted || len(clean) > 16<<10 || !utf8.ValidString(clean) {
		t.Fatalf("preview flags/size: len=%d truncated=%t redacted=%t err=%v", len(clean), truncated, redacted, e)
	}
	for _, secret := range []string{"password-sentinel", "long-secret-sentinel", "CLASSIFIED-SENTINEL", "short"} {
		if strings.Contains(clean, secret) {
			t.Fatalf("preview leaked %q", secret)
		}
	}
}
func TestPreviewKnownSecretCannotBreakNestedJSONRedaction(t *testing.T) {
	s := &Service{}
	raw, _ := json.Marshal(map[string]string{"nested": `{"ordinary":"quoted","password":"private-inner-sentinel"}`})
	clean, _, redacted, e := s.capturePreview(context.Background(), raw, []string{`"quoted"`})
	if e != nil || !redacted || strings.Contains(clean, "private-inner-sentinel") {
		t.Fatalf("known credential corrupted nested structural redaction: %q %v", clean, e)
	}
}
func TestPreviewPatternFailureIsClosed(t *testing.T) {
	s := &Service{patterns: func(context.Context) ([]*regexp.Regexp, error) { return nil, errors.New("private loader internals") }}
	_, _, _, e := s.capturePreview(context.Background(), []byte(`{"password":"secret"}`), nil)
	if !errors.Is(e, ErrUnavailable) || strings.Contains(e.Error(), "internals") {
		t.Fatalf("pattern loader did not fail safely: %v", e)
	}
	s.patterns = func(context.Context) ([]*regexp.Regexp, error) { return []*regexp.Regexp{nil}, nil }
	if _, _, _, e = s.capturePreview(context.Background(), []byte(`{}`), nil); !errors.Is(e, ErrUnavailable) {
		t.Fatal("nil redactor pattern accepted")
	}
}
