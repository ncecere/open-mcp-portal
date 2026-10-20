package capture

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/ncecere/open-mcp-portal/internal/apperr"
	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/calls"
)

func TestBuiltInRules(t *testing.T) {
	cases := map[string]string{
		"bearer": "Authorization was Bearer abc.DEF-123_xyz~ then",
		"jwt":    "token eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiIxMjM0In0.c2lnbmF0dXJl here",
		"gateway_credentials": "key omp_" + strings.Repeat("A", 43) + " and omp_sa_" + strings.Repeat("b", 43) + " ompat_" + strings.Repeat("c", 43) +
			" omprt_" + strings.Repeat("d", 43) + " ompac_" + strings.Repeat("e", 43) +
			" ompadm_" + strings.Repeat("k", 43) + " omppub_" + strings.Repeat("l", 43) + " ompwhs_" + strings.Repeat("m", 43) +
			// Keys and tokens from before the rename to Open MCP Portal.
			" omcp_" + strings.Repeat("F", 43) + " omcp_sa_" + strings.Repeat("g", 43) + " omat_" + strings.Repeat("h", 43) +
			" omrt_" + strings.Repeat("i", 43) + " omac_" + strings.Repeat("j", 43),
		"github":          "ghp_" + strings.Repeat("a", 36) + " github_pat_" + strings.Repeat("B", 30),
		"gitlab":          "glpat-" + strings.Repeat("x", 20),
		"slack":           "xoxb-1234567890-abcdefghij",
		"google":          "ya29.a0AfH6SMBx and AIza" + strings.Repeat("Z", 35),
		"aws_access_key":  "AKIAABCDEFGHIJKLMNOP",
		"private_key_pem": "-----BEGIN RSA PRIVATE KEY-----\nMIIBOg\n-----END RSA PRIVATE KEY-----",
		"url_userinfo":    "postgres://admin:hunter2@db.example.com/x",
	}
	secrets := map[string][]string{
		"bearer": {"abc.DEF-123_xyz~"},
		"jwt":    {"eyJhbGciOiJFUzI1NiJ9"},
		"gateway_credentials": {"AAAAAAAAAAAAAAAA", "bbbbbbbbbbbbbbbb", "cccccccccccccccc", "dddddddddddddddd", "eeeeeeeeeeeeeeee",
			"kkkkkkkkkkkkkkkk", "llllllllllllllll", "mmmmmmmmmmmmmmmm", "FFFFFFFFFFFFFFFF", "gggggggggggggggg", "hhhhhhhhhhhhhhhh", "iiiiiiiiiiiiiiii", "jjjjjjjjjjjjjjjj"},
		"github":          {"aaaaaaaaaaaaaaaaaaaa", "BBBBBBBBBBBBBBBBBBBB"},
		"gitlab":          {"glpat-xxxx"},
		"slack":           {"abcdefghij"},
		"google":          {"a0AfH6SMBx", "ZZZZZZZZZZZZ"},
		"aws_access_key":  {"AKIAABCDEFGHIJKLMNOP"},
		"private_key_pem": {"MIIBOg"},
		"url_userinfo":    {"hunter2", "admin:"},
	}
	for rule, sample := range cases {
		p := NewRedactor(nil).Text(sample)
		if p.Rules[rule] == 0 {
			t.Errorf("%s: no match in %q (rules %v, out %q)", rule, sample, p.Rules, p.Content)
		}
		for _, s := range secrets[rule] {
			if strings.Contains(p.Content, s) {
				t.Errorf("%s: %q still in %q", rule, s, p.Content)
			}
		}
	}
	if p := NewRedactor(nil).Text("postgres://admin:hunter2@db"); p.Content != "postgres://[REDACTED]@db" {
		t.Errorf("url_userinfo = %q", p.Content)
	}
	if p := NewRedactor(nil).Text("an ordinary sentence about tokens and keys"); p.Redactions != 0 {
		t.Errorf("false positive: %+v", p)
	}
}

func TestSensitiveKeysPatternsSecretsAndBinary(t *testing.T) {
	patterns, perr := Compile([]Pattern{{Pattern: `EMP-[0-9]{6}`}})
	if perr != nil {
		t.Fatal(perr)
	}
	r := NewRedactor(patterns, "the-identity-jwt-value", "short")
	in := `{"Password":"p","nested":{"api_key":{"x":1},"Client-Secret":"s","ok":"EMP-123456 and the-identity-jwt-value"},
		"content":[{"type":"image","data":"QUJDREVGR0g=","mimeType":"image/png"},{"type":"text","text":"short"}],
		"resource":{"uri":"x","blob":"AAAAAAAA"}}`
	p := r.Redact([]byte(in))
	var out map[string]any
	if err := json.Unmarshal([]byte(p.Content), &out); err != nil {
		t.Fatalf("not JSON: %v %s", err, p.Content)
	}
	if out["Password"] != Redacted {
		t.Errorf("Password = %v", out["Password"])
	}
	nested := out["nested"].(map[string]any)
	if nested["api_key"] != Redacted || nested["Client-Secret"] != Redacted || nested["ok"] != "[REDACTED] and [REDACTED]" {
		t.Errorf("nested = %v", nested)
	}
	content := out["content"].([]any)
	if img := content[0].(map[string]any); img["data"] != "[binary 8 bytes]" || img["mimeType"] != "image/png" {
		t.Errorf("image = %v", img)
	}
	if txt := content[1].(map[string]any); txt["text"] != "short" {
		t.Errorf("short values are not call secrets: %v", txt)
	}
	if res := out["resource"].(map[string]any); res["blob"] != "[binary 6 bytes]" {
		t.Errorf("blob = %v", res)
	}
	if p.Rules[RuleSensitiveKeys] != 3 || p.Rules["pattern:0"] != 1 || p.Rules[RuleCallSecrets] != 1 || p.Redactions != 5 {
		t.Errorf("rules = %v, redactions %d", p.Rules, p.Redactions)
	}
}

func TestTruncationAtUTF8Boundary(t *testing.T) {
	text := strings.Repeat("é", MaxPartBytes) // 2 bytes each
	raw, _ := json.Marshal(map[string]string{"text": "x" + text})
	p := NewRedactor(nil).Redact(raw)
	if !p.Truncated || len(p.Content) > MaxPartBytes || !utf8.ValidString(p.Content) || p.Bytes != int64(len(raw)) {
		t.Fatalf("truncated=%v len=%d valid=%v bytes=%d", p.Truncated, len(p.Content), utf8.ValidString(p.Content), p.Bytes)
	}
	if s, cut := Truncate("abc", 3); s != "abc" || cut {
		t.Fatal("short strings are kept")
	}
}

func TestCompileRefusals(t *testing.T) {
	many := make([]Pattern, MaxPatterns+1)
	for i := range many {
		many[i] = Pattern{Pattern: "x"}
	}
	for name, tc := range map[string]struct {
		ps     []Pattern
		reason string
		index  int
	}{
		"syntax":        {[]Pattern{{Pattern: "ok"}, {Pattern: "("}}, "syntax", 1},
		"too_long":      {[]Pattern{{Pattern: strings.Repeat("a", MaxPatternLength+1)}}, "too_long", 0},
		"empty":         {[]Pattern{{Pattern: ""}}, "too_long", 0},
		"matches_empty": {[]Pattern{{Pattern: "a*"}}, "matches_empty", 0},
		"too_many":      {many, "too_many", MaxPatterns},
	} {
		_, perr := Compile(tc.ps)
		if perr == nil || perr.Reason != tc.reason || perr.Index != tc.index {
			t.Errorf("%s: %+v", name, perr)
		}
	}
}

func TestNotJSONIsText(t *testing.T) {
	p := NewRedactor(nil).Redact([]byte(`password: Bearer abcdefgh`))
	if p.Content != "password: [REDACTED]" || p.Redactions != 1 {
		t.Fatalf("%+v", p)
	}
}

func TestJSONInsideStrings(t *testing.T) {
	p := NewRedactor(nil).Redact([]byte(`{"text":"args={\"password\":\"hunter2\"}","inner":"{\"token\":\"abc\",\"n\":1}"}`))
	if strings.Contains(p.Content, "abc") || p.Rules[RuleSensitiveKeys] != 1 {
		t.Fatalf("%+v", p)
	}
}

func TestOpenRefusesAutomationTokens(t *testing.T) {
	s := &Service{}
	_, err := s.open(context.Background(), authz.Actor{Kind: authz.KindAutomationToken, PlatformRole: authz.PlatformAdmin}, calls.Row{}, uuid.Nil, "admin")
	if e, ok := apperr.As(err); !ok || e.Code != "token_not_allowed" {
		t.Errorf("err = %v", err)
	}
}

// Several call secrets at once (the parts of a server's own credential), each
// in its raw and URL-encoded forms, inside text and inside JSON strings; short
// values are still ignored.
func TestRedactorCallSecretsInEncodedForms(t *testing.T) {
	r := NewRedactor(nil, "tenant-sentinel-1", "q sentinel&2/x", "Basic-b64-sentinel==", "abc")
	in := `{"echo":"GET /mcp?key=q+sentinel%262%2Fx&b=1 and key=q%20sentinel%262%2Fx; X-Tenant: tenant-sentinel-1; Basic-b64-sentinel== q sentinel&2/x abc"}`
	p := r.Redact([]byte(in))
	for _, secret := range []string{"tenant-sentinel-1", "sentinel%262", "sentinel&2", "q+sentinel", "Basic-b64-sentinel"} {
		if strings.Contains(p.Content, secret) {
			t.Errorf("%q survived: %s", secret, p.Content)
		}
	}
	if !strings.Contains(p.Content, "abc") {
		t.Errorf("a short value was redacted: %s", p.Content)
	}
	if p.Rules[RuleCallSecrets] != 5 {
		t.Errorf("rules = %v", p.Rules)
	}
}
