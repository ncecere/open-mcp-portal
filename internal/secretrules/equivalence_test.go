package secretrules

import (
	"reflect"
	"strings"
	"testing"
)

func TestExistingCorpusEquivalence(t *testing.T) {
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
		if old := legacyNewRedactor(nil).Text(sample); !reflect.DeepEqual(Part(old), p) {
			t.Fatalf("%s: legacy mismatch", rule)
		}
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
