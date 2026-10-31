package secretrules

import (
	"encoding/json"
	"fmt"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

func TestFindMetadataAndCounts(t *testing.T) {
	token := "ghp_" + strings.Repeat("aB3z", 9)
	r := NewRedactor(nil)
	got := r.Find(token + " " + token)
	want := []Finding{{RuleID: "secret.github", Count: 2}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("metadata = %+v", got)
	}
	typ := reflect.TypeFor[Finding]()
	if typ.NumField() != 2 || typ.Field(0).Type.Kind() != reflect.String || typ.Field(1).Type.Kind() != reflect.Int {
		t.Fatal("finding shape changed")
	}
	b, _ := json.Marshal(got)
	if strings.Contains(string(b), token) || strings.Contains(fmt.Sprint(got), token) {
		t.Fatal("matched text escaped")
	}
	if got := r.Find(strings.Repeat(token+" ", MaxFindCount+1)); got[0].Count != MaxFindCount {
		t.Fatal("count not bounded")
	}
}

func TestDetectProfileSeparation(t *testing.T) {
	r := NewRedactor(nil)
	negatives := []string{
		"the bearer of this letter", "bearer bonds",
		"Bearer " + strings.Repeat("alphabetic", 3),
		"ghp_" + strings.Repeat("x", 36),
		"glpat-" + strings.Repeat("Z", 24),
		"xoxb-" + strings.Repeat("x", 24),
		"AKIA" + "IOSFODNN7EXAMPLE",
		"postgres://user:password@localhost:5432/db",
		"ya29.short", "password",
	}
	for i, text := range negatives {
		if got := r.Find(text); len(got) != 0 {
			t.Errorf("negative %d: %+v", i, got)
		}
		if i != len(negatives)-1 && r.Text(text).Redactions == 0 {
			t.Errorf("redaction weakened for %d", i)
		}
	}
	positives := []string{
		"Bearer " + strings.Repeat("aB3z", 5),
		"Authorization: Bearer short",
		"ya29." + strings.Repeat("aB3z", 5),
	}
	for i, text := range positives {
		before := r.Text(text)
		if len(r.Find(text)) == 0 {
			t.Errorf("positive %d missing", i)
		}
		profile := DefaultDetectProfile()
		profile.BearerMinLength = 1000
		profile.GoogleOAuthMinLength = 1000
		_ = r.FindWithProfile(text, profile)
		if !reflect.DeepEqual(before, r.Text(text)) {
			t.Fatal("detect affected redaction")
		}
	}
	profile := DefaultDetectProfile()
	profile.SuppressPlaceholders = false
	if len(r.FindWithProfile(negatives[3], profile)) != 1 {
		t.Fatal("placeholder data ignored")
	}
	if len(r.Find(negatives[3])) != 0 {
		t.Fatal("profile leaked into default")
	}
}

func TestFindExactValuesAndPatterns(t *testing.T) {
	secret := "q sentinel&2/x"
	patterns, err := Compile([]Pattern{{Pattern: "CLASSIFIED"}})
	if err != nil {
		t.Fatal(err)
	}
	r := NewRedactor(patterns, secret, "short", "abcdef", "abcdef-long", secret)
	text := strings.Join([]string{secret, url.QueryEscape(secret), strings.ReplaceAll(url.QueryEscape(secret), "+", "%20"), url.PathEscape(secret), "short", "abcdef-long", "CLASSIFIED"}, " ")
	if got := r.Find(text); !reflect.DeepEqual(got, []Finding{{RuleID: "secret.call_secrets", Count: 5}}) {
		t.Fatalf("exact metadata = %+v", got)
	}
	// Overlap with a built-in rule is counted independently, even for placeholders.
	token := "ghp_" + strings.Repeat("x", 36)
	if got := NewRedactor(nil, token).Find(token); !reflect.DeepEqual(got, []Finding{{RuleID: "secret.call_secrets", Count: 1}}) {
		t.Fatal("known exact value suppressed")
	}
}

func TestDocumentEquivalence(t *testing.T) {
	patterns, _ := Compile([]Pattern{{Pattern: "EMP-[0-9]{6}"}})
	current := NewRedactor(patterns, "q sentinel&2/x", "abcdef", "abcdef-long", "short")
	old := legacyNewRedactor(patterns, "q sentinel&2/x", "abcdef", "abcdef-long", "short")
	corpus := []string{
		`{"Password":"p","nested":{"api_key":{"x":1},"Client-Secret":"s","ok":"EMP-123456 and abcdef-long"}}`,
		`{"content":[{"type":"image","data":"QUJDREVGR0g="},{"type":"text","text":"short"}],"resource":{"blob":"AAAAAAAA"}}`,
		`{"inner":"{\"token\":\"abc\",\"n\":1}","echo":"q+sentinel%262%2Fx"}`,
		`{"n":12345678901234567890,"html":"<>&","s":"é"}`,
		"not JSON Bearer abcdefgh", "", "null", "[]", "{} trailing",
		strings.Repeat("é", MaxPartBytes),
	}
	for i, raw := range corpus {
		if got, want := current.Redact([]byte(raw)), Part(old.Redact([]byte(raw))); !reflect.DeepEqual(got, want) {
			t.Fatalf("document %d mismatch", i)
		}
		if got, want := current.Text(raw), Part(old.Text(raw)); !reflect.DeepEqual(got, want) {
			t.Fatalf("text %d mismatch", i)
		}
	}
}

func TestFindBuiltInCoverage(t *testing.T) {
	payload := strings.Repeat("aB3z", 10)
	cases := map[string]string{
		"private_key_pem":     "-----BEGIN RSA PRIVATE KEY-----\n" + payload + "\n-----END RSA PRIVATE KEY-----",
		"bearer":              "Bearer " + payload,
		"jwt":                 "eyJ" + payload + "." + payload + "." + payload,
		"gateway_credentials": "omp_" + payload,
		"github":              "github_pat_" + payload,
		"gitlab":              "glpat-" + payload,
		"slack":               "xoxb-" + payload,
		"google":              "AIza" + strings.Repeat("aB3z", 8) + "aB3",
		"aws_access_key":      "AKIA" + strings.Repeat("AB3Z", 4),
		"url_userinfo":        "postgres://admin:" + payload + "@db",
	}
	if len(cases) != len(BuiltInRules) {
		t.Fatal("update detect coverage for catalog")
	}
	for _, rule := range BuiltInRules {
		t.Run(rule.Name, func(t *testing.T) {
			if got := NewRedactor(nil).Find(cases[rule.Name]); !reflect.DeepEqual(got, []Finding{{RuleID: "secret." + rule.Name, Count: 1}}) {
				t.Fatalf("metadata = %+v", got)
			}
		})
	}
}

func TestDetectMinimumBoundaries(t *testing.T) {
	r := NewRedactor(nil)
	for _, prefix := range []string{"Bearer ", "ya29."} {
		for _, n := range []int{19, 20} {
			text := prefix + strings.Repeat("a", n-1) + "3"
			if got := len(r.Find(text)); (got > 0) != (n == 20) {
				t.Errorf("minimum boundary %d", n)
			}
		}
	}
	// The raw value is short, but its encoded form meets the historical six-byte
	// threshold. Find must share that normalization rather than reinterpret it.
	raw := "a/bc"
	if got := NewRedactor(nil, raw).Find(url.QueryEscape(raw)); !reflect.DeepEqual(got, []Finding{{RuleID: "secret.call_secrets", Count: 1}}) {
		t.Fatal("encoded threshold differs")
	}
}

func TestFindClosedCatalog(t *testing.T) {
	for _, rule := range BuiltInRules {
		id := "secret." + rule.Name
		if len(id) > 64 {
			t.Fatal("identifier not bounded")
		}
		for _, c := range id {
			if !(c >= 'a' && c <= 'z' || c == '_' || c == '.') {
				t.Fatal("identifier not catalog-safe")
			}
		}
	}
}

func TestPlaceholderInsideToken(t *testing.T) {
	for _, token := range []string{
		"github_pat_" + strings.Repeat("aB3z", 6) + "_example_suffix",
		"glpat-" + strings.Repeat("aB3z", 6) + "-EXAMPLE-tail",
		"xoxb-" + strings.Repeat("aB3z", 6) + "-xxxx-tail",
	} {
		if len(NewRedactor(nil).Find(token)) != 0 {
			t.Fatal("embedded placeholder not suppressed")
		}
	}
}

func TestExactFindDoesNotCountSyntheticText(t *testing.T) {
	r := NewRedactor(nil, "abcdef", "\x00bcdef")
	if got := r.Find("abcdefbcdef"); !reflect.DeepEqual(got, []Finding{{RuleID: "secret.call_secrets", Count: 1}}) {
		t.Fatal("synthetic exact match")
	}
	if got := r.Find(strings.Repeat("abcdef ", MaxFindCount+1)); got[0].Count != MaxFindCount {
		t.Fatal("exact count unbounded")
	}
}
