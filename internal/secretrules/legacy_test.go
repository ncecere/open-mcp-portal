// Frozen base 4100cdc redactor, test-only byte-equivalence oracle.
package secretrules

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

// legacyMaxPartBytes is how much of each part (arguments, result) is kept, after
// redaction.
const legacyMaxPartBytes = 16 << 10

// legacyRedacted replaces every redacted value.
const legacyRedacted = "[REDACTED]"

// legacyRule names that are not built-in string rules.
const (
	legacyRuleSensitiveKeys = "sensitive_keys"
	legacyRuleCallSecrets   = "call_secrets"
)

// legacyRule is a built-in string rule: every match becomes [REDACTED] (or Repl).
type legacyRule struct {
	Name, Description string
	re                *regexp.Regexp
	// repl is the replacement template ("" for legacyRedacted).
	repl string
}

// legacyBuiltInRules always apply, in this order.
var legacyBuiltInRules = []legacyRule{
	{Name: "private_key_pem", Description: "PEM private keys (-----BEGIN ... PRIVATE KEY-----)",
		re: regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|$)`)},
	{Name: "bearer", Description: "Bearer tokens (Bearer <token>)",
		re: regexp.MustCompile(`(?i)\bbearer\s+[A-Za-z0-9\-._~+/]+=*`)},
	{Name: "jwt", Description: "JSON Web Tokens (eyJ...)",
		re: regexp.MustCompile(`\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*`)},
	{Name: "gateway_credentials", Description: "Open MCP Portal keys and tokens (omp_, omp_sa_, ompat_, omprt_, ompac_, the automation tokens ompadm_ and omppub_, webhook secrets ompwhs_, and the earlier omcp_, omcp_sa_, omat_, omrt_, omac_)",
		re: regexp.MustCompile(`\b(?:omp_sa_|omp_|ompat_|omprt_|ompac_|ompadm_|omppub_|ompwhs_|omcp_sa_|omcp_|omat_|omrt_|omac_)[A-Za-z0-9_-]{16,}`)},
	{Name: "github", Description: "GitHub tokens (ghp_, gho_, ghu_, ghs_, ghr_, github_pat_)",
		re: regexp.MustCompile(`\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})`)},
	{Name: "gitlab", Description: "GitLab personal access tokens (glpat-)",
		re: regexp.MustCompile(`\bglpat-[A-Za-z0-9_-]{20,}`)},
	{Name: "slack", Description: "Slack tokens (xoxa-, xoxb-, xoxp-, xoxr-, xoxs-)",
		re: regexp.MustCompile(`\bxox[abprs]-[A-Za-z0-9-]{10,}`)},
	{Name: "google", Description: "Google OAuth access tokens (ya29.) and API keys (AIza)",
		re: regexp.MustCompile(`\bya29\.[A-Za-z0-9_.-]+|\bAIza[0-9A-Za-z_-]{35}`)},
	{Name: "aws_access_key", Description: "AWS access key IDs (AKIA, ASIA)",
		re: regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`)},
	{Name: "url_userinfo", Description: "Passwords in URLs (scheme://user:password@)",
		re: regexp.MustCompile(`\b([a-zA-Z][a-zA-Z0-9+.-]*://)[^\s/@:]+:[^\s/@]+@`), repl: "${1}" + legacyRedacted + "@"},
}

// legacySensitiveKeys are normalised JSON member names (lower case, without - and
// _) whose values are always replaced.
var legacySensitiveKeys = []string{"password", "passwd", "secret", "token", "accesstoken", "refreshtoken", "idtoken", "apikey",
	"authorization", "cookie", "setcookie", "clientsecret", "privatekey", "sessionid"}

func legacynormaliseKey(k string) string {
	return strings.NewReplacer("-", "", "_", "").Replace(strings.ToLower(k))
}

// legacyPattern is an admin pattern: an RE2 expression and a note.
type legacyPattern struct {
	Pattern string `json:"pattern"`
	Note    string `json:"note,omitempty"`
}

// Limits of admin patterns.
const (
	legacyMaxPatterns      = 50
	legacyMaxPatternLength = 500
	legacyMaxNoteLength    = 200
)

// legacyPatternError says which admin pattern is invalid and why: syntax,
// too_long, too_many or matches_empty.
type legacyPatternError struct {
	Index  int
	Reason string
	Detail string
}

func (e *legacyPatternError) Error() string {
	return fmt.Sprintf("pattern %d: %s", e.Index, e.Detail)
}

// legacyCompile checks and compiles admin patterns.
func legacyCompile(ps []legacyPattern) ([]*regexp.Regexp, *legacyPatternError) {
	if len(ps) > legacyMaxPatterns {
		return nil, &legacyPatternError{Index: legacyMaxPatterns, Reason: "too_many", Detail: fmt.Sprintf("at most %d patterns", legacyMaxPatterns)}
	}
	out := make([]*regexp.Regexp, len(ps))
	for i, p := range ps {
		if p.Pattern == "" || len(p.Pattern) > legacyMaxPatternLength || utf8.RuneCountInString(p.Note) > legacyMaxNoteLength {
			return nil, &legacyPatternError{Index: i, Reason: "too_long",
				Detail: fmt.Sprintf("a pattern is 1-%d characters and a note at most %d", legacyMaxPatternLength, legacyMaxNoteLength)}
		}
		re, err := regexp.Compile(p.Pattern)
		if err != nil {
			return nil, &legacyPatternError{Index: i, Reason: "syntax", Detail: "not a valid RE2 expression: " + err.Error()}
		}
		if re.MatchString("") {
			return nil, &legacyPatternError{Index: i, Reason: "matches_empty", Detail: "the pattern matches the empty string"}
		}
		out[i] = re
	}
	return out, nil
}

// legacyRedactor applies the rules to one call's parts.
type legacyRedactor struct {
	patterns []*regexp.Regexp
	// secrets are exact values the gateway handled for this call (identity
	// JWT, provider token, every part of the server's own credential).
	secrets []string
}

// legacyNewRedactor returns a redactor with compiled admin patterns and the
// call's secrets (values shorter than 6 characters are ignored). Each secret
// is also redacted in its URL-encoded forms (a query string or a path shows a
// value that way), so a server's credential in a query part is caught in a URL
// an upstream error or a result echoes.
func legacyNewRedactor(patterns []*regexp.Regexp, secrets ...string) *legacyRedactor {
	r := &legacyRedactor{patterns: patterns}
	add := func(s string) {
		if len(s) >= 6 && !slices.Contains(r.secrets, s) {
			r.secrets = append(r.secrets, s)
		}
	}
	for _, s := range secrets {
		add(s)
		add(url.QueryEscape(s))
		add(strings.ReplaceAll(url.QueryEscape(s), "+", "%20"))
		add(url.PathEscape(s))
	}
	// Longest first, so a value containing another is replaced whole.
	slices.SortFunc(r.secrets, func(a, b string) int { return len(b) - len(a) })
	return r
}

// legacyPart is a redacted, truncated part.
type legacyPart struct {
	Content   string
	Bytes     int64 // size of the redacted JSON before truncation
	Truncated bool
	// Redactions counts replaced values; Rules counts them per rule.
	Redactions int
	Rules      map[string]int
}

// Redact redacts a JSON document (member names and strings) and truncates
// it. A document that is not JSON is treated as one string.
func (r *legacyRedactor) Redact(raw []byte) legacyPart {
	p := legacyPart{Rules: map[string]int{}}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	var out []byte
	if err := dec.Decode(&v); err == nil && !dec.More() {
		v = r.walk(v, &p)
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(v); err == nil {
			out = bytes.TrimRight(buf.Bytes(), "\n")
		}
	}
	if out == nil {
		out = []byte(r.text(string(raw), &p))
	}
	p.Bytes = int64(len(out))
	p.Content, p.Truncated = legacyTruncate(string(out), legacyMaxPartBytes)
	for _, n := range p.Rules {
		p.Redactions += n
	}
	return p
}

// Text redacts plain text (string rules only) and truncates it.
func (r *legacyRedactor) Text(s string) legacyPart {
	p := legacyPart{Rules: map[string]int{}}
	out := r.text(s, &p)
	p.Bytes = int64(len(out))
	p.Content, p.Truncated = legacyTruncate(out, legacyMaxPartBytes)
	for _, n := range p.Rules {
		p.Redactions += n
	}
	return p
}

// legacyTruncate cuts s to at most n bytes at a UTF-8 boundary.
func legacyTruncate(s string, n int) (string, bool) {
	if len(s) <= n {
		return s, false
	}
	cut := n
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut], true
}

func (r *legacyRedactor) walk(v any, p *legacyPart) any {
	switch x := v.(type) {
	case map[string]any:
		binaryItem := false
		if t, ok := x["type"].(string); ok && (t == "image" || t == "audio") {
			binaryItem = true
		}
		for k, val := range x {
			switch {
			case slices.Contains(legacySensitiveKeys, legacynormaliseKey(k)):
				x[k] = legacyRedacted
				p.Rules[legacyRuleSensitiveKeys]++
			case (k == "blob" || (k == "data" && binaryItem)) && legacyisString(val):
				x[k] = fmt.Sprintf("[binary %d bytes]", legacydecodedLen(val.(string)))
			default:
				x[k] = r.walk(val, p)
			}
		}
		return x
	case []any:
		for i := range x {
			x[i] = r.walk(x[i], p)
		}
		return x
	case string:
		// JSON inside a string (a server echoing its arguments): its members
		// are redacted by name too.
		if t := strings.TrimSpace(x); len(t) > 1 && (t[0] == '{' || t[0] == '[') {
			dec := json.NewDecoder(strings.NewReader(t))
			dec.UseNumber()
			var inner any
			if dec.Decode(&inner) == nil && !dec.More() {
				var buf bytes.Buffer
				enc := json.NewEncoder(&buf)
				enc.SetEscapeHTML(false)
				if enc.Encode(r.walk(inner, p)) == nil {
					return strings.TrimRight(buf.String(), "\n")
				}
			}
		}
		return r.text(x, p)
	}
	return v
}

func legacyisString(v any) bool { _, ok := v.(string); return ok }

// legacydecodedLen is the size of base64 data (or of the text when it isn't
// base64).
func legacydecodedLen(s string) int {
	s = strings.TrimRight(s, "=")
	n := len(s) * 3 / 4
	return n
}

func (r *legacyRedactor) text(s string, p *legacyPart) string {
	for _, rule := range legacyBuiltInRules {
		s = legacyreplace(s, rule.re, rule.repl, rule.Name, p)
	}
	for i, re := range r.patterns {
		s = legacyreplace(s, re, "", "pattern:"+strconv.Itoa(i), p)
	}
	for _, secret := range r.secrets {
		if n := strings.Count(s, secret); n > 0 {
			s = strings.ReplaceAll(s, secret, legacyRedacted)
			p.Rules[legacyRuleCallSecrets] += n
		}
	}
	return s
}

func legacyreplace(s string, re *regexp.Regexp, repl, name string, p *legacyPart) string {
	n := 0
	out := re.ReplaceAllStringFunc(s, func(m string) string {
		n++
		if repl == "" {
			return legacyRedacted
		}
		return re.ReplaceAllString(m, repl)
	})
	if n > 0 {
		p.Rules[name] += n
	}
	return out
}
