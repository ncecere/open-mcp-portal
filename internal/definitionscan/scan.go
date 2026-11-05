// Package definitionscan implements bounded, local, detection-only definition checks.
// Findings contain no input text. No result is a safety verdict.
package definitionscan

import (
	"context"
	"encoding/json"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/ncecere/open-mcp-portal/internal/secretrules"
	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
)

const Version = "v1"
const MaxBytes = 64 << 10
const MaxFindings = 128

type Rule struct {
	ID          string `json:"id"`
	Group       string `json:"group"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
}
type Finding struct {
	RuleID   string `json:"ruleId"`
	Severity string `json:"severity"`
	Count    int    `json:"count"`
	Location string `json:"location"`
}
type Result struct {
	Status         string    `json:"status"`
	RulesetVersion string    `json:"rulesetVersion"`
	Reason         string    `json:"reason,omitempty"`
	Findings       []Finding `json:"findings"`
}

var phrases = []struct{ id, severity, pattern string }{
	{"override_instructions", "medium", `\b(ignore|disregard|forget) (all |any |the |previous |prior |above )*instructions\b|\bnew instructions\b|\byou must now\b`},
	{"concealment", "high", `\bdo not (tell|mention|reveal|inform) (the )?user\b|\bwithout (telling|informing) the user\b|this could upset the user`},
	{"sensitive_path", "low", `~/\.ssh|\bid_rsa\b|\.env\b|mcp\.json|/etc/passwd|\.aws/credentials|\.config/gcloud`},
	{"pseudo_tag", "medium", `<important>|<system>|\[system\]|<instructions>`},
	{"precondition", "info", `before using this tool, (you must|first)|always call [a-z0-9_.-]+ first`},
	{"cross_tool_reference", "info", `\binstead of\b|\bwhen [a-z0-9_]+__[a-z0-9_]+ is (called|used)\b`},
	{"parameter_sink", "low", `\b(conversation history|file contents|credentials|sidenote)\b`},
	{"external_url", "info", `https?://[^\s<>]+`},
	{"encoded_blob", "info", `\b[A-Za-z0-9+/]{200,}={0,2}\b|\b[0-9a-f]{200,}\b`},
}
var compiled = func() []*regexp.Regexp {
	var out []*regexp.Regexp
	for _, p := range phrases {
		out = append(out, regexp.MustCompile(p.pattern))
	}
	return out
}()

var ruleCatalog = buildCatalog()

func Catalog() []Rule { return append([]Rule(nil), ruleCatalog...) }
func buildCatalog() []Rule {
	var out []Rule
	for _, r := range secretrules.BuiltInRules {
		sev := "high"
		if r.Name == "jwt" {
			sev = "low"
		}
		out = append(out, Rule{"secret." + r.Name, "secret", sev, r.Description})
	}
	for _, p := range phrases {
		out = append(out, Rule{"poison." + p.id, "poison", p.severity, "English lexical heuristic: " + p.id})
	}
	for _, r := range []struct{ id, sev string }{{"tag_chars", "high"}, {"bidi_override", "high"}, {"bidi_isolate_unbalanced", "medium"}, {"bidi_mark", "info"}, {"invisible", "medium"}, {"joiner", "info"}, {"variation_selector", "medium"}, {"control", "medium"}, {"private_use", "low"}, {"mixed_script_name", "medium"}, {"confusable_name", "medium"}} {
		out = append(out, Rule{"unicode." + r.id, "unicode", r.sev, "Unicode heuristic: " + r.id})
	}
	out = append(out, Rule{"length.description", "length", "info", "Description exceeds 2000 characters"}, Rule{"length.schema_text", "length", "low", "Schema string exceeds 1000 characters"})
	return out
}
func KnownRule(id string) bool {
	for _, r := range ruleCatalog {
		if r.ID == id {
			return true
		}
	}
	return false
}

// Scan has no goroutines, network, mutable shared state or content-bearing errors.
func Scan(ctx context.Context, raw []byte) Result { return ScanOrigin(ctx, raw, "") }

func ScanOrigin(ctx context.Context, raw []byte, origin string) Result {
	return scan(ctx, raw, origin, nil)
}
func scan(ctx context.Context, raw []byte, origin string, testRule func(string)) (out Result) {
	out = Result{Status: "scanned", RulesetVersion: Version, Findings: []Finding{}}
	defer func() {
		if recover() != nil {
			out.Status = "incomplete"
			out.Reason = "panic"
		}
	}()
	incomplete := func(reason string) { out.Status = "incomplete"; out.Reason = reason }
	if len(raw) > MaxBytes {
		incomplete("size")
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 25*time.Millisecond)
	defer cancel()
	if ctx.Err() != nil {
		incomplete("budget")
		return
	}
	var root any
	if json.Unmarshal(raw, &root) != nil {
		incomplete("invalid_json")
		return
	}
	redactor := secretrules.NewRedactor(nil)
	add := func(id, sev, ptr string, n int) {
		if len(ptr) > 200 {
			ptr = ptr[:strings.LastIndex(ptr[:200], "/")]
		}
		if n == 0 {
			return
		}
		if len(out.Findings) >= MaxFindings {
			incomplete("size")
			return
		}
		out.Findings = append(out.Findings, Finding{id, sev, min(n, 100000), ptr})
	}
	var walk func(any, string, string, int)
	check := func(text, ptr, key string) {
		if testRule != nil {
			testRule(text)
		}
		if ctx.Err() != nil {
			incomplete("budget")
			return
		}
		if secretCandidate(text) {
			for _, f := range redactor.Find(text) {
				sev := "high"
				if f.RuleID == "secret.jwt" {
					sev = "low"
				}
				add(f.RuleID, sev, ptr, f.Count)
			}
		}
		unicodeFind(text, key, func(id, sev string, n int) { add("unicode."+id, sev, ptr, n) })
		normalized := normalizePhrasing(text)
		for i, p := range phrases {
			if ctx.Err() != nil {
				incomplete("budget")
				return
			}
			if !phraseCandidate(p.id, normalized) {
				continue
			}
			if p.id == "external_url" {
				own, _ := url.Parse(origin)
				n := 0
				if key == "description" {
					for _, link := range compiled[i].FindAllString(normalized, 128) {
						u, e := url.Parse(link)
						if e == nil && own != nil && !strings.EqualFold(u.Host, own.Host) {
							n++
						}
					}
				}
				add("poison.external_url", "info", ptr, n)
				continue
			}
			n := len(compiled[i].FindAllStringIndex(normalized, 100000))
			sev := p.severity
			if p.id == "sensitive_path" && regexp.MustCompile(`\b(read|send|upload|copy|open)\b`).MatchString(normalized) {
				sev = "high"
			}
			add("poison."+p.id, sev, ptr, n)
		}
		n := utf8.RuneCountInString(text)
		if key == "description" && n > 2000 {
			add("length.description", "info", ptr, 1)
		}
		if (strings.Contains(ptr, "/inputSchema/") || strings.Contains(ptr, "/outputSchema/") || strings.Contains(ptr, "/arguments/")) && (key == "description" || key == "default" || key == "enum") && n > 1000 {
			add("length.schema_text", "low", ptr, 1)
		}
	}
	walk = func(v any, ptr, key string, depth int) {
		if ctx.Err() != nil {
			incomplete("budget")
			return
		}
		if depth > 32 {
			incomplete("depth")
			return
		}
		switch v := v.(type) {
		case string:
			check(v, ptr, key)
		case []any:
			for i, x := range v {
				walk(x, ptr+"/"+strconv.Itoa(i), key, depth+1)
			}
		case map[string]any:
			keys := make([]string, 0, len(v))
			for k := range v {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for i, k := range keys {
				// Arbitrary schema keys can contain secrets: use a positional marker rather
				// than reflecting attacker-controlled member names into evidence.
				part := k
				switch k {
				case "name", "title", "description", "inputSchema", "outputSchema", "properties", "items", "type", "default", "enum", "arguments", "annotations":
				default:
					part = "@" + strconv.Itoa(i)
				}
				p := ptr + "/" + part
				check(k, p, "name")
				walk(v[k], p, k, depth+1)
			}
		}
	}
	walk(root, "", "", 0)
	if ctx.Err() != nil {
		incomplete("budget")
	}
	return
}

func ascii(r rune) bool { return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' }
func unicodeFind(s, key string, add func(string, string, int)) {
	asciiOnly := true
	control := 0
	for i := 0; i < len(s); i++ {
		if s[i] >= 128 {
			asciiOnly = false
			break
		}
		if s[i] < 32 && s[i] != '\t' && s[i] != '\n' && s[i] != '\r' || s[i] == 127 {
			control++
		}
	}
	if asciiOnly {
		add("control", "medium", control)
		return
	}
	rs := []rune(s)
	counts := map[string]int{}
	isolate := 0
	for i, r := range rs {
		between := i > 0 && i+1 < len(rs) && ascii(rs[i-1]) && ascii(rs[i+1])
		switch {
		case r >= 0xe0000 && r <= 0xe007f:
			// Ignore a complete emoji tag sequence after the black-flag base.
			start := i
			for start > 0 && rs[start-1] >= 0xe0000 && rs[start-1] <= 0xe007f {
				start--
			}
			end := i
			for end+1 < len(rs) && rs[end+1] >= 0xe0000 && rs[end+1] <= 0xe007f {
				end++
			}
			if !(start > 0 && rs[start-1] == 0x1f3f4 && rs[end] == 0xe007f) {
				counts["tag_chars"]++
			}
		case r >= 0x202a && r <= 0x202e:
			counts["bidi_override"]++
		case r >= 0x2066 && r <= 0x2068:
			isolate++
		case r == 0x2069:
			if isolate == 0 {
				counts["bidi_isolate_unbalanced"]++
			} else {
				isolate--
			}
		case r == 0x200e || r == 0x200f || r == 0x61c:
			counts["bidi_mark"]++
		case r == 0x200d || r == 0x200c:
			if between {
				add("joiner", "medium", 1)
			} else {
				counts["joiner"]++
			}
		case payloadVariationSelector(r):
			if i == 0 || payloadVariationSelector(rs[i-1]) || rs[i-1] < 0x2300 {
				counts["variation_selector"]++
			}
		case r == 0x200b || r == 0x2060 || r == 0xfeff || r == 0xad || r == 0x180e || r == 0x34f:
			if between || i > 1 && invisible(rs[i-1]) && invisible(rs[i-2]) {
				counts["invisible"]++
			}
		case unicode.IsControl(r) && r != '\t' && r != '\n' && r != '\r':
			counts["control"]++
		case unicode.Is(unicode.Co, r) || r >= 0xfdd0 && r <= 0xfdef || r&0xffff >= 0xfffe:
			counts["private_use"]++
		}
	}
	counts["bidi_isolate_unbalanced"] += isolate
	if key == "name" && mixedScript(s) {
		counts["mixed_script_name"]++
	}

	for _, r := range ruleCatalog {
		if r.Group == "unicode" {
			add(strings.TrimPrefix(r.ID, "unicode."), r.Severity, counts[strings.TrimPrefix(r.ID, "unicode.")])
		}
	}
}

func secretCandidate(s string) bool {
	lower := strings.ToLower(s)
	for _, prefix := range []string{"-----BEGIN ", "eyJ", "om", "xox", "gh", "glpat-", "ya29.", "AIza", "AKIA", "ASIA", "://"} {
		if strings.Contains(s, prefix) {
			return true
		}
	}
	return strings.Contains(lower, "bearer") && (strings.Contains(lower, "authorization:") || possibleBearer(lower))
}
func phraseCandidate(id, s string) bool {
	switch id {
	case "override_instructions":
		return strings.Contains(s, "instructions") || strings.Contains(s, "you must now")
	case "concealment":
		return strings.Contains(s, "user")
	case "sensitive_path":
		return strings.ContainsAny(s, "./_")
	case "pseudo_tag":
		return strings.ContainsAny(s, "<[")
	case "precondition":
		return strings.Contains(s, "before") || strings.Contains(s, "always call")
	case "cross_tool_reference":
		return strings.Contains(s, "instead of") || strings.Contains(s, "__")
	case "parameter_sink":
		return strings.Contains(s, "history") || strings.Contains(s, "contents") || strings.Contains(s, "credentials") || strings.Contains(s, "sidenote")
	case "external_url":
		return strings.Contains(s, "://")
	case "encoded_blob":
		run := 0
		for _, r := range s {
			if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '+' || r == '/' {
				run++
				if run >= 200 {
					return true
				}
			} else {
				run = 0
			}
		}
		return false
	}
	return true
}

func invisible(r rune) bool {
	return r == 0x200b || r == 0x2060 || r == 0xfeff || r == 0xad || r == 0x180e || r == 0x34f
}

func normalizePhrasing(text string) string {
	text = cases.Fold().String(norm.NFKC.String(text))
	var out strings.Builder
	out.Grow(len(text))
	space := false
	for _, r := range text {
		if unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Variation_Selector, r) || unicode.Is(unicode.Other_Default_Ignorable_Code_Point, r) {
			continue
		}
		if unicode.IsSpace(r) {
			space = out.Len() > 0
			continue
		}
		if space {
			out.WriteByte(' ')
			space = false
		}
		out.WriteRune(r)
	}
	return out.String()
}

// This is deliberately a superset prefilter. Find owns payload validation,
// including padding in its minimum-length calculation.
func possibleBearer(lower string) bool {
	for {
		i := strings.Index(lower, "bearer")
		if i < 0 {
			return false
		}
		lower = lower[i+6:]
		if len(lower) == 0 || !unicode.IsSpace(rune(lower[0])) {
			continue
		}
		start := 0
		for start < len(lower) && unicode.IsSpace(rune(lower[start])) {
			start++
		}
		end := start
		for end < len(lower) && !unicode.IsSpace(rune(lower[end])) {
			end++
			if end-start >= 20 {
				return true
			}
		}
	}
}

func payloadVariationSelector(r rune) bool {
	return r >= 0xfe00 && r <= 0xfe0f || r >= 0xe0100 && r <= 0xe01ef
}
