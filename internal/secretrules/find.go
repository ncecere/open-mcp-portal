// Package secretrules owns the shared capture rules and the separate detect
// profile. It does not run a scanner or make safety decisions.
package secretrules

import (
	"strings"
	"unicode"
)

// MaxFindCount is the saturating per-rule count. Findings have fixed catalog
// identifiers and at most this count, never input-derived metadata.
const MaxFindCount = 100000

// Finding contains only a catalog identifier and a count. No finding is not a
// safety verdict. This text primitive does not establish scan completeness.
type Finding struct {
	RuleID string
	Count  int
}

// DetectProfile is separate from redaction: changing it cannot change Redact.
// Minimum lengths apply to token payloads, not their provider prefixes.
// Sensitive-key names and admin redaction patterns are deliberately not
// detectors. JSON traversal, severity and scan budgets belong to a later slice.
type DetectProfile struct {
	BearerMinLength      int
	GoogleOAuthMinLength int
	SuppressPlaceholders bool
}

// DefaultDetectProfile returns independent profile data. These initial
// thresholds are heuristics, not measured enforcement gates.
func DefaultDetectProfile() DetectProfile {
	return DetectProfile{BearerMinLength: 20, GoogleOAuthMinLength: 20, SuppressPlaceholders: true}
}

// Find examines text using the default detection profile and known exact
// values (including their encoded forms). It never returns matching text.
func (r *Redactor) Find(text string) []Finding {
	return r.FindWithProfile(text, DefaultDetectProfile())
}

// FindWithProfile examines each rule independently, so overlapping rules may
// both count. Results follow catalog order; exact values are counted last,
// longest first without overlapping each other. Admin patterns are excluded.
func (r *Redactor) FindWithProfile(text string, profile DetectProfile) []Finding {
	var out []Finding
	for _, rule := range BuiltInRules {
		count := 0
		rest := text
		consumed := 0
		for count < MaxFindCount {
			loc := rule.re.FindStringIndex(rest)
			if loc == nil {
				break
			}
			match := rest[loc[0]:loc[1]]
			payload := detectPayload(rule.Name, match)
			accept := !profile.SuppressPlaceholders || (!placeholder(match) && !placeholder(payload))
			switch rule.Name {
			case "bearer":
				start := consumed + loc[0]
				prefix := strings.TrimSpace(text[:start])
				authorization := len(prefix) >= len("authorization:") && strings.EqualFold(prefix[len(prefix)-len("authorization:"):], "authorization:")
				accept = accept && (authorization || (len(payload) >= profile.BearerMinLength && !lettersOnly(payload)))
			case "google":
				if strings.HasPrefix(match, "ya29.") {
					accept = accept && len(payload) >= profile.GoogleOAuthMinLength
				}
			}
			if accept {
				count++
			}
			consumed += loc[1]
			rest = rest[loc[1]:]
		}
		if count > 0 {
			out = append(out, Finding{RuleID: "secret." + rule.Name, Count: count})
		}
	}
	// Reuse the exact-value normalization/order, not redaction output.
	count := 0
	remaining := []string{text}
	for _, secret := range r.secrets {
		var next []string
		for _, part := range remaining {
			n := strings.Count(part, secret)
			count = min(MaxFindCount, count+n)
			if count == MaxFindCount {
				break
			}
			if n == 0 {
				next = append(next, part)
			} else {
				// Keep boundaries rather than inserting a synthetic marker:
				// a marker could itself match another known exact value.
				next = append(next, strings.Split(part, secret)...)
			}
		}
		if count == MaxFindCount {
			break
		}
		remaining = next
	}
	if count > 0 {
		out = append(out, Finding{RuleID: "secret." + RuleCallSecrets, Count: count})
	}
	return out
}

func detectPayload(name, match string) string {
	switch name {
	case "bearer":
		return strings.TrimSpace(match[len("bearer"):])
	case "google":
		if strings.HasPrefix(match, "ya29.") {
			return match[len("ya29."):]
		}
		return strings.TrimPrefix(match, "AIza")
	case "github":
		if strings.HasPrefix(match, "github_pat_") {
			return strings.TrimPrefix(match, "github_pat_")
		}
		return match[len("ghp_"):]
	case "gitlab":
		return match[len("glpat-"):]
	case "slack":
		return match[len("xoxb-"):]
	case "gateway_credentials":
		if i := strings.Index(match, "_"); i >= 0 {
			payload := match[i+1:]
			return strings.TrimPrefix(payload, "sa_")
		}
	case "url_userinfo":
		if i := strings.Index(match, "://"); i >= 0 {
			return strings.TrimSuffix(match[i+3:], "@")
		}
	}
	return match
}

func placeholder(s string) bool {
	lower := strings.ToLower(s)
	if strings.Contains(lower, "example") || strings.Contains(lower, "xxxx") ||
		strings.Contains(lower, "<") || strings.Contains(lower, ">") ||
		lower == "user:password" {
		return true
	}
	if len(s) > 1 && strings.Trim(s, s[:1]) == "" {
		return true
	}
	return false
}

func lettersOnly(s string) bool {
	for _, r := range s {
		if !unicode.IsLetter(r) {
			return false
		}
	}
	return true
}
