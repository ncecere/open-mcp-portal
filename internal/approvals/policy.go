package approvals

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/ncecere/open-mcp-portal/internal/apperr"
)

// NormalizeRule validates a complete replacement without silently repairing
// ambiguous selectors. A group name is exact and case-sensitive, not trimmed.
func NormalizeRule(in RuleInput) (RuleInput, error) {
	bad := func() (RuleInput, error) {
		return RuleInput{}, apperr.New(http.StatusUnprocessableEntity, "invalid_approval_rule", "Enter a name, one valid tool selector, bounded lifetimes and valid human approvers")
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || len(in.Name) > 100 || !safeText(in.Name) || in.TargetID == uuid.Nil || (in.TargetKind != "server" && in.TargetKind != "gateway") {
		return bad()
	}
	if in.PendingMinutes == 0 {
		in.PendingMinutes = 1440
	}
	if in.ValidMinutes == 0 {
		in.ValidMinutes = 15
	}
	if in.PendingMinutes < 5 || in.PendingMinutes > 1440 || in.ValidMinutes < 1 || in.ValidMinutes > 60 {
		return bad()
	}
	if (in.CapabilityID != nil) == (len(in.Classes) != 0) || (in.CapabilityID != nil && *in.CapabilityID == uuid.Nil) {
		return bad()
	}
	if len(in.Classes) > 3 || len(in.Approvers) > 100 {
		return bad()
	}
	classes := make([]string, 0, len(in.Classes))
	for _, c := range in.Classes {
		if c != "read" && c != "write" && c != "destructive" {
			return bad()
		}
		if slices.Contains(classes, c) {
			return bad()
		}
		classes = append(classes, c)
	}
	slices.Sort(classes)
	in.Classes = classes
	seen := map[string]bool{}
	for _, a := range in.Approvers {
		key := ""
		switch a.Kind {
		case "user":
			if a.UserID == nil || *a.UserID == uuid.Nil || a.GroupName != nil {
				return bad()
			}
			key = "user:" + a.UserID.String()
		case "group":
			if a.UserID != nil || a.GroupName == nil || strings.TrimSpace(*a.GroupName) == "" || len(*a.GroupName) > 500 || !safeText(*a.GroupName) {
				return bad()
			}
			key = "group:" + *a.GroupName
		default:
			return bad()
		}
		if seen[key] {
			return bad()
		}
		seen[key] = true
	}
	if in.Approvers == nil {
		in.Approvers = []Selector{}
	}
	return in, nil
}

func safeText(s string) bool {
	return utf8.ValidString(s) && !strings.ContainsFunc(s, func(r rune) bool { return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) })
}

// MatchRule returns the sole highest-priority rule, or fails closed on an
// equal-priority ambiguity. Server class rules outrank gateway-specific rules.
func MatchRule(rules []Rule, b Binding) (*Rule, error) {
	var selected *Rule
	best := 0
	ambiguous := false
	for i := range rules {
		r := &rules[i]
		if !r.Enabled {
			continue
		}
		priority := 0
		switch {
		case r.TargetKind == "server" && r.TargetID == b.ServerID:
			priority = 20
		case r.TargetKind == "gateway" && r.TargetID == b.GatewayID:
			priority = 10
		default:
			continue
		}
		if r.CapabilityID != nil {
			if *r.CapabilityID != b.CapabilityID {
				continue
			}
			priority += 2
		} else {
			class := "destructive"
			if b.ToolClass != nil {
				class = *b.ToolClass
			}
			if !slices.Contains(r.Classes, class) {
				continue
			}
			priority++
		}
		if priority == best {
			ambiguous = true
		}
		if priority > best {
			selected, best, ambiguous = r, priority, false
		}
	}
	if ambiguous {
		return nil, apperr.Conflict("approval_unavailable", "Approval policy is ambiguous; ask the server's team to review it")
	}
	return selected, nil
}

// RulesOverlap is relevant only within the same precedence tier/target.
func RulesOverlap(a, b RuleInput) bool {
	if !a.Enabled || !b.Enabled || a.TargetKind != b.TargetKind || a.TargetID != b.TargetID {
		return false
	}
	if a.CapabilityID != nil || b.CapabilityID != nil {
		return a.CapabilityID != nil && b.CapabilityID != nil && *a.CapabilityID == *b.CapabilityID
	}
	for _, c := range a.Classes {
		if slices.Contains(b.Classes, c) {
			return true
		}
	}
	return false
}

// CanonicalArguments normalizes absent/null to the object actually forwarded.
// Numbers retain their exact decimal spelling rather than losing precision.
func CanonicalArguments(raw json.RawMessage) ([]byte, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		raw = []byte("{}")
	}
	if len(raw) > 4<<20 || raw[0] != '{' {
		return nil, apperr.New(400, "invalid_arguments", "Tool arguments must be a bounded JSON object")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var obj map[string]any
	if err := dec.Decode(&obj); err != nil || obj == nil {
		return nil, apperr.New(400, "invalid_arguments", "Tool arguments must be a bounded JSON object")
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, apperr.New(400, "invalid_arguments", "Tool arguments must contain one JSON object")
	}
	check := json.NewDecoder(bytes.NewReader(raw))
	check.UseNumber()
	if err := uniqueArgumentKeys(check, 0); err != nil {
		return nil, apperr.New(400, "invalid_arguments", "Tool arguments must have unique object keys and bounded nesting")
	}
	return json.Marshal(obj)
}

// Approval previews and forwarded arguments must not disagree between JSON
// parsers about duplicate keys. Bound recursion independently of JSON's limit.
func uniqueArgumentKeys(dec *json.Decoder, depth int) error {
	if depth > 128 {
		return errors.New("approval arguments nesting limit")
	}
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	delim, container := tok.(json.Delim)
	if !container {
		return nil
	}
	if delim == '{' {
		seen := map[string]bool{}
		for dec.More() {
			key, err := dec.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok || seen[name] {
				return errors.New("duplicate approval argument key")
			}
			seen[name] = true
			if err := uniqueArgumentKeys(dec, depth+1); err != nil {
				return err
			}
		}
	} else if delim == '[' {
		for dec.More() {
			if err := uniqueArgumentKeys(dec, depth+1); err != nil {
				return err
			}
		}
	} else {
		return errors.New("unexpected approval argument delimiter")
	}
	_, err = dec.Token()
	return err
}

// argumentDigest is keyed: a public receipt must not provide an offline
// dictionary oracle for low-entropy argument values that its preview redacts.
func argumentDigest(key, canonical []byte) string {
	h := hmac.New(sha256.New, key)
	_, _ = h.Write([]byte("tool-approval-arguments/v1\n"))
	_, _ = h.Write(canonical)
	return hex.EncodeToString(h.Sum(nil))
}
