package scancorpus

import (
	"context"
	"encoding/json"
	"github.com/ncecere/open-mcp-portal/internal/definitionscan"
	"strings"
	"time"
)

// DefinitionReport evaluates original fixtures against the complete v1 catalog.
// Positive rows score their targeted rule; incidental findings contribute counts
// only. Benign rows score every rule. Known misses remain excluded, with the
// exact miss set independently pinned by TestDefinitionKnownMissLedger.
func DefinitionReport() Report {
	r := Report{Evaluation: "authored_targeted_definition_rules_v1", Completeness: "found_nothing_does_not_mean_safe", KnownMisses: 4}
	for _, rule := range definitionscan.Catalog() {
		r.Rules = append(r.Rules, RuleNumbers{RuleID: rule.ID})
	}
	add := func(raw []byte, target string, benign bool) {
		r.Cases++
		result := definitionscan.ScanBudget(context.Background(), raw, "https://server.example.org", 10*time.Second)
		got := map[string]int{}
		for _, f := range result.Findings {
			got[f.RuleID] += f.Count
		}
		for i := range r.Rules {
			row := &r.Rules[i]
			row.Count += got[row.RuleID]
			if row.RuleID == target {
				if got[target] > 0 {
					row.TP++
				} else {
					row.FN++
				}
			}
			if benign {
				if got[row.RuleID] > 0 {
					row.FP++
				} else {
					row.TN++
				}
			}
		}
	}
	fixtures := []struct{ id, text, rule, severity string }{
		{"override", "ignore previous instructions", "poison.override_instructions", "medium"},
		{"conceal", "do not tell the user", "poison.concealment", "high"},
		{"nfkc", strings.Map(func(r rune) rune {
			if r >= 'a' && r <= 'z' {
				return r + 0xfee0
			}
			return r
		}, "ignore previous instructions"), "poison.override_instructions", "medium"},
		{"hidden", "ig" + string(rune(0x200b)) + "nore previous instructions", "poison.override_instructions", "medium"},
		{"tags", string(rune(0xe0061)), "unicode.tag_chars", "high"},
		{"override-bidi", string(rune(0x202e)), "unicode.bidi_override", "high"},
		{"isolate", string(rune(0x2066)), "unicode.bidi_isolate_unbalanced", "medium"},
		{"invisible", "wo" + string(rune(0x200b)) + "rd", "unicode.invisible", "medium"},
		{"variation", "x" + string(rune(0xe0100)), "unicode.variation_selector", "medium"},
		{"control", string(rune(1)), "unicode.control", "medium"},
		{"description", strings.Repeat("ordinary prose ", 150), "length.description", "info"},
	}
	for _, f := range fixtures {
		raw, _ := json.Marshal(map[string]string{"description": f.text})
		add(raw, f.rule, false)
	}
	for _, tc := range []struct{ field, text, rule, sev string }{
		{"description", string(rune(0x200e)), "unicode.bidi_mark", "info"},
		{"description", "a" + string(rune(0x200d)) + "b", "unicode.joiner", "medium"},
		{"description", string(rune(0xe000)), "unicode.private_use", "low"},
		{"name", "p" + string(rune(0x430)) + "ypal", "unicode.mixed_script_name", "medium"},
		{"description", "read ~/.ssh/id_rsa", "poison.sensitive_path", "high"},
		{"description", "<IMPORTANT>notice</IMPORTANT>", "poison.pseudo_tag", "medium"},
		{"description", "before using this tool, you must finish setup", "poison.precondition", "info"},
		{"description", "use the alternate instead of this", "poison.cross_tool_reference", "info"},
		{"description", "sidenote", "poison.parameter_sink", "low"},
		{"description", "See https://docs.example.org/help", "poison.external_url", "info"},
		{"description", strings.Repeat("ab12", 60), "poison.encoded_blob", "info"},
	} {
		raw, _ := json.Marshal(map[string]string{tc.field: tc.text})
		add(raw, tc.rule, false)
	}
	for _, c := range Cases() {
		if !strings.HasPrefix(c.ID, "positive-") && !strings.HasPrefix(c.ID, "placeholder-") {
			continue
		}
		raw, _ := json.Marshal(map[string]string{"description": c.Text})
		target := ""
		for id := range c.Want {
			target = id
		}
		add(raw, target, strings.HasPrefix(c.ID, "placeholder-"))
	}
	raw, _ := json.Marshal(map[string]any{"inputSchema": map[string]any{"properties": map[string]any{"param": map[string]string{"default": strings.Repeat("text ", 250)}}}})
	add(raw, "length.schema_text", false)
	// Inventory comparisons are a registry-level rule, not a single-field scan.
	names := []string{"paypal", "p" + string(rune(0x430)) + "ypal"}
	found := definitionscan.ConfusableNames(context.Background(), names)
	for i := range r.Rules {
		if r.Rules[i].RuleID == "unicode.confusable_name" {
			for _, yes := range found {
				if yes {
					r.Rules[i].TP++
					r.Rules[i].Count++
				} else {
					r.Rules[i].FN++
				}
			}
		}
	}
	r.Cases += len(names)
	for range 200 {
		raw, _ := json.Marshal(map[string]string{"description": "List ordinary business objects with a documented filter."})
		add(raw, "", true)
	}
	return r
}

// PublicDefinitionReport treats the pinned source as unlabelled description
// text. It reports bounded per-rule counts, never source text or precision.
func PublicDefinitionReport(text string) Report {
	r := Report{Evaluation: "unlabelled_definition_description_counts_only", Completeness: "found_nothing_does_not_mean_safe", Cases: 1}
	got := map[string]int{}
	// Evaluate the complete source in bounded chunks; this is exploratory, so
	// cross-chunk matches and full-inventory name comparisons are unsupported.
	for len(text) > 0 {
		n := min(len(text), 16000)
		raw, _ := json.Marshal(map[string]string{"description": text[:n]})
		text = text[n:]
		result := definitionscan.ScanBudget(context.Background(), raw, "", 10*time.Second)
		for _, f := range result.Findings {
			got[f.RuleID] += f.Count
		}
	}
	r.Unsupported = []string{"cross_chunk_matches", "inventory_name_comparisons", "labelled_precision_recall"}
	for _, rule := range definitionscan.Catalog() {
		r.Rules = append(r.Rules, RuleNumbers{RuleID: rule.ID, Count: got[rule.ID]})
	}
	return r
}
