package scancorpus

import "github.com/ncecere/open-mcp-portal/internal/secretrules"

// RuleNumbers is a closed-catalog row; never add input-derived metadata.
type RuleNumbers struct {
	RuleID string `json:"rule_id"`
	TP     int    `json:"tp"`
	FP     int    `json:"fp"`
	FN     int    `json:"fn"`
	TN     int    `json:"tn"`
	Count  int    `json:"count"`
}
type Report struct {
	Evaluation   string        `json:"evaluation"`
	Completeness string        `json:"completeness"`
	Unsupported  []string      `json:"unsupported"`
	Rules        []RuleNumbers `json:"rules"`
	Cases        int           `json:"cases"`
	KnownMisses  int           `json:"known_misses"`
}

func rows() []RuleNumbers {
	var out []RuleNumbers
	for _, r := range secretrules.BuiltInRules {
		out = append(out, RuleNumbers{RuleID: "secret." + r.Name})
	}
	return append(out, RuleNumbers{RuleID: "secret.call_secrets"})
}
func newReport() Report {
	return Report{Completeness: "primitive_only_not_a_safety_verdict", Evaluation: "authored_labelled_secret_primitives", Unsupported: []string{"unicode", "phrasing", "normalization", "json-scanner", "stages", "severity", "deadlines", "binary", "personal-data"}, Rules: rows()}
}
func SyntheticReport() Report {
	r := newReport()
	for _, c := range Cases() {
		r.Cases++
		if c.Category == "known-miss" {
			r.KnownMisses++
			continue
		}
		got := map[string]int{}
		for _, f := range secretrules.NewRedactor(nil, c.Exact...).Find(c.Text) {
			got[f.RuleID] = f.Count
		}
		for i := range r.Rules {
			row := &r.Rules[i]
			g, w := got[row.RuleID] > 0, c.Want[row.RuleID] > 0
			switch {
			case g && w:
				row.TP++
			case g:
				row.FP++
			case w:
				row.FN++
			default:
				row.TN++
			}
			row.Count += got[row.RuleID]
		}
	}
	return r
}

// PublicReport scans one entire source file as raw text. Counts are exploratory,
// not labelled precision/recall or a whole JSON/stage completeness measurement.
func PublicReport(text string) Report {
	r := newReport()
	r.Evaluation = "unlabelled_raw_source_counts_only"
	r.Cases = 1
	for _, f := range secretrules.NewRedactor(nil).Find(text) {
		for i := range r.Rules {
			if r.Rules[i].RuleID == f.RuleID {
				r.Rules[i].Count = f.Count
			}
		}
	}
	return r
}
