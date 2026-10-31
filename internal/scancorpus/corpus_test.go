package scancorpus

import (
	"encoding/json"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/ncecere/open-mcp-portal/internal/secretrules"
)

func counts(c Case) map[string]int {
	out := map[string]int{}
	for _, f := range secretrules.NewRedactor(nil, c.Exact...).Find(c.Text) {
		out[f.RuleID] = f.Count
	}
	return out
}
func TestCorpus(t *testing.T) {
	ids := map[string]bool{}
	for _, c := range Cases() {
		if ids[c.ID] {
			t.Fatal("duplicate case ID")
		}
		ids[c.ID] = true
		if !reflect.DeepEqual(counts(c), c.Want) {
			t.Errorf("%s: count expectation changed", c.ID)
		}
	}
	r := SyntheticReport()
	for _, row := range r.Rules {
		if row.TP == 0 || row.FP != 0 || row.FN != 0 {
			t.Errorf("%s: coverage changed", row.RuleID)
		}
	}
}
func TestKnownMissLedger(t *testing.T) {
	want := []string{"base64", "bidi", "combining", "fullwidth", "german", "image", "json-escape", "json-secret-escape", "paraphrase", "personal-data", "split-instruction", "split-secret", "tag", "zero-width"}
	ledger, err := os.ReadFile("testdata/known-misses.md")
	if err != nil {
		t.Fatal(err)
	}
	var observed, documented []string
	for _, c := range Cases() {
		if c.Category == "known-miss" && len(counts(c)) == 0 {
			observed = append(observed, c.ID)
		}
	}
	for _, line := range strings.Split(string(ledger), "\n") {
		parts := strings.Split(line, "|")
		if len(parts) == 4 && strings.TrimSpace(parts[1]) != "ID" && strings.TrimSpace(parts[1]) != "---" {
			documented = append(documented, strings.TrimSpace(parts[1]))
		}
	}
	slices.Sort(observed)
	slices.Sort(documented)
	if !reflect.DeepEqual(observed, want) || !reflect.DeepEqual(documented, want) {
		t.Fatal("known-miss set changed: update fixture expectations AND ledger explicitly")
	}
}
func TestCapsAndPathological(t *testing.T) {
	for _, name := range []string{"github", "exact"} {
		token := "ghp_" + payload(24)
		r := secretrules.NewRedactor(nil)
		if name == "exact" {
			token = payload(16)
			r = secretrules.NewRedactor(nil, token)
		}
		got := r.Find(strings.Repeat(token+" ", secretrules.MaxFindCount+1))
		if len(got) != 1 || got[0].Count != secretrules.MaxFindCount {
			t.Fatal("count cap changed")
		}
	}
	for id, text := range Pathological() {
		t.Run(id, func(t *testing.T) {
			if len(secretrules.NewRedactor(nil).Find(text)) != 0 {
				t.Fatal("pathological expectation changed")
			}
		})
	}
}
func TestReportPrivacy(t *testing.T) {
	for _, c := range Cases() {
		r := PublicReport(c.Text)
		data, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		if len(c.Text) > 30 && strings.Contains(string(data), c.Text) {
			t.Fatal("input escaped")
		}
	}
	typ := reflect.TypeFor[RuleNumbers]()
	if typ.NumField() != 6 {
		t.Fatal("review new evidence fields")
	}
	for i := 0; i < typ.NumField(); i++ {
		if i > 0 && typ.Field(i).Type.Kind() != reflect.Int {
			t.Fatal("non numeric evidence")
		}
	}
	canary := payload(80)
	b, _ := json.Marshal(PublicReport(`{"` + canary + `":"` + canary + `"}`))
	if strings.Contains(string(b), canary) {
		t.Fatal("key/value escaped")
	}
}
func BenchmarkPrimitive(b *testing.B) {
	inputs := Pathological()
	inputs["definition-64KiB"] = strings.Repeat("Original synthetic definition. ", 2300)[:64<<10]
	inputs["arguments-16KiB"] = strings.Repeat("q ", 8<<10)
	inputs["result-64KiB"] = strings.Repeat("q ", 32<<10)
	inputs["positive"] = Cases()[0].Text
	for id, text := range inputs {
		b.Run(id, func(b *testing.B) {
			r := secretrules.NewRedactor(nil)
			b.SetBytes(int64(len(text)))
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				_ = r.Find(text)
			}
		})
	}
	b.Run("refresh-500x2KiB", func(b *testing.B) {
		r := secretrules.NewRedactor(nil)
		text := strings.Repeat("q ", 1024)
		b.ReportAllocs()
		b.ResetTimer()
		for b.Loop() {
			for range 500 {
				_ = r.Find(text)
			}
		}
	})
}
