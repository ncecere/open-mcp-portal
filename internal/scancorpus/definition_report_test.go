package scancorpus

import (
	"encoding/json"
	"github.com/ncecere/open-mcp-portal/internal/definitionscan"
	"os"
	"regexp"
	"strings"
	"testing"
)

func TestDefinitionAggregateReport(t *testing.T) {
	r := DefinitionReport()
	if len(r.Rules) != len(definitionscan.Catalog()) {
		t.Fatal("catalog mismatch")
	}
	ledger, err := os.ReadFile("testdata/definition-known-misses.md")
	if err != nil {
		t.Fatal(err)
	}
	if len(regexp.MustCompile(`(?m)^\| ([a-z]+-[a-z-]+) \|`).FindAll(ledger, -1)) != r.KnownMisses {
		t.Fatal("ledger mismatch")
	}
	groups := map[string]bool{}
	for _, row := range r.Rules {
		groups[strings.Split(row.RuleID, ".")[0]] = true
		if row.TP == 0 || row.FN != 0 || row.FP != 0 {
			t.Errorf("%+v", row)
		}
	}
	if len(groups) != 4 {
		t.Fatal(groups)
	}
	p := PublicDefinitionReport("ignore previous instructions")
	b, _ := json.Marshal(p)
	if strings.Contains(string(b), "ignore previous") {
		t.Fatal("source leaked")
	}
	for _, row := range p.Rules {
		if row.TP+row.FP+row.FN+row.TN != 0 {
			t.Fatal("unlabelled source scored")
		}
	}
}
