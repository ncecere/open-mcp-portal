package approvals

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"
)

func validRuleInput() RuleInput {
	return RuleInput{Name: "Sensitive calls", TargetKind: "server", TargetID: uuid.New(), Classes: []string{"destructive"}, Enabled: true}
}

func TestNormalizeRule(t *testing.T) {
	in := validRuleInput()
	out, err := NormalizeRule(in)
	if err != nil || out.PendingMinutes != 1440 || out.ValidMinutes != 15 || out.Approvers == nil {
		t.Fatalf("defaults: %+v %v", out, err)
	}
	id := uuid.New()
	group := " Finance, Production "
	in.Approvers = []Selector{{Kind: "user", UserID: &id}, {Kind: "group", GroupName: &group}}
	out, err = NormalizeRule(in)
	if err != nil || *out.Approvers[1].GroupName != group {
		t.Fatal("group names must remain exact")
	}
	for _, change := range []func(*RuleInput){
		func(r *RuleInput) { r.Name = "\n" },
		func(r *RuleInput) { r.TargetKind = "unknown" },
		func(r *RuleInput) { r.TargetID = uuid.Nil },
		func(r *RuleInput) { r.CapabilityID = &id },
		func(r *RuleInput) { r.Classes = nil },
		func(r *RuleInput) { r.Classes = []string{"write", "write"} },
		func(r *RuleInput) { r.Classes = []string{"unclassified"} },
		func(r *RuleInput) { r.ValidMinutes = 61 },
		func(r *RuleInput) { r.PendingMinutes = 1441 },
		func(r *RuleInput) { r.PendingMinutes = 4 },
		func(r *RuleInput) { r.Approvers = []Selector{{Kind: "user", UserID: &id, GroupName: &group}} },
		func(r *RuleInput) { r.Approvers = []Selector{{Kind: "user", UserID: &id}, {Kind: "user", UserID: &id}} },
		func(r *RuleInput) { bad := "root\x00group"; r.Approvers = []Selector{{Kind: "group", GroupName: &bad}} },
	} {
		r := validRuleInput()
		change(&r)
		if _, err := NormalizeRule(r); err == nil {
			t.Fatalf("invalid rule accepted: %+v", r)
		}
	}
}

func TestRulePrecedenceAndAmbiguity(t *testing.T) {
	b := Binding{ServerID: uuid.New(), GatewayID: uuid.New(), CapabilityID: uuid.New()}
	server := Rule{ID: uuid.New(), RuleInput: RuleInput{Name: "Server", TargetKind: "server", TargetID: b.ServerID, Classes: []string{"destructive"}, Enabled: true}}
	gateway := Rule{ID: uuid.New(), RuleInput: RuleInput{Name: "Gateway", TargetKind: "gateway", TargetID: b.GatewayID, CapabilityID: &b.CapabilityID, Enabled: true}}
	for _, rules := range [][]Rule{{gateway, server}, {server, gateway}, {gateway, gateway, server}} {
		got, err := MatchRule(rules, b)
		if err != nil || got == nil || got.ID != server.ID {
			t.Fatalf("server class must outrank gateway capability: %+v %v", got, err)
		}
	}
	if b.ToolClass != nil {
		t.Fatal("matching must not reclassify unclassified tools")
	}
	serverSpecific := server
	serverSpecific.ID, serverSpecific.CapabilityID, serverSpecific.Classes = uuid.New(), &b.CapabilityID, nil
	got, err := MatchRule([]Rule{server, serverSpecific}, b)
	if err != nil || got.ID != serverSpecific.ID {
		t.Fatalf("capability precedence: %+v %v", got, err)
	}
	if _, err := MatchRule([]Rule{server, server}, b); err == nil {
		t.Fatal("equal highest-priority rules must fail closed")
	}
	read := "read"
	b.ToolClass = &read
	if got, err := MatchRule([]Rule{server}, b); err != nil || got != nil {
		t.Fatal("destructive rule matched read")
	}
}

func TestRuleOverlap(t *testing.T) {
	a := validRuleInput()
	b := a
	if !RulesOverlap(a, b) {
		t.Fatal("identical class selectors must overlap")
	}
	b.Classes = []string{"read"}
	if RulesOverlap(a, b) {
		t.Fatal("disjoint classes overlap")
	}
	id := uuid.New()
	b.CapabilityID, b.Classes = &id, nil
	if RulesOverlap(a, b) {
		t.Fatal("different precedence selectors overlap")
	}
	a = b
	if !RulesOverlap(a, b) {
		t.Fatal("identical capability selectors must overlap")
	}
	b.Enabled = false
	if RulesOverlap(a, b) {
		t.Fatal("disabled rule cannot conflict")
	}
}

func TestCanonicalArgumentsAndKeyedDigest(t *testing.T) {
	for _, raw := range []json.RawMessage{nil, []byte("null"), []byte("{}"), []byte("  {}  ")} {
		got, err := CanonicalArguments(raw)
		if err != nil || string(got) != "{}" {
			t.Fatalf("empty normalization: %q %v", got, err)
		}
	}
	want := `{"a":9007199254740993,"b":1.0}`
	got, err := CanonicalArguments([]byte(`{"b":1.0,"a":9007199254740993}`))
	if err != nil || string(got) != want {
		t.Fatalf("canonical exact decimals: %s %v", got, err)
	}
	for _, raw := range []string{`[]`, `{`, `{} {}`, `false`, `{"x":NaN}`, `{"x":1,"x":2}`, `{"obj":[{"x":1,"x":2}]}`} {
		if _, err := CanonicalArguments([]byte(raw)); err == nil {
			t.Fatalf("invalid arguments accepted: %s", raw)
		}
	}
	a := argumentDigest([]byte("key-a"), got)
	if len(a) != 64 || a == argumentDigest([]byte("key-b"), got) || a == argumentDigest([]byte("key-a"), []byte("{}")) {
		t.Fatal("digest must bind both key and exact arguments")
	}
}
