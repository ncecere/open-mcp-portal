package curation

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestPortableConstraintNumbers(t *testing.T) {
	for _, tc := range []struct {
		text string
		ok   bool
	}{
		{"0.1", true}, {"1e-1", true}, {"0.10", true}, {"-0.0", true},
		{"9007199254740991", true}, {"-9007199254740991", true}, {"1e-300", true}, {"5e-324", true},
		{"9007199254740990.5", false}, {"9007199254740992", false}, {"9007199254740993", false},
		{"-9007199254740992", false}, {"0.10000000000000001", false}, {"1.234567890123456789", false},
		{"1e309", false}, {"1e10000", false}, {"1e-324", false}, {"1e-10000", false},
	} {
		for _, value := range []string{tc.text, `{"nested":[` + tc.text + `]}`} {
			for _, constraint := range []string{`"fixed":` + value, `"allowed":[` + value + `]`} {
				raw := []byte(`{"constraints":{"x":{` + constraint + `}}}`)
				p, err := Decode(raw)
				if (err == nil) != tc.ok {
					t.Fatalf("%s: %v", raw, err)
				}
				if err == nil {
					// Validation must never silently replace the authored spelling.
					out, _ := json.Marshal(p)
					if !strings.Contains(string(out), tc.text) {
						t.Fatalf("normalized policy: %s", out)
					}
				}
			}
		}
	}
	// Runtime equality remains exact, including numbers outside authoring limits.
	if !Equal([]byte(`1e10000`), []byte(`10e9999`)) || Equal([]byte(`9007199254740990.5`), []byte(`9007199254740990`)) {
		t.Fatal("runtime equality rounded or imposed binary64 authoring limits")
	}
}

func TestUnconstrainedRuntimeNumbersRemainUnrestricted(t *testing.T) {
	p := policy(t, `{"constraints":{"owner":{"fixed":"org"}}}`)
	for _, n := range []string{"9007199254740993", "9007199254740990.5", "1e1000000", "1e-1000000"} {
		merged, err := Merge(p, []byte(`{"n":`+n+`}`))
		if err != nil || !strings.Contains(string(merged), `"n":`+n) {
			t.Fatalf("unconstrained runtime number restricted or rounded: %s %v", merged, err)
		}
	}
}

func TestProjectionCompilesEnumOnce(t *testing.T) {
	entries := make([]string, 1000)
	for i := range entries {
		entries[i] = fmt.Sprint(i + 1)
	}
	raw := []byte(`{"type":"number","enum":[` + strings.Join(entries, ",") + `]}`)
	s, err := object(raw)
	if err != nil {
		t.Fatal(err)
	}
	w := newWorkBudget()
	c, ok := compileSchema(s, 0, w)
	if !ok || len(c.enum) != 1000 || w.values != MaxCompiledValueNodes-1000 || w.schema != MaxSchemaNodes-1001 {
		t.Fatalf("compile counts: %+v, ok=%v", w, ok)
	}
	for i := range 100 {
		v, err := parseValue([]byte(entries[i]), w, true)
		if err != nil {
			t.Fatal(err)
		}
		values, arithmetic := w.values, w.arithmetic
		validation := w.validation
		if !c.valid(v, w) {
			t.Fatalf("value %d refused", i)
		}
		if w.values != values || w.arithmetic != arithmetic || validation-w.validation != 2 {
			t.Fatalf("membership reparsed values/did arithmetic or traversed enum: %+v", w)
		}
	}
	definition := []byte(`{"inputSchema":{"type":"object","properties":{"x":` + string(raw) + `}}}`)
	p := policy(t, `{"constraints":{"x":{"allowed":[`+strings.Join(entries[:100], ",")+`]}}}`)
	if _, normalized, err := Project(definition, p); err != nil || len(normalized.Constraints["x"].Allowed) != 100 {
		t.Fatalf("bounded enum projection: %v", err)
	}
}

func TestExpensiveNumbersRejectedBeforeRationalWork(t *testing.T) {
	entries := make([]string, 1000)
	for i := range entries {
		entries[i] = fmt.Sprintf("%de10000", i+1)
	}
	s, _ := object([]byte(`{"enum":[` + strings.Join(entries, ",") + `]}`))
	w := newWorkBudget()
	if _, ok := compileSchema(s, 0, w); ok || w.arithmetic != MaxArithmeticWork || w.values != MaxCompiledValueNodes-1 {
		t.Fatalf("expensive enum not refused on its first number before rational work: %+v", w)
	}
	def := []byte(`{"inputSchema":{"type":"object","properties":{"x":{"enum":[` + strings.Join(entries, ",") + `]}}}}`)
	allowed := strings.TrimSuffix(strings.Repeat("0.1,", 100), ",")
	if _, _, err := Project(def, policy(t, `{"constraints":{"x":{"allowed":[`+allowed+`]}}}`)); err == nil {
		t.Fatal("accepted adversarial numeric enum")
	}
	if _, _, err := Project(def, policy(t, `{"nameOverride":"rename"}`)); err != nil {
		t.Fatal("rename-only unexpectedly restricted original schema", err)
	}
}

func TestCumulativeWorkBudgets(t *testing.T) {
	// Individual values and the whole schema fit byte/entry bounds, but total
	// nested enum nodes exceed the cumulative compilation budget.
	entry := `[` + strings.TrimSuffix(strings.Repeat(`null,`, 200), ",") + `]`
	enum := strings.TrimSuffix(strings.Repeat(entry+",", 60), ",")
	def := []byte(`{"inputSchema":{"type":"object","properties":{"x":{"enum":[` + enum + `]}}}}`)
	if len(def) >= MaxSchemaBytes {
		t.Fatal("fixture exceeds byte bound")
	}
	if _, _, err := Project(def, policy(t, `{"constraints":{"x":{"fixed":null}}}`)); err == nil {
		t.Fatal("cumulative enum value traversal not bounded")
	}
	w := newWorkBudget()
	w.arithmetic = 0
	n, _ := normalizeNumber("1e-300")
	if n.compile(w) || n.rat != nil || w.arithmetic != -1 {
		t.Fatal("rational allocated before budget refusal")
	}
	w = newWorkBudget()
	// Each numeric value is portable, yet together their exact rational
	// construction exceeds the projection's arithmetic budget.
	s, _ := object([]byte(`{"enum":[` + strings.TrimSuffix(strings.Repeat(`1e-300,`, 1000), ",") + `]}`))
	if _, ok := compileSchema(s, 0, w); ok || w.arithmetic != -1 || w.values <= MaxCompiledValueNodes-1000 {
		t.Fatalf("cumulative rational allocation not bounded: %+v", w)
	}
	w = newWorkBudget()
	s, _ = object([]byte(`{"multipleOf":0.1}`))
	c, ok := compileSchema(s, 0, w)
	v, err := parseValue([]byte(`0.2`), w, true)
	if !ok || err != nil {
		t.Fatal("fixture", err)
	}
	w.arithmetic = 0
	if c.valid(v, w) || w.arithmetic != -1 {
		t.Fatal("division not budgeted")
	}
	w.validation = 0
	if c.valid(v, w) || w.validation != -1 {
		t.Fatal("validation not budgeted")
	}
}

func TestProjectionRejectsWholePolicyOnValidationExhaustion(t *testing.T) {
	// Every candidate is valid, byte/node limits are met, and the first few
	// candidates fit the work quota. Exhaustion must not return that prefix.
	schema := `{"type":"array","uniqueItems":true,"items":{"type":"integer"}}`
	for range 15 {
		schema = `{"type":"array","uniqueItems":true,"items":` + schema + `}`
	}
	allowed := make([]string, 36)
	for i := range allowed {
		items := make([]string, 200)
		for j := range items {
			items[j] = fmt.Sprint(i*200 + j)
		}
		v := `[` + strings.Join(items, ",") + `]`
		for range 15 {
			v = `[` + v + `]`
		}
		allowed[i] = v
	}
	def := []byte(`{"inputSchema":{"type":"object","properties":{"x":` + schema + `}}}`)
	p := policy(t, `{"constraints":{"x":{"allowed":[`+strings.Join(allowed, ",")+`]}}}`)
	if out, normalized, err := Project(def, p); err == nil || out != nil || normalized != nil {
		t.Fatal("exhausted projection returned a partial allowed list")
	}
	// The same shape with one candidate is supported; this isn't merely a
	// rejection of the schema or each individual value.
	p = policy(t, `{"constraints":{"x":{"allowed":[`+allowed[0]+`]}}}`)
	if _, _, err := Project(def, p); err != nil {
		t.Fatal("individual candidate refused", err)
	}
}

func TestCompiledNumericAndNestedValidation(t *testing.T) {
	def := []byte(`{"inputSchema":{"type":"object","properties":{"x":{"type":"array","uniqueItems":true,"items":{"type":"number","minimum":0.1,"maximum":0.3,"multipleOf":0.1}}}}}`)
	for _, tc := range []struct {
		v  string
		ok bool
	}{{"[0.1,0.2,0.3]", true}, {"[0.1,1e-1]", false}, {"[0.15]", false}, {"[0.4]", false}, {"[0]", false}} {
		p := policy(t, `{"constraints":{"x":{"fixed":`+tc.v+`}}}`)
		if _, _, err := Project(def, p); (err == nil) != tc.ok {
			t.Fatalf("%s: %v", tc.v, err)
		}
	}
}
