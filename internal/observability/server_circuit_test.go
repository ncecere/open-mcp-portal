package observability

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestServerCircuitMetricsBoundAndRetirement(t *testing.T) {
	old := Servers
	Servers = NewBoundedLabels(1, func(v string) { ServerCircuitState.DeleteLabelValues(v) })
	ServerCircuitState.Reset()
	defer func() { ServerCircuitState.Reset(); Servers = old }()
	m := NewMetrics(nil)
	ObserveServerCircuit("one", 1)
	ObserveServerCircuit("two", 0.5) // Overflow must not merge incompatible gauges into other.
	read := func() string {
		r := httptest.NewRecorder()
		m.Handler().ServeHTTP(r, httptest.NewRequest("GET", "/metrics", nil))
		return r.Body.String()
	}
	text := read()
	if !strings.Contains(text, `omp_server_circuit_state{server="one"} 1`) || strings.Contains(text, `omp_server_circuit_state{server="two"}`) || strings.Contains(text, `omp_server_circuit_state{server="other"}`) {
		t.Fatalf("unbounded/ambiguous circuit metric: %s", text)
	}
	Servers.Sync([]string{"two"})
	ObserveServerCircuit("two", 0.5)
	text = read()
	if strings.Contains(text, `omp_server_circuit_state{server="one"}`) || !strings.Contains(text, `omp_server_circuit_state{server="two"} 0.5`) {
		t.Fatal("deleted circuit series retained or new state missing")
	}
	Servers.Sync([]string{"other"})
	ObserveServerCircuit("other", 0)
	if !strings.Contains(read(), `omp_server_circuit_state{server="other"} 0`) {
		t.Fatal("a real server literally named other was mistaken for overflow")
	}
}
