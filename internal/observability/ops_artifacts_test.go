package observability

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"gopkg.in/yaml.v3"
)

// The dashboards (deploy/grafana/dashboards) and the alert rules
// (deploy/prometheus) are built from the portal's own metrics. These tests
// parse every query and fail when one names a metric or a label the registry
// does not have, so renaming a metric breaks CI instead of an empty panel or an
// alert that can never fire. They also keep the PrometheusRule example equal to
// the rules file and give every alert a runbook entry. `make prom-check` runs
// promtool over the rules (check and unit tests).

const repoRoot = "../.."

// externalLabels are labels Prometheus and its scrape configuration add.
var externalLabels = []string{"instance", "job", "namespace", "pod", "container", "service", "endpoint", "cluster", "prometheus", "node", "le"}

// promqlWords are the functions, operators and keywords of the queries used
// here; everything else in an expression has to be a metric.
var promqlWords = map[string]bool{
	"rate": true, "irate": true, "increase": true, "delta": true, "sum": true, "min": true, "max": true, "avg": true, "count": true,
	"topk": true, "bottomk": true, "quantile": true, "histogram_quantile": true, "time": true, "vector": true, "scalar": true,
	"absent": true, "absent_over_time": true, "clamp_min": true, "clamp_max": true, "abs": true, "ceil": true, "floor": true, "round": true,
	"label_replace": true, "label_join": true, "and": true, "or": true, "unless": true, "bool": true, "offset": true,
	"by": true, "without": true, "on": true, "ignoring": true, "group_left": true, "group_right": true,
	"max_over_time": true, "min_over_time": true, "avg_over_time": true, "sum_over_time": true, "changes": true, "resets": true,
}

// registryMetrics are the metric names and their labels as NewMetrics
// registers them, read from the collectors' descriptors (a vector with no
// series yet has no samples, so Gather would not list it).
func registryMetrics(t *testing.T) map[string][]string {
	t.Helper()
	m := NewMetrics(nil)
	ch := make(chan *prometheus.Desc, 1024)
	m.registry.Describe(ch)
	close(ch)
	histograms := map[string]bool{}
	for _, c := range appCollectors() {
		if h, ok := c.(*prometheus.HistogramVec); ok {
			dch := make(chan *prometheus.Desc, 1)
			h.Describe(dch)
			close(dch)
			for d := range dch {
				name, _ := descNameLabels(t, d)
				histograms[name] = true
			}
		}
	}
	out := map[string][]string{}
	for d := range ch {
		name, labels := descNameLabels(t, d)
		out[name] = labels
		if histograms[name] {
			out[name+"_bucket"] = append(slices.Clone(labels), "le")
			out[name+"_sum"] = slices.Clone(labels)
			out[name+"_count"] = slices.Clone(labels)
		}
	}
	// Prometheus itself records `up` for every target it scrapes.
	out["up"] = []string{}
	for _, name := range []string{"omp_mcp_requests_total", "omp_db_pool_max_connections", "omp_mcp_servers", "omp_mcp_call_duration_seconds_bucket", "go_goroutines"} {
		if _, ok := out[name]; !ok {
			t.Fatalf("the registry has %d metrics, not %s", len(out), name)
		}
	}
	return out
}

var descRE = regexp.MustCompile(`fqName: "([^"]+)".*variableLabels: \{([^}]*)\}`)

func descNameLabels(t *testing.T, d *prometheus.Desc) (string, []string) {
	t.Helper()
	m := descRE.FindStringSubmatch(d.String())
	if m == nil {
		t.Fatalf("cannot read %s", d.String())
	}
	var labels []string
	for _, l := range strings.Split(m[2], ",") {
		l = strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(l), "c("), ")")
		if l != "" {
			labels = append(labels, l)
		}
	}
	return m[1], labels
}

var (
	stringRE    = regexp.MustCompile(`"(?:[^"\\]|\\.)*"`)
	selectorRE  = regexp.MustCompile(`([a-zA-Z_:][a-zA-Z0-9_:]*)\s*\{([^{}]*)\}`)
	braceRE     = regexp.MustCompile(`\{[^{}]*\}`)
	rangeRE     = regexp.MustCompile(`\[[^\]]*\]`)
	groupingRE  = regexp.MustCompile(`\b(by|without|on|ignoring|group_left|group_right)\s*\(([^)]*)\)`)
	identRE     = regexp.MustCompile(`[a-zA-Z_:][a-zA-Z0-9_:]*`)
	labelNameRE = regexp.MustCompile(`^\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*(=~|!~|!=|=)`)
	labelValues = regexp.MustCompile(`^\s*label_values\(\s*(.+?)\s*,\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\)\s*$`)
	legendRE    = regexp.MustCompile(`\{\{\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\}\}`)
)

// checkQuery reports what is wrong with one PromQL expression (or a Grafana
// label_values query): a metric, or a label of a metric, the registry lacks.
// It returns the labels the expression may use, for legends.
func checkQuery(expr string, known map[string][]string) (problems []string, allowed []string) {
	var queryLabels []string
	if m := labelValues.FindStringSubmatch(expr); m != nil {
		expr = m[1]
		queryLabels = append(queryLabels, m[2])
	}
	expr = stringRE.ReplaceAllString(expr, `""`)
	allowed = slices.Clone(externalLabels)
	var used []string
	// Selectors: each label must belong to its metric.
	for _, sel := range selectorRE.FindAllStringSubmatch(expr, -1) {
		labels, ok := known[sel[1]]
		if !ok {
			continue // reported below as an unknown metric
		}
		allowed = append(allowed, labels...)
		for _, matcher := range strings.Split(sel[2], ",") {
			if m := labelNameRE.FindStringSubmatch(matcher); m != nil && !slices.Contains(labels, m[1]) && !slices.Contains(externalLabels, m[1]) {
				problems = append(problems, "label "+m[1]+" is not a label of "+sel[1])
			}
		}
	}
	expr = braceRE.ReplaceAllString(expr, "")
	for _, g := range groupingRE.FindAllStringSubmatch(expr, -1) {
		for _, l := range strings.Split(g[2], ",") {
			if l = strings.TrimSpace(l); l != "" {
				used = append(used, l)
			}
		}
	}
	expr = groupingRE.ReplaceAllString(expr, "")
	expr = rangeRE.ReplaceAllString(expr, "")
	var metrics []string
	for _, id := range identRE.FindAllString(expr, -1) {
		if promqlWords[id] {
			continue
		}
		metrics = append(metrics, id)
	}
	for _, name := range metrics {
		labels, ok := known[name]
		if !ok {
			problems = append(problems, "unknown metric "+name)
			continue
		}
		allowed = append(allowed, labels...)
	}
	for _, l := range append(used, queryLabels...) {
		if !slices.Contains(allowed, l) {
			problems = append(problems, "label "+l+" is not a label of the metrics used")
		}
	}
	if len(metrics) == 0 && !strings.Contains(expr, "time()") && !strings.Contains(expr, "vector(") {
		problems = append(problems, "no metric in the expression")
	}
	return problems, allowed
}

func TestQueryChecker(t *testing.T) {
	known := registryMetrics(t)
	for expr, wantProblem := range map[string]string{
		`sum by (outcome) (rate(omp_mcp_requests_total{method="tools/call"}[5m]))`:                                                         "",
		`histogram_quantile(0.95, sum by (le, gateway) (rate(omp_mcp_call_duration_seconds_bucket{server=~"$server"}[$__rate_interval])))`: "",
		`time() - max by (kind) (omp_retention_last_success_timestamp_seconds) > 3600`:                                                     "",
		`label_values(omp_mcp_call_duration_seconds_count{gateway=~"$gateway"}, server)`:                                                   "",
		`absent(up{job="open-mcp-portal"} == 1)`:                                                                                           "",
		`sum(rate(omp_mcp_request_total[5m]))`:                                                                                             "unknown metric omp_mcp_request_total",
		`sum by (team) (rate(omp_mcp_requests_total[5m]))`:                                                                                 "label team is not a label of the metrics used",
		`rate(omp_mcp_requests_total{user="a"}[5m])`:                                                                                       "label user is not a label of omp_mcp_requests_total",
		`omp_mcp_servers{state="failing"} > 0 and on (gateway) vector(1)`:                                                                  "label gateway is not a label of the metrics used",
		`label_values(omp_mcp_requests_total, server)`:                                                                                     "label server is not a label of the metrics used",
		`sum(rate(omp_mcp_requests_total_bucket[5m]))`:                                                                                     "unknown metric omp_mcp_requests_total_bucket",
	} {
		problems, _ := checkQuery(expr, known)
		got := strings.Join(problems, "; ")
		if wantProblem == "" && got != "" || wantProblem != "" && !strings.Contains(got, wantProblem) {
			t.Errorf("%s\n  got %q, want %q", expr, got, wantProblem)
		}
	}
}

type rulesFile struct {
	Groups []ruleGroup `yaml:"groups"`
}

type ruleGroup struct {
	Name  string `yaml:"name"`
	Rules []rule `yaml:"rules"`
}

type rule struct {
	Alert       string            `yaml:"alert"`
	Expr        string            `yaml:"expr"`
	For         string            `yaml:"for"`
	Labels      map[string]string `yaml:"labels"`
	Annotations map[string]string `yaml:"annotations"`
}

func readRules(t *testing.T) rulesFile {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repoRoot, "deploy/prometheus/omp-alerts.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var f rulesFile
	if err := yaml.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	return f
}

// Every metric and label an alert rule uses exists, every alert has a
// severity, a duration, a summary and a runbook, and the runbook entry exists.
func TestOpsArtifactsUseRealMetrics(t *testing.T) {
	known := registryMetrics(t)
	rules := readRules(t)
	docs, err := os.ReadFile(filepath.Join(repoRoot, "docs/phase6-operations.md"))
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	n := 0
	for _, g := range rules.Groups {
		for _, r := range g.Rules {
			n++
			if r.Alert == "" || seen[r.Alert] {
				t.Errorf("alert %q is missing or repeated", r.Alert)
			}
			seen[r.Alert] = true
			if problems, allowed := checkQuery(r.Expr, known); len(problems) > 0 {
				t.Errorf("%s: %s", r.Alert, strings.Join(problems, "; "))
			} else {
				for _, text := range r.Annotations {
					for _, m := range regexp.MustCompile(`\$labels\.([a-z_]+)`).FindAllStringSubmatch(text, -1) {
						if !slices.Contains(allowed, m[1]) {
							t.Errorf("%s: the annotation uses the label %s, which the expression does not keep", r.Alert, m[1])
						}
					}
				}
			}
			if !slices.Contains([]string{"critical", "warning", "info"}, r.Labels["severity"]) || r.For == "" {
				t.Errorf("%s: severity %q, for %q", r.Alert, r.Labels["severity"], r.For)
			}
			if r.Annotations["summary"] == "" || r.Annotations["description"] == "" {
				t.Errorf("%s: no summary or description", r.Alert)
			}
			want := "https://github.com/ncecere/open-mcp-portal/blob/main/docs/phase6-operations.md#" + strings.ToLower(r.Alert)
			if r.Annotations["runbook_url"] != want {
				t.Errorf("%s: runbook_url = %q, want %q", r.Alert, r.Annotations["runbook_url"], want)
			}
			if !strings.Contains(string(docs), "\n### "+r.Alert+"\n") {
				t.Errorf("%s: docs/phase6-operations.md has no runbook entry (### %s)", r.Alert, r.Alert)
			}
		}
	}
	if n < 12 {
		t.Errorf("%d alerts", n)
	}
	// The cases the issue names are covered.
	for _, want := range []string{"OMPDown", "OMPUpstreamErrorRatioHigh", "OMPRateLimitingSustained", "OMPServersFailing", "OMPProviderRefreshRefused",
		"OMPRetentionStale", "OMPUsageRollupStale", "OMPNoLoopLeader", "OMPDBPoolSaturated", "OMPNotificationDeliveryFailures"} {
		if !seen[want] {
			t.Errorf("no alert %s", want)
		}
	}
}

// The PrometheusRule example carries exactly the rules file's groups.
func TestPrometheusRuleExampleMatchesRules(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repoRoot, "deploy/kubernetes/overlays/example/prometheusrule.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var cr struct {
		Kind string `yaml:"kind"`
		Spec struct {
			Groups []ruleGroup `yaml:"groups"`
		} `yaml:"spec"`
	}
	if err := yaml.Unmarshal(raw, &cr); err != nil {
		t.Fatal(err)
	}
	if cr.Kind != "PrometheusRule" || !reflect.DeepEqual(cr.Spec.Groups, readRules(t).Groups) {
		t.Error("deploy/kubernetes/overlays/example/prometheusrule.yaml differs from deploy/prometheus/omp-alerts.yaml: copy its groups there")
	}
}

type panel struct {
	ID      int
	Title   string
	Type    string
	Panels  []panel
	Targets []struct {
		Expr         string
		LegendFormat string
		Datasource   struct{ UID string }
	}
}

type dashboard struct {
	UID, Title string
	Panels     []panel
	Templating struct {
		List []struct {
			Name  string
			Type  string
			Query json.RawMessage
		}
	}
}

// allPanels are the panels, including those inside rows.
func (d dashboard) allPanels() []panel {
	var out []panel
	var walk func([]panel)
	walk = func(ps []panel) {
		for _, p := range ps {
			out = append(out, p)
			walk(p.Panels)
		}
	}
	walk(d.Panels)
	return out
}

// Every query of every dashboard uses metrics and labels that exist, panel
// IDs and UIDs are unique, and the datasource is the dashboard's variable.
func TestDashboardsUseRealMetrics(t *testing.T) {
	known := registryMetrics(t)
	files, err := filepath.Glob(filepath.Join(repoRoot, "deploy/grafana/dashboards/*.json"))
	if err != nil || len(files) < 5 {
		t.Fatalf("dashboards: %v %v", files, err)
	}
	uids := map[string]bool{}
	for _, file := range files {
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		var d dashboard
		if err := json.Unmarshal(raw, &d); err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		name := filepath.Base(file)
		if d.UID == "" || uids[d.UID] || d.Title == "" || strings.TrimSuffix(name, ".json") != d.UID {
			t.Errorf("%s: uid %q title %q", name, d.UID, d.Title)
		}
		uids[d.UID] = true
		ids := map[int]bool{}
		queries := 0
		for _, p := range d.allPanels() {
			if ids[p.ID] || p.ID == 0 {
				t.Errorf("%s: panel id %d repeated or missing", name, p.ID)
			}
			ids[p.ID] = true
			for _, tg := range p.Targets {
				queries++
				problems, allowed := checkQuery(tg.Expr, known)
				for _, pr := range problems {
					t.Errorf("%s: panel %q: %s (%s)", name, p.Title, pr, tg.Expr)
				}
				for _, m := range legendRE.FindAllStringSubmatch(tg.LegendFormat, -1) {
					if !slices.Contains(allowed, m[1]) {
						t.Errorf("%s: panel %q: legend uses {{%s}}, which the query lacks", name, p.Title, m[1])
					}
				}
				if tg.Datasource.UID != "${datasource}" {
					t.Errorf("%s: panel %q: datasource %q", name, p.Title, tg.Datasource.UID)
				}
			}
		}
		for _, v := range d.Templating.List {
			if v.Type != "query" {
				continue
			}
			var q struct{ Query string }
			if json.Unmarshal(v.Query, &q) != nil || q.Query == "" {
				t.Errorf("%s: variable %s has no query", name, v.Name)
				continue
			}
			queries++
			problems, _ := checkQuery(q.Query, known)
			for _, pr := range problems {
				t.Errorf("%s: variable %s: %s", name, v.Name, pr)
			}
		}
		if queries < 4 {
			t.Errorf("%s: only %d queries", name, queries)
		}
	}
}
