// Package observability exposes Prometheus metrics (docs/phase6-operations.md
// "Metrics", decision 35), following Grounded's internal/observability.
//
// Metrics are package-level so a service records one without wiring;
// NewMetrics registers them in the process registry, which METRICS_ADDR
// serves at /metrics on its own listener (off by default). Labels are
// low-cardinality by rule: methods from a fixed list, outcomes, limit keys,
// rule names, route patterns, kinds, and gateway, server and provider slugs
// of existing objects bounded by METRICS_MAX_OBJECTS. Never user, key,
// service account, team or request IDs.
package observability

import (
	"context"
	"net/http"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/ncecere/open-mcp-portal/internal/buildinfo"
)

// callBuckets are the usage rollups' latency buckets, in seconds.
var callBuckets = []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10, 30, 60, 120}

// httpBuckets suit API requests.
var httpBuckets = []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10, 30, 60}

var (
	BuildInfo = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "omp_build_info",
		Help: "Always 1: the binary's version and commit.",
	}, []string{"version", "commit"})

	MCPRequests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "omp_mcp_requests_total",
		Help: "Requests to /mcp/{slug} that passed gateway resolution, by MCP method (fixed list, else other) and outcome.",
	}, []string{"method", "outcome"})
	MCPRequestDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "omp_mcp_request_duration_seconds",
		Help:    "Time to answer /mcp/{slug} requests, by MCP method and outcome.",
		Buckets: callBuckets,
	}, []string{"method", "outcome"})
	MCPCallDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "omp_mcp_call_duration_seconds",
		Help:    "Latency of forwarded calls by gateway and server slug (bounded by METRICS_MAX_OBJECTS, else other).",
		Buckets: callBuckets,
	}, []string{"gateway", "server"})
	MCPRateLimited = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "omp_mcp_rate_limited_total",
		Help: "Requests to /mcp/{slug} refused by a rate limit, by limit.",
	}, []string{"limit"})

	PayloadCaptures = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "omp_payload_captures_total",
		Help: "Calls whose arguments and result were captured.",
	})
	PayloadRedactions = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "omp_payload_redactions_total",
		Help: "Values redacted in captured payloads, by rule (built-in rule name, sensitive_keys, call_secrets or pattern).",
	}, []string{"rule"})
	PayloadCaptureErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "omp_payload_capture_errors_total",
		Help: "Captures that failed (the call itself was served and recorded).",
	})

	ProviderTokenRefresh = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "omp_provider_token_refresh_total",
		Help: "Refreshes of people's provider tokens by provider slug and result (ok, refused, unavailable).",
	}, []string{"provider", "result"})

	// MachineTokenRequests counts requests to a token endpoint for a server in
	// machine_oauth mode (decision 73), not cache hits.
	MachineTokenRequests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "omp_machine_token_requests_total",
		Help: "Machine OAuth token requests (client credentials grant) by result (ok, refused, unavailable); cache hits are not counted.",
	}, []string{"result"})

	ServerHealthChecks = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "omp_server_health_checks_total",
		Help: "Scheduled health checks of MCP servers by result (healthy, failing).",
	}, []string{"result"})

	HTTPRequests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "omp_http_requests_total",
		Help: "HTTP requests by route pattern, method and status class (2xx, 3xx, 4xx, 5xx).",
	}, []string{"route", "method", "code"})
	HTTPRequestDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "omp_http_request_duration_seconds",
		Help:    "HTTP request latency by route pattern, method and status class.",
		Buckets: httpBuckets,
	}, []string{"route", "method", "code"})

	RetentionDeleted = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "omp_retention_deleted_total",
		Help: "Rows deleted by the retention loop, by kind.",
	}, []string{"kind"})
	RetentionLastSuccess = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "omp_retention_last_success_timestamp_seconds",
		Help: "When this replica last purged a kind without error (Unix time).",
	}, []string{"kind"})
	UsageRollupLastSuccess = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "omp_usage_rollup_last_success_timestamp_seconds",
		Help: "When this replica last completed the usage rollup (Unix time).",
	})
	LoopLeader = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "omp_loop_leader",
		Help: "1 when this replica led the loop's latest run (retention, usage_rollup), else 0.",
	}, []string{"loop"})
)

func appCollectors() []prometheus.Collector {
	return append([]prometheus.Collector{BuildInfo, MCPRequests, MCPRequestDuration, MCPCallDuration, MCPRateLimited, PayloadCaptures,
		PayloadRedactions, PayloadCaptureErrors, ProviderTokenRefresh, MachineTokenRequests, ServerHealthChecks, HTTPRequests, HTTPRequestDuration,
		RetentionDeleted, RetentionLastSuccess, UsageRollupLastSuccess, LoopLeader}, v02Collectors()...)
}

// Metrics owns a registry with the Go and process collectors, the
// application metrics, the pool and server-state collectors.
type Metrics struct {
	registry *prometheus.Registry
}

// NewMetrics registers everything (pool may be nil).
func NewMetrics(pool *pgxpool.Pool) *Metrics {
	r := prometheus.NewRegistry()
	r.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	r.MustRegister(appCollectors()...)
	r.MustRegister(NewPoolCollector(pool), NewServerStateCollector(pool))
	BuildInfo.Reset()
	BuildInfo.WithLabelValues(buildinfo.Version, buildinfo.Commit).Set(1)
	return &Metrics{registry: r}
}

// Handler serves /metrics.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{Registry: m.registry})
}

// Gather is the registry's Gather (tests).
func (m *Metrics) Gather() prometheus.Gatherer { return m.registry }

// MCP methods with their own label value.
var mcpMethods = []string{"initialize", "ping", "tools/list", "tools/call", "prompts/list", "prompts/get", "resources/list",
	"resources/templates/list", "resources/read", "notification"}

// MCPMethod maps a method to its label (other for anything else).
func MCPMethod(m string) string {
	if slices.Contains(mcpMethods, m) {
		return m
	}
	return "other"
}

// ObserveMCP records a request to /mcp/{slug}.
func ObserveMCP(method, outcome string, d time.Duration) {
	m := MCPMethod(method)
	MCPRequests.WithLabelValues(m, outcome).Inc()
	MCPRequestDuration.WithLabelValues(m, outcome).Observe(d.Seconds())
}

// ObserveCall records a forwarded call's latency.
func ObserveCall(gateway, server string, d time.Duration) {
	MCPCallDuration.WithLabelValues(Gateways.Label(gateway), Servers.Label(server)).Observe(d.Seconds())
}

// ObserveHTTP records one completed request; route is the matched pattern
// (never the raw path).
func ObserveHTTP(route, method string, status int, d time.Duration) {
	if route == "" {
		route = "unmatched"
	}
	code := strconv.Itoa(status/100) + "xx"
	HTTPRequests.WithLabelValues(route, method, code).Inc()
	HTTPRequestDuration.WithLabelValues(route, method, code).Observe(d.Seconds())
}

// ObserveProviderRefresh records a provider token refresh (result ok,
// refused or unavailable).
func ObserveProviderRefresh(provider, result string) {
	ProviderTokenRefresh.WithLabelValues(Providers.Label(provider), result).Inc()
}

// SetLeader records whether this replica led a loop's latest run.
func SetLeader(loop string, leader bool) {
	v := 0.0
	if leader {
		v = 1
	}
	LoopLeader.WithLabelValues(loop).Set(v)
}

// Other is the label of objects beyond the bound.
const Other = "other"

// BoundedLabels keeps the label values of existing objects (gateway,
// server or provider slugs), at most Max; others are Other. Sync replaces
// the set with the objects that exist and deletes series of the rest.
type BoundedLabels struct {
	mu    sync.Mutex
	max   int
	known map[string]bool
	// deleters remove a value's series from the metrics that use it.
	deleters []func(value string)
}

// NewBoundedLabels returns an empty set of at most max values.
func NewBoundedLabels(max int, deleters ...func(value string)) *BoundedLabels {
	return &BoundedLabels{max: max, known: map[string]bool{}, deleters: deleters}
}

// SetMax changes the bound (METRICS_MAX_OBJECTS).
func (b *BoundedLabels) SetMax(n int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.max = n
}

// Label is v when it is known or there is room for it, else Other.
func (b *BoundedLabels) Label(v string) string {
	if v == "" {
		return Other
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.known[v] {
		return v
	}
	if len(b.known) < b.max {
		b.known[v] = true
		return v
	}
	return Other
}

// Sync keeps the values of existing objects (the first max of them) and
// deletes the series of values that are gone.
func (b *BoundedLabels) Sync(existing []string) {
	b.mu.Lock()
	keep := map[string]bool{}
	for _, v := range existing {
		if len(keep) >= b.max {
			break
		}
		keep[v] = true
	}
	var gone []string
	for v := range b.known {
		if !keep[v] {
			gone = append(gone, v)
		}
	}
	b.known = keep
	deleters := b.deleters
	b.mu.Unlock()
	for _, v := range gone {
		for _, d := range deleters {
			d(v)
		}
	}
}

// Label sets of existing objects.
var (
	Gateways = NewBoundedLabels(200, func(v string) {
		MCPCallDuration.DeletePartialMatch(prometheus.Labels{"gateway": v})
	})
	Servers = NewBoundedLabels(200, func(v string) {
		MCPCallDuration.DeletePartialMatch(prometheus.Labels{"server": v})
	})
	Providers = NewBoundedLabels(200, func(v string) {
		ProviderTokenRefresh.DeletePartialMatch(prometheus.Labels{"provider": v})
	})
)

// SetMaxObjects applies METRICS_MAX_OBJECTS.
func SetMaxObjects(n int) {
	for _, b := range []*BoundedLabels{Gateways, Servers, Providers} {
		b.SetMax(n)
	}
}

// SyncObjects reads the slugs of existing gateways, servers and providers
// and drops series of deleted ones.
func SyncObjects(ctx context.Context, pool *pgxpool.Pool) error {
	for _, it := range []struct {
		sql string
		set *BoundedLabels
	}{
		{"SELECT slug FROM gateways ORDER BY slug", Gateways},
		{"SELECT slug FROM mcp_servers ORDER BY slug", Servers},
		{"SELECT slug FROM auth_providers ORDER BY slug", Providers},
	} {
		rows, err := pool.Query(ctx, it.sql)
		if err != nil {
			return err
		}
		var slugs []string
		for rows.Next() {
			var s string
			if err := rows.Scan(&s); err != nil {
				rows.Close()
				return err
			}
			slugs = append(slugs, s)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		it.set.Sync(slugs)
	}
	return nil
}
