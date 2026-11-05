package observability

import (
	"github.com/prometheus/client_golang/prometheus"
)

var ScanFindings = prometheus.NewCounterVec(prometheus.CounterOpts{Name: "omp_scan_findings_total", Help: "Definition heuristic findings, without content or object identifiers."}, []string{"stage", "rule", "action"})
var ScanDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "omp_scan_duration_seconds", Help: "Local definition scan duration.", Buckets: []float64{.0001, .0005, .001, .005, .01, .025, .1, 1}}, []string{"stage"})
var ScanIncomplete = prometheus.NewCounterVec(prometheus.CounterOpts{Name: "omp_scan_incomplete_total", Help: "Incomplete definition scans or persistence failures by fixed reason class."}, []string{"stage", "reason"})
var ScanRuleset = prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "omp_scan_ruleset_info", Help: "Definition ruleset compiled into this process."}, []string{"version"})
