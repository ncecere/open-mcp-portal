// Tracing settings: the standard OpenTelemetry environment variables
// (OTEL_*), read like every other setting (so they may also be keys of the
// YAML file, and the headers may come from a *_FILE), plus TRACE_LINK_TEMPLATE.
// Tracing is off unless an endpoint is set (docs/deploy.md "Tracing").

package config

import (
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"
)

// Tracing configures OpenTelemetry tracing and the link from a call to its
// trace.
type Tracing struct {
	// Exporter is OTEL_TRACES_EXPORTER: "otlp" or "none" (off whatever else is
	// set); empty means otlp when an endpoint is set.
	Exporter string
	// Endpoint is OTEL_EXPORTER_OTLP_ENDPOINT, the OTLP/HTTP base URL
	// ("/v1/traces" is added); TracesEndpoint is OTEL_EXPORTER_OTLP_TRACES_ENDPOINT,
	// the full traces URL, which wins.
	Endpoint, TracesEndpoint string
	// Protocol is OTEL_EXPORTER_OTLP_PROTOCOL: only http/protobuf is spoken.
	Protocol string
	// Headers is OTEL_EXPORTER_OTLP_HEADERS ("key=value,key=value"), sent with
	// every export; it can hold a collector's credentials, so it is a secret
	// setting (never logged or reported).
	Headers string
	// ServiceName is OTEL_SERVICE_NAME.
	ServiceName string
	// Sampler is OTEL_TRACES_SAMPLER; SamplerArg is OTEL_TRACES_SAMPLER_ARG
	// (the ratio of the ratio samplers).
	Sampler    string
	SamplerArg float64
	// LinkTemplate is TRACE_LINK_TEMPLATE: a URL containing {trace_id}, shown on
	// a call's page as the link to its trace.
	LinkTemplate string
}

// Defaults of the tracing settings.
const (
	DefaultTracesSampler    = "parentbased_traceidratio"
	DefaultSamplerArg       = 0.1
	DefaultTraceServiceName = "open-mcp-portal"
	// defaultOTLPEndpoint is the OpenTelemetry default, used when
	// OTEL_TRACES_EXPORTER=otlp names no endpoint.
	defaultOTLPEndpoint = "http://localhost:4318"
)

// tracingSamplers are the accepted OTEL_TRACES_SAMPLER values (the same as
// observability.Samplers; config does not import observability).
var tracingSamplers = []string{"always_on", "always_off", "traceidratio", "parentbased_always_on", "parentbased_always_off", "parentbased_traceidratio"}

// Enabled reports whether spans are exported.
func (t Tracing) Enabled() bool {
	switch t.Exporter {
	case "none":
		return false
	case "otlp":
		return true
	}
	return t.Endpoint != "" || t.TracesEndpoint != ""
}

// URL is the OTLP/HTTP traces URL ("" when tracing is off).
func (t Tracing) URL() string {
	if !t.Enabled() {
		return ""
	}
	if t.TracesEndpoint != "" {
		return t.TracesEndpoint
	}
	base := cmpOr(t.Endpoint, defaultOTLPEndpoint)
	return strings.TrimRight(base, "/") + "/v1/traces"
}

// Host is the collector's host and port, for reports (no path, no
// credentials, no query).
func (t Tracing) Host() string {
	u, err := url.Parse(t.URL())
	if err != nil {
		return ""
	}
	return u.Host
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// HeaderMap parses Headers.
func (t Tracing) HeaderMap() (map[string]string, error) {
	if strings.TrimSpace(t.Headers) == "" {
		return nil, nil
	}
	out := map[string]string{}
	for _, part := range strings.Split(t.Headers, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		k, v, ok := strings.Cut(part, "=")
		k = strings.TrimSpace(k)
		if !ok || k == "" || strings.ContainsAny(k, " \t\r\n:") || strings.ContainsAny(v, "\r\n") {
			// The entry itself may be a secret: it is not repeated.
			return nil, errors.New("OTEL_EXPORTER_OTLP_HEADERS must be key=value pairs separated by commas")
		}
		if u, err := url.PathUnescape(strings.TrimSpace(v)); err == nil {
			v = u
		}
		out[k] = strings.TrimSpace(v)
	}
	return out, nil
}

// TraceLink is the URL of a trace: the template with its {trace_id} filled
// in (a trace ID is 32 hex digits, so it needs no escaping).
func (t Tracing) TraceLink(traceID string) string {
	if t.LinkTemplate == "" || traceID == "" {
		return ""
	}
	return strings.ReplaceAll(t.LinkTemplate, "{trace_id}", traceID)
}

func (t Tracing) validate() []error {
	var errs []error
	if t.Exporter != "" && t.Exporter != "otlp" && t.Exporter != "none" {
		errs = append(errs, errors.New("OTEL_TRACES_EXPORTER must be otlp or none (spans are exported with OTLP over HTTP)"))
	}
	if t.Protocol != "" && t.Protocol != "http/protobuf" {
		errs = append(errs, errors.New("OTEL_EXPORTER_OTLP_PROTOCOL must be http/protobuf (the only protocol spoken)"))
	}
	for _, e := range []struct{ key, v string }{{"OTEL_EXPORTER_OTLP_ENDPOINT", t.Endpoint}, {"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", t.TracesEndpoint}} {
		if e.v == "" {
			continue
		}
		u, err := url.Parse(e.v)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			errs = append(errs, fmt.Errorf("%s must be an http(s) URL without credentials, query or fragment (use OTEL_EXPORTER_OTLP_HEADERS for credentials)", e.key))
		}
	}
	if _, err := t.HeaderMap(); err != nil {
		errs = append(errs, err)
	}
	if t.Sampler != "" && !slices.Contains(tracingSamplers, t.Sampler) {
		errs = append(errs, fmt.Errorf("OTEL_TRACES_SAMPLER must be one of %s", strings.Join(tracingSamplers, ", ")))
	}
	if t.SamplerArg < 0 || t.SamplerArg > 1 {
		errs = append(errs, errors.New("OTEL_TRACES_SAMPLER_ARG must be a ratio from 0 to 1"))
	}
	if strings.ContainsAny(t.ServiceName, " \t\r\n") || len(t.ServiceName) > 100 {
		errs = append(errs, errors.New("OTEL_SERVICE_NAME must be at most 100 characters without spaces"))
	}
	if t.LinkTemplate != "" {
		u, err := url.Parse(t.LinkTemplate)
		switch {
		case err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || hasControl(t.LinkTemplate):
			errs = append(errs, errors.New("TRACE_LINK_TEMPLATE must be an http(s) URL"))
		case strings.Count(t.LinkTemplate, "{trace_id}") != 1:
			errs = append(errs, errors.New("TRACE_LINK_TEMPLATE must contain {trace_id} once, for example https://grafana.example.com/explore?...{trace_id}"))
		}
	}
	return errs
}

func samplerArg(dst func(*Config) *float64) func(*Config, string) error {
	return func(c *Config, v string) error {
		f, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
		if err != nil || f < 0 || f > 1 {
			return fmt.Errorf("must be a ratio from 0 to 1")
		}
		*dst(c) = f
		return nil
	}
}

func lowerStr(dst func(*Config) *string) func(*Config, string) error {
	return func(c *Config, v string) error { *dst(c) = strings.ToLower(strings.TrimSpace(v)); return nil }
}
