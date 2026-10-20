package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Tracing is off by default and by every setting that does not name an
// endpoint; the standard OTEL_* variables turn it on.
func TestTracingSettings(t *testing.T) {
	c, err := LoadFrom("", env(map[string]string{}))
	if err != nil || c.Tracing.Enabled() || c.Tracing.URL() != "" || c.Tracing.Sampler != DefaultTracesSampler || c.Tracing.SamplerArg != DefaultSamplerArg {
		t.Fatalf("defaults: %+v %v", c.Tracing, err)
	}
	c, err = LoadFrom("", env(map[string]string{"OTEL_EXPORTER_OTLP_ENDPOINT": "http://collector.monitoring:4318/", "OTEL_TRACES_SAMPLER": "ParentBased_TraceIDRatio",
		"OTEL_TRACES_SAMPLER_ARG": "0.25", "OTEL_SERVICE_NAME": "omp-prod", "TRACE_LINK_TEMPLATE": "https://grafana.example.com/trace/{trace_id}"}))
	if err != nil {
		t.Fatal(err)
	}
	tr := c.Tracing
	if !tr.Enabled() || tr.URL() != "http://collector.monitoring:4318/v1/traces" || tr.Host() != "collector.monitoring:4318" || tr.Sampler != "parentbased_traceidratio" ||
		tr.SamplerArg != 0.25 || tr.ServiceName != "omp-prod" || tr.TraceLink("abc") != "https://grafana.example.com/trace/abc" || tr.TraceLink("") != "" {
		t.Errorf("%+v", tr)
	}
	// The traces endpoint is used as it is and wins; "none" turns it all off;
	// OTEL_TRACES_EXPORTER=otlp alone uses the OpenTelemetry default endpoint.
	for _, tc := range []struct {
		env     map[string]string
		enabled bool
		url     string
	}{
		{map[string]string{"OTEL_EXPORTER_OTLP_ENDPOINT": "http://a:4318", "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": "https://b.example.com/otlp/traces"}, true, "https://b.example.com/otlp/traces"},
		{map[string]string{"OTEL_EXPORTER_OTLP_ENDPOINT": "http://a:4318", "OTEL_TRACES_EXPORTER": "none"}, false, ""},
		{map[string]string{"OTEL_TRACES_EXPORTER": "otlp"}, true, "http://localhost:4318/v1/traces"},
		{map[string]string{"OTEL_TRACES_SAMPLER": "always_on"}, false, ""},
	} {
		c, err := LoadFrom("", env(tc.env))
		if err != nil || c.Tracing.Enabled() != tc.enabled || c.Tracing.URL() != tc.url {
			t.Errorf("%v: enabled=%v url=%q err=%v", tc.env, c.Tracing.Enabled(), c.Tracing.URL(), err)
		}
	}
	// The YAML file takes the same keys.
	path := filepath.Join(t.TempDir(), "c.yaml")
	if err := os.WriteFile(path, []byte("otel_exporter_otlp_endpoint: http://yaml:4318\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if c, err := LoadFrom(path, env(map[string]string{})); err != nil || c.Tracing.URL() != "http://yaml:4318/v1/traces" {
		t.Errorf("yaml: %+v %v", c.Tracing, err)
	}
}

// The export headers can carry a collector's credentials: they come from a
// file like other secrets, and a malformed value is refused without repeating
// it.
func TestTracingHeadersAreSecret(t *testing.T) {
	path := filepath.Join(t.TempDir(), "headers")
	if err := os.WriteFile(path, []byte("authorization=Bearer%20tok, x-team=a\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := LoadFrom("", env(map[string]string{"OTEL_EXPORTER_OTLP_HEADERS_FILE": path}))
	if err != nil {
		t.Fatal(err)
	}
	h, err := c.Tracing.HeaderMap()
	if err != nil || h["authorization"] != "Bearer tok" || h["x-team"] != "a" || len(h) != 2 {
		t.Errorf("%v %v", h, err)
	}
	c = smtpBase()
	c.Tracing.Headers = "sentinel-secret-without-equals"
	err = c.Validate("serve")
	if err == nil || !strings.Contains(err.Error(), "OTEL_EXPORTER_OTLP_HEADERS") || strings.Contains(err.Error(), "sentinel") {
		t.Errorf("a malformed value: %v", err)
	}
}

func TestTracingValidation(t *testing.T) {
	for name, tc := range map[string]struct {
		set  func(*Tracing)
		want string
	}{
		"valid":                {func(t *Tracing) { t.Endpoint = "http://otel:4318"; t.Sampler = "always_off" }, ""},
		"bad exporter":         {func(t *Tracing) { t.Exporter = "jaeger" }, "OTEL_TRACES_EXPORTER"},
		"grpc":                 {func(t *Tracing) { t.Protocol = "grpc" }, "OTEL_EXPORTER_OTLP_PROTOCOL"},
		"credentials in url":   {func(t *Tracing) { t.Endpoint = "https://u:p@otel:4318" }, "without credentials"},
		"not http":             {func(t *Tracing) { t.Endpoint = "otel:4318" }, "OTEL_EXPORTER_OTLP_ENDPOINT"},
		"query in traces url":  {func(t *Tracing) { t.TracesEndpoint = "https://otel/v1/traces?key=x" }, "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"},
		"unknown sampler":      {func(t *Tracing) { t.Sampler = "tail" }, "OTEL_TRACES_SAMPLER must"},
		"ratio out of range":   {func(t *Tracing) { t.SamplerArg = 2 }, "OTEL_TRACES_SAMPLER_ARG"},
		"service name":         {func(t *Tracing) { t.ServiceName = "two words" }, "OTEL_SERVICE_NAME"},
		"link without id":      {func(t *Tracing) { t.LinkTemplate = "https://grafana.example.com/explore" }, "{trace_id}"},
		"link twice":           {func(t *Tracing) { t.LinkTemplate = "https://g/{trace_id}/{trace_id}" }, "{trace_id}"},
		"link script":          {func(t *Tracing) { t.LinkTemplate = "javascript:alert('{trace_id}')" }, "TRACE_LINK_TEMPLATE must be an http(s) URL"},
		"link with credential": {func(t *Tracing) { t.LinkTemplate = "https://u:p@g/{trace_id}" }, "TRACE_LINK_TEMPLATE must be an http(s) URL"},
		"valid link":           {func(t *Tracing) { t.LinkTemplate = "https://g.example.com/explore?left=%7B%22q%22:%22{trace_id}%22%7D" }, ""},
	} {
		c := smtpBase()
		tc.set(&c.Tracing)
		err := c.Validate("serve")
		switch {
		case tc.want == "" && err != nil:
			t.Errorf("%s: %v", name, err)
		case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
			t.Errorf("%s: %v, want %q", name, err, tc.want)
		}
	}
}
