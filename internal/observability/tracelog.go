package observability

import (
	"context"
	"log/slog"

	"go.opentelemetry.io/otel/trace"
)

// NewTraceLogHandler wraps a slog handler so that a record logged with the
// context of a sampled span carries trace_id and span_id, beside request_id.
// Records of requests that are not traced are unchanged.
func NewTraceLogHandler(h slog.Handler) slog.Handler { return traceLogHandler{h} }

type traceLogHandler struct{ slog.Handler }

func (h traceLogHandler) Handle(ctx context.Context, r slog.Record) error {
	if sc := trace.SpanContextFromContext(ctx); sc.IsValid() && sc.IsSampled() {
		r.AddAttrs(slog.String("trace_id", sc.TraceID().String()), slog.String("span_id", sc.SpanID().String()))
	}
	return h.Handler.Handle(ctx, r)
}

func (h traceLogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return traceLogHandler{h.Handler.WithAttrs(attrs)}
}

func (h traceLogHandler) WithGroup(name string) slog.Handler {
	return traceLogHandler{h.Handler.WithGroup(name)}
}
