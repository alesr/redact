package redact

import (
	"context"
	"log/slog"
	"sync"
)

const redactedValue = "[REDACTED]"

// RedactionHandler is a custom slog.Handler that applies a redaction pipeline.
type RedactionHandler struct {
	handler  slog.Handler
	pipeline *RedactionPipeline
}

// NewRedactionHandler initializes a new RedactionHandler.
func NewRedactionHandler(handler slog.Handler, pipeline *RedactionPipeline) *RedactionHandler {
	return &RedactionHandler{
		handler:  handler,
		pipeline: pipeline,
	}
}

// Enabled reports whether the handler is enabled for the given level.
// Necessary to implement the slog.Handler interface.
func (h *RedactionHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.handler.Enabled(ctx, level)
}

// Handle processes the log record through the redaction pipeline before handling it
func (h *RedactionHandler) Handle(ctx context.Context, r slog.Record) error {
	redactedRecord := h.pipeline.Process(ctx, r)
	return h.handler.Handle(ctx, redactedRecord)
}

// WithAttrs returns a new handler with additional attributes.
func (h *RedactionHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &RedactionHandler{
		handler:  h.handler.WithAttrs(attrs),
		pipeline: h.pipeline,
	}
}

// WithGroup returns a new handler with the specified group.
func (h *RedactionHandler) WithGroup(name string) slog.Handler {
	return &RedactionHandler{
		handler:  h.handler.WithGroup(name),
		pipeline: h.pipeline,
	}
}

// RedactionFunc defines the signature for redaction functions.
type RedactionFunc func(ctx context.Context, r slog.Record) slog.Record

// RedactionPipeline manages a list of redaction stages.
type RedactionPipeline struct {
	mu     sync.RWMutex
	stages []RedactionFunc
}

// NewRedactionPipeline initializes a new redaction pipeline.
func NewRedactionPipeline() *RedactionPipeline {
	return &RedactionPipeline{
		stages: make([]RedactionFunc, 0),
	}
}

// AddRedactField adds a redaction stage for a specific field.
func (p *RedactionPipeline) AddRedactField(fieldName string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.stages = append(p.stages, func(ctx context.Context, r slog.Record) slog.Record {
		var attrs []slog.Attr
		r.Attrs(func(a slog.Attr) bool {
			attrs = append(attrs, a)
			return true
		})

		newRecord := slog.NewRecord(r.Time, r.Level, r.Message, r.PC)

		for _, a := range attrs {
			if a.Key == fieldName {
				newRecord.AddAttrs(slog.String(fieldName, redactedValue))
			} else {
				newRecord.AddAttrs(a)
			}
		}
		return newRecord
	})
}

// Process applies all redaction stages to the log record.
func (p *RedactionPipeline) Process(ctx context.Context, r slog.Record) slog.Record {
	p.mu.RLock()
	defer p.mu.RUnlock()
	for _, stage := range p.stages {
		r = stage(ctx, r)
	}
	return r
}
