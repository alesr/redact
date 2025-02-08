package redact

import (
	"context"
	"log/slog"
)

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
