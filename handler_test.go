package redact

import (
	"bytes"
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewRedactionHandler(t *testing.T) {
	t.Parallel()

	handler := slog.NewTextHandler(new(bytes.Buffer), &slog.HandlerOptions{})
	pipeline := NewRedactionPipeline()
	redactionHandler := NewRedactionHandler(handler, pipeline)

	assert.NotNil(t, redactionHandler)
	assert.Equal(t, handler, redactionHandler.handler)
	assert.Equal(t, pipeline, redactionHandler.pipeline)
}

func TestRedactionHandler_Enabled(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer

	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})
	pipeline := NewRedactionPipeline()
	redactionHandler := NewRedactionHandler(handler, pipeline)

	ctx := context.TODO()
	assert.True(t, redactionHandler.Enabled(ctx, slog.LevelInfo))
	assert.False(t, redactionHandler.Enabled(ctx, slog.LevelDebug)) // Because underlying handler is set to Info
}

func TestRedactionHandler_Handle(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer

	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})
	pipeline := NewRedactionPipeline()
	pipeline.AddRedactField("sensitive_data")

	redactionHandler := NewRedactionHandler(handler, pipeline)
	logger := slog.New(redactionHandler)

	logger.Info("Test message", slog.String("sensitive_data", "secret"))

	output := buf.String()

	assert.Contains(t, output, "sensitive_data=[REDACTED]")
}

func TestRedactionHandler_WithAttrs(t *testing.T) {
	t.Parallel()

	handler := slog.NewTextHandler(new(bytes.Buffer), &slog.HandlerOptions{})
	pipeline := NewRedactionPipeline()
	redactionHandler := NewRedactionHandler(handler, pipeline)

	attrs := []slog.Attr{slog.String("key1", "value1")}
	newHandler := redactionHandler.WithAttrs(attrs)

	assert.NotNil(t, newHandler)

	newRedactionHandler, ok := newHandler.(*RedactionHandler)
	assert.True(t, ok)

	assert.Equal(t, pipeline, newRedactionHandler.pipeline)
}

func TestRedactionHandler_WithGroup(t *testing.T) {
	t.Parallel()

	handler := slog.NewTextHandler(new(bytes.Buffer), &slog.HandlerOptions{})
	pipeline := NewRedactionPipeline()
	redactionHandler := NewRedactionHandler(handler, pipeline)

	newHandler := redactionHandler.WithGroup("test_group")

	assert.NotNil(t, newHandler)

	newRedactionHandler, ok := newHandler.(*RedactionHandler)
	assert.True(t, ok)

	assert.Equal(t, pipeline, newRedactionHandler.pipeline)
}
