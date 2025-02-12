package redact

import (
	"bytes"
	"context"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestRedaction(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer

	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})

	pipeline := NewRedactionPipeline()
	pipeline.AddRedactField("email")
	pipeline.AddRedactField("password")

	redactionHandler := NewRedactionHandler(handler, pipeline)

	logger := slog.New(redactionHandler)

	buf.Reset()

	logger.Info(
		"Test message",
		slog.String("username", "Rigoletto"),
		slog.String("email", "foo@bar.qux"),
		slog.String("password", "abc123"),
		slog.Int("other_field", 456),
	)

	output := buf.String()

	assert.Contains(t, output, "username=Rigoletto")
	assert.Contains(t, output, "email=[REDACTED]")
	assert.Contains(t, output, "password=[REDACTED]")
	assert.Contains(t, output, "other_field=456")
}

func TestNewRedactionPipeline(t *testing.T) {
	t.Parallel()

	pipeline := NewRedactionPipeline()

	assert.NotNil(t, pipeline)
	assert.NotNil(t, pipeline.stages)
	assert.Len(t, pipeline.stages, 0)
}

func TestRedactionPipeline_AddRedactField(t *testing.T) {
	t.Parallel()

	pipeline := NewRedactionPipeline()
	pipeline.AddRedactField("test_field")

	assert.Len(t, pipeline.stages, 1)

	var buf bytes.Buffer
	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{})
	redactionHandler := NewRedactionHandler(handler, pipeline)

	logger := slog.New(redactionHandler)
	logger.Info("Test message", slog.String("test_field", "sensitive"))

	output := buf.String()
	assert.Contains(t, output, "test_field=[REDACTED]")
}

func TestRedactionPipeline_Process(t *testing.T) {
	t.Parallel()
	pipeline := NewRedactionPipeline()
	pipeline.AddRedactField("test_field")

	record := slog.NewRecord(time.Time{}.Add(1), slog.LevelInfo, "Test message", 0)

	record.AddAttrs(slog.String("test_field", "sensitive"))
	record.AddAttrs(slog.String("other_field", "not sensitive"))

	redactedRecord := pipeline.Process(context.TODO(), record)

	var (
		redactedFieldValue string
		otherFieldValue    string
	)

	redactedRecord.Attrs(func(a slog.Attr) bool {
		if a.Key == "test_field" {
			redactedFieldValue = a.Value.String()
		}
		if a.Key == "other_field" {
			otherFieldValue = a.Value.String()
		}
		return true
	})

	assert.Equal(t, redactedMask, redactedFieldValue)
	assert.Equal(t, "not sensitive", otherFieldValue)
}

func TestRedactionPipeline_Concurrency(t *testing.T) {
	t.Parallel()

	pipeline := NewRedactionPipeline()

	var wg sync.WaitGroup
	numRoutines := 100

	wg.Add(numRoutines)

	for i := 0; i < numRoutines; i++ {
		go func() {
			defer wg.Done()
			pipeline.AddRedactField("concurrent_field")
			record := slog.NewRecord(
				time.Time{}.Add(1),
				slog.LevelInfo,
				"Test message",
				0,
			)
			record.AddAttrs(slog.String("concurrent_field", "sensitive"))
			ctx := context.TODO()
			_ = pipeline.Process(ctx, record)
		}()
	}
	wg.Wait()

	assert.GreaterOrEqual(t, len(pipeline.stages), numRoutines)
}
