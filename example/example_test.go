package example

import (
	"bytes"
	"fmt"
	"log/slog"

	"github.com/alesr/redact"
)

func ExampleNewRedactionPipeline() {
	// Create a buffer to capture the log output
	var buf bytes.Buffer

	// Create a base handler that writes to the buffer
	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{
		Level: slog.LevelInfo,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			// Remove the time attribute
			if a.Key == slog.TimeKey {
				return slog.Attr{}
			}
			return a
		},
	})

	// Create a redaction pipeline
	pipeline := redact.NewRedactionPipeline()
	pipeline.AddRedactField("email")
	pipeline.AddRedactField("password")

	// Create a RedactionHandler that wraps the original handler
	redactionHandler := redact.NewRedactionHandler(handler, pipeline)

	// Create a logger with the RedactionHandler
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
	fmt.Print(output)

	// Output: level=INFO msg="Test message" username=Rigoletto email=[REDACTED] password=[REDACTED] other_field=456
}
