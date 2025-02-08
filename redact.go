package redact

import (
	"context"
	"log/slog"
	"sync"
)

const redactedMask = "[REDACTED]"

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
				newRecord.AddAttrs(slog.String(fieldName, redactedMask))
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
