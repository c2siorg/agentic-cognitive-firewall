package main

import (
	"context"
	"testing"
	"time"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"

	"github.com/acf-sdk/sidecar/internal/pipeline"
	"github.com/acf-sdk/sidecar/internal/telemetry"
	"github.com/acf-sdk/sidecar/internal/transport"
)

type discardOTelExporter struct{}

func (discardOTelExporter) ExportSpans(
	context.Context,
	[]sdktrace.ReadOnlySpan,
) error {
	return nil
}

func (discardOTelExporter) Shutdown(context.Context) error {
	return nil
}

func BenchmarkOTelTimingCallback(b *testing.B) {
	timing := transport.Timing{
		HookType:  "on_context",
		Decision:  transport.DecisionSanitise,
		RiskScore: 0.63,
		Signals: []string{
			"instruction_override",
			"jailbreak_pattern",
		},
		Pipeline: pipeline.Trace{
			Stages: []pipeline.StageTiming{
				{Name: "validate", Duration: 2 * time.Microsecond},
				{Name: "session", Duration: time.Microsecond},
				{Name: "normalise", Duration: 3 * time.Microsecond},
				{Name: "scan", Duration: 10 * time.Microsecond},
				{Name: "aggregate", Duration: 2 * time.Microsecond},
			},
			Policy:   5 * time.Microsecond,
			Sanitise: 3 * time.Microsecond,
		},
		Total: 30 * time.Microsecond,
	}

	for _, variant := range []string{"noop", "otel_async"} {
		b.Run(variant, func(b *testing.B) {
			var exporter *telemetry.OTelExporter

			callback := func(transport.Timing) {}

			if variant == "otel_async" {
				var err error
				exporter, err = telemetry.NewOTelExporterWithSpanExporter(
					discardOTelExporter{},
				)
				if err != nil {
					b.Fatal(err)
				}

				callback = func(tm transport.Timing) {
					exporter.Record(timingToSpanEvent(tm))
				}
			}

			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				callback(timing)
			}

			b.StopTimer()

			if exporter != nil {
				dropped := exporter.Dropped()

				if err := exporter.Close(); err != nil {
					b.Fatalf("exporter close: %v", err)
				}

				b.ReportMetric(float64(dropped), "dropped")
				b.ReportMetric(
					float64(dropped)/float64(b.N)*100,
					"dropped_pct",
				)
			}
		})
	}
}
