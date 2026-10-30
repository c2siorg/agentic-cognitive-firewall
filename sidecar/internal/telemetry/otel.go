package telemetry

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

const (
	defaultQueueSize = 256
	spanQueueSize    = 128
)

var ErrTelemetryClosed = errors.New("telemetry exporter is closed")

// SpanEvent contains approved metadata only.
// Never add raw payloads, session IDs, or canonical text.
type SpanEvent struct {
	HookType  string
	Decision  string
	RiskScore float64
	Signals   []string
	Stages    []StageEvent
	Total     time.Duration
}

type StageEvent struct {
	Name     string
	Duration time.Duration
}

type OTelExporter struct {
	queue   chan SpanEvent
	dropped atomic.Uint64
	stop    chan struct{}
	done    chan struct{}

	once     sync.Once
	gate     sync.RWMutex
	closed   bool
	tp       *sdktrace.TracerProvider
	closeErr error
}

// NewOTelExporter expects an endpoint such as localhost:4318,
// without the http:// scheme.
func NewOTelExporter(ctx context.Context, endpoint string) (*OTelExporter, error) {
	if endpoint == "" {
		return nil, errors.New("OpenTelemetry endpoint cannot be empty")
	}

	exp, err := otlptracehttp.New(ctx,
		otlptracehttp.WithEndpoint(endpoint),
		otlptracehttp.WithInsecure(),
	)
	if err != nil {
		return nil, err
	}

	return NewOTelExporterWithSpanExporter(exp)
}

// NewOTelExporterWithSpanExporter allows custom exporters,
// including in-memory exporters for tests and benchmarks.
func NewOTelExporterWithSpanExporter(exp sdktrace.SpanExporter) (*OTelExporter, error) {
	if exp == nil {
		return nil, errors.New("OpenTelemetry span exporter cannot be nil")
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp, sdktrace.WithMaxQueueSize(spanQueueSize)),
	)

	e := &OTelExporter{
		queue: make(chan SpanEvent, defaultQueueSize),
		stop:  make(chan struct{}),
		done:  make(chan struct{}),
		tp:    tp,
	}

	go e.run()
	return e, nil
}

// Record never waits for queue capacity or network export.
func (e *OTelExporter) Record(event SpanEvent) {
	if e == nil {
		return
	}

	// Copy slices to prevent callers from mutating queued events.
	event.Signals = append([]string(nil), event.Signals...)
	event.Stages = append([]StageEvent(nil), event.Stages...)

	// The read lock prevents shutdown from racing with a queue send.
	e.gate.RLock()
	defer e.gate.RUnlock()

	if e.closed {
		e.dropped.Add(1)
		return
	}

	select {
	case e.queue <- event:
	default:
		// Never block the enforcement request.
		e.dropped.Add(1)
	}
}

func (e *OTelExporter) Dropped() uint64 {
	if e == nil {
		return 0
	}
	return e.dropped.Load()
}

func (e *OTelExporter) run() {
	defer close(e.done)

	tracer := e.tp.Tracer("acf.sidecar")

	for {
		select {
		case event := <-e.queue:
			e.emit(tracer, event)

		case <-e.stop:
			// Record can no longer enqueue after shutdown begins.
			// Drain every event already accepted by the queue.
			for {
				select {
				case event := <-e.queue:
					e.emit(tracer, event)
				default:
					e.closeErr = e.flush()
					return
				}
			}
		}
	}
}

func (e *OTelExporter) emit(
	tracer trace.Tracer,
	event SpanEvent,
) {
	ctx, parent := tracer.Start(
		context.Background(),
		"acf.enforcement",
		trace.WithAttributes(
			attribute.String("acf.hook_type", safeHook(event.HookType)),
			attribute.String("acf.decision", event.Decision),
			attribute.Float64("acf.risk_score", event.RiskScore),
			attribute.Int64(
				"acf.total_latency_ns",
				event.Total.Nanoseconds(),
			),
			attribute.StringSlice("acf.signals", safeSignals(event.Signals)),
		),
	)
	defer parent.End()

	// Use the parent context so every stage span belongs to the
	// same enforcement trace.
	for _, stage := range event.Stages {
		name := safeStageName(stage.Name)

		_, child := tracer.Start(
			ctx,
			"acf.stage."+name,
			trace.WithAttributes(
				attribute.String("acf.stage", name),
				attribute.String("acf.hook_type", safeHook(event.HookType)),
				attribute.String("acf.decision", event.Decision),
				attribute.Float64("acf.risk_score", event.RiskScore),
				attribute.Int64(
					"acf.latency_ns",
					stage.Duration.Nanoseconds(),
				),
			),
		)
		child.End()
	}
}

// Only stable, non-content metadata is allowed in category attributes.
func safeSignals(signals []string) []string {
	const maxSignals = 32

	result := make([]string, 0, min(len(signals), maxSignals))
	seen := make(map[string]struct{})

	for _, signal := range signals {
		if len(result) >= maxSignals {
			break
		}
		if !safeToken(signal, 64) {
			continue
		}
		if _, exists := seen[signal]; exists {
			continue
		}

		seen[signal] = struct{}{}
		result = append(result, signal)
	}

	return result
}

func safeHook(hook string) string {
	if safeToken(hook, 32) {
		return hook
	}
	return "unknown"
}

func safeStageName(name string) string {
	if safeToken(name, 32) {
		return name
	}
	return "unknown"
}

func safeToken(value string, maxLength int) bool {
	if value == "" || len(value) > maxLength {
		return false
	}

	for _, r := range value {
		if (r >= 'a' && r <= 'z') ||
			(r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') ||
			r == '_' || r == '-' || r == ':' || r == '.' {
			continue
		}
		return false
	}

	return true
}

func (e *OTelExporter) flush() error {
	ctx, cancel := context.WithTimeout(
		context.Background(),
		5*time.Second,
	)
	defer cancel()

	flushErr := e.tp.ForceFlush(ctx)
	shutdownErr := e.tp.Shutdown(ctx)

	return errors.Join(flushErr, shutdownErr)
}

// Close stops accepting events, drains the queue, and shuts down the SDK.
func (e *OTelExporter) Close() error {
	if e == nil {
		return nil
	}

	e.once.Do(func() {
		e.gate.Lock()
		e.closed = true
		close(e.stop)
		e.gate.Unlock()
	})

	select {
	case <-e.done:
		return e.closeErr
	case <-time.After(6 * time.Second):
		return context.DeadlineExceeded
	}
}
