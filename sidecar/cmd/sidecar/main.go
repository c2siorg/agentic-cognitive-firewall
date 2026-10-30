// main.go — sidecar entrypoint.
// Phase 2: loads config, builds the enforcement pipeline, and starts the
// IPC listener (UDS on Linux/macOS, named pipe on Windows).
package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/acf-sdk/sidecar/internal/config"
	"github.com/acf-sdk/sidecar/internal/crypto"
	"github.com/acf-sdk/sidecar/internal/pipeline"
	"github.com/acf-sdk/sidecar/internal/policy"
	"github.com/acf-sdk/sidecar/internal/state"
	"github.com/acf-sdk/sidecar/internal/telemetry"
	"github.com/acf-sdk/sidecar/internal/transport"
)

func main() {
	// 1. Load sidecar config (falls back to defaults if sidecar.yaml absent).
	// Config path can be overridden via ACF_CONFIG env var. Otherwise we locate
	// the project root from the current working directory so the sidecar behaves
	// the same from repo root, sidecar/, or nested package directories.
	cwd, err := os.Getwd()
	if err != nil {
		log.Fatalf("sidecar: failed to determine working directory: %v", err)
	}

	configPath := config.ResolveConfigPath(cwd)
	cfg, err := config.LoadOrDefault(configPath)
	if err != nil {
		log.Fatalf("sidecar: config error: %v", err)
	}
	cfg.PolicyDir = config.ResolvePolicyDir(cfg.PolicyDir, configPath, cwd)

	// 2. Load HMAC key from environment.
	signer, err := crypto.NewSignerFromEnv()
	if err != nil {
		log.Fatalf("sidecar: failed to load HMAC key: %v\n"+
			"  Set ACF_HMAC_KEY to a hex-encoded key (min 32 bytes).\n"+
			"  Generate: python3 -c \"import secrets; print(secrets.token_hex(32))\"", err)
	}

	// 3. Start nonce store with 5-minute TTL.
	nonceStore := crypto.NewNonceStore(5 * time.Minute)
	defer nonceStore.Stop()

	// 4. Load jailbreak patterns.
	patterns, err := config.LoadPatterns(cfg.PolicyDir)
	if err != nil {
		log.Printf("sidecar: warning — could not load jailbreak patterns: %v (scan stage will run with no patterns)", err)
		patterns = &config.Patterns{}
	}

	// 5. Initialize OPA policy engine.
	eng, err := policy.NewEngine(cfg.PolicyDir)
	if err != nil {
		log.Fatalf("sidecar: failed to initialize OPA engine: %v\n"+
			"  Check that policy_dir (%s) has valid .rego files and a data/policy_config.yaml "+
			"with a signal_weights table.", err, cfg.PolicyDir)
	}
	defer eng.Stop()
	log.Printf("sidecar: OPA engine ready (policy_dir=%s)", cfg.PolicyDir)

	// Signal weights live in policy_config.yaml. A table left in sidecar.yaml
	// is ignored, so say so rather than dropping a local override silently.
	if n := len(cfg.DeprecatedSignalWeights); n > 0 {
		log.Printf("sidecar: warning — signal_weights in %s is ignored (%d entries); "+
			"weights are read from %s", configPath, n,
			filepath.Join(cfg.PolicyDir, "data", "policy_config.yaml"))
	}

	// A pattern category with no weight scores 0.0, so a match in it can never
	// change a verdict. Surface that once at startup, not per request.
	if missing := unweightedCategories(patterns.Entries, eng.SignalWeights()); len(missing) > 0 {
		log.Printf("sidecar: warning — %d jailbreak pattern categories have no signal weight "+
			"and will score 0.0: %s", len(missing), strings.Join(missing, ", "))
	}

	// 6. Build the enforcement pipeline. The session stage runs after validate
	// so it only ever sees a known hook, and records each decision afterwards.
	sessions := state.NewTTLStore(
		time.Duration(cfg.Session.TTLSeconds)*time.Second, cfg.Session.MaxSessions)
	defer sessions.Stop()
	sessionStage := pipeline.NewSessionStage(sessions)
	pl := pipeline.NewWithEvaluator(cfg, []pipeline.Stage{
		pipeline.NewValidateStage(),
		sessionStage,
		pipeline.NewNormaliseStage(),
		pipeline.NewScanStage(cfg, patterns.Entries),
		pipeline.NewAggregateStage(cfg, eng),
	}, eng).OnDecision(sessionStage)

	mode := "strict"
	if !cfg.Pipeline.StrictMode {
		mode = "non-strict"
	}
	log.Printf("sidecar: pipeline ready (mode=%s, block_threshold=%.2f)", mode, cfg.Thresholds.BlockScore)

	// 7. Resolve IPC address (platform-specific default if unset).
	connector := transport.DefaultConnector()
	address := connector.DefaultAddress()
	if p := os.Getenv("ACF_SOCKET_PATH"); p != "" {
		address = p
	} else if cfg.SocketPath != "" {
		address = cfg.SocketPath
	}

	// Optional timing log used for overhead measurements.
	var timingRecord func(transport.Timing)

	if p := os.Getenv("ACF_TIMING_LOG"); p != "" {
		tl, err := telemetry.NewTimingLog(p)
		if err != nil {
			log.Fatalf("sidecar: failed to open timing log %s: %v", p, err)
		}

		defer func() {
			if err := tl.Close(); err != nil {
				log.Printf("sidecar: timing log close: %v", err)
			}
			if n := tl.Dropped(); n > 0 {
				log.Printf("sidecar: timing log dropped %d records", n)
			}
		}()

		timingRecord = tl.Record
		log.Printf("sidecar: timing log enabled (%s)", p)
	}

	// Optional OpenTelemetry exporter.
	var otelExporter *telemetry.OTelExporter

	if endpoint := os.Getenv("ACF_OTEL_ENDPOINT"); endpoint != "" {
		exporter, err := telemetry.NewOTelExporter(
			context.Background(),
			endpoint,
		)
		if err != nil {
			// Observability failures must not prevent enforcement from starting.
			log.Printf("sidecar: OpenTelemetry disabled: %v", err)
		} else {
			otelExporter = exporter

			defer func() {
				if err := otelExporter.Close(); err != nil {
					log.Printf("sidecar: OpenTelemetry close: %v", err)
				}
				if n := otelExporter.Dropped(); n > 0 {
					log.Printf("sidecar: OpenTelemetry dropped %d events", n)
				}
			}()

			log.Printf("sidecar: OpenTelemetry enabled (%s)", endpoint)
		}
	}

	// The transport callback only records to non-blocking queues.
	var onTiming func(transport.Timing)

	if timingRecord != nil || otelExporter != nil {
		onTiming = func(tm transport.Timing) {
			if timingRecord != nil {
				timingRecord(tm)
			}
			if otelExporter != nil {
				otelExporter.Record(timingToSpanEvent(tm))
			}
		}
	}
	// 8. Create and start listener.
	ln, err := transport.NewListener(transport.Config{
		Address:    address,
		Connector:  connector,
		Signer:     signer,
		NonceStore: nonceStore,
		Pipeline:   pl,
		OnTiming:   onTiming,
	})
	if err != nil {
		log.Fatalf("sidecar: failed to create listener on %s: %v", address, err)
	}

	log.Printf("sidecar: listening on %s", address)

	// 8. Serve in background; block on shutdown signal.
	serveErr := make(chan error, 1)
	go func() { serveErr <- ln.Serve() }()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	select {
	case sig := <-sigCh:
		log.Printf("sidecar: received %s, shutting down", sig)
		ln.Stop()
	case err := <-serveErr:
		if err != nil {
			log.Fatalf("sidecar: listener error: %v", err)
		}
	}
}
func timingToSpanEvent(tm transport.Timing) telemetry.SpanEvent {
	decisionName := "UNKNOWN"

	switch tm.Decision {
	case transport.DecisionAllow:
		decisionName = "ALLOW"
	case transport.DecisionSanitise:
		decisionName = "SANITISE"
	case transport.DecisionBlock:
		decisionName = "BLOCK"
	}

	stages := make(
		[]telemetry.StageEvent,
		0,
		len(tm.Pipeline.Stages)+2,
	)

	for _, stage := range tm.Pipeline.Stages {
		stages = append(stages, telemetry.StageEvent{
			Name:     stage.Name,
			Duration: stage.Duration,
		})
	}

	if tm.Pipeline.Policy > 0 {
		stages = append(stages, telemetry.StageEvent{
			Name:     "opa",
			Duration: tm.Pipeline.Policy,
		})
	}

	if tm.Pipeline.Sanitise > 0 {
		stages = append(stages, telemetry.StageEvent{
			Name:     "executor",
			Duration: tm.Pipeline.Sanitise,
		})
	}

	return telemetry.SpanEvent{
		HookType:  tm.HookType,
		Decision:  decisionName,
		RiskScore: tm.RiskScore,
		Signals:   tm.Signals,
		Stages:    stages,
		Total:     tm.Total,
	}
}

// unweightedCategories returns the sorted pattern categories with no entry in
// weights. Entries without a category fall back to jailbreak_pattern in the
// scan stage, so they are skipped here.
func unweightedCategories(entries []config.PatternEntry, weights map[string]float64) []string {
	seen := map[string]bool{}
	var missing []string
	for _, e := range entries {
		if e.Category == "" || seen[e.Category] {
			continue
		}
		seen[e.Category] = true
		if _, ok := weights[e.Category]; !ok {
			missing = append(missing, e.Category)
		}
	}
	sort.Strings(missing)
	return missing
}
