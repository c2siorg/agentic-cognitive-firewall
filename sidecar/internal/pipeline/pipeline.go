// Package pipeline orchestrates the four enforcement stages in order:
// validate → normalise → scan → aggregate.
//
// In strict mode (default), the pipeline short-circuits and returns BLOCK
// immediately when any stage emits a hard block signal. In non-strict mode,
// all stages run regardless and the full signal set is collected before the
// final decision is made. Non-strict mode is useful for debugging, auditing,
// and policy development.
//
// Phase 2: the final decision is derived from the aggregate score vs thresholds.
// OPA evaluation is wired in Phase 3.
package pipeline

import (
	"encoding/json"
	"log"
	"time"

	"github.com/acf-sdk/sidecar/internal/clock"
	"github.com/acf-sdk/sidecar/internal/config"
	"github.com/acf-sdk/sidecar/internal/policy"
	"github.com/acf-sdk/sidecar/pkg/decision"
	"github.com/acf-sdk/sidecar/pkg/riskcontext"
)

// Result is the output of a pipeline run.
type Result struct {
	// Decision is one of transport.DecisionAllow, DecisionSanitise, DecisionBlock.
	Decision byte
	// Score is the final aggregated risk score (0.0–1.0).
	Score float64
	// Signals is the full list of signals emitted during the run, with scores
	// back-filled by the aggregate stage.
	Signals []riskcontext.Signal
	// BlockedAt names the stage that produced the first hard block signal,
	// or empty if no hard block occurred.
	BlockedAt string
	// SanitisedPayload is the transformed payload returned to the client when
	// decision == Sanitise. Nil for Allow and Block decisions.
	SanitisedPayload []byte
}

// Trace records how long each step of one pipeline run took.
type Trace struct {
	// Stages holds one entry per stage that ran, in run order. A strict-mode
	// short-circuit leaves out the stages after the blocking one.
	Stages []StageTiming
	// Policy is the OPA evaluation time, zero when no evaluator ran.
	Policy time.Duration
	// Sanitise is the executor transform time, zero unless OPA returned
	// SANITISE with targets.
	Sanitise time.Duration
}

// StageTiming is the duration of one stage's Run.
type StageTiming struct {
	Name     string
	Duration time.Duration
}

// now reads the clock only when tracing.
func (tr *Trace) now() time.Duration {
	if tr == nil {
		return 0
	}
	return clock.Now()
}

func (tr *Trace) stage(s Stage, start time.Duration) {
	if tr == nil {
		return
	}
	tr.Stages = append(tr.Stages, StageTiming{Name: s.Name(), Duration: clock.Since(start)})
}

// Stage is a single pipeline stage. Run mutates rc in place and returns whether
// a hard block signal was emitted.
type Stage interface {
	Name() string
	Run(rc *riskcontext.RiskContext) (hardBlock bool)
}

// Evaluator is implemented by policy.Engine. It evaluates OPA policy for a
// given RiskContext and returns the decision string ("ALLOW"/"SANITISE"/"BLOCK")
// and the list of sanitise_targets declared by Rego.
// Defined here (not in the policy package) to keep the import one-directional:
// pipeline imports policy; policy imports only riskcontext — no cycle.
type Evaluator interface {
	Evaluate(rc *riskcontext.RiskContext) (decision string, sanitiseTargets []string, err error)
}

// Recorder sees each request after its decision, for example to update session
// state. It runs for requests that reached the decision step, not for those a
// stage hard-blocked in strict mode.
type Recorder interface {
	Record(rc *riskcontext.RiskContext, decision byte)
}

// Pipeline runs the enforcement stages in order.
type Pipeline struct {
	cfg       *config.Config
	stages    []Stage
	evaluator Evaluator // nil → threshold fallback (Phase 2 behaviour)
	recorders []Recorder
}

// New constructs a Pipeline with no OPA evaluator (threshold fallback only).
// Stages must be provided in pipeline order: validate, normalise, scan, aggregate.
func New(cfg *config.Config, stages []Stage) *Pipeline {
	return &Pipeline{cfg: cfg, stages: stages}
}

// NewWithEvaluator constructs a Pipeline that calls ev after the four stages
// to obtain the final decision from OPA. Falls back to threshold if ev errors.
func NewWithEvaluator(cfg *config.Config, stages []Stage, ev Evaluator) *Pipeline {
	return &Pipeline{cfg: cfg, stages: stages, evaluator: ev}
}

// OnDecision adds r to the recorders that run after each decision, and returns
// p so the call can be chained onto a constructor.
func (p *Pipeline) OnDecision(r Recorder) *Pipeline {
	p.recorders = append(p.recorders, r)
	return p
}

// Run executes all pipeline stages against rc and returns a Result.
// In strict mode, the first hard block short-circuits execution.
// In non-strict mode, all stages run and the final decision is taken after aggregate.
func (p *Pipeline) Run(rc *riskcontext.RiskContext) Result {
	return p.RunTraced(rc, nil)
}

// RunTraced is Run that also records step durations into tr. A nil tr records
// nothing and does not read the clock.
func (p *Pipeline) RunTraced(rc *riskcontext.RiskContext, tr *Trace) Result {
	var blockedAt string

	for _, s := range p.stages {
		start := tr.now()
		hardBlock := s.Run(rc)
		tr.stage(s, start)
		if hardBlock {
			if p.cfg.Pipeline.StrictMode {
				return Result{
					Decision:  decision.Block,
					Score:     rc.Score,
					Signals:   rc.Signals,
					BlockedAt: s.Name(),
				}
			}
			// non-strict: note the stage but keep running
			if blockedAt == "" {
				blockedAt = s.Name()
			}
		}
	}

	// After all stages: call OPA evaluator or fall back to threshold.
	var d byte
	var sanitised []byte

	if p.evaluator != nil {
		start := tr.now()
		opaDecision, targets, err := p.evaluator.Evaluate(rc)
		if tr != nil {
			tr.Policy = clock.Since(start)
		}
		if err != nil {
			log.Printf("pipeline: OPA evaluation error: %v (falling back to threshold)", err)
			d = thresholdDecision(rc.Score, p.cfg.Thresholds)
		} else {
			d = decisionByte(opaDecision)
			if d == decision.Sanitise && len(targets) > 0 {
				start := tr.now()
				sanitised = policy.ApplySanitise(targets, rc)
				rc.SanitisedText = decodeSanitisedText(rc.Payload, sanitised)
				if tr != nil {
					tr.Sanitise = clock.Since(start)
				}
			}
		}
	} else {
		d = thresholdDecision(rc.Score, p.cfg.Thresholds)
	}

	for _, r := range p.recorders {
		r.Record(rc, d)
	}

	return Result{
		Decision:         d,
		Score:            rc.Score,
		Signals:          rc.Signals,
		BlockedAt:        blockedAt,
		SanitisedPayload: sanitised,
	}
}

func decodeSanitisedText(payload any, sanitised []byte) string {
	if len(sanitised) == 0 {
		return ""
	}
	if _, ok := payload.(string); ok {
		var s string
		if err := json.Unmarshal(sanitised, &s); err == nil {
			return s
		}
		return ""
	}
	var wrapped struct {
		Sanitised string `json:"sanitised"`
	}
	if err := json.Unmarshal(sanitised, &wrapped); err == nil {
		return wrapped.Sanitised
	}
	return ""
}

// decisionByte converts an OPA decision string to a decision byte constant.
func decisionByte(s string) byte {
	switch s {
	case "BLOCK":
		return decision.Block
	case "SANITISE":
		return decision.Sanitise
	default:
		return decision.Allow
	}
}

// thresholdDecision maps a risk score to a decision byte using configured thresholds.
// OPA overrides this in Phase 3; in Phase 2 it is the final word.
func thresholdDecision(score float64, t config.ThresholdConfig) byte {
	switch {
	case score >= t.BlockScore:
		return decision.Block
	case score >= t.SanitiseScore:
		return decision.Sanitise
	default:
		return decision.Allow
	}
}
