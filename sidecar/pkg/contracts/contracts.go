// Package contracts defines the typed request/response envelope exchanged
// between the SDK (PEP) and the sidecar (PDP) over the IPC frame protocol.
//
// These structs formalise the JSON shape that the SDK already sends and
// provide conversion helpers to/from the internal riskcontext.RiskContext
// and pipeline.Result types.
//
// Wire compatibility: the binary frame envelope (54-byte header + JSON
// payload) is unchanged. ValidateRequest is the JSON payload of the
// request frame. ValidateResponse maps from pipeline.Result.
package contracts

import (
	"encoding/json"

	"github.com/acf-sdk/sidecar/pkg/decision"
	"github.com/acf-sdk/sidecar/pkg/riskcontext"
)

// Signal is a named risk signal with its weighted score.
// Identical to riskcontext.Signal but defined here to keep the contracts
// package self-contained for cross-SDK consumption.
type Signal struct {
	Category string  `json:"category"`
	Score    float64 `json:"score"`
}

// ValidateRequest is the typed envelope the SDK serialises as the JSON
// frame payload. Its fields match riskcontext.RiskContext exactly.
type ValidateRequest struct {
	Score      float64         `json:"score"`
	Signals    []Signal        `json:"signals"`
	Provenance string          `json:"provenance"`
	SessionID  string          `json:"session_id"`
	HookType   string          `json:"hook_type"`
	Payload    json.RawMessage `json:"payload"`
	State      json.RawMessage `json:"state,omitempty"`
}

// ToRiskContext converts a ValidateRequest to the internal RiskContext
// that the pipeline stages operate on.
func (r *ValidateRequest) ToRiskContext() (*riskcontext.RiskContext, error) {
	// Convert signals.
	signals := make([]riskcontext.Signal, len(r.Signals))
	for i, s := range r.Signals {
		signals[i] = riskcontext.Signal{
			Category: s.Category,
			Score:    s.Score,
		}
	}

	// Decode the raw payload into an any for the pipeline.
	var payload any
	if len(r.Payload) > 0 {
		if err := json.Unmarshal(r.Payload, &payload); err != nil {
			return nil, err
		}
	}

	// Decode state.
	var state any
	if len(r.State) > 0 {
		_ = json.Unmarshal(r.State, &state)
	}

	return &riskcontext.RiskContext{
		Score:      r.Score,
		Signals:    signals,
		Provenance: r.Provenance,
		SessionID:  r.SessionID,
		HookType:   r.HookType,
		Payload:    payload,
		State:      state,
	}, nil
}

// FromRiskContext builds a ValidateRequest from a RiskContext.
// This is useful for round-trip tests and for reconstructing the request
// shape after pipeline processing.
func FromRiskContext(rc *riskcontext.RiskContext) (*ValidateRequest, error) {
	signals := make([]Signal, len(rc.Signals))
	for i, s := range rc.Signals {
		signals[i] = Signal{
			Category: s.Category,
			Score:    s.Score,
		}
	}

	payloadBytes, err := json.Marshal(rc.Payload)
	if err != nil {
		return nil, err
	}

	var stateBytes json.RawMessage
	if rc.State != nil {
		stateBytes, err = json.Marshal(rc.State)
		if err != nil {
			return nil, err
		}
	}

	return &ValidateRequest{
		Score:      rc.Score,
		Signals:    signals,
		Provenance: rc.Provenance,
		SessionID:  rc.SessionID,
		HookType:   rc.HookType,
		Payload:    payloadBytes,
		State:      stateBytes,
	}, nil
}

// ValidateResponse is the typed response envelope the sidecar returns.
// It captures the full pipeline result including telemetry fields that
// the current minimal 5-byte wire frame omits.
type ValidateResponse struct {
	Decision         byte            `json:"decision"`
	Score            float64         `json:"score"`
	Signals          []Signal        `json:"signals"`
	BlockedAt        string          `json:"blocked_at,omitempty"`
	SanitisedPayload json.RawMessage `json:"sanitised_payload,omitempty"`
	Reason           string          `json:"reason,omitempty"`
	Metadata         map[string]any  `json:"metadata,omitempty"`
}

// PipelineResult holds the fields needed from pipeline.Result to build
// a ValidateResponse. Defined here to avoid importing the pipeline
// package (which would create a cycle).
type PipelineResult struct {
	Decision         byte
	Score            float64
	Signals          []riskcontext.Signal
	BlockedAt        string
	SanitisedPayload []byte
}

// ResponseFromPipeline builds a ValidateResponse from a PipelineResult.
func ResponseFromPipeline(pr PipelineResult) ValidateResponse {
	signals := make([]Signal, len(pr.Signals))
	for i, s := range pr.Signals {
		signals[i] = Signal{
			Category: s.Category,
			Score:    s.Score,
		}
	}

	var reason string
	switch pr.Decision {
	case decision.Block:
		if pr.BlockedAt != "" {
			reason = "blocked at " + pr.BlockedAt + " stage"
		} else {
			reason = "risk score exceeded block threshold"
		}
	case decision.Sanitise:
		reason = "risk score exceeded sanitise threshold"
	default:
		reason = "within acceptable risk"
	}

	return ValidateResponse{
		Decision:         pr.Decision,
		Score:            pr.Score,
		Signals:          signals,
		BlockedAt:        pr.BlockedAt,
		SanitisedPayload: pr.SanitisedPayload,
		Reason:           reason,
	}
}

// DecisionString returns the human-readable decision name.
func (r *ValidateResponse) DecisionString() string {
	switch r.Decision {
	case decision.Allow:
		return "ALLOW"
	case decision.Sanitise:
		return "SANITISE"
	case decision.Block:
		return "BLOCK"
	default:
		return "UNKNOWN"
	}
}
