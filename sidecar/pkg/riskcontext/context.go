// Package riskcontext defines the RiskContext struct — the single payload
// that flows through the entire PDP pipeline. All pipeline stages read from
// and write to this struct. The schema is fixed across v1 and v2; the State
// field is null in v1 and populated by the TTL state store in v2.
package riskcontext

// Signal is a named risk signal emitted by the scan stage and scored by the
// aggregate stage. Category identifies the signal type; Score is the weighted
// contribution (0.0–1.0) filled in by aggregate from signal_weights in policy_config.yaml.
type Signal struct {
	Category string  `json:"category"`
	Score    float64 `json:"score"`
}

// TextSpan is a half-open byte range [Start, End) in the original string of
// Payload (or the named field when Payload is a map) corresponding to a lexical
// match found by the scan stage. Internal to the sidecar pipeline only.
type TextSpan struct {
	Field string
	Start int
	End   int
}

// RiskContext is the payload exchanged over IPC and passed through every
// pipeline stage in the sidecar. It is JSON-serialised as the frame payload.
type RiskContext struct {
	// Score is the aggregated risk score (0.0–1.0). Populated by the
	// aggregate stage. Zero on the inbound frame from the SDK.
	Score float64 `json:"score"`

	// Signals is the list of named signals emitted by the scan stage,
	// with scores back-filled by the aggregate stage.
	// Empty on the inbound frame; populated as the pipeline runs.
	Signals []Signal `json:"signals"`

	// Provenance identifies the origin of the payload (e.g. "user", "rag",
	// "tool_output", "memory"). Set by the SDK before sending.
	Provenance string `json:"provenance"`

	// SessionID identifies the agent session. Used by the v2 state store.
	SessionID string `json:"session_id"`

	// HookType identifies which hook fired: "on_prompt", "on_context",
	// "on_tool_call", or "on_memory". Used by the policy engine to select
	// the correct Rego file.
	HookType string `json:"hook_type"`

	// Payload is the raw content to evaluate. Can be a string (on_prompt,
	// on_memory) or an object (on_tool_call, on_context chunk).
	Payload any `json:"payload"`

	// CanonicalText is the normalised form of Payload produced by the normalise
	// stage. It is the text the scan stage operates on. The original Payload is
	// never mutated — CanonicalText is a separate derived field.
	// Not serialised to JSON; internal to the sidecar pipeline only.
	CanonicalText string `json:"-"`

	// State is nil in v1. In v2 it is hydrated by the TTL state store before
	// the pipeline runs and contains session history for stateful policies.
	// It is sidecar-owned: the validate stage discards any value a client sends.
	State any `json:"state"`

	// ClaimedProvenance is the provenance the client sent. The validate stage
	// replaces Provenance with the label the hooks registry assigns to the
	// hook, so a client cannot pick its own trust weight. The claim is kept for
	// audit only and never reaches policy. Internal; not serialised.
	ClaimedProvenance string `json:"-"`

	// ClientSignals holds the signals the client sent, e.g. from the SDK's
	// semantic scanner. The validate stage moves them here and the aggregate
	// stage merges back only categories with a configured weight, scored by
	// that weight. Internal; not serialised.
	ClientSignals []Signal `json:"-"`

	// MatchedSpans holds the original payload byte ranges [Start, End) of
	// lexical matches discovered by the scan stage, so the executor can redact
	// only the matched spans instead of the entire payload. Internal; not serialised.
	MatchedSpans []TextSpan `json:"-"`

	// SanitisedText holds the transformed text produced by the executor when a
	// decision is SANITISE, so downstream recorders (e.g. session trust
	// extraction) never trust tokens removed by redaction. Internal; not serialised.
	SanitisedText string `json:"-"`
}
