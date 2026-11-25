// validate.go — Stage 1 of the pipeline.
// Validates the schema of the inbound RiskContext. The transport layer already
// verified the HMAC and nonce; validate checks the JSON payload fields are
// semantically valid before passing to normalise.
//
// Hard blocks on:
//   - unknown or missing hook_type
//   - empty provenance
//   - nil payload
//   - a payload the hook's registered validator rejects
//
// It also takes the fields a client must not control out of the client's
// hands: provenance is replaced by the label the hooks registry assigns to the
// hook, client signals are set aside for the aggregate stage to vet, and score
// and state, which the sidecar computes, are cleared.
package pipeline

import (
	"github.com/acf-sdk/sidecar/internal/hooks"
	"github.com/acf-sdk/sidecar/pkg/riskcontext"
)

// ValidateStage checks the schema of the inbound RiskContext. A hook type is
// valid when it is in the hooks registry.
type ValidateStage struct{}

func (v *ValidateStage) Name() string { return "validate" }

// Run validates rc and emits a hard block signal if any required field is
// missing or invalid.
func (v *ValidateStage) Run(rc *riskcontext.RiskContext) (hardBlock bool) {
	// Set the client's signals aside first, so on a rejected request the hard
	// block signal below is the only signal policy sees.
	rc.ClientSignals, rc.Signals = rc.Signals, nil
	rc.Score = 0
	rc.State = nil
	rc.MatchedSpans = nil
	rc.SanitisedText = ""

	h, ok := hooks.Lookup(rc.HookType)
	if !ok {
		rc.Signals = append(rc.Signals, riskcontext.Signal{Category: "validate:invalid_hook_type"})
		return true
	}
	if rc.Provenance == "" {
		rc.Signals = append(rc.Signals, riskcontext.Signal{Category: "validate:missing_provenance"})
		return true
	}
	if rc.Payload == nil {
		rc.Signals = append(rc.Signals, riskcontext.Signal{Category: "validate:nil_payload"})
		return true
	}
	if h.Validate != nil && h.Validate(rc.Payload) != nil {
		rc.Signals = append(rc.Signals, riskcontext.Signal{Category: "validate:invalid_payload"})
		return true
	}
	rc.ClaimedProvenance, rc.Provenance = rc.Provenance, h.Provenance
	return false
}

// NewValidateStage constructs a ValidateStage.
func NewValidateStage() *ValidateStage {
	return &ValidateStage{}
}
