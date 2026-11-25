// executor.go — reads the OPA decision output, calls sanitise if needed,
// and assembles the sanitised payload returned to the transport layer.
// OPA declares *what* to sanitise; this file performs the actual transformation.

package policy

import (
	"encoding/json"
	"sort"
	"strings"

	"github.com/acf-sdk/sidecar/pkg/riskcontext"
)

// ApplySanitise performs the sanitisation transforms declared by OPA and
// returns the encoded payload bytes to embed in the wire response.
// Returns nil if targets is empty or the payload cannot be extracted.
func ApplySanitise(targets []string, rc *riskcontext.RiskContext) []byte {
	if len(targets) == 0 {
		return nil
	}
	field, text := payloadFieldAndText(rc)
	if text == "" {
		return nil
	}

	redactNeeded := false
	splitNeeded := false
	for _, target := range targets {
		switch target {
		case "prompt_text", "context_chunk", "memory_value", "tool_params", "tool_result":
			redactNeeded = true
		case "split_chunk":
			splitNeeded = true
		}
	}

	// Redact matched spans before prepending split_chunk so original byte
	// offsets in rc.MatchedSpans never shift regardless of target set order.
	if redactNeeded {
		if spans := spansForField(rc.MatchedSpans, field, len(text)); len(spans) > 0 {
			text = redactSpans(text, spans)
		} else {
			// Fallback when no field-aligned spans are present (e.g. semantic-only
			// signals, matches in another field such as on_memory.key, or direct
			// ApplySanitise callers that did not run ScanStage).
			seg := rc.CanonicalText
			if seg != "" && strings.Contains(text, seg) {
				text = Redact(SanitiseRequest{
					Text:            text,
					MatchedSegments: []string{seg},
				})
			} else {
				text = "[REDACTED]"
			}
		}
	}

	if splitNeeded {
		text = InjectPrefix(SanitiseRequest{
			Text:   text,
			Prefix: "[ACF:SPLIT_REQUIRED]",
		})
	}

	return encodePayload(rc, text)
}

func spansForField(all []riskcontext.TextSpan, field string, limit int) []riskcontext.TextSpan {
	var out []riskcontext.TextSpan
	for _, sp := range all {
		if sp.Field == field && sp.Start >= 0 && sp.Start < sp.End && sp.End <= limit {
			out = append(out, sp)
		}
	}
	if len(out) <= 1 {
		return out
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Start != out[j].Start {
			return out[i].Start < out[j].Start
		}
		return out[i].End < out[j].End
	})
	merged := out[:1]
	for _, sp := range out[1:] {
		last := &merged[len(merged)-1]
		if sp.Start <= last.End {
			if sp.End > last.End {
				last.End = sp.End
			}
			continue
		}
		merged = append(merged, sp)
	}
	return merged
}

func redactSpans(text string, spans []riskcontext.TextSpan) string {
	var b strings.Builder
	b.Grow(len(text))
	pos := 0
	for _, sp := range spans {
		if sp.Start > pos {
			b.WriteString(text[pos:sp.Start])
		}
		b.WriteString("[REDACTED]")
		pos = sp.End
	}
	if pos < len(text) {
		b.WriteString(text[pos:])
	}
	return b.String()
}

// payloadFieldAndText extracts the primary sanitisable field name and text from
// rc.Payload. For string payloads, field is "".
func payloadFieldAndText(rc *riskcontext.RiskContext) (string, string) {
	switch v := rc.Payload.(type) {
	case string:
		return "", v
	case map[string]any:
		for _, key := range []string{"content", "value", "text", "prompt", "result"} {
			if s, ok := v[key].(string); ok {
				return key, s
			}
		}
		// Fall back to full JSON for structured payloads.
		b, _ := json.Marshal(v)
		return "__json__", string(b)
	default:
		return "", ""
	}
}

// encodePayload marshals the sanitised text back to bytes suitable for the
// wire response. String payloads are JSON-encoded as a string. Map payloads
// are wrapped in {"sanitised": <text>}.
func encodePayload(rc *riskcontext.RiskContext, sanitisedText string) []byte {
	switch rc.Payload.(type) {
	case string:
		b, _ := json.Marshal(sanitisedText)
		return b
	default:
		b, _ := json.Marshal(map[string]string{"sanitised": sanitisedText})
		return b
	}
}
