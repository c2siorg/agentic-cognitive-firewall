// builtin.go — the hooks the sidecar ships with.
package hooks

import (
	"errors"

	"github.com/acf-sdk/sidecar/pkg/riskcontext"
)

// The provenance labels match what the SDK's hook methods have always sent, so
// assigning them in the sidecar changes no trust weight for SDK traffic.
func init() {
	Register(Hook{Name: "on_prompt", Policy: "acf.policy.prompt", Provenance: "user"})
	Register(Hook{Name: "on_context", Policy: "acf.policy.context", Provenance: "rag", Input: contextInput})
	Register(Hook{Name: "on_tool_call", Policy: "acf.policy.tool", Provenance: "agent", Input: toolCallInput})
	Register(Hook{Name: "on_memory", Policy: "acf.policy.memory", Provenance: "agent", Input: memoryInput})
	// on_task declares a session's scope. It comes from the developer's code,
	// not from content, hence its own provenance.
	Register(Hook{Name: "on_task", Policy: "acf.policy.task", Provenance: "developer", Input: taskInput})
	// on_confirm records values the user explicitly approved mid-session so
	// subsequent tool calls may carry them without restarting the session.
	Register(Hook{Name: "on_confirm", Policy: "acf.policy.confirm", Provenance: "developer", Input: confirmInput})
	// on_tool_result screens a tool's output before the agent reads it, with
	// the producing tool named so policy can tell sources apart.
	Register(Hook{
		Name: "on_tool_result", Policy: "acf.policy.tool_result", Provenance: "tool_output",
		Input: toolResultInput, Validate: validateToolResult,
	})
}

func toolResultInput(rc *riskcontext.RiskContext, input map[string]any) {
	m, ok := payloadMap(rc)
	if !ok {
		return
	}
	input["tool_name"] = m["tool"]
	if s, ok := m["result"].(string); ok {
		input["payload_size_bytes"] = len([]byte(s))
	}
}

// validateToolResult requires {"tool": <name>, "result": <text>}. The SDK
// JSON-encodes structured results, so the result is always text to scan.
func validateToolResult(payload any) error {
	m, ok := payload.(map[string]any)
	if !ok {
		return errors.New("tool result must be an object")
	}
	if t, ok := m["tool"].(string); !ok || t == "" {
		return errors.New("tool must be a non-empty string")
	}
	if _, ok := m["result"].(string); !ok {
		return errors.New("result must be a string")
	}
	return nil
}

func taskInput(rc *riskcontext.RiskContext, input map[string]any) {
	if m, ok := payloadMap(rc); ok {
		input["task"] = m
	}
}

func confirmInput(rc *riskcontext.RiskContext, input map[string]any) {
	if m, ok := payloadMap(rc); ok {
		input["confirm"] = m
	}
}

func payloadMap(rc *riskcontext.RiskContext) (map[string]any, bool) {
	m, ok := rc.Payload.(map[string]any)
	return m, ok
}

func toolCallInput(rc *riskcontext.RiskContext, input map[string]any) {
	m, ok := payloadMap(rc)
	if !ok {
		return
	}
	input["tool_name"] = m["name"]
	// Arguments, so policies can check them against a session's task scope.
	if params, ok := m["params"].(map[string]any); ok {
		input["tool_params"] = params
	} else {
		input["tool_params"] = map[string]any{}
	}
	if meta, ok := m["metadata"]; ok {
		input["tool_metadata"] = meta
	} else {
		input["tool_metadata"] = map[string]any{}
	}
}

func contextInput(rc *riskcontext.RiskContext, input map[string]any) {
	m, ok := payloadMap(rc)
	if !ok {
		return
	}
	if s, ok := m["content"].(string); ok {
		input["payload_size_bytes"] = len([]byte(s))
	}
	if trust, ok := m["source_trust"]; ok {
		input["source_trust"] = trust
	}
}

func memoryInput(rc *riskcontext.RiskContext, input map[string]any) {
	m, ok := payloadMap(rc)
	if !ok {
		return
	}
	input["memory_op"] = m["op"]
	if v, ok := m["value"].(string); ok {
		input["payload_size_bytes"] = len([]byte(v))
	}
	input["integrity"] = map[string]any{
		"hmac_valid": m["hmac_valid"],
	}
}
