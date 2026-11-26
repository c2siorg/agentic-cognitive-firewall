// Package policy wraps the OPA Go SDK for policy evaluation, sanitisation
// execution, and result assembly.
//
// engine.go — OPA engine.
// Loads the Rego bundle from the policies directory at startup.
// Watches for file changes and hot-reloads without restarting.
// Serves signal_weights from policy_config.yaml to the aggregate stage.
// Queries the policy matching the RiskContext.HookType field.
// Returns a structured decision (ALLOW / SANITISE / BLOCK) with sanitise_targets.
package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
	"gopkg.in/yaml.v3"

	"github.com/acf-sdk/sidecar/internal/hooks"
	"github.com/acf-sdk/sidecar/pkg/riskcontext"
)

// TaintSource identifies where an untrusted value was read before reaching a
// consequential tool argument.
type TaintSource struct {
	Hook string `json:"hook"`
	Tool string `json:"tool,omitempty"`
}

// BlockReason describes a single policy gate or pipeline validation rule behind
// a BLOCK verdict.
type BlockReason struct {
	Code    string        `json:"code"`
	Stage   string        `json:"stage,omitempty"`
	Tool    string        `json:"tool,omitempty"`
	Param   string        `json:"param,omitempty"`
	Kind    string        `json:"kind,omitempty"`
	Value   string        `json:"value,omitempty"`
	Sources []TaintSource `json:"sources,omitempty"`
	Signal  string        `json:"signal,omitempty"`
	Detail  string        `json:"detail,omitempty"`
}

// BlockPayload is the JSON document encoded into the response frame body when
// Decision == Block.
type BlockPayload struct {
	Hook        string        `json:"hook,omitempty"`
	Confirmable bool          `json:"confirmable"`
	Reasons     []BlockReason `json:"reasons"`
}

// OPAResult is the structured output of a single OPA evaluation.
type OPAResult struct {
	// Decision is "ALLOW", "SANITISE", or "BLOCK".
	Decision string
	// SanitiseTargets lists the payload segments OPA wants transformed.
	SanitiseTargets []string
	// BlockReasons lists the structured reasons OPA produced when Decision == "BLOCK".
	BlockReasons []BlockReason
}

// IsConfirmable reports whether a BLOCK verdict with reasons on hookType in
// sessionID can be resolved mid-session via user confirmation (on_confirm).
// Only session-scoped on_tool_call blocks caused exclusively by argument_taint
// are confirmable; any other failed gate or signal keeps the block hard.
func IsConfirmable(hookType, sessionID string, reasons []BlockReason) bool {
	if hookType != "on_tool_call" || sessionID == "" || len(reasons) == 0 {
		return false
	}
	for _, r := range reasons {
		if r.Code != "argument_taint" {
			return false
		}
	}
	return true
}

// EncodeBlockPayload builds and JSON-marshals a deterministic BlockPayload.
func EncodeBlockPayload(hookType, sessionID string, reasons []BlockReason) []byte {
	out := append([]BlockReason(nil), reasons...)
	if len(out) == 0 {
		out = []BlockReason{{Code: "policy_denied"}}
	}
	payload := BlockPayload{
		Hook:        hookType,
		Confirmable: IsConfirmable(hookType, sessionID, out),
		Reasons:     out,
	}
	b, _ := json.Marshal(payload)
	return b
}

// preparedQueries holds one compiled query per registered hook, keyed by hook
// name. A loaded map is never mutated; hot reload swaps in a new one.
type preparedQueries map[string]rego.PreparedEvalQuery

// Engine is a thread-safe OPA policy evaluator with hot reload support.
type Engine struct {
	policyDir string
	mu        sync.RWMutex
	queries   preparedQueries
	// weights is signal_weights from policy_config.yaml. It is swapped with
	// queries on reload and never mutated in place.
	weights map[string]float64
	stopCh  chan struct{}
}

// NewEngine constructs an Engine that loads Rego policies from policyDir.
// It compiles all policies once at startup and starts a background goroutine
// that polls for file changes every 5 seconds and hot-reloads as needed.
func NewEngine(policyDir string) (*Engine, error) {
	e := &Engine{
		policyDir: policyDir,
		stopCh:    make(chan struct{}),
	}
	if err := e.reload(); err != nil {
		return nil, fmt.Errorf("policy.Engine: initial load failed: %w", err)
	}
	go e.watchLoop()
	return e, nil
}

// Evaluate runs the OPA policy for rc.HookType and returns the decision and
// sanitise_targets declared by Rego. Returns ("ALLOW", nil, nil) if no rule
// fires. Returns an error if the hook type is unknown or OPA evaluation fails.
//
// This method satisfies the pipeline.Evaluator interface:
//
//	Evaluate(rc) (decision string, sanitiseTargets []string, err error)
func (e *Engine) Evaluate(rc *riskcontext.RiskContext) (string, []string, error) {
	res, err := e.EvaluateDetailed(rc)
	if err != nil {
		return "BLOCK", nil, err
	}
	return res.Decision, res.SanitiseTargets, nil
}

// EvaluateDetailed runs the OPA policy for rc.HookType and returns the full
// OPAResult including structured block reasons.
func (e *Engine) EvaluateDetailed(rc *riskcontext.RiskContext) (OPAResult, error) {
	e.mu.RLock()
	q, ok := e.queries[rc.HookType]
	e.mu.RUnlock()
	if !ok {
		return OPAResult{Decision: "BLOCK"}, fmt.Errorf("policy.Engine: unknown hook_type %q", rc.HookType)
	}

	rs, err := q.Eval(context.Background(), rego.EvalInput(buildInput(rc)))
	if err != nil {
		return OPAResult{}, fmt.Errorf("policy.Engine: OPA evaluation error: %w", err)
	}

	return extractResult(rs), nil
}

// Stop shuts down the hot-reload goroutine.
func (e *Engine) Stop() {
	select {
	case <-e.stopCh:
	default:
		close(e.stopCh)
	}
}

// SignalWeights returns the signal weights from the most recent successful
// load of policy_config.yaml, and satisfies pipeline.WeightSource. The map is
// replaced wholesale on reload, so callers must not mutate it.
func (e *Engine) SignalWeights() map[string]float64 {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.weights
}

// reload compiles all Rego policies and atomically swaps the prepared queries.
func (e *Engine) reload() error {
	ctx := context.Background()

	// 1. Load data.config and the signal weights from policy_config.yaml.
	store, weights, err := loadPolicyData(e.policyDir)
	if err != nil {
		return err
	}

	// 2. Read all .rego files from policyDir (excluding test files).
	modules, err := loadModules(e.policyDir)
	if err != nil {
		return err
	}
	if len(modules) == 0 {
		return fmt.Errorf("policy.Engine: no .rego files found in %s", e.policyDir)
	}

	// 3. Compile a PreparedEvalQuery for every registered hook. A hook whose
	// policy package fails to compile fails the whole load, so a reload never
	// leaves some hooks on old policies and others on new ones.
	queries := preparedQueries{}
	for _, h := range hooks.All() {
		opts := append(modules, rego.Query("data."+h.Policy), rego.Store(store))
		q, err := rego.New(opts...).PrepareForEval(ctx)
		if err != nil {
			return fmt.Errorf("policy.Engine: compile %s (%s): %w", h.Name, h.Policy, err)
		}
		queries[h.Name] = q
	}

	// 4. Atomically swap in the new compiled queries and weights, under one
	// lock so the engine never holds queries and weights from different loads.
	e.mu.Lock()
	e.queries = queries
	e.weights = weights
	e.mu.Unlock()

	return nil
}

// watchLoop polls the policy directory every 5 seconds and reloads on change.
// Uses modification-time comparison — no fsnotify dependency (Windows safe).
func (e *Engine) watchLoop() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	lastMod := e.latestMod()

	for {
		select {
		case <-e.stopCh:
			return
		case <-ticker.C:
			if mod := e.latestMod(); mod.After(lastMod) {
				lastMod = mod
				if err := e.reload(); err != nil {
					log.Printf("policy.Engine: hot-reload failed: %v (keeping previous policies)", err)
				} else {
					log.Printf("policy.Engine: policies reloaded from %s", e.policyDir)
				}
			}
		}
	}
}

// latestMod returns the most recent modification time of any file in policyDir.
func (e *Engine) latestMod() time.Time {
	var latest time.Time
	_ = filepath.WalkDir(e.policyDir, func(_ string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err == nil && info.ModTime().After(latest) {
			latest = info.ModTime()
		}
		return nil
	})
	return latest
}

// loadPolicyData reads policy_config.yaml, builds an OPA in-memory store with
// the parsed config available as data.config inside Rego rules, and extracts
// signal_weights for the aggregate stage.
//
// The file is required. Without it there are no signal weights: every signal
// would score 0.0 and every request would be ALLOWed. So a missing or
// weightless policy_config.yaml fails the load instead of failing open — at
// startup the sidecar refuses to run, and on hot reload the previous policies
// stay live.
func loadPolicyData(policyDir string) (storage.Store, map[string]float64, error) {
	configPath := filepath.Join(policyDir, "data", "policy_config.yaml")
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, nil, fmt.Errorf("policy.Engine: cannot read %s: %w", configPath, err)
	}

	var parsed map[string]any
	if err := yaml.Unmarshal(data, &parsed); err != nil {
		return nil, nil, fmt.Errorf("policy.Engine: cannot parse policy_config.yaml: %w", err)
	}

	weights, err := parseSignalWeights(parsed["signal_weights"])
	if err != nil {
		return nil, nil, fmt.Errorf("policy.Engine: %s: %w", configPath, err)
	}

	store := inmem.NewFromObject(map[string]any{"config": parsed})
	return store, weights, nil
}

// parseSignalWeights validates the signal_weights table: a non-empty map from
// signal category to a weight in [0.0, 1.0].
func parseSignalWeights(raw any) (map[string]float64, error) {
	table, ok := raw.(map[string]any)
	if !ok || len(table) == 0 {
		return nil, errors.New("signal_weights is missing or empty")
	}
	weights := make(map[string]float64, len(table))
	for category, v := range table {
		var w float64
		switch n := v.(type) {
		case float64:
			w = n
		case int:
			w = float64(n)
		default:
			return nil, fmt.Errorf("signal_weights.%s: %v is not a number", category, v)
		}
		if w < 0 || w > 1 {
			return nil, fmt.Errorf("signal_weights.%s: %v is outside [0.0, 1.0]", category, w)
		}
		weights[category] = w
	}
	return weights, nil
}

// loadModules reads all .rego files (excluding _test.rego) from policyDir
// and returns them as rego.Module functional options.
func loadModules(policyDir string) ([]func(*rego.Rego), error) {
	entries, err := os.ReadDir(policyDir)
	if err != nil {
		return nil, fmt.Errorf("policy.Engine: cannot read policy dir %s: %w", policyDir, err)
	}

	var opts []func(*rego.Rego)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if filepath.Ext(name) != ".rego" {
			continue
		}
		// Skip test files — they define test rules that conflict with evaluation.
		if len(name) > 9 && name[len(name)-9:] == "_test.rego" {
			continue
		}
		path := filepath.Join(policyDir, name)
		contents, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("policy.Engine: cannot read %s: %w", path, err)
		}
		opts = append(opts, rego.Module(name, string(contents)))
	}
	return opts, nil
}

// buildInput constructs the OPA input document from a RiskContext.
// Common fields are always present; hook-specific fields are added per hook type.
func buildInput(rc *riskcontext.RiskContext) map[string]any {
	// Convert []Signal to []map[string]any for OPA.
	signals := make([]map[string]any, len(rc.Signals))
	for i, s := range rc.Signals {
		signals[i] = map[string]any{
			"category": s.Category,
			"score":    s.Score,
		}
	}

	input := map[string]any{
		"score":      rc.Score,
		"signals":    signals,
		"hook_type":  rc.HookType,
		"provenance": rc.Provenance,
		"session_id": rc.SessionID,
	}

	// Session state, when the request names a live session. The session stage
	// fills it from the sidecar's store; a client-sent state never gets here.
	if rc.State != nil {
		input["state"] = rc.State
	}

	// Hook-specific fields extracted from rc.Payload.
	if h, ok := hooks.Lookup(rc.HookType); ok && h.Input != nil {
		h.Input(rc, input)
	}

	return input
}

// extractResult parses an OPA ResultSet into an OPAResult.
// Returns ALLOW with no targets if the result set is empty (no rule fired).
func extractResult(rs rego.ResultSet) OPAResult {
	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return OPAResult{Decision: "ALLOW"}
	}

	obj, ok := rs[0].Expressions[0].Value.(map[string]any)
	if !ok {
		return OPAResult{Decision: "ALLOW"}
	}

	decision, _ := obj["decision"].(string)
	if decision == "" {
		decision = "ALLOW"
	}

	var targets []string
	// OPA returns Rego set values as []interface{} via the Go SDK.
	if set, ok := obj["sanitise_targets"].([]any); ok {
		for _, t := range set {
			if s, ok := t.(string); ok {
				targets = append(targets, s)
			}
		}
	}

	var reasons []BlockReason
	if decision == "BLOCK" {
		reasons = extractBlockReasons(obj["block_reasons"])
	}

	return OPAResult{Decision: decision, SanitiseTargets: targets, BlockReasons: reasons}
}

func extractBlockReasons(raw any) []BlockReason {
	items, ok := raw.([]any)
	if !ok || len(items) == 0 {
		return nil
	}
	reasons := make([]BlockReason, 0, len(items))
	for _, it := range items {
		m, ok := it.(map[string]any)
		if !ok {
			continue
		}
		code, _ := m["code"].(string)
		if code == "" {
			continue
		}
		r := BlockReason{
			Code:   code,
			Stage:  strField(m, "stage"),
			Tool:   strField(m, "tool"),
			Param:  strField(m, "param"),
			Kind:   strField(m, "kind"),
			Value:  strField(m, "value"),
			Signal: strField(m, "signal"),
			Detail: strField(m, "detail"),
		}
		if rawSources, ok := m["sources"].([]any); ok {
			for _, rs := range rawSources {
				sm, ok := rs.(map[string]any)
				if !ok {
					continue
				}
				hook := strField(sm, "hook")
				if hook == "" {
					continue
				}
				r.Sources = append(r.Sources, TaintSource{
					Hook: hook,
					Tool: strField(sm, "tool"),
				})
			}
			sort.Slice(r.Sources, func(i, j int) bool {
				if r.Sources[i].Hook != r.Sources[j].Hook {
					return r.Sources[i].Hook < r.Sources[j].Hook
				}
				return r.Sources[i].Tool < r.Sources[j].Tool
			})
		}
		reasons = append(reasons, r)
	}
	sort.Slice(reasons, func(i, j int) bool {
		a, b := reasons[i], reasons[j]
		keyA := strings.Join([]string{a.Code, a.Stage, a.Tool, a.Param, a.Kind, a.Value, a.Signal, a.Detail}, "\x00")
		keyB := strings.Join([]string{b.Code, b.Stage, b.Tool, b.Param, b.Kind, b.Value, b.Signal, b.Detail}, "\x00")
		return keyA < keyB
	})
	return reasons
}

func strField(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}
