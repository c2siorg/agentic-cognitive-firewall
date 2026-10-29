// scan.go — Stage 3 of the pipeline.
// Runs on rc.CanonicalText produced by the normalise stage:
//   - Aho-Corasick multi-pattern lexical scan against jailbreak_patterns.json
//   - Tool allowlist check (on_tool_call)
//   - Memory key allowlist check (on_memory)
//
// Emits named signals into rc.Signals. Hard-blocks only when a pattern match
// produces a signal whose weight reaches the block threshold — that is left to
// the aggregate stage. Scan itself never returns hardBlock=true; it is a pure
// signal emitter. The aggregate stage decides if the combined score is blocking.
package pipeline

import (
	"encoding/json"
	"slices"
	"strconv"
	"strings"

	"github.com/cloudflare/ahocorasick"

	"github.com/acf-sdk/sidecar/internal/config"
	"github.com/acf-sdk/sidecar/pkg/riskcontext"
)

// shellMetachars are characters that allow command chaining or injection in shells.
var shellMetachars = []string{";", "&&", "||", "|", "`", "$(", "${", " & ", ">", "<"}

// pathTraversalPatterns are sequences used to escape a directory boundary.
var pathTraversalPatterns = []string{"../", "..\\", "/..", "\\.."}

// ScanStage runs lexical pattern matching and allowlist checks.
type ScanStage struct {
	cfg     *config.Config
	matcher *ahocorasick.Matcher
	cats    [][]string // parallel to matcher dictionary: categories per normalised pattern
}

// NewScanStage constructs a ScanStage. entries is the structured pattern list
// loaded from jailbreak_patterns.json. An empty list means lexical scan is a
// no-op (no signals emitted from pattern matching).
// Distinct patterns can normalise to the same string (e.g. a zero-width-space
// variant of a plain pattern), which collapses to one node in the AC trie, so
// the dictionary is deduplicated by normalised form and each slot carries the
// categories of every entry that mapped to it.
func NewScanStage(cfg *config.Config, entries []config.PatternEntry) *ScanStage {
	s := &ScanStage{cfg: cfg}
	if len(entries) == 0 {
		return s
	}
	index := make(map[string]int)
	var dict [][]byte
	for _, e := range entries {
		norm := strings.ToLower(normalisePattern(e.Pattern))
		i, ok := index[norm]
		if !ok {
			i = len(dict)
			index[norm] = i
			dict = append(dict, []byte(norm))
			s.cats = append(s.cats, nil)
		}
		cat := e.Category
		if cat == "" {
			cat = "jailbreak_pattern"
		}
		if !slices.Contains(s.cats[i], cat) {
			s.cats[i] = append(s.cats[i], cat)
		}
	}
	s.matcher = ahocorasick.NewMatcher(dict)
	return s
}

func (s *ScanStage) Name() string { return "scan" }

// Run scans rc.CanonicalText and appends signals to rc.Signals.
// Always returns hardBlock=false — signal weighting and block decisions
// are the aggregate stage's responsibility.
func (s *ScanStage) Run(rc *riskcontext.RiskContext) (hardBlock bool) {
	text := strings.ToLower(rc.CanonicalText)

	// 1. Aho-Corasick lexical scan with per-category signal emission.
	if s.matcher != nil && len(text) > 0 {
		hits := s.matcher.MatchThreadSafe([]byte(text))
		if len(hits) > 0 {
			seen := make(map[string]bool)
			for _, idx := range hits {
				for _, cat := range s.cats[idx] {
					if !seen[cat] {
						seen[cat] = true
						rc.Signals = append(rc.Signals, riskcontext.Signal{Category: cat})
					}
				}
			}
			if !seen["jailbreak_pattern"] {
				rc.Signals = append(rc.Signals, riskcontext.Signal{Category: "jailbreak_pattern"})
			}
		}
	}

	// 2. Hook-specific allowlist and integrity checks.
	switch rc.HookType {
	case "on_tool_call":
		s.checkToolAllowlist(rc)
		s.checkToolDangerousParams(rc)
	case "on_memory":
		s.checkMemoryAllowlist(rc)
	}

	return false
}

// checkToolAllowlist emits a signal if the tool name is not in the allowlist.
func (s *ScanStage) checkToolAllowlist(rc *riskcontext.RiskContext) {
	toolName := ""
	if m, ok := rc.Payload.(map[string]any); ok {
		if n, ok := m["name"].(string); ok {
			toolName = n
		}
	}
	if toolName != "" && !s.cfg.ToolAllowed(toolName) {
		rc.Signals = append(rc.Signals, riskcontext.Signal{Category: "tool:not_allowed"})
	}
}

// checkToolDangerousParams scans all string values in the tool params for shell
// metacharacters and path traversal sequences, emitting signals independently.
// Checks listed in tool_param_scan_skip for a specific parameter are not run.
func (s *ScanStage) checkToolDangerousParams(rc *riskcontext.RiskContext) {
	m, ok := rc.Payload.(map[string]any)
	if !ok {
		return
	}
	params, ok := m["params"].(map[string]any)
	if !ok {
		return
	}
	toolName, _ := m["name"].(string)

	if s.hasDangerousParam(params, toolName, "shell_metacharacter", shellMetachars) {
		rc.Signals = append(rc.Signals, riskcontext.Signal{Category: "shell_metacharacter"})
	}

	if s.hasDangerousParam(params, toolName, "path_traversal", pathTraversalPatterns) {
		rc.Signals = append(rc.Signals, riskcontext.Signal{Category: "path_traversal"})
	}
}

func (s *ScanStage) hasDangerousParam(params map[string]any, toolName, check string, patterns []string) bool {
	for paramName, value := range params {
		_, isString := value.(string)
		if isString && s.cfg.ParamScanSkipped(toolName, paramName, check) {
			continue
		}
		lower := strings.ToLower(flattenStrings(map[string]any{paramName: value}))
		for _, seq := range patterns {
			if strings.Contains(lower, seq) {
				return true
			}
		}
	}
	return false
}

// flattenStrings recursively collects all string leaf values from a map.
// Slices are walked too: JSON arrays are ordinary tool parameters (argv-style
// args, path lists), and skipping them let a payload evade the dangerous-param
// checks simply by being wrapped in [].
func flattenStrings(m map[string]any) string {
	var parts []string
	for _, v := range m {
		if s := flattenValue(v); s != "" {
			parts = append(parts, s)
		}
	}
	return strings.Join(parts, " ")
}

// flattenValue collects string leaves from any JSON-shaped value.
func flattenValue(v any) string {
	switch val := v.(type) {
	case string:
		return val
	case float64:
		return strconv.FormatFloat(val, 'f', -1, 64)
	case float32:
		return strconv.FormatFloat(float64(val), 'f', -1, 32)
	case int:
		return strconv.Itoa(val)
	case int64:
		return strconv.FormatInt(val, 10)
	case int32:
		return strconv.FormatInt(int64(val), 10)
	case uint:
		return strconv.FormatUint(uint64(val), 10)
	case uint64:
		return strconv.FormatUint(val, 10)
	case uint32:
		return strconv.FormatUint(uint64(val), 10)
	case json.Number:
		return val.String()
	case map[string]any:
		return flattenStrings(val)
	case []any:
		var parts []string
		for _, item := range val {
			if s := flattenValue(item); s != "" {
				parts = append(parts, s)
			}
		}
		return strings.Join(parts, " ")
	}
	return ""
}

// checkMemoryAllowlist emits a signal if the memory key is not in the allowlist.
func (s *ScanStage) checkMemoryAllowlist(rc *riskcontext.RiskContext) {
	key := ""
	if m, ok := rc.Payload.(map[string]any); ok {
		if k, ok := m["key"].(string); ok {
			key = k
		}
	}
	if key != "" && !s.cfg.MemoryKeyAllowed(key) {
		rc.Signals = append(rc.Signals, riskcontext.Signal{Category: "memory:key_not_allowed"})
	}
}
