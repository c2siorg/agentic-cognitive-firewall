// session.go — the session stage.
// Runs after validate. For a request that names a session, it loads the
// session's state into rc.State so policies can read it as input.state, and
// after the decision it records the request in the session. A request with no
// session_id is evaluated on its own, exactly as before sessions existed.
package pipeline

import (
	"regexp"
	"sort"

	"github.com/acf-sdk/sidecar/internal/state"
	"github.com/acf-sdk/sidecar/internal/taint"
	"github.com/acf-sdk/sidecar/pkg/decision"
	"github.com/acf-sdk/sidecar/pkg/riskcontext"
)

// sessionIDPattern bounds session IDs to a short, printable set, so an ID can
// be logged and keyed safely. The SDK generates 32 hex characters.
var sessionIDPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)

// SessionStage hydrates and records per-session state.
type SessionStage struct {
	store state.StateStore
}

// NewSessionStage returns a SessionStage backed by store.
func NewSessionStage(store state.StateStore) *SessionStage {
	return &SessionStage{store: store}
}

func (s *SessionStage) Name() string { return "session" }

// Run loads the session's state into rc.State. It hard-blocks a malformed
// session ID rather than treating the request as sessionless, because a
// sessionless request would skip the session's restrictions.
func (s *SessionStage) Run(rc *riskcontext.RiskContext) (hardBlock bool) {
	if rc.HookType == "on_task" {
		return s.checkTask(rc)
	}
	if rc.SessionID == "" {
		return false
	}
	if !sessionIDPattern.MatchString(rc.SessionID) {
		rc.Signals = append(rc.Signals, riskcontext.Signal{Category: "validate:invalid_session_id"})
		return true
	}
	if sess := s.store.Get(rc.SessionID); sess != nil {
		view := sess.View()
		if rc.HookType == "on_tool_call" {
			if findings := taintFindings(rc.Payload, sess); len(findings) > 0 {
				// Policy decides from the findings; the signal is for the
				// decision log and per-hook attribution.
				view["taint"] = findings
				rc.Signals = append(rc.Signals, riskcontext.Signal{Category: "taint:untrusted_argument"})
			}
		}
		rc.State = view
	}
	return false
}

// taintFindings lists the values in a tool call's arguments that the session
// read in untrusted content and nobody vouched for. Each finding names the
// argument, the value and every source it was read from. Once the session has
// stopped tracking new values (TaintOverflow), an argument value it does not
// know is reported with an "overflow" source, so policy fails closed rather
// than trusting a value it can no longer vouch for.
func taintFindings(payload any, sess *state.Session) []any {
	if len(sess.Untrusted) == 0 && !sess.TaintOverflow {
		return nil
	}
	m, _ := payload.(map[string]any)
	params, _ := m["params"].(map[string]any)
	names := make([]string, 0, len(params))
	for name := range params {
		names = append(names, name)
	}
	sort.Strings(names)

	var findings []any
	for _, name := range names {
		for _, tok := range taint.ExtractUntrusted(flattenValue(params[name])) {
			key := tok.Key()
			if sess.Trusted[key] {
				continue
			}
			srcs, known := sess.Untrusted[key]
			if !known {
				if !sess.TaintOverflow {
					continue
				}
				srcs = []state.TaintSource{{Hook: "overflow"}}
			}
			sources := make([]any, len(srcs))
			for i, src := range srcs {
				sources[i] = map[string]any{"hook": src.Hook, "tool": src.Tool}
			}
			findings = append(findings, map[string]any{
				"param":   name,
				"kind":    tok.Kind,
				"value":   tok.Value,
				"sources": sources,
			})
		}
	}
	return findings
}

// checkTask validates an on_task declaration before policy sees it. A scope
// needs a session to belong to, must parse, and is declared once: the scope a
// session starts with holds for its lifetime, and a new task needs a new
// session. Policy then decides whether the scope stays within global policy.
func (s *SessionStage) checkTask(rc *riskcontext.RiskContext) (hardBlock bool) {
	if rc.SessionID == "" {
		rc.Signals = append(rc.Signals, riskcontext.Signal{Category: "task:no_session"})
		return true
	}
	if !sessionIDPattern.MatchString(rc.SessionID) {
		rc.Signals = append(rc.Signals, riskcontext.Signal{Category: "validate:invalid_session_id"})
		return true
	}
	if _, err := state.ParseTaskScope(rc.Payload); err != nil {
		rc.Signals = append(rc.Signals, riskcontext.Signal{Category: "task:invalid_scope"})
		return true
	}
	if sess := s.store.Get(rc.SessionID); sess != nil {
		if sess.Task != nil {
			rc.Signals = append(rc.Signals, riskcontext.Signal{Category: "task:already_declared"})
			return true
		}
		rc.State = sess.View()
	}
	return false
}

// Record updates the session after a decision. The pipeline calls it once per
// request that reached policy evaluation. An allowed on_task stores the scope;
// if two declarations race, the first to be recorded wins.
func (s *SessionStage) Record(rc *riskcontext.RiskContext, d byte) {
	if rc.SessionID == "" || !sessionIDPattern.MatchString(rc.SessionID) {
		return
	}
	s.store.Update(rc.SessionID, func(sess *state.Session) {
		sess.Requests++
		if d == decision.Block {
			// The agent never sees blocked content, and values in a blocked
			// request are never trusted.
			sess.Blocked++
			return
		}
		switch rc.HookType {
		case "on_task":
			if d == decision.Allow && sess.Task == nil {
				if scope, err := state.ParseTaskScope(rc.Payload); err == nil {
					sess.Task = scope
					for _, v := range scope.TrustedValues {
						for _, tok := range taint.ExtractClean(v) {
							sess.AddTrusted(tok.Key())
						}
					}
				}
			}
		case "on_prompt":
			// The user's own request: values in it are the user's to direct.
			// On SANITISE, extract only from the redacted text so tokens inside
			// removed spans are never promoted to trusted.
			text := ""
			if d == decision.Sanitise {
				text = rc.SanitisedText
			} else if raw, ok := rc.Payload.(string); ok {
				text = raw
			}
			for _, tok := range taint.ExtractClean(text) {
				sess.AddTrusted(tok.Key())
			}
		case "on_context", "on_tool_result":
			// Content the agent is about to read. A SANITISE is recorded too:
			// the sanitised text may keep values, and over-tainting can only
			// block more, never less.
			text, tool := untrustedText(rc)
			src := state.TaintSource{Hook: rc.HookType, Tool: tool}
			for _, tok := range taint.ExtractUntrusted(text) {
				sess.AddUntrusted(tok.Key(), src)
			}
		}
	})
}

// untrustedText returns the content of an on_context or on_tool_result
// request, and the producing tool for on_tool_result.
func untrustedText(rc *riskcontext.RiskContext) (text, tool string) {
	switch p := rc.Payload.(type) {
	case string:
		return p, ""
	case map[string]any:
		if rc.HookType == "on_tool_result" {
			text, _ = p["result"].(string)
			tool, _ = p["tool"].(string)
			return text, tool
		}
		text, _ = p["content"].(string)
	}
	return text, ""
}
