package pipeline

import (
	"testing"
	"time"

	"github.com/acf-sdk/sidecar/internal/state"
	"github.com/acf-sdk/sidecar/pkg/decision"
	"github.com/acf-sdk/sidecar/pkg/riskcontext"
)

// stateCapture is an Evaluator that records the state each request reached
// policy with.
type stateCapture struct {
	verdict string
	seen    []any
}

func (s *stateCapture) Evaluate(rc *riskcontext.RiskContext) (string, []string, error) {
	s.seen = append(s.seen, rc.State)
	return s.verdict, nil, nil
}

func sessionPipeline(store state.StateStore, ev Evaluator) *Pipeline {
	cfg := testConfig(true)
	stage := NewSessionStage(store)
	return NewWithEvaluator(cfg, []Stage{
		NewValidateStage(),
		stage,
		NewNormaliseStage(),
		NewScanStage(cfg, nil),
		NewAggregateStage(cfg, testWeights()),
	}, ev).OnDecision(stage)
}

func prompt(session string) *riskcontext.RiskContext {
	return &riskcontext.RiskContext{HookType: "on_prompt", Provenance: "user", SessionID: session, Payload: "hi"}
}

func TestSession_StateAccumulatesAcrossRequests(t *testing.T) {
	store := state.NewTTLStore(time.Minute, 10)
	defer store.Stop()
	ev := &stateCapture{verdict: "BLOCK"}
	pl := sessionPipeline(store, ev)

	pl.Run(prompt("s1"))
	pl.Run(prompt("s1"))
	pl.Run(prompt("s1"))

	if ev.seen[0] != nil {
		t.Errorf("first request in a session should see no state, got %v", ev.seen[0])
	}
	third, ok := ev.seen[2].(map[string]any)
	if !ok || third["requests"] != 2 || third["blocked"] != 2 {
		t.Errorf("third request saw %v, want 2 earlier requests, both blocked", ev.seen[2])
	}
}

func TestSession_SessionsAreIsolated(t *testing.T) {
	store := state.NewTTLStore(time.Minute, 10)
	defer store.Stop()
	ev := &stateCapture{verdict: "ALLOW"}
	pl := sessionPipeline(store, ev)

	pl.Run(prompt("s1"))
	pl.Run(prompt("s2"))
	if ev.seen[1] != nil {
		t.Errorf("s2 saw state from s1: %v", ev.seen[1])
	}
}

func TestSession_SessionlessRequestsKeepNoState(t *testing.T) {
	store := state.NewTTLStore(time.Minute, 10)
	defer store.Stop()
	ev := &stateCapture{verdict: "ALLOW"}
	pl := sessionPipeline(store, ev)

	pl.Run(prompt(""))
	pl.Run(prompt(""))
	if ev.seen[1] != nil || store.Len() != 0 {
		t.Errorf("sessionless requests created state: seen=%v sessions=%d", ev.seen[1], store.Len())
	}
}

func TestSession_ClientStateNeverReachesPolicy(t *testing.T) {
	store := state.NewTTLStore(time.Minute, 10)
	defer store.Stop()
	ev := &stateCapture{verdict: "ALLOW"}
	pl := sessionPipeline(store, ev)

	rc := prompt("s1")
	rc.State = map[string]any{"allowed_tools": []any{"send_money"}}
	pl.Run(rc)
	if ev.seen[0] != nil {
		t.Errorf("a client-sent state reached policy: %v", ev.seen[0])
	}
}

func TestSession_MalformedIDIsHardBlocked(t *testing.T) {
	store := state.NewTTLStore(time.Minute, 10)
	defer store.Stop()
	pl := sessionPipeline(store, &stateCapture{verdict: "ALLOW"})

	for _, id := range []string{
		"has space", "semi;colon", string(make([]byte, 129)),
		"run-1\n", "run-1\r\n", "run-1\u2028",
	} {
		res := pl.Run(prompt(id))
		if res.Decision != decision.Block || res.BlockedAt != "session" {
			t.Errorf("session id %q: decision=%d blocked_at=%q, want BLOCK at session", id, res.Decision, res.BlockedAt)
		}
	}
	if store.Len() != 0 {
		t.Errorf("malformed IDs created %d sessions", store.Len())
	}
}
