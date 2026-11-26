# ACF Architecture

## Overview

ACF (Agentic Cognitive Firewall) is a framework-agnostic security layer for LLM agents. It distributes enforcement across the full agent lifecycle through explicit hook call sites rather than a single input boundary.

The system is divided into two zones separated by a hard trust boundary:

- **PEP** (Policy Enforcement Point) — the SDK interceptor that lives inside the agent process
- **PDP** (Policy Decision Point) — the sidecar kernel that runs as a completely isolated process

All policy evaluation happens in the sidecar. The agent cannot reach inside it.

---

## System diagram

![ACF architecture](architecture.png)

---

## Seam 1 — Hook registry

![Hook registry](hook-registry.png)

Hooks self-register into a registry map. The pipeline only calls whatever is registered at each execution point. Adding a new hook is purely additive — the pipeline, IPC layer, and sidecar core do not change.

### Registered hooks

| Hook | Fires when | Primary threat |
|---|---|---|
| `on_prompt` | User input arrives | Direct prompt injection — override system instructions |
| `on_context` | RAG chunks injected | Indirect injection — malicious instructions in retrieved docs |
| `on_tool_call` | Before tool executes | Tool abuse — unsafe tool, malicious parameters, or the attacker's values in a legitimate tool's arguments |
| `on_memory` | Before memory read/write | Memory poisoning — malicious values in persistent state |
| `on_tool_result` | After a tool returns, before the agent reads it | Indirect injection through tool output, told apart by the producing tool |
| `on_task` | A session starts | — declares the session's task scope (allowed tools, trusted values, argument constraints) |
| `on_confirm` | User approves a flagged value mid-session | — promotes confirmed untrusted values in the active session without restarting |

In the sidecar each hook is one entry in `sidecar/internal/hooks`, naming its
Rego package, provenance, OPA input builder and optional payload validator.
`on_tool_result` and `on_task` were added that way, without changing the
transport, the pipeline stages or the policy engine. See
[application-policy-layer.md](application-policy-layer.md) for sessions, task
scope, tool output screening and argument tainting.

### Planned hooks (register without touching existing ones)

| Hook | Fires when |
|---|---|
| `on_outbound` | Before response sent |
| `on_subagent` | Before sub-agent spawned |
| `on_startup` | Gateway initialisation |

### How the registry works

1. On SDK init, each hook calls `registry.register(name, handler)`
2. When agent code calls `firewall.on_prompt(payload)`, the SDK looks up `on_prompt` in the registry and dispatches to the registered handler
3. The handler signs the payload, sends over IPC to the sidecar, waits for the decision, and returns it to the caller
4. Adding a v2 hook = register a new entry. The pipeline dispatcher, IPC layer, and sidecar core are untouched.

### Developer call sites (agent code)

```python
# v1 — four explicit call sites the developer places in their agent

safe   = firewall.on_prompt(user_msg)        # at message ingress
result = firewall.on_context(docs)           # before RAG injection
ok     = firewall.on_tool_call(name, params) # before tool execution
safe   = firewall.on_memory(key, value)      # before memory write
seen   = firewall.on_tool_result(tool, out)  # before the agent reads tool output

# sessions: the same hooks, evaluated as one agent run with a task scope
with firewall.session(allowed_tools=["search", "send_email"]) as s:
    s.on_prompt(user_msg)
    s.on_tool_call("send_email", {"to": "..."})
```

---

## Seam 2 — Risk context object

![Risk context object](risk_context_object.png)

The risk context object is the single payload flowing through the entire PDP pipeline. In v1 the `state` field is always null — evaluation is stateless. In v2 the state store populates it before the pipeline runs. The pipeline, scanners, aggregator, and policy engine do not change between versions.

### v1 — stateless

```
{
  score:      float        # aggregated risk score 0.0–1.0
  signals:    []           # named signals from scanner stages
  provenance: string       # origin of the payload
  session_id: string       # session identifier
  state:      null         # always null in v1
}
```

### v2 — stateful extension (same schema)

```
{
  score:      float
  signals:    []
  provenance: string
  session_id: string
  state: {                 # populated by state store before pipeline runs
    prior_score:   float
    ttl:           int
    decay_factor:  float
    turn_count:    int
  }
}
```

The `state` field was always in the schema — v1 just leaves it null. The policy engine checks `if state != null` before including historical score. Same policy files work in both versions without modification.

### State store (implemented)

`sidecar/internal/state.TTLStore`, an in-memory map keyed by `session_id`. The
session stage, right after validate, hydrates the `state` field for requests
that name a session; a recorder updates the session after the decision.
Sessionless requests keep a null `state`, and a `state` sent by the client is
always discarded.

What the store holds today, and what policies see as `input.state`, is the
session's request counters, its declared task scope, and per-request argument
taint findings, rather than the `prior_score` / `decay_factor` sketch above.
Sessions expire after an idle TTL, and the number held is capped. See
[application-policy-layer.md](application-policy-layer.md).

```
state store ──hydrates──▶ risk context ──pipeline──▶ decision
     ▲                                                   │
     └──────────────── updates after decision ───────────┘
```

### What does NOT change between v1 and v2

- The pipeline stages (validate, normalise, scan, aggregate)
- The IPC transport and binary framing
- The policy engine (Rego / YAML rules)
- The risk context object schema (state field was always there)

---

## IPC transport

Communication between the PEP and PDP uses a Unix domain socket at `/tmp/acf.sock` on Linux and macOS, or a named pipe at `\\.\pipe\acf` on Windows (override with `ACF_SOCKET_PATH`), with length-prefixed binary framing and one connection per request. The channel is authenticated, not encrypted: the property required is integrity across the process boundary. The Python and TypeScript SDKs produce byte-identical frames.

**Frame format:**

| Field | Size | Description |
|---|---|---|
| Magic byte | 1 byte | Fixed value `0xAC` — fast-reject misaddressed connections |
| Version | 1 byte | Protocol version (current: 1) |
| Payload length | 4 bytes | Length of JSON payload |
| Nonce | 16 bytes | Random per-request — replay protection |
| HMAC | 32 bytes | HMAC-SHA256 over (version + length + nonce + payload) |
| Payload | variable | JSON-serialised risk context object |

The sidecar validates the 54-byte header before touching the JSON payload. An invalid HMAC or reused nonce drops the connection immediately.

**Response frame:**

| Field | Size | Description |
|---|---|---|
| Decision | 1 byte | `0x00` ALLOW · `0x01` SANITISE · `0x02` BLOCK |
| Payload length | 4 bytes | 0 if decision is ALLOW (or an unannotated BLOCK) |
| Payload | variable | Present on SANITISE (sanitised payload JSON) and BLOCK (structured `BlockPayload` JSON) |

---

## Pipeline stages

All stages run inside the sidecar and share one risk context, which keeps the
original payload alongside the canonical text, signals, score and session state
derived from it. In the default strict mode, a hard-block signal at any stage
ends evaluation with BLOCK.

| Stage | What it does |
|---|---|
| Verify (transport) | HMAC verification in constant time and the nonce replay check, before the payload is parsed |
| 1. Validate | Looks the hook up in the registry, checks required fields and the hook's payload shape, assigns provenance from the hook, and sets the client's trust-relevant fields aside (its claimed provenance, score and state are not trusted; its signals count only for weighted categories, and only to add risk) |
| 2. Session | Loads the session's state σ: the declared task scope, the values read from untrusted content, and the values a principal vouched for. For a tool call, finds argument values that are untrusted |
| 3. Normalise | Recursive URL and Base64 decoding, Unicode NFKC normalisation, zero-width character removal, whitespace collapsing, leetspeak substitution |
| 4. Scan | Aho-Corasick lexical scan against the pattern library, plus hook-specific checks: tool allowlist, memory keys, shell metacharacters, path traversal |
| 5. Aggregate | Weights each signal by its category, takes the maximum, and multiplies by the provenance trust weight, giving a score from 0 to 1 |
| 6. Policy | Evaluates the Rego module registered for the hook against the request, signals, score and session state. The only stage that decides; every module is fail-closed |
| 7. Execute | Applies the transformation a SANITISE decision declares (redaction) to the original payload |
| 8. Record | Updates the session: values in an admitted tool result or retrieved chunk become untrusted, values in the prompt or declared scope trusted. Blocked content records nothing |

The semantic scanner, when enabled, runs in the SDK on the agent's side of the
boundary, before any of these stages. Its output arrives as client signals,
which can raise a request's risk but never lower it.

### Policy engine
OPA Go SDK embedded in the sidecar. Evaluates the Rego package registered for
the hook. Returns a decision and, for SANITISE, the targets to transform; the
executor performs the transformation. The tool-call module also applies the
task scope and the provenance rule from the session state, so a call can be
blocked without any detection signal:

```rego
decision := "ALLOW" if {
    _tool_is_permitted                # global allowlist
    _in_task_scope                    # the task's declared tools
    _constraints_satisfied            # the task's argument bounds
    not _tainted_consequential_call   # provenance: no untrusted value in a sensitive argument
    not _has_detection_signal
    input.score < 0.4
}
```

---

## Policy store (PMP)

Rego files and their data, on disk. The policy engine re-reads the directory
every 5 seconds and swaps in recompiled queries atomically; a compilation
failure leaves the previous policies active. The pattern library is loaded at
startup.

```
policies/
└── v1/
    ├── prompt.rego          instruction override · role escalation · thresholds
    ├── context.rego         source trust · embedded instruction · structural anomaly
    ├── tool.rego            allowlist · destination · detection · task scope · argument constraints · provenance
    ├── tool_result.rego     score thresholds · trusted tools
    ├── memory.rego          integrity · write scan · size limit
    ├── task.rego            a task scope may only narrow the global allowlist
    └── data/
        ├── policy_config.yaml         thresholds · allowlists · trust weights · signal weights ·
        │                              consequential_tools · sensitive_params · trusted_tools
        └── jailbreak_patterns.json    versioned pattern library (79 phrases in 13 categories)
```

Policy logic (Rego) and policy data (YAML/JSON) are kept separate: the rules
are the same for every deployment, and an application supplies the data.
[`examples/banking/`](../examples/banking/) shows an application's policy file.

---

## Observability

Today the sidecar writes a decision log with per-stage timing, off the request
path. OpenTelemetry span emission is planned: spans would be emitted
asynchronously after each decision, carrying the hook, decision, score, signals
and provenance, and linking to the agent's own trace.

---

## Enforcement latency

Measured on a Windows laptop over named pipes (see
[`benchmarkv2/overhead/`](../benchmarkv2/overhead/) and
[`benchmarkv2/agentdojo/latency_agentdojo.py`](../benchmarkv2/agentdojo/latency_agentdojo.py)):

| Measurement | p50 | p99 |
|---|---:|---:|
| Hook call without session state, semantic scanner off | 0.21–0.26 ms | about 0.5–0.6 ms |
| Hook call with a session, task scope and provenance tracking, on AgentDojo payloads | 0.53 ms | 3.1 ms |
| Inside the sidecar (two-thirds of it policy evaluation) | about 0.2 ms | |

A 64 KB payload takes about 6 ms, mostly normalisation. The sidecar process uses
about 75 MB. With the semantic scanner on, the SDK adds about 0.5 ms (TF-IDF) or
about 20 ms (sentence-transformer) per call.

---

## Language decisions

| Component | Language | Reason |
|---|---|---|
| Sidecar | Go 1.25+ | OPA Go SDK embeds natively · single binary · native UDS + goroutine concurrency |
| SDK v1 | Python 3.10+ | LangGraph/LangChain first · zero external dependencies (stdlib only) |
| SDK | TypeScript / Node 18+ | Same wire protocol and payloads as Python · no runtime dependencies · no semantic scanner |
| Policies | Rego + YAML | Declarative · hot-reloadable · testable with `opa test` |

---

## Build phases

### Phase 1 — Wire protocol and crypto
Goal: SDK can send a signed frame, sidecar can receive and verify it.
- `sidecar/internal/transport` — UDS listener, binary frame read/write
- `sidecar/internal/crypto` — HMAC sign/verify, nonce store
- `sidecar/pkg/riskcontext` — RiskContext struct
- `sdk/python` — Firewall skeleton, transport, frame
- Deliverable: working IPC round-trip with cryptographic verification

### Phase 2 — Pipeline stages
Goal: sidecar runs all four stages on a real payload.
- `sidecar/internal/pipeline` — all four stages
- `sidecar/internal/state/noop.go` — no-op StateStore wired in
- Deliverable: pipeline produces a populated RiskContext (hardcoded ALLOW)

### Phase 3 — OPA integration and policy files
Goal: real policy decisions from Rego files including SANITISE with targets.
- `sidecar/internal/policy` — OPA engine, executor, sanitise
- `policies/v1/` — all four Rego files and data
- Deliverable: end-to-end enforcement with sanitised responses

### Phase 4 — Observability and integration test suite
Goal: auditable, testable, production-ready v1.
- `sidecar/internal/telemetry` — async OTel span emission
- `tests/integration/` — 33-payload adversarial test suite
- SDK adapters — FirewallNode for LangGraph
- Deliverable: shippable v1 with all policies tested

### v2 (after v1 ships)
Done: `state/ttl_store.go`, sessions, `on_tool_result`, task scope and argument tainting (see [application-policy-layer.md](application-policy-layer.md)), and the TypeScript SDK with sessions.
Remaining: `on_outbound` hook · accumulation policies · memory hook split into `on_memory_write` / `on_memory_read` · sidecar-signed memory integrity stamps · OpenTelemetry spans
