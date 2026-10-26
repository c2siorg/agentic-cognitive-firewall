# ACF — Agentic Cognitive Firewall

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Build](https://github.com/c2siorg/agentic-cognitive-firewall/actions/workflows/ci.yml/badge.svg)](https://github.com/c2siorg/agentic-cognitive-firewall/actions/workflows/ci.yml)

ACF is an application-level policy layer for LLM agents. It checks
everything an agent takes in and every action it is about to take — the user's
prompt, retrieved documents, tool output, tool calls and memory — against
policies you write as code, and returns **ALLOW**, **SANITISE** or **BLOCK**.
Decisions are made in a separate sidecar process the agent cannot reach into,
with no model in the decision, so they do not depend on the agent's code or on
which model runs it. That makes it a fit for agents on local hardware with small
open-weight models: on AgentDojo it removes 92–93% of successful attacks for
models from 8B to 120B parameters, at about half a millisecond per check.

**New here?** The [plain-language overview](docs/overview.md) explains what the
SDK and sidecar do before any of the detail below.

---

## Why this exists

An LLM agent does not have one front door. It reads the user's message, pulls
documents from a vector store, calls tools and reads their output, and reads and
writes memory. Any of these can carry instructions an attacker planted, and the
indirect ones — a poisoned web page, an email, a tool response — reach the model
long after a front-door filter has looked at the prompt. Because agents act
through tools, a successful injection is not just a wrong answer: it can send
email, move money or delete files.

Most defences put the decision in a model: they train the agent's model to
resist, or add a guard model that classifies text as safe or unsafe. That binds
security to the model. A team that runs a small model locally, for cost or to
keep data in house, gets the least robust model, and a guard model adds an
inference call to every step. Detection also fails against attacks written to
look benign: in an AgentDojo run whose injections were written as polite notes
signed by the user, ACF's own lexical scanner flagged none of the 11,228 tool
results it screened.

ACF makes security a property of the application around the model instead:

- **Policy decides; detection only informs.** Scanners produce evidence. The
  decision rests on what the task is allowed to do, so it holds whether or not
  the attack was recognised, and whether the model was fooled, confused or
  simply wrong.
- **Where a value came from informs a decision but never grants authority.** A
  payment to an account number the agent read in a document is blocked, even
  when nothing in the document or the call looks malicious, unless the user
  vouched for it.
- **Use what the application knows.** A deployment declares what a task may do
  — which tools, which argument values, which sources it controls — and the
  sidecar enforces it for the whole agent session. The rules are shared; each
  application supplies its own policy data.
- **Check every channel** where content enters the agent or an action leaves it,
  and **decide outside the agent**, in an isolated Go sidecar that invokes no
  model and adds about half a millisecond per check.

---

## How it works

![ACF architecture](docs/architecture.png)

Two zones separated by an operating-system process boundary:

- **PEP (policy enforcement point)** — a thin SDK inside the agent process. It
  wraps each check as a signed request and sends it to the sidecar.
- **PDP (policy decision point)** — a Go sidecar. All detection and policy
  evaluation happens here.

They talk over a Unix domain socket (`/tmp/acf.sock`) on Linux and macOS, or a
named pipe (`\\.\pipe\acf`) on Windows. Every request is signed with
HMAC-SHA256 and carries a fresh nonce; a bad signature or replayed nonce is
dropped before the payload is parsed.

### Enforcement points (hooks)

| Hook | Called | Stops |
|---|---|---|
| `on_prompt` | When user input arrives | Direct prompt injection |
| `on_context` | Before retrieved chunks enter the model's context | Indirect injection in documents |
| `on_tool_result` | Before the agent reads a tool's output | Indirect injection in tool output, told apart by the producing tool |
| `on_tool_call` | Before a tool runs | Disallowed tools, dangerous parameters, and the attacker's values in a legitimate tool's arguments |
| `on_memory` | Before a memory read or write | Memory poisoning |
| `on_task` | When a session starts (sent for you) | Declares the session's task scope |

### Decisions

| Decision | Meaning |
|---|---|
| `ALLOW` | Pass the input or action through unchanged |
| `SANITISE` | Use the cleaned version the sidecar returns |
| `BLOCK` | Do not proceed |

### The pipeline

```
verify → validate → session → normalise → scan → aggregate → OPA policy → execute → record
```

| Stage | What it does |
|---|---|
| Verify | Checks the HMAC and nonce before the payload is parsed (in the transport) |
| Validate | Schema checks; assigns provenance per hook and sets aside fields the client must not control |
| Session | Loads the session's state (task scope, trusted and untrusted values) and finds argument values read from untrusted content |
| Normalise | Decodes URL and Base64, NFKC-normalises Unicode, strips zero-width characters, collapses whitespace, undoes leetspeak |
| Scan | Aho-Corasick pattern scan, allowlist and parameter checks |
| Aggregate | Combines signals into a 0.0–1.0 risk score, weighted by provenance |
| OPA policy | Rego decides per hook, using the score, signals and session state. The only stage that decides |
| Execute | Applies the transformation a SANITISE asks for |
| Record | Updates the session: values in an admitted tool result become untrusted, values in the prompt trusted |

The stages before the policy only gather evidence. In the default strict mode, a
hard block at any stage short-circuits to BLOCK.

### Sessions and the application policy layer

Calls made through `firewall.session()` are evaluated as one agent run. On top
of the per-request checks, a session can:

- **declare a task scope** — the tools the task needs and bounds on their
  arguments; anything outside it is blocked, and a scope can only narrow global
  policy, never widen it;
- **taint values from untrusted content** — email addresses, URLs, IBANs and
  account numbers the agent read in documents or tool output; a consequential
  tool (`send_email`, `send_money`, ...) whose argument repeats one is blocked
  unless the user or developer vouched for the value;
- **trust specific tools' output** — so an internal payment API's response can
  flow into a payment while the same IBAN read on a web page cannot.

See [docs/application-policy-layer.md](docs/application-policy-layer.md).

### Writing an application policy

The Rego rules are the same for every deployment. An application supplies the
data they read, in `policies/v1/data/policy_config.yaml`, and declares each
task's scope in code:

| Who | What | Where |
|---|---|---|
| ACF | The rules | `policies/v1/*.rego` (not edited) |
| Developer, once per application | The tools the application may use, which of them are consequential, which argument decides where money or data goes, and which tools' output it controls | `policy_config.yaml`: `tool_allowlist`, `consequential_tools`, `sensitive_params`, `trusted_tools` |
| Application, once per task | The task's tools, bounds on their arguments, and values the user confirmed | `fw.session(allowed_tools=..., tool_constraints=..., trusted_values=...)` |
| Application, at each boundary | The hook calls | `on_prompt`, `on_tool_call`, `on_tool_result`, ... or a framework adapter |

[`examples/banking/`](examples/banking/) is a complete worked example: a
banking agent's policy file, and scripts showing task scope, tool-result
screening, the provenance rule with user confirmation, and an agent loop.

---

## Quick start

### Prerequisites

- Go 1.25+ (to build the sidecar)
- Python 3.10+ (the SDK has no required dependencies)

### 1. Create a shared key

```bash
export ACF_HMAC_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
```

The sidecar and the SDK must use the same key.

### 2. Build and run the sidecar

```bash
make build            # or: cd sidecar && go build -o ../bin/acf-sidecar ./cmd/sidecar
./bin/acf-sidecar
# sidecar: OPA engine ready (policy_dir=.../policies/v1)
# sidecar: pipeline ready (mode=strict, block_threshold=0.85)
# sidecar: listening on /tmp/acf.sock
```

It reads `config/sidecar.yaml` (override with `ACF_CONFIG`) and the policies in
`policies/v1/`. Set `ACF_SOCKET_PATH` to listen somewhere else.

### 3. Install the SDK and make some calls

```bash
pip install -e sdk/python
```

```python
from acf import Firewall, Decision, SanitiseResult

fw = Firewall()   # reads ACF_HMAC_KEY and ACF_SOCKET_PATH

fw.on_prompt("What is the capital of France?")             # Decision.ALLOW
fw.on_prompt("Ignore previous instructions and ...")       # Decision.BLOCK

for chunk in fw.on_context(retrieved_docs):                # one result per chunk
    if chunk.decision is Decision.SANITISE:
        use(chunk.sanitised_text)

result = fw.on_tool_call("search", {"query": "weather"})
```

### 4. Use a session with a task scope

```python
with fw.session(
    allowed_tools=["get_balance", "send_money", "web_fetch"],
    trusted_values=["GB29NWBK60161331926819"],   # a payee the user saved
    tool_constraints={"send_money": {"amount": {"max": 100}}},
) as s:
    s.on_prompt(user_message)
    page = s.on_tool_result("web_fetch", html)   # screened before the agent reads it
    if isinstance(page, SanitiseResult):
        html = page.sanitised_text
    decision = s.on_tool_call("send_money", {"recipient": iban, "amount": 20})
```

`session()` raises `FirewallError` if the sidecar rejects the scope.

### Optional: semantic scanning

The lexical scan in the sidecar catches known phrasings. For paraphrases, the
SDK can add an embedding-based scanner (TF-IDF or a sentence-transformer):

```bash
pip install -e 'sdk/python[scanners]'
```

```python
fw = Firewall(enable_semantic_scan=True, semantic_backend="sentence-transformer")
```

### Docker

```bash
docker compose up -d                                  # sidecar
docker compose --profile observability up -d          # plus an OpenTelemetry collector
cd demo && docker compose up --build                  # nine attack scenarios, no API keys
```

---

## What's in this repo

| Path | What it is |
|---|---|
| [`sidecar/`](sidecar/) | The Go policy decision point: IPC transport and crypto, the pipeline stages, the OPA engine, the session store, value tainting, and the hook registry |
| [`sdk/python/`](sdk/python/) | The Python SDK: `Firewall`, `Session`, the optional semantic scanner, and framework adapters |
| [`sdk/typescript/`](sdk/typescript/) | The TypeScript SDK for Node: `Firewall`, `Session`, `guardTool`, and a LangGraph.js node; same wire protocol as Python |
| [`policies/v1/`](policies/v1/) | Rego policies, one per hook, with their unit tests, plus `data/` (thresholds, allowlists, trust settings, signal weights, the pattern library) |
| [`config/`](config/) | Sidecar configuration (`sidecar.yaml`, with an annotated example) |
| [`tests/integration/`](tests/integration/) | End-to-end tests against the real sidecar binary: an 80-case adversarial corpus, gap probes, forgery probes and session flows |
| [`examples/`](examples/) | Runnable scripts: one hook at a time, a banking agent with its own policy, framework adapters, and the TypeScript SDK |
| [`demo/`](demo/) | A Docker demo of nine attack scenarios, three of them in a session under the banking policy |
| [`benchmarks/`](benchmarks/) | Replays public benchmark payloads through ACF with no model (detector catch rates) |
| [`benchmarkv2/`](benchmarkv2/) | Evaluations for the paper: runtime overhead, InjecAgent with a live agent, AgentDojo (model-free replay and live agent), and an Agent Security Bench scaffold |
| [`docs/`](docs/) | Architecture, design notes, threat analysis and the paper sources |
| [`scripts/`](scripts/) | Utilities, such as measuring the semantic scanner's detection rate |

### Framework integrations

| Integration | Status |
|---|---|
| LangChain — `acf.adapters.langchain.guard_tools` | Wraps tools so each call and result passes through ACF; with a `Session`, task scope and the provenance rule apply. Also works for LangGraph agents |
| LangGraph — `acf.adapters.langgraph.FirewallNode` | Any hook as a graph node; accepts a `Session` |
| Agent Kernel — `acf.adapters.agent_kernel.ACFInputGuardrail` | Input guardrail; accepts a `Session` |
| TypeScript — `sdk/typescript` | `guardTool` for any async tool function, and `firewallNode` for LangGraph.js |

---

## Testing

```bash
make test               # Go unit tests, including the Rego policy tests
make sdk-test-python    # Python SDK tests
make sdk-test-ts        # TypeScript SDK tests (against a fake sidecar)
make examples           # every example against a freshly built sidecar
make integration        # end-to-end tests against a freshly built sidecar
make test-all           # all of the above, plus the benchmark tests
make opa-test           # Rego tests with the opa binary, if you have it
```

CI runs on every push and pull request to `main`:

| Job | What it runs |
|---|---|
| Go tests | Sidecar unit tests and Rego policy tests, `go vet` |
| Integration tests | The real sidecar binary against the adversarial corpus, probes and session flows, on Ubuntu and Windows |
| Python tests | The Python SDK, and the framework adapters against real LangChain |
| TypeScript tests | The TypeScript SDK against a fake sidecar that verifies every frame |
| Examples | Every example in `examples/` against a freshly built sidecar, under the shipped and the banking policy |
| AgentDojo benchmark | The benchmark's tests and a two-task replay with no model |

---

## Evaluation

On [AgentDojo](https://github.com/ethz-spylab/agentdojo), the default benchmark,
with three open-weight models served on local hardware (949 attacked cases each):

| Agent model | Attack success, undefended | With ACF | Attacks removed | Benign tasks completed, undefended → with ACF |
|---|---:|---:|---:|---:|
| Qwen3 8B | 11.3% | 0.8% | 93% | 39% → 30% |
| Gemma 4 26B | 19.6% | 1.6% | 92% | 84% → 67% |
| gpt-oss-120b | 37.9% | 2.7% | 93% | 72% → 55% |

- **The protection comes from policy, not detection.** Content scanning alone
  changed nothing on this attack; task scope and the provenance rule did the
  work.
- **It holds without a model's help**: an agent scripted to obey every injected
  instruction goes from 98.0% attack success to 3.1%.
- **What remains** are attacks with no destination to track, such as opening a
  web page. No payment, message or invitation to an attacker's address got
  through with any model.
- **The cost** is benign task completion, mostly where the user wants the agent
  to act on an address or account it read; asking the user to confirm the
  destination recovers about half of it. Each check takes about 0.5 ms.

Full results, the scanner comparison, latency, limits and the run behind every
number: [docs/evaluation.md](docs/evaluation.md). To reproduce: `make bench-setup`
once, then `make bench` for the model-free replay (about 7 minutes) or
`make bench-agent MODEL=... BASE_URL=...` for a live agent. Other benchmarks
(runtime overhead, InjecAgent, Agent Security Bench) are in
[`benchmarkv2/`](benchmarkv2/README.md).

---

## Security model and limits

- **The enforcement point is in-process.** ACF protects an honest agent from
  injected content and from forged or misconfigured fields. It cannot stop a
  fully compromised agent process from simply not calling the hooks; that would
  need tools to be reachable only through the sidecar.
- **Detection is best-effort; policy is the guarantee.** Pattern and semantic
  detection miss paraphrased and novel attacks. Task scope and argument tainting
  do not depend on recognising an attack, which is why they carry the stronger
  claims.
- **Tainting covers the value types it extracts**: email addresses, URLs and
  their hosts (with or without a scheme), IBANs and account numbers in IBAN
  form, and long numbers. A name or a paraphrased instruction is not tracked,
  and an attack whose goal has no destination value, such as opening a web
  page, is outside the provenance rule.
- **Memory reads rely on a client-supplied integrity flag**, which the SDKs do
  not send yet, so reads are blocked (fail closed). A proper fix needs a
  sidecar-signed stamp and a wire protocol change.
- **The semantic scanner runs in the agent process**, so its signals can only
  add risk; the sidecar never lets them lower it.

[docs/mitre-atlas-analysis.md](docs/mitre-atlas-analysis.md) maps coverage and
gaps against MITRE ATLAS.

---

## Status and roadmap

| | Goal | Status |
|---|---|---|
| Phase 1 | Wire protocol, HMAC and nonce crypto | Done |
| Phase 2 | Pipeline stages | Done |
| Phase 3 | OPA integration and Rego policies | Done |
| Phase 4 | Integration test suite; OpenTelemetry observability | Test suite done; OpenTelemetry not started (a per-request timing log exists) |
| v2 | Sessions, `on_tool_result`, task scope, argument tainting | Done |
| v2 | TypeScript SDK with sessions and tool-result screening | Done (no semantic scanner) |
| v2 | `on_outbound`, `on_subagent`, accumulation policies, signed memory integrity | Planned |

---

## Documentation

- [Overview](docs/overview.md) — plain-language introduction
- [Evaluation](docs/evaluation.md) — AgentDojo results with three local models, scanners, latency, limits
- [Architecture](docs/architecture.md) — full design, wire protocol, pipeline
- [Application policy layer](docs/application-policy-layer.md) — sessions, task scope, tool output, tainting
- [Pipeline](docs/pipeline.md) — stage-by-stage detail
- [Semantic scanner](docs/semantic-scanner.md) — the optional embedding-based detector
- [Crypto](docs/crypto.md) — HMAC signing and nonce replay protection
- [MITRE ATLAS analysis](docs/mitre-atlas-analysis.md) — threat mapping and residual risk
- [NIST SP 800-53 SI-10 mapping](docs/nist-800-53-mapping.md) — information input validation and residual risk
- [Phase 1](docs/phase1.md) · [Phase 2](docs/phase2.md) · [Phase 3](docs/phase3.md) — implementation notes per phase
- [Policies](policies/v1/README.md) — the Rego policies and their coverage
- [Philosophy](PHILOSOPHY.md) — design principles
- [Implementation log](docs/implementation_log.md) — decisions, trade-offs and corrections over time

---

## License

Apache 2.0 — see [LICENSE](LICENSE).
