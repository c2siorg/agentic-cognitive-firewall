# The application policy layer

ACF's detectors look for attacks in text. This layer adds what a deployment
knows about its own application: which tools a task needs, which values the
user or developer vouches for, and which tools' output it controls. The sidecar
enforces that per session, at every enforcement point, whatever model runs the
agent.

It rests on four mechanisms, each described below:

| Mechanism | Stops | Configured by |
|---|---|---|
| **Sessions** | — (the foundation: the sidecar remembers earlier calls in an agent run) | `Firewall.session()`; `session` block in `sidecar.yaml` |
| **Task scope** | Tools the task never needed; arguments outside declared bounds | `allowed_tools`, `tool_constraints` on `Firewall.session()` |
| **Tool output screening** | Injected instructions in tool output, told apart by the producing tool | `on_tool_result`; `trusted_tools` in `policy_config.yaml` |
| **Argument tainting** | A legitimate tool called with the attacker's arguments, e.g. `send_email` to an address an injected page planted | `consequential_tools`, `sensitive_params`, `trusted_tools` in `policy_config.yaml`; `trusted_values` on `Firewall.session()` |

The sidecar also no longer accepts the trust-relevant fields a client sends:
see [Server-side trust](#server-side-trust).

## Using it

```python
from acf import Firewall

firewall = Firewall()

with firewall.session(
    allowed_tools=["get_balance", "send_money", "web_fetch"],
    trusted_values=["GB29NWBK60161331926819"],          # the user's saved payee
    tool_constraints={
        "send_money": {"amount": {"max": 100}},
    },
) as s:
    s.on_prompt(user_message)                     # values the user names become trusted
    page = s.on_tool_result("web_fetch", html)    # screened; its values become untrusted
    ok = s.on_tool_call("send_money", {"recipient": iban, "amount": 20})
```

- `firewall.session()` without arguments gives a session with no task scope:
  tainting and tool output screening still apply.
- The `Firewall`'s own hook methods stay sessionless and behave exactly as
  before, so existing integrations are unaffected.
- If the sidecar rejects the scope, `session()` raises `FirewallError`, so an
  agent never runs believing it is scoped when it is not.
- A `Session` works in place of a `Firewall` in the LangGraph `FirewallNode`.

## Sessions

A session is a sequence of hook calls the sidecar treats as one agent run,
named by a `session_id` the SDK puts on each call. The SDK generates 128 random
bits by default; a supplied ID must be 1–128 characters from
`A-Z a-z 0-9 . _ : -`, and a malformed one is blocked rather than treated as
sessionless.

The sidecar keeps each session's state in memory (`state.TTLStore`): the
declared task scope, the values for tainting, and request counters. A session
expires after `session.ttl_seconds` without a call (default 1800). At most
`session.max_sessions` are held (default 10000); at the cap, expired sessions
are swept first and then the least recently seen is evicted. Evicting a session
forgets its scope and tainting, so size the cap for your concurrency.

Policies read the session as `input.state`:

```json
{
  "requests": 3,
  "blocked": 0,
  "task": {"allowed_tools": [...], "trusted_values": [...], "tool_constraints": {...}},
  "taint": [{"param": "to", "kind": "email", "value": "attacker@evil.example",
             "sources": [{"hook": "on_tool_result", "tool": "web_fetch"}]}]
}
```

`task` is present once declared; `taint` only on a tool call with findings.

## Task scope

Declared once per session through the `on_task` hook, which `session()` sends
for you:

- `allowed_tools` — the tools the task may call.
- `tool_constraints` — per tool, per argument, any of `allowed` (a list of
  permitted values), `pattern` (an RE2 regular expression) and `max` (the
  largest number). All checks in a rule must hold. An argument the call does
  not pass is not checked; an empty `allowed` list permits nothing; a `pattern`
  or `max` applied to the wrong type fails closed.
- `trusted_values` — values the developer vouches for, used by tainting.

Rules:

- **A scope can only narrow global policy.** `task.rego` rejects a scope that
  names a tool outside `tool_allowlist` in `policy_config.yaml`.
- **A scope is set once.** A second declaration in the same session is
  blocked; a new task needs a new session.
- A declaration needs a session, and must parse: unknown keys, wrong types, a
  constraint on a tool not in `allowed_tools`, a pattern that does not compile,
  or oversized lists are rejected.

`tool.rego` then blocks a call to a tool outside the scope, or one whose
arguments break a constraint. Sessions with no scope, and sessionless requests,
are governed by the global allowlist alone.

## Tool output screening

`on_tool_result` carries `{"tool": <name>, "result": <text>}` (the SDK
JSON-encodes structured results) and gets provenance `tool_output`.
`tool_result.rego` screens it by risk score as `on_context` does: BLOCK from
0.8, SANITISE from 0.4. Output from a tool in `trusted_tools` comes from a
source the deployment controls, such as an internal API, and is not screened.
`trusted_tools` ships empty, so all output is screened by default.

## Argument tainting

The attacks a tool allowlist cannot stop use a tool the task legitimately needs
with the attacker's arguments. Within a session the sidecar remembers the values
the agent read in untrusted content and blocks a consequential tool call that
repeats one.

**Values tracked.** `internal/taint` extracts email addresses, URLs and their
hosts (written with a scheme or starting with `www.`), IBANs
(checksum-verified), account numbers in IBAN form that fail the checksum, and
long digit runs such as account and phone numbers, excluding dates. A bare
domain with neither a scheme nor `www.` is not extracted. Values are normalised, so the same value written two
ways matches.

**Recording**, after each decision:

| Request | Values become |
|---|---|
| `on_prompt` | trusted: the user's own request |
| `on_task` `trusted_values` | trusted |
| `on_context`, `on_tool_result` | untrusted, tagged with the hook and producing tool. SANITISE is recorded too, since over-tainting can only block more |
| anything BLOCKed | nothing: the agent never saw blocked content, and values in a blocked request are never trusted |

A trusted value is never tainted. Each session tracks at most 4096 untrusted and
2048 trusted values; past the untrusted cap, an argument value the session no
longer knows is reported with an `overflow` source, so policy fails closed.

**Deciding.** On `on_tool_call`, each argument value carrying an untrusted
value becomes a finding in `input.state.taint`. `tool.rego` blocks the call when
the tool is consequential, the argument is sensitive, and at least one source is
untrusted: a retrieved document, an overflow, or output from a tool not in
`trusted_tools`. So a payment API's own output can flow into a payment, while
the same IBAN read on a web page cannot.

## Configuration

`policies/v1/data/policy_config.yaml` (hot-reloaded):

| Key | Meaning | Default |
|---|---|---|
| `trusted_tools` | Tools whose output is not screened and whose values do not taint | `[]` |
| `consequential_tools` | Tools whose arguments must not carry untrusted values. Omit the key to treat every tool as consequential; `[]` switches tainting off | typical names: `send_email`, `send_money`, `share_file`, `execute_command`, ... (adapt to your tools) |
| `sensitive_params` | Per tool, the arguments tainting checks, e.g. `{send_money: [recipient]}`; a tool with no entry has every argument checked | `{}` |
| `tool_allowlist` | The global allowlist a task scope must stay within | as before |

`config/sidecar.yaml`:

```yaml
session:
  ttl_seconds: 1800     # idle expiry
  max_sessions: 10000   # cap; least recently seen evicted beyond it
```

New signals, all in `signal_weights`: `validate:invalid_session_id`,
`validate:invalid_payload`, `task:no_session`, `task:invalid_scope`,
`task:already_declared` (each 1.0), and `taint:untrusted_argument` (0.0: it
records findings for the decision log; `tool.rego` decides from
`input.state.taint`).

## Server-side trust

Three request fields used to be set by the client and trusted:

- **Signals.** Policies read categories nothing in the sidecar emits, such as
  `source_trust`, and a category with no weight kept the client's score.
  `context.rego` halves the effective score on a high `source_trust`, so a
  client could turn a SANITISE into an ALLOW. On `main` before this change, 8
  integration corpus cases downgraded that way. Client signals are now kept
  only for weighted categories, scored by the weight: they can add risk, never
  subtract it.
- **Provenance.** It set the trust weight. The sidecar now assigns it per hook
  and keeps the client's claim for audit only.
- **State.** It is discarded; `input.state` only ever holds what the sidecar
  stored.

`TestClientFieldForgeryProbe` and `TestProvenanceForgeryProbe` guard this over
the wire.

## Request flow

```
validate ─▶ session ─▶ normalise ─▶ scan ─▶ aggregate ─▶ OPA ─▶ record
   │           │                                                   │
   │           └─ loads input.state, computes taint findings       └─ stores scope,
   └─ assigns provenance, sets client fields aside,                   trusted and
      checks the hook's payload shape                                 untrusted values
```

Hooks are registered in `sidecar/internal/hooks`: each entry names its Rego
package, provenance, OPA input builder and optional payload validator. Adding a
hook is a registry entry and a Rego file.

## Limits

State these when citing the layer:

- **The enforcement point is in-process.** The agent holds the HMAC key. The
  layer protects an honest agent from injected content and from misconfigured
  or forged fields. It does not stop a fully compromised agent process from
  simply not calling the hooks. That would need a proxy mode in which tools are
  reachable only through the sidecar.
- **Tainting covers the value types it extracts.** A person's name, a file
  path, or free text paraphrased from an injection is not tainted.
- **Trusted means trusted.** Output from `trusted_tools` and values in the
  user's prompt or `trusted_values` are never treated as tainted.
- **Sanitised content falls back to whole-value redaction** only when a sanitised
  decision has no matched lexical spans in the primary field (e.g. semantic-only
  signals or matches in another map field); lexical matches redact only the
  matched spans.
- **Memory reads still trust the client's `hmac_valid` flag.** A real fix needs
  a sidecar-signed stamp returned to the client, which needs a new response
  field and a wire version bump. Not part of this layer.
- **A session's scope is fixed.** There is no way to widen it mid-session.

## Tests

| Where | What |
|---|---|
| `sidecar/internal/taint` | Extraction, normalisation, date and IBAN false positives |
| `sidecar/internal/state` | TTL store, caps, task scope parsing, taint caps and overflow |
| `sidecar/internal/pipeline/task_scope_test.go`, `taint_flow_test.go`, `tool_result_test.go`, `trust_test.go` | End-to-end runs of the shipped policies |
| `policies/v1/*_test.rego` | Rego unit tests, run under `go test` by `TestRegoPolicyTests` |
| `tests/integration/session_flow_test.go`, `client_field_forgery_probe_test.go` | Over the wire, against the real sidecar binary |
| `sdk/python/tests/test_session.py`, `test_tool_result.py` | SDK sessions, scope declaration, tool results, LangGraph node |
