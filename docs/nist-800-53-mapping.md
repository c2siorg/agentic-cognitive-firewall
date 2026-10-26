# ACF and NIST SP 800-53 Rev. 5 SI-10

This document maps the Agentic Cognitive Firewall (ACF) implementation to **SI-10, Information Input Validation**, from NIST SP 800-53 Rev. 5. It identifies concrete mechanisms in the repository, where they provide only partial coverage, and risks that remain outside ACF's enforcement boundary.

**This is an engineering mapping, not a compliance assessment or certification.** NIST SI-10 applies to organization-defined information inputs in a defined system boundary. A deployment must identify those inputs, select applicable requirements, validate its configuration and integrations, and assess the complete system—not ACF in isolation.

## Summary

ACF implements input checks at its sidecar boundary and applies additional normalisation, scanning, risk aggregation, session checks, and policy evaluation to agent-facing events. The strongest direct SI-10 alignment is the validation of registered hook types and required payload fields, combined with explicit handling of malformed session/task inputs. Normalisation and scanning help identify suspicious or obfuscated content, but they are not substitutes for complete schema and semantic validation.

| Control element | Assessment | Rationale |
|---|---|---|
| SI-10 — Information Input Validation | **Partial** | ACF validates selected envelope and hook-specific fields and rejects several malformed inputs. The repository does not demonstrate comprehensive syntax, range, length, and semantic validation for every field and downstream consumer. |
| SI-10(1) — Manual Override Capability | **Not demonstrated** | The repository does not establish a controlled manual override workflow with authorised users and audit requirements for bypassing validation. |
| SI-10(2) — Review and Resolve Errors | **Not demonstrated in the repository** | The code emits validation signals and has tests, but a time-bound operational process for reviewing and resolving validation errors is not established by those mechanisms alone. |
| SI-10(3) — Predictable Behavior | **Partial** | Several malformed inputs produce explicit hard-block signals, and validation tests cover selected cases. Strict and non-strict pipeline modes differ, and this document does not establish exhaustive or deployment-wide predictable behavior. |
| SI-10(4) — Timing Interactions | **Not demonstrated** | The repository records processing timings for observability, but that is not evidence that timing interactions among components have been assessed to determine responses to invalid inputs. |
| SI-10(5) — Restrict Inputs to Trusted Sources and Approved Formats | **Partial** | HMAC verification, replay protection, a hook registry, hook validators, server-assigned provenance, and allowlists provide useful boundaries. A valid signature does not make content trustworthy, and the controls do not establish that every input source and format is restricted. |
| SI-10(6) — Injection Prevention | **Partial** | Canonicalisation, pattern scanning, argument-taint findings, allowlist checks and policy decisions reduce some prompt- and tool-mediated risks. ACF does not universally enforce parameterised interfaces or output encoding in downstream tools and interpreters. |

The labels above describe repository evidence only. “Not demonstrated” means this repository does not establish the control; an operator may have separate procedures or controls that must be assessed independently.

## Scope and information inputs

The mapping focuses on information received by the ACF sidecar and the agent hooks that it mediates. Depending on how ACF is deployed, examples include:

- The framed request and JSON-encoded `RiskContext` received over the local IPC transport.
- `hook_type`, `provenance`, `payload`, and `session_id` fields.
- Hook-specific values such as tool names and parameters, memory keys and operations, tool results, retrieved context, and task-scope declarations.
- Client-provided signals and fields such as score or state that must not be trusted as authoritative sidecar state.

Each deployment should document which of these inputs apply, their expected syntax and semantics, accepted ranges and sizes, trusted origins, and the component responsible for validating them. This list is illustrative, not a complete input inventory for every integration.

## How the runtime handles inputs

The implementation wires the transport checks and pipeline stages together in [`main.go`](../sidecar/cmd/sidecar/main.go). Relevant stages and their relationship to SI-10 are summarised below.

| Stage or component | Implemented behavior | Relationship to SI-10 and limitations |
|---|---|---|
| IPC transport | Verifies the request HMAC and nonce before accepting the JSON as a `RiskContext`; an invalid HMAC or reused nonce is rejected at the transport boundary. See [`listener.go`](../sidecar/internal/transport/listener.go) and the crypto package. | Helps protect message integrity and replay resistance. Authentication/integrity checks do not establish that the content itself is valid, safe, or semantically acceptable. |
| Validate | Looks up `hook_type` in the hook registry; rejects unknown hook types, empty provenance and nil payloads; invokes a hook-specific validator when one is registered. It replaces client-claimed provenance with registry-assigned provenance and removes client-controlled score/state before later stages. See [`validate.go`](../sidecar/internal/pipeline/validate.go) and [`builtin.go`](../sidecar/internal/hooks/builtin.go). | The most direct implementation of the base SI-10 objective. Validation depth is hook-dependent; an optional validator means the repository should not be interpreted as proving every nested field is validated for type, length, range, and domain semantics. |
| Session | Validates session-ID syntax and task-scope declarations, loads server-held state, and reports findings when tool arguments contain values tracked as untrusted. See [`session.go`](../sidecar/internal/pipeline/session.go). | Adds format checks and input provenance/taint context. It does not, by itself, prove that every tool parameter is valid for the ultimate target API or interpreter. |
| Normalise | Builds canonical text for scanning by recursively decoding URL/Base64 representations, applying Unicode NFKC normalisation, removing selected zero-width characters, collapsing whitespace, and cleaning common leetspeak substitutions. It leaves the original payload unchanged. See [`normalise.go`](../sidecar/internal/pipeline/normalise.go). | Helps detection withstand common text-obfuscation techniques. It is a transformation for scanning, not a comprehensive validator, and should not be treated as proof that the original payload is valid. |
| Scan | Searches canonical text for configured lexical patterns and checks selected tool/memory allowlists and potentially dangerous parameters. See [`scan.go`](../sidecar/internal/pipeline/scan.go). | Supports detection and restriction of selected risky inputs. Pattern matching is not exhaustive and cannot replace field-specific validation or safe handling at the eventual command/query boundary. |
| Aggregate | Combines signal weights and provenance trust weight to calculate a risk score. See [`aggregate.go`](../sidecar/internal/pipeline/aggregate.go). | Converts findings to risk information; scoring alone does not validate the syntax or semantics of an input. |
| Policy and execution | The sidecar constructs an OPA evaluator and calls it after the stages. Policies return ALLOW, SANITISE, or BLOCK and may select sanitisation targets; the executor applies supported transformations. See [`main.go`](../sidecar/cmd/sidecar/main.go), [`engine.go`](../sidecar/internal/policy/engine.go), and [`policies/v1`](../policies/v1). | Adds policy-based decisions and selected transformations. Policy outcomes and sanitisation do not guarantee that every input accepted by a downstream tool is well-formed or safely parameterised. |

### Trust-boundary details

The implementation assigns provenance per registered hook rather than trusting the client-provided label. Client-provided score and state are cleared, while client signals are held aside and later weighted by the aggregate stage. These are useful integrity controls around the decision context, but they do not make untrusted payload text safe by default.

The normalisation, scanning and policy pipeline should be understood as defence in depth. An input that does not match a configured pattern may still be malformed or dangerous for a specific downstream application. Conversely, a suspicious-text signal is a detection result; it is not a schema-validation error for every possible consumer.

## SI-10 control mapping

### SI-10 — Information Input Validation

**Assessment: Partial.** The sidecar checks a subset of envelope requirements and registered hook validators before passing data through subsequent processing. Tests cover representative invalid hook types, missing provenance, nil payloads, and registered hook types in [`validate_test.go`](../sidecar/internal/pipeline/validate_test.go).

This does not establish comprehensive validation of every accepted payload field. An integration must still define and enforce field-specific syntax, data types, character sets, maximum lengths, numerical bounds, enumerated values, and domain constraints where applicable. Inputs used to construct commands, queries, URLs, file paths, or other structured messages require protections appropriate to those destinations.

### SI-10(1) — Manual Override Capability

**Assessment: Not demonstrated.** The repository does not establish a manual mechanism for overriding validation with clearly defined authorised roles and an audit trail for each override. The normal ALLOW/SANITISE/BLOCK policy result should not be assumed to provide a controlled exception process for validation failures.

If an operating organisation requires such a capability, it must define which inputs may be overridden, who may authorise it, how the exception is limited, and where its use is audited. A deployment should avoid introducing an undocumented bypass around the sidecar's enforcement boundary.

### SI-10(2) — Review and Resolve Errors

**Assessment: Not demonstrated in the repository.** Validation failures can produce named signals and the repository includes tests, but that does not establish a process that reviews errors and resolves systemic causes within an organisation-defined time period.

This enhancement depends substantially on operations: identify how validation failures are collected, assigned, reviewed, escalated, and closed; define a resolution timeframe; and retain evidence that recurrent failures or validator defects are addressed. ACF's signals and logs may inform that process, but the process itself must be demonstrated by the deployment.

### SI-10(3) — Predictable Behavior

**Assessment: Partial.** The validator emits named signals and hard-blocks unknown hook types, empty provenance, nil payloads, and rejected hook-specific payloads. The session stage similarly rejects malformed session identifiers and invalid task declarations. Existing tests document some expected cases.

The pipeline's strict mode returns BLOCK immediately on a hard-block result; non-strict mode continues through later stages and derives a final decision after aggregation. That difference must be understood and tested for the deployment configuration. Tests for representative cases do not establish predictable handling for every malformed or oversized input, every policy error, or every downstream integration.

### SI-10(4) — Timing Interactions

**Assessment: Not demonstrated.** The sidecar has timing instrumentation for transport and pipeline processing, but timing measurements alone do not demonstrate that interactions among components have been assessed when choosing how to handle invalid inputs.

A deployment should assess relevant timeouts, cancellation, resource exhaustion, retry behavior, and differences between fast-rejected and fully processed requests. This mapping does not claim that ACF's timing instrumentation satisfies those system-level requirements.

### SI-10(5) — Restrict Inputs to Trusted Sources and Approved Formats

**Assessment: Partial.** HMAC validation and nonce replay checks constrain the IPC message boundary. The hook registry recognises supported hook types; hook-specific validation can restrict payload shapes; provenance is assigned by the sidecar; and selected tool and memory operations are checked against allowlists.

These safeguards should not be confused with universal trust in the content. A valid HMAC establishes that a message was produced by a party with the key and was not altered without detection; it does not certify the payload's truthfulness, intent, or suitability for a downstream operation. Deployment-specific trusted-source policy, key protection, allowed formats, and per-field constraints remain necessary.

### SI-10(6) — Injection Prevention

**Assessment: Partial.** Canonicalisation makes selected text obfuscations more visible to scanning. Lexical pattern checks, tool/memory allowlists, session taint findings, provenance-aware scoring and OPA decisions can reduce selected prompt-injection and tool-abuse paths when agent activity passes through the corresponding ACF hooks.

Coverage is bounded by the configured patterns, hook paths, policies and integrations. ACF does not universally enforce parameterised interfaces or output encoding for every command, query, template, URL, file path, or other interpreter used by downstream tools. Integrations must pass data as data rather than concatenate untrusted values into executable commands or query syntax, and must apply context-appropriate escaping or encoding where required. ACF should not be treated as a replacement for secure implementation of those downstream interfaces.

## Gaps and residual risk

The following residual risks remain relevant even when ACF is enabled:

1. **Incomplete field-level validation.** The presence of a hook validator does not prove that every accepted field has appropriate bounds and semantics. Integrations must validate the contract of the destination that consumes each value.
2. **Detection is not proof of validity.** Normalisation and pattern matching improve visibility into suspicious strings but can have false negatives and false positives. Unknown payloads and novel encodings may not match configured patterns.
3. **The original payload remains distinct from canonical scan text.** Normalisation produces text for detection without mutating the original payload. Downstream handling still needs its own parsing, validation, and safe-use controls.
4. **Coverage depends on use of guarded hooks.** A tool, storage path, external service, or model interaction that bypasses the relevant ACF hook is outside the protection that hook provides.
5. **Policy and mode configuration matters.** Strict and non-strict modes behave differently after a hard-block signal. The runtime also has a threshold fallback if OPA evaluation returns an error; deployments should test and assess that behavior rather than assume all policy-engine failures necessarily fail closed.
6. **Operational requirements are separate.** Controlled overrides, time-bound error review, monitoring, incident handling, and evidence retention require deployment-level procedures where applicable.
7. **Key and endpoint security remain critical.** HMAC and replay protection depend on protecting the signing key and the local IPC boundary; they do not defend against a compromised trusted process or key.

## Evidence and validation

Relevant implementation and tests include:

- [`validate.go`](../sidecar/internal/pipeline/validate.go) and [`validate_test.go`](../sidecar/internal/pipeline/validate_test.go) — top-level validation and representative invalid-input tests.
- [`session.go`](../sidecar/internal/pipeline/session.go) and its session/task tests — session identifier, task-scope, and taint-related checks.
- [`normalise.go`](../sidecar/internal/pipeline/normalise.go) and [`normalise_test.go`](../sidecar/internal/pipeline/normalise_test.go) — canonical-text transformations.
- [`scan.go`](../sidecar/internal/pipeline/scan.go) and [`scan_test.go`](../sidecar/internal/pipeline/scan_test.go) — configured pattern scanning and selected allowlist/dangerous-parameter checks.
- [`aggregate.go`](../sidecar/internal/pipeline/aggregate.go), [`main.go`](../sidecar/cmd/sidecar/main.go), and [`engine.go`](../sidecar/internal/policy/engine.go) — scoring and the wired policy-evaluation path.
- [`listener.go`](../sidecar/internal/transport/listener.go) — authenticated IPC request handling.

The presence of implementation or unit tests is evidence for the listed behavior, not a substitute for system-level verification. Before relying on this mapping, verify the exact version, configuration, active hooks, downstream tools, and operational procedures in the target deployment.

## References

- NIST, [SP 800-53 Rev. 5 — Security and Privacy Controls for Information Systems and Organizations](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final). Consult the publication page for release notes and supplemental control-catalog material.
- ACF implementation: [`sidecar/internal/pipeline`](../sidecar/internal/pipeline), [`sidecar/internal/transport`](../sidecar/internal/transport), [`sidecar/internal/hooks`](../sidecar/internal/hooks), [`sidecar/internal/policy`](../sidecar/internal/policy), and [`policies/v1`](../policies/v1).
- Related ACF analysis: [MITRE ATLAS analysis](mitre-atlas-analysis.md).
