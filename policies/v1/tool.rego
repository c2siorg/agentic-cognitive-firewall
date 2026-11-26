# ACF — Tool Call Hook Policy (v1)
# Scope: on_tool_call
# Taxonomy coverage:
#   Detection   → parameter_injection BLOCK, shell_metacharacter BLOCK,
#                 path_traversal BLOCK
#   Permission  → tool_allowlist BLOCK, network_destination_allowlist BLOCK
#   Task scope  → session allowed_tools BLOCK, argument constraints BLOCK
#   Taint       → untrusted value in a consequential tool's argument BLOCK
#   Containment → tool_call_threshold ALLOW / SANITISE / BLOCK

package acf.policy.tool

import future.keywords.in
import future.keywords.if
import future.keywords.contains
import future.keywords.every

# ---------------------------------------------------------------------
# Default: BLOCK for on_tool_call — fail-closed by default.
# A tool call must pass ALL gates (allowlist + destination + task scope
# + detection + containment) to receive ALLOW. Anything else falls to
# BLOCK.
# ---------------------------------------------------------------------
default decision := "BLOCK"
# sanitise_targets is a set — no default needed

# Every gate except the score threshold.
_gates_pass if {
    _tool_is_permitted
    _destination_is_permitted
    _in_task_scope
    _constraints_satisfied
    not _tainted_consequential_call
    not _has_detection_signal
}

# ---------------------------------------------------------------------
# ALLOW — all gates pass and the score is below threshold.
# ---------------------------------------------------------------------

decision := "ALLOW" if {
    _gates_pass
    input.score < 0.4
}

# ---------------------------------------------------------------------
# Containment — medium score → SANITISE
# Tool is permitted but risk score is elevated.
# ---------------------------------------------------------------------

decision := "SANITISE" if {
    _gates_pass
    input.score >= 0.4
    input.score < 0.8
}

sanitise_targets contains "tool_params" if {
    _gates_pass
    input.score >= 0.4
    input.score < 0.8
}

# ---------------------------------------------------------------------
# Everything else falls through to default BLOCK:
# - Tool not on allowlist
# - Destination not on allowlist
# - Detection signal fired (parameter_injection, shell_metacharacter,
#   path_traversal)
# - Containment score >= 0.8
# ---------------------------------------------------------------------

# ---------------------------------------------------------------------
# Structured block reasons — one entry per failed gate or signal
# ---------------------------------------------------------------------

_tool_name := input.tool_name if {
    is_string(input.tool_name)
} else := ""

block_reasons contains {"code": "tool_not_allowed", "tool": _tool_name} if {
    not _tool_is_permitted
}

block_reasons contains {
    "code": "destination_not_allowed",
    "tool": _tool_name,
    "detail": sprintf("%v", [input.tool_metadata.destination]),
} if {
    not _destination_is_permitted
}

block_reasons contains {"code": "outside_task_scope", "tool": _tool_name} if {
    not _in_task_scope
}

block_reasons contains {
    "code": "constraint_violation",
    "tool": _tool_name,
    "param": param,
} if {
    rules := input.state.task.tool_constraints[input.tool_name]
    some param, rule in rules
    not _param_ok(param, rule)
}

block_reasons contains {
    "code": "argument_taint",
    "tool": _tool_name,
    "param": finding.param,
    "kind": finding.kind,
    "value": finding.value,
    "sources": untrusted_sources,
} if {
    _is_consequential_tool
    some finding in input.state.taint
    _is_sensitive_param(finding.param)
    untrusted_sources := [s | some s in finding.sources; _is_untrusted_source(s)]
    count(untrusted_sources) > 0
}

block_reasons contains {
    "code": "detection_signal",
    "tool": _tool_name,
    "signal": sig.category,
} if {
    some sig in input.signals
    sig.category in {"parameter_injection", "shell_metacharacter", "path_traversal"}
    sig.score >= 0.5
}

block_reasons contains {"code": "risk_threshold", "tool": _tool_name} if {
    decision == "BLOCK"
    input.score >= 0.8
}

# ---------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------

# Tool allowlist: tool must be listed, or no allowlist is configured
_tool_is_permitted if {
    input.tool_name in data.config.tool_allowlist
}

_tool_is_permitted if {
    not data.config.tool_allowlist
}

# Destination allowlist: destination must be listed, or no destination
# in the request, or no allowlist configured
_destination_is_permitted if {
    not input.tool_metadata.destination
}

_destination_is_permitted if {
    not data.config.destination_allowlist
}

_destination_is_permitted if {
    input.tool_metadata.destination
    data.config.destination_allowlist
    input.tool_metadata.destination in data.config.destination_allowlist
}

# ---------------------------------------------------------------------
# Task scope — declared per session through on_task and held in
# input.state.task by the sidecar. A request with no session, or a
# session with no declared task, is not restricted by these gates.
# ---------------------------------------------------------------------

_in_task_scope if {
    not input.state.task
}

_in_task_scope if {
    input.tool_name in input.state.task.allowed_tools
}

# Every constrained argument of this tool that the call passes must meet
# all of its rule's checks. An argument the call does not pass is not
# checked.
_constraints_satisfied if {
    not input.state.task.tool_constraints[input.tool_name]
}

_constraints_satisfied if {
    rules := input.state.task.tool_constraints[input.tool_name]
    every param, rule in rules {
        _param_ok(param, rule)
    }
}

_param_ok(param, _) if {
    not _passes_param(param)
}

_param_ok(param, rule) if {
    value := input.tool_params[param]
    _allowed_ok(value, rule)
    _pattern_ok(value, rule)
    _max_ok(value, rule)
}

_passes_param(param) if {
    _ = input.tool_params[param]
}

_allowed_ok(_, rule) if {
    not "allowed" in object.keys(rule)
}

_allowed_ok(value, rule) if {
    value in rule.allowed
}

_pattern_ok(_, rule) if {
    not "pattern" in object.keys(rule)
}

_pattern_ok(value, rule) if {
    is_string(value)
    regex.match(rule.pattern, value)
}

_max_ok(_, rule) if {
    not "max" in object.keys(rule)
}

_max_ok(value, rule) if {
    is_number(value)
    value <= rule.max
}

# ---------------------------------------------------------------------
# Argument taint — a consequential tool may not take a sensitive argument
# whose value the agent read in untrusted content: a retrieved document,
# or output from a tool not in data.config.trusted_tools. The sidecar puts
# this request's findings in input.state.taint; values from the user's
# prompt and the task's trusted_values never appear there.
# ---------------------------------------------------------------------

_tainted_consequential_call if {
    _is_consequential_tool
    some finding in input.state.taint
    _is_sensitive_param(finding.param)
    some source in finding.sources
    _is_untrusted_source(source)
}

# consequential_tools omitted: every tool is consequential (strict).
_is_consequential_tool if {
    not "consequential_tools" in object.keys(data.config)
}

_is_consequential_tool if {
    input.tool_name in data.config.consequential_tools
}

# A tool with no sensitive_params entry has every argument checked.
_is_sensitive_param(_) if {
    not data.config.sensitive_params[input.tool_name]
}

_is_sensitive_param(param) if {
    param in data.config.sensitive_params[input.tool_name]
}

# on_context and overflow sources are always untrusted; tool output is
# untrusted unless the tool is listed in trusted_tools.
_is_untrusted_source(source) if {
    source.hook != "on_tool_result"
}

_is_untrusted_source(source) if {
    source.hook == "on_tool_result"
    not source.tool in data.config.trusted_tools
}

# Detection signal presence
_has_detection_signal if {
    some sig in input.signals
    sig.category in {"parameter_injection", "shell_metacharacter", "path_traversal"}
    sig.score >= 0.5
}
