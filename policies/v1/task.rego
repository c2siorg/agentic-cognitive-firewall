# ACF — Task Scope Hook Policy
# Scope: on_task
#
# A session declares the tools it needs, the values the developer vouches
# for, and bounds on individual arguments. The sidecar has already checked
# the declaration parses, belongs to a session, and is the session's first.
# This policy decides whether the scope stays within global policy: a task
# scope can only narrow what policy_config.yaml permits, never widen it.

package acf.policy.task

import future.keywords.in
import future.keywords.if
import future.keywords.every
import future.keywords.contains

default decision := "BLOCK"

decision := "ALLOW" if {
    not _rejected_by_sidecar
    _within_global_allowlist
}

block_reasons contains {"code": sig.category} if {
    some sig in input.signals
    _is_task_rejection(sig.category)
}

block_reasons contains {"code": "scope_exceeds_allowlist", "tool": tool} if {
    data.config.tool_allowlist
    some tool in input.task.allowed_tools
    not tool in data.config.tool_allowlist
}

# In strict mode the sidecar hard-blocks a bad declaration before policy
# runs; in non-strict mode its task:* signal arrives here.
_is_task_rejection(cat) if { startswith(cat, "task:") }
_is_task_rejection(cat) if { startswith(cat, "validate:") }

_rejected_by_sidecar if {
    some sig in input.signals
    _is_task_rejection(sig.category)
}

# No global allowlist configured: every tool is permitted, so any scope
# narrows it.
_within_global_allowlist if {
    not data.config.tool_allowlist
}

_within_global_allowlist if {
    every tool in input.task.allowed_tools {
        tool in data.config.tool_allowlist
    }
}
