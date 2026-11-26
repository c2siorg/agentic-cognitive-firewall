# ACF — Tool Result Hook Policy
# Scope: on_tool_result
#
# A tool's output is untrusted content the agent is about to read, like a
# retrieved document, but the sidecar knows which tool produced it. Output
# from a tool listed in data.config.trusted_tools comes from a source the
# deployment controls (an internal API, say) and is not screened; output from
# any other tool is screened by risk score, as on_context does.
#
# Taxonomy coverage:
#   Trust       → trusted_tools ALLOW
#   Containment → tool_result_threshold ALLOW / SANITISE / BLOCK

package acf.policy.tool_result

import future.keywords.in
import future.keywords.if
import future.keywords.contains

default decision := "ALLOW"

decision := "BLOCK" if {
    not _trusted_tool
    input.score >= 0.8
}

decision := "SANITISE" if {
    not _trusted_tool
    input.score >= 0.4
    input.score < 0.8
}

sanitise_targets contains "tool_result" if {
    not _trusted_tool
    input.score >= 0.4
    input.score < 0.8
}

_tool_name := input.tool_name if {
    is_string(input.tool_name)
} else := ""

block_reasons contains {"code": "risk_threshold", "tool": _tool_name} if {
    not _trusted_tool
    input.score >= 0.8
}

_trusted_tool if {
    input.tool_name in data.config.trusted_tools
}
