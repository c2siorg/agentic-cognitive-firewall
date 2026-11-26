# ACF — Mid-Session Confirmation Hook Policy
# Scope: on_confirm
#
# Allows the application to record user-confirmed values mid-session so
# subsequent consequential tool calls may pass argument tainting without
# restarting the session. Rejects requests with sidecar validation/session
# failures or injection signals in the submitted values.

package acf.policy.confirm

import future.keywords.in
import future.keywords.if
import future.keywords.contains

default decision := "BLOCK"

decision := "ALLOW" if {
    not _rejected_by_sidecar
    not _has_injection_signal
    input.score < 0.8
}

block_reasons contains {"code": sig.category} if {
    some sig in input.signals
    _is_rejection_signal(sig.category)
}

block_reasons contains {"code": "detection_signal", "signal": sig.category} if {
    some sig in input.signals
    _is_injection_category(sig.category)
    sig.score >= 0.5
}

block_reasons contains {"code": "risk_threshold"} if {
    decision == "BLOCK"
    input.score >= 0.8
    not _rejected_by_sidecar
    not _has_injection_signal
}

_is_rejection_signal(cat) if {
    startswith(cat, "confirm:")
}

_is_rejection_signal(cat) if {
    startswith(cat, "validate:")
}

_rejected_by_sidecar if {
    some sig in input.signals
    _is_rejection_signal(sig.category)
}

_is_injection_category(cat) if {
    cat in {
        "jailbreak_pattern",
        "instruction_override",
        "role_escalation",
        "obfuscation_escalation",
        "policy_integrity",
        "parameter_injection",
        "shell_metacharacter",
        "path_traversal",
    }
}

_has_injection_signal if {
    some sig in input.signals
    _is_injection_category(sig.category)
    sig.score >= 0.5
}
