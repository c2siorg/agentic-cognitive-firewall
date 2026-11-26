# ACF — Memory Hook Policy (v1)
# Scope: on_memory
# Taxonomy coverage:
#   Detection   → write_time_content_scan SANITISE
#   Integrity   → write_time_hmac_stamp STAMP, read_time_hmac_verify BLOCK
#   Trust       → write_provenance_tag TAG, read_time_trust_weight ALLOW/LOW_TRUST
#   Containment → memory_entry_size_limit BLOCK

package acf.policy.memory

import future.keywords.in
import future.keywords.if
import future.keywords.contains

# ---------------------------------------------------------------------
# Default
# ---------------------------------------------------------------------
default decision := "ALLOW"
# sanitise_targets is a set — no default needed

# ---------------------------------------------------------------------
# Integrity — read-time HMAC verify → BLOCK if invalid
# On read operations, if the HMAC does not match, block immediately.
# This is an unconditional gate — no scoring involved.
# ---------------------------------------------------------------------

decision := "BLOCK" if {
    input.memory_op == "read"
    not input.integrity.hmac_valid == true
}

# ---------------------------------------------------------------------
# Detection — write-time content scan → SANITISE
# Scans memory writes for injection residuals or sensitive content.
# ---------------------------------------------------------------------

decision := "SANITISE" if {
    input.memory_op == "write"
    _has_content_scan_signal
    not _exceeds_size_limit
}

sanitise_targets contains "memory_value" if {
    input.memory_op == "write"
    _has_content_scan_signal
}

# ---------------------------------------------------------------------
# Containment — memory entry size limit → BLOCK
# Prevents oversized writes that could be used for data exfiltration
# or denial of service against the memory store.
# ---------------------------------------------------------------------

decision := "BLOCK" if {
    input.memory_op == "write"
    _exceeds_size_limit
}

# ---------------------------------------------------------------------
# Metadata — single else-chain to avoid conflict
# Priority: low_trust_marker > tag_provenance > stamp_hmac > empty
#
# Trust — write provenance tag includes HMAC stamp instruction.
# Trust — read-time low trust marker for downstream weighting.
# Integrity — write-time HMAC stamp when no provenance tag needed.
# ---------------------------------------------------------------------

metadata := {"action": "low_trust_marker"} if {
    input.memory_op == "read"
    input.integrity.hmac_valid == true
    some sig in input.signals
    sig.category == "low_trust_source"
    sig.score >= 0.5
} else := {"action": "tag_provenance", "provenance": input.provenance, "trust_level": "verified"} if {
    input.memory_op == "write"
    input.provenance == "internal"
    not _has_content_scan_signal
    not _exceeds_size_limit
    input.score < 0.4
} else := {"action": "tag_provenance", "provenance": input.provenance, "trust_level": "unverified"} if {
    input.memory_op == "write"
    input.provenance != "internal"
    not _has_content_scan_signal
    not _exceeds_size_limit
    input.score < 0.4
} else := {"action": "stamp_hmac", "provenance": input.provenance} if {
    input.memory_op == "write"
    not _has_content_scan_signal
    not _exceeds_size_limit
    input.score < 0.4
} else := {}

# Default max entry size: 16384 bytes
_max_entry_bytes := data.config.max_memory_entry_bytes if {
    data.config.max_memory_entry_bytes
} else := 16384

_exceeds_size_limit if {
    input.payload_size_bytes > _max_entry_bytes
}

# ---------------------------------------------------------------------
# Structured block reasons
# ---------------------------------------------------------------------

block_reasons contains {"code": "hmac_invalid"} if {
    input.memory_op == "read"
    not input.integrity.hmac_valid == true
}

block_reasons contains {"code": "memory_size_limit"} if {
    input.memory_op == "write"
    _exceeds_size_limit
}

# ---------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------

_has_content_scan_signal if {
    some sig in input.signals
    sig.category == "content_scan"
    sig.score >= 0.5
}
_has_content_scan_signal if {
    some sig in input.signals
    sig.category == "jailbreak_pattern"
}
