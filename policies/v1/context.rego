# ACF — Context Hook Policy (v1)
# Scope: on_context
# Taxonomy coverage:
#   Detection   → embedded_instruction SANITISE, structural_anomaly BLOCK
#   Trust       → source_trust_weighting MULTIPLIER
#   Containment → context_risk_threshold ALLOW / SANITISE / BLOCK,
#                 rag_chunk_size_limit SPLIT

package acf.policy.context

import future.keywords.in
import future.keywords.if
import future.keywords.contains

# ---------------------------------------------------------------------
# Default
# ---------------------------------------------------------------------
default decision := "ALLOW"
# sanitise_targets is a set — no default needed
default trust_multiplier := 1.0

# ---------------------------------------------------------------------
# Detection — structural anomaly → hard BLOCK
# ---------------------------------------------------------------------

decision := "BLOCK" if {
    some sig in input.signals
    sig.category == "structural_anomaly"
    sig.score >= 0.8
}

# ---------------------------------------------------------------------
# Detection — embedded instruction → SANITISE (strip the chunk)
# ---------------------------------------------------------------------

decision := "SANITISE" if {
    some sig in input.signals
    sig.category == "embedded_instruction"
    sig.score >= 0.6
    not _has_hard_block
}

sanitise_targets contains "context_chunk" if {
    some sig in input.signals
    sig.category == "embedded_instruction"
    sig.score >= 0.6
    not _has_hard_block
}

# ---------------------------------------------------------------------
# Trust — source trust weighting
# Adjusts the effective score based on provenance trust.
# Low-trust sources (score < 0.3) get a 2x multiplier on risk.
# High-trust sources (score >= 0.7) get a 0.5x multiplier (reduced risk).
# ---------------------------------------------------------------------

trust_multiplier := 2.0 if {
    some sig in input.signals
    sig.category == "source_trust"
    sig.score < 0.3
}

trust_multiplier := 0.5 if {
    some sig in input.signals
    sig.category == "source_trust"
    sig.score >= 0.7
}

# Effective score = raw score × trust multiplier
_effective_score := input.score * trust_multiplier

# ---------------------------------------------------------------------
# Containment — context risk threshold (graduated, uses effective score)
# ---------------------------------------------------------------------

decision := "BLOCK" if {
    _effective_score >= 0.8
    not _has_hard_block
    not _has_embedded_instruction
}

decision := "SANITISE" if {
    _effective_score >= 0.4
    _effective_score < 0.8
    not _has_hard_block
    not _has_embedded_instruction
}

sanitise_targets contains "context_chunk" if {
    _effective_score >= 0.4
    _effective_score < 0.8
    not _has_hard_block
    not _has_embedded_instruction
}

# ---------------------------------------------------------------------
# Containment — RAG chunk size limit
# Oversized chunks are split rather than blocked.
# Returns SANITISE with a "split" target.
# ---------------------------------------------------------------------

decision := "SANITISE" if {
    input.payload_size_bytes > 0
    input.payload_size_bytes > _max_chunk_bytes
    not _has_hard_block
    not _has_embedded_instruction
    _effective_score < 0.4
}

sanitise_targets contains "split_chunk" if {
    input.payload_size_bytes > 0
    input.payload_size_bytes > _max_chunk_bytes
}

# Default max chunk size: 8192 bytes (configurable via data)
_max_chunk_bytes := data.config.max_chunk_bytes if {
    data.config.max_chunk_bytes
} else := 8192

# ---------------------------------------------------------------------
# Structured block reasons
# ---------------------------------------------------------------------

block_reasons contains {"code": "detection_signal", "signal": "structural_anomaly"} if {
    _has_hard_block
}

block_reasons contains {"code": "risk_threshold"} if {
    decision == "BLOCK"
    _effective_score >= 0.8
    not _has_hard_block
    not _has_embedded_instruction
}

# ---------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------

_has_hard_block if {
    some sig in input.signals
    sig.category == "structural_anomaly"
    sig.score >= 0.8
}

_has_embedded_instruction if {
    some sig in input.signals
    sig.category == "embedded_instruction"
    sig.score >= 0.6
}
