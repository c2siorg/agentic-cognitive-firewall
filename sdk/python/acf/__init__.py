"""
ACF SDK — Agentic Cognitive Firewall.

Public API:
    Firewall       — main entry point, four hook call sites
    Session        — hook calls evaluated as one agent session (Firewall.session())
    Decision       — ALLOW | SANITISE | BLOCK
    SanitiseResult — returned on SANITISE, contains the scrubbed payload
    ChunkResult    — per-chunk result from on_context
    FirewallError  — base exception
    FirewallConnectionError — raised when the sidecar is unreachable
    FirewallBlocked — raised by adapters on BLOCK decisions
"""
from .firewall import Firewall
from .models import (
    BlockInfo,
    BlockReason,
    ChunkResult,
    Decision,
    FirewallBlocked,
    FirewallConnectionError,
    FirewallError,
    SanitiseResult,
    TaintSource,
)
from .session import Session

__all__ = [
    "Firewall",
    "Session",
    "Decision",
    "SanitiseResult",
    "BlockInfo",
    "BlockReason",
    "TaintSource",
    "ChunkResult",
    "FirewallBlocked",
    "FirewallError",
    "FirewallConnectionError",
]
