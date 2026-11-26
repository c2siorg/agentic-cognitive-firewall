"""
Data models for the ACF SDK.

Decision       — ALLOW | SANITISE | BLOCK enum returned by all hook calls.
SanitiseResult — returned on SANITISE decisions; contains the scrubbed payload.
BlockInfo      — structured block reasons returned alongside BLOCK decisions.
ChunkResult    — returned by on_context; per-chunk decision and sanitised text.
FirewallError  — base exception for all ACF SDK errors.
"""
from __future__ import annotations

import enum
import json
from dataclasses import dataclass, field
from typing import Optional


class Decision(enum.Enum):
    """The three possible enforcement outcomes."""
    ALLOW    = 0x00
    SANITISE = 0x01
    BLOCK    = 0x02

    @classmethod
    def from_byte(cls, b: int) -> "Decision":
        """Return the Decision corresponding to a response byte.

        Raises ValueError for any unrecognised byte.
        """
        for member in cls:
            if member.value == b:
                return member
        raise ValueError(f"Unknown decision byte: {b:#04x}")


@dataclass
class SanitiseResult:
    """Returned when the sidecar decides SANITISE.

    The caller should use ``sanitised_text`` in place of the original input.
    """
    decision: Decision                   # always Decision.SANITISE
    sanitised_payload: bytes             # raw bytes from the response frame
    sanitised_text: Optional[str] = None # UTF-8 decoded, or None if decoding fails


@dataclass(frozen=True)
class TaintSource:
    """Where an untrusted value was read before reaching a tool argument."""
    hook: str
    tool: str = ""


@dataclass(frozen=True)
class BlockReason:
    """One policy gate or validation failure behind a BLOCK decision."""
    code: str
    stage: str = ""
    tool: str = ""
    param: str = ""
    kind: str = ""
    value: str = ""
    sources: tuple[TaintSource, ...] = ()
    signal: str = ""
    detail: str = ""


@dataclass(frozen=True)
class BlockInfo:
    """Structured explanation attached to a BLOCK decision from the sidecar."""
    hook: str = ""
    confirmable: bool = False
    reasons: tuple[BlockReason, ...] = ()
    raw_payload: bytes = b""

    @property
    def untrusted_values(self) -> tuple[str, ...]:
        """Distinct argument values flagged by argument_taint, in order.

        Drops redundant ``number`` sub-tokens that are already substrings of an
        ``iban`` or ``account`` token in the same block, since confirming the
        enclosing account trusts its digit suffix too.
        """
        accounts = [
            r.value for r in self.reasons
            if r.code == "argument_taint" and r.kind in ("iban", "account") and r.value
        ]
        seen: set[str] = set()
        values: list[str] = []
        for reason in self.reasons:
            if reason.code != "argument_taint" or not reason.value:
                continue
            if reason.kind == "number" and any(reason.value in acct for acct in accounts):
                continue
            if reason.value not in seen:
                seen.add(reason.value)
                values.append(reason.value)
        return tuple(values)


def parse_block_info(raw: bytes) -> Optional[BlockInfo]:
    """Decode structured BlockInfo JSON from a BLOCK response payload."""
    if not raw:
        return None
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    reasons: list[BlockReason] = []
    raw_reasons = data.get("reasons")
    if isinstance(raw_reasons, list):
        for item in raw_reasons:
            if not isinstance(item, dict):
                continue
            code = item.get("code")
            if not isinstance(code, str) or not code:
                continue
            sources: list[TaintSource] = []
            raw_sources = item.get("sources")
            if isinstance(raw_sources, list):
                for src in raw_sources:
                    if isinstance(src, dict) and isinstance(src.get("hook"), str) and src["hook"]:
                        tool = src.get("tool")
                        sources.append(TaintSource(hook=src["hook"], tool=tool if isinstance(tool, str) else ""))
            reasons.append(BlockReason(
                code=code,
                stage=item.get("stage", "") if isinstance(item.get("stage"), str) else "",
                tool=item.get("tool", "") if isinstance(item.get("tool"), str) else "",
                param=item.get("param", "") if isinstance(item.get("param"), str) else "",
                kind=item.get("kind", "") if isinstance(item.get("kind"), str) else "",
                value=item.get("value", "") if isinstance(item.get("value"), str) else "",
                sources=tuple(sources),
                signal=item.get("signal", "") if isinstance(item.get("signal"), str) else "",
                detail=item.get("detail", "") if isinstance(item.get("detail"), str) else "",
            ))
    hook = data.get("hook")
    return BlockInfo(
        hook=hook if isinstance(hook, str) else "",
        confirmable=bool(data.get("confirmable", False)),
        reasons=tuple(reasons),
        raw_payload=raw,
    )


@dataclass
class ChunkResult:
    """Per-chunk result returned by ``Firewall.on_context``."""
    original: str
    decision: Decision
    sanitised_text: Optional[str] = None


class FirewallError(Exception):
    """Base exception for ACF SDK errors."""


class FirewallConnectionError(FirewallError):
    """Raised when the transport cannot connect to the sidecar after all retries."""


class FirewallBlocked(FirewallError):
    """Raised by framework adapters when the firewall returns BLOCK.

    Unlike a plain decision return, this propagates as a real exception so
    it can halt an agent framework's execution flow (e.g. a LangGraph run).
    Carries the hook that blocked and structured block info when available.
    """

    def __init__(
        self,
        message: str,
        *,
        hook: str | None = None,
        block_info: BlockInfo | None = None,
    ) -> None:
        super().__init__(message)
        self.hook = hook
        self.block_info = block_info
