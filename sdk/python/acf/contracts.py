"""
Schema contracts for the ACF validate pipeline.

Defines the typed request and response envelopes exchanged between the SDK
(PEP) and the sidecar (PDP) over the IPC frame protocol. These dataclasses
formalise the ad-hoc dictionary that ``Firewall._build_payload`` has been
building since v1 and add a structured response contract that exposes
pipeline telemetry (score, signals, blocked_at) back to the caller.

Wire compatibility
------------------
The binary frame envelope (54-byte header + JSON payload) is unchanged.
``ValidateRequest.to_dict()`` produces the exact JSON shape the sidecar
already parses as ``riskcontext.RiskContext``. ``ValidateResponse`` is
designed to be populated from the current 5-byte response *or* from a
future enriched JSON response body.

Zero external dependencies — stdlib + typing only.
"""
from __future__ import annotations

import enum
import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# ── Enums ────────────────────────────────────────────────────────────────


class HookType(str, enum.Enum):
    """The four v1 hook call sites."""
    ON_PROMPT    = "on_prompt"
    ON_CONTEXT   = "on_context"
    ON_TOOL_CALL = "on_tool_call"
    ON_MEMORY    = "on_memory"


class ProvenanceType(str, enum.Enum):
    """Origin labels for payloads sent to the sidecar."""
    USER   = "user"
    RAG    = "rag"
    AGENT  = "agent"
    SDK    = "sdk"
    SYSTEM = "system"


# ── Signal ───────────────────────────────────────────────────────────────


@dataclass
class Signal:
    """A named risk signal with its weighted score.

    On the request path, SDK-side semantic scanner hits are sent with scores
    pre-populated. The sidecar's aggregate stage back-fills scores from
    ``policy_config.yaml`` signal_weights for lexical scanner hits.
    """
    category: str
    score: float = 0.0


# ── Typed hook payloads ──────────────────────────────────────────────────


@dataclass
class PromptPayload:
    """Payload for ``on_prompt`` — a single user prompt string."""
    text: str

    def to_wire(self) -> str:
        """Return the wire-format value for the ``payload`` field.

        ``on_prompt`` sends the raw string, not a dict wrapper, so the
        sidecar's normalise stage receives a plain string in
        ``rc.Payload``.
        """
        return self.text


@dataclass
class ContextPayload:
    """Payload for ``on_context`` — a single RAG chunk."""
    content: str

    def to_wire(self) -> str:
        """Return the wire-format value.

        Like ``on_prompt``, context chunks are sent as plain strings.
        """
        return self.content


@dataclass
class ToolCallPayload:
    """Payload for ``on_tool_call`` — a tool name and its parameters."""
    name: str
    params: Dict[str, Any] = field(default_factory=dict)

    def to_wire(self) -> Dict[str, Any]:
        """Return the wire-format value.

        The sidecar expects ``{"name": str, "params": dict}``.
        """
        return {"name": self.name, "params": self.params}


@dataclass
class MemoryPayload:
    """Payload for ``on_memory`` — a memory key/value/op triple."""
    key: str
    value: str
    op: str = "write"

    def to_wire(self) -> Dict[str, Any]:
        """Return the wire-format value.

        The sidecar expects ``{"key": str, "value": str, "op": str}``.
        """
        return {"key": self.key, "value": self.value, "op": self.op}


# Union type alias for type checkers.
Payload = PromptPayload | ContextPayload | ToolCallPayload | MemoryPayload


# ── ValidateRequest ──────────────────────────────────────────────────────


@dataclass
class ValidateRequest:
    """Typed request envelope sent from the SDK to the sidecar.

    Mirrors ``riskcontext.RiskContext`` in the Go sidecar. The
    ``to_dict()`` method produces the exact JSON shape the sidecar
    currently parses, so this is a drop-in replacement for the ad-hoc
    dictionary ``Firewall._build_payload`` used to build.

    Example::

        req = ValidateRequest(
            hook_type=HookType.ON_PROMPT,
            provenance=ProvenanceType.USER,
            payload=PromptPayload(text="Hello, world!"),
        )
        wire_bytes = req.encode()
    """
    hook_type: HookType
    provenance: ProvenanceType
    payload: Payload
    signals: List[Signal] = field(default_factory=list)
    session_id: str = ""
    score: float = 0.0
    state: Any = None

    def to_dict(self) -> Dict[str, Any]:
        """Serialise to the wire-format dict the sidecar expects.

        Field order and names match ``riskcontext.RiskContext`` exactly::

            {"score", "signals", "provenance", "session_id",
             "hook_type", "payload", "state"}
        """
        # Resolve payload to its wire representation.
        wire_payload: Any
        if hasattr(self.payload, "to_wire"):
            wire_payload = self.payload.to_wire()
        else:
            wire_payload = self.payload

        return {
            "score":      self.score,
            "signals":    [{"category": s.category, "score": s.score} for s in self.signals],
            "provenance": self.provenance.value if isinstance(self.provenance, ProvenanceType) else self.provenance,
            "session_id": self.session_id,
            "hook_type":  self.hook_type.value if isinstance(self.hook_type, HookType) else self.hook_type,
            "payload":    wire_payload,
            "state":      self.state,
        }

    def encode(self) -> bytes:
        """Serialise to compact JSON bytes, ready for the frame encoder."""
        return json.dumps(self.to_dict(), separators=(",", ":")).encode("utf-8")

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ValidateRequest":
        """Construct from a raw dict (e.g. parsed from JSON).

        Primarily useful on the sidecar side or in tests. The ``payload``
        field is reconstructed into the appropriate typed payload class
        based on ``hook_type``.
        """
        hook_type_raw = data.get("hook_type", "")
        try:
            hook_type = HookType(hook_type_raw)
        except ValueError:
            hook_type = hook_type_raw  # type: ignore[assignment]

        provenance_raw = data.get("provenance", "")
        try:
            provenance = ProvenanceType(provenance_raw)
        except ValueError:
            provenance = provenance_raw  # type: ignore[assignment]

        signals = [
            Signal(category=s.get("category", ""), score=s.get("score", 0.0))
            for s in data.get("signals", [])
        ]

        # Reconstruct typed payload when possible.
        raw_payload = data.get("payload")
        payload: Any
        if isinstance(raw_payload, str):
            if hook_type == HookType.ON_PROMPT:
                payload = PromptPayload(text=raw_payload)
            elif hook_type == HookType.ON_CONTEXT:
                payload = ContextPayload(content=raw_payload)
            else:
                payload = PromptPayload(text=raw_payload)
        elif isinstance(raw_payload, dict):
            if hook_type == HookType.ON_TOOL_CALL:
                payload = ToolCallPayload(
                    name=raw_payload.get("name", ""),
                    params=raw_payload.get("params", {}),
                )
            elif hook_type == HookType.ON_MEMORY:
                payload = MemoryPayload(
                    key=raw_payload.get("key", ""),
                    value=raw_payload.get("value", ""),
                    op=raw_payload.get("op", "write"),
                )
            else:
                payload = PromptPayload(text=str(raw_payload))
        else:
            payload = PromptPayload(text=str(raw_payload) if raw_payload is not None else "")

        return cls(
            hook_type=hook_type,
            provenance=provenance,
            payload=payload,
            signals=signals,
            session_id=data.get("session_id", ""),
            score=data.get("score", 0.0),
            state=data.get("state"),
        )


# ── ValidateResponse ─────────────────────────────────────────────────────


@dataclass
class ValidateResponse:
    """Typed response envelope returned from the sidecar to the SDK.

    Today the wire protocol returns a minimal 5-byte frame
    (decision + san_len + body). This dataclass captures the full
    pipeline result including telemetry that can be surfaced when
    the wire protocol is extended or when running in-process.

    ``from_wire()`` constructs a response from the current minimal
    wire format. ``from_pipeline_result()`` constructs a full response
    from a ``pipeline.Result`` dict (useful in tests and future
    enriched responses).
    """
    decision: int           # 0x00 ALLOW, 0x01 SANITISE, 0x02 BLOCK
    score: float = 0.0
    signals: List[Signal] = field(default_factory=list)
    blocked_at: str = ""
    sanitised_payload: Optional[bytes] = None
    sanitised_text: Optional[str] = None
    reason: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_wire(cls, wire: Dict[str, Any]) -> "ValidateResponse":
        """Construct from the current minimal wire response.

        ``wire`` is the dict returned by ``frame.decode_response``::

            {"decision": int, "sanitised_payload": bytes}
        """
        raw = wire.get("sanitised_payload", b"")
        text = raw.decode("utf-8", errors="replace") if raw else None
        return cls(
            decision=wire["decision"],
            sanitised_payload=raw if raw else None,
            sanitised_text=text,
        )

    @classmethod
    def from_pipeline_result(cls, result: Dict[str, Any]) -> "ValidateResponse":
        """Construct from a full pipeline result dict.

        Accepts the shape returned by the Go sidecar's ``pipeline.Result``
        when serialised to JSON::

            {"decision": int, "score": float, "signals": [...],
             "blocked_at": str, "sanitised_payload": bytes}
        """
        signals = [
            Signal(category=s.get("category", ""), score=s.get("score", 0.0))
            for s in result.get("signals", [])
        ]
        raw = result.get("sanitised_payload", b"")
        text = None
        if isinstance(raw, bytes) and raw:
            text = raw.decode("utf-8", errors="replace")
        elif isinstance(raw, str) and raw:
            text = raw
            raw = raw.encode("utf-8")

        return cls(
            decision=result.get("decision", 0x00),
            score=result.get("score", 0.0),
            signals=signals,
            blocked_at=result.get("blocked_at", ""),
            sanitised_payload=raw if raw else None,
            sanitised_text=text,
            reason=result.get("reason", ""),
            metadata=result.get("metadata", {}),
        )

    def to_dict(self) -> Dict[str, Any]:
        """Serialise to a JSON-friendly dict for logging and telemetry."""
        d: Dict[str, Any] = {
            "decision":   self.decision,
            "score":      self.score,
            "signals":    [{"category": s.category, "score": s.score} for s in self.signals],
            "blocked_at": self.blocked_at,
            "reason":     self.reason,
        }
        if self.sanitised_text is not None:
            d["sanitised_text"] = self.sanitised_text
        if self.metadata:
            d["metadata"] = self.metadata
        return d

    @property
    def is_allowed(self) -> bool:
        """True when the decision is ALLOW."""
        return self.decision == 0x00

    @property
    def is_blocked(self) -> bool:
        """True when the decision is BLOCK."""
        return self.decision == 0x02

    @property
    def is_sanitised(self) -> bool:
        """True when the decision is SANITISE."""
        return self.decision == 0x01
