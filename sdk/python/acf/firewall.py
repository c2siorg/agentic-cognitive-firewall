"""
Firewall — the main developer-facing class.

Provides the four v1 hook call sites:
  on_prompt(text)             -> Decision
  on_context(chunks)          -> list[ChunkResult]
  on_tool_call(name, params)  -> Decision
  on_memory(key, value, op)   -> Decision

Each method builds a RiskContext JSON payload, delegates to Transport,
and returns the decoded Decision (or raises FirewallError on failure).

Optional: the semantic scanner can be enabled to pre-populate signals in
the RiskContext before sending. When enabled, the scanner runs in the SDK
and emits SemanticHit results that map to Signal objects the sidecar
already understands. The sidecar's scan stage appends its lexical signals
on top — both flow into OPA together.
"""
from __future__ import annotations

import binascii
import json
import logging
import os
from typing import TYPE_CHECKING, Any

from .models import (
    ChunkResult,
    Decision,
    FirewallError,
    SanitiseResult,
)
from .transport import Transport, DEFAULT_SOCKET_PATH

if TYPE_CHECKING:
    from .session import Session

logger = logging.getLogger(__name__)


class Firewall:
    """Entry point for the ACF SDK.

    Args:
        socket_path: Path to the sidecar IPC address. Defaults to
                     ``/tmp/acf.sock`` on Linux/macOS or ``\\\\.\\pipe\\acf``
                     on Windows, or the ACF_SOCKET_PATH environment variable.
        hmac_key:    Raw bytes of the HMAC key. If None, read ACF_HMAC_KEY
                     from the environment (hex-encoded) and decode it.
        enable_semantic_scan:
                     If True, runs the semantic scanner on string payloads
                     before sending, pre-populating signals in the
                     RiskContext. Default False — base SDK stays zero-deps.
                     Can also be set via ACF_SEMANTIC_SCAN env var
                     (true/1/yes or false/0/no). The env var takes
                     precedence over the constructor argument.
                     Requires: pip install acf-sdk[scanners]
        semantic_signal_threshold:
                     Only semantic hits at or above this score (0.0-1.0) are
                     forwarded as signals to the sidecar. When None (the
                     default), 0.50 is used for every backend: scores are
                     calibrated against a benign background corpus at scanner
                     startup, so 0.50 means "less background-like than any
                     benign reference text" regardless of backend or model.
                     See scanners/calibration.py.
        semantic_backend:
                     Embedding backend for the semantic scanner. Use "tfidf"
                     for lightweight/CI environments (no PyTorch needed) or
                     "sentence-transformer" for production accuracy. Can also
                     be set via ACF_SEMANTIC_SCAN_BACKEND env var (env wins).
                     Default: "tfidf".

    Raises:
        FirewallError: If no HMAC key can be resolved, or if semantic
                       scanning is requested but the [scanners] extra is
                       not installed.
    """

    def __init__(
        self,
        socket_path: str | None = None,
        hmac_key: bytes | None = None,
        enable_semantic_scan: bool | None = None,
        semantic_signal_threshold: float | None = None,
        semantic_backend: str = "tfidf",
    ) -> None:
        resolved_path = (
            socket_path
            or os.environ.get("ACF_SOCKET_PATH")
            or DEFAULT_SOCKET_PATH
        )

        if hmac_key is None:
            raw = os.environ.get("ACF_HMAC_KEY", "")
            if not raw:
                raise FirewallError(
                    "No HMAC key provided. Pass hmac_key= or set ACF_HMAC_KEY "
                    "(hex-encoded, min 32 bytes)."
                )
            try:
                hmac_key = binascii.unhexlify(raw)
            except (ValueError, binascii.Error) as exc:
                raise FirewallError(f"ACF_HMAC_KEY is not valid hex: {exc}") from exc

        self._transport = Transport(socket_path=resolved_path, key=hmac_key)

        # Resolve the semantic-scan flag. Env var wins, then constructor
        # arg, then default off. Keeps base SDK zero-deps for users who
        # don't opt in.
        env_flag = os.environ.get("ACF_SEMANTIC_SCAN", "").strip().lower()
        if env_flag in ("true", "1", "yes"):
            enable_semantic_scan = True
        elif env_flag in ("false", "0", "no"):
            enable_semantic_scan = False
        elif enable_semantic_scan is None:
            enable_semantic_scan = False

        self._semantic_scanner = None
        self._semantic_signal_threshold = None
        if enable_semantic_scan:
            try:
                from .scanners import SemanticScanner, SemanticScannerConfig
            except ImportError as exc:
                raise FirewallError(
                    "Semantic scanning was enabled but the [scanners] extra "
                    "is not installed. Install with: pip install acf-sdk[scanners]"
                ) from exc
            env_backend = os.environ.get("ACF_SEMANTIC_SCAN_BACKEND", "").strip().lower()
            resolved_backend = env_backend if env_backend in ("tfidf", "sentence-transformer") else semantic_backend

            # One threshold for every backend. Scores are calibrated against a
            # benign background corpus at scanner startup (see
            # scanners/calibration.py), so 0.5 means the same thing —
            # "less background-like than any benign reference text" — whether
            # the backend is TF-IDF or a sentence-transformer, and whichever
            # model that transformer is. This replaces the previous pair of
            # hand-tuned per-backend constants, which had to be re-measured
            # every time the model or the pattern library changed.
            config = SemanticScannerConfig()
            default_signal_threshold = config.default_threshold

            # User-provided threshold wins over the calibrated default.
            self._semantic_signal_threshold = (
                semantic_signal_threshold
                if semantic_signal_threshold is not None
                else default_signal_threshold
            )

            self._semantic_scanner = SemanticScanner(config=config, backend=resolved_backend)
            logger.info("acf-sdk: semantic scanner enabled (%s backend, signal threshold %.2f)",
                        resolved_backend, self._semantic_signal_threshold)

    # ── sessions ─────────────────────────────────────────────────────────────

    def session(
        self,
        session_id: str | None = None,
        *,
        allowed_tools: list[str] | None = None,
        trusted_values: list[str] | None = None,
        tool_constraints: dict[str, dict[str, dict[str, Any]]] | None = None,
    ) -> "Session":
        """Start a session: hook calls the sidecar treats as one agent run.

        Within a session the sidecar remembers earlier calls, so a policy can
        decide on more than the single request in front of it. Use the
        returned Session's hook methods in place of this Firewall's::

            with firewall.session(
                allowed_tools=["get_balance", "send_money"],
                trusted_values=["GB29NWBK60161331926819"],
                tool_constraints={"send_money": {
                    "recipient": {"allowed": ["GB29NWBK60161331926819"]},
                    "amount": {"max": 100},
                }},
            ) as s:
                s.on_prompt(user_msg)
                s.on_tool_call("send_money", {"recipient": "...", "amount": 20})

        Passing allowed_tools declares the session's task scope. For the rest
        of the session the sidecar blocks any tool call outside allowed_tools,
        and any call whose arguments break tool_constraints. Each constraint is
        a dict with any of ``allowed`` (list of permitted values), ``pattern``
        (regular expression) and ``max`` (largest number); all must hold, and
        an argument the call does not pass is not checked. A scope can only
        narrow the sidecar's global allowlist, and is set once per session.

        Within any session the sidecar also tracks values the agent reads in
        retrieved content and tool output: email addresses, URLs and hosts,
        IBANs, and long numbers. A call to one of the sidecar's
        consequential_tools whose argument repeats such a value is blocked,
        unless the value appeared in the user's prompt or in trusted_values,
        or came only from a tool in the sidecar's trusted_tools. So list in
        trusted_values the values you vouch for, such as recipients the user
        supplied outside the prompt.

        session_id defaults to a random 128-bit hex string. A supplied ID must
        be 1-128 characters from A-Z a-z 0-9 . _ : -, the same rule the
        sidecar enforces.

        Raises:
            FirewallError: If the session ID is malformed, if trusted_values or
                           tool_constraints are given without allowed_tools, or
                           if the sidecar rejects the scope (for example, a tool
                           outside its global allowlist).
        """
        from .session import Session
        return Session(
            self,
            session_id,
            allowed_tools=allowed_tools,
            trusted_values=trusted_values,
            tool_constraints=tool_constraints,
        )

    # ── v1 hook call sites ────────────────────────────────────────────────────
    # These are sessionless: each call is evaluated on its own.

    def on_prompt(self, text: str) -> Decision | SanitiseResult:
        """Evaluate a user prompt before it enters the model context.

        Returns Decision.ALLOW, Decision.BLOCK, or a SanitiseResult.
        """
        return self._on_prompt(text, session_id="")

    def on_context(self, chunks: list[str]) -> list[ChunkResult]:
        """Evaluate RAG chunks before injection into the model context.

        Each chunk is evaluated independently. Returns one ChunkResult per chunk.
        Chunks with a BLOCK decision have sanitised_text=None.
        """
        return self._on_context(chunks, session_id="")

    def on_tool_call(self, name: str, params: dict[str, Any]) -> Decision | SanitiseResult:
        """Evaluate a tool call before the tool executes.

        Returns Decision.ALLOW, Decision.BLOCK, or a SanitiseResult.
        """
        return self._on_tool_call(name, params, session_id="")

    def on_memory(self, key: str, value: str, op: str = "write") -> Decision | SanitiseResult:
        """Evaluate a memory read or write before it is committed.

        op: "write" (default) or "read".
        Returns Decision.ALLOW, Decision.BLOCK, or a SanitiseResult.
        """
        return self._on_memory(key, value, op, session_id="")

    def on_tool_result(self, tool: str, result: Any) -> Decision | SanitiseResult:
        """Evaluate a tool's output before the agent reads it.

        tool names the tool that produced the output, so policy can tell
        sources apart: output from a tool in the sidecar's trusted_tools list
        is not screened. A result that is not a string is JSON-encoded first.

        Returns Decision.ALLOW, Decision.BLOCK, or a SanitiseResult whose
        sanitised_text is the cleaned output to show the agent instead.
        """
        return self._on_tool_result(tool, result, session_id="")

    # ── hook implementations, shared with Session ────────────────────────────

    def _on_tool_result(self, tool: str, result: Any, *, session_id: str) -> Decision | SanitiseResult:
        text = result if isinstance(result, str) else json.dumps(result, separators=(",", ":"), default=str)
        payload = self._build_payload(
            "on_tool_result",
            {"tool": tool, "result": text},
            provenance="tool_output",
            session_id=session_id,
        )
        return self._send(payload)

    def _on_task(self, scope: dict[str, Any], *, session_id: str) -> Decision | SanitiseResult:
        payload = self._build_payload("on_task", scope, provenance="developer", session_id=session_id)
        return self._send(payload)

    def _on_prompt(self, text: str, *, session_id: str) -> Decision | SanitiseResult:
        payload = self._build_payload("on_prompt", text, provenance="user", session_id=session_id)
        return self._send(payload)

    def _on_context(self, chunks: list[str], *, session_id: str) -> list[ChunkResult]:
        results = []
        for chunk in chunks:
            payload  = self._build_payload("on_context", chunk, provenance="rag", session_id=session_id)
            decision = self._send(payload)
            if isinstance(decision, SanitiseResult):
                results.append(ChunkResult(
                    original=chunk,
                    decision=Decision.SANITISE,
                    sanitised_text=decision.sanitised_text,
                ))
            else:
                results.append(ChunkResult(
                    original=chunk,
                    decision=decision,
                    sanitised_text=None,
                ))
        return results

    def _on_tool_call(
        self, name: str, params: dict[str, Any], *, session_id: str
    ) -> Decision | SanitiseResult:
        payload = self._build_payload(
            "on_tool_call",
            {"name": name, "params": params},
            provenance="agent",
            session_id=session_id,
        )
        return self._send(payload)

    def _on_memory(
        self, key: str, value: str, op: str, *, session_id: str
    ) -> Decision | SanitiseResult:
        payload = self._build_payload(
            "on_memory",
            {"key": key, "value": value, "op": op},
            provenance="agent",
            session_id=session_id,
        )
        return self._send(payload)

    # ── internals ────────────────────────────────────────────────────────────

    def _build_payload(
        self,
        hook_type: str,
        content: Any,
        *,
        provenance: str = "sdk",
        session_id: str = "",
    ) -> bytes:
        signals = self._run_semantic_scanner(hook_type, content)
        ctx = {
            "score":       0.0,
            "signals":     signals,
            "provenance":  provenance,
            "session_id":  session_id,
            "hook_type":   hook_type,
            "payload":     content,
            "state":       None,
        }
        return json.dumps(ctx, separators=(",", ":")).encode("utf-8")

    def _run_semantic_scanner(self, hook_type: str, content: Any) -> list[dict]:
        """Run the semantic scanner on string content and return wire-format signals.

        Returns an empty list if the scanner is disabled, the content isn't
        a usable string, or the scanner produces no hits. Scanner errors are
        logged and swallowed — the sidecar's lexical scan still runs, so a
        scanner failure must not break the request.
        """
        if self._semantic_scanner is None:
            return []

        # The scanner only operates on text. Extract a string from the
        # content if possible; otherwise skip.
        text = self._extract_text(hook_type, content)
        if not text:
            return []

        # Import the scanner types lazily — only needed when enabled.
        from .scanners import InputType, ScanInput, TrustLevel

        hook_to_input_type = {
            "on_prompt":      InputType.PROMPT,
            "on_context":     InputType.RAG_DOCUMENT,
            "on_tool_call":   InputType.TOOL_CALL,
            "on_memory":      InputType.MEMORY_WRITE,
            "on_tool_result": InputType.TOOL_OUTPUT,
        }
        input_type = hook_to_input_type.get(hook_type, InputType.PROMPT)

        scan_input = ScanInput(
            agent_id="sdk",
            execution_id="sdk",
            session_id="sdk",
            input_type=input_type,
            normalized_content=text,
            trust_level=TrustLevel.LOW,
        )

        try:
            result = self._semantic_scanner.scan(scan_input)
        except Exception as exc:  # pragma: no cover — defensive
            logger.warning("acf-sdk: semantic scanner error: %s", exc)
            return []

        # Map SemanticHit → wire-format Signal dict the sidecar already accepts.
        # Filter by signal_threshold first — the scanner's own default_threshold
        # is set lower for in-process reporting; we use a stricter bar before
        # forwarding to the sidecar so weak TF-IDF surface-overlap doesn't
        # become evidence in OPA's view. When users upgrade to the
        # sentence-transformer backend they can drop this threshold.
        return [
            {"category": hit.matched_category, "score": hit.similarity_score}
            for hit in result.semantic_hits
            if hit.similarity_score >= self._semantic_signal_threshold
        ]

    @staticmethod
    def _extract_text(hook_type: str, content: Any) -> str:
        """Pull a string out of the per-hook payload shape.

        on_prompt:    content is already a string
        on_context:   content is a single chunk string
        on_tool_call: content is {"name", "params"} — scan params as JSON
        on_memory:    content is {"key", "value", "op"} — scan the value
        on_tool_result: content is {"tool", "result"} — scan the result
        on_task:      content is a scope declaration — nothing to scan
        """
        if isinstance(content, str):
            return content
        if isinstance(content, dict):
            if hook_type == "on_tool_call":
                params = content.get("params")
                if isinstance(params, dict) and params:
                    return json.dumps(params, separators=(",", ":"))
                if isinstance(params, str):
                    return params
            if hook_type == "on_memory":
                value = content.get("value")
                if isinstance(value, str) and value:
                    return value
            if hook_type == "on_tool_result":
                result = content.get("result")
                if isinstance(result, str) and result:
                    return result
        return ""

    def _send(self, payload: bytes) -> Decision | SanitiseResult:
        resp     = self._transport.send(payload)
        decision = Decision.from_byte(resp["decision"])

        if decision == Decision.SANITISE:
            raw  = resp["sanitised_payload"]
            text = raw.decode("utf-8", errors="replace") if raw else None
            return SanitiseResult(
                decision=decision,
                sanitised_payload=raw,
                sanitised_text=_unwrap_sanitised(text),
            )
        return decision


def _unwrap_sanitised(text: str | None) -> str | None:
    """Recover the cleaned text from the sidecar's encoding of it.

    The sidecar JSON-encodes the sanitised value: a string payload comes back
    as a JSON string, any other payload as {"sanitised": text}. Anything else
    is returned unchanged.
    """
    if text is None:
        return None
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        return text
    if isinstance(value, str):
        return value
    if isinstance(value, dict) and len(value) == 1 and isinstance(value.get("sanitised"), str):
        return value["sanitised"]
    return text