"""
Session — hook calls the sidecar treats as one agent run.

Inside a session the sidecar remembers earlier calls, so a policy can decide
on more than the single request in front of it. The state lives in the
sidecar, keyed by the session ID; the SDK only carries the ID on each call
and cannot read or write the state.

Create one with ``Firewall.session()`` and use its hook methods in place of
the Firewall's. It is also a context manager, for readable scoping::

    with firewall.session() as s:
        s.on_prompt(user_msg)
        results = s.on_context(docs)
        s.on_tool_call("send_email", {"to": "..."})

The sidecar drops a session's state after a period with no calls (30 minutes
by default), so there is nothing to close.
"""
from __future__ import annotations

import re
import secrets
from typing import TYPE_CHECKING, Any

from .models import ChunkResult, Decision, FirewallError, SanitiseResult

if TYPE_CHECKING:
    from .firewall import Firewall

# Same rule as the sidecar's session stage, so a bad ID fails here, early,
# rather than as a BLOCK on the first call.
_SESSION_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")


class Session:
    """A sequence of hook calls the sidecar evaluates as one agent session.

    Args:
        firewall:   The Firewall whose transport and scanner the session uses.
        session_id: The session's ID. Defaults to a random 128-bit hex string.
        allowed_tools, trusted_values, tool_constraints:
                    The task scope, declared to the sidecar when the session is
                    created. See Firewall.session.

    Attributes:
        id:    The session ID.
        scope: The declared task scope, or None if none was declared.

    Raises:
        FirewallError: If session_id is not 1-128 characters from
                       A-Z a-z 0-9 . _ : -, or the task scope is incomplete
                       or rejected by the sidecar.
    """

    def __init__(
        self,
        firewall: "Firewall",
        session_id: str | None = None,
        *,
        allowed_tools: list[str] | None = None,
        trusted_values: list[str] | None = None,
        tool_constraints: dict[str, dict[str, dict[str, Any]]] | None = None,
    ) -> None:
        sid = secrets.token_hex(16) if session_id is None else session_id
        if not isinstance(sid, str) or not _SESSION_ID.fullmatch(sid):
            raise FirewallError(
                "session_id must be 1-128 characters from A-Z a-z 0-9 . _ : -"
            )
        self._firewall = firewall
        self.id = sid
        self.scope: dict[str, Any] | None = None

        if allowed_tools is None:
            if trusted_values is not None or tool_constraints is not None:
                raise FirewallError(
                    "trusted_values and tool_constraints need allowed_tools: "
                    "a task scope starts from the tools it allows"
                )
            return

        scope: dict[str, Any] = {"allowed_tools": list(allowed_tools)}
        if trusted_values is not None:
            scope["trusted_values"] = list(trusted_values)
        if tool_constraints is not None:
            scope["tool_constraints"] = tool_constraints
        result = firewall._on_task(scope, session_id=sid)
        decision = getattr(result, "decision", result)
        if decision is not Decision.ALLOW:
            # Fail loudly: an agent must never run believing it is scoped
            # when the sidecar did not accept the scope.
            raise FirewallError(
                f"the sidecar rejected the task scope ({decision.name}); check that every "
                "allowed tool is in its global allowlist and the constraints are well formed"
            )
        self.scope = scope

    def __enter__(self) -> "Session":
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def __repr__(self) -> str:
        return f"Session(id={self.id!r})"

    def on_prompt(self, text: str) -> Decision | SanitiseResult:
        """Evaluate a user prompt in this session. See Firewall.on_prompt."""
        return self._firewall._on_prompt(text, session_id=self.id)

    def on_context(self, chunks: list[str]) -> list[ChunkResult]:
        """Evaluate retrieved chunks in this session. See Firewall.on_context."""
        return self._firewall._on_context(chunks, session_id=self.id)

    def on_tool_call(self, name: str, params: dict[str, Any]) -> Decision | SanitiseResult:
        """Evaluate a tool call in this session. See Firewall.on_tool_call."""
        return self._firewall._on_tool_call(name, params, session_id=self.id)

    def on_memory(self, key: str, value: str, op: str = "write") -> Decision | SanitiseResult:
        """Evaluate a memory read or write in this session. See Firewall.on_memory."""
        return self._firewall._on_memory(key, value, op, session_id=self.id)

    def on_tool_result(self, tool: str, result: Any) -> Decision | SanitiseResult:
        """Evaluate a tool's output in this session. See Firewall.on_tool_result."""
        return self._firewall._on_tool_result(tool, result, session_id=self.id)
