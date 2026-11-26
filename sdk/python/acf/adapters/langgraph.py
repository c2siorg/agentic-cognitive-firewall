"""
FirewallNode — drop-in node for LangGraph.

Wraps a Firewall in a node you can insert anywhere in a StateGraph. Picks one
of the hooks (on_prompt, on_context, on_tool_call, on_memory, on_tool_result)
and runs it on whatever value you point it at in state. A Session works in
place of a Firewall, so a node can enforce a session's task scope.

If the firewall says BLOCK, the node raises FirewallBlocked — a real exception
that propagates out of the graph run so the caller can stop. If it says
SANITISE, the node writes the cleaned value back to state. If it says ALLOW,
nothing changes.

langgraph itself is not a required dependency. This module imports without it;
you only need it installed to actually run a graph.
"""
from __future__ import annotations

from typing import Any, Callable, Literal, Optional

from ..firewall import Firewall
from ..models import Decision, SanitiseResult, ChunkResult, FirewallBlocked


HookType = Literal["on_prompt", "on_context", "on_tool_call", "on_memory", "on_tool_result"]
_HOOKS = ("on_prompt", "on_context", "on_tool_call", "on_memory", "on_tool_result")


class FirewallNode:
    """A LangGraph node that runs a firewall check on a value in state.

    Example:
        from langgraph.graph import StateGraph
        from acf import Firewall
        from acf.adapters.langgraph import FirewallNode

        fw = Firewall()

        graph = StateGraph(MyState)
        graph.add_node("prompt_guard", FirewallNode(
            firewall=fw,
            hook="on_prompt",
            input_key="user_message",
        ))

    Args:
        firewall:   The Firewall to use, or a Session to also enforce its task
                    scope and the provenance of argument values.
        hook:       Which hook to run. One of on_prompt, on_context,
                    on_tool_call, on_memory, on_tool_result.

    To guard the tools an agent node calls, wrap them with
    acf.adapters.langchain.guard_tools instead: it checks every call and
    screens every result, which a node placed before or after the agent
    cannot do.
        input_key:  Where to read the value from in state.
        output_key: Where to write the result back. Defaults to input_key.
        on_block:   Optional callback (state, decision) -> None. Runs right
                    before FirewallBlocked is raised. Handy for logging.

    Raises:
        FirewallBlocked: On a BLOCK decision.
    """

    def __init__(
        self,
        firewall: Firewall,
        hook: HookType,
        input_key: str,
        output_key: Optional[str] = None,
        on_block: Optional[Callable[[dict, Decision], None]] = None,
    ) -> None:
        if hook not in _HOOKS:
            raise ValueError(
                f"Invalid hook {hook!r}. Must be one of: " + ", ".join(_HOOKS)
            )
        self._firewall = firewall
        self._hook = hook
        self._input_key = input_key
        self._output_key = output_key or input_key
        self._on_block = on_block

    def __call__(self, state: dict[str, Any]) -> dict[str, Any]:
        """Run the firewall check on the configured state key."""
        if self._input_key not in state:
            raise KeyError(
                f"FirewallNode: state is missing required key {self._input_key!r}"
            )

        value = state[self._input_key]
        decision = self._dispatch(value)

        # Blocked — let the caller log if they want, then stop the run.
        if decision == Decision.BLOCK:
            if self._on_block is not None:
                self._on_block(state, decision)
            raise FirewallBlocked(
                f"FirewallNode blocked input at hook {self._hook}",
                hook=self._hook,
                block_info=getattr(self._firewall, "last_block", None),
            )

        # Sanitised — swap the cleaned value back into state.
        if isinstance(decision, SanitiseResult):
            return {self._output_key: decision.sanitised_text}

        # on_context returns a list of per-chunk results — handled separately.
        if self._hook == "on_context" and isinstance(decision, list):
            return self._handle_context_result(decision)

        # Allowed — nothing to update.
        return {}

    def _dispatch(self, value: Any) -> Any:
        """Call the right hook on the firewall with the value from state."""
        if self._hook == "on_prompt":
            if not isinstance(value, str):
                raise TypeError(
                    f"on_prompt expects str, got {type(value).__name__}"
                )
            return self._firewall.on_prompt(value)

        if self._hook == "on_context":
            if not isinstance(value, list):
                raise TypeError(
                    f"on_context expects list[str], got {type(value).__name__}"
                )
            return self._firewall.on_context(value)

        if self._hook == "on_tool_call":
            if not isinstance(value, dict) or "name" not in value:
                raise TypeError(
                    "on_tool_call expects dict with 'name' and 'params' keys"
                )
            return self._firewall.on_tool_call(
                name=value["name"],
                params=value.get("params", {}),
            )

        if self._hook == "on_memory":
            if not isinstance(value, dict) or "key" not in value or "value" not in value:
                raise TypeError(
                    "on_memory expects dict with 'key', 'value', and 'op' keys"
                )
            return self._firewall.on_memory(
                key=value["key"],
                value=value["value"],
                op=value.get("op", "write"),
            )

        if self._hook == "on_tool_result":
            if not isinstance(value, dict) or "tool" not in value or "result" not in value:
                raise TypeError(
                    "on_tool_result expects dict with 'tool' and 'result' keys"
                )
            return self._firewall.on_tool_result(
                tool=value["tool"],
                result=value["result"],
            )

        raise RuntimeError(f"Unreachable hook: {self._hook}")

    def _handle_context_result(
        self, results: list[ChunkResult]
    ) -> dict[str, Any]:
        """Drop blocked chunks, swap in sanitised text where present, keep the rest."""
        kept: list[str] = []
        for r in results:
            if r.decision == Decision.BLOCK:
                # Blocked chunk — drop it without stopping the whole run.
                continue
            if r.decision == Decision.SANITISE and r.sanitised_text is not None:
                kept.append(r.sanitised_text)
            else:
                kept.append(r.original)
        return {self._output_key: kept}