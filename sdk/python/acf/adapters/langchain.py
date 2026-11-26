"""
LangChain adapter: guard an agent's tools with ACF.

``guard_tools`` wraps LangChain tools so every call and every result goes
through the firewall:

- before a tool runs, ``on_tool_call`` decides whether it may; a blocked call
  never runs, and the agent receives a refusal it can read and recover from;
- after it runs, ``on_tool_result`` screens the output before the agent reads
  it, so a sanitised result reaches the agent in place of the original.

Pass a ``Session`` rather than a ``Firewall`` to enforce a task scope and the
provenance rule: the session remembers the values each result carried, so a
later call that sends money or data to one of them is blocked. The wrapped
tools keep their names, descriptions, and argument schemas, so they work with
any LangChain or LangGraph agent::

    from acf import Firewall
    from acf.adapters.langchain import guard_tools

    fw = Firewall()
    with fw.session(allowed_tools=["read_file", "send_money"]) as session:
        agent = create_agent(model, tools=guard_tools(tools, session))
        agent.invoke({"messages": [("user", request)]})

langchain-core is not a dependency of the SDK. This module imports without it;
calling ``guard_tools`` needs it installed (``pip install langchain-core``).
"""
from __future__ import annotations

import asyncio
from typing import Any, Callable, Iterable

from ..models import BlockInfo, Decision, SanitiseResult

BLOCKED_CALL = "Blocked by policy: {tool} may not run with these arguments."
WITHHELD_RESULT = "[The result of {tool} was withheld by policy.]"


def _require_langchain():
    try:
        from langchain_core.tools import BaseTool
    except ImportError as exc:  # pragma: no cover - exercised without langchain
        raise ImportError(
            "acf.adapters.langchain needs langchain-core: pip install langchain-core"
        ) from exc
    return BaseTool


def guard_tools(
    tools: Iterable[Any],
    guard: Any,
    *,
    raise_on_block: bool = False,
    confirm: Callable[[BlockInfo], bool] | None = None,
) -> list:
    """Wrap LangChain tools so their calls and results pass through ACF.

    Args:
        tools: LangChain tools (``BaseTool`` instances, including ``@tool``
            functions).
        guard: A ``Firewall`` or a ``Session``. A session also enforces its
            task scope and the provenance of argument values.
        raise_on_block: Raise ``FirewallBlocked`` instead of returning a
            refusal to the agent when a call is blocked.
        confirm: Optional callback invoked when ``on_tool_call`` blocks solely on
            confirmable argument taint (``block_info.confirmable``). Returning
            ``True`` approves ``block_info.untrusted_values`` via ``guard.confirm``
            and retries the tool call once.

    Returns:
        The wrapped tools, in the same order.
    """
    BaseTool = _require_langchain()
    wrapper = _guarded_tool_class(BaseTool)
    return [wrapper.wrap(tool, guard, raise_on_block, confirm) for tool in tools]


_GUARDED = None


def _guarded_tool_class(BaseTool):
    """Build the wrapper class lazily, so the module imports without LangChain."""
    global _GUARDED
    if _GUARDED is not None:
        return _GUARDED

    from ..models import FirewallBlocked

    class GuardedTool(BaseTool):
        """A LangChain tool whose calls and results ACF decides on."""

        inner: Any = None
        guard: Any = None
        raise_on_block: bool = False
        confirm: Any = None

        @classmethod
        def wrap(cls, tool, guard, raise_on_block=False, confirm=None):
            return cls(
                name=tool.name,
                description=tool.description,
                args_schema=tool.args_schema,
                return_direct=getattr(tool, "return_direct", False),
                inner=tool,
                guard=guard,
                raise_on_block=raise_on_block,
                confirm=confirm,
            )

        def _before(self, arguments: dict) -> str | None:
            """None if the call may run, otherwise the refusal for the agent."""
            if self.guard.on_tool_call(self.name, arguments) == Decision.BLOCK:
                block_info = getattr(self.guard, "last_block", None)
                if (
                    self.confirm is not None
                    and block_info is not None
                    and block_info.confirmable
                    and block_info.untrusted_values
                    and callable(getattr(self.guard, "confirm", None))
                    and self.confirm(block_info)
                    and self.guard.confirm(list(block_info.untrusted_values)) == Decision.ALLOW
                ):
                    if self.guard.on_tool_call(self.name, arguments) != Decision.BLOCK:
                        return None
                    block_info = getattr(self.guard, "last_block", None)
                if self.raise_on_block:
                    raise FirewallBlocked(
                        f"ACF blocked {self.name}",
                        hook="on_tool_call",
                        block_info=block_info,
                    )
                return BLOCKED_CALL.format(tool=self.name)
            return None

        def _after(self, output: Any) -> Any:
            screened = self.guard.on_tool_result(self.name, output)
            if isinstance(screened, SanitiseResult):
                return screened.sanitised_text
            if screened == Decision.BLOCK:
                return WITHHELD_RESULT.format(tool=self.name)
            return output

        def _run(self, *args: Any, run_manager: Any = None, **kwargs: Any) -> Any:
            arguments = kwargs if kwargs else (args[0] if args else {})
            refusal = self._before(arguments if isinstance(arguments, dict) else {"input": arguments})
            if refusal is not None:
                return refusal
            return self._after(self.inner.invoke(arguments))

        async def _arun(self, *args: Any, run_manager: Any = None, **kwargs: Any) -> Any:
            arguments = kwargs if kwargs else (args[0] if args else {})
            payload = arguments if isinstance(arguments, dict) else {"input": arguments}
            refusal = await asyncio.to_thread(self._before, payload)
            if refusal is not None:
                return refusal
            output = await self.inner.ainvoke(arguments)
            return await asyncio.to_thread(self._after, output)

    _GUARDED = GuardedTool
    return GuardedTool
