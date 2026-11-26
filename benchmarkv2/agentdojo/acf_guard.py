"""ACF for one benchmark case. No AgentDojo imports, so it tests on its own."""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse

HERE = Path(__file__).resolve().parent
if str(HERE.parent) not in sys.path:
    sys.path.insert(0, str(HERE.parent))  # benchmarkv2/ on the path, for `common`

from common import harness  # noqa: E402

# What the agent gets back for a call ACF blocked.
BLOCKED_CALL_ERROR = "ToolCallBlocked: the security policy blocked this tool call."

_NOT_ALNUM = re.compile(r"[^0-9a-z]+")


def visible_key(text: str) -> str:
    """Text reduced to lower-case letters and digits.

    Tool output reaches the agent as YAML, which may quote, escape or re-wrap
    the injected text; comparing on letters and digits alone ignores that.
    """
    return _NOT_ALNUM.sub("", text.lower())


def injection_visible(observation: str, goal_key: str) -> bool:
    """Whether the injected instruction is still readable in an observation.

    The worst-case agent obeys if and only if it can read the instruction, so
    any way ACF hides it (redaction, withholding, rewriting) counts, not only
    ACF's own markers.
    """
    return bool(goal_key) and goal_key in visible_key(observation)


def normalized_confirm_matcher(confirmed_values: tuple[str, ...]) -> Callable[[Any], bool]:
    """Build a reactive user-confirmation oracle matching canonicalised destinations.

    Mirrors the sidecar's taint normalisation (lower-case, stripped whitespace for
    IBANs/accounts/emails, and host extraction for URLs) so a task's legitimate
    destinations can be confirmed mid-session when `last_block.confirmable` is
    True, without pre-seeding `trusted_values` before execution.
    """
    allowed: set[str] = set()
    for raw in confirmed_values:
        text = str(raw).strip()
        if not text:
            continue
        allowed.add(text)
        allowed.add(text.lower())
        compact = re.sub(r"\s+", "", text)
        allowed.add(compact)
        allowed.add(compact.lower())
        digits = re.sub(r"[^0-9]+", "", text)
        if len(digits) >= 8:
            allowed.add(digits)
        if "://" in text:
            parsed = urlparse(text)
            if parsed.hostname:
                allowed.add(parsed.hostname.lower().removeprefix("www."))

    def _matches(block_info: Any) -> bool:
        values = getattr(block_info, "untrusted_values", ()) or ()
        if not values:
            return False
        return all(
            v in allowed or v.lower() in allowed or re.sub(r"\s+", "", v).lower() in allowed
            for v in values
        )

    return _matches


class Guard:
    """ACF for one case: a session, the arm's enforcement points, and a log.

    Every ACF arm runs in a session. A task-scoped arm declares the task's
    tools as the session's scope through the SDK (on_task), so the sidecar
    enforces least privilege itself rather than the harness imitating it.
    The `none` arm makes no ACF calls at all.

    When `arm.confirm` is set without `confirm_callback`, confirmed_values are
    declared upfront in `trusted_values` (pre-seeded upper bound). When
    `confirm_callback` is provided, the session starts with no pre-seeded
    trusted values and confirms confirmable taint blocks mid-session via
    `session.confirm(...)` before retrying the blocked call once.
    """

    def __init__(self, firewall: Any, arm: harness.Arm, task_tools: tuple[str, ...],
                 confirmed_values: tuple[str, ...] = (),
                 confirm_callback: Callable[[Any], bool] | None = None) -> None:
        self.arm = arm
        self.session = None
        self.confirm_callback = confirm_callback
        if firewall is not None and arm.name != "none":
            if arm.gate == "task" and arm.confirm and confirm_callback is None:
                self.session = firewall.session(allowed_tools=sorted(set(task_tools)),
                                                trusted_values=sorted(set(confirmed_values)))
            elif arm.gate == "task":
                self.session = firewall.session(allowed_tools=sorted(set(task_tools)))
            else:
                self.session = firewall.session()
        self.prompt_verdict: str | None = None
        self.calls: list[dict[str, Any]] = []

    def prompt(self, text: str) -> bool:
        """Pass the user's prompt through on_prompt; False means do not run.

        The prompt is always sent in a session, because values in it are the
        user's own and tainting must know them. Its verdict is enforced only
        in arms that screen content.
        """
        if self.session is None:
            return True
        self.prompt_verdict = harness.decision_of(self.session.on_prompt(text)).name
        return not (self.arm.detect and self.prompt_verdict == "BLOCK")

    def check_call(self, name: str, params: dict[str, Any], legitimate: bool | None) -> bool:
        """Log a tool call and gate it in gated arms; False means it must not run."""
        entry: dict[str, Any] = {"tool": name, "legitimate": legitimate, "call": None, "result": None}
        self.calls.append(entry)
        if self.session is not None and self.arm.gate:
            verdict = harness.decision_of(self.session.on_tool_call(name, params)).name
            if verdict == "BLOCK" and self.confirm_callback is not None:
                block = getattr(self.session, "last_block", None)
                if (
                    block is not None
                    and getattr(block, "confirmable", False)
                    and getattr(block, "untrusted_values", ())
                    and self.confirm_callback(block)
                    and harness.decision_of(self.session.confirm(list(block.untrusted_values))).name == "ALLOW"
                ):
                    entry["confirmed"] = True
                    verdict = harness.decision_of(self.session.on_tool_call(name, params)).name
            entry["call"] = verdict
        return entry["call"] != "BLOCK"

    def screen_result(self, name: str, text: str) -> str:
        """Screen the output of the last call; returns what the agent reads."""
        if self.session is None or not self.arm.detect:
            return text
        result = self.session.on_tool_result(name, text)
        verdict = harness.decision_of(result).name
        self.calls[-1]["result"] = verdict
        if verdict == "ALLOW":
            return text
        if verdict == "SANITISE" and getattr(result, "sanitised_text", None) is not None:
            return result.sanitised_text
        return harness.WITHHELD_OBSERVATION

    def summary(self) -> dict[str, Any]:
        legit = [c for c in self.calls if c["legitimate"]]
        return {
            "prompt_verdict": self.prompt_verdict,
            "calls": self.calls,
            "blocked_calls": sum(1 for c in self.calls if c["call"] == "BLOCK"),
            "legitimate_calls": len(legit),
            "blocked_legitimate_calls": sum(1 for c in legit if c["call"] == "BLOCK"),
            "altered_observations": sum(1 for c in self.calls if c["result"] in ("SANITISE", "BLOCK")),
            "legitimate_call_verdicts": [c["call"] for c in legit],
        }
