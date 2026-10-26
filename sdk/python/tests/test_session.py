"""
Tests for Firewall.session() and the Session hook methods.

The transport is replaced with a recorder, so these check what the SDK puts
on the wire: the session ID on every call in a session, none on the
Firewall's own sessionless calls.
"""
from __future__ import annotations

import json

import pytest

from acf import Firewall, Session
from acf.models import ChunkResult, Decision, FirewallError

HMAC_KEY = b"test-key-32-bytes-long-padded!!!"


@pytest.fixture
def firewall(monkeypatch):
    monkeypatch.delenv("ACF_SEMANTIC_SCAN", raising=False)
    fw = Firewall(socket_path="/tmp/acf_test_session.sock", hmac_key=HMAC_KEY)
    sent: list[dict] = []
    verdicts: dict[str, Decision] = {}  # hook_type -> decision; default ALLOW

    def record(payload: bytes) -> dict:
        body = json.loads(payload)
        sent.append(body)
        decision = verdicts.get(body["hook_type"], Decision.ALLOW)
        return {"decision": decision.value, "sanitised_payload": b""}

    monkeypatch.setattr(fw._transport, "send", record)
    fw.sent = sent  # type: ignore[attr-defined]
    fw.verdicts = verdicts  # type: ignore[attr-defined]
    return fw


def test_every_call_in_a_session_carries_its_id(firewall):
    with firewall.session() as s:
        s.on_prompt("hello")
        assert isinstance(s.on_context(["a chunk"])[0], ChunkResult)
        s.on_tool_call("search", {"q": "x"})
        s.on_memory("notes", "v", "write")
    assert [p["hook_type"] for p in firewall.sent] == ["on_prompt", "on_context", "on_tool_call", "on_memory"]
    assert {p["session_id"] for p in firewall.sent} == {s.id}


def test_firewall_calls_stay_sessionless(firewall):
    firewall.on_prompt("hello")
    firewall.on_tool_call("search", {})
    assert [p["session_id"] for p in firewall.sent] == ["", ""]


def test_sessions_get_distinct_random_ids(firewall):
    a, b = firewall.session(), firewall.session()
    assert a.id != b.id
    assert len(a.id) == 32 and all(c in "0123456789abcdef" for c in a.id)


def test_explicit_id_is_kept(firewall):
    s = firewall.session("run-42:tenant.a")
    s.on_prompt("x")
    assert s.id == "run-42:tenant.a"
    assert firewall.sent[0]["session_id"] == "run-42:tenant.a"


@pytest.mark.parametrize(
    "bad",
    [
        "", "has space", "semi;colon", "x" * 129,
        "run-1\n", "x" * 128 + "\n", "run-1\r\n", "run-1\u2028",
    ],
)
@pytest.mark.parametrize("scoped", [False, True])
def test_malformed_ids_fail_early(firewall, bad, scoped):
    scope = {"allowed_tools": ["search"]} if scoped else {}
    with pytest.raises(FirewallError, match="session_id must be"):
        firewall.session(bad, **scope)
    assert firewall.sent == []


@pytest.mark.parametrize("session_id", ["a", "A0._:-", "x" * 128])
def test_valid_session_id_boundaries_are_kept(firewall, session_id):
    session = firewall.session(session_id)
    session.on_prompt("hello")
    assert session.id == session_id
    assert firewall.sent[0]["session_id"] == session_id


def test_session_payloads_match_firewall_payloads_apart_from_the_id(firewall):
    firewall.on_tool_call("search", {"q": "x"})
    firewall.session("s1").on_tool_call("search", {"q": "x"})
    plain, in_session = firewall.sent
    assert in_session["session_id"] == "s1"
    in_session["session_id"] = ""
    assert plain == in_session


def test_session_is_exported():
    assert Session.__module__ == "acf.session"


def test_scope_is_declared_once_when_the_session_starts(firewall):
    constraints = {"send_money": {"amount": {"max": 100}}}
    s = firewall.session(
        allowed_tools=["send_money"],
        trusted_values=["GB29NWBK60161331926819"],
        tool_constraints=constraints,
    )
    s.on_tool_call("send_money", {"amount": 20})
    task, call = firewall.sent
    assert task["hook_type"] == "on_task" and task["session_id"] == s.id
    assert task["payload"] == {
        "allowed_tools": ["send_money"],
        "trusted_values": ["GB29NWBK60161331926819"],
        "tool_constraints": constraints,
    }
    assert task["provenance"] == "developer"
    assert call["hook_type"] == "on_tool_call"
    assert s.scope == task["payload"]


def test_no_scope_means_no_declaration(firewall):
    s = firewall.session()
    assert s.scope is None
    assert firewall.sent == []


def test_rejected_scope_raises(firewall):
    firewall.verdicts["on_task"] = Decision.BLOCK
    with pytest.raises(FirewallError, match="rejected the task scope"):
        firewall.session(allowed_tools=["send_money"])


@pytest.mark.parametrize("extra", [{"trusted_values": ["x"]}, {"tool_constraints": {"a": {}}}])
def test_scope_details_need_allowed_tools(firewall, extra):
    with pytest.raises(FirewallError, match="need allowed_tools"):
        firewall.session(**extra)
    assert firewall.sent == []
