"""Tests for acf.models — Decision enum and result dataclasses."""
import pytest
from acf.models import (
    BlockInfo,
    BlockReason,
    ChunkResult,
    Decision,
    FirewallBlocked,
    FirewallConnectionError,
    FirewallError,
    SanitiseResult,
    TaintSource,
    parse_block_info,
)


def test_decision_members():
    members = {m.name for m in Decision}
    assert members == {"ALLOW", "SANITISE", "BLOCK"}


def test_decision_values():
    assert Decision.ALLOW.value    == 0x00
    assert Decision.SANITISE.value == 0x01
    assert Decision.BLOCK.value    == 0x02


def test_decision_from_byte_allow():
    assert Decision.from_byte(0x00) == Decision.ALLOW


def test_decision_from_byte_sanitise():
    assert Decision.from_byte(0x01) == Decision.SANITISE


def test_decision_from_byte_block():
    assert Decision.from_byte(0x02) == Decision.BLOCK


def test_decision_from_byte_invalid():
    with pytest.raises(ValueError, match="Unknown decision byte"):
        Decision.from_byte(0xFF)


def test_sanitise_result_fields():
    r = SanitiseResult(
        decision=Decision.SANITISE,
        sanitised_payload=b"safe",
        sanitised_text="safe",
    )
    assert r.decision == Decision.SANITISE
    assert r.sanitised_payload == b"safe"
    assert r.sanitised_text == "safe"


def test_sanitise_result_default_text():
    r = SanitiseResult(decision=Decision.SANITISE, sanitised_payload=b"x")
    assert r.sanitised_text is None


def test_chunk_result_fields():
    r = ChunkResult(original="raw", decision=Decision.ALLOW)
    assert r.original == "raw"
    assert r.decision == Decision.ALLOW
    assert r.sanitised_text is None


def test_firewall_error_is_exception():
    assert issubclass(FirewallError, Exception)


def test_firewall_connection_error_inherits():
    assert issubclass(FirewallConnectionError, FirewallError)


def test_parse_block_info_extracts_reasons_and_untrusted_values():
    raw = (
        b'{"hook":"on_tool_call","confirmable":true,"reasons":['
        b'{"code":"argument_taint","tool":"send_money","param":"recipient",'
        b'"kind":"iban","value":"GB29NWBK60161331926819","sources":[{"hook":"on_tool_result","tool":"read_file"}]},'
        b'{"code":"argument_taint","tool":"send_money","param":"recipient",'
        b'"kind":"number","value":"60161331926819","sources":[{"hook":"on_tool_result","tool":"read_file"}]}]}'
    )
    info = parse_block_info(raw)
    assert info is not None
    assert info.hook == "on_tool_call"
    assert info.confirmable is True
    assert info.untrusted_values == ("GB29NWBK60161331926819",)
    assert len(info.reasons) == 2
    assert info.reasons[0] == BlockReason(
        code="argument_taint",
        tool="send_money",
        param="recipient",
        kind="iban",
        value="GB29NWBK60161331926819",
        sources=(TaintSource(hook="on_tool_result", tool="read_file"),),
    )
    assert parse_block_info(b"") is None
    assert parse_block_info(b"not-json") is None


def test_firewall_blocked_carries_block_info():
    info = BlockInfo(hook="on_tool_call", confirmable=True)
    exc = FirewallBlocked("blocked", hook="on_tool_call", block_info=info)
    assert exc.hook == "on_tool_call"
    assert exc.block_info is info
