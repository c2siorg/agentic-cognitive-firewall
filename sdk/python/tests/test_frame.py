"""Tests for acf.frame — binary frame encode/decode round-trips."""
import hashlib
import hmac
import struct

import pytest
from acf.frame import (
    MAGIC,
    VERSION,
    HEADER_SIZE,
    FrameError,
    decode_request,
    decode_response,
    encode_request,
    encode_response,
    signed_message,
)

KEY     = b"test-key-32-bytes-long-padded!!!"
PAYLOAD = b'{"hook_type":"on_prompt","payload":"hello"}'


# ── encode_request ────────────────────────────────────────────────────────────

def test_encode_request_magic():
    frame = encode_request(PAYLOAD, KEY)
    assert frame[0] == MAGIC


def test_encode_request_version():
    frame = encode_request(PAYLOAD, KEY)
    assert frame[1] == VERSION


def test_encode_request_length_field():
    frame = encode_request(PAYLOAD, KEY)
    length_field = struct.unpack(">I", frame[2:6])[0]
    assert length_field == len(PAYLOAD)


def test_encode_request_nonce_length():
    frame = encode_request(PAYLOAD, KEY)
    nonce = frame[6:22]
    assert len(nonce) == 16


def test_encode_request_nonce_unique():
    f1 = encode_request(PAYLOAD, KEY)
    f2 = encode_request(PAYLOAD, KEY)
    assert f1[6:22] != f2[6:22], "two frames must have different nonces"


def test_encode_request_total_length():
    frame = encode_request(PAYLOAD, KEY)
    assert len(frame) == HEADER_SIZE + len(PAYLOAD)


def test_encode_request_hmac_valid():
    """The HMAC in the encoded frame must be verifiable with the same key."""
    frame   = encode_request(PAYLOAD, KEY)
    version = frame[1]
    length  = struct.unpack(">I", frame[2:6])[0]
    nonce   = frame[6:22]
    mac     = frame[22:54]
    payload = frame[HEADER_SIZE:]

    msg      = signed_message(version, length, nonce, payload)
    expected = hmac.new(KEY, msg, hashlib.sha256).digest()
    assert hmac.compare_digest(mac, expected)


# ── decode_request ────────────────────────────────────────────────────────────

def test_decode_request_roundtrip():
    frame  = encode_request(PAYLOAD, KEY)
    result = decode_request(frame)
    assert result["payload"] == PAYLOAD
    assert result["version"] == VERSION
    assert len(result["nonce"]) == 16
    assert len(result["hmac"]) == 32


def test_decode_request_bad_magic():
    frame      = bytearray(encode_request(PAYLOAD, KEY))
    frame[0]   = 0xFF
    with pytest.raises(FrameError, match="bad magic"):
        decode_request(bytes(frame))


def test_decode_request_bad_version():
    frame    = bytearray(encode_request(PAYLOAD, KEY))
    frame[1] = 0x02
    with pytest.raises(FrameError, match="unsupported version"):
        decode_request(bytes(frame))


def test_decode_request_truncated_header():
    with pytest.raises(FrameError, match="truncated"):
        decode_request(b"\xac\x01\x00\x00\x00\x05")  # only 6 bytes


def test_decode_request_truncated_payload():
    # Build a valid header claiming 100-byte payload, but only supply 10.
    frame    = bytearray(encode_request(b"x" * 100, KEY))
    short    = bytes(frame[:HEADER_SIZE + 10])
    with pytest.raises(FrameError, match="truncated"):
        decode_request(short)


# ── encode_response / decode_response ────────────────────────────────────────

def test_decode_response_allow():
    data   = encode_response(0x00)
    result = decode_response(data)
    assert result["decision"] == 0x00
    assert result["sanitised_payload"] == b""


def test_decode_response_block():
    data   = encode_response(0x02)
    result = decode_response(data)
    assert result["decision"] == 0x02
    assert result["sanitised_payload"] == b""


def test_decode_response_sanitise():
    body   = b"safe content"
    data   = encode_response(0x01, body)
    result = decode_response(data)
    assert result["decision"] == 0x01
    assert result["sanitised_payload"] == body


def test_decode_response_truncated():
    with pytest.raises(FrameError, match="truncated response"):
        decode_response(b"\x00\x00\x00")


def test_decode_response_truncated_payload():
    # Header declares a 16-byte sanitised payload, but only 3 bytes are provided.
    truncated = b"\x01" + struct.pack(">I", 16) + b"abc"
    with pytest.raises(FrameError, match="truncated sanitised payload"):
        decode_response(truncated)


# ── signed_message ────────────────────────────────────────────────────────────

def test_signed_message_composition():
    nonce   = b"\x01" * 16
    payload = b"hello"
    msg     = signed_message(VERSION, len(payload), nonce, payload)

    assert msg[0] == VERSION
    assert struct.unpack(">I", msg[1:5])[0] == len(payload)
    assert msg[5:21] == nonce
    assert msg[21:] == payload
