"""
Binary frame encoder/decoder for the ACF IPC protocol.
Mirrors sidecar/internal/transport/frame.go exactly.

Request frame layout (54-byte header + payload):
  [0]      magic     — 0xAC
  [1]      version   — 1
  [2:6]    length    — uint32 big-endian
  [6:22]   nonce     — 16 random bytes
  [22:54]  hmac      — 32 bytes HMAC-SHA256 over signed_message(...)
  [54:]    payload   — JSON bytes

Response frame layout:
  [0]      decision  — 0x00 ALLOW · 0x01 SANITISE · 0x02 BLOCK
  [1:5]    san_len   — uint32 big-endian (0 if not SANITISE)
  [5:]     sanitised — JSON bytes (SANITISE only)
"""
from __future__ import annotations

import hashlib
import hmac as _hmac
import secrets
import struct

MAGIC       = 0xAC
VERSION     = 1
HEADER_SIZE = 54  # 1 + 1 + 4 + 16 + 32

# Struct format for the 54-byte request header.
# >  big-endian
# B  magic (1 byte)
# B  version (1 byte)
# I  payload length (4 bytes)
# 16s nonce (16 bytes)
# 32s HMAC (32 bytes)
_HEADER_FMT = ">BB I 16s 32s"

# Struct format for the 5-byte response header.
# B  decision (1 byte)
# I  sanitised length (4 bytes)
_RESP_FMT = ">B I"


class FrameError(Exception):
    """Raised on malformed or unrecognised frame data."""


def signed_message(version: int, length: int, nonce: bytes, payload: bytes) -> bytes:
    """Return the byte string that is the HMAC input.

    Layout: version(1B) || length(4B BE) || nonce(16B) || payload
    Must match SignedMessage() in sidecar/internal/transport/frame.go exactly.
    """
    return struct.pack(">B I 16s", version, length, nonce) + payload


def encode_request(payload: bytes, key: bytes) -> bytes:
    """Encode a signed request frame.

    Generates a fresh 16-byte nonce, computes HMAC-SHA256, and returns
    the complete 54-byte header + payload frame.
    """
    nonce  = secrets.token_bytes(16)
    length = len(payload)
    msg    = signed_message(VERSION, length, nonce, payload)
    mac    = _hmac.new(key, msg, hashlib.sha256).digest()
    header = struct.pack(_HEADER_FMT, MAGIC, VERSION, length, nonce, mac)
    return header + payload


def decode_request(data: bytes) -> dict:
    """Decode a request frame from raw bytes.

    Returns a dict with keys: version, nonce, hmac, payload.
    Raises FrameError on bad magic, bad version, or truncated data.
    Does NOT verify the HMAC — that is the caller's responsibility.
    """
    if len(data) < HEADER_SIZE:
        raise FrameError(
            f"truncated frame: got {len(data)} bytes, need at least {HEADER_SIZE}"
        )

    magic, version, length, nonce, mac = struct.unpack_from(_HEADER_FMT, data, 0)

    if magic != MAGIC:
        raise FrameError(f"bad magic byte: got {magic:#04x}, want {MAGIC:#04x}")
    if version != VERSION:
        raise FrameError(f"unsupported version: {version}")

    end = HEADER_SIZE + length
    if len(data) < end:
        raise FrameError(
            f"truncated payload: got {len(data) - HEADER_SIZE} bytes, want {length}"
        )

    return {
        "version": version,
        "nonce":   nonce,
        "hmac":    mac,
        "payload": data[HEADER_SIZE:end],
    }


def encode_response(decision: int, sanitised: bytes = b"") -> bytes:
    """Encode a response frame.

    decision: 0x00 ALLOW, 0x01 SANITISE, 0x02 BLOCK.
    sanitised: only meaningful on SANITISE; ignored otherwise.
    """
    san_len = len(sanitised) if decision == 0x01 else 0
    header  = struct.pack(_RESP_FMT, decision, san_len)
    return header + sanitised[:san_len]


def decode_response(data: bytes) -> dict:
    """Decode a response frame from raw bytes.

    Returns a dict with keys: decision (int), sanitised_payload (bytes).
    Raises FrameError on truncated data.
    """
    if len(data) < 5:
        raise FrameError(
            f"truncated response: got {len(data)} bytes, need at least 5"
        )

    decision, san_len = struct.unpack_from(_RESP_FMT, data, 0)
    if len(data) < 5 + san_len:
        raise FrameError(
            f"truncated sanitised payload: got {len(data) - 5} bytes, want {san_len}"
        )

    sanitised = data[5 : 5 + san_len] if san_len > 0 else b""

    return {
        "decision":          decision,
        "sanitised_payload": sanitised,
    }
