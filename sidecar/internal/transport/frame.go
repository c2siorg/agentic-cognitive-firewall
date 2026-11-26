// Package transport handles the UDS accept loop and binary frame encoding/decoding.
//
// Request frame layout (54-byte header + variable payload):
//
//	[0]      magic     — 0xAC, fast-reject misaddressed connections
//	[1]      version   — current: 1
//	[2:6]    length    — uint32 big-endian, length of JSON payload
//	[6:22]   nonce     — 16 random bytes, per-request replay protection
//	[22:54]  hmac      — 32 bytes, HMAC-SHA256 over SignedMessage(version+length+nonce+payload)
//	[54:]    payload   — JSON-serialised RiskContext
//
// Response frame layout:
//
//	[0]      decision  — 0x00 ALLOW · 0x01 SANITISE · 0x02 BLOCK
//	[1:5]    san_len   — uint32 big-endian (0 if empty)
//	[5:]     payload   — JSON bytes (SANITISE: sanitised payload; BLOCK: BlockPayload)
package transport

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"

	"github.com/acf-sdk/sidecar/internal/crypto"
	"github.com/acf-sdk/sidecar/pkg/decision"
)

const (
	// MagicByte is the first byte of every request frame.
	MagicByte = byte(0xAC)
	// VersionByte is the current protocol version.
	VersionByte = byte(0x01)
	// HeaderSize is the fixed size of the request frame header in bytes.
	HeaderSize = 54 // 1 + 1 + 4 + 16 + 32

	// DecisionAllow is the response byte for an ALLOW decision.
	DecisionAllow = decision.Allow
	// DecisionSanitise is the response byte for a SANITISE decision.
	DecisionSanitise = decision.Sanitise
	// DecisionBlock is the response byte for a BLOCK decision.
	DecisionBlock = decision.Block
)

// Sentinel errors returned by frame decode functions.
var (
	ErrBadMagic    = errors.New("transport: bad magic byte")
	ErrBadVersion  = errors.New("transport: unsupported protocol version")
	ErrBadHMAC     = errors.New("transport: HMAC verification failed")
	ErrReplayNonce = errors.New("transport: nonce replay detected")
)

// RequestFrame holds the decoded fields of an inbound request frame.
// HMAC and nonce verification is the caller's responsibility.
type RequestFrame struct {
	Version byte
	Nonce   [16]byte
	HMAC    [32]byte
	Payload []byte
}

// ResponseFrame holds the fields of an outbound response frame.
type ResponseFrame struct {
	Decision         byte
	SanitisedPayload []byte
}

// SignedMessage returns the byte slice that is the HMAC input:
//
//	version(1B) || length(4B big-endian) || nonce(16B) || payload
//
// Both the encoder and the verifier must call this to ensure they sign
// and verify the same bytes.
func SignedMessage(version byte, length uint32, nonce [16]byte, payload []byte) []byte {
	buf := make([]byte, 1+4+16+len(payload))
	buf[0] = version
	binary.BigEndian.PutUint32(buf[1:5], length)
	copy(buf[5:21], nonce[:])
	copy(buf[21:], payload)
	return buf
}

// EncodeRequest encodes a signed request frame from a raw JSON payload.
// It generates a fresh 16-byte nonce, computes the HMAC, and returns
// the complete frame bytes (54-byte header + payload).
func EncodeRequest(payload []byte, s *crypto.Signer) ([]byte, error) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}

	length := uint32(len(payload))
	msg := SignedMessage(VersionByte, length, nonce, payload)
	mac := s.Sign(msg)

	frame := make([]byte, HeaderSize+len(payload))
	frame[0] = MagicByte
	frame[1] = VersionByte
	binary.BigEndian.PutUint32(frame[2:6], length)
	copy(frame[6:22], nonce[:])
	copy(frame[22:54], mac)
	copy(frame[54:], payload)
	return frame, nil
}

// DecodeRequest reads exactly one request frame from r.
// Returns ErrBadMagic or ErrBadVersion on a malformed header.
// HMAC and nonce verification are left to the caller.
func DecodeRequest(r io.Reader) (*RequestFrame, error) {
	header := make([]byte, HeaderSize)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}

	if header[0] != MagicByte {
		return nil, ErrBadMagic
	}
	if header[1] != VersionByte {
		return nil, ErrBadVersion
	}

	length := binary.BigEndian.Uint32(header[2:6])
	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}

	rf := &RequestFrame{
		Version: header[1],
		Payload: payload,
	}
	copy(rf.Nonce[:], header[6:22])
	copy(rf.HMAC[:], header[22:54])
	return rf, nil
}

// EncodeResponse encodes a response frame to a byte slice.
func EncodeResponse(resp *ResponseFrame) []byte {
	sanLen := uint32(len(resp.SanitisedPayload))
	buf := make([]byte, 5+len(resp.SanitisedPayload))
	buf[0] = resp.Decision
	binary.BigEndian.PutUint32(buf[1:5], sanLen)
	if sanLen > 0 {
		copy(buf[5:], resp.SanitisedPayload)
	}
	return buf
}

// DecodeResponse reads exactly one response frame from r.
func DecodeResponse(r io.Reader) (*ResponseFrame, error) {
	header := make([]byte, 5)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}

	decision := header[0]
	sanLen := binary.BigEndian.Uint32(header[1:5])

	var sanitised []byte
	if sanLen > 0 {
		sanitised = make([]byte, sanLen)
		if _, err := io.ReadFull(r, sanitised); err != nil {
			return nil, err
		}
	}

	return &ResponseFrame{
		Decision:         decision,
		SanitisedPayload: sanitised,
	}, nil
}
