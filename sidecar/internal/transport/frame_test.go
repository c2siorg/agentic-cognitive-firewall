package transport

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/acf-sdk/sidecar/internal/crypto"
)

func testSigner(t *testing.T) *crypto.Signer {
	t.Helper()
	s, err := crypto.NewSigner([]byte("test-key-32-bytes-long-padded!!!"))
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	return s
}

func TestEncodeRequest_Header(t *testing.T) {
	s := testSigner(t)
	payload := []byte(`{"hook_type":"on_prompt"}`)

	frame, err := EncodeRequest(payload, s)
	if err != nil {
		t.Fatalf("EncodeRequest: %v", err)
	}

	if frame[0] != MagicByte {
		t.Errorf("magic byte: got %#x, want %#x", frame[0], MagicByte)
	}
	if frame[1] != VersionByte {
		t.Errorf("version byte: got %#x, want %#x", frame[1], VersionByte)
	}

	gotLen := binary.BigEndian.Uint32(frame[2:6])
	if gotLen != uint32(len(payload)) {
		t.Errorf("length field: got %d, want %d", gotLen, len(payload))
	}
}

func TestEncodeRequest_NonceUnique(t *testing.T) {
	s := testSigner(t)
	payload := []byte(`{"hook_type":"on_prompt"}`)

	f1, _ := EncodeRequest(payload, s)
	f2, _ := EncodeRequest(payload, s)

	if bytes.Equal(f1[6:22], f2[6:22]) {
		t.Error("two frames have identical nonces — nonce generation is not random")
	}
}

func TestDecodeRequest_RoundTrip(t *testing.T) {
	s := testSigner(t)
	payload := []byte(`{"hook_type":"on_prompt","payload":"hello"}`)

	frame, err := EncodeRequest(payload, s)
	if err != nil {
		t.Fatalf("EncodeRequest: %v", err)
	}

	rf, err := DecodeRequest(bytes.NewReader(frame))
	if err != nil {
		t.Fatalf("DecodeRequest: %v", err)
	}

	if !bytes.Equal(rf.Payload, payload) {
		t.Errorf("payload mismatch: got %q, want %q", rf.Payload, payload)
	}
	if rf.Version != VersionByte {
		t.Errorf("version: got %d, want %d", rf.Version, VersionByte)
	}
}

func TestDecodeRequest_BadMagic(t *testing.T) {
	s := testSigner(t)
	frame, _ := EncodeRequest([]byte(`{}`), s)
	frame[0] = 0xFF

	_, err := DecodeRequest(bytes.NewReader(frame))
	if err != ErrBadMagic {
		t.Errorf("expected ErrBadMagic, got %v", err)
	}
}

func TestDecodeRequest_BadVersion(t *testing.T) {
	s := testSigner(t)
	frame, _ := EncodeRequest([]byte(`{}`), s)
	frame[1] = 0x02

	_, err := DecodeRequest(bytes.NewReader(frame))
	if err != ErrBadVersion {
		t.Errorf("expected ErrBadVersion, got %v", err)
	}
}

func TestDecodeRequest_Truncated(t *testing.T) {
	_, err := DecodeRequest(bytes.NewReader([]byte{0xAC, 0x01, 0x00}))
	if err == nil {
		t.Error("expected error for truncated frame, got nil")
	}
}

func TestEncodeResponse_Allow(t *testing.T) {
	resp := &ResponseFrame{Decision: DecisionAllow}
	buf := EncodeResponse(resp)

	if buf[0] != DecisionAllow {
		t.Errorf("decision: got %#x, want %#x", buf[0], DecisionAllow)
	}
	sanLen := binary.BigEndian.Uint32(buf[1:5])
	if sanLen != 0 {
		t.Errorf("sanitised length: got %d, want 0", sanLen)
	}
	if len(buf) != 5 {
		t.Errorf("response length: got %d, want 5", len(buf))
	}
}

func TestEncodeResponse_Sanitise(t *testing.T) {
	sanitised := []byte(`{"safe":"content"}`)
	resp := &ResponseFrame{Decision: DecisionSanitise, SanitisedPayload: sanitised}
	buf := EncodeResponse(resp)

	if buf[0] != DecisionSanitise {
		t.Errorf("decision: got %#x, want %#x", buf[0], DecisionSanitise)
	}
	if len(buf) != 5+len(sanitised) {
		t.Errorf("total length: got %d, want %d", len(buf), 5+len(sanitised))
	}
}

func TestDecodeResponse_All(t *testing.T) {
	cases := []struct {
		name     string
		decision byte
		san      []byte
	}{
		{"allow", DecisionAllow, nil},
		{"block", DecisionBlock, nil},
		{"block with payload", DecisionBlock, []byte(`{"confirmable":true}`)},
		{"sanitise", DecisionSanitise, []byte("safe content")},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			encoded := EncodeResponse(&ResponseFrame{Decision: tc.decision, SanitisedPayload: tc.san})
			decoded, err := DecodeResponse(bytes.NewReader(encoded))
			if err != nil {
				t.Fatalf("DecodeResponse: %v", err)
			}
			if decoded.Decision != tc.decision {
				t.Errorf("decision: got %#x, want %#x", decoded.Decision, tc.decision)
			}
			if !bytes.Equal(decoded.SanitisedPayload, tc.san) {
				t.Errorf("sanitised payload: got %q, want %q", decoded.SanitisedPayload, tc.san)
			}
		})
	}
}

func TestSignedMessage_Composition(t *testing.T) {
	nonce := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	payload := []byte("test payload")
	length := uint32(len(payload))

	msg := SignedMessage(VersionByte, length, nonce, payload)

	if msg[0] != VersionByte {
		t.Errorf("version at [0]: got %#x", msg[0])
	}
	gotLen := binary.BigEndian.Uint32(msg[1:5])
	if gotLen != length {
		t.Errorf("length at [1:5]: got %d, want %d", gotLen, length)
	}
	if !bytes.Equal(msg[5:21], nonce[:]) {
		t.Error("nonce at [5:21] does not match")
	}
	if !bytes.Equal(msg[21:], payload) {
		t.Error("payload at [21:] does not match")
	}
}
