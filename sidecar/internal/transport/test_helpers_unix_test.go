//go:build !windows

package transport

import (
	"os"
	"path/filepath"
	"testing"
)

// testAddress returns a platform-appropriate temporary IPC address.
// On Linux/macOS this is a UDS socket file in a short temporary directory.
// We avoid t.TempDir() because on macOS (Darwin) sockaddr_un.sun_path is limited
// to 104 bytes, and t.TempDir() embeds full test names that easily exceed this limit.
func testAddress(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "acf")
	if err != nil {
		t.Fatalf("failed to create temp dir for test socket: %v", err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(dir)
	})
	return filepath.Join(dir, "acf.sock")
}

func TestAddress_SunPathLimit(t *testing.T) {
	addr := testAddress(t)
	// Darwin sun_path is 104 bytes including null terminator; Linux is 108.
	const darwinMaxLen = 103
	if len(addr) > darwinMaxLen {
		t.Errorf("testAddress returned path of length %d (%q), exceeds Darwin sun_path limit of %d", len(addr), addr, darwinMaxLen)
	}
}
