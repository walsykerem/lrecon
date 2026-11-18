package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// A file shorter than one read block with no sentinel used to seek back by the
// sentinel length and re-read the same tail forever.
func TestFuseWireShortFileWithoutSentinel(t *testing.T) {
	p := filepath.Join(t.TempDir(), "plain.bin")
	if err := os.WriteFile(p, bytes.Repeat([]byte{0xAA}, 512), 0o644); err != nil {
		t.Fatal(err)
	}
	off, w, err := fuseWire(p)
	if err != nil {
		t.Fatalf("fuseWire: %v", err)
	}
	if w != nil || off != 0 {
		t.Fatalf("got off=%d wire=%v, want no wire", off, w)
	}
}

// The sentinel straddling a block boundary must still be found, at its real
// offset, with the wire bytes that follow it.
func TestFuseWireSentinelAcrossBlockBoundary(t *testing.T) {
	const block = 8 << 20
	sent := []byte(fuseSentinel)
	wire := []byte{3, 2, '1', '0'}
	data := make([]byte, block+len(sent)+len(wire))
	// Start the sentinel so its tail falls into the second block.
	at := block - len(sent)/2
	copy(data[at:], sent)
	copy(data[at+len(sent):], wire)

	p := filepath.Join(t.TempDir(), "electron.bin")
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
	off, got, err := fuseWire(p)
	if err != nil {
		t.Fatalf("fuseWire: %v", err)
	}
	if off != int64(at) {
		t.Fatalf("offset = %d, want %d", off, at)
	}
	if !bytes.HasPrefix(got, wire) {
		t.Fatalf("wire bytes = %v, want prefix %v", got, wire)
	}
}
