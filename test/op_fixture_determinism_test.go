package main

// The pcap fixture is committed bytes, and the contract tests read it as if it
// were wire capture. If make.py drifted from the committed file, every TLS/DNS
// assertion would describe a capture nobody can regenerate. This re-runs the
// generator in a temp dir and compares the bytes.

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestFixturePcapRegeneratesByteForByte(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not installed: the fixture generator cannot be re-run here")
	}
	script, err := filepath.Abs(filepath.Join("testdata", "fixtures", "pcap", "make.py"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	cmd := exec.Command(python, script) // make.py writes ./fixture.pcap in its CWD
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("make.py: %v\n%s", err, out)
	}
	want, err := os.ReadFile(filepath.Join("testdata", "fixtures", "pcap", "fixture.pcap"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "fixture.pcap"))
	if err != nil {
		t.Fatalf("make.py wrote no fixture.pcap: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("make.py output differs from the committed fixture: committed %d bytes sha256 %x, regenerated %d bytes sha256 %x",
			len(want), sha256.Sum256(want), len(got), sha256.Sum256(got))
	}
	if len(want) != 513 {
		t.Fatalf("fixture.pcap is %s: %s", "not the 513-byte 4-packet capture the generator writes", fmt.Sprint(len(want)))
	}
}
