package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A sidecar is untrusted input: core:dataset must not name a file outside the
// meta's directory, or a downloaded capture could read anything on the host.
func TestSignalDatasetPathStaysInDir(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "secret.bin")
	if err := os.WriteFile(secret, make([]byte, 16), 0o644); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(dir, "cap")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	meta := `{"global":{"core:datatype":"cf32_le","core:sample_rate":1000,"core:dataset":"../secret.bin"}}`
	mp := filepath.Join(sub, "a.sigmf-meta")
	if err := os.WriteFile(mp, []byte(meta), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := decodeSignalRecording(mp); err == nil || !strings.Contains(err.Error(), "escapes") {
		t.Fatalf("relative escape: got %v, want escapes error", err)
	}

	meta = `{"global":{"core:datatype":"cf32_le","core:sample_rate":1000,"core:dataset":"` + secret + `"}}`
	if err := os.WriteFile(mp, []byte(meta), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := decodeSignalRecording(mp); err == nil || !strings.Contains(err.Error(), "must be relative") {
		t.Fatalf("absolute path: got %v, want relative-only error", err)
	}
}

// A cancelled archive walk stops instead of writing every member.
func TestExtractAllCtxCancel(t *testing.T) {
	src := writeZip(t, "a.zip", []zipEntry{{"a.txt", []byte("a")}, {"b.txt", []byte("b")}})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := ExtractAllCtx(ctx, src, t.TempDir(), &Digest{})
	if err == nil || !strings.Contains(err.Error(), "context canceled") {
		t.Fatalf("got %v, want context canceled", err)
	}
}
