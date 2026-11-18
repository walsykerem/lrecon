package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestMetaGhidraTimeoutRefuses: a Ghidra run over its budget must be a
// refusal (exit 2, kind=timeout), not a rc=0 result whose only content is an
// "error" field. The op used to answer {error:"timeout",stage:...} and a
// caller could not tell a timeout from a real answer.
func TestMetaGhidraTimeoutRefuses(t *testing.T) {
	dir := t.TempDir()
	slow := filepath.Join(dir, "analyzeHeadless")
	if err := os.WriteFile(slow, []byte("#!/bin/sh\nsleep 30\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LRECON_ANALYZEHEADLESS", slow)
	t.Setenv("LRECON_GHIDRA_CACHE", "off")
	t.Setenv("LRECON_GHIDRA_TIMEOUT", "1s")
	// The kind gate refuses bytecode before Ghidra, so the target has to be a
	// native image.
	pe := buildTarget(t, "windows", "amd64", "meta.exe")

	_, err := metaTestRun(t, "comment", metaTestArg(t, map[string]any{
		"file": pe, "address": "0x1400", "text": "note",
	}))
	if err == nil {
		t.Fatal("a timed out Ghidra run returned a result")
	}
	if got := classify(err.Error()); got != kindTimeout {
		t.Fatalf("classify(%q) = %s, want timeout", err, got)
	}
}
