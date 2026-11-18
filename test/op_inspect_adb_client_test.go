package main

import (
	"os"
	"path/filepath"
	"testing"
)

// a07FakeTool writes an executable stub so an op that spawns a host tool can be
// exercised offline: the fake is the only "adb"/"apktool" on PATH.
func a07FakeTool(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatalf("write fake %s: %v", name, err)
	}
}

// A tool that prints something other than a version line is a tool the op could
// not use, not an lrecon fault: the envelope has to say no_engine, not internal.
func TestInspectADBClientUnusableVersionIsNoEngine(t *testing.T) {
	dir := t.TempDir()
	a07FakeTool(t, dir, "adb", "echo 'surprise output, no version line'")
	t.Setenv("PATH", dir)

	_, err := ops["inspect_adb_client"].run("/bin/true")
	if err == nil {
		t.Fatal("a junk `adb version` must refuse, not report a client")
	}
	if got := classify(err.Error()); got != kindNoEngine {
		t.Fatalf("kind = %s, want %s: %v", got, kindNoEngine, err)
	}
}
