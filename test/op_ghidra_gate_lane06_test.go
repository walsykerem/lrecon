package main

// LANE06: ghidraGate is the pre-resolution guard used by ops that resolve an
// address/name/job before ghidraOp. Its order is the contract: a missing target
// owes io first, a managed kind owes the kind refusal before the tool claim,
// and a native target with no finder owes the missing-engine skip.

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGhidraGateOrderOfAnswers(t *testing.T) {
	failGhidra(t) // any finder call on a managed/missing case is a test failure
	// 1. Missing target: io first, nil gate answer.
	if s := ghidraGate(filepath.Join(t.TempDir(), "missing.bin")); s != nil {
		t.Fatalf("missing target gate = %q, want nil (io is the op's answer)", s.Reason)
	}
	// 2. Managed kind: refuse the kind, never consult the finder.
	managed := buildCLIPE(t, true)
	if s := ghidraGate(managed); s == nil || !strings.Contains(s.Reason, "pe-dotnet") {
		t.Fatalf("managed kind gate = %v, want pe-dotnet refusal", s)
	}
}

func TestGhidraGateNativeNeedsEngine(t *testing.T) {
	native := "/bin/ls"
	if d, err := Probe(native); err != nil || !ghidraNativeKinds[d.Kind] {
		t.Skipf("/bin/ls not native here (%q, %v)", d.Kind, err)
	}
	old := ghidraFinder
	t.Cleanup(func() { ghidraFinder = old })
	called := false
	ghidraFinder = func() (string, string, error) {
		called = true
		return "", "", errors.New("absent in this test")
	}
	s := ghidraGate(native)
	if s == nil || !strings.Contains(s.Reason, "ghidra") {
		t.Fatalf("native gate = %v, want missing-engine skip", s)
	}
	if !called {
		t.Fatal("finder not consulted for a native target")
	}
}

func TestGhidraGateTargetFromJob(t *testing.T) {
	failGhidra(t)
	managed := buildCLIPE(t, true)
	jobPath := filepath.Join(t.TempDir(), "job.json")
	job, _ := json.Marshal(map[string]any{"file": managed, "name": "probe"})
	if err := os.WriteFile(jobPath, job, 0o644); err != nil {
		t.Fatal(err)
	}
	got := ghidraGateTarget(jobPath)
	if got != managed {
		t.Fatalf("gate target = %q, want job.file %q", got, managed)
	}
	// A plain binary is its own target.
	if got := ghidraGateTarget(managed); got != managed {
		t.Fatalf("managed target = %q", got)
	}
}
