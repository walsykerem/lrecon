package main

// The managed guard lives in ghidraOp and metaGhidraOp, so it covers all 39
// route-G items, not only decompile_all. One representative per runner, and a
// native target must still reach the tool.

import (
	"errors"
	"strings"
	"testing"
)

func TestGhidraGuardCoversSiblings(t *testing.T) {
	failGhidra(t)
	managed := buildCLIPE(t, true)
	for _, opName := range []string{"list_procedures", "list_unknowns"} {
		t.Run(opName, func(t *testing.T) {
			res, err := runOp(opName, managed)
			if err != nil {
				t.Fatalf("%s on a managed assembly returned an error: %v", opName, err)
			}
			s, ok := res.(*skip)
			if !ok {
				t.Fatalf("%s returned %T, want a skip naming the kind", opName, res)
			}
			if !strings.Contains(s.Reason, "pe-dotnet") {
				t.Fatalf("%s skip does not name the kind: %q", opName, s.Reason)
			}
		})
	}
}

func TestGhidraGuardLeavesNative(t *testing.T) {
	d, err := Probe("/bin/ls")
	if err != nil || !ghidraNativeKinds[d.Kind] {
		t.Skipf("/bin/ls is not a native kind here (%q, %v)", d.Kind, err)
	}
	called := false
	old := ghidraFinder
	t.Cleanup(func() { ghidraFinder = old })
	ghidraFinder = func() (string, string, error) {
		called = true
		return "", "", errors.New("absent in this test")
	}
	res, err := runOp("list_procedures", "/bin/ls")
	if err != nil {
		t.Fatalf("native target: %v", err)
	}
	s, ok := res.(*skip)
	if !ok || !strings.Contains(s.Reason, "ghidra") {
		t.Fatalf("native target did not reach the tool: %T %v", res, res)
	}
	if !called {
		t.Fatal("the finder was never consulted for a native target")
	}
}
