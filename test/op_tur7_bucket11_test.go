package main

// TUR7 bucket 11: a cold lrecon must not conjure the state it reports on.
//
// The status/xref/call-graph items in this slice answer about a live session or
// an analyzer. With neither present each one has to say so with a classified
// refusal and leave the state tree byte-empty. Repeating every call makes a
// fabricated session or a cached graph observable as a file the op wrote.
// ghidraGate is the gate in front of the route-G items, so the test flips the
// finder absent -> present -> absent on the same target: a gate that always
// allows fails the first half, one that always denies fails the second.

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// tur7B11NoState fails when the isolated state dir gained anything. A session
// that was invented, or a graph cached on the way to a refusal, lands here.
func tur7B11NoState(t *testing.T, dir string, round int) {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("round %d: read state dir: %v", round, err)
	}
	if len(ents) != 0 {
		names := make([]string, len(ents))
		for i, e := range ents {
			names[i] = e.Name()
		}
		t.Fatalf("round %d: cold op wrote state %v into an empty state dir", round, names)
	}
}

func TestTur7Bucket11ColdSessionNoState(t *testing.T) {
	fixture := filepath.Join("testdata", "fixtures", "macho")
	if d, err := Probe(fixture); err != nil || !ghidraNativeKinds[d.Kind] {
		t.Fatalf("fixture %s is not a native kind (%q, %v)", fixture, d.Kind, err)
	}

	state := t.TempDir()
	t.Setenv("LRECON_STATE", state)
	t.Setenv("LRECON_SESSION", "")
	t.Setenv("LRECON_NAME", "_main")
	if got, want := sessionPath(), filepath.Join(state, "session.json"); got != want {
		t.Fatalf("sessionPath() = %q, want %q", got, want)
	}

	old := ghidraFinder
	t.Cleanup(func() { ghidraFinder = old })
	absent := func() (string, string, error) { return "", "", errors.New("no ghidra in this test") }
	ghidraFinder = absent

	const coldSays = "no session: no document has been opened yet"
	for round := 0; round < 3; round++ {
		// The session reader: no cursor, no answer.
		_, err := runOp("get_navigation_context", "")
		if err == nil {
			t.Fatalf("round %d: cold get_navigation_context answered instead of refusing", round)
		}
		if !strings.Contains(err.Error(), coldSays) {
			t.Fatalf("round %d: get_navigation_context error = %q, want %q", round, err, coldSays)
		}
		if k := classify(err.Error()); k != kindNoEngine {
			t.Fatalf("round %d: get_navigation_context kind = %s, want %s", round, k, kindNoEngine)
		}

		// The analyzer readers: the tool is missing, so they refuse by name
		// instead of returning an empty graph or an empty xref list.
		for _, name := range []string{"get_call_graph", "find_xrefs_to_name"} {
			res, err := runOp(name, fixture)
			if err != nil {
				t.Fatalf("round %d: %s: %v", round, name, err)
			}
			s, ok := res.(*skip)
			if !ok {
				t.Fatalf("round %d: %s returned %T, want a missing-engine skip", round, name, res)
			}
			if !strings.Contains(s.Reason, "ghidra analyzeHeadless not installed") {
				t.Fatalf("round %d: %s skip = %q, want the missing-engine reason", round, name, s.Reason)
			}
			if k := classify(s.Reason); k != kindNoEngine {
				t.Fatalf("round %d: %s kind = %s, want %s", round, name, k, kindNoEngine)
			}
		}

		tur7B11NoState(t, state, round)
	}

	// The gate itself must gate: refuse with no finder, allow with one, refuse
	// again when it goes away — same target every time.
	if s := ghidraGate(fixture); s == nil || !strings.Contains(s.Reason, "ghidra") {
		t.Fatalf("gate with the finder absent = %v, want a ghidra refusal", s)
	}
	ghidraFinder = func() (string, string, error) { return "/fake/analyzeHeadless", "12.0", nil }
	if s := ghidraGate(fixture); s != nil {
		t.Fatalf("gate with the finder present = %q, want allow (nil)", s.Reason)
	}
	ghidraFinder = absent
	if s := ghidraGate(fixture); s == nil {
		t.Fatal("gate allowed the same target after the finder disappeared: it does not gate")
	}
	tur7B11NoState(t, state, -1)
}
