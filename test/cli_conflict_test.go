package main

import (
	"os"
	"strings"
	"testing"
)

// Two flags that answer different questions cannot be one call: lrecon used to
// keep one and drop the other in silence, so the caller never learned that
// half of the command line was ignored.
func TestCLIRefusesConflictingFlags(t *testing.T) {
	target := writeTemp(t, "conflict.txt", []byte("hello lrecon\n"))
	cases := []struct {
		name string
		args []string
		want []string
	}{
		{"op and ext-op", []string{"--op", "list_strings", "--ext-op", "ghidra_prescript", target}, []string{"--op", "--ext-op"}},
		{"list-ops and list-ext-ops", []string{"--list-ops", "--list-ext-ops"}, []string{"--list-ops", "--list-ext-ops"}},
		{"op twice", []string{"--op", "list_strings", "--op", "trace_dylib_resolution", target}, []string{"--op"}},
		{"negative pid", []string{"--pid", "-1", target}, []string{"--pid"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, stderr, code := runCLIAll(t, c.args...)
			if code != 2 {
				t.Fatalf("exit %d, want 2; stderr:\n%s", code, stderr)
			}
			for _, w := range c.want {
				if !strings.Contains(stderr, w) {
					t.Fatalf("stderr does not name %s:\n%s", w, stderr)
				}
			}
		})
	}
}

// --max-bytes is a text budget, and an op answer is machine output: the flag
// must not refuse the call and must not cut the answer either. It only says
// on stderr that it had no effect.
func TestCLIMaxBytesWithOpNotesInsteadOfCutting(t *testing.T) {
	if _, err := os.Stat(lsPath); err != nil {
		t.Skipf("no native fixture: %v", err)
	}
	out, stderr, code := runCLIAll(t, "--max-bytes", "10", "--op", "list_strings", lsPath)
	if code != 0 {
		t.Fatalf("exit %d, want 0; stderr:\n%s", code, stderr)
	}
	if !strings.Contains(out, "list_strings") {
		t.Fatalf("op answer does not name the op:\n%s", out)
	}
	if !strings.Contains(stderr, "--max-bytes 10 does not apply to --op") {
		t.Fatalf("stderr does not carry the note:\n%s", stderr)
	}
}

// Without the flag there is nothing to report: the default budget must stay
// quiet.
func TestCLIMaxBytesNoteOnlyWhenFlagGiven(t *testing.T) {
	if _, err := os.Stat(lsPath); err != nil {
		t.Skipf("no native fixture: %v", err)
	}
	_, stderr, code := runCLIAll(t, "--op", "list_strings", lsPath)
	if code != 0 {
		t.Fatalf("exit %d, want 0; stderr:\n%s", code, stderr)
	}
	if strings.Contains(stderr, "--max-bytes") {
		t.Fatalf("stderr mentions --max-bytes without the flag:\n%s", stderr)
	}
}

// One --op still answers: refusing the conflicts must not break the one shape
// that has always worked.
func TestCLISingleOpStillRuns(t *testing.T) {
	if _, err := os.Stat(lsPath); err != nil {
		t.Skipf("no native fixture: %v", err)
	}
	out, code := runCLI(t, "--op", "list_strings", lsPath)
	if code != 0 {
		t.Fatalf("exit %d, want 0; output:\n%s", code, out)
	}
	if !strings.Contains(out, "list_strings") {
		t.Fatalf("op answer does not name the op:\n%s", out)
	}
}
