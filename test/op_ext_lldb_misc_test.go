package main

import (
	"errors"
	"os"
	"strings"
	"testing"
)

func TestLldbLaunchFailureLine(t *testing.T) {
	cases := []struct{ in, want string }{
		{"error: '/tmp/go.mod' is not a valid executable", "'/tmp/go.mod' is not a valid executable"},
		{"(lldb) process launch --stop-at-entry\nerror: process launch failed: unable to locate", "process launch failed: unable to locate"},
		{"Process 1 launched\n* thread #1: tid = 0x1", ""},
	}
	for _, c := range cases {
		if got := lldbLaunchFailureLine(c.in); got != c.want {
			t.Fatalf("lldbLaunchFailureLine(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestLldbNoProcessKeepsMessage: a batch lldb dialog has no inferior, and the
// one sentence lldb gives for that is an answer. The item must say which
// engine is missing (no_engine) and keep lldb's own words, plus the note that
// explains why this run cannot have a process.
func TestLldbNoProcessKeepsMessage(t *testing.T) {
	dir := t.TempDir()
	fake := dir + "/lldb"
	script := "#!/bin/sh\necho 'error: Command requires a current process.' >&2\nexit 1\n"
	if err := os.WriteFile(fake, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)

	_, err := lldbRun([]string{"register read"}, "/bin/ls", kindBadArg)
	var ref *extRefusal
	if !errors.As(err, &ref) {
		t.Fatalf("lldbRun error = %v, want an extRefusal", err)
	}
	if ref.kind != kindNoEngine {
		t.Fatalf("kind = %q, want %q", ref.kind, kindNoEngine)
	}
	if !strings.Contains(ref.msg, "Command requires a current process.") {
		t.Fatalf("message lost lldb's sentence: %q", ref.msg)
	}
	if !strings.Contains(ref.msg, "no inferior exists") {
		t.Fatalf("message lost the no-inferior note: %q", ref.msg)
	}
}
