package main

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// issue7FakeLldb puts an executable lldb shim on PATH so the misc LLDB items
// can be driven without a real debugger.
func issue7FakeLldb(t *testing.T, body string) {
	t.Helper()
	dir := t.TempDir()
	script := "#!/bin/sh\n" + body + "\n"
	if err := os.WriteFile(filepath.Join(dir, "lldb"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+":/bin:/usr/bin")
}

func issue7Target(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(p, []byte("MZ"), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func issue7Refusal(t *testing.T, err error, want errorKind) *extRefusal {
	t.Helper()
	var ref *extRefusal
	if !errors.As(err, &ref) {
		t.Fatalf("error = %v, want an extRefusal", err)
	}
	if ref.kind != want {
		t.Fatalf("kind = %s, want %s: %v", ref.kind, want, err)
	}
	return ref
}

// The 13 misc LLDB items had no fake-tool test at all. Each one is one batch
// dialog, so the exact command is the contract: a typo there is a different
// lldb command, not a formatting detail.
func TestIssue7LldbMiscOpsFakeTool(t *testing.T) {
	target := issue7Target(t)
	issue7FakeLldb(t, `printf 'ran:%s\n' "$*"`)

	live := func(cmd string) []string {
		return []string{"process launch --stop-at-entry", cmd, "process kill", target}
	}
	cases := []struct {
		name string
		run  func(string, []string) (any, error)
		args []string
		want []string
	}{
		{"disassemble", runLldbDisassemble, []string{"main"}, []string{"disassemble -n main", target}},
		{"disassemble_default", runLldbDisassemble, nil, []string{"disassemble -n main", target}},
		{"breakpoint_set", runLldbBreakpointSet, []string{"other"}, []string{"breakpoint set -n other", target}},
		{"breakpoint_set_default", runLldbBreakpointSet, nil, []string{"breakpoint set -n main", target}},
		{"breakpoint_list", runLldbBreakpointList, nil, []string{"breakpoint list", target}},
		{"breakpoint_delete", runLldbBreakpointDelete, []string{"3"}, []string{"breakpoint delete 3", target}},
		{"breakpoint_delete_default", runLldbBreakpointDelete, nil, []string{"breakpoint delete 1", target}},
		{"watchpoint", runLldbWatchpoint, []string{"0x1000"}, []string{"watchpoint set expression 0x1000", target}},
		{"watchpoint_default", runLldbWatchpoint, nil, []string{"watchpoint set expression 0", target}},
		{"image_lookup", runLldbImageLookup, []string{"puts"}, []string{"image lookup -n puts", target}},
		{"image_lookup_default", runLldbImageLookup, nil, []string{"image lookup -n main", target}},
		{"source_list", runLldbSourceList, []string{"42"}, []string{"source list -l 42", target}},
		{"source_list_default", runLldbSourceList, nil, []string{"source list -l 1", target}},
		{"frame_variable", runLldbFrameVariable, nil, []string{"frame variable", target}},
		{"thread_backtrace", runLldbThreadBacktrace, nil, live("thread backtrace")},
		{"diagnostics", runLldbDiagnostics, nil, []string{"diagnostics dump", target}},
		{"thread_list_full", runLldbThreadListFull, nil, live("thread list")},
		{"image_list_full", runLldbImageListFull, nil, []string{"image list", target}},
		{"target_list_full", runLldbTargetListFull, nil, []string{"target list", target}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v, err := c.run(target, c.args)
			if err != nil {
				t.Fatalf("%s: %v", c.name, err)
			}
			out, ok := v.(extOut)
			if !ok || out.Tool != "lldb" {
				t.Fatalf("%s = %T, want an lldb extOut", c.name, v)
			}
			if !slices.Equal(out.Args, c.want) {
				t.Fatalf("%s args = %v, want %v", c.name, out.Args, c.want)
			}
			if !strings.Contains(out.Output, "ran:") {
				t.Fatalf("%s lost the fake lldb output: %q", c.name, out.Output)
			}
		})
	}
}

func issue7MiscOps() []struct {
	name string
	run  func(string, []string) (any, error)
} {
	return []struct {
		name string
		run  func(string, []string) (any, error)
	}{
		{"disassemble", runLldbDisassemble},
		{"breakpoint_set", runLldbBreakpointSet},
		{"breakpoint_list", runLldbBreakpointList},
		{"breakpoint_delete", runLldbBreakpointDelete},
		{"watchpoint", runLldbWatchpoint},
		{"image_lookup", runLldbImageLookup},
		{"source_list", runLldbSourceList},
		{"frame_variable", runLldbFrameVariable},
		{"thread_backtrace", runLldbThreadBacktrace},
		{"diagnostics", runLldbDiagnostics},
		{"thread_list_full", runLldbThreadListFull},
		{"image_list_full", runLldbImageListFull},
		{"target_list_full", runLldbTargetListFull},
	}
}

func TestIssue7LldbMiscOpsMissingTargetIsIO(t *testing.T) {
	issue7FakeLldb(t, `printf 'must not run\n'`)
	for _, c := range issue7MiscOps() {
		t.Run(c.name, func(t *testing.T) {
			_, err := c.run("/nonexistent-issue7-target", nil)
			issue7Refusal(t, err, kindIO)
		})
	}
}

func TestIssue7LldbMiscOpsMissingToolIsNoEngine(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	target := issue7Target(t)
	for _, c := range issue7MiscOps() {
		t.Run(c.name, func(t *testing.T) {
			_, err := c.run(target, nil)
			issue7Refusal(t, err, kindNoEngine)
		})
	}
}

// A batch dialog has no inferior. lldb exits 1 with that one sentence; the item
// must answer no_engine with lldb's words and the note, not invent output.
func TestIssue7LldbMiscOpsNoProcessIsNoEngine(t *testing.T) {
	issue7FakeLldb(t, `printf '%s\n' 'error: Command requires a current process.' >&2; exit 1`)
	target := issue7Target(t)
	for _, c := range issue7MiscOps() {
		t.Run(c.name, func(t *testing.T) {
			_, err := c.run(target, nil)
			ref := issue7Refusal(t, err, kindNoEngine)
			if !strings.Contains(ref.msg, "Command requires a current process.") || !strings.Contains(ref.msg, "note:") {
				t.Fatalf("no-process refusal lost its message: %q", ref.msg)
			}
		})
	}
}

// lldb exits 0 when the target is not runnable; the transcript is the only
// clue, and a live item must turn it into bad_arg instead of reporting a run.
func TestIssue7LldbMiscOpsLaunchFailureIsBadArg(t *testing.T) {
	issue7FakeLldb(t, `printf '%s\n' "error: 'target' is not a valid executable"`)
	target := issue7Target(t)
	for _, c := range []struct {
		name string
		run  func(string, []string) (any, error)
	}{
		{"thread_backtrace", runLldbThreadBacktrace},
		{"thread_list_full", runLldbThreadListFull},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := c.run(target, nil)
			ref := issue7Refusal(t, err, kindBadArg)
			if !strings.Contains(ref.msg, "is not a valid executable") {
				t.Fatalf("launch refusal lost lldb's line: %q", ref.msg)
			}
		})
	}
}
