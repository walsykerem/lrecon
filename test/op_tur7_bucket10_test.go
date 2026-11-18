package main

// Tur 7 bucket 10 — external-tool gating is real, not phrase matching.
//
// One op, two PATHs, two verdicts. With the tool absent the op answers a typed
// no_engine refusal that names the missing tool; with a stub on PATH the same
// op answers with the stub's own bytes, so the answer is the tool's output and
// not lrecon's synthesis. The answer has to track the bytes: a second stub with
// different bytes must move it. A stub that runs and exits 1 must surface that
// exit as the op's refusal, and one absent tool must refuse even when the other
// ext tools are on PATH.

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	b10AdbOut     = "List of devices attached\n0011223344 tcp:8080 tcp:9090"
	b10AdbOut2    = "List of devices attached\nffeeddcc tcp:7000 tcp:7100"
	b10ApktoolOut = "bucket10 apktool frameworks: 1.apk"
	b10JadxOut    = "bucket10 jadx plugin: custom"
	b10LldbOut    = "rax = 0x0000000000000b10"
	b10GhidraOut  = "bucket10 analyzeHeadless: import done"
)

// b10Quote single-quotes one shell word.
func b10Quote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// b10Stub writes one /bin/sh shim. The stub is the only producer of output, so
// a canned lrecon answer cannot match two different stub bodies.
func b10Stub(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func b10StubPrint(t *testing.T, dir, name, out string) string {
	t.Helper()
	return b10Stub(t, dir, name, "printf '%s' "+b10Quote(out))
}

// b10NoEngine asserts the absent-tool answer: a typed refusal with kind
// no_engine whose message names the missing tool.
func b10NoEngine(t *testing.T, err error, mention string) *extRefusal {
	t.Helper()
	var ref *extRefusal
	if !errors.As(err, &ref) {
		t.Fatalf("absent tool error = %T %v, want *extRefusal", err, err)
	}
	if ref.kind != kindNoEngine {
		t.Fatalf("absent tool kind = %q, want %q (%s)", ref.kind, kindNoEngine, ref.msg)
	}
	if !strings.Contains(ref.msg, mention) {
		t.Fatalf("absent tool message %q does not name %q", ref.msg, mention)
	}
	return ref
}

// b10Answer asserts the present-tool answer is the stub's bytes: the tool it
// drove, the subcommand at argIndex, and Output/Lines equal to what the stub
// printed.
func b10Answer(t *testing.T, v any, err error, tool string, argIndex int, argWant, out string) extOut {
	t.Helper()
	if err != nil {
		t.Fatalf("%s with the stub on PATH: %v", tool, err)
	}
	got, ok := v.(extOut)
	if !ok {
		t.Fatalf("%s answer = %T, want extOut", tool, v)
	}
	if got.Tool != tool {
		t.Fatalf("tool = %q, want %q", got.Tool, tool)
	}
	if len(got.Args) <= argIndex || got.Args[argIndex] != argWant {
		t.Fatalf("%s args = %v, want arg %d = %q", tool, got.Args, argIndex, argWant)
	}
	if got.Output != out {
		t.Fatalf("%s output = %q, want the stub's %q", tool, got.Output, out)
	}
	if want := rtLines(out); strings.Join(got.Lines, "\n") != strings.Join(want, "\n") {
		t.Fatalf("%s lines = %v, want %v", tool, got.Lines, want)
	}
	return got
}

func TestTur7Bucket10ExtToolGating(t *testing.T) {
	prev := opOutput
	opOutput = ""
	defer func() { opOutput = prev }()

	target := filepath.Join(t.TempDir(), "target.bin")
	if err := os.WriteFile(target, []byte("MZ"), 0o644); err != nil {
		t.Fatal(err)
	}
	empty := t.TempDir()

	// Absent from PATH: every op refuses with no_engine naming its own tool.
	t.Run("absent", func(t *testing.T) {
		t.Setenv("PATH", empty)
		_, err := runExtOp("adb_forward_list", "", nil)
		b10NoEngine(t, err, "adb not installed")
		_, err = runExtOp("apktool_list_frameworks", "", nil)
		b10NoEngine(t, err, "apktool not installed")
		_, err = runExtOp("jadx_plugins", "", nil)
		b10NoEngine(t, err, "jadx not installed")
		_, err = runExtOp("lldb_register_read", target, []string{"rax"})
		b10NoEngine(t, err, "lldb not installed")
		// findGhidra's override is authoritative: a bad LRECON_GHIDRA is a
		// missing engine, never a silent PATH fallback.
		t.Setenv("LRECON_ANALYZEHEADLESS", "")
		t.Setenv("LRECON_GHIDRA", filepath.Join(empty, "no-analyzeHeadless"))
		_, err = runExtOp("ghidra_noanalysis", target, nil)
		b10NoEngine(t, err, "analyzeHeadless not installed")
	})

	// One absent tool still refuses while the other ext tools sit on PATH: the
	// gate is per tool, not "some external tool exists".
	t.Run("absent adb among present tools", func(t *testing.T) {
		dir := t.TempDir()
		b10StubPrint(t, dir, "apktool", b10ApktoolOut)
		b10StubPrint(t, dir, "jadx", b10JadxOut)
		b10StubPrint(t, dir, "lldb", b10LldbOut)
		t.Setenv("PATH", dir)
		_, err := runExtOp("adb_forward_list", "", nil)
		b10NoEngine(t, err, "adb not installed")
	})

	// Present on PATH: the answer is the stub's bytes, and different bytes move
	// it. Same op, two stubs, two answers.
	t.Run("present adb", func(t *testing.T) {
		first := t.TempDir()
		b10StubPrint(t, first, "adb", b10AdbOut)
		t.Setenv("PATH", first)
		v, err := runExtOp("adb_forward_list", "", nil)
		out := b10Answer(t, v, err, "adb", 0, "forward", b10AdbOut)

		second := t.TempDir()
		b10StubPrint(t, second, "adb", b10AdbOut2)
		t.Setenv("PATH", second)
		v, err = runExtOp("adb_forward_list", "", nil)
		out2 := b10Answer(t, v, err, "adb", 0, "forward", b10AdbOut2)
		if out.Output == out2.Output {
			t.Fatalf("two different stubs produced one answer: %q", out.Output)
		}
	})

	t.Run("present apktool", func(t *testing.T) {
		dir := t.TempDir()
		b10StubPrint(t, dir, "apktool", b10ApktoolOut)
		t.Setenv("PATH", dir)
		v, err := runExtOp("apktool_list_frameworks", "", nil)
		b10Answer(t, v, err, "apktool", 0, "lf", b10ApktoolOut)
	})

	t.Run("present jadx", func(t *testing.T) {
		dir := t.TempDir()
		b10StubPrint(t, dir, "jadx", b10JadxOut)
		t.Setenv("PATH", dir)
		v, err := runExtOp("jadx_plugins", "", nil)
		b10Answer(t, v, err, "jadx", 0, "plugins", b10JadxOut)
	})

	t.Run("present lldb", func(t *testing.T) {
		dir := t.TempDir()
		b10StubPrint(t, dir, "lldb", b10LldbOut)
		t.Setenv("PATH", dir)
		v, err := runExtOp("lldb_register_read", target, []string{"rax"})
		b10Answer(t, v, err, "lldb", 0, "register read rax", b10LldbOut)
	})

	t.Run("present ghidra", func(t *testing.T) {
		dir := t.TempDir()
		stub := b10StubPrint(t, dir, "analyzeHeadless", b10GhidraOut)
		t.Setenv("PATH", empty)
		t.Setenv("LRECON_ANALYZEHEADLESS", "")
		t.Setenv("LRECON_GHIDRA", stub)
		v, err := runExtOp("ghidra_noanalysis", target, nil)
		b10Answer(t, v, err, "analyzeHeadless", 1, "lrecon", b10GhidraOut)
	})

	// The stub runs and fails: the op must not turn that into an answer. The
	// tool's own error line becomes the refusal text.
	t.Run("stub fails", func(t *testing.T) {
		dir := t.TempDir()
		b10Stub(t, dir, "adb", "printf 'error: device offline\\n' >&2\nexit 1")
		t.Setenv("PATH", dir)
		_, err := runExtOp("adb_forward_list", "", nil)
		ref := b10NoEngine(t, err, "error: device offline")
		if !strings.Contains(ref.msg, "forward --list") {
			t.Fatalf("refusal lost the command it ran: %q", ref.msg)
		}
	})
}
