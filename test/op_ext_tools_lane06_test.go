package main

// LANE06: the ext tools with no targeted test (apktool, jadx, analyzeHeadless,
// lldb memory/attach and the lldb engine helpers). Fake shims on PATH prove the
// exact argv lrecon assembled; arg-error paths are checked with no tool present.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func lane06ExtOut(t *testing.T, v any, err error, tool string, want ...string) extOut {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %v", tool, err)
	}
	out, ok := v.(extOut)
	if !ok {
		t.Fatalf("%s = %T, want extOut", tool, v)
	}
	if out.Tool != tool {
		t.Fatalf("tool = %q, want %q", out.Tool, tool)
	}
	// extDir puts a temp dir in -d/-o; compare args after dropping that value.
	got := append([]string{}, out.Args...)
	wantArgs := append([]string{}, want...)
	if len(got) != len(wantArgs) {
		t.Fatalf("%s args = %v, want %v", tool, got, wantArgs)
	}
	for i := range got {
		if strings.HasPrefix(wantArgs[i], "<dir>") {
			if got[i] == "" {
				t.Fatalf("%s arg %d is empty, want a dir", tool, i)
			}
			continue
		}
		if got[i] != wantArgs[i] {
			t.Fatalf("%s arg %d = %q, want %q (all: %v)", tool, i, got[i], wantArgs[i], got)
		}
	}
	if !strings.Contains(out.Output, "ran:") || len(out.Lines) == 0 {
		t.Fatalf("%s output lost: %q", tool, out.Output)
	}
	return out
}

func TestApktoolDecodeBuildArgs(t *testing.T) {
	rtFakeTool(t, "apktool", `printf 'ran:%s\n' "$*"`)
	v, err := apktoolDecode("app.apk", []string{"-f"}, "-no-res")
	out := lane06ExtOut(t, v, err, "apktool", "d", "-o", "<dir>", "-no-res", "app.apk", "-f")
	if !strings.HasSuffix(out.Args[2], "/out") {
		t.Fatalf("decode -o = %q", out.Args[2])
	}
	v, err = apktoolBuild("app.apk", []string{"-a"})
	out = lane06ExtOut(t, v, err, "apktool", "b", "-o", "<dir>", "app.apk", "-a")
	if !strings.HasSuffix(out.Args[2], "/out.apk") {
		t.Fatalf("build -o = %q", out.Args[2])
	}
}

func TestJadxVariantFlagsAndArgErrors(t *testing.T) {
	rtNoTools(t)
	if _, err := jadxMappings("app.apk", nil); err == nil || !strings.Contains(err.Error(), "needs a mappings file") {
		t.Fatalf("jadx_mappings no arg = %v", err)
	}
	if _, err := jadxSingleClassFull("app.apk", nil); err == nil || !strings.Contains(err.Error(), "needs a class name") {
		t.Fatalf("jadx_single_class_full no arg = %v", err)
	}
	if _, err := jadxPlugins("app.apk", nil); err == nil || !strings.Contains(err.Error(), "takes no target") {
		t.Fatalf("jadx_plugins with target = %v", err)
	}
	rtFakeTool(t, "jadx", `printf 'ran:%s\n' "$*"`)
	cases := []struct {
		name string
		run  func(string, []string) (any, error)
		want []string
	}{
		{"gradle", jadxExportGradle, []string{"-d", "<dir>", "-e", "--export-gradle-type", "auto", "app.apk"}},
		{"deobf", jadxDeobf, []string{"-d", "<dir>", "--deobf", "app.apk"}},
		{"callgraph", jadxCallGraph, []string{"-d", "<dir>", "--call-graph", "dot", "app.apk"}},
		{"cfg", jadxCfg, []string{"-d", "<dir>", "--cfg", "app.apk"}},
		{"outputjson", jadxOutputJson, []string{"-d", "<dir>", "--output-format", "json", "app.apk"}},
		{"mapping", jadxMappings, nil}, // handled below (extra arg)
	}
	for _, c := range cases[:5] {
		t.Run(c.name, func(t *testing.T) {
			v, err := c.run("app.apk", nil)
			lane06ExtOut(t, v, err, "jadx", c.want...)
		})
	}
	v, err := jadxMappings("app.apk", []string{"map.txt", "-v"})
	lane06ExtOut(t, v, err, "jadx", "-d", "<dir>", "--mappings-path", "map.txt", "app.apk", "-v")
}

func lane06FakeGhidra(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "analyzeHeadless")
	if err := os.WriteFile(p, []byte("#!/bin/sh\nprintf 'ran:%s\\n' \"$*\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LRECON_GHIDRA", p)
}

func TestGhidraExtImportFlagAssembly(t *testing.T) {
	lane06FakeGhidra(t)
	v, err := extGhidraImport("app.bin", []string{"-noanalysis"}, "-processor", "ARM:LE:32:v7")
	out := lane06ExtOut(t, v, err, "analyzeHeadless", "<dir>", "lrecon", "-processor", "ARM:LE:32:v7", "-import", "app.bin", "-noanalysis")
	if !strings.HasSuffix(out.Args[0], "/project") {
		t.Fatalf("ghidra project = %q", out.Args[0])
	}
	v, err = ghidraCspec("app.bin", []string{"default"})
	out = lane06ExtOut(t, v, err, "analyzeHeadless", "<dir>", "lrecon", "-processor", "AARCH64:LE:64:v8A", "-cspec", "default", "-import", "app.bin")
	_ = out
}

func TestGhidraExtArgValidationAndScriptError(t *testing.T) {
	rtNoTools(t)
	if _, err := ghidraPrescript("app.bin", nil); err == nil || !strings.Contains(err.Error(), "needs an argument") {
		t.Fatalf("ghidra_prescript no arg = %v", err)
	}
	if _, err := ghidraProcessor("app.bin", nil); err == nil || !strings.Contains(err.Error(), "needs an argument") {
		t.Fatalf("ghidra_processor no arg = %v", err)
	}
	if _, err := ghidraCspec("app.bin", nil); err == nil || !strings.Contains(err.Error(), "needs an argument") {
		t.Fatalf("ghidra_cspec no arg = %v", err)
	}
	// A pre-script Ghidra could not load exits 0 with the error only in the log;
	// lrecon must turn that log line into kindInternal.
	if line := ghidraScriptError("INFO start\nREPORT SCRIPT ERROR: missing.py\nINFO done"); line == "" {
		t.Fatal("ghidraScriptError missed the log line")
	}
}

func TestLldbMemoryArgsAndAttachValidation(t *testing.T) {
	rtNoTools(t)
	target := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(target, []byte("MZ"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := runLldbRegisterRead(target, nil); err == nil {
		t.Fatal("register read with no lldb should refuse")
	}
	// Attach validates the tool first, then the pid; a fake lldb must be present
	// to reach the pid error paths.
	rtFakeTool(t, "lldb", `printf 'ran:%s\n' "$*"`)
	_, err := runLldbProcessAttach(target, []string{" "}) // file target, no pid arg
	var ref *extRefusal
	if !errors.As(err, &ref) || ref.kind != kindNeedsArg {
		t.Fatalf("attach no pid = %v", err)
	}
	_, err = runLldbProcessAttach("abc", []string{"-1"})
	if !errors.As(err, &ref) || ref.kind != kindBadArg {
		t.Fatalf("attach bad pid = %v", err)
	}
	_, err = runLldbProcessAttach("999999", []string{"999999"})
	if !errors.As(err, &ref) || ref.kind != kindNoEngine || !strings.Contains(ref.msg, "no live process") {
		t.Fatalf("attach dead pid = %v", err)
	}
	v, err := runLldbRegisterRead(target, []string{"rax"})
	out := lane06ExtOut(t, v, err, "lldb", "register read rax", target)
	_ = out
}

func TestLldbNoProcessLineAndErrors(t *testing.T) {
	if lldbNoProcessLine("error: Command requires a current process.") == "" {
		t.Fatal("missed no-process line")
	}
	if lldbNoProcessLine("error: target create '/tmp/no current process' failed") != "" {
		t.Fatal("path text mistaken for no-process")
	}
	got := lldbErrors("banner\nerror: one\nwarning: two\nerror: three")
	if len(got) != 2 || got[0] != "error: one" || got[1] != "error: three" {
		t.Fatalf("lldbErrors = %v", got)
	}
}

func TestGdbLldbEngineParsesTranscript(t *testing.T) {
	// Fake lldb prints a real thread list + stop reason; gdbSessionStatusLLDB
	// must scrape both, not just answer "no-inferior".
	rtFakeTool(t, "lldb", `printf '%s\n' '(lldb) thread list' 'thread #1: tid = 0x1, stop reason = breakpoint 1.1' 'thread #2: tid = 0x2'`)
	v, err := gdbSessionStatusLLDB("/bin/ls")
	if err != nil {
		t.Fatal(err)
	}
	res, ok := v.(rtGdbStatus)
	if !ok {
		t.Fatalf("status = %T", v)
	}
	if res.Engine != "lldb" || len(res.Threads) != 2 || res.Threads[0].ID != "1" || res.Stopped != "breakpoint 1.1" {
		t.Fatalf("status = %+v", res)
	}
	// No-process stderr must map to no-inferior with a note, not a hard error.
	rtFakeTool(t, "lldb", `printf '%s\n' 'error: Command requires a current process.' >&2; exit 1`)
	v, err = gdbSessionStatusLLDB("/bin/ls")
	if err != nil {
		t.Fatal(err)
	}
	res = v.(rtGdbStatus)
	if res.Stopped != "no-inferior" || !strings.Contains(res.Note, "no inferior exists") {
		t.Fatalf("no-process status = %+v", res)
	}
}

func TestLldbDialogBatchArgs(t *testing.T) {
	rtFakeTool(t, "lldb", `printf 'ran:%s\n' "$*"`)
	out, errOut, err := lldbDialog(context.Background(), "lldb", "target.bin", "register read", "thread list")
	if err != nil || !strings.Contains(out, "--batch --no-lldbinit -o register read -o thread list -- target.bin") {
		t.Fatalf("lldbDialog out=%q err=%q errOut=%q", out, err, errOut)
	}
}
