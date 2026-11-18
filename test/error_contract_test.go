package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The refusal envelope promises a closed kind set. A caller switch-cases on it,
// so every message the ops can produce has to land on one of these nine, and
// the four scenarios a sweep can hit (no argument, wrong value, missing file,
// foreign state) must each name themselves.
func TestKindSetIsClosed(t *testing.T) {
	want := map[errorKind]bool{
		kindNeedsArg: true, kindBadArg: true, kindOutOfScope: true, kindNoEngine: true, kindTimeout: true,
		kindUsage: true, kindIO: true, kindStateConflict: true, kindInternal: true,
	}
	if len(kindList) != len(want) {
		t.Fatalf("kindList = %v, want %d kinds", kindList, len(want))
	}
	seen := map[errorKind]bool{}
	for _, k := range kindList {
		if seen[k] {
			t.Fatalf("kind %q listed twice", k)
		}
		seen[k] = true
		if !want[k] {
			t.Fatalf("unexpected kind %q in kindList", k)
		}
	}
	if string(kindStateConflict) != "state_conflict" {
		t.Fatalf("state conflict kind = %q, want state_conflict", kindStateConflict)
	}
}

// classify is the bridge from an op's prose to the kind. These are the real
// messages the 229 ops returned under bad-argument probes: an oversized swift
// blob, a missing state file, a device that answered with an error, a job that
// left a field out.
func TestClassifyContractMessages(t *testing.T) {
	cases := []struct {
		msg  string
		kind errorKind
	}{
		// A typed file that is not the format the op reads.
		{`/tmp/x.bin is neither Mach-O nor ELF`, kindBadArg},
		{`/tmp/x.bin: no MZ header`, kindBadArg},
		{`/tmp/x.bin has no wasm magic`, kindBadArg},
		{`/tmp/x.bin does not carry the Dart snapshot magic`, kindBadArg},
		{`/tmp/x.bin has no sourceMappingURL trailer: nothing to recover`, kindBadArg},
		{`safetensors header declares 727905341920923785 bytes, file holds 15575`, kindBadArg},
		{`this op takes two targets: <left>,<right> (got "/tmp/x.bin")`, kindBadArg},
		{`no page to load: pass <endpoint>=<html>`, kindBadArg},
		{`/tmp/x.bin: lrecon reads on-disk headers only and never maps a loaded image`, kindBadArg},
		// Measured with `--op compare_source_to_bundle --json /bin/ls` and
		// `--op inspect_native_exports --json /bin/ls`: two deliberate refusals
		// the sweep saw as kind internal.
		{`/bin/ls: asar header JSON: EOF`, kindBadArg},
		{`/bin/ls: Mach-O exports are covered by inspect_macho; inspect_native_exports reads PE and ELF export tables`, kindBadArg},
		// Skip reasons are refusals too (main.go turns a bare *skip into
		// refuse(reason)), so a target that is simply too small for the op must
		// not read as lrecon's own fault. Measured with tiny fixtures.
		{`/tmp/tiny.bin is 1 bytes, shorter than one 4 KiB block`, kindBadArg},
		{`/tmp/tiny.bin is 1 bytes, shorter than the Dart header`, kindBadArg},
		{`/tmp/tiny.bin has an empty header or an empty body; an Apple .ips needs both`, kindBadArg},
		{`/tmp/tiny.bin: asar header: EOF`, kindBadArg},
		{`/tmp/tiny.bin has one JSON line; an Apple .ips carries the header on line 1 and the crash body from line 2 on`, kindBadArg},
		{`/tmp/tiny.bin holds 0 bytes, too short for a dispatcher`, kindBadArg},
		{`/tmp/tiny.bin is 0 bytes, shorter than the 8-byte header length`, kindBadArg},
		// A2: the size cap is the caller's file, not lrecon's fault. The three
		// readers word it three ways and all three are measured.
		{`/tmp/big.bin is 314572800 bytes, over the 268435456-byte cap`, kindBadArg},
		{`/tmp/big.bin is larger than the 268435456-byte cap`, kindBadArg},
		{`LRECON_LEN=999999999999: 999999999999 is above the 268435456-byte cap`, kindBadArg},
		// A request outside the product's scope: not a wrong value and not a
		// missing tool, so a caller must not go install a debugger for it.
		{`live runtime targets are out of scope: lrecon reads static files only`, kindOutOfScope},
		{`live debug sessions out of scope: lrecon reads static files only`, kindOutOfScope},
		{`website targets are out of scope: fetch the page yourself`, kindOutOfScope},
		// A job or an op that was called without a value it needs.
		{`set_comment: job needs "address" and "text"`, kindNeedsArg},
		{`update_analysis_settings: job needs at least one of "deep", "maxBytes", "minString"`, kindNeedsArg},
		{`set LRECON_AT (address) or LRECON_NAME (symbol) for this op`, kindNeedsArg},
		{`this op needs <apk-or-dex>#<com.example.Class>`, kindNeedsArg},
		// A tool, device or asset the route needs is not here.
		{`adb -s emulator-5554 shell cmd package list packages -f: cmd: Can't find service: package`, kindNoEngine},
		{`adb shell uiautomator dump --windows /data/local/tmp/ui.xml failed: exit status 137`, kindNoEngine},
		{`dumpsys window listed no windows: `, kindNoEngine},
		{`cdp 127.0.0.1:1: exit status 1: file:///tmp/eval1:2`, kindNoEngine},
		{`no device ready: 1 attached, none in state "device"`, kindNoEngine},
		{`decoder table decoders.json not found: ship decoders.json beside lrecon or set LRECON_DECODERS`, kindNoEngine},
		// Ghidra present but its GoRttiMapper refuses the target's Go version:
		// measured on the macho fixture (was kind internal).
		{`ghidra analyzeHeadless "mirror" on macho: ERROR Untested Go version [1.26.5] (GoRttiMapper)`, kindNoEngine},
		{`close_binary: no session to close in /tmp/state`, kindNoEngine},
		// A path that is not there.
		{`open /no/such/file: no such file or directory`, kindIO},
		{`stat /no/such/file: no such file or directory`, kindIO},
		{`/no/such/file cannot be read`, kindIO},
		// lldb says "does not exist" where the stdlib says "no such file";
		// measured with `--op gdb_console /nonexistent` (was kind internal).
		{`lldb: error: '//nonexistent-l10-elf' does not exist`, kindIO},
		// A state tree holding another artifact.
		{`state conflict: /tmp/state/config.json holds "lrecon.other/1", want "lrecon.settings/1"`, kindStateConflict},
		// lrecon's own fault stays internal, and the message is the clue.
		{`runtime error: index out of range [1] with length 0`, kindInternal},
	}
	for _, c := range cases {
		if got := classify(c.msg); got != c.kind {
			t.Errorf("classify(%q) = %s, want %s", c.msg, got, c.kind)
		}
	}
}

// decline was the one refusal path that printed prose even under --json. A
// live target, a website target and two modes that cannot be one document must
// all answer with the same three-field envelope on stdout, nothing on stderr,
// exit 2, and op null because no op was named.
func TestDeclineEnvelopeJSON(t *testing.T) {
	target := writeTemp(t, "target.bin", []byte("not an artifact\n"))
	cases := []struct {
		name string
		args []string
		kind string
		says string
	}{
		{"live pid", []string{"--json", "--pid", "1"}, "out_of_scope", "out of scope"},
		{"process name", []string{"--json", "--process", "Safari"}, "out_of_scope", "out of scope"},
		{"website target", []string{"--json", "https://example.com/page"}, "out_of_scope", "out of scope"},
		{"json plus diff", []string{"--json", "--diff", "old", target}, "usage", "cannot be combined"},
		{"json plus extract", []string{"--json", "--extract", "a", target}, "usage", "cannot be combined"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			stdout, stderr, code := runCLIAll(t, c.args...)
			if code != 2 {
				t.Fatalf("exit %d, want 2; stdout:\n%s\nstderr:\n%s", code, stdout, stderr)
			}
			if !strings.HasPrefix(stderr, "lrecon: ") {
				t.Fatalf("stderr = %q, want the prefixed refusal line", stderr)
			}
			m := decodeEnvelope(t, stdout)
			if m["kind"] != c.kind {
				t.Fatalf("kind = %v, want %s: %s", m["kind"], c.kind, stdout)
			}
			if m["op"] != nil {
				t.Fatalf("op = %v, want null: %s", m["op"], stdout)
			}
			if detail, _ := m["error"].(string); !strings.Contains(detail, c.says) {
				t.Fatalf("error = %q, want it to say %q", detail, c.says)
			}
		})
	}
}

// The same decline without --json keeps the old contract: nothing on stdout,
// one prefixed line on stderr, exit 2.
func TestDeclineTextWithoutJSON(t *testing.T) {
	stdout, stderr, code := runCLIAll(t, "https://example.com/page")
	if code != 2 {
		t.Fatalf("exit %d, want 2; stderr:\n%s", code, stderr)
	}
	if stdout != "" {
		t.Fatalf("no --json but wrote stdout:\n%s", stdout)
	}
	if !strings.HasPrefix(stderr, "lrecon: ") || !strings.Contains(stderr, "out of scope") {
		t.Fatalf("stderr = %q, want the plain refusal line", stderr)
	}
}

// A dirty state tree is a contract refusal, not a bad target: the envelope
// names state_conflict so a sweep can tell "wrong file" from "wrong state".
func TestStateConflictEnvelope(t *testing.T) {
	state := t.TempDir()
	if err := os.WriteFile(filepath.Join(state, "config.json"), []byte(`{"kind":"lrecon.other/1"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LRECON_STATE", state)
	target := writeTemp(t, "state-target.bin", []byte("not an artifact\n"))
	stdout, stderr, code := runCLIAll(t, "--json", "--op", "inspect_analysis_settings", target)
	if code != 2 {
		t.Fatalf("exit %d, want 2; stdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	if !strings.HasPrefix(stderr, "lrecon: ") {
		t.Fatalf("stderr = %q, want the prefixed refusal line", stderr)
	}
	m := decodeEnvelope(t, stdout)
	if m["kind"] != "state_conflict" {
		t.Fatalf("kind = %v, want state_conflict: %s", m["kind"], stdout)
	}
	if detail, _ := m["error"].(string); !strings.Contains(detail, "state conflict") {
		t.Fatalf("error = %q, want it to name the state conflict", detail)
	}
	if m["op"] != "inspect_analysis_settings" {
		t.Fatalf("op = %v, want the named op", m["op"])
	}
}

// A format refusal on a path that is not there used to hide the real cause:
// "x is not ELF" for a file the op never opened. The kind must name the first
// problem, so the missing path wins and the envelope says io.
func TestFormatRefusalKeepsMissingPath(t *testing.T) {
	err := formatRefusal("/no/such/artifact.bin", "is not ELF, Mach-O or PE")
	if err == nil {
		t.Fatal("missing path: want an error")
	}
	if got := classify(err.Error()); got != kindIO {
		t.Fatalf("classify(%q) = %s, want io", err, got)
	}
	present := writeTemp(t, "present.bin", []byte("not an artifact\n"))
	err = formatRefusal(present, "is not ELF, Mach-O or PE")
	if err == nil || classify(err.Error()) != kindBadArg {
		t.Fatalf("present but wrong format: err = %v, want bad_arg", err)
	}
}

// exec.CommandContext kills the child at the deadline, and the raw error is
// "signal: killed" — which classified as internal. The run helpers must name
// the deadline so a slow device answers kind=timeout instead.
func TestDeadlineKillIsTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := rtRunRaw(ctx, "/bin/sleep", "5"); err == nil {
		t.Fatal("killed command: want an error")
	} else if got := classify(err.Error()); got != kindTimeout {
		t.Fatalf("classify(%q) = %s, want timeout", err, got)
	}
}

// A sweep found two ops answering a wrong-format target with kind internal:
// compare_source_to_bundle on a Mach-O, and inspect_native_exports on a Mach-O.
// Both are the caller's mistake, so the envelope has to name itself bad_arg.
// cliPath is the test-built binary, so it is Mach-O here and ELF on linux.
func TestWrongFormatTargetIsBadArg(t *testing.T) {
	stdout, stderr, code := runCLIAll(t, "--op", "compare_source_to_bundle", "--json", cliPath)
	if code != 2 {
		t.Fatalf("exit %d, want 2; stdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	if !strings.HasPrefix(stderr, "lrecon: ") {
		t.Fatalf("stderr = %q, want the prefixed refusal line", stderr)
	}
	m := decodeEnvelope(t, stdout)
	if m["kind"] != "bad_arg" {
		t.Fatalf("kind = %v, want bad_arg: %s", m["kind"], stdout)
	}
	// A file too small for the op is the same caller mistake, on four more ops
	// the fixture sweep hit as kind internal (skip reasons count: main.go turns
	// a bare *skip into a refusal).
	tiny := writeTemp(t, "tiny.bin", []byte("x"))
	for _, op := range []string{"compare_source_to_bundle", "inspect_byte_entropy", "inspect_dart_aot", "inspect_recorded_crash", "inspect_evm_interface", "inspect_model_artifact"} {
		stdout, stderr, code := runCLIAll(t, "--op", op, "--json", tiny)
		if code != 2 {
			t.Fatalf("%s: exit %d, want 2; stdout:\n%s\nstderr:\n%s", op, code, stdout, stderr)
		}
		if !strings.HasPrefix(stderr, "lrecon: ") {
			t.Fatalf("%s: stderr = %q, want the prefixed refusal line", op, stderr)
		}
		m := decodeEnvelope(t, stdout)
		if m["kind"] != "bad_arg" {
			t.Fatalf("%s: kind = %v, want bad_arg: %s", op, m["kind"], stdout)
		}
	}
}
