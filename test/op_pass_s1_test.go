package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestPassS1 exercises ops 1-59 of `lrecon --list-ops --json` (list order)
// through the REAL CLI against tracked fixtures. Each op must either emit real
// data (rc=0 with a non-empty result) or a correct typed refusal (rc=2 with
// kind in needs_arg/bad_arg/out_of_scope/no_engine).
//
// The CLI is exec'd (not called in-process) because several ops call
// refuseKind() -> os.Exit(2) directly, which would kill the test binary.
func TestPassS1(t *testing.T) {
	bin := s1Build(t)
	stateDir := t.TempDir()
	base := s1BaseEnv(stateDir)
	cases := s1Cases(t)

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rc, kind, out := s1Run(t, bin, c, base)
			short := s1Short(out)
			switch {
			case rc == 0:
				var top map[string]any
				if err := json.Unmarshal([]byte(out), &top); err != nil {
					t.Errorf("FAIL | rc=0 bad JSON: %v | %s | %s", err, c.note, short)
					return
				}
				res, ok := top["result"]
				if !ok {
					t.Errorf("FAIL | rc=0 no result | %s | %s", c.note, short)
					return
				}
				sig, has := s1DataSig(res)
				if !has {
					t.Errorf("FAIL | rc=0 no real data | %s | %s", c.note, short)
					return
				}
				t.Logf("PASS | data(%s) | %s | %s", sig, c.note, short)
			case rc == 2 && s1Typed(kind):
				t.Logf("PASS | typed:%s | %s | %s", kind, c.note, short)
			default:
				t.Errorf("FAIL | rc=%d kind=%s | %s | %s", rc, kind, c.note, short)
			}
		})
	}
}

type s1Case struct {
	name   string
	target string
	env    map[string]string
	out    bool // append -o <tempdir>
	note   string
}

// s1Cases mirrors probe_s1.py::spec_for exactly; job targets are real JSON
// written from tracked fixture paths.
func s1Cases(t *testing.T) []s1Case {
	t.Helper()
	fixture := func(p string) string {
		a, err := filepath.Abs(filepath.Join("testdata", "fixtures", p))
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	job := func(v any) string {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(t.TempDir(), "job.json")
		if err := os.WriteFile(p, b, 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	macho, elf := fixture("macho"), fixture("elf")
	pe, wasm := fixture("pe.exe"), fixture("wasm.wasm")
	asar, ips := fixture("electron/app.asar"), fixture("ips/ls.ips")

	return []s1Case{
		{name: "address_name", target: macho, env: map[string]string{"LRECON_AT": "0x1000003e4"}, note: "macho + LRECON_AT"},
		{name: "address_to_file_offset", target: macho, env: map[string]string{"LRECON_AT": "0x1000003e4"}, note: "macho + LRECON_AT"},
		{name: "analyze_function", target: macho, env: map[string]string{"LRECON_AT": "0x1000003e4", "LRECON_NAME": ""}, note: "macho + AT"},
		{name: "analyze_javascript_application", target: wasm, note: "wasm bytes (lexer)"},
		{name: "analyze_swift_types", target: macho, note: "macho"},
		{name: "analyze_web_bundle", target: elf, note: "elf bytes"},
		{name: "annotate_native_function", target: macho, note: "macho"},
		{name: "batch_decompile", target: macho, env: map[string]string{"LRECON_ARGS": "0x1000003e4"}, note: "macho + ARGS"},
		{name: "binary_overview", target: macho, note: "macho"},
		{name: "binary_session", target: macho, note: "macho, shared LRECON_STATE"},
		{name: "build_call_path", target: macho, env: map[string]string{"LRECON_FROM": "entry", "LRECON_TO": "_main"}, note: "macho + FROM/TO"},
		{name: "build_reconstruction_obligation_ledger", target: job(map[string]any{"file": elf, "state": t.TempDir(), "rows": []any{map[string]any{"symbol": "main", "reason": "s1"}}}), note: "job: elf + 1 row"},
		{name: "capture_adb_screen", note: "no device"},
		{name: "capture_browser_scenario", target: macho, note: "macho not DevTools endpoint"},
		{name: "capture_electron_scenario", target: macho, note: "macho not DevTools endpoint"},
		{name: "capture_native_ui_scenario", note: "no device"},
		{name: "capture_process_scenario", target: macho, note: "macho not a pid"},
		{name: "capture_web_screenshot", target: macho, note: "macho not DevTools endpoint"},
		{name: "check_deception_signals", target: macho, note: "macho"},
		{name: "check_runtime_evasion", target: macho, note: "macho"},
		{name: "close_binary", note: "closes session from binary_session"},
		{name: "close_frida_session", note: "live-session refusal"},
		{name: "close_gdb_session", target: elf, note: "elf, batch lldb"},
		{name: "close_rizin_debug_session", target: elf, note: "live-debug refusal"},
		{name: "collect_adb_bugreport", target: macho, note: "macho not .zip path"},
		{name: "comment", target: macho, note: "macho"},
		{name: "compare_application_versions", target: job(map[string]any{"old": elf, "new": pe}), note: "job: elf vs pe.exe"},
		{name: "compare_artifacts", target: job(map[string]any{"old": elf, "new": pe}), note: "job: elf vs pe.exe"},
		{name: "compare_bundles", target: job(map[string]any{"old": elf, "new": pe}), note: "job: elf/pe not archives"},
		{name: "compare_functions", target: macho, env: map[string]string{"LRECON_FROM": "0x1000003e4", "LRECON_TO": "0x1000003f4"}, note: "macho + FROM/TO"},
		{name: "compare_javascript_export_shapes", target: elf, note: "single file, needs 2-script dir"},
		{name: "compare_managed_members", target: pe, note: "single target, needs left,right"},
		{name: "compare_process_captures", target: elf + "," + macho, note: "elf,macho not JSON captures"},
		{name: "compare_source_to_bundle", target: asar, note: "electron/app.asar"},
		{name: "compare_wasm_interfaces", target: wasm + "," + wasm, note: "wasm,wasm"},
		{name: "compare_web_captures", target: macho, note: "macho not DevTools endpoint"},
		{name: "compare_web_screenshots", target: macho, note: "macho not DevTools endpoint"},
		{name: "correlate_static_and_runtime", target: job(map[string]any{"file": elf, "crash": ips}), note: "job: elf (no uuid) + ips"},
		{name: "current_address", note: "no session"},
		{name: "current_document", note: "no session"},
		{name: "current_procedure", note: "no session"},
		{name: "cutter_command", target: macho, note: "command-console refusal"},
		{name: "decode_android_resources", target: macho, note: "macho not zip"},
		{name: "decode_interface_builder", target: macho, note: "macho not NIBArchive"},
		{name: "decode_signal_recording", target: macho, note: "macho not SigMF JSON"},
		{name: "decompile_all", target: macho, note: "macho"},
		{name: "decompile_jeb_item", target: macho, note: "macho not apk:fqcn"},
		{name: "demangle_swift", target: macho, note: "no $s symbols"},
		{name: "discover_webmcp_tools", target: macho, note: "macho not DevTools endpoint"},
		{name: "evaluate_reconstruction_coverage", target: job(map[string]any{"resolved": []string{"_main"}, "unresolved": []any{map[string]any{"reason": "x", "symbol": "_x"}}}), note: "job: 1 resolved/1 unresolved"},
		{name: "execute_rizin_command", target: macho, note: "command-console refusal"},
		{name: "export_environment_bundle", target: job(map[string]any{"file": elf}), out: true, note: "job: elf + -o"},
		{name: "export_evidence_bundle", target: job(map[string]any{"file": elf}), out: true, note: "job: elf + -o"},
		{name: "export_web_scripts", target: asar, out: true, note: "app.asar + -o"},
		{name: "extract_artifact", target: job(map[string]any{"file": asar, "member": "package.json"}), note: "job: asar, no -o"},
		{name: "extract_firmware", target: job(map[string]any{"file": elf}), note: "job: elf, no -o"},
		{name: "find_changed_behavior", target: job(map[string]any{"old": elf, "new": pe}), note: "job: elf vs pe.exe"},
		{name: "find_xrefs_to_name", target: macho, env: map[string]string{"LRECON_NAME": "_main", "LRECON_AT": ""}, note: "macho + NAME"},
		{name: "frida_session_status", note: "live-session refusal"},
	}
}

func s1Build(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "lrecon_s1")
	cmd := exec.Command("go", "build", "-o", bin, ".")
	cmd.Dir = "."
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build failed: %v\n%s", err, out)
	}
	return bin
}

func s1BaseEnv(stateDir string) map[string]string {
	return map[string]string{
		"LRECON_STATE":           stateDir,
		"LRECON_GHIDRA":          "/nonexistent/lrecon-ghidra",
		"LRECON_ANALYZEHEADLESS": "",
		"LRECON_GHIDRA_TIMEOUT":  "10s",
		"LRECON_OP_DEADLINE":     "10s",
	}
}

func s1Run(t *testing.T, bin string, c s1Case, base map[string]string) (int, string, string) {
	t.Helper()
	env := os.Environ()
	for k, v := range base {
		env = append(env, k+"="+v)
	}
	for k, v := range c.env {
		env = append(env, k+"="+v)
	}
	args := []string{"--op", c.name, "--json"}
	if c.target != "" {
		args = append(args, c.target)
	}
	if c.out {
		args = append(args, "-o", t.TempDir())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = env
	cmd.Dir = "."
	var outB, errB bytes.Buffer
	cmd.Stdout, cmd.Stderr = &outB, &errB
	err := cmd.Run()
	rc := 0
	if err != nil {
		ee, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatalf("exec %s: %v (stderr %s)", c.name, err, errB.String())
		}
		rc = ee.ExitCode()
	}
	out := strings.TrimSpace(outB.String())
	kind := ""
	var top map[string]any
	if json.Unmarshal([]byte(out), &top) == nil {
		if k, ok := top["kind"].(string); ok {
			kind = k
		}
	}
	return rc, kind, out
}

func s1Typed(k string) bool {
	switch k {
	case "needs_arg", "bad_arg", "out_of_scope", "no_engine":
		return true
	}
	return false
}

// s1DataSig returns a compact signature of non-empty leaves in a JSON result.
func s1DataSig(v any) (string, bool) {
	var sig []string
	var walk func(any, string)
	walk = func(x any, p string) {
		switch n := x.(type) {
		case map[string]any:
			for k, vv := range n {
				walk(vv, p+"."+k)
			}
		case []any:
			if len(n) > 0 {
				sig = append(sig, fmt.Sprintf("%s[%d]", p, len(n)))
			}
		case string:
			if n != "" {
				sig = append(sig, p+"=str")
			}
		case float64:
			if n > 0 {
				sig = append(sig, p+"="+strconv.FormatFloat(n, 'f', -1, 64))
			}
		case bool:
			if n {
				sig = append(sig, p+"=true")
			}
		}
	}
	walk(v, "")
	return strings.Join(sig, ","), len(sig) > 0
}

func s1Short(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 220 {
		return s[:220] + "..."
	}
	return s
}
