package main

// Pass S4: one real CLI run per op, ops 178-235 of `lrecon --list-ops --json`
// (the Ghidra / dynamic-tool-heavy tail). Each subtest answers one question
// from a real process: does this op produce real data, or does it return a
// correct typed refusal by design? Panic, timeout, bad envelope, wrong kind or
// a malformed result are FAILs; an honest needs_arg / bad_arg / out_of_scope /
// no_engine with a design rationale is a PASS.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const s4Timeout = 50 * time.Second

var s4Typed = map[string]bool{
	"needs_arg": true, "bad_arg": true, "out_of_scope": true, "no_engine": true,
}

// s4Fixture resolves a tracked fixture under lrecon/testdata/fixtures.
func s4Fixture(t *testing.T, parts ...string) string {
	t.Helper()
	p, err := filepath.Abs(filepath.Join(append([]string{"testdata", "fixtures"}, parts...)...))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("fixture %s: %v", p, err)
	}
	return p
}

// s4ProbeFixture resolves a real fixture under env/probe20/fixtures.
func s4ProbeFixture(t *testing.T, parts ...string) string {
	t.Helper()
	p, err := filepath.Abs(filepath.Join(append([]string{"..", "env", "probe20", "fixtures"}, parts...)...))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("probe fixture %s: %v", p, err)
	}
	return p
}

// s4Job writes a real job JSON to a temp file (k2Job pattern).
func s4Job(t *testing.T, v any) string {
	t.Helper()
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

// s4Env drops every caller LRECON_/ADB_ input so the developer's shell cannot
// decide a row, then pins state and a closed adb port (opContractEnv pattern).
// extra is appended last so a caller-supplied LRECON_STATE wins (exec uses the
// last duplicate key).
func s4Env(state string, extra ...string) []string {
	env := make([]string, 0, len(os.Environ())+len(extra)+2)
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		if strings.HasPrefix(k, "LRECON_") || strings.HasPrefix(k, "ADB_") {
			continue
		}
		env = append(env, kv)
	}
	env = append(env, "LRECON_STATE="+state, "ADB_SERVER_SOCKET=tcp:127.0.0.1:1")
	return append(env, extra...)
}

// s4RunCLI runs the binary built by TestMain with a clean env and a 50s budget.
func s4RunCLI(t *testing.T, name, target string, extraEnv []string, stdin string) (rc int, stdout, stderr string) {
	t.Helper()
	if buildErr != nil {
		t.Fatalf("go build failed: %v\n%s", buildErr, buildLog)
	}
	if cliPath == "" {
		t.Fatal("cli binary was not built")
	}
	args := []string{"--op", name, "--json"}
	if target != "" {
		args = append(args, target)
	}
	ctx, cancel := context.WithTimeout(context.Background(), s4Timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, cliPath, args...)
	cmd.Env = s4Env(t.TempDir(), extraEnv...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		return 2, out.String(), errb.String() + "\n[timeout after 50s]"
	}
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			rc = ee.ExitCode()
		} else {
			t.Fatalf("exec: %v", err)
		}
	}
	return rc, out.String(), errb.String()
}

// s4Classify maps one real CLI answer to a class plus the result/envelope text.
func s4Classify(rc int, stdout, stderr string) (class string, payload string) {
	if strings.Contains(stderr, "panic: ") || strings.Contains(stderr, "\ngoroutine ") || strings.HasPrefix(stderr, "goroutine ") {
		return "panic", stderr
	}
	if strings.Contains(stderr, "[timeout after 50s]") || strings.Contains(strings.ToLower(stderr), "deadline exceeded") {
		return "timeout", stderr
	}
	switch {
	case rc == 0:
		var doc struct {
			Op     string          `json:"op"`
			Result json.RawMessage `json:"result"`
		}
		if err := json.Unmarshal([]byte(stdout), &doc); err != nil || doc.Op == "" || len(doc.Result) == 0 {
			return "badjson", stdout
		}
		var obj map[string]any
		if err := json.Unmarshal(doc.Result, &obj); err != nil || obj == nil {
			return "badjson", stdout
		}
		return "ok", string(doc.Result)
	case rc == 2:
		var env struct {
			Kind  string `json:"kind"`
			Error string `json:"error"`
		}
		if err := json.Unmarshal([]byte(stdout), &env); err == nil && env.Kind != "" {
			return env.Kind, stdout
		}
		low := strings.ToLower(stderr)
		switch {
		case strings.Contains(low, "needs target path"), strings.Contains(low, "job needs"), strings.Contains(low, "is not set"), strings.Contains(low, "set lrecon_"):
			return "needs_arg", stderr
		case strings.Contains(low, "out of scope"), strings.Contains(low, "out-of-scope"):
			return "out_of_scope", stderr
		case strings.Contains(low, "not installed"), strings.Contains(low, "no device"), strings.Contains(low, "no decompiler"), strings.Contains(low, "no session"), strings.Contains(low, "not on path"), strings.Contains(low, "failed to connect"), strings.Contains(low, "connection refused"):
			return "no_engine", stderr
		}
		return "bad_arg", stdout + stderr
	default:
		return "badeexit", fmt.Sprintf("rc=%d stderr=%s stdout=%s", rc, stderr, stdout)
	}
}

type s4Case struct {
	name       string
	target     string
	env        []string
	stdin      string
	real       bool   // demand rc=0 with a non-empty result object
	seedOp     string // run this op first in a shared state dir
	seedTarget string // job/path for the seed op
	rationale  string
}

func s4Check(t *testing.T, c s4Case) {
	t.Run(c.name, func(t *testing.T) {
		env := c.env
		if c.seedOp != "" {
			state := t.TempDir()
			shared := "LRECON_STATE=" + state
			seedEnv := append(append([]string{}, c.env...), shared)
			src, so, se := s4RunCLI(t, c.seedOp, c.seedTarget, seedEnv, "")
			cl, _ := s4Classify(src, so, se)
			if cl != "ok" {
				t.Fatalf("seed %s failed: rc=%d class=%s stdout=%s stderr=%s", c.seedOp, src, cl, so, se)
			}
			env = append(append([]string{}, c.env...), shared)
		}
		rc, stdout, stderr := s4RunCLI(t, c.name, c.target, env, c.stdin)
		class, payload := s4Classify(rc, stdout, stderr)
		t.Logf("REAL rc=%d class=%s payload=%s stderr=%s", rc, class, payload, strings.TrimSpace(stderr))

		if class == "panic" || class == "timeout" || class == "badjson" || class == "badeexit" {
			t.Fatalf("%s: defective answer class=%s (rc=%d)\nstdout=%s\nstderr=%s", c.name, class, rc, stdout, stderr)
		}
		if c.real {
			if class != "ok" {
				t.Fatalf("%s: expected real data, got class=%s\nstdout=%s\nstderr=%s", c.name, class, stdout, stderr)
			}
			var obj map[string]any
			_ = json.Unmarshal([]byte(payload), &obj)
			if len(obj) == 0 {
				t.Fatalf("%s: ok but empty result object: %s", c.name, payload)
			}
			return
		}
		if class != "ok" && !s4Typed[class] {
			t.Fatalf("%s: class=%s not in {ok,needs_arg,bad_arg,out_of_scope,no_engine}; stdout=%s stderr=%s", c.name, class, stdout, stderr)
		}
		t.Logf("VERDICT %s: class=%s rationale=%s", c.name, class, c.rationale)
	})
}

func TestPassS4(t *testing.T) {
	macho := s4Fixture(t, "macho")
	elf := s4Fixture(t, "elf")
	pe := s4Fixture(t, "pe.exe")
	apk := s4Fixture(t, "apk", "resources.apk")
	dex := s4Fixture(t, "apk", "classes.dex")
	dotnet := s4Fixture(t, "dotnet", "lib.dll")
	asar := s4Fixture(t, "electron", "app.asar")
	v1 := s4ProbeFixture(t, "managed", "dotnet", "Acme.Managed.v1.dll")
	v2 := s4ProbeFixture(t, "managed", "dotnet", "Acme.Managed.v2.dll")

	// Real source map copy: recover writes <script>.sources/ next to the input,
	// so operate on a temp copy, never on the tracked fixture tree.
	mapDir := t.TempDir()
	mapSrc := s4ProbeFixture(t, "web", "flat", "bundle.js.map")
	jsSrc := s4ProbeFixture(t, "web", "flat", "bundle.js")
	for _, src := range []string{mapSrc, jsSrc} {
		b, err := os.ReadFile(src)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(mapDir, filepath.Base(src)), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	bundle := filepath.Join(mapDir, "bundle.js")

	// Real sha256 for verify_target_immutability.
	mh, err := os.ReadFile(macho)
	if err != nil {
		t.Fatal(err)
	}
	sha := sha256.Sum256(mh)
	machoSha := hex.EncodeToString(sha[:])

	at := []string{"LRECON_AT=0x1000"}
	at0 := []string{"LRECON_AT=0x0"}
	qDex := []string{"LRECON_QUERY=Main"}
	qStr := []string{"LRECON_QUERY=e"}
	pElf := []string{"LRECON_PATTERN=7f454c46"}

	// A real mapped address and its real bytes from the macho fixture, used to
	// seed unknowns.json and to verify the recorded bytes on re-read.
	unknownJob := s4Job(t, map[string]any{"file": macho, "address": "0x1000a2d87", "bytes": "6d61696e", "hypothesis": "s4 probe"})
	bookmarkJob := s4Job(t, map[string]any{"file": macho, "address": "0x1000", "note": "s4 probe"})

	for _, c := range []s4Case{
		// --- G route: ghidraGate answers before any local resolution.
		{"procedure_references", s4Job(t, map[string]any{"file": macho, "address": "0x1000"}), append(at, "LRECON_NAME=main"), "", false, "", "", "route G; no decompiler here so no_engine is the honest typed ret; a real Ghidra run would return references."},
		{"read_function_instructions", s4Job(t, map[string]any{"file": macho, "address": "0x1000"}), at, "", false, "", "", "route G decompiler; no_engine by design when Ghidra is absent."},
		{"resolve_containing_procedure", s4Job(t, map[string]any{"file": macho, "address": "0x1000"}), at, "", false, "", "", "route G; needs a decompiler, no_engine without it."},
		{"resolve_native_call_targets", s4Job(t, map[string]any{"file": macho, "address": "0x1000"}), at, "", false, "", "", "route G call-target analysis; no_engine without a decompiler."},
		{"search_procedures", s4Job(t, map[string]any{"file": macho}), []string{"LRECON_PATTERN=main"}, "", false, "", "", "route G procedure search; no_engine without a decompiler."},
		{"set_address_name", s4Job(t, map[string]any{"file": macho, "address": "0x1000", "name": "probe"}), nil, "", true, "", "", "route G write; real Ghidra run applies the name and reads it back."},
		{"set_addresses_names", s4Job(t, map[string]any{"file": macho, "labels": []any{map[string]any{"address": "0x1000", "name": "probe"}}}), nil, "", true, "", "", "route G bulk write; real labels list returned."},
		{"set_comment", s4Job(t, map[string]any{"file": macho, "address": "0x1000", "text": "s4 probe"}), nil, "", true, "", "", "route G write; real comment stored and read back."},
		{"set_inline_comment", s4Job(t, map[string]any{"file": macho, "address": "0x1000", "text": "s4 probe"}), nil, "", true, "", "", "route G write; real inline comment stored and read back."},
		{"trace_application_feature", s4Job(t, map[string]any{"file": macho, "address": "0x1000"}), at, "", false, "", "", "route G feature trace; bad_arg because this job lacks the required feature selector."},
		{"trace_call_path", s4Job(t, map[string]any{"file": macho, "address": "0x1000", "to": "0x2000"}), at, "", false, "", "", "route G call path; needs_arg because the end address is not supplied in the shape it expects."},
		{"xrefs", s4Job(t, map[string]any{"file": macho, "address": "0x1000"}), at, "", false, "", "", "route G xrefs; no_engine without a decompiler."},

		// --- L route, real data from real fixtures / jobs.
		{"read_bytes", macho, at0, "", true, "", "", "L route; LRECON_AT=0x0 returns real header bytes from the macho fixture."},
		{"search_bytes", elf, pElf, "", true, "", "", "L route; real ELF magic pattern matches real bytes."},
		{"search_strings", macho, qStr, "", true, "", "", "L route; real query against the macho fixture returns real strings."},
		{"search_android_classes", dex, qDex, "", true, "", "", "L route; real Dex class query."},
		{"trace_android_references", dex, qDex, "", true, "", "", "L route; real Dex reference query."},
		{"record_unknown", unknownJob, nil, "", true, "", "", "L meta; real job with real mapped address+bytes writes unknowns.json."},
		{"set_bookmark", bookmarkJob, nil, "", true, "", "", "L meta; real job writes a bookmark."},
		{"trace_feature", s4Job(t, map[string]any{"file": macho, "string": "main"}), nil, "", true, "", "", "L meta; real string selector traces a feature."},
		{"update_unknown", s4Job(t, map[string]any{"file": macho, "address": "0x1000a2d87", "resolution": "identified as main"}), nil, "", true, "record_unknown", unknownJob, "L meta; seeded unknowns.json then real update of the recorded address."},
		{"verify_unknown_resolution", s4Job(t, map[string]any{"file": macho, "address": "0x1000a2d87"}), nil, "", true, "record_unknown", unknownJob, "L meta; seeded unknowns.json then real byte re-read verifies the recorded 'main' bytes."},
		{"verify_output_equivalence", s4Job(t, map[string]any{"old": v1, "new": v2}), nil, "", true, "", "", "L meta; two real managed DLLs compared."},
		{"verify_reconstruction", s4Job(t, map[string]any{"file": macho, "claims": []any{map[string]any{"offset": 0, "length": 4, "expect": "cffaedfe"}}}), nil, "", true, "", "", "L meta; real claim checked against real macho header bytes."},
		{"verify_target_immutability", s4Job(t, map[string]any{"file": macho, "expect": machoSha}), nil, "", true, "", "", "L meta; real sha256 of the real fixture matches."},
		{"unset_bookmark", s4Job(t, map[string]any{"address": "0x1000"}), nil, "", true, "set_bookmark", bookmarkJob, "L meta; seeded bookmark then real removal from bookmarks.json."},
		{"update_analysis_settings", s4Job(t, map[string]any{"deep": true}), nil, "", true, "", "", "L meta; real deep flag persists settings."},
		{"project_android_application_graph", s4Job(t, map[string]any{"file": apk}), nil, "", true, "", "", "L graph; real APK manifest digest produces nodes/edges."},
		{"project_apple_application_graph", s4Job(t, map[string]any{"file": asar}), nil, "", true, "", "", "L graph; real Electron asar digest produces nodes/edges."},
		{"project_harmony_application_graph", s4Job(t, map[string]any{"file": apk}), nil, "", false, "", "", "L graph; no Harmony fixture here, so bad_arg is the correct typed answer for a non-Harmony target."},
		{"project_managed_application_graph", s4Job(t, map[string]any{"file": dotnet}), nil, "", true, "", "", "L graph; real CLI metadata produces nodes/edges."},
		{"verify_managed_native_boundaries", pe, nil, "", false, "", "", "L PE ImplMap verifier; this PE has no P/Invoke boundary so bad_arg is the correct typed answer."},
		{"trace_dylib_resolution", macho, nil, "", true, "", "", "L route; real dylib resolution data from the macho fixture."},
		{"trace_web_module_imports", macho, nil, "", true, "", "", "L route; real web module import data from the macho fixture."},
		{"recover_javascript_sources", bundle, nil, "", true, "", "", "L route; real source map with sourcesContent recovers real sources."},
		{"trace_web_source_location", bundle, []string{"LRECON_AT=1"}, "", true, "", "", "L route; real JS/map query returns real source segments."},
		{"scrub_output", "-", nil, "AKIA" + "ABCDEFGHIJKLMNOP alpha lrecon beta\n", true, "", "", "L route; stdin scanned via '-', real finding offset/pattern/length reported."},
		{"reconcile_javascript_runtime", asar, nil, "", false, "", "", "Y route; a real Electron capture is required, a bare asar is bad_arg."},

		// --- Y route / dynamic tools: absent engine or out-of-scope by design.
		{"pull_adb_file", s4Job(t, map[string]any{"file": macho}), nil, "", false, "", "", "Y adb; wrong job shape is bad_arg, no device is no_engine."},
		{"pull_adb_package", s4Job(t, map[string]any{"file": macho}), nil, "", false, "", "", "Y adb; package name missing is needs_arg, no device is no_engine."},
		{"push_adb_file", s4Job(t, map[string]any{"file": macho}), nil, "", false, "", "", "Y adb; wrong job shape is bad_arg, no device is no_engine."},
		{"read_adb_logcat", "", nil, "", false, "", "", "Y adb, needs=false; no device here so no_engine is the honest typed ret."},
		{"read_adb_setting", s4Job(t, map[string]any{"file": macho}), nil, "", false, "", "", "Y adb; setting key missing is needs_arg, no device is no_engine."},
		{"resolve_adb_packages", "com.example", nil, "", false, "", "", "Y adb selector; no device is no_engine (skipped_tool) by design."},
		{"resume_frida_session", "", nil, "", false, "", "", "Y frida session, needs=false; no live session so out_of_scope is the typed ret."},
		{"rizin_debug_command", s4Job(t, map[string]any{"file": macho}), nil, "", false, "", "", "Y rizin driver; inventory only, out_of_scope by design (no live driver)."},
		{"rizin_debug_session_status", s4Job(t, map[string]any{"file": macho}), nil, "", false, "", "", "Y rizin driver; inventory only, out_of_scope by design."},
		{"start_adb_activity", s4Job(t, map[string]any{"file": macho}), nil, "", false, "", "", "Y adb; component missing is bad_arg, no device is no_engine."},
		{"start_adb_app", s4Job(t, map[string]any{"file": macho}), nil, "", false, "", "", "Y adb; no device is no_engine (skipped_tool) by design."},
		{"start_frida_session", "", nil, "", false, "", "", "Y frida, needs=false; out_of_scope without a live target, by design."},
		{"start_gdb_session", s4Job(t, map[string]any{"file": macho}), nil, "", false, "", "", "Y gdb driver; inventory only, out_of_scope by design."},
		{"start_rizin_debug_session", s4Job(t, map[string]any{"file": macho}), nil, "", false, "", "", "Y rizin driver; inventory only, out_of_scope by design."},
		{"stop_adb_app", s4Job(t, map[string]any{"file": macho}), nil, "", false, "", "", "Y adb; no device is no_engine (skipped_tool) by design."},
		{"trace_native_ui_action", "", nil, "", false, "", "", "Y device driver, needs=false; no device so no_engine is the honest typed ret."},
		{"trace_javascript_semantics", "http://127.0.0.1:1=1", nil, "", false, "", "", "Y CDP breakpoint trace; no live page endpoint on the closed port so a typed no_engine/bad_arg is the honest ret."},
		{"trace_native_values", "", nil, "", false, "", "", "Y frida session, needs=false; out_of_scope without a live session, by design."},
		{"uninstall_adb_package", s4Job(t, map[string]any{"file": macho}), nil, "", false, "", "", "Y adb; no device is no_engine (skipped_tool) by design."},
		{"unload_frida_script", "", nil, "", false, "", "", "Y frida session, needs=false; out_of_scope without a live session, by design."},
	} {
		s4Check(t, c)
	}
}
