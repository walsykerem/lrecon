package main

// Pass S3: real-run evidence for ops at positions 119-177 of `lrecon --list-ops`.
// Every subtest calls the real runOp with a tracked fixture (or the real host
// tool), then checks either produced data or a design-correct typed refusal.
// No synthetic/shim data is used.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"testing"
)

func s3Fix(parts ...string) string {
	p := append([]string{"testdata", "fixtures"}, parts...)
	abs, err := filepath.Abs(filepath.Join(p...))
	if err != nil {
		panic(err)
	}
	return abs
}

func s3PFX(parts ...string) string {
	p := append([]string{"..", "env", "probe20", "fixtures"}, parts...)
	abs, err := filepath.Abs(filepath.Join(p...))
	if err != nil {
		panic(err)
	}
	return abs
}

func s3Raw(t *testing.T, name, target string) any {
	t.Helper()
	res, err := runOp(name, target)
	if err != nil {
		t.Fatalf("%s(%q): %v", name, target, err)
	}
	return res
}

// s3Val round-trips through JSON exactly like the real CLI --json envelope;
// this also proves the result is serializable.
func s3Val(t *testing.T, name, target string) any {
	t.Helper()
	b, err := json.Marshal(s3Raw(t, name, target))
	if err != nil {
		t.Fatalf("%s: marshal: %v", name, err)
	}
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatalf("%s: unmarshal: %v", name, err)
	}
	return v
}

func s3Obj(t *testing.T, name, target string) map[string]any {
	t.Helper()
	m, ok := s3Val(t, name, target).(map[string]any)
	if !ok {
		t.Fatalf("%s: result is not a JSON object", name)
	}
	return m
}

func s3Typed(t *testing.T, name, target string, want errorKind, reason string) {
	t.Helper()
	res, err := runOp(name, target)
	msg := ""
	switch {
	case err != nil:
		msg = err.Error()
	case res != nil:
		// A bare skip is the no_engine answer: the CLI turns it into a
		// refusal envelope, in-process it comes back as a *skip result.
		if sk, ok := res.(*skip); ok {
			msg = sk.Reason
		}
	}
	if msg == "" {
		t.Fatalf("%s(%q): expected typed %s, got success: %v", name, target, want, res)
	}
	if got := classify(msg); got != want {
		t.Fatalf("%s(%q): classify=%q want %q; msg=%q", name, target, got, want, msg)
	}
	t.Logf("typed=%s reason=%s msg=%s", want, reason, msg)
}

// s3TypedCLI is for ops whose run body calls refuseKind -> os.Exit(2): they
// cannot be called in-process without killing the test binary. Build the real
// CLI and read its --json refusal envelope.
func s3TypedCLI(t *testing.T, name, target string, want errorKind, reason string) {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "lrecon")
	build := exec.Command("go", "build", "-o", bin, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	args := []string{"--op", name, "--json"}
	if target != "" {
		args = append(args, target)
	}
	cmd := exec.Command(bin, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err == nil {
		t.Fatalf("%s(%q): expected refusal, CLI succeeded: %s", name, target, stdout.String())
	}
	var e struct {
		Kind  string `json:"kind"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &e); err != nil {
		t.Fatalf("%s: parse refusal %q (stderr %q): %v", name, stdout.String(), stderr.String(), err)
	}
	if e.Kind != string(want) {
		t.Fatalf("%s: kind=%q want %q; err=%q", name, e.Kind, want, e.Error)
	}
	t.Logf("typed=%s reason=%s err=%s", want, reason, e.Error)
}

func s3Has(t *testing.T, m map[string]any, keys ...string) {
	t.Helper()
	for _, k := range keys {
		if _, ok := m[k]; !ok {
			t.Fatalf("missing key %q in %v", k, m)
		}
	}
}

func s3Pos(t *testing.T, m map[string]any, key string) float64 {
	t.Helper()
	v, ok := m[key].(float64)
	if !ok || v <= 0 {
		t.Fatalf("%s = %v (%T), want >0; full=%v", key, m[key], m[key], m)
	}
	return v
}

func s3Arr(t *testing.T, m map[string]any, key string) []any {
	t.Helper()
	v, ok := m[key].([]any)
	if !ok {
		t.Fatalf("%s = %v (%T), want array; full=%v", key, m[key], m[key], m)
	}
	return v
}

func s3Eq(t *testing.T, m map[string]any, key string, want any) {
	t.Helper()
	if m[key] != want {
		t.Fatalf("%s = %v, want %v; full=%v", key, m[key], want, m)
	}
}

func s3NonEmpty(t *testing.T, m map[string]any, key string) string {
	t.Helper()
	v, ok := m[key].(string)
	if !ok || v == "" {
		t.Fatalf("%s = %v (%T), want non-empty string", key, m[key], m[key])
	}
	return v
}

// s3Ghidra runs a real headless-Ghidra op on the tracked ELF at a real function.
func s3Ghidra(t *testing.T, name string) map[string]any {
	t.Helper()
	t.Setenv("LRECON_NAME", "FUN_00401000")
	return s3Obj(t, name, s3Fix("elf"))
}

// s3Session opens a real session on the tracked fat Mach-O at a real function.
func s3Session(t *testing.T) string {
	t.Helper()
	t.Setenv("LRECON_STATE", t.TempDir())
	t.Setenv("LRECON_SESSION", "")
	fat := s3Fix("fatbin", "universal.fat")
	fns, err := nativeFunctions(fat)
	if err != nil || len(fns) == 0 {
		t.Fatalf("nativeFunctions(%s) = %d, %v", fat, len(fns), err)
	}
	t.Setenv("LRECON_AT", fmt.Sprintf("0x%x", fns[len(fns)/2].Start+1))
	if _, err := runOp("binary_session", fat); err != nil {
		t.Fatalf("binary_session: %v", err)
	}
	if _, err := runOp("goto_address", fat); err != nil {
		t.Fatalf("goto_address: %v", err)
	}
	return fat
}

func TestPassS3(t *testing.T) {
	// ---- 119-136: inspect / static real data -------------------------------
	t.Run("inspect_pcap_capture", func(t *testing.T) {
		m := s3Obj(t, "inspect_pcap_capture", s3Fix("pcap", "fixture.pcap"))
		s3Eq(t, m, "format", "pcap")
		s3Pos(t, m, "packets")
		if len(s3Arr(t, m, "protocols")) == 0 {
			t.Fatal("no protocols from real pcap")
		}
	})
	t.Run("inspect_pcap_client", func(t *testing.T) {
		m := s3Obj(t, "inspect_pcap_client", s3Fix("pcap", "fixture.pcap"))
		s3Has(t, m, "capture", "http_clients", "tls_clients")
		t.Logf("http_clients=%v tls_clients=%v", m["http_clients"], m["tls_clients"])
	})
	t.Run("inspect_pe_certificates", func(t *testing.T) {
		m := s3Obj(t, "inspect_pe_certificates", s3Fix("pe.exe"))
		s3Has(t, m, "present", "signed", "entries")
		s3Arr(t, m, "entries")
		t.Logf("present=%v signed=%v (unsigned PE is a valid real answer)", m["present"], m["signed"])
	})
	t.Run("inspect_pe_imports", func(t *testing.T) {
		m := s3Obj(t, "inspect_pe_imports", s3Fix("pe.exe"))
		s3Pos(t, m, "total")
		if len(s3Arr(t, m, "dlls")) == 0 || len(s3Arr(t, m, "imports")) == 0 {
			t.Fatal("no dlls/imports from real PE")
		}
	})
	t.Run("inspect_pe_load_config", func(t *testing.T) {
		m := s3Obj(t, "inspect_pe_load_config", s3Fix("pe.exe"))
		s3Has(t, m, "present", "declared_size", "security_cookie", "guard_flag_names")
		t.Logf("present=%v (absent load config is a valid parsed answer)", m["present"])
	})
	t.Run("inspect_pe_resources", func(t *testing.T) {
		m := s3Obj(t, "inspect_pe_resources", s3Fix("pe.exe"))
		s3Has(t, m, "present", "leaves", "types")
		s3Arr(t, m, "types")
		t.Logf("present=%v (no resource directory is a valid parsed answer)", m["present"])
	})
	t.Run("inspect_plist", func(t *testing.T) {
		m := s3Obj(t, "inspect_plist", s3Fix("keyed", "archive.plist"))
		if len(s3Arr(t, m, "keys")) == 0 {
			t.Fatal("no keys from real plist")
		}
	})
	t.Run("inspect_python_pyc", func(t *testing.T) {
		m := s3Obj(t, "inspect_python_pyc", s3Fix("pyc", "fixture_pyc.pyc"))
		s3NonEmpty(t, m, "toolchain")
		if len(s3Arr(t, m, "qualnames")) == 0 {
			t.Fatal("no qualnames from real pyc")
		}
	})
	t.Run("inspect_recorded_crash", func(t *testing.T) {
		m := s3Obj(t, "inspect_recorded_crash", s3Fix("ips", "ls.ips"))
		s3NonEmpty(t, m, "app")
		s3Has(t, m, "header", "images")
		s3Arr(t, m, "images")
	})
	t.Run("inspect_rust_binary", func(t *testing.T) {
		m := s3Obj(t, "inspect_rust_binary", s3Fix("rust", "fixture_rust"))
		s3NonEmpty(t, m, "kind")
		if len(s3Arr(t, m, "crates")) == 0 {
			t.Fatal("no crates from real Rust binary")
		}
	})
	t.Run("inspect_signal_decoders", func(t *testing.T) {
		t.Setenv("LRECON_QUERY", "usb")
		m := s3Obj(t, "inspect_signal_decoders", "")
		s3Eq(t, m, "query", "usb")
		s3NonEmpty(t, m, "table")
		s3Has(t, m, "matches")
	})
	t.Run("inspect_signature", func(t *testing.T) {
		m := s3Obj(t, "inspect_signature", s3Fix("macho"))
		s3NonEmpty(t, m, "magic")
		if len(s3Arr(t, m, "blobs")) == 0 {
			t.Fatal("no code-signing blobs from real Mach-O")
		}
	})
	t.Run("inspect_sqlite_database", func(t *testing.T) {
		m := s3Obj(t, "inspect_sqlite_database", s3Fix("sqlite", "fixture.db"))
		s3Pos(t, m, "page_size")
		if len(s3Arr(t, m, "tables")) == 0 {
			t.Fatal("no tables from real sqlite")
		}
	})
	t.Run("inspect_wasm_artifact", func(t *testing.T) {
		m := s3Obj(t, "inspect_wasm_artifact", s3Fix("wasm.wasm"))
		s3Eq(t, m, "magic", "\\0asm")
		if len(s3Arr(t, m, "sections")) == 0 {
			t.Fatal("no sections from real wasm")
		}
	})
	t.Run("inspect_web_event_listeners", func(t *testing.T) {
		s3Typed(t, "inspect_web_event_listeners", s3Fix("elf"), kindBadArg,
			"a plain ELF is not a DevTools endpoint; live listeners need host:port")
	})
	t.Run("inspect_web_network_capture", func(t *testing.T) {
		m := s3Obj(t, "inspect_web_network_capture", s3PFX("web", "real-capture.har"))
		s3NonEmpty(t, m, "version")
		s3Pos(t, m, "entries")
	})
	t.Run("inspect_web_page", func(t *testing.T) {
		s3Typed(t, "inspect_web_page", s3Fix("elf"), kindBadArg,
			"a plain ELF is not a DevTools endpoint; live pages need host:port")
	})
	t.Run("inspect_with_objdump", func(t *testing.T) {
		m := s3Obj(t, "inspect_with_objdump", s3Fix("elf"))
		s3NonEmpty(t, m, "tool")
		out := s3NonEmpty(t, m, "output")
		if len(out) < 32 {
			t.Fatalf("objdump output too short: %q", out)
		}
	})

	// ---- 137-154: device / session / static list real data ---------------
	t.Run("install_adb_package", func(t *testing.T) {
		s3Typed(t, "install_adb_package", s3Fix("apk", "classes.dex"), kindNoEngine,
			"no device attached; install needs a real device")
	})
	t.Run("instrument_with_frida", func(t *testing.T) {
		s3TypedCLI(t, "instrument_with_frida", "", kindOutOfScope,
			"live session attach is explicitly out of scope for a static-file reader")
	})
	t.Run("list_adb_devices", func(t *testing.T) {
		// Real `adb devices -l` table ([] may be empty) or a no_engine skip
		// when the host tool is absent: both are honest, non-fabricated.
		v := s3Val(t, "list_adb_devices", "")
		switch x := v.(type) {
		case []any:
			t.Logf("real android device table: %v", x)
		case map[string]any:
			t.Logf("typed skip (host adb absent): %v", x)
		default:
			t.Fatalf("unexpected result type %T", v)
		}
	})
	t.Run("list_adb_directory", func(t *testing.T) {
		s3Typed(t, "list_adb_directory", "/sdcard", kindNoEngine,
			"no device attached; `adb shell ls` needs one")
	})
	t.Run("list_adb_features", func(t *testing.T) {
		m := s3Obj(t, "list_adb_features", "")
		s3Has(t, m, "features", "count")
		if len(s3Arr(t, m, "features")) == 0 {
			t.Fatal("no host features from real adb host-features")
		}
	})
	t.Run("list_adb_packages", func(t *testing.T) {
		s3Typed(t, "list_adb_packages", "", kindNoEngine,
			"no device attached; `adb shell cmd package list packages -f` needs one")
	})
	t.Run("list_adb_processes", func(t *testing.T) {
		s3Typed(t, "list_adb_processes", "", kindNoEngine,
			"no device attached; `adb shell ps -A` needs one")
	})
	t.Run("list_adb_services", func(t *testing.T) {
		s3Typed(t, "list_adb_services", "", kindNoEngine,
			"no device attached; `adb shell dumpsys -l` needs one")
	})
	t.Run("list_architectures", func(t *testing.T) {
		m := s3Obj(t, "list_architectures", s3Fix("macho"))
		s3NonEmpty(t, m, "format")
		if len(s3Arr(t, m, "architectures")) == 0 {
			t.Fatal("no architectures from real Mach-O")
		}
	})
	t.Run("list_bookmarks", func(t *testing.T) {
		m := s3Obj(t, "list_bookmarks", "")
		s3Has(t, m, "bookmarks", "count", "total", "exists", "bookmarks_file")
		s3Arr(t, m, "bookmarks")
		t.Logf("real bookmark file: exists=%v count=%v", m["exists"], m["count"])
	})
	t.Run("list_browser_targets", func(t *testing.T) {
		s3Typed(t, "list_browser_targets", s3Fix("elf"), kindBadArg,
			"a plain ELF is not a DevTools endpoint; live targets need host:port")
	})
	t.Run("list_cutter_sessions", func(t *testing.T) {
		m := s3Obj(t, "list_cutter_sessions", "")
		s3Has(t, m, "cutter_processes", "projects", "searched", "process_source")
		if len(s3Arr(t, m, "searched")) == 0 {
			t.Fatal("no project dirs searched on real host")
		}
		t.Logf("real kernel process table / filesystem glob: cutter=%v projects=%v",
			m["cutter_processes"], m["projects"])
	})
	t.Run("list_documents", func(t *testing.T) {
		fat := s3Session(t)
		m := s3Obj(t, "list_documents", "")
		docs := s3Arr(t, m, "documents")
		if len(docs) == 0 {
			t.Fatal("no documents in real session")
		}
		d := docs[0].(map[string]any)
		s3Eq(t, d, "path", fat)
		s3Eq(t, d, "exists", true)
	})
	t.Run("list_electron_targets", func(t *testing.T) {
		s3Typed(t, "list_electron_targets", s3Fix("elf"), kindBadArg,
			"a plain ELF is not a DevTools endpoint; live Electron targets need host:port")
	})
	t.Run("list_frida_devices", func(t *testing.T) {
		m := s3Obj(t, "list_frida_devices", "")
		s3Has(t, m, "devices", "count", "note")
		s3Arr(t, m, "devices")
		t.Logf("real adb devices -l based frida device list: count=%v note=%v", m["count"], m["note"])
	})
	t.Run("list_frida_processes", func(t *testing.T) {
		m := s3Obj(t, "list_frida_processes", "")
		s3Has(t, m, "processes", "count", "device", "device_type", "note")
		if len(s3Arr(t, m, "processes")) == 0 {
			t.Fatal("no processes from real host")
		}
	})
	t.Run("list_javascript_runtime_targets", func(t *testing.T) {
		s3Typed(t, "list_javascript_runtime_targets", s3Fix("elf"), kindBadArg,
			"a plain ELF is not a DevTools endpoint; live JS targets need host:port")
	})
	t.Run("list_jeb_units", func(t *testing.T) {
		m := s3Obj(t, "list_jeb_units", s3Fix("apk", "classes.dex"))
		if len(s3Arr(t, m, "dex")) == 0 || len(s3Arr(t, m, "units")) == 0 {
			t.Fatal("no dex units from real DEX")
		}
	})
	t.Run("list_strings", func(t *testing.T) {
		m := s3Obj(t, "list_strings", s3Fix("elf"))
		s3Pos(t, m, "total")
		if len(s3Arr(t, m, "rows")) == 0 {
			t.Fatal("no strings from real ELF")
		}
	})
	t.Run("load_frida_script", func(t *testing.T) {
		s3TypedCLI(t, "load_frida_script", "", kindOutOfScope,
			"loading a script into a live session is explicitly out of scope")
	})

	// ---- 161-177: Ghidra, navigation, open, more Ghidra -------------------
	t.Run("match_native_functions", func(t *testing.T) {
		m := s3Ghidra(t, "match_native_functions")
		s3NonEmpty(t, m, "ghidra_version")
		s3Pos(t, m, "functions_hashed")
		s3Has(t, m, "groups", "basis")
	})
	t.Run("next_address", func(t *testing.T) {
		s3Session(t)
		m := s3Obj(t, "next_address", "")
		s3Eq(t, m, "found", true)
		s3NonEmpty(t, m, "from")
		to := s3NonEmpty(t, m, "to")
		if to == m["from"] {
			t.Fatal("next_address did not move the cursor")
		}
	})
	t.Run("observe_javascript_runtime", func(t *testing.T) {
		s3Typed(t, "observe_javascript_runtime", s3Fix("elf"), kindBadArg,
			"a plain ELF is not a DevTools endpoint; live JS runtime needs host:port")
	})
	t.Run("observe_native_calls", func(t *testing.T) {
		s3TypedCLI(t, "observe_native_calls", s3Fix("elf"), kindOutOfScope,
			"live call tracing is out of scope; the static answer is Ghidra")
	})
	t.Run("observe_native_ui", func(t *testing.T) {
		s3Typed(t, "observe_native_ui", "", kindNoEngine,
			"no device attached; `adb shell uiautomator dump` needs one")
	})
	t.Run("observe_web_execution", func(t *testing.T) {
		s3Typed(t, "observe_web_execution", s3Fix("elf"), kindBadArg,
			"a plain ELF is not a DevTools endpoint; live web execution needs host:port")
	})
	t.Run("observe_web_session", func(t *testing.T) {
		s3Typed(t, "observe_web_session", s3Fix("elf"), kindBadArg,
			"a plain ELF is not a DevTools endpoint; live web session needs host:port")
	})
	t.Run("open_binary", func(t *testing.T) {
		m := s3Obj(t, "open_binary", s3Fix("elf"))
		s3Eq(t, m, "kind", "elf")
		s3NonEmpty(t, m, "document")
		s3NonEmpty(t, m, "sha256")
	})
	t.Run("open_bundle_resources", func(t *testing.T) {
		m := s3Obj(t, "open_bundle_resources", s3Fix("car", "Assets.car"))
		s3Eq(t, m, "container", "BOMStore")
		s3Pos(t, m, "blocks")
	})
	t.Run("open_jeb_project", func(t *testing.T) {
		s3Typed(t, "open_jeb_project", s3Fix("apk", "classes.dex"), kindBadArg,
			"a DEX is not a readable APK zip; JEB project open needs a real APK")
	})
	t.Run("prev_address", func(t *testing.T) {
		s3Session(t)
		m := s3Obj(t, "prev_address", "")
		s3Eq(t, m, "found", true)
		s3NonEmpty(t, m, "to")
	})
	t.Run("list_names", func(t *testing.T) {
		m := s3Ghidra(t, "list_names")
		s3NonEmpty(t, m, "ghidra_version")
		s3Has(t, m, "names", "sample")
	})
	t.Run("list_procedures", func(t *testing.T) {
		m := s3Ghidra(t, "list_procedures")
		s3NonEmpty(t, m, "ghidra_version")
		s3Pos(t, m, "functions")
	})
	t.Run("list_segments", func(t *testing.T) {
		m := s3Ghidra(t, "list_segments")
		s3NonEmpty(t, m, "ghidra_version")
		s3Pos(t, m, "blocks")
		if len(s3Arr(t, m, "segments")) == 0 {
			t.Fatal("no segments from real Ghidra analysis")
		}
	})
	t.Run("list_unknowns", func(t *testing.T) {
		t.Setenv("LRECON_NAME", "FUN_00401000")
		m := s3Obj(t, "list_unknowns", s3Fix("elf"))
		s3Has(t, m, "count", "ranges", "bytes")
		s3Arr(t, m, "ranges")
	})
	t.Run("procedure_address", func(t *testing.T) {
		m := s3Ghidra(t, "procedure_address")
		s3NonEmpty(t, m, "entry")
		s3Pos(t, m, "size")
	})
	t.Run("procedure_assembly", func(t *testing.T) {
		m := s3Ghidra(t, "procedure_assembly")
		s3NonEmpty(t, m, "text")
		s3Pos(t, m, "instructions")
	})
	t.Run("procedure_callees", func(t *testing.T) {
		m := s3Ghidra(t, "procedure_callees")
		s3Has(t, m, "count", "edges")
		s3Arr(t, m, "edges")
	})
	t.Run("procedure_callers", func(t *testing.T) {
		m := s3Ghidra(t, "procedure_callers")
		s3Has(t, m, "count", "edges")
		s3Arr(t, m, "edges")
	})
	t.Run("procedure_info", func(t *testing.T) {
		m := s3Ghidra(t, "procedure_info")
		s3NonEmpty(t, m, "function")
		s3Has(t, m, "parameters", "locals", "calling_convention")
	})
	t.Run("procedure_pseudo_code", func(t *testing.T) {
		m := s3Ghidra(t, "procedure_pseudo_code")
		s3NonEmpty(t, m, "pseudocode")
		s3Pos(t, m, "lines")
	})
}
