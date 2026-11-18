package main

// TUR3 LANE 15 independent simulation tests. Calls the real lrecon binary
// (./lrecon) and real fixtures; verifies only real output.

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
)

const (
	r3l15Bin  = "./lrecon"
	r3l15T1   = "/Users/keremurhan/kalitetest/test1"
	r3l15Dex  = "testdata/fixtures/apk/classes.dex"
	r3l15From = "com.example.fix.Main"
)

// r3l15Run calls the real binary and decodes its stdout JSON. env holds extra
// environment variables (LRECON_AT, LRECON_FROM/TO); errors arrive in the stdout envelope.
func r3l15Run(t *testing.T, env []string, args ...string) map[string]any {
	t.Helper()
	c := exec.Command(r3l15Bin, args...)
	if len(env) > 0 {
		c.Env = append(os.Environ(), env...)
	}
	var out, errOut bytes.Buffer
	c.Stdout, c.Stderr = &out, &errOut
	_ = c.Run() // rc is in the stdout envelope or stderr; we read both.
	body := out.String()
	if strings.TrimSpace(body) == "" {
		body = errOut.String()
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		t.Fatalf("%v: not JSON (rc stdout=%q stderr=%q): %v", args, out.String(), errOut.String(), err)
	}
	return m
}

func r3l15Result(t *testing.T, m map[string]any) map[string]any {
	t.Helper()
	r, ok := m["result"].(map[string]any)
	if !ok {
		t.Fatalf("no result, envelope = %v", m)
	}
	return r
}

// dotnetsf.go: the 7-bit length prefix and header table decode real bytes.
func TestR3L15DotnetBundleHeader(t *testing.T) {
	b := []byte{2, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 4, 'a', 'b', 'c', 'd'}
	b = append(b, make([]byte, 40)...) // v2 sidecar: deps/runtimeconfig + flags
	h, ok := parseBundleHeader(b)
	if !ok || h.major != 2 || h.files != 3 || h.id != "abcd" {
		t.Fatalf("header = %+v ok=%v", h, ok)
	}
	if h.entriesFrom != 57 {
		t.Fatalf("entriesFrom = %d, want 57", h.entriesFrom)
	}
	// read7: a 1-byte prefix, a 3-byte string, overflow rejection.
	s, n, ok := read7([]byte{3, 'x', 'y', 'z', 'w'}, 0, 16)
	if !ok || s != "xyz" || n != 4 {
		t.Fatalf("read7 = %q,%d,%v", s, n, ok)
	}
	if _, _, ok := read7([]byte{0x80, 0x80, 0x80, 0x80, 0x80}, 0, 16); ok {
		t.Fatal("5-byte overflowing prefix must be refused")
	}
}

// readcap.go: exceeding the limit is an error, not a silent truncation.
func TestR3L15ReadCapped(t *testing.T) {
	p := writeTemp(t, "r3l15_cap.bin", []byte("abcdefghij"))
	b, err := readCapped(p, 10)
	if err != nil || string(b) != "abcdefghij" {
		t.Fatalf("exact fit: %q, %v", b, err)
	}
	if _, err := readCapped(p, 9); err == nil {
		t.Fatal("a file over the cap must error, not truncate")
	}
}

// op_inspect_native_api.go — real Mach-O, 5 real imports.
func TestR3L15InspectNativeAPI(t *testing.T) {
	r := r3l15Result(t, r3l15Run(t, nil, "--op", "inspect_native_api", r3l15T1, "--json"))
	if r["format"] != "macho" || r["imports"] != float64(5) {
		t.Fatalf("imports = %v format=%v, want 5/macho", r["imports"], r["format"])
	}
	rows, _ := r["rows"].([]any)
	if len(rows) != 5 {
		t.Fatalf("rows = %d, want 5", len(rows))
	}
}

// op_inspect_android_method.go — real dex, 2 real methods (code_off 680).
func TestR3L15InspectAndroidMethod(t *testing.T) {
	r := r3l15Result(t, r3l15Run(t, nil, "--op", "inspect_android_method", r3l15Dex+"#"+r3l15From, "--json"))
	if r["methods"] != float64(2) {
		t.Fatalf("methods = %v, want 2", r["methods"])
	}
	rows, _ := r["rows"].([]any)
	if len(rows) != 2 {
		t.Fatalf("rows = %d, want 2", len(rows))
	}
	main, _ := rows[1].(map[string]any)
	if main["name"] != "main" || main["code_off"] != float64(680) {
		t.Fatalf("row[1] = %v, want main/code_off 680", main)
	}
}

// op_list_adb_features.go — real adb server feature list.
func TestR3L15ListADBFeatures(t *testing.T) {
	r := r3l15Result(t, r3l15Run(t, nil, "--op", "list_adb_features", "--json"))
	n, _ := r["count"].(float64)
	if n < 1 {
		t.Fatalf("count = %v, want > 0", r["count"])
	}
	feats, _ := r["features"].([]any)
	if len(feats) != int(n) {
		t.Fatalf("features = %d != count %v", len(feats), n)
	}
}

// op_resolve_containing_procedure.go — G op, real Ghidra address.
func TestR3L15ResolveContainingProcedure(t *testing.T) {
	r := r3l15Result(t, r3l15Run(t, []string{"LRECON_AT=0x100000500"},
		"--op", "resolve_containing_procedure", r3l15T1, "--json"))
	if r["found"] != true || r["function"] != "entry" || r["offset_in_function"] != float64(24) {
		t.Fatalf("resolve = %v, want entry+24", r)
	}
}

// op_address_to_file_offset.go — G op, real file offset 1256.
func TestR3L15AddressToFileOffset(t *testing.T) {
	r := r3l15Result(t, r3l15Run(t, []string{"LRECON_AT=0x1000004e8"},
		"--op", "address_to_file_offset", r3l15T1, "--json"))
	if r["file_offset_resolved"] != true || r["file_offset"] != float64(1256) {
		t.Fatalf("offset = %v, want resolved/1256", r)
	}
}

// op_compare_functions.go — G op, comparison of two real functions.
func TestR3L15CompareFunctions(t *testing.T) {
	r := r3l15Result(t, r3l15Run(t, []string{"LRECON_FROM=0x1000004e8", "LRECON_TO=0x1000006cc"},
		"--op", "compare_functions", r3l15T1, "--json"))
	if r["union_lines"] == nil || r["similarity"] == nil {
		t.Fatalf("compare = %v, want similarity/union_lines", r)
	}
	a, _ := r["a"].(map[string]any)
	b, _ := r["b"].(map[string]any)
	if a["decompiled"] != true || b["decompiled"] != true {
		t.Fatalf("both functions must decompile: %v", r)
	}
}

// op_ext_lldb_memory.go — Y route: needs_arg when an argument is missing, no_engine
// when there is no live process. No route writes to the target.
func TestR3L15LldbExtOps(t *testing.T) {
	cases := []struct {
		op   string
		kind string
	}{
		{"lldb_register_read", "no_engine"},
		{"lldb_register_write", "no_engine"},
		{"lldb_memory_read", "needs_arg"},
		{"lldb_memory_write", "needs_arg"},
		{"lldb_expression", "needs_arg"},
		{"lldb_process_attach", "needs_arg"},
	}
	for _, c := range cases {
		t.Run(c.op, func(t *testing.T) {
			m := r3l15Run(t, nil, "--ext-op", c.op, r3l15T1, "--json")
			if m["kind"] != c.kind {
				t.Fatalf("kind = %v, want %s (err=%v)", m["kind"], c.kind, m["error"])
			}
		})
	}
}

// op_observe_native_ui.go — no_engine when there is no device; does not write to the target.
func TestR3L15ObserveNativeUI(t *testing.T) {
	m := r3l15Run(t, nil, "--op", "observe_native_ui", r3l15T1, "--json")
	if m["kind"] != "no_engine" {
		t.Fatalf("kind = %v, want no_engine", m["kind"])
	}
}

// op_trace_javascript_semantics.go — file is not a DevTools endpoint: bad_arg.
func TestR3L15TraceJavascriptSemantics(t *testing.T) {
	m := r3l15Run(t, nil, "--op", "trace_javascript_semantics", r3l15T1, "--json")
	if m["kind"] != "bad_arg" {
		t.Fatalf("kind = %v, want bad_arg", m["kind"])
	}
}
