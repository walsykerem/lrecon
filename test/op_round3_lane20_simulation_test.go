package main

// Round 3 audit, lane 20: real behavior simulations (no fakes/mocks).
// Each test runs a real path in production code with meaningful input.

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// R3L20-1: inspect_artifact register + digests (REAL targets).
func TestR3L20InspectArtifactRealTargets(t *testing.T) {
	o, ok := ops["inspect_artifact"]
	if !ok || o.route != "L" || !o.needs {
		t.Fatalf("inspect_artifact registry = %+v", o)
	}
	for _, target := range []string{
		"/Users/keremurhan/kalitetest/test1",
		"/Users/keremurhan/kalitetest/test2",
		"/Users/keremurhan/walsyrea/lrecon/lrecon",
	} {
		st, err := os.Stat(target)
		if err != nil {
			t.Fatalf("stat %s: %v", target, err)
		}
		got, err := o.run(target)
		if err != nil {
			t.Fatalf("inspect_artifact(%s): %v", target, err)
		}
		m, ok := got.(struct {
			Document     string   `json:"document"`
			Kind         string   `json:"kind"`
			Format       string   `json:"format"`
			Size         int64    `json:"size"`
			SHA256       string   `json:"sha256,omitempty"`
			Slices       int      `json:"slices"`
			Toolchain    string   `json:"toolchain,omitempty"`
			Exports      int      `json:"exports"`
			Hardening    []string `json:"hardening"`
			Capabilities []string `json:"capabilities,omitempty"`
			Notes        []string `json:"notes,omitempty"`
		})
		if !ok || m.Document != target || m.Kind != "macho" || m.Size != st.Size() || m.SHA256 == "" {
			t.Fatalf("inspect_artifact(%s) = %+v", target, got)
		}
	}
}

// R3L20-2: inspect_native_load_image - skip reason + stat-before-refuse.
func TestR3L20InspectNativeLoadImageSkip(t *testing.T) {
	o := ops["inspect_native_load_image"]
	if o.route != "L" || !o.needs {
		t.Fatalf("registry = %+v", o)
	}
	got, err := o.run("/Users/keremurhan/kalitetest/test1")
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	s, ok := got.(*skip)
	if !ok || !strings.Contains(s.Reason, "never maps a loaded image") {
		t.Fatalf("skip = %+v", got)
	}
	if _, err := o.run("/Users/keremurhan/walsyrea/lrecon/no-such-file-r3l20"); err == nil {
		t.Fatal("missing target must io-error, not be hidden by the refusal")
	}
	if _, err := o.run(t.TempDir()); err == nil {
		t.Fatal("directory target must error")
	}
}

// R3L20-3: list_bookmarks - targetless, real state dir, job filter.
func TestR3L20ListBookmarksRealState(t *testing.T) {
	o := ops["list_bookmarks"]
	if o.route != "L" || o.needs {
		t.Fatalf("registry = %+v", o)
	}
	root := t.TempDir()
	job := filepath.Join(root, "job.json")
	body := `{"state":"` + root + `","file":"/Users/keremurhan/kalitetest/test1"}`
	if err := os.WriteFile(job, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := o.run(job)
	if err != nil {
		t.Fatalf("list_bookmarks: %v", err)
	}
	m := got.(map[string]any)
	if m["count"] != 0 || m["total"] != 0 || m["bookmarks_file"] != filepath.Join(root, "bookmarks.json") {
		t.Fatalf("bookmarks = %+v", m)
	}
	if err := os.WriteFile(filepath.Join(root, "bookmarks.json"), []byte(`[{"file":"/a","address":"0x1","note":"n","created":"c"},{"file":"/b","address":"0x2","note":"m","created":"d"}]`), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err = o.run(job)
	if err != nil {
		t.Fatal(err)
	}
	m = got.(map[string]any)
	if m["count"] != 0 || m["total"] != 2 || m["exists"] != true {
		t.Fatalf("filtered bookmarks = %+v", m)
	}
}

// R3L20-4: wasm import/export parser real byte stream (tag kinds + limits).
func TestR3L20WasmIfaceRealStream(t *testing.T) {
	// 8-byte magic+version, section 2 (imports) and 7 (exports).
	var mod, tag, imports, exports []byte
	mod = append(mod, nameBytes("env")...)
	mod = append(mod, nameBytes("log")...)
	mod = append(mod, 0x00, 0x00)
	tag = append(tag, nameBytes("env")...)
	tag = append(tag, nameBytes("t")...)
	tag = append(tag, 0x04, 0x00, 0x00)
	imports = append(imports, uleb(2)...)
	imports = append(imports, mod...)
	imports = append(imports, tag...)
	exports = append(exports, uleb(1)...)
	exports = append(exports, nameBytes("run")...)
	exports = append(exports, 0x00, 0x00)
	stream := []byte("\x00asm\x01\x00\x00\x00")
	stream = append(stream, 0x02)
	stream = append(stream, uleb(uint32(len(imports)))...)
	stream = append(stream, imports...)
	stream = append(stream, 0x07)
	stream = append(stream, uleb(uint32(len(exports)))...)
	stream = append(stream, exports...)
	dir := t.TempDir()
	f := filepath.Join(dir, "m.wasm")
	if err := os.WriteFile(f, stream, 0o644); err != nil {
		t.Fatal(err)
	}
	iface, err := readWasmIface(f)
	if err != nil {
		t.Fatalf("readWasmIface: %v (tag import refused)", err)
	}
	if !reflect.DeepEqual(iface.imports, []string{"env.log", "env.t"}) || !reflect.DeepEqual(iface.exports, []string{"run"}) {
		t.Fatalf("iface = %+v", iface)
	}
	// Non-wasm bytes are rejected.
	if _, err := readWasmIface("/Users/keremurhan/kalitetest/test1"); err == nil || !strings.Contains(err.Error(), "not a wasm module") {
		t.Fatalf("non-wasm err = %v", err)
	}
}

func uleb(n uint32) []byte {
	var out []byte
	for {
		b := byte(n & 0x7f)
		n >>= 7
		if n != 0 {
			b |= 0x80
		}
		out = append(out, b)
		if n == 0 {
			return out
		}
	}
}

func nameBytes(s string) []byte { return append(uleb(uint32(len(s))), []byte(s)...) }

// R3L20-5: checkMember rejects path traversal (zip-slip guard).
func TestR3L20CheckMemberRejectsTraversal(t *testing.T) {
	for _, m := range []string{"", "/etc/passwd", "../evil", "a/../b", `a\b`} {
		if err := checkMember(m); err == nil {
			t.Errorf("checkMember(%q) accepted", m)
		}
	}
	for _, m := range []string{"a", "lib/index.js", "a/b/c.txt"} {
		if err := checkMember(m); err != nil {
			t.Errorf("checkMember(%q) = %v", m, err)
		}
	}
}

// R3L20-6: real zip extraction through ExtractAll (electron/asar/zip route).
func TestR3L20ExtractAllRealZip(t *testing.T) {
	dir := t.TempDir()
	zp := filepath.Join(dir, "a.zip")
	f, err := os.Create(zp)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	w, err := zw.Create("lib/index.js")
	if err != nil {
		t.Fatal(err)
	}
	w.Write([]byte("console.log('r3l20')"))
	zw.Close()
	f.Close()
	out := filepath.Join(dir, "out")
	var d Digest
	if err := ExtractAll(zp, out, &d); err != nil {
		t.Fatalf("ExtractAll: %v", err)
	}
	b, err := os.ReadFile(filepath.Join(out, "lib", "index.js"))
	if err != nil || !bytes.Contains(b, []byte("r3l20")) {
		t.Fatalf("extracted = %q, %v", b, err)
	}
	if len(d.Notes) == 0 || !strings.Contains(d.Notes[len(d.Notes)-1], "extracted 1 files") {
		t.Fatalf("notes = %v", d.Notes)
	}
}

// R3L20-7: ghidraGate refuses non-decompilable kind before tool check.
func TestR3L20GhidraGateKindRefusal(t *testing.T) {
	// A zip/apk is not a decompiler target: refusal must name the kind, not
	// "install Ghidra" (op_ghidra_gate.go:24).
	zp := filepath.Join(t.TempDir(), "a.zip")
	f, _ := os.Create(zp)
	zw := zip.NewWriter(f)
	w, _ := zw.Create("x")
	w.Write([]byte("x"))
	zw.Close()
	f.Close()
	s := ghidraGate(zp)
	if s == nil || !strings.Contains(s.Reason, "no decompiler") {
		t.Fatalf("ghidraGate(zip) = %+v", s)
	}
	// A missing target is not hidden by an engine claim.
	if s := ghidraGate("/no/such/r3l20"); s != nil {
		t.Fatalf("ghidraGate(missing) = %+v, want io passthrough", s)
	}
}
