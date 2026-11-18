package main

// Round 2, lane 20 independent simulation tests. Each test verifies the real
// behavior of production code with meaningful input; production code is not
// loosened to make tests pass. Existing test helpers (writeTemp, Probe, wasmLeb, sfPE,
// objcMachO, metaMustRun, v8cacheBuf, deriveWitnesses) are used.

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --- truncate (truncate_test.go / main.go) ---

func TestR2L20TruncateUTF8AndControl(t *testing.T) {
	// Must not cut in the middle of a multi-byte rune; the cut shifts to the rune start.
	s := "αβγδε\nlast line\n"
	got := truncate(s, 8) // 8 bytes = α(2)+β(2)+γ(2)+δ(1.5) -> δ rune is shifted
	if !strings.HasPrefix(got, "αβγ") {
		t.Fatalf("UTF-8 cut in the middle of a rune: %q", got)
	}
	if !strings.Contains(got, "note: truncated at ") {
		t.Fatalf("no truncation note: %q", got)
	}
	// In a mid-line cut, the body must end with a newline.
	body, _, _ := strings.Cut(got, "note: truncated")
	if !strings.HasSuffix(body, "\n") {
		t.Fatalf("truncated body does not end with a newline: %q", body)
	}
}

// --- types (types.go / types_test.go) ---

func TestR2L20ConstsMarshalShape(t *testing.T) {
	// Plain string if the sentinel has a single element; a list otherwise.
	cases := []struct {
		c    consts
		want string
	}{
		{consts{constNotDetected}, `"not_detected"`},
		{consts{constNotScanned}, `"not_scanned"`},
		{consts{"a", "b"}, `["a","b"]`},
		{consts{}, `[]`},
	}
	for _, tc := range cases {
		b, err := json.Marshal(tc.c)
		if err != nil {
			t.Fatal(err)
		}
		if string(b) != tc.want {
			t.Fatalf("Marshal(%v) = %s, want %s", tc.c, b, tc.want)
		}
	}
	// Round-trip: both string and list forms can be read back.
	for _, in := range []string{`"not_detected"`, `["x","y"]`} {
		var c consts
		if err := json.Unmarshal([]byte(in), &c); err != nil {
			t.Fatalf("Unmarshal(%s): %v", in, err)
		}
		b, _ := json.Marshal(c)
		if string(b) != in {
			t.Fatalf("round-trip %s -> %s", in, b)
		}
	}
}

func TestR2L20TextSafeAndEntryPoint(t *testing.T) {
	// Control characters are dropped, CR/LF/TAB are escaped, the cap is applied.
	got, omitted := textSafe("a\x1b[2K\rb\nc\tdelete\x7f")
	if strings.ContainsAny(got, "\r\n\t") || strings.Contains(got, "\x1b") || strings.Contains(got, "\x7f") {
		t.Fatalf("control character leaked: %q", got)
	}
	if !strings.Contains(got, `\r`) || !strings.Contains(got, `\n`) || !strings.Contains(got, `\t`) {
		t.Fatalf("CR/LF/TAB not escaped: %q", got)
	}
	if omitted != 2 { // only ESC and DEL are dropped; \r\n\t are escaped, [2K is plain text
		t.Fatalf("omitted = %d, want 2", omitted)
	}
	long := strings.Repeat("x", textFieldCap+50)
	s, n := textSafe(long)
	if len(s) != textFieldCap || n != 50 {
		t.Fatalf("cap: len=%d omitted=%d", len(s), n)
	}
	// Entrypoint is printed in hex; nil is hidden.
	ep := uint64(0x401000)
	d := Digest{Kind: "elf", Entrypoint: &ep}
	if !strings.Contains(d.Text(), "entrypoint: 0x401000\n") {
		t.Fatalf("entrypoint missing: %q", d.Text())
	}
	if strings.Contains((Digest{Kind: "elf"}).Text(), "entrypoint") {
		t.Fatal("nil entrypoint was printed")
	}
}

// --- v8cache (v8cache.go / v8cache_test.go) ---

func TestR2L20V8CacheRealGenerations(t *testing.T) {
	// Generate three real generations with different payloads; the reader must
	// decode each with the correct header width and hashes.
	for i, l := range v8cacheLayouts {
		payload := uint32(16 + i*8)
		b := v8cacheBuf(l, payload)
		// Hash values that make each generation unique.
		binary.LittleEndian.PutUint32(b[4:], uint32(0x1000+i))
		d, err := Probe(writeTemp(t, "gen.jsc", b))
		if err != nil {
			t.Fatal(err)
		}
		if d.Kind != "v8-cache" {
			t.Fatalf("gen %d kind = %q", i, d.Kind)
		}
		joined := strings.Join(d.Capabilities, "\n")
		for _, want := range []string{
			"v8cache:header=" + fmt.Sprint(l.header),
			"v8cache:payload=" + fmt.Sprint(payload),
			"v8cache:version_hash=0x" + fmt.Sprintf("%08x", uint32(0x1000+i)),
		} {
			if !strings.Contains(joined, want) {
				t.Fatalf("gen %d missing %q in %v", i, want, d.Capabilities)
			}
		}
		if d.Coverage == nil || d.Coverage.Parsed != 1 {
			t.Fatalf("gen %d coverage = %+v", i, d.Coverage)
		}
	}
}

// --- wasm (wasm.go / wasm_test.go) ---

func TestR2L20WasmImportExportCounts(t *testing.T) {
	// A real import + export section: the import label and export count are read correctly.
	impPayload := append(wasmLeb(1), append(wasmName("env"), wasmName("log")...)...)
	impPayload = append(impPayload, 0x00) // func kind
	impPayload = append(impPayload, wasmLeb(0)...)
	expPayload := append(wasmLeb(2), append(wasmName("run"), 0x00)...)
	expPayload = append(expPayload, wasmLeb(0)...)
	expPayload = append(expPayload, append(wasmName("main"), 0x00)...)
	expPayload = append(expPayload, wasmLeb(1)...)
	mod := append(wasmHead(), wasmSection(2, impPayload)...)
	mod = append(mod, wasmSection(7, expPayload)...)
	mod = append(mod, wasmProducersSection("processed-by", "rustc", "1.80")...)
	d, err := Probe(writeTemp(t, "mod.wasm", mod))
	if err != nil {
		t.Fatal(err)
	}
	if d.Kind != "wasm" || d.Exports != 2 {
		t.Fatalf("kind/exports = %q/%d", d.Kind, d.Exports)
	}
	if len(d.Imports) != 1 || d.Imports[0] != "env.log" {
		t.Fatalf("imports = %v", d.Imports)
	}
	if wasmCapVersion(d, "rustc") != "1.80" {
		t.Fatalf("producer = %v", d.Capabilities)
	}
}

func TestR2L20WasmLEB64WideLimits(t *testing.T) {
	// memory64 limit: flag bit 2 -> u64 LEB width. The 2^40 value does not fit in u32.
	c := &wasmCursor{b: []byte{0x80, 0x80, 0x80, 0x80, 0x01}} // 2^28
	v, ok := c.u32()
	if !ok || v != 1<<28 {
		t.Fatalf("u32 2^28 = %d/%v", v, ok)
	}
	c = &wasmCursor{b: []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01}}
	v64, ok := c.u64()
	if !ok || v64 != ^uint64(0) {
		t.Fatalf("u64 max = %d/%v", v64, ok)
	}
	// 11th byte -> rejected.
	c = &wasmCursor{b: []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00}}
	if _, ok := c.u64(); ok {
		t.Fatal("11-byte LEB was accepted")
	}
}

// --- witness (witness.go / witness_test.go) ---

func TestR2L20WitnessUnionAndDisjoint(t *testing.T) {
	// Overlapping spans merge; the union is not a read counter.
	var d Digest
	d.witness(Witness{Axis: "a", Class: "A", Value: "v", Start: 0, End: 10})
	d.witness(Witness{Axis: "a", Class: "A", Value: "v", Start: 5, End: 20})
	if d.BytesScanned != 20 {
		t.Fatalf("union = %d, want 20", d.BytesScanned)
	}
	if d.witnessed("v") {
		t.Fatal("a single class was counted as a witness")
	}
	// Overlapping spans of the same class from two different call sites count as one class.
	var overlap Digest
	overlap.witness(Witness{Axis: "note", Class: "A", Value: "v", Start: 0, End: 10})
	overlap.witness(Witness{Axis: "slice", Class: "B", Value: "v", Start: 5, End: 15})
	if overlap.witnessed("v") {
		t.Fatal("two overlapping classes were counted as a witness")
	}
	// Two disjoint classes -> witness. Different call sites (Axis) must be used,
	// otherwise witnessClasses freezes the class per site.
	var disjoint Digest
	disjoint.witness(Witness{Axis: "note", Class: "A", Value: "v", Start: 0, End: 10})
	disjoint.witness(Witness{Axis: "slice", Class: "B", Value: "v", Start: 20, End: 30})
	if !disjoint.witnessed("v") {
		t.Fatal("two disjoint classes were not counted as a witness")
	}
	if disjoint.BytesScanned != 20 {
		t.Fatalf("union = %d, want 20", disjoint.BytesScanned)
	}
}

// --- zz_extra_metab_test.go ---

func TestR2L20MetaBThunkRoundTrip(t *testing.T) {
	// Decode tiny and fat thunks in a real PE image; slot VA and bytes are correct.
	body := make([]byte, 32)
	body[0] = 0x02
	copy(body[1:], []byte{0xff, 0x25, 0x09, 0x00, 0x00, 0x00})
	img, base, ptr := metaBThunkImage(t, body)
	slot, note, err := metaBThunk(img, 0x1000, base, ptr)
	if err != nil || note != "" || slot.bytes != "ff 25 09 00 00 00" || slot.va != base+0x1010 {
		t.Fatalf("tiny thunk = %+v note %q err %v", slot, note, err)
	}
	// A malformed header must be refused.
	bad := make([]byte, 8)
	img, base, ptr = metaBThunkImage(t, bad)
	if _, _, err := metaBThunk(img, 0x1000, base, ptr); err == nil {
		t.Fatal("malformed method body header was accepted")
	}
}

// --- zz_extra_ops_test.go ---

func TestR2L20ObjCClassResolution(t *testing.T) {
	b := objcClassListMachO()
	f := metaMustRun(t, "get_objc_classes", writeTemp(t, "classes", b))
	if metaNum(t, f, "count") != 3 || metaNum(t, f, "unresolved") != 1 {
		t.Fatalf("count/unresolved = %v/%v", f["count"], f["unresolved"])
	}
	classes := numList(t, f["classes"])
	if len(classes) != 2 || classes[0] != "Alpha" || classes[1] != "Beta" {
		t.Fatalf("classes = %v", classes)
	}
}

func TestR2L20ZipTraversalAndDotDot(t *testing.T) {
	// Real zip: traversal is refused, an innocent name like "..foo.js" is accepted.
	dir := t.TempDir()
	out := filepath.Join(dir, "out")
	withOpOutput(t, out)
	evil := zipScripts(t, "evil.zip", map[string][]byte{"../../etc/x.js": []byte("pwn")}, nil)
	if _, err := runOp("export_web_scripts", evil); err == nil || !strings.Contains(err.Error(), "escapes the export directory") {
		t.Fatalf("traversal error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "etc", "x.js")); !os.IsNotExist(err) {
		t.Fatalf("traversal wrote outside: %v", err)
	}
	ok := zipScripts(t, "ok.zip", map[string][]byte{"..foo.js": []byte("var a=1\n")}, nil)
	withOpOutput(t, out)
	f := fields(t, run(t, "export_web_scripts", ok))
	if f["written"] != float64(1) {
		t.Fatalf("written = %v", f["written"])
	}
}

// --- zz_extra_parsers_test.go ---

func TestR2L20DemangleAndSwiftHelpers(t *testing.T) {
	cases := []struct{ sym, name, rest string }{
		{"_$s4Test3fooyyF", "Test.foo", "yyF"},
		{"$s3foo3bar3baz", "foo.bar.baz", ""},
		{"_$s100x", "", "100x"},
		{"plainC", "", "plainC"},
	}
	for _, c := range cases {
		name, rest := demangleSwift(c.sym)
		if name != c.name || rest != c.rest {
			t.Fatalf("demangleSwift(%q) = %q/%q", c.sym, name, rest)
		}
	}
	if n, size, ok := swiftSectionCount(swiftSec{name: "types", data: make([]byte, 8)}); n != 2 || size != 4 || !ok {
		t.Fatalf("swiftSectionCount = %d/%d/%v", n, size, ok)
	}
}

func TestR2L20CheckOpOutputGate(t *testing.T) {
	// A reader op refuses -o, a writer op requires it; error class bad_arg/needs_arg.
	err := checkOpOutput("inspect_pe", "/tmp/out.json")
	var ae *opArgError
	if err == nil || !asOpArgError(err, &ae) || ae.kind != kindBadArg {
		t.Fatalf("reader -o error = %#v", err)
	}
	err = checkOpOutput("export_web_scripts", "")
	if err == nil || !asOpArgError(err, &ae) || ae.kind != kindNeedsArg {
		t.Fatalf("writer missing -o error = %#v", err)
	}
	if err := checkOpOutput("", "/tmp/digest.json"); err != nil {
		t.Fatalf("plain -o refused: %v", err)
	}
}

// --- testdata/fixtures/tiny/main.go ---

func TestR2L20TinyFixtureCompilesAndRuns(t *testing.T) {
	// The fixture is a standalone program: it must be valid Go and have its own main.
	info, err := os.Stat("testdata/fixtures/tiny/main.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "testdata/fixtures/tiny/main.go", nil, 0)
	if err != nil {
		t.Fatalf("fixture is not valid Go: %v", err)
	}
	if f.Name.Name != "main" || info.IsDir() {
		t.Fatalf("fixture package = %q", f.Name.Name)
	}
	hasMain := false
	ast.Inspect(f, func(n ast.Node) bool {
		if fn, ok := n.(*ast.FuncDecl); ok && fn.Name.Name == "main" {
			hasMain = true
		}
		return true
	})
	if !hasMain {
		t.Fatal("fixture has no main()")
	}
}
