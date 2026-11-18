package main

// Extra coverage for pure helpers that the op-level tests never reached:
// demangling, legacy session documents, dex note parsing, path trimming, the
// -o/--op gate and the P/Invoke boundary helpers. Each case asserts the value
// the helper returns, not merely that it did not fail.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestDemangleSwiftParts(t *testing.T) {
	cases := []struct {
		sym, name, rest string
	}{
		{"_$s4Test3fooyyF", "Test.foo", "yyF"},
		{"$s4Test3fooyyF", "Test.foo", "yyF"},
		{"_$s3foo3bar3baz", "foo.bar.baz", ""},
		{"_$s1a1b1c1d1e1f1g", "a.b.c.d.e.f", "1g"}, // six components is the cap
		{"_$s100x", "", "100x"},                    // a three-digit length is not a component
		{"_$s0a", "", "0a"},                        // zero length never consumes bytes
		{"_$s9short", "", "9short"},                // length beyond the body
		{"_$sabc", "", "abc"},                      // no digit run at all
		{"_$s", "", ""},
		{"plainC", "", "plainC"},
	}
	for _, c := range cases {
		name, rest := demangleSwift(c.sym)
		if name != c.name || rest != c.rest {
			t.Fatalf("demangleSwift(%q) = %q, %q; want %q, %q", c.sym, name, rest, c.name, c.rest)
		}
	}
}

func TestSessionLegacyDocument(t *testing.T) {
	write := func(t *testing.T, body string) string {
		t.Helper()
		p := filepath.Join(t.TempDir(), "session.json")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	cases := []struct {
		name, body, doc string
		ok              bool
	}{
		{"legacy", `{"document":"/tmp/a.bin"}`, "/tmp/a.bin", true},
		{"document plus non-string fields", `{"document":"x","project":"/tmp"}`, "x", true},
		{"new session kind", `{"kind":"lrecon.session/1","document":"x"}`, "", false},
		{"document not a string", `{"document":7}`, "", false},
		{"empty document", `{"document":""}`, "", false},
		{"not json", `document=/tmp/a`, "", false},
	}
	for _, c := range cases {
		p := write(t, c.body)
		doc, ok := sessionLegacyDocument(p)
		if doc != c.doc || ok != c.ok {
			t.Fatalf("%s: sessionLegacyDocument = %q/%v, want %q/%v", c.name, doc, ok, c.doc, c.ok)
		}
	}
	if doc, ok := sessionLegacyDocument(filepath.Join(t.TempDir(), "missing.json")); ok || doc != "" {
		t.Fatalf("missing file = %q/%v, want empty/false", doc, ok)
	}
}

func TestDexClassLines(t *testing.T) {
	d := Digest{Notes: []string{
		"  dex: class com.example.Beta super com.example.Alpha methods methods run,stop:()V  ",
		"dex: class com.example.Plain",
		"dex: class com.example.WithSuper super com.example.Base",
		"unrelated note",
		"dex: class  super com.example.Orphan",
	}}
	got := dexClassLines(d)
	if len(got) != 4 {
		t.Fatalf("parsed %d classes, want 4: %#v", len(got), got)
	}
	want := []metaNode{
		{Kind: "class", Name: "com.example.Beta", Super: "com.example.Alpha", Methods: []string{"run", "stop"}},
		{Kind: "class", Name: "com.example.Plain"},
		{Kind: "class", Name: "com.example.WithSuper", Super: "com.example.Base"},
		{Kind: "class", Name: "", Super: "com.example.Orphan"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("dexClassLines = %#v\nwant %#v", got, want)
	}
}

func TestLastPathPart(t *testing.T) {
	cases := map[string]string{
		"/System/Library/Frameworks/AppKit": "AppKit",
		"/System/Library/Frameworks/":       "Frameworks/", // suffix is measured on the untrimmed path
		"libsystem_kernel.dylib":            "libsystem_kernel.dylib",
		"":                                  "",
		"/":                                 "/",
	}
	for in, want := range cases {
		if got := lastPathPart(in); got != want {
			t.Fatalf("lastPathPart(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestBytes0(t *testing.T) {
	cases := []struct {
		in, want []byte
	}{
		{nil, nil},
		{[]byte{}, []byte{}},
		{[]byte("name\x00\x00"), []byte("name")},
		{[]byte{0, 0, 0}, []byte{}},
		{[]byte("no-trailer"), []byte("no-trailer")},
	}
	for _, c := range cases {
		if got := bytes0(c.in); !reflect.DeepEqual(got, c.want) {
			t.Fatalf("bytes0(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestCheckOpOutputGate(t *testing.T) {
	// -o is the digest destination on the plain path.
	if err := checkOpOutput("", "/tmp/digest.json"); err != nil {
		t.Fatalf("plain -o refused: %v", err)
	}
	// A reader op keeps stdout and must not be handed -o.
	if err := checkOpOutput("inspect_pe", "  "); err != nil {
		t.Fatalf("blank -o refused for a reader: %v", err)
	}
	err := checkOpOutput("inspect_pe", "/tmp/out.json")
	if err == nil {
		t.Fatal("reader op accepted -o")
	}
	var argErr *opArgError
	if !asOpArgError(err, &argErr) || argErr.kind != kindBadArg {
		t.Fatalf("reader -o error = %#v, want bad_arg", err)
	}
	if !strings.Contains(err.Error(), `-o does not apply to --op "inspect_pe"`) {
		t.Fatalf("reader -o message = %q", err)
	}
	// Tur4 #16: simulation.md item 16's "-o DIR writes report files" is
	// speculative for stdout-only ops like binary_overview: item 17 rejects
	// -o + --op as bad_arg, opWritesOutput lists only the 6 writing ops, and
	// checkOpOutput rejects -o on every reader. No dir-report writing for
	// binary_overview; this pins the reject so a sweep cannot mistake the
	// speculation for a feature.
	for _, name := range []string{"binary_overview", "inspect_pe"} {
		err := checkOpOutput(name, "/tmp/reports")
		if err == nil {
			t.Fatalf("%s accepted -o DIR; stdout-only ops must reject", name)
		}
		if !asOpArgError(err, &argErr) || argErr.kind != kindBadArg {
			t.Fatalf("%s -o DIR error = %#v, want bad_arg", name, err)
		}
	}
	// Writing ops need -o, and the message names the accepted form.
	for name, spec := range opWritesOutput {
		if err := checkOpOutput(name, ""); err == nil {
			t.Fatalf("%s accepted a missing -o", name)
		} else if !asOpArgError(err, &argErr) || argErr.kind != kindNeedsArg {
			t.Fatalf("%s missing -o error = %#v, want needs_arg", name, err)
		} else if !strings.Contains(err.Error(), spec) {
			t.Fatalf("%s missing -o message %q does not name %q", name, err, spec)
		}
		if err := checkOpOutput(name, "/tmp/out"); err != nil {
			t.Fatalf("%s refused a valid -o: %v", name, err)
		}
	}
}

// asOpArgError is errors.As without importing errors just for one type.
func asOpArgError(err error, dst **opArgError) bool {
	e, ok := err.(*opArgError)
	if ok {
		*dst = e
	}
	return ok
}

func TestPInvokeBoundaryHelpers(t *testing.T) {
	cc := map[uint16]string{
		0: "winapi", 0x0100: "cdecl", 0x0200: "stdcall", 0x0300: "thiscall",
		0x0400: "fastcall", 0x0500: "winapi", 0x0600: "cc6", 0x0700: "cc7",
	}
	for flags, want := range cc {
		if got := pinvokeCallConv(flags); got != want {
			t.Fatalf("pinvokeCallConv(%#x) = %q, want %q", flags, got, want)
		}
	}
	mods := []struct {
		module, library string
		want            bool
	}{
		{"kernel32", "kernel32.dll", true},
		{"KERNEL32.DLL", "kernel32.dll", true},
		{"kernel32.dll", "kernel32.dll", true},
		{"user32", "kernel32.dll", false},
	}
	for _, c := range mods {
		if got := sameModule(c.module, c.library); got != c.want {
			t.Fatalf("sameModule(%q,%q) = %v, want %v", c.module, c.library, got, c.want)
		}
	}
	imps := []struct {
		imported, name string
		want           bool
	}{
		{"_printf@8", "printf", true},
		{"printf", "_printf", true},
		{"_printf@8", "puts", false},
	}
	for _, c := range imps {
		if got := sameImport(c.imported, c.name); got != c.want {
			t.Fatalf("sameImport(%q,%q) = %v, want %v", c.imported, c.name, got, c.want)
		}
	}
	if got := joinNote("", "second"); got != "second" {
		t.Fatalf("joinNote(empty) = %q", got)
	}
	if got := joinNote("first", "second"); got != "first; second" {
		t.Fatalf("joinNote = %q", got)
	}

	imports := []nativeAPI{{Name: "CreateFileW", Stub: 0x1010}, {Name: "CloseHandle", Stub: 0x1020}}
	if got, ok := metaBImportAt(imports, 0x1010); !ok || got.Name != "CreateFileW" {
		t.Fatalf("metaBImportAt hit = %#v/%v", got, ok)
	}
	if got, ok := metaBImportAt(imports, 0x9999); ok || got.Name != "" {
		t.Fatalf("metaBImportAt miss = %#v/%v", got, ok)
	}
}

func TestSwiftSectionCountAndDescriptorName(t *testing.T) {
	if n, size, ok := swiftSectionCount(swiftSec{name: "types", data: make([]byte, 8)}); n != 2 || size != 4 || !ok {
		t.Fatalf("fixed section = %d/%d/%v, want 2/4/true", n, size, ok)
	}
	if n, size, ok := swiftSectionCount(swiftSec{name: "types", data: make([]byte, 6)}); n != 0 || size != 4 || ok {
		t.Fatalf("misaligned section = %d/%d/%v, want 0/4/false", n, size, ok)
	}
	if n, size, ok := swiftSectionCount(swiftSec{name: "fieldmd", data: make([]byte, 37)}); n != 0 || size != 37 || !ok {
		t.Fatalf("variable section = %d/%d/%v, want 0/37/true", n, size, ok)
	}

	// One relative descriptor at offset 0 of a `types` section: the target is
	// 12 bytes in, its name field points 12 bytes past itself to "MyType".
	const base = 0x8000
	data := make([]byte, 256)
	put32(data, 0, 12|2) // low two bits are flags and are masked off
	put32(data, 12+8, 12)
	copy(data[32:], "MyType\x00")
	va := func(addr uint64, n int) []byte {
		if addr < base || addr+uint64(n) > base+uint64(len(data)) {
			return nil
		}
		return data[addr-base : addr-base+uint64(n)]
	}
	s := swiftSec{name: "types", addr: base, data: data}
	if name, ok := swiftDescriptorName(va, s, 0, swiftMask["types"]); !ok || name != "MyType" {
		t.Fatalf("descriptor name = %q/%v, want MyType/true", name, ok)
	}
	if _, ok := swiftDescriptorName(va, s, 4, swiftMask["types"]); ok {
		t.Fatal("descriptor with a zero relative offset resolved a name")
	}
	// A name target outside the readable VA space must not invent a name.
	outside := func(uint64, int) []byte { return nil }
	if _, ok := swiftDescriptorName(outside, s, 0, swiftMask["types"]); ok {
		t.Fatal("descriptor resolved against an unmapped VA")
	}
}

func put32(b []byte, at int, v uint32) {
	b[at] = byte(v)
	b[at+1] = byte(v >> 8)
	b[at+2] = byte(v >> 16)
	b[at+3] = byte(v >> 24)
}

// TestCheckOpOutputJSONShape pins the machine-readable class of the refusal so
// callers can branch on exit 2 + kind without matching prose.
func TestCheckOpOutputJSONShape(t *testing.T) {
	err := checkOpOutput("export_web_scripts", "")
	b, mErr := json.Marshal(map[string]string{"kind": string(err.(*opArgError).kind)})
	if mErr != nil {
		t.Fatal(mErr)
	}
	if string(b) != `{"kind":"needs_arg"}` {
		t.Fatalf("refusal class = %s", b)
	}
}
