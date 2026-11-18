package main

// TUR3 lane09 — genuine simulation tests. Covers the 11 lane files by calling
// the real functions in-package; no mocks, no fake envelopes. Each assertion
// pins behaviour that the shipped binary's --op output also exercises.

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// ---- cxxvtable.go ----------------------------------------------------------

func TestR3LNN01CxxTableSymbols(t *testing.T) {
	for name, want := range map[string]string{
		"_ZTV3Foo":        "_ZTV",
		"_ZTI3Foo":        "_ZTI",
		"_ZTS3Foo":        "_ZTS",
		"__ZTV3Foo":       "_ZTV",
		"_ZTV3Foo.llvm.5": "_ZTV",
		"_ZN3Foo3barEv":   "",
		"_ZSt4cout":       "",
	} {
		if got := cxxTableKind(name); got != want {
			t.Errorf("cxxTableKind(%q) = %q, want %q", name, got, want)
		}
	}
	for name, want := range map[string]string{
		"_ZTI3Foo":        "Foo",
		"_ZTVN3Foo3BarE":  "Foo::Bar",
		"_ZTV3Foo.llvm.7": "Foo",
		"plain":           "",
	} {
		if got := cxxTableType(name); got != want {
			t.Errorf("cxxTableType(%q) = %q, want %q", name, got, want)
		}
	}
	if got := cxxShorten("abcdef", 3); got != "abc…" {
		t.Fatalf("cxxShorten cut = %q", got)
	}
	if got := cxxShorten("abc", 3); got != "abc" {
		t.Fatalf("cxxShorten whole = %q", got)
	}
}

func TestR3LNN02CxxHasRelRo(t *testing.T) {
	type sec struct {
		name string
		size uint64
	}
	makeELF := func(sections ...sec) *elf.File {
		t.Helper()
		shstr := []byte{0}
		nameOff := map[string]uint32{}
		addName := func(s string) uint32 {
			off := uint32(len(shstr))
			shstr = append(shstr, s...)
			shstr = append(shstr, 0)
			return off
		}
		for _, s := range sections {
			nameOff[s.name] = addName(s.name)
		}
		shstrIdx := addName(".shstrtab")
		const ehsize, shentsize = 64, 64
		shstrOff := ehsize
		shoff := (shstrOff + len(shstr) + 7) &^ 7
		num := len(sections) + 2
		b := make([]byte, shoff+num*shentsize)
		le := binary.LittleEndian
		copy(b, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0})
		le.PutUint16(b[16:], 1)
		le.PutUint16(b[18:], 62)
		le.PutUint32(b[20:], 1)
		le.PutUint64(b[40:], uint64(shoff))
		le.PutUint16(b[52:], ehsize)
		le.PutUint16(b[58:], shentsize)
		le.PutUint16(b[60:], uint16(num))
		le.PutUint16(b[62:], uint16(num-1))
		copy(b[shstrOff:], shstr)
		sh := func(i int) []byte { return b[shoff+i*shentsize : shoff+(i+1)*shentsize] }
		for i, s := range sections {
			h := sh(i + 1)
			le.PutUint32(h[0:], nameOff[s.name])
			le.PutUint32(h[4:], 1)
			le.PutUint64(h[32:], s.size)
		}
		h := sh(num - 1)
		le.PutUint32(h[0:], shstrIdx)
		le.PutUint32(h[4:], 3)
		le.PutUint64(h[24:], uint64(shstrOff))
		le.PutUint64(h[32:], uint64(len(shstr)))
		f, err := elf.NewFile(bytes.NewReader(b))
		if err != nil {
			t.Fatal(err)
		}
		return f
	}
	if !cxxHasRelRo(makeELF(sec{".data.rel.ro", 16})) {
		t.Fatal(".data.rel.ro size 16 must be relro")
	}
	if !cxxHasRelRo(makeELF(sec{".data.rel.ro.local", 32})) {
		t.Fatal(".data.rel.ro.local size 32 must be relro")
	}
	if cxxHasRelRo(makeELF(sec{".data.rel.ro", 8})) {
		t.Fatal("undersized .data.rel.ro must not count")
	}
	if cxxHasRelRo(makeELF(sec{".text", 4096})) {
		t.Fatal(".text is not relro")
	}
	if cxxHasRelRo(makeELF()) {
		t.Fatal("no sections cannot be relro")
	}
}

// ---- notes.go --------------------------------------------------------------

func TestR3LNN03DeepNote(t *testing.T) {
	deepNote(nil, "keep going") // must not panic
	d := &Digest{}
	deepNote(d, "  read the prototype tree  ")
	if len(d.Notes) != 1 || d.Notes[0] != "deep: read the prototype tree" {
		t.Fatalf("deepNote trim/prefix: %#v", d.Notes)
	}
	deepNote(d, "   ")
	if len(d.Notes) != 1 {
		t.Fatalf("blank note appended: %#v", d.Notes)
	}
	deepNote(d, "second step")
	if len(d.Notes) != 2 || d.Notes[1] != "deep: second step" {
		t.Fatalf("second note: %#v", d.Notes)
	}
}

// ---- op_export_web_scripts.go ----------------------------------------------

func TestR3LNN04WriteExportedRejectsTraversal(t *testing.T) {
	dir := t.TempDir()
	for _, rel := range []string{"..", "../escape.js", "a/../../escape.js", `a\b.js`} {
		if err := writeExported(dir, rel, []byte("x")); err == nil {
			t.Errorf("writeExported(%q) accepted an escaping member", rel)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "escape.js")); !os.IsNotExist(err) {
		t.Fatal("a rejected member was written")
	}
}

func TestR3LNN05WriteExportedRealFile(t *testing.T) {
	dir := t.TempDir()
	body := []byte("console.log(\"r3l09\");\n")
	if err := writeExported(dir, "app/main.js", body); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "app", "main.js"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("written bytes = %q, want %q", got, body)
	}
}

// ---- op_inspect_keyed_archive.go -------------------------------------------

func TestR3LNN06OpenBplist(t *testing.T) {
	// Minimal well-formed bplist00: one null object + a 32-byte trailer.
	b := []byte("bplist00")
	b = append(b, 0x00) // object 0 at file offset 8
	table := len(b)
	b = append(b, byte(8)) // offset table entry: object 0 lives at file offset 8
	b = append(b, make([]byte, 32)...)
	tr := b[len(b)-32:]
	tr[6] = 1                                // offset int size
	tr[7] = 1                                // object ref size
	binary.BigEndian.PutUint64(tr[8:16], 1)  // object count
	binary.BigEndian.PutUint64(tr[16:24], 0) // top object
	binary.BigEndian.PutUint64(tr[24:32], uint64(table))
	b[table] = 8 // object 0 offset
	p, err := openBplist(b)
	if err != nil {
		t.Fatalf("openBplist(valid): %v", err)
	}
	if len(p.offs) != 1 || p.offs[0] != 8 || p.top != 0 || p.refSize != 1 {
		t.Fatalf("openBplist parsed %+v", p)
	}
	for _, bad := range [][]byte{
		[]byte("not a bplist at all...................."),
		bytes.Repeat([]byte{0}, 8),
	} {
		if _, err := openBplist(bad); err == nil {
			t.Fatal("openBplist accepted a non-bplist00 buffer")
		}
	}
}

// ---- op_native_cache.go ----------------------------------------------------

func TestR3LNN07GhidraEntryKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "target.bin")
	if err := os.WriteFile(path, []byte("target bytes v1"), 0o644); err != nil {
		t.Fatal(err)
	}
	st1, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	k1 := ghidraEntryKey(path, "12.1.4", st1)
	if again := ghidraEntryKey(path, "12.1.4", st1); again != k1 {
		t.Fatal("same bytes/version changed the cache key")
	}
	if k2 := ghidraEntryKey(path, "12.1.5", st1); k2 == k1 {
		t.Fatal("Ghidra version change did not change the cache key")
	}
	if err := os.WriteFile(path, []byte("target bytes v2"), 0o644); err != nil {
		t.Fatal(err)
	}
	st2, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if k2 := ghidraEntryKey(path, "12.1.4", st2); k2 == k1 {
		t.Fatal("byte change did not change the cache key")
	}
	if len(k1) != 16 {
		t.Fatalf("cache key = %q, want 16 hex chars", k1)
	}
}

// ---- op_read_function_instructions.go / op_native_util.go ------------------

func TestR3LNN08NativeRef(t *testing.T) {
	t.Setenv("LRECON_AT", "")
	t.Setenv("LRECON_NAME", "")
	if _, err := nativeRef(); err == nil {
		t.Fatal("nativeRef with neither env set must fail")
	}
	t.Setenv("LRECON_NAME", "main")
	if got, err := nativeRef(); err != nil || got != "main" {
		t.Fatalf("nativeRef(NAME) = %q, %v", got, err)
	}
	t.Setenv("LRECON_AT", "0x401000")
	if got, err := nativeRef(); err != nil || got != "0x401000" {
		t.Fatalf("nativeRef(AT) = %q, want AT to win", got)
	}
}

// ---- proctable_darwin.go ---------------------------------------------------

func TestR3LNN09DarwinProcRows(t *testing.T) {
	b := make([]byte, 3*darwinKinfoProcSize)
	put := func(rec, pid int, comm string) {
		base := rec * darwinKinfoProcSize
		b[base+darwinPidOffset] = byte(pid)
		b[base+darwinPidOffset+1] = byte(pid >> 8)
		b[base+darwinPidOffset+2] = byte(pid >> 16)
		b[base+darwinPidOffset+3] = byte(pid >> 24)
		copy(b[base+darwinCommOffset:base+darwinCommOffset+darwinCommLen], comm)
	}
	put(0, 42, "Cutter")
	put(1, 43, "zsh")
	put(2, 0, "unused")
	got, plausible := darwinProcMatches(b, "cutter")
	if plausible != 2 || len(got) != 1 || got[0] != "42 Cutter" {
		t.Fatalf("darwinProcMatches = %q, plausible=%d", got, plausible)
	}
	rows, plausible := darwinProcRows(b)
	if plausible != 2 || len(rows) != 2 {
		t.Fatalf("darwinProcRows plausible=%d rows=%d", plausible, len(rows))
	}
	if _, plausible := darwinProcRows(nil); plausible != 0 {
		t.Fatalf("empty buffer plausible=%d, want 0", plausible)
	}
}

// ---- op registry: all seven registered ops from this lane ------------------

func TestR3LNN10LaneOpsRegistered(t *testing.T) {
	want := map[string]string{
		"close_rizin_debug_session":  "Y",
		"export_web_scripts":         "L",
		"inspect_adb_package":        "Y",
		"inspect_keyed_archive":      "L",
		"inspect_web_page":           "Y",
		"read_function_instructions": "G",
		"stop_adb_app":               "Y",
	}
	for name, route := range want {
		o, ok := ops[name]
		if !ok {
			t.Errorf("op %q not registered", name)
			continue
		}
		if o.route != route {
			t.Errorf("op %q route = %q, want %q", name, o.route, route)
		}
		if !o.needs {
			t.Errorf("op %q should need a target", name)
		}
	}
	if len(ops) != 235 {
		t.Fatalf("registered ops = %d, want 235", len(ops))
	}
}
