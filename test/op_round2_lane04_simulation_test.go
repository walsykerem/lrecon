package main

// TUR 2 AUDIT — LANE 04 independent simulation tests.
// Only this file was written; production code and other test files were not changed.
// Annotations were not trusted: each function's real behavior was verified with meaningful input.

import (
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"encoding/binary"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---------- notes.go ----------
func TestR2L04NotesDeepNote(t *testing.T) {
	d := &Digest{}
	deepNote(d, "  read the prototype tree  ")
	if len(d.Notes) != 1 || d.Notes[0] != "deep: read the prototype tree" {
		t.Fatalf("deepNote trim/prefix: %#v", d.Notes)
	}
	deepNote(d, "   ")
	deepNote(nil, "x")
	if len(d.Notes) != 1 {
		t.Fatalf("empty/nil must be no-op: %#v", d.Notes)
	}
}

// ---------- move.go ----------
func TestR2L04MoveMatchAndIdentifier(t *testing.T) {
	if !moveMatch([]byte{0xa1, 0x1c, 0xeb, 0x0b, 0x05}, 0) {
		t.Fatal("valid move magic refused")
	}
	if moveMatch([]byte{0xa1, 0x1c, 0xeb}, 0) || moveMatch([]byte{0, 0, 0, 0}, 0) {
		t.Fatal("short/wrong magic accepted")
	}
	for _, s := range []string{"Alpha_1", "module", "A9"} {
		if !moveIdentifier(s) {
			t.Fatalf("valid identifier %q refused", s)
		}
	}
	for _, s := range []string{"", "bad-name", "a.b", "a b"} {
		if moveIdentifier(s) {
			t.Fatalf("invalid identifier %q accepted", s)
		}
	}
}

func TestR2L04MoveModuleName(t *testing.T) {
	// identifiers table: ULEB len + bytes, two entries.
	ident := func(s string) []byte {
		b := binary.AppendUvarint(nil, uint64(len(s)))
		return append(b, []byte(s)...)
	}
	b := append(ident("Alpha"), ident("Beta")...)

	name, reason, detail := moveModuleName(b, 0, 2, 0)
	if name != "Alpha" || reason != "" || detail != "" {
		t.Fatalf("want=0: %q %q %q", name, reason, detail)
	}
	name, _, _ = moveModuleName(b, 0, 2, 1)
	if name != "Beta" {
		t.Fatalf("want=1: %q", name)
	}
	if _, reason, _ = moveModuleName(b, 0, 0, 0); reason != "move-table-unverified" {
		t.Fatalf("count=0: %q", reason)
	}
	if _, reason, _ = moveModuleName(b, 0, 2, 2); reason != "move-table-unverified" {
		t.Fatalf("want>=count: %q", reason)
	}
	if _, reason, _ = moveModuleName(b, len(b), 2, 0); reason != "move-table-truncated" {
		t.Fatalf("off past end: %q", reason)
	}
	// second entry corrupted to a non-identifier: want=1 must be refused.
	bad := append(ident("Alpha"), ident("bad-name")...)
	if _, reason, _ = moveModuleName(bad, 0, 2, 1); reason != "move-table-unverified" {
		t.Fatalf("bad identifier: %q", reason)
	}
}

// ---------- luaproto.go ----------
func luaTestHeader51() []byte {
	b := make([]byte, 12)
	copy(b, []byte("\x1bLua"))
	b[4] = 0x51
	b[5] = 0
	b[6] = 1 // little endian
	b[7] = 4 // int
	b[8] = 8 // size_t
	b[9] = 4 // instruction
	b[10] = 8
	b[11] = 0
	return b
}

func luaTestHeader52() []byte {
	b := make([]byte, 33)
	copy(b, []byte("\x1bLua"))
	b[4] = 0x52
	copy(b[6:12], []byte("\x19\x93\r\n\x1a\n"))
	b[12], b[13], b[14], b[15], b[16] = 4, 8, 4, 8, 8
	binary.LittleEndian.PutUint64(b[17:25], 0x5678)
	binary.LittleEndian.PutUint64(b[25:33], math.Float64bits(370.5))
	return b
}

func luaTestHeader54() []byte {
	b := make([]byte, 31)
	copy(b, []byte("\x1bLua"))
	b[4] = 0x54
	copy(b[6:12], []byte("\x19\x93\r\n\x1a\n"))
	b[12], b[13], b[14] = 4, 8, 8
	binary.LittleEndian.PutUint64(b[15:23], 0x5678)
	binary.LittleEndian.PutUint64(b[23:31], math.Float64bits(370.5))
	return b
}

func luaOrderIsLittle(o binary.ByteOrder) bool {
	return o != nil && o.Uint64([]byte{1, 0, 0, 0, 0, 0, 0, 0}) == 1
}

func TestR2L04LuaProtoHeader(t *testing.T) {
	h, ok := luaProtoHeader(luaTestHeader51())
	if !ok || h.version != 0x51 || h.body != 12 || !luaOrderIsLittle(h.order) {
		t.Fatalf("5.1 header: %+v ok=%v", h, ok)
	}
	h, ok = luaProtoHeader(luaTestHeader52())
	if !ok || h.version != 0x52 || h.body != 33 || !luaOrderIsLittle(h.order) {
		t.Fatalf("5.2 header: %+v ok=%v", h, ok)
	}
	h, ok = luaProtoHeader(luaTestHeader54())
	if !ok || h.version != 0x54 || h.body != 31 || !luaOrderIsLittle(h.order) {
		t.Fatalf("5.4 header: %+v ok=%v", h, ok)
	}
	bad := luaTestHeader51()
	bad[4] = 0x99
	if _, ok := luaProtoHeader(bad); ok {
		t.Fatal("unknown version accepted")
	}
	bad = luaTestHeader52()
	bad[6] = 0 // corrupt LUAC_DATA
	if _, ok := luaProtoHeader(bad); ok {
		t.Fatal("corrupt LUAC_DATA accepted")
	}
	bad = luaTestHeader51()
	bad[7] = 3 // bad int size
	if _, ok := luaProtoHeader(bad); ok {
		t.Fatal("bad word size accepted")
	}
}

func TestR2L04LuaSentinelAndSizes(t *testing.T) {
	if luaOrder(0) == nil || luaOrderIsLittle(luaOrder(0)) {
		t.Fatal("luaOrder(0) must be big endian")
	}
	if !luaOrderIsLittle(luaOrder(1)) || luaOrder(2) != nil {
		t.Fatal("luaOrder(1)=little, luaOrder(2)=nil")
	}
	if !luaSizes(4, 8, 4, 8, 8) || luaSizes(3, 8, 4, 8, 8) || luaSizes(4, 8, 8, 8, 8) {
		t.Fatal("luaSizes word-width rule")
	}
	le := make([]byte, 16)
	binary.LittleEndian.PutUint64(le[:8], 0x5678)
	binary.LittleEndian.PutUint64(le[8:], math.Float64bits(370.5))
	if !luaOrderIsLittle(luaSentinelOrder(le, 0, 8, 8)) {
		t.Fatal("LE sentinel not detected")
	}
	be := make([]byte, 16)
	binary.BigEndian.PutUint64(be[:8], 0x5678)
	binary.BigEndian.PutUint64(be[8:], math.Float64bits(370.5))
	if o := luaSentinelOrder(be, 0, 8, 8); o == nil || luaOrderIsLittle(o) {
		t.Fatal("BE sentinel not detected")
	}
	if luaSentinelOrder([]byte{1, 2}, 0, 8, 8) != nil {
		t.Fatal("short sentinel accepted")
	}
	if luaFloat([]byte(le[8:]), binary.LittleEndian) != 370.5 {
		t.Fatal("luaFloat64")
	}
	f4 := math.Float32bits(370.5)
	b4 := make([]byte, 4)
	binary.LittleEndian.PutUint32(b4, f4)
	if luaFloat(b4, binary.LittleEndian) != 370.5 {
		t.Fatal("luaFloat32")
	}
}

// ---------- main.go ----------
func TestR2L04MainCutAndTruncate(t *testing.T) {
	if s, cut := cutUTF8("hello", 10); s != "hello" || cut {
		t.Fatalf("fits: %q %v", s, cut)
	}
	if s, cut := cutUTF8("hello", 0); s != "hello" || cut {
		t.Fatalf("limit<=0: %q %v", s, cut)
	}
	// "h€llo" = 1+3+3 bytes; cutting at 2 must back up to the rune start at 1.
	s, cut := cutUTF8("h€llo", 2)
	if s != "h" || !cut {
		t.Fatalf("rune boundary: %q %v", s, cut)
	}
	out := truncate("hello world", 5)
	if !strings.HasPrefix(out, "hell\n") || !strings.Contains(out, "note: truncated at 5 of 11 bytes") {
		t.Fatalf("truncate no newline: %q", out)
	}
	out = truncate("line1\nline2", 8)
	if !strings.HasPrefix(out, "line1\n") || !strings.Contains(out, "note: truncated at 6 of 11 bytes") {
		t.Fatalf("truncate at newline: %q", out)
	}
	if truncate("short", 100) != "short" {
		t.Fatal("truncate changed fitting string")
	}
}

func TestR2L04MainClassifiers(t *testing.T) {
	for _, s := range []string{"123", "0x1f", "0XFF"} {
		if !isByteCount(s) {
			t.Fatalf("isByteCount(%q)", s)
		}
	}
	for _, s := range []string{"1f", "", "-5", "0x"} {
		if isByteCount(s) {
			t.Fatalf("isByteCount(%q) must be false", s)
		}
	}
	for _, s := range []string{"www.foo.com", "https://x", "ftp://a"} {
		if !looksLikeWebsite(s) {
			t.Fatalf("looksLikeWebsite(%q)", s)
		}
	}
	for _, s := range []string{"/tmp/x", "1http://x", "://x"} {
		if looksLikeWebsite(s) {
			t.Fatalf("looksLikeWebsite(%q) must be false", s)
		}
	}
	if !looksLikePID("pid:123") || !looksLikePID("pid=1") || looksLikePID("PID:1") || looksLikePID("123") {
		t.Fatal("looksLikePID")
	}
	if !looksLikeProcessName("definitely_not_a_real_process_xyz") ||
		looksLikeProcessName("/tmp/foo") || looksLikeProcessName("foo.exe") || looksLikeProcessName("") {
		t.Fatal("looksLikeProcessName")
	}
}

func TestR2L04MainNamedModeAndFlagCount(t *testing.T) {
	cases := []struct {
		args []string
		want string
	}{
		{[]string{"--op", "foo"}, "foo"},
		{[]string{"--ext-op=bar"}, "bar"},
		{[]string{"--deep"}, "deep"},
		{[]string{"--extract"}, "extract"},
		{[]string{"--extract-all"}, "extract_all"},
		{[]string{"--op", "foo", "--deep"}, "foo"},
		{[]string{"--", "--op", "foo"}, ""},
	}
	for _, c := range cases {
		if got := namedMode(c.args); got != c.want {
			t.Fatalf("namedMode(%v) = %q want %q", c.args, got, c.want)
		}
	}
	args := []string{"-v", "--v", "-v=1", "--", "-v"}
	if n := flagCount(args, "v"); n != 3 {
		t.Fatalf("flagCount = %d want 3", n)
	}
	if n := flagCount(args, "none"); n != 0 {
		t.Fatalf("flagCount(none) = %d", n)
	}
}

// ---------- managed.go + managed_cil.go ----------
func TestR2L04ManagedTargetFrameworkAndModules(t *testing.T) {
	if got := targetFramework([]byte("xx.NETCoreApp,Version=v8.0\x00more")); got != ".NETCoreApp,Version=v8.0" {
		t.Fatalf("targetFramework = %q", got)
	}
	if got := targetFramework([]byte(".NETFramework,Version=v4.7.2\x00")); got != ".NETFramework,Version=v4.7.2" {
		t.Fatalf("targetFramework framework = %q", got)
	}
	if got := targetFramework([]byte("nothing here")); got != "" {
		t.Fatalf("targetFramework none = %q", got)
	}
	heap := []byte("kernel32.dll\x00libSystem.dylib\x00libfoo.so\x00myapp\x00")
	if n := nativeModules(heap); n != 2 {
		t.Fatalf("nativeModules = %d want 2", n)
	}
	if n := nativeModules([]byte("myapp\x00")); n != 0 {
		t.Fatalf("nativeModules none = %d", n)
	}
}

func TestR2L04ManagedColWidth(t *testing.T) {
	var rows [0x2D]int
	if colWidth("u2", 0, &rows) != 2 || colWidth("u4", 0, &rows) != 4 {
		t.Fatal("u2/u4")
	}
	if colWidth("str", 0, &rows) != 2 || colWidth("str", 1, &rows) != 4 {
		t.Fatal("str heap width")
	}
	if colWidth("guid", 2, &rows) != 4 || colWidth("blob", 4, &rows) != 4 {
		t.Fatal("guid/blob heap width")
	}
	rows[0x00] = 100
	if colWidth("Module", 0, &rows) != 2 {
		t.Fatal("small table must be 2 bytes")
	}
	rows[0x00] = 70000
	if colWidth("Module", 0, &rows) != 4 {
		t.Fatal("large table must be 4 bytes")
	}
	w, o := colWidths([]string{"u2", "u4", "str"}, 0, &rows)
	if len(w) != 3 || w[0] != 2 || w[1] != 4 || w[2] != 2 || o[0] != 0 || o[1] != 2 || o[2] != 6 {
		t.Fatalf("colWidths w=%v o=%v", w, o)
	}
}

func TestR2L04ManagedIL2CPPAndUnity(t *testing.T) {
	if got := unityVersion([]byte("Unity 2021.3.5f1")); got != "2021.3.5f1" {
		t.Fatalf("unityVersion = %q", got)
	}
	if got := unityVersion([]byte("il2cpp 2020.1.0p9")); got != "2020.1.0p9" {
		t.Fatalf("unityVersion p = %q", got)
	}
	if got := unityVersion([]byte("Unity 1999.1.1f1")); got != "" {
		t.Fatalf("unityVersion old = %q", got)
	}
	if got := unityVersion([]byte("nothing")); got != "" {
		t.Fatalf("unityVersion none = %q", got)
	}
	if v, ok := il2cppMarkers([]byte("global-metadata.dat Unity 2021.3.5f1")); !ok || v != "2021.3.5f1" {
		t.Fatalf("il2cppMarkers = %q %v", v, ok)
	}
	if _, ok := il2cppMarkers([]byte("global-metadata.dat")); ok {
		t.Fatal("metadata alone must not be IL2CPP finding")
	}
}

func TestR2L04ManagedCompressedUint(t *testing.T) {
	cases := []struct {
		b     []byte
		val   int
		width int
	}{
		{[]byte{0x7f}, 127, 1},
		{[]byte{0x80, 0x01}, 1, 2},
		{[]byte{0xC0, 0x00, 0x01, 0x00}, 256, 4},
		{[]byte{}, 0, 0},
		{[]byte{0xE0}, 0, 0},
	}
	for _, c := range cases {
		v, w := compressedUint(c.b)
		if v != c.val || w != c.width {
			t.Fatalf("compressedUint(%x) = %d,%d want %d,%d", c.b, v, w, c.val, c.width)
		}
	}
}

// ---------- mangling.go ----------
func TestR2L04ManglingFamily(t *testing.T) {
	legacy := "_ZN3foo17h0123456789abcdefE"
	if fam, shape := manglingFamily(legacy); fam != "rust-legacy" || shape != "hash-suffix" {
		t.Fatalf("legacy = %q %q", fam, shape)
	}
	if fam, _ := manglingFamily(legacy + ".llvm.123"); fam != "rust-legacy" {
		t.Fatalf("llvm strip = %q", fam)
	}
	if fam, _ := manglingFamily("?foo@@YAXXZ"); fam != "msvc" {
		t.Fatalf("msvc = %q", fam)
	}
	if fam, _ := manglingFamily("go:foo"); fam != "go" {
		t.Fatalf("go = %q", fam)
	}
	if fam, _ := manglingFamily("$s4main3fooyyF"); fam != "swift" {
		t.Fatalf("swift = %q", fam)
	}
	if fam, shape := manglingFamily("randomName"); fam != "" || shape != "" {
		t.Fatalf("unknown = %q %q", fam, shape)
	}
}

func TestR2L04ManglingDecision(t *testing.T) {
	counts := manglingCounts([]string{"?a@@YAXXZ", "?b@@YAXXZ", "?c@@YAXXZ", "go:x"})
	if counts["msvc"] != 3 || counts["go"] != 1 {
		t.Fatalf("manglingCounts = %v", counts)
	}
	caps, note, below := manglingDecision(counts, 10)
	if len(caps) != 1 || caps[0] != "mangling:msvc=3" || below != "" {
		t.Fatalf("decision caps=%v note=%q below=%q", caps, note, below)
	}
	if !strings.Contains(note, "mangling: msvc=3 go=1 (of 10 symbol names)") {
		t.Fatalf("decision note = %q", note)
	}
	caps, note, below = manglingDecision(map[string]int{"msvc": 2}, 5)
	if caps != nil || note != "" || !strings.Contains(below, "msvc=2 (of 5 symbol names, minimum 3)") {
		t.Fatalf("below-threshold caps=%v note=%q below=%q", caps, note, below)
	}
}

// ---------- mobile.go ----------
func TestR2L04MobileSniffs(t *testing.T) {
	if !isDex([]byte("dex\n035\x00")) || !isDex([]byte("cdex001\x00")) || isDex([]byte("PK\x03\x04")) {
		t.Fatal("isDex")
	}
	bx := make([]byte, 8)
	binary.LittleEndian.PutUint32(bx[:4], axmlMagic)
	binary.LittleEndian.PutUint32(bx[4:], 100)
	if !isBinaryXML(bx) {
		t.Fatal("valid binary XML refused")
	}
	binary.LittleEndian.PutUint32(bx[4:], 4)
	if isBinaryXML(bx) {
		t.Fatal("size<=8 accepted")
	}
	binary.LittleEndian.PutUint32(bx[4:], 64<<20+1)
	if isBinaryXML(bx) {
		t.Fatal("oversize accepted")
	}
}

func TestR2L04MobileDexULEBAndMUTF8(t *testing.T) {
	if v, n, ok := dexULEB([]byte{0x7f}, 0, 1); v != 127 || n != 1 || !ok {
		t.Fatalf("uleb 1 byte: %d %d %v", v, n, ok)
	}
	if v, n, ok := dexULEB([]byte{0x80, 0x01}, 0, 2); v != 128 || n != 2 || !ok {
		t.Fatalf("uleb 2 byte: %d %d %v", v, n, ok)
	}
	if _, _, ok := dexULEB([]byte{0x80, 0x80, 0x80, 0x80, 0x80}, 0, 5); ok {
		t.Fatal("uleb overflow accepted")
	}
	if s, units, ok := dexMUTF8([]byte("hello\x00world"), 0, 12); s != "hello" || units != 5 || !ok {
		t.Fatalf("mutf8 ascii: %q %d %v", s, units, ok)
	}
	// CESU-8 surrogate pair for U+1F600.
	smile := []byte{0xED, 0xA0, 0xBD, 0xED, 0xB8, 0x80, 0x00}
	if s, units, ok := dexMUTF8(smile, 0, len(smile)); s != "😀" || units != 2 || !ok {
		t.Fatalf("mutf8 surrogate: %q %d %v", s, units, ok)
	}
	if _, _, ok := dexMUTF8([]byte{0xF0, 0x9F, 0x98, 0x80, 0x00}, 0, 5); ok {
		t.Fatal("4-byte lead accepted")
	}
}

func TestR2L04MobileAXMLLen(t *testing.T) {
	if v, n, ok := axmlLen8([]byte{0x7f}); v != 127 || n != 1 || !ok {
		t.Fatalf("axmlLen8 1: %d %d %v", v, n, ok)
	}
	// 2-byte form: high = b[0]&0x7f, low = b[1].
	if v, n, ok := axmlLen8([]byte{0x81, 0x02}); v != 258 || n != 2 || !ok {
		t.Fatalf("axmlLen8 2: %d %d %v", v, n, ok)
	}
	if _, _, ok := axmlLen8([]byte{}); ok {
		t.Fatal("axmlLen8 empty")
	}
	if v, n, ok := axmlLen16([]byte{0xff, 0x7f}); v != 32767 || n != 2 || !ok {
		t.Fatalf("axmlLen16 2: %d %d %v", v, n, ok)
	}
	if v, n, ok := axmlLen16([]byte{0x00, 0x80, 0x01, 0x00}); v != 1 || n != 4 || !ok {
		t.Fatalf("axmlLen16 4: %d %d %v", v, n, ok)
	}
}

// ---------- msvcrti.go ----------
func TestR2L04MsvcMachineAndName(t *testing.T) {
	mi, ok := msvcMachineFor(pe.IMAGE_FILE_MACHINE_AMD64)
	if !ok || mi.ptr != 8 || mi.reloc != 0x0003 {
		t.Fatalf("amd64: %+v %v", mi, ok)
	}
	mi, ok = msvcMachineFor(pe.IMAGE_FILE_MACHINE_I386)
	if !ok || mi.ptr != 4 || mi.reloc != 0x0007 {
		t.Fatalf("i386: %+v %v", mi, ok)
	}
	if _, ok := msvcMachineFor(0x999); ok {
		t.Fatal("unknown machine accepted")
	}
	if name, ok := msvcName([]byte(".?AVLeaf@@")); name != "Leaf" || !ok {
		t.Fatalf("msvcName = %q %v", name, ok)
	}
	if _, ok := msvcName([]byte(".?A")); ok {
		t.Fatal("short name accepted")
	}
	if _, ok := msvcName([]byte(".?AVa b@@")); ok {
		t.Fatal("control char accepted")
	}
	if _, ok := msvcName([]byte("garbage")); ok {
		t.Fatal("missing prefix accepted")
	}
	lst := msvcAppendUnique([]uint32{1, 2}, 2)
	if len(lst) != 2 {
		t.Fatalf("appendUnique duplicate: %v", lst)
	}
	lst = msvcAppendUnique(lst, 3)
	if len(lst) != 3 || lst[2] != 3 {
		t.Fatalf("appendUnique new: %v", lst)
	}
	classes := []*msvcClass{{name: "A", bases: []string{"B"}, offsets: []uint32{0x10, 0x20}}}
	want := "msvc-class 1 (A 1 [B] @0x10,0x20)"
	if got := msvcClassLine(classes); got != want {
		t.Fatalf("msvcClassLine = %q want %q", got, want)
	}
}

// ---------- native.go ----------
func TestR2L04NativeSymbolsAndUleb(t *testing.T) {
	if symbolsState(true) != "present" || symbolsState(false) != "stripped" {
		t.Fatal("symbolsState")
	}
	if v, n := uleb128([]byte{0x80, 0x01}); v != 128 || n != 2 {
		t.Fatalf("uleb128 = %d %d", v, n)
	}
	if v, n := uleb128([]byte{0x7f}); v != 127 || n != 1 {
		t.Fatalf("uleb128 1 = %d %d", v, n)
	}
	ten := []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80}
	if v, n := uleb128(ten); v != 0 || n != 0 {
		t.Fatalf("uleb128 overflow = %d %d", v, n)
	}
}

func TestR2L04NativeTrieTerminals(t *testing.T) {
	// root: term=0, 1 child 'a' -> child at offset 5: term=1, no children.
	b := []byte{0x00, 0x01, 'a', 0x00, 0x05, 0x01, 0x00}
	if n := trieTerminals(b); n != 1 {
		t.Fatalf("trieTerminals = %d want 1", n)
	}
	// single terminal root, no children.
	if n := trieTerminals([]byte{0x01, 0x00}); n != 1 {
		t.Fatalf("trieTerminals root = %d", n)
	}
	// empty/invalid must not panic or over-count.
	if n := trieTerminals(nil); n != 0 {
		t.Fatalf("trieTerminals nil = %d", n)
	}
}

func TestR2L04NativeGoBuildinfoHeader(t *testing.T) {
	h := make([]byte, 32)
	h[0], h[1] = 8, 0x02 // ptrSize 8, inline version flag
	h[18] = 0x08         // varint length
	copy(h[19:], "go1.21.0")
	out := parseGoBuildinfoHeader(h)
	if !out.ok || out.version != "go1.21.0" || out.ptrSize != 8 {
		t.Fatalf("inline header: %+v", out)
	}
	// pointer form: flags bit0 selects endianness.
	h2 := make([]byte, 32)
	h2[0], h2[1] = 8, 0x00
	out = parseGoBuildinfoHeader(h2)
	if !out.ok || out.endian != "little" || out.version != "" {
		t.Fatalf("pointer little: %+v", out)
	}
	h2[1] = 0x01
	out = parseGoBuildinfoHeader(h2)
	if !out.ok || out.endian != "big" {
		t.Fatalf("pointer big: %+v", out)
	}
	// invalid ptrSize and truncated header.
	h3 := make([]byte, 32)
	h3[0], h3[1] = 5, 0x00
	if out = parseGoBuildinfoHeader(h3); out.ok {
		t.Fatal("bad ptrSize accepted")
	}
	if out = parseGoBuildinfoHeader([]byte{8, 2}); !out.cut {
		t.Fatal("short header not marked cut")
	}
}

func TestR2L04NativeHelpers(t *testing.T) {
	crate, ver, ok := rustSplitCrate("libfoo-1.2.3")
	if crate != "libfoo" || ver != "1.2.3" || !ok {
		t.Fatalf("rustSplitCrate = %q %q %v", crate, ver, ok)
	}
	if _, _, ok := rustSplitCrate("nocrate"); ok {
		t.Fatal("rustSplitCrate on bare name")
	}
	u := uniqued([]string{"a", "", "a", "b", "b"})
	if len(u) != 2 || u[0] != "a" || u[1] != "b" {
		t.Fatalf("uniqued = %v", u)
	}
	if u = uniqued(nil); u == nil || len(u) != 0 {
		t.Fatalf("uniqued(nil) must be non-nil empty: %v", u)
	}
	if b := basenames([]string{"/a/b/foo.exe", "/x/bar"}); len(b) != 2 || b[0] != "foo.exe" || b[1] != "bar" {
		t.Fatalf("basenames = %v", b)
	}
	d := &Digest{}
	list := capped(d, "crates", []string{"a", "b", "c"}, 2)
	if len(list) != 2 || len(d.Notes) != 1 || !strings.Contains(d.Notes[0], "crates truncated to 2 of 3") {
		t.Fatalf("capped = %v notes=%v", list, d.Notes)
	}
	syms := []objectSymbol{{Value: 0x1000, Kind: 'T', Name: "_bump"}}
	if s, found := findObjectSymbol(syms, "bump"); !found || s.Value != 0x1000 {
		t.Fatalf("findObjectSymbol bare = %+v %v", s, found)
	}
	if _, found := findObjectSymbol(syms, "nope"); found {
		t.Fatal("findObjectSymbol false positive")
	}
}

func TestR2L04NativeArchNameMaps(t *testing.T) {
	if machoArch(macho.CpuAmd64) != "x86-64" || machoArch(macho.CpuArm64) != "arm64" || machoArch(macho.Cpu(0x123)) != "cpu-0x123" {
		t.Fatal("machoArch")
	}
	if platformName(1) != "macOS" || platformName(99) != "platform99" {
		t.Fatal("platformName")
	}
	if verString(0x00010203) != "1.2.3" || verString(0x00010200) != "1.2" {
		t.Fatal("verString")
	}
	if peSubsystem(3) != "console" || peSubsystem(99) != "subsystem99" {
		t.Fatal("peSubsystem")
	}
	if elfArch(elf.EM_X86_64) != "x86-64" || elfArch(elf.EM_AARCH64) != "arm64" {
		t.Fatal("elfArch")
	}
	if peArch(pe.IMAGE_FILE_MACHINE_AMD64) != "x86-64" || peArch(0x999) != "pe-0x999" {
		t.Fatal("peArch")
	}
}

// ---------- objc.go + objectsyms.go ----------
func TestR2L04ObjcPrintableAndSymbolLine(t *testing.T) {
	for _, s := range []string{"", "hello", " ", strings.Repeat("a", 256)} {
		if !objcPrintable(s) {
			t.Fatalf("objcPrintable(%q) refused", s[:min(len(s), 8)])
		}
	}
	for _, s := range []string{strings.Repeat("a", 257), "a\nb", "\x7f", "é"} {
		if objcPrintable(s) {
			t.Fatalf("objcPrintable refused bad input accepted")
		}
	}
	sym := objectSymbol{Value: 0x1234, Kind: 'T', Name: "foo"}
	if got := sym.line(); got != "0000000000001234 T foo" {
		t.Fatalf("objectSymbol.line = %q", got)
	}
}

func TestR2L04ObjectSymbolTableDispatch(t *testing.T) {
	dir := t.TempDir()
	// Empty file -> objdumpFormat returns "" -> refused before any parser.
	empty := filepath.Join(dir, "empty.bin")
	if err := os.WriteFile(empty, nil, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := objectSymbolTable(empty); err == nil || !strings.Contains(err.Error(), "not an object file") {
		t.Fatalf("empty file: %v", err)
	}
	// Non-ELF/PE/archive magic falls through to the Mach-O parser, which rejects the stub.
	unknown := filepath.Join(dir, "unknown.bin")
	if err := os.WriteFile(unknown, []byte("not an object"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := objectSymbolTable(unknown); err == nil || !strings.Contains(err.Error(), "cannot read macho symbols") {
		t.Fatalf("unknown magic: %v", err)
	}
	// ELF magic -> dispatched to ELF parser, which rejects the stub.
	elfStub := filepath.Join(dir, "stub.elf")
	if err := os.WriteFile(elfStub, []byte("\x7fELF\x02\x01\x01\x00"+"garbage"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := objectSymbolTable(elfStub); err == nil || !strings.Contains(err.Error(), "cannot read elf symbols") {
		t.Fatalf("elf stub: %v", err)
	}
	// Missing path -> refused.
	if _, err := objectSymbolTable(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("missing file accepted")
	}
}

// ---------- ocaml.go + ocaml_test.go (existing tests verified without modification) ----------
func TestR2L04OcamlPureHelpers(t *testing.T) {
	if name, ok := ocamlName([]byte("TEXT\x00pad")); name != "TEXT" || !ok {
		t.Fatalf("ocamlName = %q %v", name, ok)
	}
	if name, ok := ocamlName([]byte("abc")); name != "abc" || !ok {
		t.Fatalf("ocamlName no NUL = %q %v", name, ok)
	}
	if _, ok := ocamlName([]byte("\x00x")); ok {
		t.Fatal("ocamlName empty accepted")
	}
	if _, ok := ocamlName([]byte{0x01, 0x00}); ok {
		t.Fatal("ocamlName control accepted")
	}
	if !ocamlDigits([]byte("1234")) || ocamlDigits([]byte("12a")) {
		t.Fatal("ocamlDigits")
	}
	if !ocamlTOCFits(2, 100) || ocamlTOCFits(2, 20) || ocamlTOCFits(-1, 100) || ocamlTOCFits(4097, 100000) {
		t.Fatal("ocamlTOCFits")
	}
}
