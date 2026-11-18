package main

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const libcryptoDylib = "/opt/homebrew/opt/openssl@3/lib/libcrypto.3.dylib"

// --- hand-built fixtures ---

// constELF writes an ELF64 whose sections carry one SHA-256 K table in .text,
// the CRC-32 polynomial in .rodata, an undefined mprotect in .dynsym and a
// .symtab with one local, one exported and one FILE symbol. extra bytes are
// placed in .rodata behind the polynomial.
func constELF(t *testing.T, extra []byte) string {
	t.Helper()
	const (
		textOff  = 0x200
		roOff    = 0x300
		dstrOff  = 0x400
		dsymOff  = 0x440
		strOff   = 0x470
		symOff   = 0x4a0
		shstrOff = 0x530
		shOff    = 0x600
		textAddr = 0x401000
	)
	shstr := []byte("\x00.text\x00.rodata\x00.dynstr\x00.dynsym\x00.strtab\x00.symtab\x00.shstrtab\x00")
	dstr := []byte("\x00mprotect\x00")
	str := []byte("\x00local_helper\x00exported_fn\x00crt.o\x00")
	b := make([]byte, shOff+8*64)

	copy(b, "\x7fELF")
	b[4], b[5], b[6], b[7] = 2, 1, 1, 0
	le := binary.LittleEndian
	le.PutUint16(b[0x10:], 2)  // ET_EXEC
	le.PutUint16(b[0x12:], 62) // EM_X86_64
	le.PutUint32(b[0x14:], 1)
	le.PutUint64(b[0x18:], textAddr)
	le.PutUint64(b[0x28:], shOff)
	le.PutUint16(b[0x34:], 64) // e_ehsize
	le.PutUint16(b[0x3a:], 64) // e_shentsize
	le.PutUint16(b[0x3c:], 8)  // e_shnum
	le.PutUint16(b[0x3e:], 7)  // e_shstrndx

	copy(b[textOff+8:], cryptoTables[1].needle) // sha256_K at .text+8
	copy(b[roOff:], cryptoTables[6].needle)     // crc32_poly at .rodata+0
	copy(b[roOff+0x20:], extra)                 // optional second table at .rodata+0x20
	copy(b[dstrOff:], dstr)
	copy(b[strOff:], str)
	copy(b[shstrOff:], shstr)

	putSym := func(off int, name uint32, info byte, shndx uint16) {
		e := b[off:]
		le.PutUint32(e[0:], name)
		e[4] = info // bind<<4 | type
		le.PutUint16(e[6:], shndx)
		le.PutUint64(e[8:], textAddr)
	}
	putSym(dsymOff+24, 1, 0x12, 0)      // STB_GLOBAL|STT_FUNC, undefined
	putSym(symOff+24, 1, 0x02, 1)       // local_helper
	putSym(symOff+48, 14, 0x12, 1)      // exported_fn
	putSym(symOff+72, 26, 0x04, 0xfff1) // crt.o, STT_FILE

	putSH := func(idx int, name, typ uint32, flags, addr, off, size, align uint64, link, info uint32) {
		sh := b[shOff+idx*64:]
		le.PutUint32(sh[0x00:], name)
		le.PutUint32(sh[0x04:], typ)
		le.PutUint64(sh[0x08:], flags)
		le.PutUint64(sh[0x10:], addr)
		le.PutUint64(sh[0x18:], off)
		le.PutUint64(sh[0x20:], size)
		le.PutUint32(sh[0x28:], link)
		le.PutUint32(sh[0x2c:], info)
		le.PutUint64(sh[0x30:], align)
	}
	putSH(1, 1, 1, 6, textAddr, textOff, 0x80, 16, 0, 0) // .text
	putSH(2, 7, 1, 2, 0x402000, roOff, 0x40, 16, 0, 0)   // .rodata
	putSH(3, 15, 3, 2, 0, dstrOff, uint64(len(dstr)), 1, 0, 0)
	putSH(4, 23, 11, 2, 0x402100, dsymOff, 48, 8, 3, 1) // .dynsym -> .dynstr
	putSH(5, 31, 3, 0, 0, strOff, uint64(len(str)), 1, 0, 0)
	putSH(6, 39, 2, 0, 0, symOff, 96, 8, 5, 2) // .symtab -> .strtab, locals=2
	putSH(7, 47, 3, 0, 0, shstrOff, uint64(len(shstr)), 1, 0, 0)

	path := filepath.Join(t.TempDir(), "const.elf")
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// constPE writes a PE32+ image with one .rdata section holding the MD5 IV and
// no import table: constants fire, jit and names stay honest strings.
func constPE(t *testing.T) string {
	t.Helper()
	img := make([]byte, 0x400)
	le := binary.LittleEndian
	copy(img, "MZ")
	le.PutUint32(img[0x3c:], 0x40)
	copy(img[0x40:], "PE\x00\x00")
	coff := img[0x44:]
	le.PutUint16(coff[0:], pe.IMAGE_FILE_MACHINE_AMD64)
	le.PutUint16(coff[2:], 1)    // one section
	le.PutUint16(coff[16:], 240) // optional header size
	le.PutUint16(coff[18:], pe.IMAGE_FILE_EXECUTABLE_IMAGE)
	opt := coff[20:]
	le.PutUint16(opt[0:], 0x20b)
	le.PutUint32(opt[32:], 0x1000) // section alignment
	le.PutUint32(opt[36:], 0x200)  // file alignment
	le.PutUint32(opt[56:], 0x2000) // image size
	le.PutUint32(opt[60:], 0x200)  // headers size
	le.PutUint16(opt[68:], 3)      // console
	le.PutUint32(opt[108:], 16)    // number of data directories

	sec := img[0x148:]
	copy(sec, ".rdata")
	le.PutUint32(sec[8:], 0x100)              // virtual size
	le.PutUint32(sec[12:], 0x1000)            // VA
	le.PutUint32(sec[16:], 0x100)             // raw size
	le.PutUint32(sec[20:], 0x200)             // raw offset
	le.PutUint32(sec[36:], 0x40000040)        // initialized data
	copy(img[0x200:], cryptoTables[3].needle) // md5_iv

	path := filepath.Join(t.TempDir(), "const.exe")
	if err := os.WriteFile(path, img, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// --- tests ---

func TestConstScanSharedIVLabel(t *testing.T) {
	buf := append(bytes.Repeat([]byte{0xaa}, 0x40), cryptoTables[4].needle...)
	hits := scanConstants(buf, "__TEXT,__const", 0x1000)
	if len(hits) != 1 {
		t.Fatalf("hits = %d, want 1", len(hits))
	}
	if got := constLines(hits)[0]; got != "sha256|blake2s|blake3|strong|__TEXT,__const|0x1040" {
		t.Fatalf("line = %q", got)
	}
}

func TestScanConstantsSortsByOffset(t *testing.T) {
	var buf []byte
	buf = append(buf, cryptoTables[3].needle...) // md5_iv at 0
	buf = append(buf, make([]byte, 0x20)...)     // gap
	buf = append(buf, cryptoTables[1].needle...) // sha256_K at 0x30
	hits := scanConstants(buf, ".rodata", 0x200)
	lines := constLines(hits)
	want := []string{"md5_iv|strong|.rodata|0x200", "sha256_K|strong|.rodata|0x230"}
	if !slices.Equal(lines, want) {
		t.Fatalf("lines = %v, want %v", lines, want)
	}
	// Feeding the hits back in reverse must not change the order.
	slices.Reverse(hits)
	if got := constLines(hits); !slices.Equal(got, want) {
		t.Fatalf("re-sorted = %v, want %v", got, want)
	}
}

func TestSetConstantsHonest(t *testing.T) {
	cases := []struct {
		name    string
		hits    []constHit
		scanned int
		want    []string
	}{
		{"nothing scanned", nil, 0, []string{constNotScanned}},
		{"scanned, no hit", nil, 3, consts{constNotDetected}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var d Digest
			setConstants(&d, c.hits, c.scanned, 0)
			if !slices.Equal(d.Constants, consts(c.want)) {
				t.Fatalf("constants = %v, want %v", d.Constants, c.want)
			}
		})
	}
}

func TestSetConstantsCap(t *testing.T) {
	var hits []constHit
	for i := range maxConstHits + 6 {
		hits = append(hits, constHit{"md5_iv", "strong", ".data", int64(i * 16)})
	}
	var d Digest
	setConstants(&d, hits, 1, 0)
	if len(d.Constants) != maxConstHits {
		t.Fatalf("kept %d hits, want %d", len(d.Constants), maxConstHits)
	}
	if len(d.Notes) != 1 || !strings.Contains(d.Notes[0], fmt.Sprintf("constants truncated to %d of %d", maxConstHits, len(hits))) {
		t.Fatalf("notes = %v", d.Notes)
	}
}

// Twenty-one hits must all survive: a digest that drops them hides the fact
// that the table appears twenty-one times.
func TestSetConstantsKeepsTwentyOneHits(t *testing.T) {
	var hits []constHit
	for i := range 21 {
		hits = append(hits, constHit{"sha256_K", "strong", ".data", int64(i * 32)})
	}
	var d Digest
	setConstants(&d, hits, 1, 0)
	if len(d.Constants) != 21 {
		t.Fatalf("kept %d hits, want 21", len(d.Constants))
	}
	if len(d.Notes) != 0 {
		t.Fatalf("notes = %v, want none", d.Notes)
	}
}

func TestJITToken(t *testing.T) {
	cases := []struct {
		name  string
		token string
		ok    bool
	}{
		{"_pthread_jit_write_protect_np", "pthread_jit_write_protect_np", true},
		{"_pthread_jit_mprotect_np", "pthread_jit", true},
		{"_mprotect", "mprotect", true},
		{"mprotect@GLIBC_2.2.5", "mprotect", true},
		{"libJavaScriptCore.dylib", "JavaScriptCore", true},
		{"__ZN2v88internal4HeapD2Ev", "v8", true},
		{"libv8.dylib", "v8", true},
		{"_malloc", "", false},
		{"_vm_protect", "", false},
		{"_VirtualProtect", "", false},
	}
	for _, c := range cases {
		got, ok := jitToken(c.name)
		if got != c.token || ok != c.ok {
			t.Fatalf("jitToken(%q) = %q,%v want %q,%v", c.name, got, ok, c.token, c.ok)
		}
	}
}

func TestJITValue(t *testing.T) {
	var d Digest
	if got := jitValue(&d, nil); got != jitNotDetected {
		t.Fatalf("empty = %q, want %q", got, jitNotDetected)
	}
	got := jitValue(&d, []string{"pthread_jit", "mprotect", "mprotect"})
	if got != "imports:mprotect,pthread_jit" {
		t.Fatalf("value = %q", got)
	}
}

func TestNamesValue(t *testing.T) {
	if got := namesValue(0); got != nameNotRecovered {
		t.Fatalf("zero = %q, want %q", got, nameNotRecovered)
	}
	if got := namesValue(7); got != "local:7" {
		t.Fatalf("count = %q", got)
	}
}

func TestNativeELFConstantsJITNames(t *testing.T) {
	path := constELF(t, nil)
	d := probeFixture(t, path)
	want := []string{"sha256_K|strong|.text|0x208", "crc32_poly|weak|.rodata|0x300"}
	if !slices.Equal(d.Constants, consts(want)) {
		t.Fatalf("constants = %v, want %v", d.Constants, want)
	}
	if d.JIT != "imports:mprotect" {
		t.Fatalf("jit = %q", d.JIT)
	}
	if d.Names != "local:1" { // the STT_FILE marker is not a recovered name
		t.Fatalf("names = %q", d.Names)
	}

	first, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	again, err := Probe(path)
	if err != nil {
		t.Fatal(err)
	}
	second, err := json.Marshal(again)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("same file, different digest:\n%s\n%s", first, second)
	}
}

// A big-endian ELF stores the same tables swapped. Missing that form means a
// ppc64 target reports no constants at all.
func TestNativeELFConstantsBigEndian(t *testing.T) {
	path := constELF(t, cryptoTables[1].be) // sha256_K, big-endian form
	d := probeFixture(t, path)
	want := "sha256_K|strong|.rodata|0x320"
	if !slices.Contains(d.Constants, want) {
		t.Fatalf("missing %q from %v", want, d.Constants)
	}
}

func TestNativePEConstantsHonest(t *testing.T) {
	d := probeFixture(t, constPE(t))
	want := []string{"md5_iv|strong|.rdata|0x200"}
	if !slices.Equal(d.Constants, consts(want)) {
		t.Fatalf("constants = %v, want %v", d.Constants, want)
	}
	if d.JIT != jitNotDetected {
		t.Fatalf("jit = %q, want %q", d.JIT, jitNotDetected)
	}
	if d.Names != nameNotRecovered {
		t.Fatalf("names = %q, want %q", d.Names, nameNotRecovered)
	}
}

func TestConstantsRealTargets(t *testing.T) {
	// A tracked real Mach-O (Go-built) is the host-independent stand-in for a
	// system dylib: it carries one chacha table in __TEXT,__rodata.
	d := probeFixture(t, fixtureMacho)
	for _, want := range []string{
		"chacha_sigma|strong|__TEXT,__rodata|0xa9c40",
	} {
		if !slices.Contains(d.Constants, want) {
			t.Fatalf("missing %q from %v", want, d.Constants)
		}
	}
	// The JSON document is complete by contract (main.go: only text output obeys
	// the budget). What must stay honest is the text rendering: it has to fit
	// the budget and, when the full text did not, say it was cut.
	const budget = 300 // > evidence line + budgetNoteReserve, so the cut is real
	txt := digestText(d, budget)
	if len(d.Text()) <= budget {
		t.Fatalf("full text is only %d bytes; the budget check proved nothing", len(d.Text()))
	}
	if len(txt) > budget {
		t.Fatalf("text digest is %d bytes, over the %d-byte budget", len(txt), budget)
	}
	if !strings.Contains(txt, "note: truncated at ") {
		t.Fatalf("digest text is %d bytes and the %d-byte budget did not say it was cut", len(d.Text()), budget)
	}

	// A real Mach-O with no crypto tables must say so rather than match
	// something. The Unity player is the tracked binary for that: a Go or fat
	// fixture carries chacha tables of its own and would answer detected.
	plain := probeFixture(t, "testdata/fixtures/il2cpp/player.bin")
	if !slices.Equal(plain.Constants, consts{constNotDetected}) {
		t.Fatalf("player constants = %v, want not_detected", plain.Constants)
	}
	if plain.JIT != jitNotDetected {
		t.Fatalf("player jit = %q, want %q", plain.JIT, jitNotDetected)
	}
	// Names must still be recovered from a Mach-O with no crypto tables, or the
	// negative above could be a reader that gave up on the file entirely.
	if named := probeFixture(t, fixtureRust); named.Names == nameNotRecovered {
		t.Fatalf("rust fixture names = %q, want a recovered list", named.Names)
	}
}

// A big-endian target stores the same word tables swapped. Missing that form
// means a ppc64 target reports no constants at all.
func TestScanConstantsBigEndian(t *testing.T) {
	be := cryptoTables[4].be // sha256|blake2s|blake3
	if len(be) == 0 {
		t.Fatal("shared IV table has no big-endian form")
	}
	buf := append([]byte{0xaa, 0xbb}, be...)
	hits := scanConstants(buf, ".rodata", 0x1000)
	if len(hits) != 1 {
		t.Fatalf("hits = %v, want 1", hits)
	}
	if hits[0].label != "sha256|blake2s|blake3" || hits[0].off != 0x1002 {
		t.Fatalf("hit = %+v", hits[0])
	}
}

// A section bigger than one window is still searched end to end, and a needle
// that straddles the window seam is not lost.
func TestScanSectionWindows(t *testing.T) {
	buf := make([]byte, 12<<20)
	copy(buf[constWindow-10:], cryptoTables[1].needle) // straddles the seam
	copy(buf[len(buf)-64:], cryptoTables[4].be)        // past the old 8 MiB cap
	hits, read, partial := scanSection(bytes.NewReader(buf), 0, int64(len(buf)), ".data")
	if read != int64(len(buf)) {
		t.Fatalf("read %d bytes, want %d", read, len(buf))
	}
	if partial {
		t.Fatal("section reported as capped although it fits the budget")
	}
	if len(hits) != 2 {
		t.Fatalf("hits = %v, want 2", hits)
	}
	if hits[0].off != int64(constWindow-10) {
		t.Fatalf("seam hit at %#x, want %#x", hits[0].off, constWindow-10)
	}
	if hits[1].off != int64(len(buf)-64) {
		t.Fatalf("tail hit at %#x, want %#x", hits[1].off, len(buf)-64)
	}
}

// A digest that never scanned for constants must say so instead of leaving the
// field empty: an absent field reads as "nothing found".
func TestUnknownTargetSaysNotScanned(t *testing.T) {
	d := probeFixture(t, writeTemp(t, "g.bin", bytes.Repeat([]byte{0x00, 0x01}, 2500)))
	if len(d.Constants) != 1 || d.Constants[0] != constNotScanned {
		t.Fatalf("constants = %v, want not_scanned", d.Constants)
	}
}
