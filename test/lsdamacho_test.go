package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// lsdaMachOFixtureSource exercises a virtual destructor, a virtual method, a
// throw and two catch clauses, which is the smallest program that makes ld64
// write several LSDA blobs with real type tables into __gcc_except_tab.
const lsdaMachOFixtureSource = `#include <stdexcept>
int sink;
struct Base { virtual ~Base(); virtual int f() { return 1; } };
Base::~Base() { sink++; }
struct Derived : Base { ~Derived(); int f() override { return 2; } };
Derived::~Derived() { sink++; }
__attribute__((noinline)) int run(int argc) {
  try {
    if (argc > 1) throw std::runtime_error("x");
    throw std::out_of_range("y");
  } catch (const std::runtime_error&) { return 1; }
    catch (const std::out_of_range&) { return 2; }
  return 0;
}
int main(int argc, char**) { Derived d; return run(argc) + d.f(); }
`

// lsdaMachOCompile builds one fixture in a temp dir. The inspector under test
// never runs the produced program.
func lsdaMachOCompile(t *testing.T, compiler, file, source string, args ...string) string {
	t.Helper()
	if _, err := exec.LookPath(compiler); err != nil {
		t.Skipf("%s not installed", compiler)
	}
	dir := t.TempDir()
	src := filepath.Join(dir, file)
	if err := os.WriteFile(src, []byte(source), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, strings.TrimSuffix(file, filepath.Ext(file)))
	cmd := exec.Command(compiler, append(args, src, "-o", out)...)
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%s: %v\n%s", compiler, err, b)
	}
	return out
}

func lsdaMachONote(t *testing.T, path string) string {
	t.Helper()
	d, err := Probe(path)
	if err != nil {
		t.Fatal(err)
	}
	var note string
	for _, n := range d.Notes {
		if strings.HasPrefix(n, "deep: cxx-eh-macho ") {
			note = n
		}
	}
	if note == "" {
		t.Fatalf("no cxx-eh-macho note: %v", d.Notes)
	}
	for _, s := range d.Skipped {
		if strings.HasPrefix(s.Reason, "lsdamacho-") {
			t.Fatalf("good fixture refused: %s: %s", s.Reason, s.Detail)
		}
	}
	if !containsStr(d.Capabilities, "cxx-eh") {
		t.Fatalf("capability cxx-eh missing: %v", d.Capabilities)
	}
	return note
}

func TestLSDAMachOFixture(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("the fixture is a Mach-O final image")
	}
	bin := lsdaMachOCompile(t, "clang++", "t.cpp", lsdaMachOFixtureSource, "-O1", "-fexceptions")
	note := lsdaMachONote(t, bin)
	for _, want := range []string{"std::runtime_error", "std::out_of_range"} {
		if !strings.Contains(note, want) {
			t.Fatalf("note %q missing %q", note, want)
		}
	}
	var n int
	if _, err := fmt.Sscanf(note[strings.Index(note, "cxx-eh-macho "):], "cxx-eh-macho %d LSDAs,", &n); err != nil || n < 2 {
		t.Fatalf("note %q: want >=2 LSDA records, err=%v", note, err)
	}

	// Shipped binaries are stripped: the symbol fallback is gone, so this is the
	// path that proves the __unwind_info list and the chained-fixup type names.
	if _, err := exec.LookPath("strip"); err != nil {
		t.Log("strip not installed; skipping the stripped path")
		return
	}
	stripped := filepath.Join(t.TempDir(), "stripped")
	if b, err := exec.Command("strip", "-o", stripped, bin).CombinedOutput(); err != nil {
		t.Logf("strip: %v\n%s", err, b)
		return
	}
	note = lsdaMachONote(t, stripped)
	if !strings.Contains(note, "std::runtime_error") || !strings.Contains(note, "std::out_of_range") {
		t.Fatalf("stripped note %q lost a catch type", note)
	}
}

func TestLSDAMachOAbsentOnC(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("the fixture is a Mach-O final image")
	}
	bin := lsdaMachOCompile(t, "clang", "c.c", "int main(void) { return 0; }\n", "-O1")
	d, err := Probe(bin)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range d.Skipped {
		if strings.HasPrefix(s.Reason, "lsdamacho-") {
			t.Fatalf("plain C binary got a reader skip: %s: %s", s.Reason, s.Detail)
		}
	}
	for _, n := range d.Notes {
		if strings.HasPrefix(n, "deep: cxx-eh-macho ") {
			t.Fatalf("plain C binary got a note: %s", n)
		}
	}
}

// lsdaMachOSynthetic builds a 64-bit Mach-O with one __TEXT segment holding a
// __gcc_except_tab section and a one-entry __unwind_info. The segment's vmaddr
// is 0 and every section addr is its file offset, so the image-base-relative
// lsdaOffset is the blob's file offset plus rel.
func lsdaMachOSynthetic(gcc []byte, rel uint32) []byte {
	const hdr, segCmd, sectHdr = 32, 72, 80
	cmdSize := segCmd + sectHdr*2
	gccOff := hdr + cmdSize
	infoOff := (gccOff + len(gcc) + 7) &^ 7

	// Header, one index entry and its lsda array, then the sentinel entry whose
	// array offset ends the first range.
	info := make([]byte, 28+12*2+8)
	binary.LittleEndian.PutUint32(info[0:], 1)  // version
	binary.LittleEndian.PutUint32(info[4:], 28) // common encodings
	binary.LittleEndian.PutUint32(info[8:], 0)
	binary.LittleEndian.PutUint32(info[12:], 28) // personalities
	binary.LittleEndian.PutUint32(info[16:], 0)
	binary.LittleEndian.PutUint32(info[20:], 28) // index
	binary.LittleEndian.PutUint32(info[24:], 2)  // one page + sentinel
	binary.LittleEndian.PutUint32(info[28:], 0x1000)
	binary.LittleEndian.PutUint32(info[32:], 0)
	binary.LittleEndian.PutUint32(info[36:], 52) // lsda array starts here
	binary.LittleEndian.PutUint32(info[40:], 0x2000)
	binary.LittleEndian.PutUint32(info[44:], 0)
	binary.LittleEndian.PutUint32(info[48:], 60) // sentinel: end of the array
	binary.LittleEndian.PutUint32(info[52:], 0)
	binary.LittleEndian.PutUint32(info[56:], uint32(gccOff)+rel)

	total := infoOff + len(info)
	b := make([]byte, total)
	binary.LittleEndian.PutUint32(b[0:], 0xfeedfacf)
	binary.LittleEndian.PutUint32(b[4:], 0x0100000c) // arm64
	binary.LittleEndian.PutUint32(b[12:], 2)         // MH_EXECUTE
	binary.LittleEndian.PutUint32(b[16:], 1)         // ncmds
	binary.LittleEndian.PutUint32(b[20:], uint32(cmdSize))

	seg := b[hdr:]
	binary.LittleEndian.PutUint32(seg[0:], 0x19) // LC_SEGMENT_64
	binary.LittleEndian.PutUint32(seg[4:], uint32(cmdSize))
	copy(seg[8:24], "__TEXT")
	binary.LittleEndian.PutUint64(seg[40:], uint64(total)) // vmsize
	binary.LittleEndian.PutUint64(seg[48:], uint64(total)) // filesize
	binary.LittleEndian.PutUint32(seg[64:], 2)
	copy(b[gccOff:], gcc)
	copy(b[infoOff:], info)
	put := func(i int, name string, off, size int) {
		sc := seg[segCmd+i*sectHdr:]
		copy(sc[0:16], name)
		copy(sc[16:32], "__TEXT")
		binary.LittleEndian.PutUint64(sc[32:], uint64(off))
		binary.LittleEndian.PutUint64(sc[40:], uint64(size))
		binary.LittleEndian.PutUint32(sc[48:], uint32(off))
	}
	put(0, "__gcc_except_tab", gccOff, len(gcc))
	put(1, "__unwind_info", infoOff, len(info))
	return b
}

func lsdaMachORefusal(t *testing.T, b []byte) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	d, err := Probe(path)
	if err != nil {
		t.Fatal(err)
	}
	var refusals []Skip
	for _, s := range d.Skipped {
		if strings.HasPrefix(s.Reason, "lsdamacho-") {
			refusals = append(refusals, s)
		}
	}
	if len(refusals) != 1 {
		t.Fatalf("want exactly one lsdamacho refusal, got %+v", refusals)
	}
	switch refusals[0].Reason {
	case lsdamachoHeaderBad, lsdamachoOffsetOutside:
	default:
		t.Fatalf("refusal %q is outside the closed set for a broken table", refusals[0].Reason)
	}
	for _, n := range d.Notes {
		if strings.HasPrefix(n, "deep: cxx-eh-macho ") {
			t.Fatalf("partial claim survived a bad table: %s", n)
		}
	}
	if containsStr(d.Capabilities, "cxx-eh") {
		t.Fatalf("partial claim set the cxx-eh capability: %v", d.Capabilities)
	}
}

func TestLSDAMachORefusal(t *testing.T) {
	// lsdaMachOSynthetic builds the image in memory: debug/macho parses it on
	// any host, so this test does not need a darwin toolchain.
	// A call-site table that claims more bytes than the record holds.
	lsdaMachORefusal(t, lsdaMachOSynthetic([]byte{0xff, 0xff, 0x01, 0x7f}, 0))
	// A type-table offset past the record.
	lsdaMachORefusal(t, lsdaMachOSynthetic([]byte{0xff, 0x9b, 0x10, 0x01, 0x00}, 0))
}

// TestLSDAMachOTruncatedIsNotAbsent: same rule as the .eh_frame reader. A cut
// Mach-O made the compact-unwind walker fail to open the file, which is an
// unreadable header, not proof that the image has no LSDA blobs.
func TestLSDAMachOTruncatedIsNotAbsent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cut-macho")
	if err := os.WriteFile(path, truncatedMachOHead(), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	d, err := Probe(path)
	if err != nil {
		t.Fatalf("Probe(%s): %v", path, err)
	}
	reasons := skippedReasons(d)
	if !reasons[lsdamachoHeaderBad] {
		t.Fatalf("skipped = %+v, want reason %q for a cut Mach-O", d.Skipped, lsdamachoHeaderBad)
	}
	if reasons[lsdamachoAbsent] {
		t.Fatalf("cut Mach-O also claimed %q; absence and an unreadable header are different claims", lsdamachoAbsent)
	}
}
