package main

import (
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// msvcFixture is the cross-compile input: clang emits ??_R0..??_R4 for every
// polymorphic class, including the virtual base that exercises pdisp/vdisp.
const msvcFixture = `
struct Base { virtual void f(); int b; };
void Base::f() {}
struct Mid : virtual Base { virtual void g(); int m; };
void Mid::g() {}
struct Leaf : Mid { void f() override; int l; };
void Leaf::f() {}
Leaf *make() { return new Leaf; }
`

// msvcRTTISection lays out one locator for Demo : Base inside a PE section at
// RVA 0x1000. The vftable slot before the first method is the pointer the scan
// follows; the COL self pointer is the second, CFG-era pointer.
func msvcRTTISection(name, baseName string) []byte {
	const (
		base  = 0x1000
		td1   = 0x1000
		td2   = 0x1040
		chd   = 0x1080
		arr   = 0x1090
		bcd1  = 0x10a0
		bcd2  = 0x10c0
		col   = 0x10e0
		vft   = 0x1100
		secSz = 0x400
	)
	b := make([]byte, secSz)
	at := func(rva uint32) []byte { return b[rva-base:] }
	put := func(rva int, v uint32) { binary.LittleEndian.PutUint32(b[rva-base:], v) }

	copy(at(td1)[16:], name+"\x00")
	copy(at(td2)[16:], baseName+"\x00")

	put(chd+8, 2)    // numBaseClasses, self first
	put(chd+12, arr) // pBaseClassArray
	put(arr, bcd1)   // pre-order: Demo, then Base
	put(arr+4, bcd2)
	put(bcd1, td1)     // BaseClassDescriptor: type descriptor
	put(bcd1+4, 1)     // numContainedBases
	put(bcd1+20, 0x40) // attributes
	put(bcd1+24, chd)  // class hierarchy
	put(bcd2, td2)
	put(bcd2+20, 0x40)
	put(bcd2+24, chd)
	put(col, 1)      // signature
	put(col+4, 0x10) // vftable offset
	put(col+12, td1) // type descriptor
	put(col+16, chd) // class hierarchy
	put(col+20, col) // self pointer
	put(vft+8, col)  // vftable[-8]
	return b
}

// msvcPEFixture wraps section bytes in a minimal PE32+ image: one .rdata
// section at RVA 0x1000, raw at 0x200. No linker is available on this host, so
// the PE path is tested against this hand-built image.
func msvcPEFixture(section []byte) []byte {
	const (
		peOff   = 0x80
		optSize = 0xf0
		secOff  = 0x80 + 4 + 20 + optSize
		rawOff  = 0x200
		rvaBase = 0x1000
		rawSize = 0x400
	)
	b := make([]byte, rawOff+rawSize)
	copy(b, "MZ")
	binary.LittleEndian.PutUint32(b[0x3c:], peOff)
	copy(b[peOff:], "PE\x00\x00")
	fh := b[peOff+4:]
	binary.LittleEndian.PutUint16(fh[0:], 0x8664)   // IMAGE_FILE_MACHINE_AMD64
	binary.LittleEndian.PutUint16(fh[2:], 1)        // NumberOfSections
	binary.LittleEndian.PutUint16(fh[16:], optSize) // SizeOfOptionalHeader
	binary.LittleEndian.PutUint16(fh[18:], 0x0022)  // executable image
	oh := fh[20:]
	binary.LittleEndian.PutUint16(oh[0:], 0x20b)   // PE32+
	binary.LittleEndian.PutUint32(oh[32:], 0x1000) // SectionAlignment
	binary.LittleEndian.PutUint32(oh[36:], 0x200)  // FileAlignment
	binary.LittleEndian.PutUint32(oh[56:], 0x2000) // SizeOfImage
	binary.LittleEndian.PutUint32(oh[60:], rawOff) // SizeOfHeaders
	binary.LittleEndian.PutUint16(oh[68:], 3)      // IMAGE_SUBSYSTEM_WINDOWS_CUI
	binary.LittleEndian.PutUint32(oh[108:], 16)    // NumberOfRvaAndSizes
	sh := b[secOff:]
	copy(sh, ".rdata")
	binary.LittleEndian.PutUint32(sh[8:], rawSize)  // VirtualSize
	binary.LittleEndian.PutUint32(sh[12:], rvaBase) // VirtualAddress
	binary.LittleEndian.PutUint32(sh[16:], rawSize) // SizeOfRawData
	binary.LittleEndian.PutUint32(sh[20:], rawOff)  // PointerToRawData
	binary.LittleEndian.PutUint32(sh[36:], 0x40000040)
	copy(b[rawOff:], section)
	return b
}

func msvcNote(d Digest, prefix string) string {
	for _, n := range d.Notes {
		if strings.HasPrefix(n, prefix) {
			return n
		}
	}
	return ""
}

func msvcSkipped(d Digest, prefix string) []string {
	var out []string
	for _, s := range d.Skipped {
		if strings.HasPrefix(s.Reason, prefix) {
			out = append(out, s.Reason+": "+s.Detail)
		}
	}
	return out
}

// TestMSVCRttiPE: hand-built image, so the linked-image RVA path is covered
// without lld-link. The locator is reachable only through the vftable slot.
func TestMSVCRttiPE(t *testing.T) {
	path := writeTemp(t, "demo.exe", msvcPEFixture(msvcRTTISection(".?AVDemo@@", ".?AVBase@@")))
	d := probeFixture(t, path)
	if d.Kind != "pe" {
		t.Fatalf("kind = %q, want pe", d.Kind)
	}
	line := msvcNote(d, "msvc-class ")
	if line != "msvc-class 1 (Demo 2 [Demo Base] @0x10)" {
		t.Fatalf("msvc-class = %q", line)
	}
	if s := msvcSkipped(d, "msvcrti-"); len(s) != 0 {
		t.Fatalf("unexpected refusals: %v", s)
	}
	if !strings.Contains(d.Text(), "msvc-class 1") {
		t.Fatalf("note missing from Text:\n%s", d.Text())
	}
	t.Logf("hand-built PE: %s", line)
}

// TestMSVCRttiAbsentPE: a PE with no locator is an answer only because the whole
// file was read; an absent reason is exactly the claim the reader must gate.
func TestMSVCRttiAbsentPE(t *testing.T) {
	path := writeTemp(t, "plain.exe", msvcPEFixture(make([]byte, 0x400)))
	d := probeFixture(t, path)
	if line := msvcNote(d, "msvc-class "); line != "" {
		t.Fatalf("recovered a class from an empty .rdata: %q", line)
	}
	reasons := msvcSkipped(d, "msvcrti-absent")
	if len(reasons) != 1 {
		t.Fatalf("want one msvcrti-absent refusal, got %v", reasons)
	}
}

// TestMSVCRttiRefusals exercises the two refusals a linked image cannot reach:
// an unrelocated object field and a type name that is not type-info spelling.
func TestMSVCRttiRefusals(t *testing.T) {
	good := msvcRTTISection(".?AVDemo@@", ".?AVBase@@")
	sec := &msvcSec{name: ".rdata", rva: 0x1000, data: good}
	img := &msvcImage{secs: []*msvcSec{sec}, ptr: 8}
	cls, reason, detail := img.parseCol(msvcPos{sec: sec, off: 0xe0})
	if reason != "" {
		t.Fatalf("valid locator refused: %s: %s", reason, detail)
	}
	if cls.name != "Demo" || len(cls.bases) != 2 || cls.bases[1] != "Base" || cls.offsets[0] != 0x10 {
		t.Fatalf("recovered %+v", cls)
	}

	bad := &msvcSec{name: ".rdata", rva: 0x1000,
		data: msvcRTTISection("notrtti", ".?AVBase@@")}
	imgBad := &msvcImage{secs: []*msvcSec{bad}, ptr: 8}
	if _, reason, _ := imgBad.parseCol(msvcPos{sec: bad, off: 0xe0}); reason != msvcReasonName {
		t.Fatalf("bad name reason = %q, want %q", reason, msvcReasonName)
	}

	// A COFF object field with no ADDR32NB fixup must not be read as an offset
	// into the section that holds the locator.
	objSec := &msvcSec{name: ".rdata", data: good}
	obj := &msvcImage{obj: true, machine: 0x8664, ptr: 8, secs: []*msvcSec{objSec}}
	if _, reason, _ := obj.parseCol(msvcPos{sec: objSec, off: 0xe0}); reason != msvcReasonImage {
		t.Fatalf("unrelocated reason = %q, want %q", reason, msvcReasonImage)
	}
}

// TestMSVCRttiChdReason: a malformed hierarchy descriptor is the descriptor's
// own shape even in an object, where every unresolved field is an image-base
// failure; only an unresolved base array keeps that reason.
func TestMSVCRttiChdReason(t *testing.T) {
	fixture := msvcRTTISection(".?AVDemo@@", ".?AVBase@@")
	sec := &msvcSec{name: ".rdata", rva: 0x1000, data: fixture}
	img := &msvcImage{secs: []*msvcSec{sec}, ptr: 8}
	if st, ok := img.chdValid(msvcPos{sec: sec, off: 0x80}); !ok || st != msvcRefOK {
		t.Fatalf("valid hierarchy refused: status=%v ok=%v", st, ok)
	}

	bad := append([]byte(nil), fixture...)
	binary.LittleEndian.PutUint32(bad[0x80:], 2) // signature > 1
	badSec := &msvcSec{name: ".rdata", rva: 0x1000, data: bad}
	badImg := &msvcImage{secs: []*msvcSec{badSec}, ptr: 8}
	if st, ok := badImg.chdValid(msvcPos{sec: badSec, off: 0x80}); ok || st != msvcRefOK {
		t.Fatalf("bad signature accepted: status=%v ok=%v", st, ok)
	}
	for _, tc := range []struct {
		st     msvcRefStatus
		object bool
		want   string
	}{
		{msvcRefOK, true, msvcReasonCol},        // shape failure in an object
		{msvcRefOK, false, msvcReasonCol},       // shape failure in an image
		{msvcRefNoFixup, true, msvcReasonImage}, // unresolved field in an object
		{msvcRefNoFixup, false, msvcReasonCol},
	} {
		if got := msvcChdReason(tc.st, tc.object); got != tc.want {
			t.Errorf("msvcChdReason(%v, object=%v) = %q, want %q", tc.st, tc.object, got, tc.want)
		}
	}
}

// TestMSVCMachineTable: one row per machine feeds membership, pointer width and
// the image-relative fixup, so a machine cannot be accepted by one question and
// mis-sized by another.
func TestMSVCMachineTable(t *testing.T) {
	for _, mi := range msvcMachines {
		if !msvcMachine(mi.machine) {
			t.Errorf("%#x not accepted by msvcMachine", mi.machine)
		}
		if got := msvcPointerSize(mi.machine); got != mi.ptr {
			t.Errorf("%#x pointer size = %d, want %d", mi.machine, got, mi.ptr)
		}
		if mi.ptr != 4 && mi.ptr != 8 {
			t.Errorf("%#x pointer size %d is not a pointer", mi.machine, mi.ptr)
		}
		if !msvcImageReloc(mi.machine, mi.reloc) {
			t.Errorf("%#x rejects its own fixup %#x", mi.machine, mi.reloc)
		}
		if msvcImageReloc(mi.machine, mi.reloc+1) {
			t.Errorf("%#x accepts fixup %#x", mi.machine, mi.reloc+1)
		}
	}
	const unknown = 0x1234
	if msvcMachine(unknown) || msvcPointerSize(unknown) != 4 || msvcImageReloc(unknown, 0x0003) {
		t.Errorf("%#x is not a machine this reader addresses", unknown)
	}
}

// TestMSVCRttiCOFF cross-compiles the fixture with clang and reads the object's
// symbols plus raw sections: ??_R4 names the locator, and every image-relative
// field is resolved through its ADDR32NB relocation.
func TestMSVCRttiCOFF(t *testing.T) {
	cc, err := exec.LookPath("clang")
	if err != nil {
		t.Skipf("clang unavailable: %v", err)
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "t.cpp")
	if err := os.WriteFile(src, []byte(msvcFixture), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	obj := filepath.Join(dir, "t.obj")
	out, err := exec.Command(cc, "--target=x86_64-pc-windows-msvc",
		"-fms-extensions", "-fno-exceptions", "-c", src, "-o", obj).CombinedOutput()
	if err != nil {
		t.Skipf("clang has no x86_64-pc-windows-msvc target: %v\n%s", err, out)
	}
	d := probeFixture(t, obj)
	if d.Kind != "unknown" {
		t.Fatalf("kind = %q, want unknown (a COFF object has no magic)", d.Kind)
	}
	line := msvcNote(d, "msvc-class ")
	for _, want := range []string{
		"msvc-class 3",
		"(Leaf 3 [Leaf Mid Base] @0x0,0x20)",
		"(Mid 2 [Mid Base] @0x0,0x18)",
		"(Base 1 [Base] @0x0)",
	} {
		if !strings.Contains(line, want) {
			t.Fatalf("msvc-class %q missing %q", line, want)
		}
	}
	if s := msvcSkipped(d, "msvcrti-"); len(s) != 0 {
		t.Fatalf("unexpected refusals: %v", s)
	}
	if d.Coverage == nil || d.Coverage.Parsed < 5 {
		t.Fatalf("coverage = %+v, want at least 5 parsed locators", d.Coverage)
	}
	t.Logf("COFF object: %s", line)
}
