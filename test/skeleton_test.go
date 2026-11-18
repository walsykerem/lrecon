package main

import (
	"bytes"
	"debug/elf"
	"debug/macho"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// --- hand-built fixtures, no toolchain and no external binary ---

func putU32(w *bytes.Buffer, v uint32) { binary.Write(w, binary.LittleEndian, v) }

func putS32(w *bytes.Buffer, v int32) { binary.Write(w, binary.LittleEndian, v) }

// skeletonELF writes a tiny ELF64 with .text and, when frames is set,
// .eh_frame + .eh_frame_hdr whose two FDEs use DW_EH_PE_datarel|sdata4 (0x3b).
func skeletonELF(t *testing.T, frames bool) string {
	t.Helper()
	return skeletonELFEnc(t, frames, 0x3b)
}

// skeletonELFEnc is skeletonELF with the FDE pointer encoding chosen by the
// caller: 0x3b (datarel) resolves against the .eh_frame_hdr base, 0x1b (pcrel)
// against the address of the field itself.
func skeletonELFEnc(t *testing.T, frames bool, enc byte) string {
	t.Helper()
	const (
		textAddr  = uint64(0x401000)
		hdrAddr   = uint64(0x400200)
		frameAddr = uint64(0x400300)
		textOff   = 0x200
		hdrOff    = 0x240
		frameOff  = 0x280
	)
	shstr := []byte("\x00.text\x00.eh_frame_hdr\x00.eh_frame\x00.shstrtab\x00")
	const (
		nameText  = 1
		nameHdr   = 7
		nameFrame = 21
		nameStrt  = 31
	)

	var frame bytes.Buffer
	var fdes []int
	if frames {
		appendCIE := func() int {
			off := frame.Len()
			var body bytes.Buffer
			body.WriteByte(1)          // DWARF version
			body.WriteString("zR\x00") // augmentation
			body.WriteByte(1)          // code alignment
			body.WriteByte(0x78)       // data alignment -8
			body.WriteByte(16)         // return register
			body.WriteByte(1)          // augmentation length
			body.WriteByte(enc)        // FDE pointer encoding
			putU32(&frame, uint32(body.Len()+4))
			putU32(&frame, 0) // CIE id
			frame.Write(body.Bytes())
			return off
		}
		appendFDE := func(cieOff int, start, size uint32) {
			off := frame.Len()
			var body bytes.Buffer
			// FDE body: initial_location then address_range; the augmentation
			// length follows the range in real DWARF, so it is not here.
			// initial_location: datarel resolves against .eh_frame_hdr, pcrel
			// against the address of the field itself (record offset + 8).
			if enc&0x70 == 0x10 {
				putS32(&body, int32(start-(uint32(frameAddr)+uint32(off)+8)))
			} else {
				putS32(&body, int32(start-uint32(hdrAddr)))
			}
			putU32(&body, size)
			putU32(&frame, uint32(body.Len()+4))
			putU32(&frame, uint32(off+4-cieOff)) // distance back to the CIE
			frame.Write(body.Bytes())
			fdes = append(fdes, off)
		}
		cie0 := appendCIE()
		appendFDE(cie0, 0x401000, 0x18)
		cie1 := appendCIE()
		appendFDE(cie1, 0x401020, 0x10)
	}

	var hdr bytes.Buffer
	if frames {
		hdr.WriteByte(1)    // version
		hdr.WriteByte(0x1b) // eh_frame pointer: pcrel|sdata4
		hdr.WriteByte(0x03) // count: udata4
		hdr.WriteByte(0x3b) // table: datarel|sdata4
		putS32(&hdr, int32(frameAddr-(hdrAddr+4)))
		putU32(&hdr, 2)
		for i, start := range []uint32{0x401000, 0x401020} {
			putS32(&hdr, int32(start-uint32(hdrAddr)))
			putS32(&hdr, int32(frameAddr+uint64(fdes[i])-hdrAddr))
		}
	}
	shstrOff := frameOff + frame.Len()
	total := shstrOff + len(shstr)
	b := make([]byte, total)

	copy(b, "\x7fELF")
	b[4] = 2 // ELFCLASS64
	b[5] = 1 // little endian
	b[6] = 1 // version
	b[7] = 0
	binary.LittleEndian.PutUint16(b[0x10:], 2)  // ET_EXEC
	binary.LittleEndian.PutUint16(b[0x12:], 62) // EM_X86_64
	binary.LittleEndian.PutUint32(b[0x14:], 1)
	binary.LittleEndian.PutUint64(b[0x18:], textAddr) // e_entry
	binary.LittleEndian.PutUint64(b[0x28:], 64)       // e_shoff
	binary.LittleEndian.PutUint16(b[0x34:], 64)       // e_ehsize
	binary.LittleEndian.PutUint16(b[0x3a:], 64)       // e_shentsize
	if frames {
		binary.LittleEndian.PutUint16(b[0x3c:], 5)
		binary.LittleEndian.PutUint16(b[0x3e:], 4)
	} else {
		binary.LittleEndian.PutUint16(b[0x3c:], 3)
		binary.LittleEndian.PutUint16(b[0x3e:], 2)
	}

	putSH := func(idx int, name, typ uint32, flags, addr, off, size, align uint64) {
		sh := b[64+idx*64:]
		binary.LittleEndian.PutUint32(sh[0x00:], name)
		binary.LittleEndian.PutUint32(sh[0x04:], typ)
		binary.LittleEndian.PutUint64(sh[0x08:], flags)
		binary.LittleEndian.PutUint64(sh[0x10:], addr)
		binary.LittleEndian.PutUint64(sh[0x18:], off)
		binary.LittleEndian.PutUint64(sh[0x20:], size)
		binary.LittleEndian.PutUint64(sh[0x30:], align)
	}
	putSH(1, nameText, 1, 6, textAddr, textOff, 0x40, 16) // SHF_ALLOC|SHF_EXECINSTR
	if frames {
		putSH(2, nameHdr, 1, 2, hdrAddr, hdrOff, uint64(hdr.Len()), 4)
		putSH(3, nameFrame, 1, 2, frameAddr, frameOff, uint64(frame.Len()), 8)
		copy(b[hdrOff:], hdr.Bytes())
		copy(b[frameOff:], frame.Bytes())
	}
	last := 2
	if frames {
		last = 4
	}
	putSH(last, nameStrt, 3, 0, 0, uint64(shstrOff), uint64(len(shstr)), 1)
	copy(b[shstrOff:], shstr)

	path := filepath.Join(t.TempDir(), "skeleton.elf")
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// skeletonMachO writes a thin arm64 Mach-O with one __TEXT,__text section and
// an LC_FUNCTION_STARTS chain of three deltas plus a zero terminator.
func skeletonMachO(t *testing.T) string {
	t.Helper()
	const (
		segOff   = 32
		funcOff  = segOff + 152
		chainOff = funcOff + 16
		dataOff  = chainOff + 16
	)
	payload := []byte{0x80, 0x08, 0x40, 0x40, 0x00} // 0x400, 0x40, 0x40, end
	textOff := dataOff + len(payload)
	b := make([]byte, textOff+0x100)
	le := binary.LittleEndian
	le.PutUint32(b[0:], 0xfeedfacf)
	le.PutUint32(b[4:], 0x0100000c) // CPU_TYPE_ARM64
	le.PutUint32(b[8:], 0)
	le.PutUint32(b[12:], 2)   // MH_EXECUTE
	le.PutUint32(b[16:], 3)   // ncmds
	le.PutUint32(b[20:], 184) // sizeofcmds: 152+16+16
	le.PutUint32(b[24:], 0)
	le.PutUint32(b[28:], 0)

	seg := b[segOff:]
	le.PutUint32(seg[0:], 0x19) // LC_SEGMENT_64
	le.PutUint32(seg[4:], 152)
	copy(seg[8:24], "__TEXT")
	le.PutUint64(seg[24:], 0x100000000) // vmaddr
	le.PutUint64(seg[32:], 0x1000)      // vmsize
	le.PutUint64(seg[40:], 0)
	le.PutUint64(seg[48:], uint64(len(b)))
	le.PutUint32(seg[56:], 7) // maxprot
	le.PutUint32(seg[60:], 5) // initprot
	le.PutUint32(seg[64:], 1) // nsects
	le.PutUint32(seg[68:], 0)

	sect := seg[72:]
	copy(sect[0:16], "__text")
	copy(sect[16:32], "__TEXT")
	le.PutUint64(sect[32:], 0x100000400)     // addr
	le.PutUint64(sect[40:], 0x100)           // size
	le.PutUint32(sect[48:], uint32(textOff)) // offset
	le.PutUint32(sect[52:], 4)               // align
	le.PutUint32(sect[64:], 0x80000400)      // flags: pure instructions

	le.PutUint32(b[funcOff:], 0x26) // LC_FUNCTION_STARTS
	le.PutUint32(b[funcOff+4:], 16)
	le.PutUint32(b[funcOff+8:], dataOff)
	le.PutUint32(b[funcOff+12:], uint32(len(payload)))

	le.PutUint32(b[chainOff:], 0x80000034) // LC_DYLD_CHAINED_FIXUPS
	le.PutUint32(b[chainOff+4:], 16)
	copy(b[dataOff:], payload)

	path := filepath.Join(t.TempDir(), "skeleton.macho")
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// --- tests ---

func TestSkeletonELFFrames(t *testing.T) {
	path := skeletonELF(t, true)
	f, err := elf.Open(path)
	if err != nil {
		t.Fatalf("elf.Open on fixture: %v", err)
	}
	defer f.Close()
	iv, bad, err := elfFrames(f, 0x400200)
	if err != nil {
		t.Fatalf("elfFrames: %v", err)
	}
	if bad != 0 {
		t.Fatalf("skipped %d records, want 0", bad)
	}
	want := []interval{{0x401000, 0x401018}, {0x401020, 0x401030}}
	if len(iv) != len(want) {
		t.Fatalf("intervals = %v, want %v", iv, want)
	}
	for i := range want {
		if iv[i] != want[i] {
			t.Fatalf("interval %d = %#x..%#x, want %#x..%#x", i, iv[i].start, iv[i].end, want[i].start, want[i].end)
		}
	}

	s := elfSkeleton(path)
	if s.Status != skelOK {
		t.Fatalf("status = %q, note %q", s.Status, s.Note)
	}
	if s.Intervals != 2 || s.TextBytes != 0x40 || s.Attributed != 0x28 {
		t.Fatalf("intervals/text/attributed = %d/%#x/%#x", s.Intervals, s.TextBytes, s.Attributed)
	}
	if s.Ratio == nil || *s.Ratio != 0.625 {
		t.Fatalf("ratio = %v, want 0.625", s.Ratio)
	}
	if len(s.Sources) != 1 || s.Sources[0] != "eh_frame" {
		t.Fatalf("sources = %v", s.Sources)
	}
}

// TestSkeletonELFPcrelFrames: with DW_EH_PE_pcrel every initial_location is
// relative to the address of the field itself, so resolving against the section
// base puts every FDE but the first outside .text and the skeleton reports a
// fraction of the functions the file actually records.
func TestSkeletonELFPcrelFrames(t *testing.T) {
	path := skeletonELFEnc(t, true, 0x1b)
	f, err := elf.Open(path)
	if err != nil {
		t.Fatalf("elf.Open on fixture: %v", err)
	}
	defer f.Close()
	iv, bad, err := elfFrames(f, 0x400200)
	if err != nil {
		t.Fatalf("elfFrames: %v", err)
	}
	if bad != 0 {
		t.Fatalf("skipped %d records, want 0", bad)
	}
	want := []interval{{0x401000, 0x401018}, {0x401020, 0x401030}}
	if len(iv) != len(want) {
		t.Fatalf("intervals = %v, want %v", iv, want)
	}
	for i := range want {
		if iv[i] != want[i] {
			t.Fatalf("interval %d = %#x..%#x, want %#x..%#x", i, iv[i].start, iv[i].end, want[i].start, want[i].end)
		}
	}
	if s := elfSkeleton(path); s.Intervals != 2 || s.Attributed != 0x28 {
		t.Fatalf("intervals/attributed = %d/%#x, want 2/0x28", s.Intervals, s.Attributed)
	}
}

func TestSkeletonMachOFunctionStarts(t *testing.T) {
	path := skeletonMachO(t)
	f, err := macho.Open(path)
	if err != nil {
		t.Fatalf("macho.Open on fixture: %v", err)
	}
	defer f.Close()
	iv, found, err := functionStarts(path, 0, f)
	if err != nil || !found {
		t.Fatalf("functionStarts found=%v err=%v", found, err)
	}
	want := []interval{
		{0x100000400, 0x100000440},
		{0x100000440, 0x100000480},
		{0x100000480, 0x100000500},
	}
	if len(iv) != len(want) {
		t.Fatalf("intervals = %v, want %v", iv, want)
	}
	for i := range want {
		if iv[i] != want[i] {
			t.Fatalf("interval %d = %#x..%#x, want %#x..%#x", i, iv[i].start, iv[i].end, want[i].start, want[i].end)
		}
	}

	s := machoSkeleton(path, false)
	if s.Status != skelOK {
		t.Fatalf("status = %q, note %q", s.Status, s.Note)
	}
	if s.Intervals != 3 || s.TextBytes != 0x100 || s.Attributed != 0x100 {
		t.Fatalf("intervals/text/attributed = %d/%#x/%#x", s.Intervals, s.TextBytes, s.Attributed)
	}
	if !s.ChainedFixups {
		t.Fatal("LC_DYLD_CHAINED_FIXUPS presence not recorded")
	}
	if s.Arch != "arm64" {
		t.Fatalf("arch = %q, want arm64", s.Arch)
	}
}

// TestSkeletonGoPclntab resolves the running Go test binary, so the Go path is
// exercised against a real pclntab that no fixture can fake.
func TestSkeletonGoPclntab(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Skipf("os.Executable: %v", err)
	}
	f, err := macho.Open(exe)
	if err != nil {
		t.Skipf("%s is not a thin Mach-O here: %v", exe, err)
	}
	f.Close()
	s := machoSkeleton(exe, false)
	if s.Status != skelOK {
		t.Fatalf("status = %q (note %q), want ok", s.Status, s.Note)
	}
	if s.Intervals <= 0 {
		t.Fatalf("intervals = %d, want > 0", s.Intervals)
	}
	if len(s.Sources) != 1 || s.Sources[0] != "pclntab" {
		t.Fatalf("sources = %v, want pclntab", s.Sources)
	}
}

// TestSkeletonMustNotLie: no unwind table and no symbol source means unknown,
// with no ratio in JSON, not 0% and not 100%.
func TestSkeletonMustNotLie(t *testing.T) {
	path := skeletonELF(t, false)
	s := elfSkeleton(path)
	if s.Status != skelUnknown {
		t.Fatalf("status = %q, want unknown", s.Status)
	}
	if s.Ratio != nil {
		t.Fatalf("ratio = %v, want nil", *s.Ratio)
	}
	if s.Note == "" {
		t.Fatal("unknown status with no reason string")
	}
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b, []byte("attributed_ratio")) {
		t.Fatalf("unknown skeleton emitted a ratio: %s", b)
	}
	line := s.line()
	if !bytes.HasPrefix([]byte(line), []byte("skeleton: unknown (")) {
		t.Fatalf("line = %q", line)
	}
}

// A linker table larger than maxIntervals must stop at the cap and say so, not
// allocate one interval per byte of a hostile payload.
func TestSkeletonCap(t *testing.T) {
	path := skeletonMachO(t)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	const funcOff = 32 + 152 // LC_FUNCTION_STARTS follows LC_SEGMENT_64
	payloadOff := len(b)
	chain := bytes.Repeat([]byte{0x01}, maxIntervals+1)
	b = append(b, chain...)
	binary.LittleEndian.PutUint32(b[funcOff+8:], uint32(payloadOff))
	binary.LittleEndian.PutUint32(b[funcOff+12:], uint32(len(chain)))
	binary.LittleEndian.PutUint64(b[32+72+40:], maxIntervals+0x100) // __text covers the starts
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
	s := machoSkeleton(path, false)
	if !bytes.Contains([]byte(s.Note), []byte("func-starts-capped")) {
		t.Fatalf("note = %q, want func-starts-capped", s.Note)
	}
	if s.Intervals > maxIntervals {
		t.Fatalf("intervals = %d, over the %d cap", s.Intervals, maxIntervals)
	}
}

// text_bytes must describe bytes the file holds: a section header may claim
// more than exists on disk.
func TestSkeletonTextBytes(t *testing.T) {
	path := skeletonMachO(t)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	binary.LittleEndian.PutUint64(b[32+72+40:], 1<<30) // __text claims 1 GiB
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	s := machoSkeleton(path, false)
	if s.TextBytes == 0 {
		t.Fatal("text_bytes = 0, want the bytes actually present")
	}
	if s.TextBytes > uint64(st.Size()) {
		t.Fatalf("text_bytes = %d, over file size %d", s.TextBytes, st.Size())
	}
	if s.TextBytes != 0x100 {
		t.Fatalf("text_bytes = %d, want 0x100 (file tail)", s.TextBytes)
	}
}
