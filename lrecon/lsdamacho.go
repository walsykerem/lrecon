package main

// Mach-O C++ exception tables. Darwin's linker never emits `.eh_frame` for a
// final image: unwind information lives in `__TEXT,__unwind_info` (compact
// unwind) and the per-function LSDA blobs are concatenated, back to back, in
// `__TEXT,__gcc_except_tab`. lsda.go walks the ELF/Mach-O pair FDE -> LSDA, so
// a macOS C++ binary with no FDE has no way to name an LSDA and refuses with
// `lsda-absent`. This reader supplies the address from the compact-unwind side
// instead:
//
//	__unwind_info header -> top-level index -> lsda_index array
//	lsda_index entry     -> functionOffset, lsdaOffset (from the image base)
//	LSDA record          -> the same grammar cxa_personality.cpp walks
//
// libcxxabi is the grammar (llvm-project libcxxabi/src/cxa_personality.cpp
// header :719-741, call site :749-752, action :781, ttype :787, type table
// :422-453); the reader reuses lsda.go's parseLSDA, actions, typeName and the
// encoded-pointer helpers verbatim. The compact-unwind side is the SDK header
// mach-o/compact_unwind_encoding.h (:476-491 for the index and lsda arrays) and
// apple-oss-distributions/libunwind src/UnwindCursor.hpp:1636-1641, which bounds
// one index entry's lsda array by the *next* entry's offset: ld64 writes a
// final sentinel entry whose offset is the end of the previous range, so the
// sentinel's own range is empty. lsdaOffset is relative to the image base
// (`lsda = lsdaIndex.lsdaOffset(mid) + sects.dso_base`, UnwindCursor.hpp:1788),
// not to the section, and _TEXT's vmaddr is that base.
//
// A record is self-delimiting here: the type-table offset in its header is the
// distance from the cursor after that ULEB to the byte just past the type
// table, so classInfo is the record end (cxa_personality.cpp:733-735). Records
// with no type table (`ttypeEncoding == DW_EH_PE_omit`) end where the next
// record begins, which the lsda array already told us.
//
// Nothing here executes the target. A malformed table ends in one of the four
// closed reasons below, never in a partial summary: half a type table is a
// guess about which handlers exist, and a wrong handler count is worse than a
// refusal. Absence is silent: a plain C Mach-O has no `__gcc_except_tab`, and a
// post reader that reported that as a skip would paint every C binary as a
// refusal. `lsdamacho-absent` is only for an image that has the section but no
// LSDA list (no __unwind_info entries and no GCC_except_table symbols), and for
// an image whose __eh_frame exists, where lsda.go already owns the answer.

import (
	"debug/macho"
	"fmt"
	"os"
	"slices"
	"strings"
)

const (
	lsdamachoAbsent         = "lsdamacho-absent"
	lsdamachoHeaderBad      = "lsdamacho-header-unreadable"
	lsdamachoOffsetOutside  = "lsdamacho-offset-outside-section"
	lsdamachoTypeUnresolved = "lsdamacho-type-unresolved"
)

func init() {
	reasonRegistry["lsdamacho"] = reasonSet(lsdamachoAbsent, lsdamachoHeaderBad,
		lsdamachoOffsetOutside, lsdamachoTypeUnresolved)
	register(reader{
		format: "lsdamacho",
		reasons: []string{lsdamachoAbsent, lsdamachoHeaderBad,
			lsdamachoOffsetOutside, lsdamachoTypeUnresolved},
		match:   lsdaMachOMatch,
		post:    true,
		inspect: inspectLSDAMacho,
	})
}

// lsdaMachOMatch is the cheap prefilter: only a Mach-O image can carry a
// __gcc_except_tab section, and the fat form is parsed slice by slice.
func lsdaMachOMatch(head []byte, size int64) bool {
	return isMachO(head) || fatMachOOK(head, size)
}

// lsdaMachOImg pairs the table view lsda.go already builds with the Mach-O file
// it came from: the reader needs __unwind_info and the segment base, which
// lsdaImage does not keep.
type lsdaMachOImg struct {
	im *lsdaImage
	mf *macho.File
	// Read while the file is open: debug/macho closes the underlying reader
	// with the File, so a section opened later yields nothing.
	info  []byte
	hasEH bool
}

func newLSDAMachOImg(im *lsdaImage, mf *macho.File) lsdaMachOImg {
	out := lsdaMachOImg{im: im, mf: mf}
	if s := mf.Section("__unwind_info"); s != nil {
		out.info = lsdaReadSection(s.Open())
	}
	out.hasEH = mf.Section("__eh_frame") != nil
	return out
}

func inspectLSDAMacho(path string, d *Digest) {
	f, err := os.Open(path)
	if err != nil {
		d.skip(lsdamachoHeaderBad, err.Error())
		return
	}
	defer f.Close()
	imgs, err := lsdaMachOImages(path, f)
	if err != nil {
		// The Mach-O header did not parse: a cut or corrupt image, which is not
		// the same answer as "this slice carries no exception table".
		d.skip(lsdamachoHeaderBad, err.Error())
		return
	}
	sum := &lsdaSummary{seen: map[string]bool{}}
	any := false
	for _, mi := range imgs {
		if len(mi.im.gcc) == 0 {
			continue // no exception table in this slice: an ordinary C image
		}
		// __eh_frame means the linker was asked for DWARF unwind tables; lsda.go
		// walks that pair, and reading the same blobs here would double the note.
		if mi.hasEH {
			continue
		}
		any = true
		starts, reason, detail := mi.starts()
		if reason != "" {
			d.skip(reason, detail)
			return
		}
		if len(starts) == 0 {
			d.skip(lsdamachoAbsent, "no LSDA addresses for __gcc_except_tab")
			return
		}
		if reason, detail := mi.walk(starts, sum); reason != "" {
			d.skip(reason, detail)
			return
		}
		d.parsed()
	}
	if !any || sum.lsdas == 0 {
		if any {
			d.skip(lsdamachoAbsent, "no LSDA records")
		}
		return
	}
	names := strings.Join(sum.names, ", ")
	if sum.more > 0 {
		names += fmt.Sprintf(", +%d more", sum.more)
	}
	if names == "" {
		names = "none"
	}
	deepNote(d, fmt.Sprintf("cxx-eh-macho %d LSDAs, %d catch types: %s",
		sum.lsdas, sum.types, names))
	// The capability is a claim about parsed handlers, so it is only set when a
	// catch clause actually resolved to a name.
	if sum.types > 0 && !containsStr(d.Capabilities, "cxx-eh") {
		d.Capabilities = append(d.Capabilities, "cxx-eh")
	}
}

// lsdaMachOImages is lsda.go's slice walk with the *macho.File kept. Fat
// archives give one image per arch; a malformed header is the only error.
func lsdaMachOImages(path string, f *os.File) ([]lsdaMachOImg, error) {
	var head [512]byte
	n, err := f.ReadAt(head[:], 0)
	if n < 4 {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if fatMachOOK(head[:n], st.Size()) {
		fat, err := macho.OpenFat(path)
		if err != nil {
			return nil, err
		}
		defer fat.Close()
		out := make([]lsdaMachOImg, 0, len(fat.Arches))
		for _, a := range fat.Arches {
			out = append(out, newLSDAMachOImg(lsdaMachO(f, a.File), a.File))
		}
		return out, nil
	}
	mf, err := macho.Open(path)
	if err != nil {
		return nil, err
	}
	defer mf.Close()
	return []lsdaMachOImg{newLSDAMachOImg(lsdaMachO(f, mf), mf)}, nil
}

// starts lists the LSDA addresses __gcc_except_tab holds. __unwind_info is the
// final-image source; the symbol table is the fallback for a toolchain that
// emitted a table without compact unwind. Both are only allowed to name bytes
// inside the section.
func (mi lsdaMachOImg) starts() ([]uint64, string, string) {
	if mi.info != nil {
		starts, reason, detail := mi.unwindStarts(mi.info)
		if reason != "" || len(starts) > 0 {
			return starts, reason, detail
		}
	}
	return mi.symbolStarts()
}

// unwindStarts reads the top-level index and the lsda_index arrays. Every
// offset it follows is a section offset; the LSDA offsets inside the arrays are
// image-base offsets, the one place the two bases differ.
func (mi lsdaMachOImg) unwindStarts(b []byte) ([]uint64, string, string) {
	if len(b) < 28 {
		return nil, lsdamachoHeaderBad, fmt.Sprintf("__unwind_info is %d bytes", len(b))
	}
	o := mi.mf.ByteOrder
	if v := o.Uint32(b[:4]); v != 1 {
		return nil, lsdamachoHeaderBad, fmt.Sprintf("__unwind_info version %d", v)
	}
	idxOff := uint64(o.Uint32(b[20:]))
	idxCount := uint64(o.Uint32(b[24:]))
	if idxCount == 0 {
		return nil, "", ""
	}
	// 12 bytes per index entry. The count is attacker-controlled; refuse before
	// multiplying it into a slice bound.
	if idxCount > 1<<20 || idxOff+12*idxCount > uint64(len(b)) {
		return nil, lsdamachoHeaderBad, fmt.Sprintf("index at %#x count %d past %d bytes", idxOff, idxCount, len(b))
	}
	text := mi.mf.Segment("__TEXT")
	if text == nil {
		return nil, lsdamachoHeaderBad, "no __TEXT segment for the image base"
	}
	gccEnd := mi.im.gccAddr + uint64(len(mi.im.gcc))
	var out []uint64
	for i := range idxCount {
		off := uint64(o.Uint32(b[idxOff+12*i+8:]))
		end := off // the sentinel entry bounds the previous range at its own offset
		if i+1 < idxCount {
			end = uint64(o.Uint32(b[idxOff+12*(i+1)+8:]))
		}
		if off > end || end > uint64(len(b)) || (end-off)%8 != 0 {
			return nil, lsdamachoHeaderBad, fmt.Sprintf("lsda array [%#x,%#x) outside %d bytes", off, end, len(b))
		}
		for a := off; a < end; a += 8 {
			lo := uint64(o.Uint32(b[a+4:]))
			va := text.Addr + lo
			if va < mi.im.gccAddr || va >= gccEnd {
				return nil, lsdamachoOffsetOutside, fmt.Sprintf("LSDA %#x outside __gcc_except_tab [%#x,%#x)", va, mi.im.gccAddr, gccEnd)
			}
			out = append(out, va)
		}
	}
	slices.Sort(out)
	return dedupeStarts(out), "", ""
}

// symbolStarts covers the toolchain that emitted __gcc_except_tab without
// compact unwind. ld64 names each blob GCC_except_tableN; strip removes those
// local symbols, so this is only ever a fallback.
func (mi lsdaMachOImg) symbolStarts() ([]uint64, string, string) {
	if mi.mf.Symtab == nil {
		return nil, "", ""
	}
	gccEnd := mi.im.gccAddr + uint64(len(mi.im.gcc))
	var out []uint64
	for _, s := range mi.mf.Symtab.Syms {
		if !strings.HasPrefix(strings.TrimLeft(s.Name, "_"), "GCC_except_table") {
			continue
		}
		if s.Value >= mi.im.gccAddr && s.Value < gccEnd {
			out = append(out, s.Value)
		}
	}
	slices.Sort(out)
	return dedupeStarts(out), "", ""
}

func dedupeStarts(in []uint64) []uint64 {
	out := in[:0]
	for _, v := range in {
		if len(out) == 0 || out[len(out)-1] != v {
			out = append(out, v)
		}
	}
	return out
}

// walk reads every record in [start_i, start_i+1). The gap is the record for a
// table with no type table and alignment padding otherwise; both parse the same
// way, and the type-table offset trims the slice to the exact record.
func (mi lsdaMachOImg) walk(starts []uint64, sum *lsdaSummary) (string, string) {
	gccEnd := mi.im.gccAddr + uint64(len(mi.im.gcc))
	for i, st := range starts {
		if st < mi.im.gccAddr || st >= gccEnd {
			return lsdamachoOffsetOutside, fmt.Sprintf("LSDA %#x outside __gcc_except_tab", st)
		}
		end := gccEnd
		if i+1 < len(starts) {
			end = starts[i+1]
		}
		if end <= st || end > gccEnd {
			return lsdamachoOffsetOutside, fmt.Sprintf("LSDA %#x ends at %#x, section ends at %#x", st, end, gccEnd)
		}
		b := mi.im.gcc[st-mi.im.gccAddr : end-mi.im.gccAddr]
		n, reason, detail := mi.recordLen(b)
		if reason != "" {
			return reason, detail
		}
		sum.lsdas++
		if reason, detail := mi.im.parseLSDA(b[:n], st, sum); reason != "" {
			if reason == lsdaTypeTableUnresolve {
				return lsdamachoTypeUnresolved, detail
			}
			return lsdamachoHeaderBad, detail
		}
	}
	return "", ""
}

// recordLen returns the record length the header states. With a type table the
// length is classInfo - start; without one the caller's gap is the only bound.
func (mi lsdaMachOImg) recordLen(b []byte) (int, string, string) {
	if len(b) == 0 {
		return 0, lsdamachoHeaderBad, "empty LSDA record"
	}
	p := 1
	if lpEnc := b[0]; lpEnc != dwEHPEOmit {
		np, ok := mi.im.skipEncoded(b, p, lpEnc)
		if !ok {
			return 0, lsdamachoHeaderBad, fmt.Sprintf("LPStart encoding %#x", lpEnc)
		}
		p = np
	}
	if p >= len(b) {
		return 0, lsdamachoHeaderBad, "LSDA header cut after LPStart"
	}
	enc := b[p]
	p++
	if enc == dwEHPEOmit {
		return len(b), "", ""
	}
	off, np, ok := lsdaULEB(b, p)
	if !ok {
		return 0, lsdamachoHeaderBad, "type-table offset unreadable"
	}
	p = np
	if off > uint64(len(b)-p) {
		return 0, lsdamachoOffsetOutside, fmt.Sprintf("type table at +%d past the %d-byte record", off, len(b))
	}
	return p + int(off), "", ""
}
