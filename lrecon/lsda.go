package main

// Itanium C++ exception tables. A C++ binary carries two side tables that the
// language runtime needs and a disassembly does not show: `.eh_frame` says
// which address ranges can unwind and points at an LSDA, and the LSDA (emitted
// into `.gcc_except_table`) says which call sites have landing pads, which of
// those are cleanups, and which `_ZTI` type_info objects a catch clause names.
//
// This reader walks that pair and reports only what the bytes prove:
//
//	FDE (in .eh_frame) -> augmentation 'L' encoding -> LSDA address
//	LSDA header       -> call-site table + action table + type table
//	positive ttype    -> classInfo - index*size -> _ZTI symbol -> class name
//
// Grammar is llvm/llvm-project libcxxabi/src/cxa_personality.cpp (encodings
// :218-233, LEB readers :243/:266, readEncodedPointer :293, header parse
// :719-741, call site :749-752, action entry :781, ttype index :787, filter
// :792-796, type table index :422-453). The .eh_frame side is the CIE `zPLR`
// augmentation as parsed by gimli-rs/gimli src/read/cfi.rs:1533-1582 and the
// FDE record at :1653; the unwind table itself is not needed and not read.
//
// Nothing here executes the target. A malformed table ends in one of the four
// closed reasons below, never in a partial summary: half a type table is a
// guess about which handlers exist, and a wrong handler count is worse than a
// refusal.

import (
	"bytes"
	"debug/elf"
	"debug/macho"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"strings"
)

const (
	lsdaAbsent             = "lsda-absent"
	lsdaTruncated          = "lsda-truncated"
	lsdaBadEncoding        = "lsda-bad-encoding"
	lsdaTypeTableUnresolve = "lsda-type-table-unresolved"

	// lsdaMaxSection bounds one side table. Real binaries keep both under a
	// few hundred KiB; a section past this is a hostile or broken layout.
	lsdaMaxSection = 16 << 20
	// lsdaMaxNames is the printed cap. The count stays exact, the list does not.
	lsdaMaxNames = 8
	// lsdaMaxActions bounds one action chain. The chain is a singly linked
	// list inside the table, so a corrupt offset can loop forever.
	lsdaMaxActions = 64
)

// errLSDAOutOfScope means the file is not an object format this pass parses.
// It must stay silent: post readers see every file, and a skip line here would
// claim a refusal where the pass simply has nothing to say.
var errLSDAOutOfScope = fmt.Errorf("lsda: out of scope")

// DWARF pointer encodings, low nibble = value format, high bits = application.
// libcxxabi accepts only absptr/pcrel/(pcrel|indirect) for the type table
// (:409-412), but GCC emits udata4/sdata4 forms too, so the size table below
// covers every fixed-width value the standard defines.
const (
	dwEHPEOmit     = 0xff
	dwEHPEAbsptr   = 0x00
	dwEHPEUleb128  = 0x01
	dwEHPEUdata2   = 0x02
	dwEHPEUdata4   = 0x03
	dwEHPEUdata8   = 0x04
	dwEHPESleb128  = 0x09
	dwEHPESdata2   = 0x0a
	dwEHPESdata4   = 0x0b
	dwEHPESdata8   = 0x0c
	dwEHPEPcrel    = 0x10
	dwEHPEDatarel  = 0x30
	dwEHPEIndirect = 0x80
)

func init() {
	reasonRegistry["lsda"] = reasonSet(lsdaAbsent, lsdaTruncated, lsdaBadEncoding, lsdaTypeTableUnresolve)
	register(reader{
		format:  "lsda",
		reasons: []string{lsdaAbsent, lsdaTruncated, lsdaBadEncoding, lsdaTypeTableUnresolve},
		match:   lsdaMatch,
		post:    true,
		inspect: inspectLSDA,
	})
}

// lsdaMatch keeps the reader off text and other non-image kinds: post readers
// run for every file, and an ELF or Mach-O magic is the only cheap proof that
// an exception table could exist at all. The fat check reuses the detector's
// rule so a Java class cannot be mistaken for a universal binary here.
func lsdaMatch(head []byte, size int64) bool {
	if len(head) >= 4 && string(head[:4]) == "\x7fELF" {
		return true
	}
	return isMachO(head) || fatMachOOK(head, size)
}

// lsdaMap is one file-backed, loadable address range. Everything the reader
// touches — the LSDA, its type table, a type_info object's name pointer — is
// reached through a virtual address, so the mapping is the only address
// translation this reader allows.
type lsdaMap struct {
	addr uint64
	size uint64
	off  uint64
}

// lsdaImage is one ELF image or one Mach-O slice. Fat files give several.
type lsdaImage struct {
	f       *os.File
	order   binary.ByteOrder
	ptr     int
	maps    []lsdaMap
	eh      []byte
	ehAddr  uint64
	gcc     []byte
	gccAddr uint64
	syms    map[uint64]string // _ZTI address -> mangled name, when symbols survive
	// fixups is the Mach-O chained-fixup import list. A __got slot in the file
	// holds an encoded bind token, not the final address, so the slot's import
	// ordinal is the only way back to the _ZTI name in a stripped image.
	fixups []string
}

func inspectLSDA(path string, d *Digest) {
	f, err := os.Open(path)
	if err != nil {
		// An unreadable file is not an absent table: the pass did not look.
		d.skip(lsdaTruncated, err.Error())
		return
	}
	defer f.Close()
	imgs, err := lsdaImages(path, f)
	if err == errLSDAOutOfScope {
		// Post readers run over every file another reader claimed. A shape this
		// pass does not parse (fat slice guard, non-object blob) is out of
		// scope, not a refusal, so it must not add a skip line.
		return
	}
	if err != nil {
		// A parser failure means the image was read and did not add up: a cut or
		// corrupt file. Absence is a different answer and stays below.
		d.skip(lsdaTruncated, err.Error())
		return
	}
	sum := &lsdaSummary{seen: map[string]bool{}}
	any := false
	for _, im := range imgs {
		// A slice with neither table is an ordinary C slice, not a refusal:
		// the other slice may still carry the C++ handlers.
		if len(im.gcc) == 0 || len(im.eh) == 0 {
			continue
		}
		any = true
		if reason, detail := im.walk(sum); reason != "" {
			d.skip(reason, detail)
			return
		}
		d.parsed()
	}
	if !any {
		d.skip(lsdaAbsent, "no .gcc_except_table/.eh_frame pair in any image")
		return
	}
	if sum.lsdas == 0 {
		d.skip(lsdaAbsent, fmt.Sprintf("%d FDEs, none carry an LSDA pointer", sum.fdes))
		return
	}
	names := strings.Join(sum.names, ", ")
	if sum.more > 0 {
		names += fmt.Sprintf(", +%d more", sum.more)
	}
	if names == "" {
		names = "none"
	}
	deepNote(d, fmt.Sprintf("cxx-eh %d call sites, %d landing pads, %d catch types: %s",
		sum.sites, sum.pads, sum.types, names))
	// Cleanup-only ranges are the destructor sites: action entry 0 means no
	// catch clause, only a call to run cleanups. Naming them separately keeps
	// "landing pads" from being read as "handlers".
	if sum.cleanups > 0 {
		deepNote(d, fmt.Sprintf("cxx-eh %d cleanup-only ranges", sum.cleanups))
	}
}

// lsdaSummary aggregates every LSDA in the image. A binary with several FDEs
// has several tables, and the user wants the program's handler set, not one
// function's.
type lsdaSummary struct {
	fdes, lsdas int
	sites, pads int
	cleanups    int
	types       int
	names       []string
	more        int
	seen        map[string]bool
}

func (s *lsdaSummary) add(name string) {
	if name == "" || s.seen[name] {
		return
	}
	s.seen[name] = true
	s.types++
	if len(s.names) < lsdaMaxNames {
		s.names = append(s.names, name)
		return
	}
	s.more++
}

func lsdaImages(path string, f *os.File) ([]*lsdaImage, error) {
	head := make([]byte, 4)
	if _, err := f.ReadAt(head, 0); err != nil {
		return nil, err
	}
	if string(head) == "\x7fELF" {
		im, err := lsdaELF(path, f)
		if err != nil {
			return nil, err
		}
		return []*lsdaImage{im}, nil
	}
	if st, err := f.Stat(); err == nil && fatMachOOK(head, st.Size()) {
		fat, err := macho.OpenFat(path)
		if err != nil {
			return nil, err
		}
		defer fat.Close()
		var out []*lsdaImage
		for _, a := range fat.Arches {
			out = append(out, lsdaMachO(f, a.File))
		}
		if !lsdaAnyEHFrame(out) {
			return nil, errLSDAOutOfScope
		}
		return out, nil
	}
	if !isMachO(head) {
		return nil, errLSDAOutOfScope
	}
	mf, err := macho.Open(path)
	if err != nil {
		return nil, err
	}
	defer mf.Close()
	im := lsdaMachO(f, mf)
	if !lsdaAnyEHFrame([]*lsdaImage{im}) {
		return nil, errLSDAOutOfScope
	}
	return []*lsdaImage{im}, nil
}

// lsdaAnyEHFrame reports whether this pass can walk the image at all. On macOS
// the linker normally keeps LSDA in __gcc_except_tab behind __unwind_info and
// emits no __eh_frame; lsdamacho owns that shape, so a Mach-O without
// __eh_frame is out of scope here, not a refusal.
func lsdaAnyEHFrame(imgs []*lsdaImage) bool {
	for _, im := range imgs {
		if len(im.eh) > 0 {
			return true
		}
	}
	return false
}

func lsdaELF(path string, f *os.File) (*lsdaImage, error) {
	ef, err := elf.Open(path)
	if err != nil {
		return nil, err
	}
	defer ef.Close()
	im := &lsdaImage{f: f, order: ef.ByteOrder, ptr: 4, syms: map[uint64]string{}}
	if ef.Class == elf.ELFCLASS64 {
		im.ptr = 8
	}
	// Program headers, not sections, are the load view: an LSDA pointer is a
	// virtual address, and only PT_LOAD says which file bytes back it.
	for _, p := range ef.Progs {
		if p.Type == elf.PT_LOAD && p.Filesz > 0 {
			im.maps = append(im.maps, lsdaMap{addr: p.Vaddr, size: p.Filesz, off: p.Off})
		}
	}
	if s := ef.Section(".eh_frame"); s != nil {
		im.eh, im.ehAddr = lsdaReadSection(s.Open()), s.Addr
	}
	if s := ef.Section(".gcc_except_table"); s != nil {
		im.gcc, im.gccAddr = lsdaReadSection(s.Open()), s.Addr
	}
	// .dynsym survives strip; .symtab is the full table. Either one gives the
	// _ZTI names without dereferencing a type_info object.
	if syms, err := ef.Symbols(); err == nil {
		lsdaAddSyms(im.syms, func(yield func(uint64, string)) {
			for _, s := range syms {
				yield(s.Value, s.Name)
			}
		})
	}
	if syms, err := ef.DynamicSymbols(); err == nil {
		lsdaAddSyms(im.syms, func(yield func(uint64, string)) {
			for _, s := range syms {
				yield(s.Value, s.Name)
			}
		})
	}
	return im, nil
}

func lsdaMachO(f *os.File, mf *macho.File) *lsdaImage {
	im := &lsdaImage{f: f, order: mf.ByteOrder, ptr: 4, syms: map[uint64]string{}}
	if mf.Magic == macho.Magic64 {
		im.ptr = 8
	}
	for _, l := range mf.Loads {
		if seg, ok := l.(*macho.Segment); ok && seg.Filesz > 0 {
			im.maps = append(im.maps, lsdaMap{addr: seg.Addr, size: seg.Filesz, off: seg.Offset})
		}
	}
	if s := mf.Section("__eh_frame"); s != nil {
		im.eh, im.ehAddr = lsdaReadSection(s.Open()), s.Addr
	}
	// Mach-O section names live in a 16-byte field, so the linker-visible name
	// is the truncated __gcc_except_tab; the long spelling appears in objects
	// produced by tools that emit the full name into a longer field.
	if s := mf.Section("__gcc_except_table"); s != nil {
		im.gcc, im.gccAddr = lsdaReadSection(s.Open()), s.Addr
	} else if s := mf.Section("__gcc_except_tab"); s != nil {
		im.gcc, im.gccAddr = lsdaReadSection(s.Open()), s.Addr
	}
	im.fixups = lsdaChainedFixups(f, mf)
	if mf.Symtab != nil {
		lsdaAddSyms(im.syms, func(yield func(uint64, string)) {
			for _, s := range mf.Symtab.Syms {
				// Mach-O prepends one underscore to every C symbol, so the
				// table spelling is __ZTI... while the ELF one is _ZTI....
				yield(s.Value, s.Name)
			}
		})
	}
	return im
}

func lsdaAddSyms(dst map[uint64]string, each func(func(uint64, string))) {
	each(func(addr uint64, name string) {
		if addr == 0 {
			return
		}
		name = strings.TrimPrefix(name, "_")
		// Only type_info objects are indexed: the type table points at them,
		// and the vtable/symbol pair for every other name would be noise.
		if !strings.HasPrefix(name, "_ZTI") {
			return
		}
		if _, dup := dst[addr]; !dup {
			dst[addr] = name
		}
	})
}

func lsdaReadSection(r io.Reader) []byte {
	b, _ := io.ReadAll(io.LimitReader(r, lsdaMaxSection))
	return b
}

// lsdaCIE is the part of a Common Information Entry this reader needs: where
// the FDE's encodings came from and whether an LSDA pointer follows.
type lsdaCIE struct {
	z       bool
	hasLSDA bool
	lsdaEnc byte
	fdeEnc  byte
}

// walk parses every record in .eh_frame, follows each FDE that announces an
// LSDA, and folds the table into sum. An error is a reason from the closed set
// plus the byte fact that produced it; no summary survives a refusal.
func (im *lsdaImage) walk(sum *lsdaSummary) (string, string) {
	cies := map[int]lsdaCIE{}
	for off := 0; off+4 <= len(im.eh); {
		recStart := off
		length := uint64(im.order.Uint32(im.eh[off:]))
		off += 4
		idSize := 4
		if length == 0xffffffff {
			if off+8 > len(im.eh) {
				return lsdaTruncated, fmt.Sprintf(".eh_frame cut in 64-bit length at %#x", off)
			}
			length = im.order.Uint64(im.eh[off:])
			off += 8
			idSize = 8
		}
		if length == 0 {
			break // zero terminator; GCC pads the section with it
		}
		if length > uint64(len(im.eh)-off) {
			return lsdaTruncated, fmt.Sprintf(".eh_frame record at %#x claims %d bytes, %d left", recStart, length, len(im.eh)-off)
		}
		rec := im.eh[off : off+int(length)]
		if len(rec) < idSize {
			return lsdaTruncated, fmt.Sprintf(".eh_frame record at %#x shorter than its id", recStart)
		}
		id := uint64(im.order.Uint32(rec))
		if idSize == 8 {
			id = im.order.Uint64(rec)
		}
		idPos := recStart + 4
		if idSize == 8 {
			idPos = recStart + 12
		}
		if id == 0 {
			cie, why := im.parseCIE(rec[idSize:], im.ehAddr+uint64(idPos+idSize))
			if why != "" {
				return lsdaBadEncoding, why
			}
			cies[recStart] = cie
			off += int(length)
			continue
		}
		// The CIE pointer is a backward distance from the pointer field to the
		// CIE record, not an absolute offset.
		cieStart := idPos - int(id)
		cie, ok := cies[cieStart]
		if !ok {
			return lsdaBadEncoding, fmt.Sprintf("FDE at %#x points at missing CIE %#x", recStart, cieStart)
		}
		sum.fdes++
		p := idSize
		p, ok = im.skipEncoded(rec, p, cie.fdeEnc)
		if !ok {
			return lsdaBadEncoding, fmt.Sprintf("FDE at %#x has unreadable initial location", recStart)
		}
		// address_range uses the same value format; the application bits (pcrel
		// and friends) are meaningless for a length and do not apply.
		p, ok = im.skipEncoded(rec, p, cie.fdeEnc&0x0f)
		if !ok {
			return lsdaTruncated, fmt.Sprintf("FDE at %#x has unreadable address range", recStart)
		}
		if !cie.z {
			off += int(length)
			continue
		}
		augLen, np, ok := lsdaULEB(rec, p)
		if !ok {
			return lsdaTruncated, fmt.Sprintf("FDE at %#x has no augmentation length", recStart)
		}
		p = np
		augEnd := p + int(augLen)
		if augEnd > len(rec) {
			return lsdaTruncated, fmt.Sprintf("FDE at %#x augmentation runs past the record", recStart)
		}
		if !cie.hasLSDA || augLen == 0 {
			off += int(length)
			continue
		}
		lsdaVA, _, ok := im.readEncoded(rec, p, cie.lsdaEnc, im.ehAddr+uint64(off+p), im.gccAddr)
		if !ok {
			return lsdaBadEncoding, fmt.Sprintf("FDE at %#x LSDA encoding %#x", recStart, cie.lsdaEnc)
		}
		off += int(length)
		if lsdaVA == 0 {
			continue
		}
		table, baseVA, ok := im.tail(lsdaVA)
		if !ok {
			return lsdaTruncated, fmt.Sprintf("LSDA at %#x is not inside a loadable range", lsdaVA)
		}
		sum.lsdas++
		if reason, detail := im.parseLSDA(table, baseVA, sum); reason != "" {
			return reason, detail
		}
	}
	return "", ""
}

// parseCIE reads the augmentation in order. `z` means the rest of the CIE is a
// length-counted block; L/P/R consume it in the order the string spells them,
// and any character this reader does not know is refused rather than skipped,
// because a skipped character shifts every later encoding.
func (im *lsdaImage) parseCIE(b []byte, _ uint64) (lsdaCIE, string) {
	cie := lsdaCIE{fdeEnc: dwEHPEAbsptr}
	if len(b) < 1 {
		return cie, "CIE without a version byte"
	}
	version := b[0]
	p := 1
	end := -1
	for i := p; i < len(b); i++ {
		if b[i] == 0 {
			end = i
			break
		}
	}
	if end < 0 {
		return cie, "CIE augmentation string is unterminated"
	}
	aug := string(b[p:end])
	p = end + 1
	if _, np, ok := lsdaULEB(b, p); !ok {
		return cie, "CIE code alignment truncated"
	} else {
		p = np
	}
	if _, np, ok := lsdaSLEB(b, p); !ok {
		return cie, "CIE data alignment truncated"
	} else {
		p = np
	}
	if version == 1 {
		p++
	} else {
		if _, np, ok := lsdaULEB(b, p); !ok {
			return cie, "CIE return-address register truncated"
		} else {
			p = np
		}
	}
	if p > len(b) {
		return cie, "CIE header truncated"
	}
	if !strings.HasPrefix(aug, "z") {
		return cie, ""
	}
	cie.z = true
	augLen, np, ok := lsdaULEB(b, p)
	if !ok {
		return cie, "CIE augmentation length truncated"
	}
	p = np
	augEnd := p + int(augLen)
	if augEnd > len(b) {
		return cie, "CIE augmentation data runs past the record"
	}
	for _, c := range aug[1:] {
		switch c {
		case 'L':
			if p >= augEnd {
				return cie, "CIE 'L' augmentation has no encoding"
			}
			cie.hasLSDA = true
			cie.lsdaEnc = b[p]
			p++
		case 'R':
			if p >= augEnd {
				return cie, "CIE 'R' augmentation has no encoding"
			}
			cie.fdeEnc = b[p]
			p++
		case 'P':
			if p >= augEnd {
				return cie, "CIE 'P' augmentation has no encoding"
			}
			enc := b[p]
			p++
			// The personality value is not needed; only its length is, and
			// decode length does not depend on the relative base.
			np, ok := im.skipEncoded(b, p, enc)
			if !ok || np > augEnd {
				return cie, "CIE personality pointer is unreadable"
			}
			p = np
		case 'S':
			// Signal frame: a flag, no bytes.
		default:
			return cie, fmt.Sprintf("unknown CIE augmentation %q", c)
		}
	}
	if p != augEnd {
		return cie, fmt.Sprintf("CIE augmentation length %d does not match its data %d", augLen, p-(augEnd-int(augLen)))
	}
	return cie, ""
}

// parseLSDA reads the table at b (whose first byte has virtual address baseVA).
// The layout is the one libcxxabi walks: LPStart, ttype base, call sites, then
// the action and type tables that the offsets point into.
func (im *lsdaImage) parseLSDA(b []byte, baseVA uint64, sum *lsdaSummary) (string, string) {
	if len(b) < 1 {
		return lsdaTruncated, "LSDA is empty"
	}
	p := 0
	lpEnc := b[p]
	p++
	if lpEnc != dwEHPEOmit {
		// LPStart is not needed for a call-site count, but it must be readable:
		// an unsupported encoding shifts everything after it.
		np, ok := im.skipEncoded(b, p, lpEnc)
		if !ok {
			return lsdaBadEncoding, fmt.Sprintf("LSDA LPStart encoding %#x", lpEnc)
		}
		p = np
	}
	if p >= len(b) {
		return lsdaTruncated, "LSDA header cut after LPStart"
	}
	ttypeEnc := b[p]
	p++
	var classInfoVA uint64
	if ttypeEnc != dwEHPEOmit {
		off, np, ok := lsdaULEB(b, p)
		if !ok {
			return lsdaTruncated, "LSDA type-table offset unreadable"
		}
		p = np
		if off > uint64(len(b)-p) {
			return lsdaTypeTableUnresolve, fmt.Sprintf("type table at +%d past the %d-byte LSDA", off, len(b))
		}
		// libcxxabi's classInfo = lsda + classInfoOffset, where lsda is the
		// cursor after reading the offset (:733-735).
		classInfoVA = baseVA + uint64(p) + off
	}
	if p >= len(b) {
		return lsdaTruncated, "LSDA header cut after the type-table offset"
	}
	csEnc := b[p]
	p++
	if csEnc == dwEHPEOmit {
		return lsdaBadEncoding, "call-site encoding is DW_EH_PE_omit"
	}
	csLen, np, ok := lsdaULEB(b, p)
	if !ok {
		return lsdaTruncated, "LSDA call-site table length unreadable"
	}
	p = np
	csEnd := p + int(csLen)
	if csEnd > len(b) {
		return lsdaTruncated, fmt.Sprintf("call-site table claims %d bytes, %d left", csLen, len(b)-p)
	}
	q := p
	for q < csEnd {
		nq, ok := im.skipEncoded(b, q, csEnc)
		if !ok {
			return lsdaBadEncoding, "call-site start encoding unreadable"
		}
		q = nq
		nq, ok = im.skipEncoded(b, q, csEnc)
		if !ok {
			return lsdaTruncated, "call-site length unreadable"
		}
		q = nq
		lp, nq, ok := im.readEncoded(b, q, csEnc, baseVA+uint64(q), im.gccAddr)
		if !ok {
			return lsdaBadEncoding, "landing-pad encoding unreadable"
		}
		q = nq
		action, nq, ok := lsdaULEB(b, q)
		if !ok || nq > csEnd {
			return lsdaTruncated, fmt.Sprintf("call-site action entry at %#x unreadable", q)
		}
		q = nq
		sum.sites++
		if lp == 0 {
			continue // no landing pad: a call site that cannot throw
		}
		sum.pads++
		if action == 0 {
			// libcxxabi treats action 0 as "found a cleanup" directly
			// (:757-762): no catch clause, only destructor work.
			sum.cleanups++
			continue
		}
		ap := csEnd + int(action) - 1
		if reason, detail := im.actions(b, ap, ttypeEnc, classInfoVA, sum); reason != "" {
			return reason, detail
		}
	}
	if q != csEnd {
		return lsdaTruncated, fmt.Sprintf("call-site table ended at %#x, header said %#x", q, csEnd)
	}
	return "", ""
}

// actions follows one 1-based action entry through its chain. Each record is
// <ttypeIndex SLEB><next offset SLEB>, and the next offset is relative to the
// byte after ttypeIndex (:890-897). A positive index is a catch type; a
// negative one is an exception-specification filter, not a class name.
func (im *lsdaImage) actions(b []byte, ap int, ttypeEnc byte, classInfoVA uint64, sum *lsdaSummary) (string, string) {
	seen := map[int]bool{}
	sawCatch, sawCleanup := false, false
	for range lsdaMaxActions {
		if ap < 0 || ap >= len(b) {
			return lsdaTruncated, fmt.Sprintf("action entry at %#x outside the LSDA", ap)
		}
		if seen[ap] {
			return lsdaBadEncoding, fmt.Sprintf("action chain loops at %#x", ap)
		}
		seen[ap] = true
		ti, np, ok := lsdaSLEB(b, ap)
		if !ok {
			return lsdaTruncated, fmt.Sprintf("action ttypeIndex at %#x unreadable", ap)
		}
		next, _, ok := lsdaSLEB(b, np)
		if !ok {
			return lsdaTruncated, fmt.Sprintf("action next offset at %#x unreadable", np)
		}
		if ti > 0 {
			name, reason, detail := im.typeName(uint64(ti), ttypeEnc, classInfoVA)
			if reason != "" {
				return reason, detail
			}
			sum.add(name)
			sawCatch = true
		} else if ti == 0 {
			sawCleanup = true
		}
		if next == 0 {
			// A call site whose actions only run destructors is a cleanup
			// range; one that also names a catch type is reported as a catch.
			if sawCleanup && !sawCatch {
				sum.cleanups++
			}
			return "", ""
		}
		ap = np + int(next)
	}
	return lsdaBadEncoding, fmt.Sprintf("action chain longer than %d entries", lsdaMaxActions)
}

// typeName resolves a positive ttypeIndex. The type table is indexed backwards
// from classInfo in units of the encoding's value size (libcxxabi :422-453),
// and each entry is either the type_info address itself or, with
// DW_EH_PE_indirect, the address of a slot holding it.
func (im *lsdaImage) typeName(idx uint64, enc byte, classInfoVA uint64) (string, string, string) {
	size, ok := lsdaEncSize(enc, im.ptr)
	if !ok {
		return "", lsdaBadEncoding, fmt.Sprintf("type table index uses variable encoding %#x", enc)
	}
	if classInfoVA == 0 {
		return "", lsdaTypeTableUnresolve, "type table base missing while a catch index was set"
	}
	if size == 0 || idx > classInfoVA/size {
		return "", lsdaTypeTableUnresolve, fmt.Sprintf("type index %d underflows the table base %#x", idx, classInfoVA)
	}
	entryVA := classInfoVA - idx*size
	eb, ok := im.bytesAt(entryVA, size)
	if !ok {
		return "", lsdaTypeTableUnresolve, fmt.Sprintf("type table entry %d at %#x is not mapped", idx, entryVA)
	}
	val, _, ok := im.readEncoded(eb, 0, enc, entryVA, im.gccAddr)
	if !ok || val == 0 {
		return "", lsdaTypeTableUnresolve, fmt.Sprintf("type table entry %d at %#x is empty", idx, entryVA)
	}
	if enc&dwEHPEIndirect != 0 {
		slotVA := val
		val, ok = im.pointerAt(slotVA)
		if !ok || val == 0 {
			return "", lsdaTypeTableUnresolve, fmt.Sprintf("indirect type table entry %d has no pointer", idx)
		}
		// Darwin writes a chained-fixup bind token here, not an address. The
		// token's import ordinal names the symbol even when the slot itself
		// cannot be dereferenced before the dynamic linker runs.
		if name, ok := im.fixupName(val); ok {
			return lsdaDemangle(name), "", ""
		}
	}
	if name, ok := im.syms[val]; ok {
		return lsdaDemangle(name), "", ""
	}
	// Stripped images keep no _ZTI name, but the Itanium type_info object
	// still starts with vptr then the mangled-name pointer. Reading it is the
	// same evidence the runtime itself uses, one dereference later.
	nameVA, ok := im.pointerAt(val + uint64(im.ptr))
	if ok {
		if s, ok := im.cstring(nameVA); ok && s != "" {
			return lsdaDemangle(s), "", ""
		}
	}
	return "", lsdaTypeTableUnresolve, fmt.Sprintf("typeinfo at %#x has no resolvable name", val)
}

// lsdaEncSize is the fixed byte width one type-table entry occupies. uleb128
// and sleb128 are legal DWARF but cannot be indexed backwards by a ttypeIndex,
// so libcxxabi never emits them here.
func lsdaEncSize(enc byte, ptr int) (uint64, bool) {
	switch enc & 0x0f {
	case dwEHPEAbsptr:
		return uint64(ptr), true
	case dwEHPEUdata2, dwEHPESdata2:
		return 2, true
	case dwEHPEUdata4, dwEHPESdata4:
		return 4, true
	case dwEHPEUdata8, dwEHPESdata8:
		return 8, true
	}
	return 0, false
}

// readEncoded decodes one pointer. fieldVA is the address of the encoded bytes
// (the pcrel base); dataVA is the section base for datarel. Indirection is left
// to the caller because the type table needs the slot, while an LSDA pointer
// needs the address the slot was never involved in.
func (im *lsdaImage) readEncoded(b []byte, off int, enc byte, fieldVA, dataVA uint64) (uint64, int, bool) {
	if enc == dwEHPEOmit {
		return 0, off, true
	}
	if off < 0 || off >= len(b) {
		return 0, off, false
	}
	var v uint64
	next := off
	switch enc & 0x0f {
	case dwEHPEAbsptr:
		if off+im.ptr > len(b) {
			return 0, off, false
		}
		switch im.ptr {
		case 8:
			v = im.order.Uint64(b[off:])
		case 4:
			v = uint64(im.order.Uint32(b[off:]))
		default:
			return 0, off, false
		}
		next = off + im.ptr
	case dwEHPEUleb128:
		var ok bool
		if v, next, ok = lsdaULEB(b, off); !ok {
			return 0, off, false
		}
	case dwEHPESleb128:
		s, n, ok := lsdaSLEB(b, off)
		if !ok {
			return 0, off, false
		}
		v, next = uint64(s), n
	case dwEHPEUdata2:
		if off+2 > len(b) {
			return 0, off, false
		}
		v, next = uint64(im.order.Uint16(b[off:])), off+2
	case dwEHPESdata2:
		if off+2 > len(b) {
			return 0, off, false
		}
		v, next = uint64(int64(int16(im.order.Uint16(b[off:])))), off+2
	case dwEHPEUdata4:
		if off+4 > len(b) {
			return 0, off, false
		}
		v, next = uint64(im.order.Uint32(b[off:])), off+4
	case dwEHPESdata4:
		if off+4 > len(b) {
			return 0, off, false
		}
		v, next = uint64(int64(int32(im.order.Uint32(b[off:])))), off+4
	case dwEHPEUdata8:
		if off+8 > len(b) {
			return 0, off, false
		}
		v, next = im.order.Uint64(b[off:]), off+8
	case dwEHPESdata8:
		if off+8 > len(b) {
			return 0, off, false
		}
		v, next = uint64(int64(im.order.Uint64(b[off:]))), off+8
	default:
		return 0, off, false
	}
	switch enc & 0x70 {
	case 0:
	case dwEHPEPcrel:
		if v != 0 {
			if fieldVA == 0 {
				return 0, off, false
			}
			v += fieldVA
		}
	case dwEHPEDatarel:
		if v != 0 {
			if dataVA == 0 {
				return 0, off, false
			}
			v += dataVA
		}
	default:
		// textrel/funcrel/aligned are legal DWARF but never emitted for these
		// tables; refusing keeps the cursor honest instead of guessing a base.
		return 0, off, false
	}
	return v, next, true
}

// skipEncoded advances over one encoded value without interpreting it.
func (im *lsdaImage) skipEncoded(b []byte, off int, enc byte) (int, bool) {
	if enc == dwEHPEOmit {
		return off, true
	}
	switch enc & 0x0f {
	case dwEHPEUleb128:
		_, n, ok := lsdaULEB(b, off)
		return n, ok
	case dwEHPESleb128:
		_, n, ok := lsdaSLEB(b, off)
		return n, ok
	}
	n, ok := lsdaEncSize(enc, im.ptr)
	if !ok || off < 0 || uint64(off)+n > uint64(len(b)) {
		return off, false
	}
	return off + int(n), true
}

func lsdaULEB(b []byte, off int) (uint64, int, bool) {
	var v uint64
	for i := range 10 {
		if off < 0 || off+i >= len(b) {
			return 0, off, false
		}
		c := b[off+i]
		if i == 9 && c > 1 {
			return 0, off, false
		}
		v |= uint64(c&0x7f) << (7 * uint(i))
		if c&0x80 == 0 {
			return v, off + i + 1, true
		}
	}
	return 0, off, false
}

func lsdaSLEB(b []byte, off int) (int64, int, bool) {
	var v int64
	var shift uint
	for i := range 10 {
		if off < 0 || off+i >= len(b) {
			return 0, off, false
		}
		c := b[off+i]
		if i == 9 && c&0x7f > 1 {
			return 0, off, false
		}
		v |= int64(c&0x7f) << shift
		shift += 7
		if c&0x80 == 0 {
			if shift < 64 && c&0x40 != 0 {
				v |= -1 << shift
			}
			return v, off + i + 1, true
		}
	}
	return 0, off, false
}

// tail returns everything from va to the end of its loadable range, capped.
// The LSDA and its tables live in one section, so one bounded read covers the
// whole table without allocating the rest of the image.
func (im *lsdaImage) tail(va uint64) ([]byte, uint64, bool) {
	m, ok := im.region(va)
	if !ok {
		return nil, 0, false
	}
	n := min(m.size-(va-m.addr), lsdaMaxSection)
	b, ok := im.readAt(va, n)
	return b, va, ok
}

func (im *lsdaImage) region(va uint64) (lsdaMap, bool) {
	for _, m := range im.maps {
		if va >= m.addr && va < m.addr+m.size {
			return m, true
		}
	}
	return lsdaMap{}, false
}

func (im *lsdaImage) bytesAt(va uint64, n uint64) ([]byte, bool) {
	if _, ok := im.region(va); !ok {
		return nil, false
	}
	return im.readAt(va, n)
}

func (im *lsdaImage) readAt(va uint64, n uint64) ([]byte, bool) {
	m, ok := im.region(va)
	if !ok || n == 0 || va-m.addr > m.size || n > m.size-(va-m.addr) {
		return nil, false
	}
	b := make([]byte, n)
	got, err := im.f.ReadAt(b, int64(m.off+(va-m.addr)))
	if err != nil && err != io.EOF {
		return nil, false
	}
	if uint64(got) != n {
		return nil, false
	}
	return b, true
}

func (im *lsdaImage) pointerAt(va uint64) (uint64, bool) {
	b, ok := im.bytesAt(va, uint64(im.ptr))
	if !ok {
		return 0, false
	}
	if im.ptr == 8 {
		return im.order.Uint64(b), true
	}
	return uint64(im.order.Uint32(b)), true
}

func (im *lsdaImage) cstring(va uint64) (string, bool) {
	b, ok := im.bytesAt(va, 512)
	if !ok {
		// A name at the very end of a segment may be shorter than the probe;
		// fall back to the tail read and still require a terminator.
		m, ok := im.region(va)
		if !ok {
			return "", false
		}
		b, ok = im.readAt(va, m.size-(va-m.addr))
		if !ok {
			return "", false
		}
	}
	if i := strings.IndexByte(string(b), 0); i >= 0 {
		return string(b[:i]), true
	}
	return "", false
}

// lsdaChainedFixups reads LC_DYLD_CHAINED_FIXUPS just far enough to name an
// imported symbol. The chain itself is not walked: a type table slot holds a
// dyld_chained_ptr_64_bind whose low 24 bits are the import ordinal, and the
// imports table maps that ordinal to a `__ZTI...` name.
func lsdaChainedFixups(f *os.File, mf *macho.File) []string {
	var raw []byte
	for _, l := range mf.Loads {
		b := l.Raw()
		if len(b) >= 16 && mf.ByteOrder.Uint32(b) == uint32(lcChainedFixups) {
			raw = b
			break
		}
	}
	if raw == nil {
		return nil
	}
	off := mf.ByteOrder.Uint32(raw[8:])
	size := mf.ByteOrder.Uint32(raw[12:])
	if size == 0 || size > lsdaMaxSection {
		return nil
	}
	blob := make([]byte, size)
	if _, err := f.ReadAt(blob, int64(off)); err != nil {
		return nil
	}
	if len(blob) < 28 {
		return nil
	}
	imports := int(mf.ByteOrder.Uint32(blob[8:]))
	symbols := int(mf.ByteOrder.Uint32(blob[12:]))
	count := int(mf.ByteOrder.Uint32(blob[16:]))
	format := mf.ByteOrder.Uint32(blob[20:])
	symFormat := mf.ByteOrder.Uint32(blob[24:])
	// Compressed symbol strings would need a zlib reader; the common writer
	// leaves them uncompressed, and refusing here costs only the fallback.
	if symFormat != 0 || count <= 0 || count > 1<<20 || imports < 0 || symbols < 0 {
		return nil
	}
	entry := 0
	switch format {
	case 1, 2:
		entry = 4
		if format == 2 {
			entry = 8
		}
	case 3:
		entry = 16
	default:
		return nil
	}
	if imports+count*entry > len(blob) || symbols > len(blob) {
		return nil
	}
	out := make([]string, count)
	for i := range count {
		var nameOff uint32
		if format == 3 {
			nameOff = uint32(mf.ByteOrder.Uint64(blob[imports+i*entry:]) >> 32)
		} else {
			// lib_ordinal:8, weak:1, name_offset:23
			nameOff = mf.ByteOrder.Uint32(blob[imports+i*entry:]) >> 9
		}
		start := symbols + int(nameOff)
		if start < 0 || start >= len(blob) {
			continue
		}
		end := bytes.IndexByte(blob[start:], 0)
		if end < 0 {
			continue
		}
		out[i] = string(blob[start : start+end])
	}
	return out
}

// fixupName decodes a chained bind token. Bit 63 distinguishes bind from
// rebase; rebases carry no symbol name and fall through to address lookup.
func (im *lsdaImage) fixupName(v uint64) (string, bool) {
	if v>>63 == 0 {
		return "", false
	}
	ord := int(v & 0xffffff)
	if ord < 0 || ord >= len(im.fixups) || im.fixups[ord] == "" {
		return "", false
	}
	return im.fixups[ord], true
}

// lsdaDemangle turns an Itanium type encoding into the C++ spelling. This is
// deliberately not a demangler: it reads length-prefixed nested components and
// the std substitutions, which is the whole shape of a type_info name. A
// template or vendor extension it does not understand falls back to the exact
// mangled payload, never to a guessed class name.
func lsdaDemangle(name string) string {
	// Mach-O imports carry a double underscore: ___ZTI / __ZTI / _ZTI all
	// spell the same Itanium type-info prefix once the linker underscore is
	// gone.
	s := strings.TrimLeft(name, "_")
	s = strings.TrimPrefix(s, "ZTI")
	if s == "" {
		return name
	}
	if out, ok := itaniumTypeName(s); ok {
		return out
	}
	return s
}

// itaniumNameParser reads the type encoding shared by the LSDA catch-clause
// names and the _ZTV/_ZTI/_ZTS symbols: one decoder, one spelling per symbol.
type itaniumNameParser struct {
	s string
	i int
}

// itaniumTypeName decodes a type component: the length-prefixed nested form and
// the std substitutions are the whole shape of a type_info name, and anything
// else is refused rather than guessed.
func itaniumTypeName(s string) (string, bool) {
	p := &itaniumNameParser{s: s}
	if p.i < len(p.s) && p.s[p.i] == 'N' {
		p.i++
		var parts []string
		for p.i < len(p.s) && p.s[p.i] != 'E' {
			part, ok := p.component()
			if !ok {
				return "", false
			}
			if part != "" && !itaniumABINamespace(part) {
				parts = append(parts, part)
			}
		}
		if p.i >= len(p.s) || p.s[p.i] != 'E' {
			return "", false
		}
		p.i++
		if len(parts) == 0 || p.i != len(p.s) {
			return "", false
		}
		return strings.Join(parts, "::"), true
	}
	var parts []string
	for p.i < len(p.s) {
		part, ok := p.component()
		if !ok {
			return "", false
		}
		if part != "" && !itaniumABINamespace(part) {
			parts = append(parts, part)
		}
	}
	if len(parts) == 0 {
		return "", false
	}
	return strings.Join(parts, "::"), true
}

func (p *itaniumNameParser) component() (string, bool) {
	if p.i >= len(p.s) {
		return "", false
	}
	if p.s[p.i] == 'S' {
		return p.substitution()
	}
	if p.s[p.i] < '0' || p.s[p.i] > '9' {
		return "", false
	}
	n := 0
	for p.i < len(p.s) && p.s[p.i] >= '0' && p.s[p.i] <= '9' {
		n = n*10 + int(p.s[p.i]-'0')
		p.i++
		if n > len(p.s) {
			return "", false
		}
	}
	if n == 0 || p.i+n > len(p.s) {
		return "", false
	}
	name := p.s[p.i : p.i+n]
	p.i += n
	return name, true
}

// substitution covers the standard abbreviations that appear in a type_info
// name. St is `std`; the others are only useful when a libstdc++ binary names
// std::string or one of the stream classes in a catch clause.
func (p *itaniumNameParser) substitution() (string, bool) {
	if p.i+1 >= len(p.s) || p.s[p.i] != 'S' {
		return "", false
	}
	switch p.s[p.i+1] {
	case 't':
		p.i += 2
		return "std", true
	case 'a':
		p.i += 2
		return "std::allocator", true
	case 'b':
		p.i += 2
		return "std::basic_string", true
	case 's':
		p.i += 2
		return "std::string", true
	case 'i':
		p.i += 2
		return "std::istream", true
	case 'o':
		p.i += 2
		return "std::ostream", true
	case 'd':
		p.i += 2
		return "std::iostream", true
	case '_':
		p.i += 2
		return "", true
	}
	return "", false
}

// itaniumABINamespace drops the inline namespace a standard library wraps its
// types in. libc++ calls std::runtime_error std::__1::runtime_error, libstdc++
// calls std::string std::__cxx11::basic_string; neither prefix is part of the
// class the catch clause names.
func itaniumABINamespace(part string) bool {
	switch part {
	case "__1", "__2", "__cxx11", "__ndk1":
		return true
	}
	return false
}
