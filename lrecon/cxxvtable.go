package main

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

// Itanium C++ vtable -> slot -> function recovery from ELF relocations.
//
// A vtable slot is a pointer the linker has to write, so the relocation is the
// evidence: reading the word stored in the file only tells us what the loader
// will replace. This reader therefore resolves every virtual function slot
// through SHT_RELA and refuses a slot that carries no relocation instead of
// treating a raw word as an address. The target is never executed and no
// symbol name is guessed: a function is named only when a relocation or the
// symbol table names it.
//
// The layout is the ABI contract, not a heuristic:
//
//	[-2] offset-to-top (0 in a primary vtable, negative for a secondary one)
//	[-1] &_ZTI<type>
//	[0..] virtual function pointers, in declaration order
//
// A secondary vtable for a non-virtual base repeats [-2]/[-1] before its own
// functions, which is why the same walk needs no special case. A primary vtable
// with virtual bases also carries vcall/vbase offset entries after the function
// slots; those are plain integers without relocations, so the walk simply stops
// when the relocation chain ends (or the symbol size says so).
//
// Symbol authority is the Itanium mangler: _ZTV<type>, _ZTI<type>, _ZTS<type>
// are the vtable, typeinfo and typeinfo-name objects (gcc/cp/mangle.cc
// mangle_vtbl_for_type, mangle_typeinfo_for_type, mangle_typeinfo_string_for_type).
// The class name comes from the _ZTV symbol, the base relationship from the
// _ZTI object: __class_type_info has no base, __si_class_type_info one,
// __vmi_class_type_info a base array whose __offset_flags bit 0 is the virtual
// mask and bits 8.. the base offset.
//
// Scope refusal: x86-64 only (the relocation numbers below are that ABI's), a
// stripped symbol table or a slot with no relocation is reported, never
// bridged with a guess. Nothing here claims a class for a Mach-O or PE target.

const (
	cxxMaxVtables = 256
	cxxMaxRela    = 32 << 20
	cxxMaxBases   = 32
	cxxMaxSlots   = 4096
	cxxFuncShown  = 4
	cxxNameShown  = 128
)

// Closed reason set. Each names an observation the reader could not make, not a
// verdict about the target.
const (
	cxxReasonAbsent     = "cxxvtable-absent"
	cxxReasonStripped   = "cxxvtable-symtab-stripped"
	cxxReasonReloc      = "cxxvtable-reloc-unresolved"
	cxxReasonRTTIBad    = "cxxvtable-rtti-unreadable"
	cxxReasonRTTINone   = "cxxvtable-rtti-absent"
	cxxReasonTooMany    = "cxxvtable-too-many-classes"
	cxxReasonTruncated  = "cxxvtable-truncated"
	cxxReasonNameUnread = "cxxvtable-name-unreadable"
)

func init() {
	register(reader{
		format: "cxxvtable",
		reasons: []string{
			cxxReasonAbsent,
			cxxReasonStripped,
			cxxReasonReloc,
			cxxReasonRTTIBad,
			cxxReasonRTTINone,
			cxxReasonTooMany,
			cxxReasonTruncated,
			cxxReasonNameUnread,
		},
		post:    true,
		inspect: inspectCxxVtable,
	})
}

func init() {
	reasonRegistry["cxxvtable"] = reasonSet(
		cxxReasonAbsent, cxxReasonStripped, cxxReasonReloc, cxxReasonRTTIBad,
		cxxReasonRTTINone, cxxReasonTooMany, cxxReasonTruncated, cxxReasonNameUnread,
	)
}

// cxxReloc is one relocation as the loader would apply it. name is the symbol
// the relocation names; it may be empty for a RELATIVE entry, where the target
// address alone identifies the object.
type cxxReloc struct {
	target uint64
	name   string
	typ    uint32
}

// cxxSection maps a canonical address space onto file bytes. ET_REL has no
// addresses at all, so the reader gives each allocated section a stable synthetic
// base; every symbol and relocation is then compared in that same space.
type cxxSection struct {
	base uint64
	size uint64
	off  uint64
}

type cxxImage struct {
	r     io.ReaderAt
	rel   bool // ET_REL: r_offset and st_value are section-relative
	secs  []cxxSection
	byIdx map[int]cxxSection
	symAt map[uint64]string
	relAt map[uint64]cxxReloc
}

// cxxSym is a raw symtab entry. debug/elf's Symbols drops the leading null
// symbol, which shifts every r_info symbol index by one; RELA indices are into
// the on-disk table, so the table is read here and indexed by its real position.
type cxxSym struct {
	name  string
	value uint64
	size  uint64
	shndx elf.SectionIndex
}

type cxxClass struct {
	name   string
	slots  int // declared virtual slots, from the vtable object size
	funcs  []string
	base   string
	bases  []string
	virt   int
	offset int64
}

type cxxRefusal struct {
	reason string
	detail string
}

func inspectCxxVtable(path string, d *Digest) {
	if d.Kind != "elf" {
		return
	}
	fh, err := os.Open(path)
	if err != nil {
		return
	}
	defer fh.Close()
	f, err := elf.NewFile(fh)
	if err != nil {
		// The native reader owns an unreadable ELF and already said so; a second
		// refusal here would claim the same failure twice.
		return
	}
	if f.Machine != elf.EM_X86_64 {
		// The relocation numbers are the x86-64 psABI's. On another machine the
		// same bytes are different relocations, so silence is the only safe answer.
		return
	}
	syms, err := cxxSymbols(f)
	if err != nil {
		if cxxHasRelRo(f) {
			d.skip(cxxReasonStripped, "no symbol table and .data.rel.ro is present")
		}
		return
	}

	var vtables []cxxSym
	rttiSeen := false
	for _, s := range syms {
		if s.shndx == elf.SHN_UNDEF {
			continue
		}
		kind := cxxTableKind(s.name)
		switch kind {
		case "_ZTV":
			vtables = append(vtables, s)
		case "_ZTI", "_ZTS":
			rttiSeen = true
		}
	}
	if len(vtables) == 0 {
		switch {
		case rttiSeen:
			// Typeinfo without a vtable is a real shape (only abstract classes, or
			// a translation unit that never instantiates the class), so it is an
			// absence answer rather than a failed read.
			d.skip(cxxReasonAbsent, "Itanium RTTI symbols but no _ZTV")
		case cxxHasRelRo(f):
			// Vtable storage exists but no symbol names it: a stripped symbol
			// table, not an absence of classes.
			d.skip(cxxReasonStripped, "no _ZTV symbol names and .data.rel.ro is present")
		}
		return
	}
	if len(vtables) > cxxMaxVtables {
		d.skip(cxxReasonTooMany, fmt.Sprintf("%d _ZTV symbols, cap %d", len(vtables), cxxMaxVtables))
		vtables = vtables[:cxxMaxVtables]
	}

	im, err := cxxLoadImage(f, fh, syms)
	if err != nil {
		d.skip(cxxReasonTruncated, err.Error())
		return
	}

	type cand struct {
		addr uint64
		sym  cxxSym
	}
	cands := make([]cand, 0, len(vtables))
	for _, s := range vtables {
		addr, ok := im.addrOf(s)
		if !ok {
			d.skip(cxxReasonReloc, s.name+": vtable address outside the section table")
			continue
		}
		cands = append(cands, cand{addr: addr, sym: s})
	}
	sort.Slice(cands, func(i, j int) bool {
		if cands[i].addr != cands[j].addr {
			return cands[i].addr < cands[j].addr
		}
		return cands[i].sym.name < cands[j].sym.name
	})

	var classes []cxxClass
	seen := map[string]bool{}
	baseEdges := 0
	totalSlots := 0
	for _, c := range cands {
		cls, refusals, ok := im.recover(c.addr, c.sym)
		for _, r := range refusals {
			d.skip(r.reason, r.detail)
		}
		if !ok {
			continue
		}
		d.parsed()
		classes = append(classes, cls)
		seen[cls.name] = true
		totalSlots += cls.slots
		if len(cls.bases) > 0 {
			baseEdges++
		}
	}
	if len(classes) == 0 {
		return
	}

	// One summary line plus one line per vtable: the summary keeps the counts
	// comparable across binaries, the per-line form keeps the names and the base
	// edge readable without parsing a nested dump.
	deepNote(d, fmt.Sprintf("cxx-class %d (%d vtables, %d slots, %d bases)",
		len(seen), len(classes), totalSlots, baseEdges))
	for _, c := range classes {
		line := fmt.Sprintf("cxx-class %s slots=%d", c.name, c.slots)
		if c.base != "" {
			line += " base=" + c.base
		}
		if c.offset != 0 {
			line += fmt.Sprintf(" offset_to_top=%d", c.offset)
		}
		if c.virt > 0 {
			line += fmt.Sprintf(" virtual_bases=%d", c.virt)
		}
		if len(c.funcs) > 0 {
			shown := c.funcs
			more := 0
			if len(shown) > cxxFuncShown {
				more = len(shown) - cxxFuncShown
				shown = shown[:cxxFuncShown]
			}
			line += " fn=" + strings.Join(shown, ",")
			if more > 0 {
				line += fmt.Sprintf("+%d", more)
			}
		}
		deepNote(d, line)
	}
}

// recover walks one vtable object. The first return value is only trusted when
// ok is true; refusals explain every part that was not read, and a refused
// vtable contributes no note at all.
func (im *cxxImage) recover(addr uint64, sym cxxSym) (cxxClass, []cxxRefusal, bool) {
	var cls cxxClass
	cls.name = cxxTableType(sym.name)
	if cls.name == "" {
		cls.name = cxxTypeInfoName(im, addr+8)
	}
	if cls.name == "" {
		return cls, []cxxRefusal{{cxxReasonNameUnread, sym.name + ": no length-prefixed type name"}}, false
	}
	cls.name = cxxShorten(cls.name, cxxNameShown)

	size := sym.size
	if size < 16 {
		// No usable size: follow the relocation chain from the typeinfo slot. A
		// gap ends the vtable, because a function slot must be relocated.
		size = 16
		for im.hasReloc(addr + size) {
			size += 8
		}
	}
	if raw, ok := im.word(addr); ok {
		cls.offset = int64(raw)
	}

	// [-1] is the typeinfo pointer. Without its relocation the slot order cannot
	// be distinguished from a table that happens to start with two words.
	if _, ok := im.relAt[addr+8]; !ok {
		return cls, []cxxRefusal{{cxxReasonReloc, sym.name + ": [-1] typeinfo slot has no relocation"}}, false
	}
	bases, virt, rttiReason := im.rtti(addr + 8)
	var refusals []cxxRefusal
	if rttiReason != "" {
		refusals = append(refusals, cxxRefusal{rttiReason, sym.name + ": RTTI"})
	} else {
		cls.bases = bases
		cls.virt = virt
		for _, b := range bases {
			cls.base = b
			break
		}
	}

	if size > 16+8*cxxMaxSlots {
		return cls, append(refusals, cxxRefusal{cxxReasonTruncated,
			fmt.Sprintf("%s: vtable size %d exceeds %d slots", sym.name, size, cxxMaxSlots)}), false
	}
	end := addr + size
	for i := uint64(0); addr+16+i*8+8 <= end; i++ {
		slot := addr + 16 + i*8
		r, ok := im.relAt[slot]
		if !ok {
			// A primary vtable with virtual bases appends vcall/vbase offset
			// words after the function slots; those are integers, not pointers,
			// so they carry no relocation. A relocated word after the gap would
			// instead mean a function slot lost its relocation, and that is
			// refused rather than silently cut short.
			if im.relocAhead(slot+8, end) {
				return cls, append(refusals, cxxRefusal{cxxReasonReloc,
					fmt.Sprintf("%s: slot %d has no relocation before a relocated word", sym.name, i)}), false
			}
			break
		}
		// Only the two relocation kinds that make a code pointer exist on x86-64.
		// A GLOB_DAT here would name an imported object, not a virtual function.
		if r.typ != uint32(elf.R_X86_64_RELATIVE) && r.typ != uint32(elf.R_X86_64_64) {
			return cls, append(refusals, cxxRefusal{cxxReasonReloc,
				fmt.Sprintf("%s: slot %d relocation type %d", sym.name, i, r.typ)}), false
		}
		name := r.name
		if name == "" {
			name = im.symAt[r.target]
		}
		if name == "" {
			name = fmt.Sprintf("fn@%#x", r.target)
		}
		cls.funcs = append(cls.funcs, name)
	}
	cls.slots = len(cls.funcs)
	return cls, refusals, true
}

// rtti reads the typeinfo object a vtable's [-1] slot names. The vptr at offset
// 0 is the discriminator: __si_class_type_info and __vmi_class_type_info carry
// their shape, and __class_type_info carries none. A vptr that is not one of
// those three is refused instead of being read as whichever layout fits.
func (im *cxxImage) rtti(infoSlot uint64) (bases []string, virt int, reason string) {
	target, _, ok := im.pointer(infoSlot)
	if !ok {
		return nil, 0, cxxReasonRTTINone
	}
	vptr, vname, ok := im.pointer(target)
	if !ok {
		return nil, 0, cxxReasonRTTIBad
	}
	if vname == "" {
		vname = im.symAt[vptr]
	}
	switch {
	case strings.Contains(vname, "__si_class_type_info"):
		b := im.baseName(target + 16)
		if b == "" {
			return nil, 0, cxxReasonRTTIBad
		}
		return []string{b}, 0, ""
	case strings.Contains(vname, "__vmi_class_type_info"):
		_, okFlags := im.u32(target + 16)
		count, okCount := im.u32(target + 20)
		if !okFlags || !okCount || count == 0 || count > cxxMaxBases {
			return nil, 0, cxxReasonRTTIBad
		}
		for i := range count {
			p := target + 24 + uint64(i)*16
			b := im.baseName(p)
			if b == "" {
				return nil, 0, cxxReasonRTTIBad
			}
			flags, ok := im.word(p + 8)
			if !ok {
				return nil, 0, cxxReasonRTTIBad
			}
			// __virtual_mask is 0x1, __offset_shift is 8; a virtual base is a
			// vtable offset, not a subobject offset, so it is counted apart.
			if flags&1 != 0 {
				virt++
			}
			bases = append(bases, b)
		}
		return bases, virt, ""
	case strings.Contains(vname, "__class_type_info"):
		return nil, 0, ""
	default:
		return nil, 0, cxxReasonRTTIBad
	}
}

// baseName resolves a __base_class_type_info __base_type pointer to a class
// name. The fast path is the _ZTI symbol; when local symbols were dropped the
// object's own __type_name pointer is still typeinfo data, so it is read too.
func (im *cxxImage) baseName(slot uint64) string {
	target, name, ok := im.pointer(slot)
	if !ok {
		return ""
	}
	if name == "" {
		name = im.symAt[target]
	}
	if b := cxxTableType(name); b != "" {
		return cxxShorten(b, cxxNameShown)
	}
	if n := cxxTypeInfoName(im, target+8); n != "" {
		return cxxShorten(n, cxxNameShown)
	}
	return ""
}

// cxxTypeInfoName reads the __type_name pointer at the given typeinfo offset.
func cxxTypeInfoName(im *cxxImage, slot uint64) string {
	_, name, ok := im.pointer(slot)
	if !ok {
		return ""
	}
	if name == "" {
		name = im.symAt[im.mustTarget(slot)]
	}
	return cxxTableType(name)
}

func (im *cxxImage) mustTarget(slot uint64) uint64 {
	if r, ok := im.relAt[slot]; ok {
		return r.target
	}
	w, _ := im.word(slot)
	return w
}

// cxxLoadImage builds the canonical address space and the relocation map. Only
// allocated sections take part: a debug section's bytes are not loadable, so an
// address there would be a coincidence rather than a target. syms is the table
// the caller already read; parsing it twice per digest would double the only
// unbounded parse here.
func cxxLoadImage(f *elf.File, r io.ReaderAt, syms []cxxSym) (*cxxImage, error) {
	im := &cxxImage{
		r:     r,
		rel:   f.Type == elf.ET_REL,
		byIdx: map[int]cxxSection{},
		symAt: map[uint64]string{},
		relAt: map[uint64]cxxReloc{},
	}
	next := uint64(0x100000)
	for i, s := range f.Sections {
		if s.Flags&elf.SHF_ALLOC == 0 {
			continue
		}
		base := s.Addr
		if im.rel || base == 0 {
			base = next
			next += (s.Size + 0xfff) &^ 0xfff
			next += 0x1000
		}
		sec := cxxSection{base: base, size: s.Size, off: s.Offset}
		im.secs = append(im.secs, sec)
		im.byIdx[i] = sec
	}

	for _, s := range syms {
		if s.shndx == elf.SHN_UNDEF {
			continue
		}
		addr, ok := im.addrOf(s)
		if !ok || addr == 0 {
			continue
		}
		if _, dup := im.symAt[addr]; !dup {
			im.symAt[addr] = s.name
		}
	}

	// .rela.dyn links against .dynsym while .rela.text links against .symtab, so
	// each relocation section is read with the table it actually indexes.
	cache := map[int][]cxxSym{}
	for _, s := range f.Sections {
		if s.Type != elf.SHT_RELA {
			continue
		}
		if s.Size > cxxMaxRela {
			return nil, fmt.Errorf("%s is %d bytes, cap %d", s.Name, s.Size, cxxMaxRela)
		}
		link := int(s.Link)
		table, ok := cache[link]
		if !ok {
			table = cxxLinkSymbols(f, link)
			cache[link] = table
		}
		if len(table) == 0 {
			continue
		}
		data := sectionBytes(s, cxxMaxRela)
		base, relSec := uint64(0), false
		if im.rel {
			if sec, ok := im.byIdx[int(s.Info)]; ok {
				base, relSec = sec.base, true
			}
		}
		for i := 0; i+24 <= len(data); i += 24 {
			off := binary.LittleEndian.Uint64(data[i:])
			info := binary.LittleEndian.Uint64(data[i+8:])
			addend := uint64(int64(binary.LittleEndian.Uint64(data[i+16:])))
			typ := uint32(info)
			idx := int(info >> 32)
			if idx <= 0 || idx >= len(table) {
				continue
			}
			addr := off
			if im.rel {
				if !relSec {
					continue
				}
				addr = base + off
			}
			target := addend
			name := table[idx].name
			if typ == uint32(elf.R_X86_64_64) {
				// S + A: the symbol's canonical address plus the addend. An
				// undefined symbol contributes zero and the name still stands.
				if symAddr, ok := im.addrOf(table[idx]); ok {
					target += symAddr
				}
			}
			im.relAt[addr] = cxxReloc{target: target, name: name, typ: typ}
		}
	}
	return im, nil
}

func cxxLinkSymbols(f *elf.File, link int) []cxxSym {
	for _, typ := range []elf.SectionType{elf.SHT_SYMTAB, elf.SHT_DYNSYM} {
		if idx, ok := cxxSectionIndex(f, typ); ok && idx == link {
			return cxxReadSymtab(f, idx)
		}
	}
	return nil
}

// cxxSectionIndex finds the header index of the first section of a type; symbol
// tables are located by walking the table because debug/elf exposes no index.
func cxxSectionIndex(f *elf.File, typ elf.SectionType) (int, bool) {
	for i, s := range f.Sections {
		if s.Type == typ {
			return i, true
		}
	}
	return 0, false
}

func cxxSymbols(f *elf.File) ([]cxxSym, error) {
	for _, typ := range []elf.SectionType{elf.SHT_SYMTAB, elf.SHT_DYNSYM} {
		if idx, ok := cxxSectionIndex(f, typ); ok {
			if syms := cxxReadSymtab(f, idx); len(syms) > 0 {
				return syms, nil
			}
		}
	}
	return nil, errors.New("no symbol table")
}

// cxxReadSymtab parses Elf64_Sym entries in table order, including the null
// entry, so an index from r_info addresses the same symbol the linker saw.
func cxxReadSymtab(f *elf.File, idx int) []cxxSym {
	s := f.Sections[idx]
	if s.Entsize != 24 || s.Link == 0 || int(s.Link) >= len(f.Sections) {
		return nil
	}
	data := sectionBytes(s, cxxMaxRela)
	str, err := f.Sections[s.Link].Data()
	if err != nil {
		return nil
	}
	var out []cxxSym
	for i := 0; i+24 <= len(data); i += 24 {
		nameOff := binary.LittleEndian.Uint32(data[i:])
		shndx := elf.SectionIndex(binary.LittleEndian.Uint16(data[i+6:]))
		value := binary.LittleEndian.Uint64(data[i+8:])
		size := binary.LittleEndian.Uint64(data[i+16:])
		name := ""
		if int(nameOff) < len(str) {
			if z := bytes.IndexByte(str[nameOff:], 0); z >= 0 {
				name = string(str[nameOff : int(nameOff)+z])
			}
		}
		out = append(out, cxxSym{name: name, value: value, size: size, shndx: shndx})
	}
	return out
}

func (im *cxxImage) addrOf(s cxxSym) (uint64, bool) {
	if s.shndx == elf.SHN_ABS {
		return s.value, true
	}
	if s.shndx == elf.SHN_UNDEF {
		return 0, false
	}
	if im.rel {
		sec, ok := im.byIdx[int(s.shndx)]
		if !ok {
			return 0, false
		}
		return sec.base + s.value, true
	}
	return s.value, true
}

func (im *cxxImage) section(addr uint64) (cxxSection, bool) {
	for _, s := range im.secs {
		if addr >= s.base && addr < s.base+s.size {
			return s, true
		}
	}
	return cxxSection{}, false
}

func (im *cxxImage) word(addr uint64) (uint64, bool) {
	s, ok := im.section(addr)
	if !ok || addr+8 > s.base+s.size {
		return 0, false
	}
	var b [8]byte
	if _, err := im.r.ReadAt(b[:], int64(s.off+addr-s.base)); err != nil {
		return 0, false
	}
	return binary.LittleEndian.Uint64(b[:]), true
}

func (im *cxxImage) u32(addr uint64) (uint32, bool) {
	s, ok := im.section(addr)
	if !ok || addr+4 > s.base+s.size {
		return 0, false
	}
	var b [4]byte
	if _, err := im.r.ReadAt(b[:], int64(s.off+addr-s.base)); err != nil {
		return 0, false
	}
	return binary.LittleEndian.Uint32(b[:]), true
}

// pointer returns the target and name a slot will hold at load time. A stored
// word without a relocation is only returned as a value, never as a class name,
// unless the symbol table independently names that exact address.
func (im *cxxImage) pointer(addr uint64) (uint64, string, bool) {
	if r, ok := im.relAt[addr]; ok {
		return r.target, r.name, true
	}
	w, ok := im.word(addr)
	if !ok {
		return 0, "", false
	}
	return w, im.symAt[w], true
}

func (im *cxxImage) hasReloc(addr uint64) bool {
	_, ok := im.relAt[addr]
	return ok
}

func (im *cxxImage) relocAhead(from, end uint64) bool {
	for a := from; a+8 <= end; a += 8 {
		if im.hasReloc(a) {
			return true
		}
	}
	return false
}

// cxxTableKind classifies an Itanium special symbol without decoding it. The
// mangling.go family check is the authority for "this is an Itanium table at
// all"; the prefix then says which of the three RTTI/vtable objects it is.
func cxxTableKind(name string) string {
	if fam, shape := manglingFamily(name); fam != "itanium" || shape != "table" {
		return ""
	}
	n := manglingLLVMRe.ReplaceAllString(name, "")
	if strings.HasPrefix(n, "__Z") {
		n = n[1:] // a Mach-O symbol would carry one extra underscore
	}
	for _, kind := range []string{"_ZTV", "_ZTI", "_ZTS"} {
		if strings.HasPrefix(n, kind) {
			return kind
		}
	}
	return ""
}

// cxxTableType decodes the type component of _ZTV/_ZTI/_ZTS. A _ZTI name is the
// same type component an LSDA catch clause names, so the decoder is shared with
// lsda.go: the same symbol spells the same class whichever reader asked.
func cxxTableType(name string) string {
	if name == "" {
		return ""
	}
	name = manglingLLVMRe.ReplaceAllString(name, "")
	if strings.HasPrefix(name, "__Z") {
		name = name[1:]
	}
	for _, kind := range []string{"_ZTS", "_ZTI", "_ZTV"} {
		if strings.HasPrefix(name, kind) {
			if t, ok := itaniumTypeName(name[len(kind):]); ok {
				return t
			}
			return ""
		}
	}
	return ""
}

func cxxShorten(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}

func cxxHasRelRo(f *elf.File) bool {
	for _, name := range []string{".data.rel.ro", ".data.rel.ro.local"} {
		if s := f.Section(name); s != nil && s.Size >= 16 {
			return true
		}
	}
	return false
}
