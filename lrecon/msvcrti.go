package main

import (
	"debug/pe"
	"encoding/binary"
	"fmt"
	"slices"
	"strings"
)

// MSVC C++ RTTI class recovery.
//
// clang and MSVC write the same four descriptors behind every vftable:
//
//	TypeDescriptor            {vftable ptr, spare, char name[]}
//	BaseClassDescriptor       {imgrel TD, nContained, mdisp, pdisp, vdisp, attr, imgrel CHD}
//	ClassHierarchyDescriptor  {signature, attributes, numBaseClasses, imgrel baseArray}
//	CompleteObjectLocator     {signature, offset, cdOffset, imgrel TD, imgrel CHD, imgrel self}
//
// Only the TypeDescriptor header is pointer-sized. Every descriptor field is 32
// bits even on x64, because an image-relative field is an RVA, not an address.
// A linked image stores the RVA directly; a COFF object stores an addend and
// leaves the section to an ADDR32NB/DIR32NB relocation. An unrelocated field is
// refused instead of read as an offset into whichever section happens to hold
// the descriptor: that guess would silently turn a base pointer into a self
// pointer and still look plausible.
//
// The base array is pre-order depth-first and starts with the class itself, so
// the list is printed in descriptor order and never rewritten into a tree.
//
// The target is never executed and nothing is guessed: a locator that does not
// validate end to end is refused with one of the closed reasons below.

const (
	msvcReasonAbsent = "msvcrti-absent"
	msvcReasonCol    = "msvcrti-col-invalid"
	msvcReasonImage  = "msvcrti-imagebase-unresolved"
	msvcReasonName   = "msvcrti-name-unreadable"
)

const (
	msvcColSize    = 24 // six 32-bit fields, including the CFG self pointer
	msvcChdSize    = 16
	msvcBcdSize    = 28
	msvcNameCap    = 512 // longest type name read before the descriptor is refused
	msvcClassCap   = 16
	msvcBaseCap    = 24
	msvcRefusalCap = 8 // skip lines per reason, so a hostile table cannot flood
	msvcScanCap    = 32 << 20
	msvcImageCap   = 64 << 20
)

func init() {
	register(reader{
		format: "msvcrti",
		post:   true,
		reasons: []string{
			msvcReasonAbsent, msvcReasonCol, msvcReasonImage, msvcReasonName,
		},
		// no match: a COFF object has no magic and a PE already reached
		// dispatchPost through the magic switch; both are re-opened here.
		inspect: inspectMSVCRtti,
	})
	reasonRegistry["msvcrti"] = reasonSet(
		msvcReasonAbsent, msvcReasonCol, msvcReasonImage, msvcReasonName)
}

func inspectMSVCRtti(path string, d *Digest) {
	if d.Kind != "pe" && d.Kind != "unknown" {
		return
	}
	f, err := pe.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	object := f.OptionalHeader == nil
	if object {
		// A COFF object has no magic of its own, so the header is the claim: a
		// named machine, real sections, and no "executable image" bit (that bit
		// belongs to a linked PE, which native.go already owns).
		if f.Characteristics&pe.IMAGE_FILE_EXECUTABLE_IMAGE != 0 ||
			len(f.Sections) == 0 || !msvcMachine(f.Machine) {
			return
		}
	} else if msvcManagedImage(f) {
		return // CLR image: RTTI lives in metadata, not in these descriptors
	}

	img, ok := msvcOpen(path, f, d.FileSize)
	if !ok {
		return
	}
	// Only an end-to-end read may answer "absent"; a section-only read leaves the
	// absence unclaimed, and the scan reason says nothing rather than guessing.
	if img.raw > 0 {
		// The read is from byte zero, not from the sequential cursor the native
		// parse left at EOF; recording it as a contiguous span double-counted it.
		d.witness(Witness{Axis: "read", Class: "read", Value: "read", Start: 0, End: int64(img.raw)})
	}

	seen := map[msvcPos]bool{}
	var candidates []msvcCandidate
	for _, pos := range img.symbolCols(f) {
		if seen[pos] {
			continue
		}
		seen[pos] = true
		candidates = append(candidates, msvcCandidate{pos: pos, symbol: true})
	}
	if !object {
		scanned, cut := img.scanCols(seen)
		if cut {
			d.Notes = append(d.Notes, fmt.Sprintf(
				"msvcrti: locator scan stopped after %d MiB", msvcScanCap>>20))
		}
		for _, pos := range scanned {
			seen[pos] = true
			candidates = append(candidates, msvcCandidate{pos: pos})
		}
	}

	var classes []*msvcClass
	byName := map[string]*msvcClass{}
	refusals, dropped := 0, 0
	perReason := map[string]int{}
	for _, c := range candidates {
		cls, reason, detail := img.parseCol(c.pos)
		if reason != "" {
			// Scanned candidates already validated, so a failure here is a named
			// locator: report it. Scan misses stay silent or every 4-byte value in
			// .rdata would become a finding.
			if c.symbol {
				refusals++
				if perReason[reason] < msvcRefusalCap {
					perReason[reason]++
					d.skip(reason, detail)
					d.unparsed()
				}
			}
			continue
		}
		d.parsed()
		if have, ok := byName[cls.name]; ok {
			for _, off := range cls.offsets {
				have.offsets = msvcAppendUnique(have.offsets, off)
			}
			continue
		}
		if len(classes) >= msvcClassCap {
			dropped++
			continue
		}
		byName[cls.name] = cls
		classes = append(classes, cls)
	}

	if dropped > 0 {
		d.Notes = append(d.Notes, fmt.Sprintf("msvcrti: %d more classes not listed", dropped))
	}
	if len(classes) == 0 {
		if refusals == 0 && d.complete() {
			d.skip(msvcReasonAbsent, fmt.Sprintf(
				"no complete object locator in %d section(s)", len(img.secs)))
		}
		return
	}
	d.Notes = append(d.Notes, msvcClassLine(classes))
}

// msvcCandidate is one locator position. symbol marks a locator named by a
// ??_R4 symbol, the only candidates whose failures are reported.
type msvcCandidate struct {
	pos    msvcPos
	symbol bool
}

// msvcClass is one recovered class: the name from its type descriptor, the base
// names in descriptor order, and every vftable offset that shares the locator.
type msvcClass struct {
	name    string
	bases   []string
	offsets []uint32
}

// msvcPos is a byte position inside the image, never a file offset: PE resolves
// RVAs through the section table and a COFF object addresses bytes by section.
type msvcPos struct {
	sec *msvcSec
	off uint32
}

type msvcSec struct {
	name   string
	data   []byte
	rva    uint32 // PE only; zero for every section of a COFF object
	exec   bool
	relocs map[uint32]msvcReloc // COFF only: field offset -> fixup
}

type msvcReloc struct {
	idx int
	typ uint16
}

type msvcImage struct {
	obj     bool
	machine uint16
	ptr     int
	secs    []*msvcSec
	syms    []pe.COFFSymbol // raw records: relocation indexes address these
	raw     int             // bytes read end to end, zero when only sections were read
}

// msvcMachineInfo is one COFF machine this reader can address: the descriptor
// pointer width and the relocation that marks an image-relative field. The
// membership test, the pointer width and the fixup check below are three
// questions about the same set, so they read one table instead of three
// switches that can drift apart when a machine is added.
type msvcMachineInfo struct {
	machine uint16
	ptr     int
	reloc   uint16 // IMAGE_REL_<machine>_ADDR32NB
}

var msvcMachines = []msvcMachineInfo{
	{pe.IMAGE_FILE_MACHINE_AMD64, 8, 0x0003},
	{pe.IMAGE_FILE_MACHINE_ARM64, 8, 0x0003},
	{pe.IMAGE_FILE_MACHINE_IA64, 8, 0x0003},
	{pe.IMAGE_FILE_MACHINE_I386, 4, 0x0007},
	{pe.IMAGE_FILE_MACHINE_ARM, 4, 0x0002},
	{pe.IMAGE_FILE_MACHINE_ARMNT, 4, 0x0002},
}

func msvcMachineFor(m uint16) (msvcMachineInfo, bool) {
	for _, mi := range msvcMachines {
		if mi.machine == m {
			return mi, true
		}
	}
	return msvcMachineInfo{}, false
}

func msvcMachine(m uint16) bool {
	_, ok := msvcMachineFor(m)
	return ok
}

func msvcPointerSize(m uint16) int {
	if mi, ok := msvcMachineFor(m); ok {
		return mi.ptr
	}
	return 4
}

// msvcManagedImage reports a CLR image through its COM descriptor, so a .NET
// assembly does not report "no RTTI" for a language that never had any.
func msvcManagedImage(f *pe.File) bool {
	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		return oh.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress != 0
	case *pe.OptionalHeader64:
		return oh.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress != 0
	}
	return false
}

func msvcOpen(path string, f *pe.File, size int64) (*msvcImage, bool) {
	img := &msvcImage{
		obj:     f.OptionalHeader == nil,
		machine: f.Machine,
		ptr:     msvcPointerSize(f.Machine),
		syms:    f.COFFSymbols,
	}
	// One read for a small image: it lets the digest claim the whole file was
	// scanned, which is what "absent" needs. A larger image is read section by
	// section and never claims absence.
	var all []byte
	if size > 0 && size <= msvcImageCap {
		if b, err := readCapped(path, msvcImageCap); err == nil && int64(len(b)) == size {
			all = b
			img.raw = len(b)
		}
	}
	for _, s := range f.Sections {
		sec := &msvcSec{
			name: s.Name,
			rva:  s.VirtualAddress,
			exec: s.Characteristics&pe.IMAGE_SCN_MEM_EXECUTE != 0,
		}
		start, end := int64(s.Offset), int64(s.Offset)+int64(s.Size)
		if all != nil && start >= 0 && end <= int64(len(all)) {
			sec.data = all[start:end]
		} else if b, err := s.Data(); err == nil {
			sec.data = b
		}
		if img.obj {
			sec.relocs = make(map[uint32]msvcReloc, len(s.Relocs))
			for _, r := range s.Relocs {
				sec.relocs[r.VirtualAddress] = msvcReloc{idx: int(r.SymbolTableIndex), typ: r.Type}
			}
		}
		img.secs = append(img.secs, sec)
	}
	return img, len(img.secs) > 0
}

// symbolCols returns the locators named by ??_R4 symbols. A linked image may
// carry no symbol table at all, which is why the PE scan exists below.
func (m *msvcImage) symbolCols(f *pe.File) []msvcPos {
	var out []msvcPos
	for _, s := range f.Symbols {
		if !strings.HasPrefix(s.Name, "??_R4") {
			continue
		}
		if s.SectionNumber <= 0 || int(s.SectionNumber) > len(m.secs) {
			continue
		}
		out = append(out, msvcPos{sec: m.secs[s.SectionNumber-1], off: s.Value})
	}
	return out
}

// scanCols finds locators through the pointer every vftable keeps eight bytes
// before its first slot. Only a locator that parses end to end survives, so a
// random 4-byte value is not reported as RTTI.
func (m *msvcImage) scanCols(done map[msvcPos]bool) (out []msvcPos, cut bool) {
	budget := msvcScanCap
	seen := map[msvcPos]bool{}
	for _, s := range m.secs {
		if s.exec {
			continue // a vftable lives in read-only data, never in code
		}
		n := len(s.data)
		if n > budget {
			n, cut = budget, true
		}
		budget -= n
		for off := 0; off+4 <= n; off += 4 {
			pos, ok := m.rvaPos(binary.LittleEndian.Uint32(s.data[off:]))
			if !ok || seen[pos] || done[pos] {
				continue
			}
			if _, reason, _ := m.parseCol(pos); reason != "" {
				continue
			}
			seen[pos] = true
			out = append(out, pos)
		}
		if budget <= 0 {
			return out, cut || n < len(s.data)
		}
	}
	return out, false
}

func (m *msvcImage) u32(s *msvcSec, off uint32) (uint32, bool) {
	if uint64(off)+4 > uint64(len(s.data)) {
		return 0, false
	}
	return binary.LittleEndian.Uint32(s.data[off:]), true
}

func (m *msvcImage) bytes(s *msvcSec, off, n uint32) ([]byte, bool) {
	if uint64(off)+uint64(n) > uint64(len(s.data)) {
		return nil, false
	}
	return s.data[off : off+n], true
}

func (m *msvcImage) rvaPos(v uint32) (msvcPos, bool) {
	for _, s := range m.secs {
		if s.rva == 0 {
			continue // COFF object sections have no RVA
		}
		if v >= s.rva && uint64(v-s.rva) < uint64(len(s.data)) {
			return msvcPos{sec: s, off: v - s.rva}, true
		}
	}
	return msvcPos{}, false
}

type msvcRefStatus int

const (
	msvcRefOK        msvcRefStatus = iota
	msvcRefOutside                 // PE RVA that maps into no section
	msvcRefNoFixup                 // COFF field with no relocation at all
	msvcRefBadSymbol               // COFF relocation that names no usable section
)

// ref resolves one 32-bit image-relative field. In a linked image that is an RVA
// and needs no relocation; in an object the relocation is the only thing that
// says which section the addend belongs to.
func (m *msvcImage) ref(s *msvcSec, off uint32) (msvcPos, msvcRefStatus) {
	v, ok := m.u32(s, off)
	if !ok {
		return msvcPos{}, msvcRefOutside
	}
	if !m.obj {
		p, ok := m.rvaPos(v)
		if !ok {
			return msvcPos{}, msvcRefOutside
		}
		return p, msvcRefOK
	}
	r, ok := s.relocs[off]
	if !ok {
		return msvcPos{}, msvcRefNoFixup
	}
	if !msvcImageReloc(m.machine, r.typ) || r.idx < 0 || r.idx >= len(m.syms) {
		return msvcPos{}, msvcRefBadSymbol
	}
	sym := m.syms[r.idx]
	if sym.SectionNumber <= 0 || int(sym.SectionNumber) > len(m.secs) {
		return msvcPos{}, msvcRefBadSymbol
	}
	return msvcPos{sec: m.secs[sym.SectionNumber-1], off: sym.Value + v}, msvcRefOK
}

// msvcImageReloc is the image-relative (RVA) relocation of each COFF machine.
// A section-relative fixup here would name a different base, so anything else is
// refused rather than added to a section base.
func msvcImageReloc(machine, typ uint16) bool {
	mi, ok := msvcMachineFor(machine)
	return ok && typ == mi.reloc
}

func msvcRefReason(_ msvcRefStatus, object bool) string {
	// In an object every unresolved image-relative field is an image-base
	// failure; in a linked image the RVA itself is the descriptor's error.
	if object {
		return msvcReasonImage
	}
	return msvcReasonCol
}

// msvcChdReason names the reason for a refused class-hierarchy descriptor. Only
// an unresolved field is an image-base failure; a header, count or base array
// that does not fit is the descriptor's own shape, in an object too.
func msvcChdReason(st msvcRefStatus, object bool) string {
	if st == msvcRefOK {
		return msvcReasonCol
	}
	return msvcRefReason(st, object)
}

// chdValid accepts a hierarchy descriptor whose header and base array are
// readable. A base descriptor points at its own hierarchy, so this is a shape
// check, not an identity check against the derived class. The returned status is
// the base-array reference, so a caller can tell an unresolved image base
// (msvcReasonImage in an object) from a descriptor of the wrong shape
// (msvcReasonCol).
func (m *msvcImage) chdValid(pos msvcPos) (msvcRefStatus, bool) {
	b, ok := m.bytes(pos.sec, pos.off, msvcChdSize)
	if !ok {
		return msvcRefOK, false
	}
	if sig := binary.LittleEndian.Uint32(b); sig > 1 {
		return msvcRefOK, false
	}
	if n := binary.LittleEndian.Uint32(b[8:]); n < 1 || n > msvcBaseCap {
		return msvcRefOK, false
	}
	_, st := m.ref(pos.sec, pos.off+12)
	return st, st == msvcRefOK
}

func msvcRefDetail(st msvcRefStatus) string {
	switch st {
	case msvcRefNoFixup:
		return "field has no image-relative relocation"
	case msvcRefBadSymbol:
		return "relocation names no usable section"
	}
	return "field does not map into the image"
}

// parseCol validates one complete object locator end to end and returns the
// class it describes, or the reason it was refused.
func (m *msvcImage) parseCol(col msvcPos) (*msvcClass, string, string) {
	where := fmt.Sprintf("%s+%#x", col.sec.name, col.off)
	b, ok := m.bytes(col.sec, col.off, msvcColSize)
	if !ok {
		return nil, msvcReasonCol, where + ": locator cut"
	}
	if sig := binary.LittleEndian.Uint32(b); sig > 1 {
		return nil, msvcReasonCol, fmt.Sprintf("%s: locator signature %d, want 0 or 1", where, sig)
	}
	offset := binary.LittleEndian.Uint32(b[4:])
	td, st := m.ref(col.sec, col.off+12)
	if st != msvcRefOK {
		return nil, msvcRefReason(st, m.obj),
			where + ": type descriptor " + msvcRefDetail(st)
	}
	chd, st := m.ref(col.sec, col.off+16)
	if st != msvcRefOK {
		return nil, msvcRefReason(st, m.obj),
			where + ": class hierarchy " + msvcRefDetail(st)
	}
	// The CFG self pointer is not needed to name the class, but when it does
	// resolve it must point back at this locator.
	if self, st := m.ref(col.sec, col.off+20); st == msvcRefOK && self != col {
		return nil, msvcReasonCol, where + ": self pointer does not point back at the locator"
	}

	cb, ok := m.bytes(chd.sec, chd.off, msvcChdSize)
	if !ok {
		return nil, msvcReasonCol, fmt.Sprintf("%s+%#x: class hierarchy cut", chd.sec.name, chd.off)
	}
	if sig := binary.LittleEndian.Uint32(cb); sig > 1 {
		return nil, msvcReasonCol, fmt.Sprintf("%s+%#x: hierarchy signature %d, want 0 or 1",
			chd.sec.name, chd.off, sig)
	}
	num := binary.LittleEndian.Uint32(cb[8:])
	if num < 1 || num > msvcBaseCap {
		return nil, msvcReasonCol, fmt.Sprintf("%s+%#x: %d base classes, want 1..%d",
			chd.sec.name, chd.off, num, msvcBaseCap)
	}
	arr, st := m.ref(chd.sec, chd.off+12)
	if st != msvcRefOK {
		return nil, msvcRefReason(st, m.obj),
			where + ": base class array " + msvcRefDetail(st)
	}

	name, ok := m.typeName(td)
	if !ok {
		return nil, msvcReasonName, fmt.Sprintf("%s: type descriptor at %s+%#x carries no readable name",
			where, td.sec.name, td.off)
	}

	bases := make([]string, 0, num)
	for i := range num {
		bcd, st := m.ref(arr.sec, arr.off+4*i)
		if st != msvcRefOK {
			return nil, msvcRefReason(st, m.obj),
				fmt.Sprintf("%s: base descriptor %d %s", where, i, msvcRefDetail(st))
		}
		if _, ok := m.bytes(bcd.sec, bcd.off, msvcBcdSize); !ok {
			return nil, msvcReasonCol,
				fmt.Sprintf("%s+%#x: base descriptor %d cut", bcd.sec.name, bcd.off, i)
		}
		bt, st := m.ref(bcd.sec, bcd.off)
		if st != msvcRefOK {
			return nil, msvcRefReason(st, m.obj),
				fmt.Sprintf("%s+%#x: base %d type descriptor %s",
					bcd.sec.name, bcd.off, i, msvcRefDetail(st))
		}
		bname, ok := m.typeName(bt)
		if !ok {
			return nil, msvcReasonName,
				fmt.Sprintf("%s+%#x: base %d type descriptor has no readable name",
					bcd.sec.name, bcd.off, i)
		}
		bchd, st := m.ref(bcd.sec, bcd.off+24)
		// A base descriptor names its own class hierarchy, not the derived one:
		// a virtual base carries a hierarchy of its own. Requiring equality would
		// refuse the only shape the ABI emits for virtual inheritance.
		if st != msvcRefOK {
			return nil, msvcRefReason(st, m.obj),
				fmt.Sprintf("%s+%#x: base %d names no class hierarchy: %s",
					bcd.sec.name, bcd.off, i, msvcRefDetail(st))
		}
		if chdSt, ok := m.chdValid(bchd); !ok {
			// Only an unresolved base array is an image-base failure; a header or
			// count that does not fit is the descriptor's own shape.
			detail := ""
			if chdSt != msvcRefOK {
				detail = ": base array " + msvcRefDetail(chdSt)
			}
			return nil, msvcChdReason(chdSt, m.obj),
				fmt.Sprintf("%s+%#x: base %d names no valid class hierarchy%s",
					bcd.sec.name, bcd.off, i, detail)
		}
		bases = append(bases, bname)
	}
	return &msvcClass{name: name, bases: bases, offsets: []uint32{offset}}, "", ""
}

// typeName reads the NUL-terminated name that follows the pointer-sized
// TypeDescriptor header: 16 bytes on x64, 8 on x86.
func (m *msvcImage) typeName(td msvcPos) (string, bool) {
	hdr := uint32(8)
	if m.ptr == 8 {
		hdr = 16
	}
	if uint64(td.off)+uint64(hdr) >= uint64(len(td.sec.data)) {
		return "", false
	}
	b := td.sec.data[td.off+hdr:]
	if len(b) > msvcNameCap {
		b = b[:msvcNameCap] // no terminator within the cap is not a name
	}
	end := -1
	for i, c := range b {
		if c == 0 {
			end = i
			break
		}
	}
	if end < 0 {
		return "", false // no terminator within the cap is not a name
	}
	return msvcName(b[:end])
}

// msvcName accepts only the type-info spelling. ".?AVLeaf@@" is reported as
// "Leaf"; a nested @ or a template ? is kept whole because stripping it would
// invent a name the descriptor does not carry.
func msvcName(raw []byte) (string, bool) {
	if len(raw) < 4 || string(raw[:3]) != ".?A" {
		return "", false
	}
	for _, c := range raw {
		if c < 0x21 || c > 0x7e {
			return "", false
		}
	}
	s := string(raw)
	if len(s) > 6 && strings.HasSuffix(s, "@@") {
		inner := s[4 : len(s)-2]
		if inner != "" && !strings.ContainsAny(inner, "@?") {
			return inner, true
		}
	}
	return s, true
}

func msvcAppendUnique(list []uint32, v uint32) []uint32 {
	if slices.Contains(list, v) {
		return list
	}
	return append(list, v)
}

// msvcClassLine is one note: class count, then name, base count, base names in
// descriptor order and every vftable offset that shares the class locator.
func msvcClassLine(classes []*msvcClass) string {
	var b strings.Builder
	fmt.Fprintf(&b, "msvc-class %d", len(classes))
	for _, c := range classes {
		fmt.Fprintf(&b, " (%s %d [%s] @", c.name, len(c.bases), strings.Join(c.bases, " "))
		for i, off := range c.offsets {
			if i > 0 {
				b.WriteByte(',')
			}
			fmt.Fprintf(&b, "%#x", off)
		}
		b.WriteByte(')')
	}
	return b.String()
}
