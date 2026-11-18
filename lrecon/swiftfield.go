package main

import (
	"bytes"
	"debug/elf"
	"debug/macho"
	"encoding/binary"
	"fmt"
	"os"
	"strings"
)

// Swift field metadata: __swift5_fieldmd names the fields of every nominal type
// and __swift5_reflstr holds their names. Neither section carries a byte offset
// (verified: swiftc 6.2.4, arm64; see swift.go's header). The offsets live only
// in the type's static metadata record, so this reader pairs the field
// descriptor with its __swift5_types descriptor and then with the metadata
// record that points back at that descriptor. A layout it cannot prove from
// those three links is refused by name, never guessed from type names.
const (
	swiftFieldAbsent               = "swiftfield-absent"
	swiftFieldDescriptorUnreadable = "swiftfield-descriptor-unreadable"
	swiftFieldTyperefOutsideTypes  = "swiftfield-typeref-outside-types"
	swiftFieldReflstrMissing       = "swiftfield-reflstr-missing"
	swiftFieldNameOutsideReflstr   = "swiftfield-name-outside-reflstr"
	swiftFieldLayoutUnknown        = "swiftfield-layout-unknown"
)

func init() {
	register(reader{
		format: "swiftfield",
		post:   true,
		reasons: []string{
			swiftFieldAbsent, swiftFieldDescriptorUnreadable,
			swiftFieldTyperefOutsideTypes, swiftFieldReflstrMissing,
			swiftFieldNameOutsideReflstr, swiftFieldLayoutUnknown,
		},
		match: func(head []byte, size int64) bool {
			return fatMachOOK(head, size) || isMachO(head) ||
				bytes.HasPrefix(head, []byte("\x7fELF"))
		},
		inspect: inspectSwiftField,
	})
}

// The set is registered separately because the field name (`swiftfield`) and
// the reader name must stay one vocabulary, as java.go does.
func init() {
	reasonRegistry["swiftfield"] = reasonSet(
		swiftFieldAbsent, swiftFieldDescriptorUnreadable,
		swiftFieldTyperefOutsideTypes, swiftFieldReflstrMissing,
		swiftFieldNameOutsideReflstr, swiftFieldLayoutUnknown,
	)
}

// swiftFieldImage is one thin image with EVERY readable section, not only the
// __swift5_* ones: the field offsets sit in the type metadata record, which
// lives in __DATA/__const and never in a section named __swift5_*.
type swiftFieldImage struct {
	base     uint64 // lowest loaded VA; chained-fixup targets are relative to it
	sections []swiftSec
	segs     []swiftSeg
}

// swiftFieldObject is one field descriptor (TargetFieldDescriptor) resolved far
// enough to print. It is not printed unless every field has a name and the
// metadata supplied exactly NumFields offsets.
type swiftFieldObject struct {
	typ     string
	names   []string
	offsets []uint32
}

func inspectSwiftField(path string, d *Digest) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	var imgs []swiftFieldImage
	switch d.Kind {
	case "macho":
		if ff, err := macho.NewFatFile(f); err == nil {
			defer ff.Close()
			for _, a := range ff.Arches {
				imgs = append(imgs, machoSwiftFieldImage(a.File))
			}
		} else if mf, err := macho.NewFile(f); err == nil {
			imgs = append(imgs, machoSwiftFieldImage(mf))
		}
	case "elf":
		if ef, err := elf.NewFile(f); err == nil {
			imgs = append(imgs, elfSwiftFieldImage(ef))
		}
	}
	swiftFieldReport(imgs, d)
}

func machoSwiftFieldImage(f *macho.File) swiftFieldImage {
	img := swiftFieldImage{}
	for _, l := range f.Loads {
		seg, ok := l.(*macho.Segment)
		if !ok {
			continue
		}
		img.segs = append(img.segs, swiftSeg{seg.Addr, seg.Filesz})
		if seg.Offset == 0 || img.base == 0 {
			if img.base == 0 || seg.Addr < img.base {
				img.base = seg.Addr
			}
		}
	}
	for _, s := range f.Sections {
		if b, err := s.Data(); err == nil {
			img.sections = append(img.sections, swiftSec{s.Name, s.Addr, b})
		}
	}
	return img
}

func elfSwiftFieldImage(f *elf.File) swiftFieldImage {
	img := swiftFieldImage{}
	for _, p := range f.Progs {
		if p.Type != elf.PT_LOAD {
			continue
		}
		img.segs = append(img.segs, swiftSeg{p.Vaddr, p.Filesz})
		if img.base == 0 || p.Vaddr < img.base {
			img.base = p.Vaddr
		}
	}
	// ELF section data needs no image base: pointers are plain virtual
	// addresses, so keep base at 0 unless a segment supplied one, and let the
	// plain-pointer path in swiftFieldTargets handle it.
	for _, s := range f.Sections {
		if b, err := s.Data(); err == nil {
			img.sections = append(img.sections, swiftSec{s.Name, s.Addr, b})
		}
	}
	return img
}

// at reads n bytes at VA, but only from the one section that fully contains the
// range: a read that would cross a section boundary is refused, not stitched.
func (img swiftFieldImage) at(va uint64, n int) []byte {
	if n <= 0 {
		return nil
	}
	for _, s := range img.sections {
		if va < s.addr || va+uint64(n) > s.addr+uint64(len(s.data)) {
			continue
		}
		i := int(va - s.addr)
		return s.data[i : i+n]
	}
	return nil
}

func (img swiftFieldImage) section(name string) (swiftSec, bool) {
	for _, s := range img.sections {
		if canon, ok := swiftSectionName(s.name); ok && canon == name {
			return s, true
		}
	}
	return swiftSec{}, false
}

func swiftFieldReport(imgs []swiftFieldImage, d *Digest) {
	for _, img := range imgs {
		fieldmd, ok := img.section("fieldmd")
		if !ok {
			// Only a file that already has another __swift5_* section is a
			// Swift binary missing fieldmd; a plain Mach-O is not claimed.
			swift := 0
			for _, s := range img.sections {
				if _, ok := swiftSectionName(s.name); ok {
					swift++
				}
			}
			if swift > 0 {
				d.skip(swiftFieldAbsent, "swift sections present without __swift5_fieldmd")
			}
			continue
		}
		reflstr, ok := img.section("reflstr")
		if !ok {
			d.skip(swiftFieldReflstrMissing, fmt.Sprintf("%s: __swift5_fieldmd present without __swift5_reflstr", img.archName()))
			continue
		}
		types, haveTypes := img.section("types")
		d.scanned(int64(len(fieldmd.data)))
		for _, obj := range swiftFieldObjects(img, fieldmd, reflstr, types, haveTypes, d) {
			if len(obj.offsets) != len(obj.names) {
				continue
			}
			var at []string
			for _, off := range obj.offsets {
				at = append(at, fmt.Sprintf("@%d", off))
			}
			deepNote(d, fmt.Sprintf("swift-fields %d %s %s (%s)",
				len(obj.names), strings.Join(at, ", "), obj.typ, strings.Join(obj.names, ", ")))
			d.parsed()
		}
	}
}

func (img swiftFieldImage) archName() string {
	if len(img.segs) == 0 {
		return "image"
	}
	return fmt.Sprintf("image@%#x", img.base)
}

// swiftFieldObjects walks __swift5_fieldmd. TargetFieldDescriptor is 16 bytes,
// followed by NumFields records of FieldRecordSize bytes; a body cut mid-record
// or a record smaller than TargetFieldRecord is refused, not reinterpreted.
func swiftFieldObjects(img swiftFieldImage, fieldmd, reflstr, types swiftSec, haveTypes bool, d *Digest) []swiftFieldObject {
	const hdr = 16
	const recMin = 12
	var out []swiftFieldObject
	unreadable := false

	for off := 0; off+hdr <= len(fieldmd.data); {
		h := fieldmd.data[off : off+hdr]
		if allZero(h) {
			break
		}
		kind := binary.LittleEndian.Uint16(h[8:])
		recSize := int(binary.LittleEndian.Uint16(h[10:]))
		n := int(binary.LittleEndian.Uint32(h[12:]))
		if recSize < recMin || n < 0 || n > 1<<20 {
			unreadable = true
			break
		}
		end := off + hdr + n*recSize
		if end > len(fieldmd.data) {
			unreadable = true
			break
		}
		descVA := fieldmd.addr + uint64(off)

		names, ok := swiftFieldNames(fieldmd, reflstr, off, n, recSize, d)
		if !ok {
			off = end
			continue
		}
		swiftFieldCheckTyperefs(img, fieldmd, types, haveTypes, off, n, recSize, d)

		// Only a struct carries the field offset vector at a fixed place in
		// its metadata; class and enum layouts are elsewhere and are refused
		// by name below.
		if kind == 0 {
			if nominal, ok := swiftFieldNominal(img, types, haveTypes, descVA); ok {
				if metaVA, ok := swiftFieldMetadata(img, nominal, uint32(n)); ok {
					fov := binary.LittleEndian.Uint32(mustAt(img, nominal+24, 4))
					if offs, ok := swiftFieldOffsets(img, metaVA, fov, n); ok {
						out = append(out, swiftFieldObject{
							typ:     swiftFieldTypeName(img, nominal),
							names:   names,
							offsets: offs,
						})
						off = end
						continue
					}
				}
			}
		}
		d.skip(swiftFieldLayoutUnknown, fmt.Sprintf(
			"%s: %d field(s) at %#x: no metadata field offset vector", img.archName(), n, descVA))
		d.unparsed()
		off = end
	}
	if unreadable {
		d.skip(swiftFieldDescriptorUnreadable, fmt.Sprintf("%s: __swift5_fieldmd is not a sequence of 16-byte descriptors", img.archName()))
		d.unparsed()
	}
	return out
}

// swiftFieldNames resolves every FieldRecord's FieldName relative pointer into
// __swift5_reflstr. The base is the address of the 4-byte offset itself, so a
// name one byte outside the section is a refusal, not a best-effort read.
func swiftFieldNames(fieldmd, reflstr swiftSec, off, n, recSize int, d *Digest) ([]string, bool) {
	names := make([]string, 0, n)
	for i := range n {
		recVA := fieldmd.addr + uint64(off+16+i*recSize)
		relAt := recVA + 8
		rel := int32(binary.LittleEndian.Uint32(fieldmd.data[off+16+i*recSize+8:]))
		target := relAt + uint64(int64(rel))
		name, ok := cStringAt(reflstr, target)
		if !ok {
			d.skip(swiftFieldNameOutsideReflstr, fmt.Sprintf(
				"%s: field name %#x outside __swift5_reflstr", fieldmdTag(fieldmd), target))
			return nil, false
		}
		names = append(names, name)
	}
	return names, true
}

func fieldmdTag(s swiftSec) string { return fmt.Sprintf("fieldmd@%#x", s.addr) }

func cStringAt(s swiftSec, va uint64) (string, bool) {
	if va < s.addr || va >= s.addr+uint64(len(s.data)) {
		return "", false
	}
	body := s.data[va-s.addr:]
	if i := bytes.IndexByte(body, 0); i >= 0 {
		body = body[:i]
	}
	if len(body) == 0 || len(body) > 4096 {
		return "", false
	}
	for _, c := range body {
		if c < 0x20 || c > 0x7e {
			return "", false
		}
	}
	return string(body), true
}

// swiftFieldCheckTyperefs follows each record's MangledTypeName control data
// only far enough to prove a DIRECT (kind 0x01) symbolic reference lands in
// __swift5_types, as MetadataValues.h/Mangling.rst require. Literal mangled
// fragments and indirect references are left alone: the layout does not use
// them, so they are never guessed at.
func swiftFieldCheckTyperefs(img swiftFieldImage, fieldmd, types swiftSec, haveTypes bool, off, n, recSize int, d *Digest) {
	for i := range n {
		recOff := off + 16 + i*recSize
		rel := int32(binary.LittleEndian.Uint32(fieldmd.data[recOff+4:]))
		target := fieldmd.addr + uint64(recOff+4) + uint64(int64(rel))
		kind := img.at(target, 1)
		if len(kind) != 1 || kind[0] < 0x01 || kind[0] > 0x17 {
			continue // literal mangled text inside the control data, or unreadable
		}
		delta := img.at(target+1, 4)
		if len(delta) != 4 {
			continue
		}
		dest := target + 1 + uint64(int64(int32(binary.LittleEndian.Uint32(delta))))
		if kind[0] != 0x01 {
			continue
		}
		if !haveTypes || dest < types.addr || dest >= types.addr+uint64(len(types.data)) {
			d.skip(swiftFieldTyperefOutsideTypes, fmt.Sprintf(
				"%s: direct type reference %#x outside __swift5_types", fieldmdTag(fieldmd), dest))
		}
	}
}

// swiftFieldNominal finds the __swift5_types descriptor whose Fields relative
// pointer (offset 16) names this field descriptor. That is the only proven link
// between the two sections; matching by name would be a guess.
func swiftFieldNominal(img swiftFieldImage, types swiftSec, haveTypes bool, fieldsVA uint64) (uint64, bool) {
	if !haveTypes {
		return 0, false
	}
	targets, _, ok := swiftTargets(types.data, types.addr, 3)
	if !ok {
		return 0, false
	}
	for _, desc := range targets {
		b := img.at(desc+16, 4)
		if len(b) != 4 {
			continue
		}
		rel := int32(binary.LittleEndian.Uint32(b))
		if desc+16+uint64(int64(rel)) == fieldsVA {
			return desc, true
		}
	}
	return 0, false
}

// swiftFieldMetadata scans loaded sections for the metadata record that points
// back at descVA. A non-generic struct's record is [kind][descriptor
// pointer][field offset vector], kind 0x200 (MetadataKind::Struct in
// MetadataValues.h; docs/ABI/TypeMetadata.rst prints the simplified 1). The
// descriptor pointer may be a plain VA or a dyld chained fixup, so both forms
// are tried and the entry is accepted only if the offset vector is plausible.
func swiftFieldMetadata(img swiftFieldImage, descVA uint64, want uint32) (uint64, bool) {
	for _, s := range img.sections {
		if _, ok := swiftSectionName(s.name); ok {
			continue // metadata never lives in a __swift5_* section
		}
		for i := 0; i+16 <= len(s.data); i += 8 {
			word := binary.LittleEndian.Uint64(s.data[i:])
			va := s.addr + uint64(i)
			for _, cand := range swiftFieldTargets(word, img.base) {
				if cand != descVA {
					continue
				}
				metaVA := va - 8
				kind := img.at(metaVA, 4)
				if len(kind) != 4 || binary.LittleEndian.Uint32(kind) != 0x200 {
					continue
				}
				num := binary.LittleEndian.Uint32(mustAt(img, descVA+20, 4))
				fov := binary.LittleEndian.Uint32(mustAt(img, descVA+24, 4))
				if num != want || fov == 0 || fov > 1<<12 {
					continue
				}
				return metaVA, true
			}
		}
	}
	return 0, false
}

// swiftFieldTargets returns the VAs a metadata word can denote: a plain pointer
// (ELF and x86_64 Mach-O) and the dyld chained-fixup rebase form used by arm64
// Mach-O, where the stored word is image-relative with a high8 byte.
func swiftFieldTargets(word, base uint64) []uint64 {
	if word == 0 {
		return nil
	}
	out := []uint64{word}
	if base != 0 {
		target := word & 0xfffffffff
		high := (word >> 36) & 0xff
		out = append(out, base+target+high<<56)
	}
	return out
}

// swiftFieldOffsets reads the field offset vector: FieldOffsetVectorOffset is
// in pointer-sized words from the metadata record. Offsets are 32-bit
// (swiftc emits u32 words, not pointer-sized) and must not decrease; anything
// else means the record found is not this type's and is refused upstream.
func swiftFieldOffsets(img swiftFieldImage, metaVA uint64, fov uint32, n int) ([]uint32, bool) {
	at := metaVA + uint64(fov)*8
	offs := make([]uint32, n)
	var prev uint32
	for i := range n {
		b := img.at(at+uint64(4*i), 4)
		if len(b) != 4 {
			return nil, false
		}
		v := binary.LittleEndian.Uint32(b)
		if v >= 1<<24 || (i > 0 && v < prev) {
			return nil, false
		}
		prev = v
		offs[i] = v
	}
	return offs, true
}

// swiftFieldTypeName reads the descriptor's Name, then its parent module name.
// A parent that does not resolve leaves the bare type name; the layout is still
// proven, only the display name is shorter.
func swiftFieldTypeName(img swiftFieldImage, descVA uint64) string {
	name := swiftFieldContextName(img, descVA)
	if name == "" {
		return fmt.Sprintf("type@%#x", descVA)
	}
	if parent := swiftFieldParent(img, descVA); parent != 0 {
		if p := swiftFieldContextName(img, parent); p != "" {
			return p + "." + name
		}
	}
	return name
}

func swiftFieldParent(img swiftFieldImage, descVA uint64) uint64 {
	b := img.at(descVA+4, 4)
	if len(b) != 4 {
		return 0
	}
	rel := int32(binary.LittleEndian.Uint32(b))
	if rel == 0 {
		return 0
	}
	return descVA + 4 + uint64(int64(rel))
}

func swiftFieldContextName(img swiftFieldImage, descVA uint64) string {
	b := img.at(descVA+8, 4)
	if len(b) != 4 {
		return ""
	}
	rel := int32(binary.LittleEndian.Uint32(b))
	if rel == 0 {
		return ""
	}
	target := descVA + 8 + uint64(int64(rel))
	for _, s := range img.sections {
		if target < s.addr || target >= s.addr+uint64(len(s.data)) {
			continue
		}
		name, ok := cStringAt(s, target)
		if ok {
			return name
		}
	}
	return ""
}

func mustAt(img swiftFieldImage, va uint64, n int) []byte {
	if b := img.at(va, n); b != nil {
		return b
	}
	return make([]byte, n)
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}
