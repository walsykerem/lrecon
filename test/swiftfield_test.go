package main

import (
	"encoding/binary"
	"strings"
	"testing"
)

// synthetic Swift field image: __swift5_reflstr, __swift5_types, one nominal
// type descriptor, one field descriptor (3 struct fields) and the static
// metadata record that carries the offsets. Laid out exactly as swiftc 6.2.4
// emits them for `struct Pt { var x: Int64; var y: Int32; var z: String }`,
// minus the typeref control data this reader does not need.
func swiftFieldTestImage() swiftFieldImage {
	const (
		reflstrVA = 0x4000
		typesVA   = 0x4100
		descVA    = 0x4200
		fieldsVA  = 0x4300
		metaVA    = 0x4400
		moduleVA  = 0x4500
		strVA     = 0x4600
	)
	put := func(b []byte, off int, v uint32) {
		binary.LittleEndian.PutUint32(b[off:], v)
	}
	rel := func(at, target uint64) uint32 { return uint32(int32(int64(target) - int64(at))) }

	types := make([]byte, 4)
	put(types, 0, rel(typesVA, descVA))

	desc := make([]byte, 32)
	put(desc, 0, 0x51) // struct, nominal
	put(desc, 4, rel(descVA+4, moduleVA))
	put(desc, 8, rel(descVA+8, strVA)) // "Pt"
	put(desc, 16, rel(descVA+16, fieldsVA))
	put(desc, 20, 3) // NumFields
	put(desc, 24, 2) // FieldOffsetVectorOffset, in words

	module := make([]byte, 16)
	put(module, 8, rel(moduleVA+8, strVA+3)) // "mod"

	fields := make([]byte, 16+3*12)
	fields[8] = 0 // Kind: Struct
	binary.LittleEndian.PutUint16(fields[10:], 12)
	put(fields, 12, 3)
	names := []string{"x", "y", "z"}
	for i := range names {
		rec := 16 + i*12
		put(fields, rec+8, rel(fieldsVA+uint64(rec+8), reflstrVA+uint64(i*2)))
	}

	meta := make([]byte, 8+8+12)
	put(meta, 0, 0x200) // MetadataKind::Struct
	binary.LittleEndian.PutUint64(meta[8:], descVA)
	put(meta, 16, 0)
	put(meta, 20, 8)
	put(meta, 24, 12)

	return swiftFieldImage{sections: []swiftSec{
		{name: "__swift5_reflstr", addr: reflstrVA, data: []byte("x\x00y\x00z\x00")},
		{name: "__swift5_types", addr: typesVA, data: types},
		{name: "__DATA,__const", addr: descVA, data: desc},
		{name: "__DATA,__const2", addr: moduleVA, data: module},
		{name: "__swift5_fieldmd", addr: fieldsVA, data: fields},
		{name: "__DATA,__data", addr: metaVA, data: meta},
		{name: "__TEXT,__cstring", addr: strVA, data: []byte("Pt\x00mod\x00")},
	}}
}

func TestSwiftFieldLayout(t *testing.T) {
	var d Digest
	swiftFieldReport([]swiftFieldImage{swiftFieldTestImage()}, &d)

	want := "deep: swift-fields 3 @0, @8, @12 mod.Pt (x, y, z)"
	if len(d.Notes) != 1 || d.Notes[0] != want {
		t.Fatalf("notes = %q, want exactly %q", d.Notes, want)
	}
	if d.Skipped != nil {
		t.Fatalf("skipped = %+v, want none", d.Skipped)
	}
	if d.Coverage == nil || d.Coverage.Parsed != 1 {
		t.Fatalf("coverage = %+v, want 1 parsed", d.Coverage)
	}
}

// A field name one byte outside __swift5_reflstr is refused by name; nothing is
// printed for the descriptor.
func TestSwiftFieldNameOutsideReflstr(t *testing.T) {
	img := swiftFieldTestImage()
	for i := range img.sections {
		if img.sections[i].name == "__swift5_reflstr" {
			img.sections[i].addr -= 0x10 // names now point behind the section
		}
	}
	var d Digest
	swiftFieldReport([]swiftFieldImage{img}, &d)
	if len(d.Notes) != 0 {
		t.Fatalf("notes = %q, want none", d.Notes)
	}
	if !hasSkip(d.Skipped, swiftFieldNameOutsideReflstr) {
		t.Fatalf("skipped = %+v, want %s", d.Skipped, swiftFieldNameOutsideReflstr)
	}
}

// Without __swift5_fieldmd the reader must say so, not stay silent.
func TestSwiftFieldAbsent(t *testing.T) {
	img := swiftFieldTestImage()
	keep := img.sections[:0]
	for _, s := range img.sections {
		if s.name != "__swift5_fieldmd" {
			keep = append(keep, s)
		}
	}
	img.sections = keep
	var d Digest
	swiftFieldReport([]swiftFieldImage{img}, &d)
	if len(d.Notes) != 0 || !hasSkip(d.Skipped, swiftFieldAbsent) {
		t.Fatalf("notes = %q skipped = %+v, want only %s", d.Notes, d.Skipped, swiftFieldAbsent)
	}
}

// Chained-fixup words store an image-relative target with a high8 byte; a
// plain pointer must also decode, because ELF and x86_64 Mach-O use those.
func TestSwiftFieldChainedTarget(t *testing.T) {
	const base, desc = 0x100000000, 0x4200
	if got := swiftFieldTargets(base+desc, base); len(got) == 0 || got[0] != base+desc {
		t.Fatalf("plain targets = %v", got)
	}
	// DYLD_CHAINED_PTR_64 rebase: target 0x4200, high8 0
	if got := swiftFieldTargets(0x4200, base); len(got) != 2 || got[1] != base+0x4200 {
		t.Fatalf("chained targets = %v", got)
	}
	// Bits 36..43 are high8, OR'd into the top byte of the target VA.
	if got := swiftFieldTargets(uint64(2)<<36|0x4200, base); len(got) != 2 || got[1] != base+0x4200+(uint64(2)<<56) {
		t.Fatalf("high8 targets = %v", got)
	}
}

func hasSkip(skips []Skip, reason string) bool {
	for _, s := range skips {
		if s.Reason == reason && strings.TrimSpace(s.Detail) != "" {
			return true
		}
	}
	return false
}
