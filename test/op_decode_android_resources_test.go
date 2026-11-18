package main

import (
	"encoding/binary"
	"testing"
)

// sfArscCompact builds a resources.arsc whose single type chunk holds one
// regular entry and one compact entry. A compact entry (FLAG_COMPACT) keeps
// its key index in the first 16 bits and carries the value data in the u32,
// so a parser that reads the u32 as the key index loses the name.
func sfArscCompact() []byte {
	types := axmlPool([]string{"string"}, true)
	keys := axmlPool([]string{"app_name", "other_name"}, true)

	const pkgHdr = 288
	pkg := make([]byte, pkgHdr)
	binary.LittleEndian.PutUint16(pkg[0:], 0x0200)
	binary.LittleEndian.PutUint16(pkg[2:], pkgHdr)
	binary.LittleEndian.PutUint32(pkg[8:], 0x7f)
	for i, r := range "com.sim.res" {
		binary.LittleEndian.PutUint16(pkg[12+2*i:], uint16(r))
	}
	binary.LittleEndian.PutUint32(pkg[268:], pkgHdr)
	binary.LittleEndian.PutUint32(pkg[276:], uint32(pkgHdr+len(types)))
	pkg = append(pkg, types...)
	pkg = append(pkg, keys...)

	spec := make([]byte, 16)
	binary.LittleEndian.PutUint16(spec[0:], 0x0202)
	binary.LittleEndian.PutUint16(spec[2:], 16)
	binary.LittleEndian.PutUint32(spec[4:], 16)
	spec[8] = 1
	binary.LittleEndian.PutUint16(spec[14:], 2)
	pkg = append(pkg, spec...)

	const typeHdr = 20
	const entriesStart = typeHdr + 8
	tc := make([]byte, entriesStart+16)
	binary.LittleEndian.PutUint16(tc[0:], 0x0201)
	binary.LittleEndian.PutUint16(tc[2:], typeHdr)
	binary.LittleEndian.PutUint32(tc[4:], uint32(len(tc)))
	tc[8] = 1 // type id → types[0]
	binary.LittleEndian.PutUint32(tc[12:], 2)
	binary.LittleEndian.PutUint32(tc[16:], entriesStart)
	// Legacy u32 offset table: entry 0 at +0, entry 1 at +8.
	binary.LittleEndian.PutUint32(tc[typeHdr:], 0)
	binary.LittleEndian.PutUint32(tc[typeHdr+4:], 8)
	// Entry 0: full layout, size 8, flags 0, key index 0.
	binary.LittleEndian.PutUint16(tc[entriesStart:], 8)
	binary.LittleEndian.PutUint32(tc[entriesStart+4:], 0)
	// Entry 1: compact layout, 16-bit key index 1, value data 0x7f020001.
	binary.LittleEndian.PutUint16(tc[entriesStart+8:], 1)
	binary.LittleEndian.PutUint16(tc[entriesStart+10:], 0x0008)
	binary.LittleEndian.PutUint32(tc[entriesStart+12:], 0x7f020001)
	pkg = append(pkg, tc...)
	binary.LittleEndian.PutUint32(pkg[4:], uint32(len(pkg)))

	tbl := make([]byte, 12)
	binary.LittleEndian.PutUint16(tbl[0:], 0x0002)
	binary.LittleEndian.PutUint16(tbl[2:], 12)
	binary.LittleEndian.PutUint32(tbl[8:], 1)
	tbl = append(tbl, pkg...)
	binary.LittleEndian.PutUint32(tbl[4:], uint32(len(tbl)))
	return tbl
}

// TestDecodeAndroidResourcesCompactEntry: a compact entry's key index lives in
// the first 16 bits; the u32 behind it is the value data.
func TestDecodeAndroidResourcesCompactEntry(t *testing.T) {
	p := writeZip(t, "app.apk", []zipEntry{{"resources.arsc", sfArscCompact()}})
	m := opStatic(t, "decode_android_resources", p)

	pkgs, ok := m["packages"].([]any)
	if !ok || len(pkgs) != 1 {
		t.Fatalf("packages = %v, want 1", m["packages"])
	}
	pkg := pkgs[0].(map[string]any)
	if got := opStaticNum(t, pkg, "entries"); got != 2 {
		t.Fatalf("entries = %d, want 2", got)
	}
	names, ok := pkg["names"].([]any)
	if !ok || len(names) != 2 {
		t.Fatalf("names = %v, want 2 entries", pkg["names"])
	}
	want := []string{"string/app_name", "string/other_name"}
	for i, w := range want {
		if names[i] != w {
			t.Fatalf("names[%d] = %v, want %q", i, names[i], w)
		}
	}
}
