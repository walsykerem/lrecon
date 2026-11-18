package main

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// firmwareHits' bool reports a cap hit, not success: extract_firmware read it
// as "found something" and so skipped every image.
func TestExtractFirmwareCarvesParts(t *testing.T) {
	img := make([]byte, 256)
	// "hsqs" is little-endian squashfs, "UBI#" a UBI image; both are carved
	// anywhere in the dump, unlike gzip/xz which only count at offset 0.
	copy(img[32:], []byte("hsqs"))
	copy(img[128:], []byte("UBI#"))

	dir := t.TempDir()
	p := filepath.Join(dir, "flash.bin")
	if err := os.WriteFile(p, img, 0o644); err != nil {
		t.Fatal(err)
	}
	m := opStatic(t, "extract_firmware", p)

	parts, ok := m["parts"].([]any)
	if !ok || len(parts) != 2 {
		t.Fatalf("parts = %v, want 2 carved containers", m["parts"])
	}
	first := parts[0].(map[string]any)
	if got := opStaticNum(t, first, "offset"); got != 32 {
		t.Fatalf("first offset = %d, want 32", got)
	}
	if got := opStaticNum(t, first, "bytes"); got != 128-32 {
		t.Fatalf("first bytes = %d, want %d (up to the next magic)", got, 128-32)
	}
	if got := m["capped"]; got != false {
		t.Fatalf("capped = %v, want false", got)
	}
	// The carved file must exist and hold the bytes between the two magics.
	carved, err := os.ReadFile(filepath.Join(opStaticStr(t, m, "dir"), opStaticStr(t, first, "file")))
	if err != nil {
		t.Fatal(err)
	}
	if len(carved) != 128-32 || string(carved[:4]) != "hsqs" {
		t.Fatalf("carved %d bytes starting %q, want the squashfs magic", len(carved), carved[:4])
	}
}

// sfDartSnapshot builds a minimal snapshot header plus the 32-char version hash
// that follows it; hash may be replaced to test the unreadable branch.
func sfDartSnapshot(hash []byte) []byte {
	payload := make([]byte, 64)
	binary.LittleEndian.PutUint32(payload, dartMagic)
	binary.LittleEndian.PutUint64(payload[4:], uint64(len(payload)-4))
	binary.LittleEndian.PutUint64(payload[12:], 2) // full-aot
	copy(payload[dartHeaderSize:], hash)
	return payload
}

// The hash lives after the 20-byte header; reading it from offset 0 only ever
// saw the magic, so version_hash was always empty.
func TestInspectDartAOTReadsVersionHash(t *testing.T) {
	const hash = "3d4e5f60718293a4b5c6d7e8f90a1b2c"
	p := opStaticFile(t, "snapshot", sfDartSnapshot([]byte(hash)))
	m := opStatic(t, "inspect_dart_aot", p)

	if got := opStaticStr(t, m, "kind"); got != "full-aot" {
		t.Fatalf("kind = %q, want full-aot", got)
	}
	if got := opStaticStr(t, m, "version_hash"); got != hash {
		t.Fatalf("version_hash = %q, want %q", got, hash)
	}
	if got := m["length_consistent"]; got != true {
		t.Fatalf("length_consistent = %v, want true", got)
	}
}

func TestInspectDartAOTUnreadableHashSkips(t *testing.T) {
	p := opStaticFile(t, "snapshot-nohash", sfDartSnapshot(make([]byte, 32)))
	v, err := runOp("inspect_dart_aot", p)
	if err != nil {
		t.Fatalf("inspect_dart_aot: %v", err)
	}
	s, ok := v.(*skip)
	if !ok || s.Reason == "" {
		t.Fatalf("got %#v, want a skip naming the unreadable hash", v)
	}
}

// ---------------------------------------------------------- keyed archive

// sfBP is one bplist object for sfBplist: 's' string, 'd' dict, 'a' array,
// 'u' UID. References are single bytes, so refSize is 1 everywhere.
type sfBP struct {
	kind byte
	str  string
	keys []byte
	vals []byte
	refs []byte
	uid  byte
}

func sfBplist(objs []sfBP) []byte {
	// Offsets and the table index are file-relative, so the 8-byte magic counts.
	body := []byte("bplist00")
	var offs []int
	for _, o := range objs {
		offs = append(offs, len(body))
		switch o.kind {
		case 's':
			// 0xF is the extended-count marker, so a 15+ char string needs it.
			if len(o.str) < 15 {
				body = append(body, 0x50|byte(len(o.str)))
			} else {
				body = append(body, 0x5F, 0x10, byte(len(o.str)))
			}
			body = append(body, o.str...)
		case 'd':
			body = append(body, 0xD0|byte(len(o.keys)))
			body = append(body, o.keys...)
			body = append(body, o.vals...)
		case 'a':
			body = append(body, 0xA0|byte(len(o.refs)))
			body = append(body, o.refs...)
		case 'u':
			body = append(body, 0x80, o.uid)
		}
	}
	offSize := 1
	if len(body) >= 256 {
		offSize = 2
	}
	table := len(body)
	for _, off := range offs {
		if offSize == 1 {
			body = append(body, byte(off))
			continue
		}
		body = append(body, byte(off>>8), byte(off))
	}
	tr := make([]byte, 32)
	tr[6], tr[7] = byte(offSize), 1
	binary.BigEndian.PutUint64(tr[8:], uint64(len(objs)))
	binary.BigEndian.PutUint64(tr[16:], 0) // top object
	binary.BigEndian.PutUint64(tr[24:], uint64(table))
	return append(body, tr...)
}

func TestInspectKeyedArchiveNamesClasses(t *testing.T) {
	p := opStaticFile(t, "keyed", sfBplist([]sfBP{
		{kind: 'd', keys: []byte{1, 2}, vals: []byte{3, 4}}, // $top
		{kind: 's', str: "$archiver"},                       //
		{kind: 's', str: "$objects"},                        //
		{kind: 's', str: "NSKeyedArchiver"},                 //
		{kind: 'a', refs: []byte{5}},                        // one archived instance
		{kind: 'd', keys: []byte{7}, vals: []byte{6}},       // {"$class": 6}
		{kind: 'd', keys: []byte{9}, vals: []byte{8}},       // {"$classname": "NSString"}
		{kind: 's', str: "$class"},                          //
		{kind: 's', str: "NSString"},                        //
		{kind: 's', str: "$classname"},                      //
	}))
	m := opStatic(t, "inspect_keyed_archive", p)

	if got := opStaticStr(t, m, "archiver"); got != "NSKeyedArchiver" {
		t.Fatalf("archiver = %q", got)
	}
	if got := opStaticNum(t, m, "objects"); got != 1 {
		t.Fatalf("objects = %d, want 1", got)
	}
	if got := opStaticNum(t, m, "classes"); got != 1 {
		t.Fatalf("classes = %d, want 1", got)
	}
	names, _ := m["class_names"].([]any)
	if len(names) != 1 || names[0] != "NSString" {
		t.Fatalf("class_names = %v", m["class_names"])
	}
	tops, _ := m["top_keys"].([]any)
	if len(tops) != 2 || tops[0] != "$archiver" || tops[1] != "$objects" {
		t.Fatalf("top_keys = %v", m["top_keys"])
	}
}

// ------------------------------------------------------ android resources

// sfArsc builds a one-package resources.arsc: package com.sim.res with type
// "string" and one entry keyed "app_name".
func sfArsc() []byte {
	types := axmlPool([]string{"string"}, true)
	keys := axmlPool([]string{"app_name"}, true)

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

	// A 0x0202 type-spec chunk names the type; 0x0201 alone carries entries.
	spec := make([]byte, 16)
	binary.LittleEndian.PutUint16(spec[0:], 0x0202)
	binary.LittleEndian.PutUint16(spec[2:], 16)
	binary.LittleEndian.PutUint32(spec[4:], 16)
	spec[8] = 1
	binary.LittleEndian.PutUint16(spec[14:], 1)
	pkg = append(pkg, spec...)

	const typeHdr = 24
	tc := make([]byte, typeHdr+4+8)
	binary.LittleEndian.PutUint16(tc[0:], 0x0201)
	binary.LittleEndian.PutUint16(tc[2:], typeHdr)
	binary.LittleEndian.PutUint32(tc[4:], uint32(len(tc)))
	tc[8] = 1 // type id → types[0]
	binary.LittleEndian.PutUint32(tc[12:], 1)
	binary.LittleEndian.PutUint32(tc[16:], typeHdr+4)
	binary.LittleEndian.PutUint32(tc[typeHdr:], 0)     // entry 0 sits at entriesStart
	binary.LittleEndian.PutUint32(tc[typeHdr+4+4:], 0) // key index 0
	pkg = append(pkg, tc...)
	binary.LittleEndian.PutUint32(pkg[4:], uint32(len(pkg)))

	tbl := make([]byte, 12)
	binary.LittleEndian.PutUint16(tbl[0:], 0x0002)
	binary.LittleEndian.PutUint16(tbl[2:], 12)
	binary.LittleEndian.PutUint32(tbl[8:], 1) // one package
	tbl = append(tbl, pkg...)
	binary.LittleEndian.PutUint32(tbl[4:], uint32(len(tbl)))
	return tbl
}

// TestDecodeAndroidResourcesCorruptEntry: a resources.arsc that is present but
// cannot be read is an error, not the "this APK carries no resources.arsc"
// sentence, which is only true when the entry is missing.
func TestDecodeAndroidResourcesCorruptEntry(t *testing.T) {
	p := filepath.Join(t.TempDir(), "broken.apk")
	payload := sfArsc()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.CreateHeader(&zip.FileHeader{Name: "resources.arsc", Method: zip.Store})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	raw := buf.Bytes()
	// The stored body follows the 30-byte local header and its name; flip one
	// byte so the entry reads back with a CRC mismatch.
	n := int(binary.LittleEndian.Uint16(raw[26:28])) + int(binary.LittleEndian.Uint16(raw[28:30]))
	start := 30 + n
	if start+len(payload) > len(raw) {
		t.Fatalf("local header does not hold the body: start %d, %d bytes, file %d", start, len(payload), len(raw))
	}
	raw[start+len(payload)/2] ^= 0xff
	if err := os.WriteFile(p, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = runOp("decode_android_resources", p)
	if err == nil {
		t.Fatalf("corrupt resources.arsc reported as a successful decode")
	}
	if !strings.Contains(err.Error(), "unreadable") {
		t.Fatalf("error %q does not say the entry could not be read", err)
	}
}

func TestDecodeAndroidResourcesPackage(t *testing.T) {
	p := filepath.Join(t.TempDir(), "app.apk")
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("resources.arsc")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(sfArsc()); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	m := opStatic(t, "decode_android_resources", p)

	pkgs, ok := m["packages"].([]any)
	if !ok || len(pkgs) != 1 {
		t.Fatalf("packages = %v, want 1", m["packages"])
	}
	pkg := pkgs[0].(map[string]any)
	if got := opStaticNum(t, pkg, "id"); got != 0x7f {
		t.Fatalf("id = %#x, want 0x7f", got)
	}
	if got := opStaticStr(t, pkg, "name"); got != "com.sim.res" {
		t.Fatalf("name = %q", got)
	}
	types, _ := pkg["types"].([]any)
	if len(types) != 1 || types[0] != "string" {
		t.Fatalf("types = %v", pkg["types"])
	}
	if got := opStaticNum(t, pkg, "entries"); got != 1 {
		t.Fatalf("entries = %d, want 1", got)
	}
	names, _ := pkg["names"].([]any)
	if len(names) != 1 || names[0] != "string/app_name" {
		t.Fatalf("names = %v", pkg["names"])
	}
}

// TestRepairRefusalKinds pins the two repair ops: record_unknown records a
// bytes-only job once and calls the second write a state conflict, while a job
// without an address is a missing argument (the job file itself is optional).
// recover_javascript_sources refuses a map whose only source climbs out, and a
// map with no embedded content, as bad_arg rather than an internal error.
func TestRepairRefusalKinds(t *testing.T) {
	t.Setenv("LRECON_STATE", t.TempDir())
	job := writeTemp(t, "job.json", []byte(`{"address":"0x1000","bytes":"deadbeef"}`))
	a21WantKind(t, "record_unknown", "", kindNeedsArg)
	a21WantKind(t, "record_unknown", "/nonexistent-xyz", kindNeedsArg)
	if _, err := runOp("record_unknown", job); err != nil {
		t.Fatalf("record_unknown on a bytes-only job: %v", err)
	}
	a21WantKind(t, "record_unknown", job, kindStateConflict)

	a21WantKind(t, "recover_javascript_sources", "", kindNeedsArg)
	a21WantKind(t, "recover_javascript_sources", "/nonexistent-xyz", kindIO)
	escape := writeTemp(t, "escape.js.map",
		[]byte(`{"version":3,"sources":["../a.js"],"sourcesContent":["x"]}`))
	a21WantKind(t, "recover_javascript_sources", escape, kindBadArg)
	plain := writeTemp(t, "plain.js.map", []byte(`{"version":3,"sources":["a.js"]}`))
	a21WantKind(t, "recover_javascript_sources", plain, kindBadArg)
}
