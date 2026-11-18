package main

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"unicode/utf16"
)

type zipEntry struct {
	name string
	data []byte
}

func writeZip(t *testing.T, name string, entries []zipEntry) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	f, err := os.Create(p)
	if err != nil {
		t.Fatalf("create %s: %v", p, err)
	}
	zw := zip.NewWriter(f)
	for _, e := range entries {
		w, err := zw.Create(e.name)
		if err != nil {
			t.Fatalf("zip entry %s: %v", e.name, err)
		}
		if _, err := w.Write(e.data); err != nil {
			t.Fatalf("zip write %s: %v", e.name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close %s: %v", p, err)
	}
	return p
}

func binaryManifest(size uint32) []byte {
	b := make([]byte, size)
	binary.LittleEndian.PutUint32(b, axmlMagic)
	binary.LittleEndian.PutUint32(b[4:], size)
	return b
}

// --- compiled-manifest fixture writer (AXML) ---

type testAttr struct {
	name string
	str  string // pool string value when kind is 0x03
	num  int32
	kind byte // 0x03 string, 0x10 int
}

func axmlChunk(typ uint16, hsize int, body []byte) []byte {
	b := make([]byte, hsize+len(body))
	binary.LittleEndian.PutUint16(b[0:], typ)
	binary.LittleEndian.PutUint16(b[2:], uint16(hsize))
	binary.LittleEndian.PutUint32(b[4:], uint32(len(b)))
	copy(b[hsize:], body)
	return b
}

func axmlPool(strs []string, utf8 bool) []byte {
	var data, offs []byte
	put := func(u uint32) { offs = binary.LittleEndian.AppendUint32(offs, u) }
	for _, s := range strs {
		put(uint32(len(data)))
		if utf8 {
			data = append(data, byte(len(s)), byte(len(s)))
			data = append(data, s...)
			data = append(data, 0)
			continue
		}
		data = binary.LittleEndian.AppendUint16(data, uint16(len(s)))
		for _, r := range utf16.Encode([]rune(s)) {
			data = binary.LittleEndian.AppendUint16(data, r)
		}
		data = binary.LittleEndian.AppendUint16(data, 0)
	}
	for len(data)%4 != 0 {
		data = append(data, 0)
	}
	const hsize = 28 // pool fields live in the header itself
	flags := uint32(0)
	if utf8 {
		flags = 0x100
	}
	b := make([]byte, hsize+len(offs)+len(data))
	binary.LittleEndian.PutUint16(b[0:], 0x0001)
	binary.LittleEndian.PutUint16(b[2:], hsize)
	binary.LittleEndian.PutUint32(b[4:], uint32(len(b)))
	binary.LittleEndian.PutUint32(b[8:], uint32(len(strs)))
	binary.LittleEndian.PutUint32(b[12:], 0) // style count
	binary.LittleEndian.PutUint32(b[16:], flags)
	binary.LittleEndian.PutUint32(b[20:], hsize+uint32(len(offs))) // strings start
	binary.LittleEndian.PutUint32(b[24:], 0)                       // styles start
	copy(b[hsize:], offs)
	copy(b[hsize+len(offs):], data)
	return b
}

func axmlTag(idx map[string]uint32, name string, attrs []testAttr) []byte {
	size := 36 + 20*len(attrs)
	b := make([]byte, size)
	binary.LittleEndian.PutUint16(b[0:], 0x0102)
	binary.LittleEndian.PutUint16(b[2:], 16)
	binary.LittleEndian.PutUint32(b[4:], uint32(size))
	binary.LittleEndian.PutUint32(b[20:], idx[name])
	binary.LittleEndian.PutUint16(b[24:], 20) // attribute start, from attr ext
	binary.LittleEndian.PutUint16(b[26:], 20) // attribute size
	binary.LittleEndian.PutUint16(b[28:], uint16(len(attrs)))
	for i, a := range attrs {
		at := b[36+i*20:]
		binary.LittleEndian.PutUint32(at[4:], idx[a.name])
		if a.kind == 0x03 {
			binary.LittleEndian.PutUint32(at[8:], idx[a.str])
			continue
		}
		binary.LittleEndian.PutUint32(at[8:], 0xffffffff)
		at[15] = a.kind
		binary.LittleEndian.PutUint32(at[16:], uint32(a.num))
	}
	return b
}

func axmlFixture(utf8 bool) []byte {
	strs := []string{"manifest", "package", "uses-permission", "name", "uses-sdk",
		"minSdkVersion", "targetSdkVersion", "com.example.app",
		"android.permission.INTERNET", "android.permission.CAMERA"}
	idx := map[string]uint32{}
	for i, s := range strs {
		idx[s] = uint32(i)
	}
	var body []byte
	body = append(body, axmlPool(strs, utf8)...)
	body = append(body, axmlChunk(0x0180, 8, nil)...) // resource map, must be skipped
	body = append(body, axmlTag(idx, "manifest", []testAttr{{name: "package", str: "com.example.app", kind: 0x03}})...)
	body = append(body, axmlTag(idx, "uses-permission", []testAttr{{name: "name", str: "android.permission.INTERNET", kind: 0x03}})...)
	body = append(body, axmlTag(idx, "uses-permission", []testAttr{{name: "name", str: "android.permission.CAMERA", kind: 0x03}})...)
	body = append(body, axmlTag(idx, "uses-permission", []testAttr{{name: "name", str: "android.permission.INTERNET", kind: 0x03}})...)
	body = append(body, axmlTag(idx, "uses-sdk", []testAttr{
		{name: "minSdkVersion", kind: 0x10, num: 24},
		{name: "targetSdkVersion", kind: 0x10, num: 34},
	})...)
	head := make([]byte, 8)
	binary.LittleEndian.PutUint16(head[0:], 0x0003)
	binary.LittleEndian.PutUint16(head[2:], 8)
	binary.LittleEndian.PutUint32(head[4:], uint32(8+len(body)))
	return append(head, body...)
}

// axmlComponentsFixture is a compiled manifest that declares the component
// graph: one activity, one service and one receiver.
func axmlComponentsFixture(utf8 bool) []byte {
	strs := []string{"manifest", "package", "name", "activity", "service", "receiver",
		"com.example.app", "com.example.app.MainActivity", "com.example.app.SyncService",
		"com.example.app.BootReceiver"}
	idx := map[string]uint32{}
	for i, s := range strs {
		idx[s] = uint32(i)
	}
	var body []byte
	body = append(body, axmlPool(strs, utf8)...)
	body = append(body, axmlChunk(0x0180, 8, nil)...) // resource map, must be skipped
	body = append(body, axmlTag(idx, "manifest", []testAttr{{name: "package", str: "com.example.app", kind: 0x03}})...)
	body = append(body, axmlTag(idx, "activity", []testAttr{{name: "name", str: "com.example.app.MainActivity", kind: 0x03}})...)
	body = append(body, axmlTag(idx, "service", []testAttr{{name: "name", str: "com.example.app.SyncService", kind: 0x03}})...)
	body = append(body, axmlTag(idx, "receiver", []testAttr{{name: "name", str: "com.example.app.BootReceiver", kind: 0x03}})...)
	head := make([]byte, 8)
	binary.LittleEndian.PutUint16(head[0:], 0x0003)
	binary.LittleEndian.PutUint16(head[2:], 8)
	binary.LittleEndian.PutUint32(head[4:], uint32(8+len(body)))
	return append(head, body...)
}

func TestAPKManifest(t *testing.T) {
	for _, utf8 := range []bool{true, false} {
		p := writeZip(t, "app.apk", []zipEntry{
			{"AndroidManifest.xml", axmlFixture(utf8)},
			{"classes.dex", dexFile()},
		})
		d, err := Probe(p)
		if err != nil {
			t.Fatalf("Probe(utf8=%v): %v", utf8, err)
		}
		if d.MobilePkg != "com.example.app" {
			t.Fatalf("utf8=%v: MobilePkg = %q", utf8, d.MobilePkg)
		}
		want := []string{"android.permission.INTERNET", "android.permission.CAMERA"}
		if strings.Join(d.MobilePerms, ",") != strings.Join(want, ",") {
			t.Fatalf("utf8=%v: MobilePerms = %q, want %q", utf8, d.MobilePerms, want)
		}
		if d.MobileSDK != "min 24, target 34" {
			t.Fatalf("utf8=%v: MobileSDK = %q", utf8, d.MobileSDK)
		}
		if !strings.Contains(d.Text(), "mobile_package: com.example.app") {
			t.Fatalf("utf8=%v: digest text misses mobile_package:\n%s", utf8, d.Text())
		}
	}
}

func TestAPKManifestMalformed(t *testing.T) {
	bad := binaryManifest(64)
	for i := 8; i < len(bad); i++ {
		bad[i] = 0xff
	}
	p := writeZip(t, "app.apk", []zipEntry{{"AndroidManifest.xml", bad}, {"classes.dex", dexFile()}})
	d, err := Probe(p)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	wantNote(t, d, "manifest: AXML parse failed")
	if d.MobilePkg != "" || len(d.MobilePerms) != 0 || d.MobileSDK != "" {
		t.Fatalf("malformed manifest leaked fields: %q %q %q", d.MobilePkg, d.MobilePerms, d.MobileSDK)
	}
}

func dexFile() []byte {
	b := make([]byte, 0x70)
	copy(b, "dex\n035\x00")
	binary.LittleEndian.PutUint32(b[0x38:], 3) // string ids
	binary.LittleEndian.PutUint32(b[0x40:], 4) // type ids
	binary.LittleEndian.PutUint32(b[0x60:], 1) // class defs
	return b
}

func wantNote(t *testing.T, d Digest, want string) {
	t.Helper()
	if slices.Contains(d.Notes, want) {
		return
	}
	t.Fatalf("note %q missing from %q", want, d.Notes)
}

func wantCap(t *testing.T, d Digest, want string) {
	t.Helper()
	if !containsStr(d.Capabilities, want) {
		t.Fatalf("capability %q missing from %q", want, d.Capabilities)
	}
}

// emForbiddenTools are product names a note must never carry: a note says what
// to recover, not which program to run.
var emForbiddenTools = []string{
	"jadx", "apktool", "tshark", "ilspy", "ilspycmd", "ghidra", "frida",
	"binwalk", "unblob", "objdump", "otool", "sqlite3", "unzip", "wasm2wat",
	"hermes-dec", "blutter",
}

func emAssertNoToolNames(t *testing.T, d Digest) {
	t.Helper()
	for _, n := range d.Notes {
		low := strings.ToLower(n)
		for _, bad := range emForbiddenTools {
			if strings.Contains(low, bad) {
				t.Fatalf("note names tool %q: %q", bad, n)
			}
		}
	}
}

// TestAndroidComponentGraph: the compiled manifest carries the component
// names, so the activity/service/receiver graph is readable without decoding
// the whole package.
func TestAndroidComponentGraph(t *testing.T) {
	p := writeZip(t, "app.apk", []zipEntry{
		{"AndroidManifest.xml", axmlComponentsFixture(true)},
		{"classes.dex", dexFile()},
	})
	d, err := Probe(p)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	joined := strings.Join(d.Notes, "\n")
	for _, want := range []string{
		"android components:",
		"activity com.example.app.MainActivity",
		"service com.example.app.SyncService",
		"receiver com.example.app.BootReceiver",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("note %q missing from %q", want, d.Notes)
		}
	}
	emAssertNoToolNames(t, d)
}

func TestAPK(t *testing.T) {
	p := writeZip(t, "app.apk", []zipEntry{
		{"AndroidManifest.xml", binaryManifest(0x100)},
		{"classes.dex", dexFile()},
		{"classes2.dex", dexFile()},
		{"lib/arm64-v8a/libflutter.so", []byte("elf")},
		{"lib/arm64-v8a/libhermes.so", []byte("elf")},
		{"resources.arsc", make([]byte, 1024)},
	})
	d, err := Probe(p)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if d.Kind != "apk" {
		t.Fatalf("Kind = %q, want apk", d.Kind)
	}
	wantCap(t, d, "android")
	wantCap(t, d, "flutter")
	wantCap(t, d, "react-native")
	if len(d.Capabilities) != 3 {
		t.Fatalf("Capabilities = %q, want exactly 3", d.Capabilities)
	}
	wantNote(t, d, "apk: 6 entries")
	wantNote(t, d, "apk: classes.dex: 2")
	wantNote(t, d, "apk: resources.arsc: 1024 bytes")
	wantNote(t, d, "apk: AndroidManifest.xml: binary XML (0x00080003)")
	for _, want := range []string{
		"decode the dex bytecode of the packed classes",
		"decode the package resource table",
		"decode the package structure",
	} {
		if !notesContain(d, want) {
			t.Fatalf("note %q missing: %q", want, d.Notes)
		}
	}
	emAssertNoToolNames(t, d)
}

func TestAAB(t *testing.T) {
	p := writeZip(t, "app.aab", []zipEntry{
		{"BundleConfig.pb", []byte("pb")},
		{"base/manifest/AndroidManifest.xml", binaryManifest(0x80)},
		{"base/lib/arm64-v8a/libflutter.so", []byte("elf")},
		{"base/resources.pb", []byte("pb")},
	})
	d, err := Probe(p)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if d.Kind != "aab" {
		t.Fatalf("Kind = %q, want aab", d.Kind)
	}
	wantCap(t, d, "android")
	wantCap(t, d, "flutter")
	wantNote(t, d, "aab: 4 entries")
	wantNote(t, d, "aab: AndroidManifest.xml: binary XML (0x00080003)")
	emAssertNoToolNames(t, d)
}

func TestIPA(t *testing.T) {
	plist := []byte(`<?xml version="1.0"?><plist version="1.0"><dict>` +
		`<key>CFBundleIdentifier</key><string>com.example.demo</string>` +
		`<key>DTSDKName</key><string>iphoneos17.2</string>` +
		`<key>MinimumOSVersion</key><string>16.0</string>` +
		`<key>NSCameraUsageDescription</key><string>camera</string>` +
		`</dict></plist>`)
	p := writeZip(t, "app.ipa", []zipEntry{
		{"Payload/Demo.app/Info.plist", plist},
		{"Payload/Demo.app/embedded.mobileprovision", []byte("prov")},
		{"Payload/Demo.app/Demo", []byte("macho")},
		{"Payload/Demo.app/Frameworks/A.framework/A", []byte("macho")},
		{"Payload/Demo.app/Frameworks/B.framework/B", []byte("macho")},
	})
	d, err := Probe(p)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if d.Kind != "ipa" {
		t.Fatalf("Kind = %q, want ipa", d.Kind)
	}
	if d.MobilePkg != "com.example.demo" {
		t.Fatalf("MobilePkg = %q, want com.example.demo", d.MobilePkg)
	}
	if d.MobileSDK != "iphoneos17.2 min 16.0" {
		t.Fatalf("MobileSDK = %q, want iphoneos17.2 min 16.0", d.MobileSDK)
	}
	wantCap(t, d, "ios")
	wantCap(t, d, "signed-provision")
	if len(d.Capabilities) != 2 {
		t.Fatalf("Capabilities = %q, want exactly 2", d.Capabilities)
	}
	wantNote(t, d, "ipa: 5 entries")
	wantNote(t, d, "ipa: Info.plist present")
	wantNote(t, d, "ipa: embedded.mobileprovision present")
	wantNote(t, d, "ipa: frameworks: 2")
	if !notesContain(d, "read the bundle Info.plist keys, the embedded provisioning profile and the Mach-O slices") {
		t.Fatalf("bundle decode note missing: %q", d.Notes)
	}
	emAssertNoToolNames(t, d)
}

func TestDex(t *testing.T) {
	p := filepath.Join(t.TempDir(), "classes.dex")
	if err := os.WriteFile(p, dexFile(), 0o644); err != nil {
		t.Fatalf("write dex: %v", err)
	}
	d, err := Probe(p)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if d.Kind != "dex" {
		t.Fatalf("Kind = %q, want dex", d.Kind)
	}
	wantCap(t, d, "android")
	wantNote(t, d, "dex: version 035")
	wantNote(t, d, "dex: strings=3 types=4 classes=1")
	if !notesContain(d, "read the class and method names from the string pool") {
		t.Fatalf("dex name note missing: %q", d.Notes)
	}
	emAssertNoToolNames(t, d)
}

func TestAndroidManifest(t *testing.T) {
	p := filepath.Join(t.TempDir(), "AndroidManifest.xml")
	if err := os.WriteFile(p, binaryManifest(0x100), 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	d, err := Probe(p)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if d.Kind != "android-manifest" {
		t.Fatalf("Kind = %q, want android-manifest", d.Kind)
	}
	wantCap(t, d, "android")
	found := false
	for _, n := range d.Notes {
		if strings.Contains(n, "binary XML (0x00080003)") {
			found = true
		}
	}
	if !found {
		t.Fatalf("binary manifest note missing: %q", d.Notes)
	}
	if !notesContain(d, "decode the package resources and the classes") {
		t.Fatalf("package handoff note missing: %q", d.Notes)
	}
	emAssertNoToolNames(t, d)
}

// Unknown files must not acquire any mobile field.
func TestUnknownNotMobile(t *testing.T) {
	dir := t.TempDir()
	plain := filepath.Join(dir, "blob.bin")
	if err := os.WriteFile(plain, []byte{0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x02, 0x03}, 0o644); err != nil {
		t.Fatalf("write blob: %v", err)
	}
	other := writeZip(t, "plain.zip", []zipEntry{{"readme.txt", []byte("hi")}})
	d, err := Probe(plain)
	if err != nil {
		t.Fatalf("Probe(%s): %v", plain, err)
	}
	if len(d.Capabilities) != 0 {
		t.Fatalf("%s: Capabilities = %q, want none", plain, d.Capabilities)
	}
	for _, n := range d.Notes {
		if strings.HasPrefix(n, "deep:") {
			t.Fatalf("%s: unexpected handoff note %q", plain, n)
		}
	}
	dz, err := Probe(other)
	if err != nil {
		t.Fatalf("Probe(zip): %v", err)
	}
	if dz.Kind != "zip" {
		t.Fatalf("Kind = %q, want zip", dz.Kind)
	}
	if len(dz.Capabilities) != 0 {
		t.Fatalf("zip: Capabilities = %q, want none", dz.Capabilities)
	}
	wantNote(t, dz, "deep: zip container: read the entry table to inventory the member names and sizes")
}

// TestAPKManifestCapNotes: a manifest with more permissions than the digest
// reports says the list was cut.
func TestAPKManifestCapNotes(t *testing.T) {
	strs := []string{"manifest", "package", "uses-permission", "name", "com.example.app"}
	for i := range 70 {
		strs = append(strs, "android.permission.P"+strconv.Itoa(i))
	}
	idx := map[string]uint32{}
	for i, s := range strs {
		idx[s] = uint32(i)
	}
	var body []byte
	body = append(body, axmlPool(strs, true)...)
	body = append(body, axmlTag(idx, "manifest", []testAttr{{name: "package", str: "com.example.app", kind: 0x03}})...)
	for i := range 70 {
		body = append(body, axmlTag(idx, "uses-permission", []testAttr{{name: "name", str: "android.permission.P" + strconv.Itoa(i), kind: 0x03}})...)
	}
	head := make([]byte, 8)
	binary.LittleEndian.PutUint16(head[0:], 0x0003)
	binary.LittleEndian.PutUint16(head[2:], 8)
	binary.LittleEndian.PutUint32(head[4:], uint32(8+len(body)))
	d, err := Probe(writeTemp(t, "AndroidManifest.xml", append(head, body...)))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if len(d.MobilePerms) != axmlListCap {
		t.Fatalf("mobile_permission = %d, want %d", len(d.MobilePerms), axmlListCap)
	}
	wantNote(t, d, "android permissions truncated to 64 of 70")
}

// dexMapItem is one map_list entry; offs must be in increasing order.
type dexMapItem struct {
	typ       uint16
	size, off uint32
}

// dexWithMap appends a map_list at EOF, points map_off at it and reseals, so
// the map is the only source that can disagree with the header.
func dexWithMap(b []byte, items []dexMapItem) []byte {
	at := len(b)
	out := append(append([]byte(nil), b...), make([]byte, 4+12*len(items))...)
	binary.LittleEndian.PutUint32(out[at:], uint32(len(items)))
	for i, it := range items {
		o := out[at+4+12*i:]
		binary.LittleEndian.PutUint16(o, it.typ)
		binary.LittleEndian.PutUint32(o[4:], it.size)
		binary.LittleEndian.PutUint32(o[8:], it.off)
	}
	binary.LittleEndian.PutUint32(out[0x34:], uint32(at))
	return dexSeal(out)
}

// dexSections is the real section list of a fixture, map_list excluded.
func dexSections(b []byte) []dexMapItem {
	u32 := func(o int) uint32 { return binary.LittleEndian.Uint32(b[o:]) }
	return []dexMapItem{
		{0x0000, u32(0x24), 0},
		{0x0001, u32(0x38), u32(0x3C)},
		{0x0002, u32(0x40), u32(0x44)},
		{0x0005, u32(0x58), u32(0x5C)},
		{0x0006, u32(0x60), u32(0x64)},
	}
}

func dexSealedFixture(t *testing.T, f dexFixture) []byte {
	t.Helper()
	b := f.build()
	return dexWithMap(b, append(dexSections(b), dexMapItem{0x1000, 1, uint32(len(b))}))
}

// TestDexCompact: the cdex001 magic is a dex, its header is 0x88, and the map_list
// still witnesses the sections.
func TestDexCompact(t *testing.T) {
	f := dexHappy()
	f.version, f.hdrSize = dexCompactVersion, dexHeaderCompact
	b := f.build()
	copy(b, dexCompactMagic+"\x00")
	b = dexWithMap(b, append(dexSections(b), dexMapItem{0x1000, 1, uint32(len(b))}))
	d, err := Probe(writeTemp(t, "classes.dex", b))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if d.Kind != "dex" {
		t.Fatalf("Kind = %q, want dex", d.Kind)
	}
	for _, want := range []string{
		"dex: version 001",
		"dex: compact dex header (cdex001)",
		"dex: map_list items=6 types=header,string_id,type_id,method_id,class_def,map_list",
		"dex: compact dex: class_data uses owned-data offsets, class names not decoded",
	} {
		wantNote(t, d, want)
	}
	wantCap(t, d, "dex-001")
	wantCap(t, d, "compact-dex")
	if len(d.Skipped) != 0 {
		t.Fatalf("Skipped = %+v, want none", d.Skipped)
	}
	if d.Coverage == nil || d.Coverage.Unknown != 1 {
		t.Fatalf("Coverage = %+v, want one undecoded unit", d.Coverage)
	}

	// The same compact file with a flipped byte must refuse on the checksum, not
	// fall back to names.
	bad := append([]byte(nil), b...)
	bad[len(bad)-1] ^= 0xFF
	d, err = Probe(writeTemp(t, "classes.dex", bad))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if len(d.Skipped) != 1 || d.Skipped[0].Reason != "dex-checksum-mismatch" {
		t.Fatalf("Skipped = %+v, want dex-checksum-mismatch", d.Skipped)
	}

	// A compact header that is not 0x88 is refused, so the two magics stay distinct.
	short := append([]byte(nil), b...)
	binary.LittleEndian.PutUint32(short[0x24:], dexHeaderSize)
	dexProbeReason(t, dexSeal(short), "dex-bad-header-size")
}

// TestDexMapList: the map is a real cross-check, so a byte-perfect copy passes
// and a copy whose header fields all agree still fails when the map disagrees.
func TestDexMapList(t *testing.T) {
	good := dexSealedFixture(t, dexHappy())
	d, err := Probe(writeTemp(t, "classes.dex", good))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	wantNote(t, d, "dex: map_list items=6 types=header,string_id,type_id,method_id,class_def,map_list")
	if len(d.Skipped) != 0 {
		t.Fatalf("Skipped = %+v, want none", d.Skipped)
	}

	// Byte-perfect copy: same digest facts, still no refusal.
	cp := append([]byte(nil), good...)
	d, err = Probe(writeTemp(t, "copy.dex", cp))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if len(d.Skipped) != 0 {
		t.Fatalf("copy: Skipped = %+v, want none", d.Skipped)
	}

	mapOff := func(b []byte) int { return int(binary.LittleEndian.Uint32(b[0x34:])) }
	// Offset past file_size: file_size and adler32 are both recomputed, so only
	// the map can catch it.
	past := append([]byte(nil), good...)
	n := int(binary.LittleEndian.Uint32(past[mapOff(past):]))
	binary.LittleEndian.PutUint32(past[mapOff(past)+4+12*(n-1)+8:], uint32(len(past)+0x10))
	dexProbeReason(t, dexSeal(past), "dex-bad-map")

	// Header item claimed away from offset 0.
	moved := append([]byte(nil), good...)
	binary.LittleEndian.PutUint32(moved[mapOff(moved)+4+8:], 8)
	dexProbeReason(t, dexSeal(moved), "dex-bad-map")

	// No map at all is legal for this reader: it says so instead of guessing.
	plain := dexHappy().build()
	d, err = Probe(writeTemp(t, "plain.dex", plain))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	wantNote(t, d, "dex: map_list absent (map_off=0)")
	if len(d.Skipped) != 0 {
		t.Fatalf("Skipped = %+v, want none", d.Skipped)
	}
}

func dexProbeReason(t *testing.T, b []byte, reason string) {
	t.Helper()
	d, err := Probe(writeTemp(t, "classes.dex", b))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if len(d.Skipped) != 1 || d.Skipped[0].Reason != reason {
		t.Fatalf("Skipped = %+v, want %s", d.Skipped, reason)
	}
}

// TestDexPackerMarker: a marker names the packer at the real string offset; no
// marker means no packer note at all.
func TestDexPackerMarker(t *testing.T) {
	f := dexHappy()
	f.strs = append(f.strs, "lib/arm64-v8a/libjiagu.so")
	b := f.build()
	d, err := Probe(writeTemp(t, "classes.dex", b))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	note := ""
	for _, n := range d.Notes {
		if strings.Contains(n, "packer claim") {
			note = n
		}
	}
	if !strings.Contains(note, `"Qihoo 360 Jiagu"`) || !strings.Contains(note, `(string marker "libjiagu" at 0x`) {
		t.Fatalf("packer note = %q", note)
	}
	_, after, _ := strings.Cut(note, " at 0x")
	off, err := strconv.ParseInt(strings.TrimSuffix(after, ")"), 16, 64)
	if err != nil {
		t.Fatalf("offset in %q: %v", note, err)
	}
	_, n, ok := dexULEB(b, int(off), len(b))
	if !ok || !strings.HasPrefix(string(b[int(off)+n:]), "lib/arm64-v8a/libjiagu.so") {
		t.Fatalf("offset 0x%x does not hold the marker string", off)
	}

	d, err = Probe(writeTemp(t, "plain.dex", dexHappy().build()))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	for _, n := range d.Notes {
		if strings.Contains(n, "packer") {
			t.Fatalf("plain dex carries a packer note: %q", n)
		}
	}
}

// TestAPKPackerEntries: zip entry names are structural evidence too, and an
// oddly named dex is called out without inventing a packer.
func TestAPKPackerEntries(t *testing.T) {
	p := writeZip(t, "app.apk", []zipEntry{
		{"AndroidManifest.xml", binaryManifest(0x100)},
		{"classes.dex", dexFile()},
		{"assets/payload.dex", dexFile()},
		{"lib/arm64-v8a/libjiagu.so", []byte("x")},
		{"lib/arm64-v8a/libjiagu_v2.so", []byte("x")},
	})
	d, err := Probe(p)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	joined := strings.Join(d.Notes, "\n")
	for _, want := range []string{
		`apk: packer claim "Qihoo 360 Jiagu" (entry lib/arm64-v8a/libjiagu.so)`,
		"apk: dex entry assets/payload.dex is not a standard classes*.dex name",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("note %q missing from %q", want, d.Notes)
		}
	}
	if n := strings.Count(joined, "packer claim"); n != 1 {
		t.Fatalf("packer claim repeated %d times: %q", n, d.Notes)
	}

	stock := writeZip(t, "stock.apk", []zipEntry{
		{"AndroidManifest.xml", binaryManifest(0x100)},
		{"classes.dex", dexFile()},
		{"classes2.dex", dexFile()},
	})
	d, err = Probe(stock)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	for _, n := range d.Notes {
		if strings.Contains(n, "packer") || strings.Contains(n, "not a standard classes") {
			t.Fatalf("stock apk carries a packer note: %q", n)
		}
	}
}

const plainManifest = `<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.plain">
  <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="34"/>
  <uses-permission android:name="android.permission.INTERNET"/>
  <uses-permission android:name="android.permission.CAMERA"/>
</manifest>
`

// A plain zip names its member count; the entry table is the next step.
func TestZipEntryCount(t *testing.T) {
	p := writeZip(t, "t.zip", []zipEntry{
		{"a.txt", []byte("hi")},
		{"b/c.txt", []byte("x")},
	})
	d, err := Probe(p)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if d.Kind != "zip" {
		t.Fatalf("Kind = %q, want zip", d.Kind)
	}
	wantNote(t, d, "zip: 2 entries")
}

// A plain-text manifest inside an apk carries the same mobile fields as the
// binary AXML one.
func TestAPKPlainManifest(t *testing.T) {
	p := writeZip(t, "app.apk", []zipEntry{
		{"AndroidManifest.xml", []byte(plainManifest)},
		{"classes.dex", dexFile()},
	})
	d, err := Probe(p)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if d.Kind != "apk" {
		t.Fatalf("Kind = %q, want apk", d.Kind)
	}
	wantNote(t, d, "apk: AndroidManifest.xml: plain XML")
	if d.MobilePkg != "com.example.plain" || d.MobileSDK != "min 21, target 34" {
		t.Fatalf("manifest fields = %q %q", d.MobilePkg, d.MobileSDK)
	}
	if len(d.MobilePerms) != 2 {
		t.Fatalf("MobilePerms = %v, want 2", d.MobilePerms)
	}
}

// A standalone plain-text manifest keeps kind text but fills mobile fields.
func TestPlainManifestStandalone(t *testing.T) {
	p := filepath.Join(t.TempDir(), "AndroidManifest.xml")
	if err := os.WriteFile(p, []byte(plainManifest), 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	d, err := Probe(p)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if d.Kind != "text" {
		t.Fatalf("Kind = %q, want text", d.Kind)
	}
	wantCap(t, d, "android")
	wantNote(t, d, "android-manifest: plain XML")
	if d.MobilePkg != "com.example.plain" {
		t.Fatalf("MobilePkg = %q, want com.example.plain", d.MobilePkg)
	}
}

// TestReadEntryRefusesOversize checks a zip entry that does not fit the
// caller's budget is refused whole instead of being silently truncated to max
// bytes, which would hand a half-read manifest or arsc to the parser.
func TestReadEntryRefusesOversize(t *testing.T) {
	p := writeZip(t, "budget.zip", []zipEntry{{"classes.dex", bytes.Repeat([]byte("d"), 32)}})
	zr, err := zip.OpenReader(p)
	if err != nil {
		t.Fatalf("open %s: %v", p, err)
	}
	defer zr.Close()
	if len(zr.File) != 1 {
		t.Fatalf("entries = %d, want 1", len(zr.File))
	}
	f := zr.File[0]
	if b, ok := readEntry(f, 16); ok || b != nil {
		t.Fatalf("readEntry(max=16) = %d bytes, ok=%v; want refusal", len(b), ok)
	}
	b, ok := readEntry(f, 64)
	if !ok || len(b) != 32 || b[0] != 'd' {
		t.Fatalf("readEntry(max=64) = %d bytes, ok=%v; want the full 32-byte body", len(b), ok)
	}
	if _, ok := readEntry(f, 0); ok {
		t.Fatal("readEntry(max=0) accepted a body, want refusal")
	}
}
