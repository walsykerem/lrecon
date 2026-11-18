package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The detection fixtures the parity doc names. Each test pins one kind, the
// fields that kind must report and the handoff note that must follow it.

// TestProbeSQLite: the 100-byte header facts, the write-ahead log sidecar and
// the handoff note.
func TestProbeSQLite(t *testing.T) {
	hdr := make([]byte, 100)
	copy(hdr, "SQLite format 3\x00")
	binary.BigEndian.PutUint16(hdr[16:18], 4096)
	hdr[18], hdr[19] = 2, 2 // write-ahead log journal mode
	binary.BigEndian.PutUint32(hdr[96:100], 3045000)
	path := writeTemp(t, "app.db", hdr)
	d, err := Probe(path)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if d.Kind != "sqlite" {
		t.Fatalf("kind = %q, want sqlite", d.Kind)
	}
	if d.SQLitePageSize != 4096 {
		t.Fatalf("sqlite_page_size = %d, want 4096", d.SQLitePageSize)
	}
	if d.SQLiteVersion != "2/2 lib 3.45.0" {
		t.Fatalf("sqlite_version = %q, want 2/2 lib 3.45.0", d.SQLiteVersion)
	}
	if !d.SQLiteWAL {
		t.Fatal("sqlite_wal = false, want true")
	}
	if !notesContain(d, "deep: ") {
		t.Fatalf("no deep: handoff note: %v", d.Notes)
	}

	// a legacy header is still a live write-ahead log when the sidecar exists
	hdr[18], hdr[19] = 1, 1
	if err := os.WriteFile(path, hdr, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+"-wal", nil, 0o644); err != nil {
		t.Fatal(err)
	}
	d, err = Probe(path)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if !d.SQLiteWAL {
		t.Fatal("sqlite_wal = false with a -wal sidecar, want true")
	}
	if d.SQLiteVersion != "1/1 lib 3.45.0" {
		t.Fatalf("sqlite_version = %q, want 1/1 lib 3.45.0", d.SQLiteVersion)
	}
}

// TestProbePlist: an XML property list reports its keys, and the bundle keys
// carry their value.
func TestProbePlist(t *testing.T) {
	body := []byte(`<?xml version="1.0"?><plist version="1.0"><dict><key>CFBundleIdentifier</key><string>com.example.app</string></dict></plist>`)
	d, err := Probe(writeTemp(t, "Info.plist", body))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if d.Kind != "plist" {
		t.Fatalf("kind = %q, want plist", d.Kind)
	}
	if !containsStr(d.PlistKeys, "CFBundleIdentifier = com.example.app") {
		t.Fatalf("plist_key = %v, want CFBundleIdentifier = com.example.app", d.PlistKeys)
	}
	if !notesContain(d, "deep: ") {
		t.Fatalf("no deep: handoff note: %v", d.Notes)
	}
}

// TestProbeWASM: the magic and the module version.
func TestProbeWASM(t *testing.T) {
	d, err := Probe(writeTemp(t, "mod.wasm", []byte("\x00asm\x01\x00\x00\x00")))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if d.Kind != "wasm" || d.Format != "v1" {
		t.Fatalf("kind/format = %q/%q, want wasm/v1", d.Kind, d.Format)
	}
	if !containsStr(d.Capabilities, "wasm") {
		t.Fatalf("capabilities = %v, want wasm", d.Capabilities)
	}
}

// TestProbePcapMagic: a classic capture names its link type.
func TestProbePcapMagic(t *testing.T) {
	hdr := make([]byte, 24)
	binary.LittleEndian.PutUint32(hdr[0:4], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(hdr[4:6], 2)
	binary.LittleEndian.PutUint16(hdr[6:8], 4)
	binary.LittleEndian.PutUint32(hdr[16:20], 65535)
	binary.LittleEndian.PutUint32(hdr[20:24], 1) // ethernet
	d, err := Probe(writeTemp(t, "cap.pcap", hdr))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if d.Kind != "pcap" || d.Format != "pcap" {
		t.Fatalf("kind/format = %q/%q, want pcap/pcap", d.Kind, d.Format)
	}
	if d.PcapLinkType != "ethernet" {
		t.Fatalf("pcap_link_type = %q, want ethernet", d.PcapLinkType)
	}
}

// TestProbeSquashfsMagic: a rootfs container is a firmware image.
func TestProbeSquashfsMagic(t *testing.T) {
	body := make([]byte, 96)
	copy(body, "hsqs")
	d, err := Probe(writeTemp(t, "rootfs.img", body))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if d.Kind != "firmware" || d.Format != "squashfs" {
		t.Fatalf("kind/format = %q/%q, want firmware/squashfs", d.Kind, d.Format)
	}
	if !notesContain(d, "deep: ") {
		t.Fatalf("no deep: handoff note: %v", d.Notes)
	}
}

// TestProbeHermes: the bytecode snapshot magic.
func TestProbeHermes(t *testing.T) {
	body := append([]byte{0xc6, 0x1f, 0xbc, 0x03}, make([]byte, 32)...)
	d, err := Probe(writeTemp(t, "index.hbc", body))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if d.Kind != "hermes" {
		t.Fatalf("kind = %q, want hermes", d.Kind)
	}
}

// TestProbeELF: a linux binary.
func TestProbeELF(t *testing.T) {
	d, err := Probe(buildTarget(t, "linux", "amd64", "hello.elf"))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if d.Kind != "elf" {
		t.Fatalf("kind = %q, want elf", d.Kind)
	}
}

// TestProbePE: a windows binary without a managed header.
func TestProbePE(t *testing.T) {
	d, err := Probe(buildCLIPE(t, false))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if d.Kind != "pe" {
		t.Fatalf("kind = %q, want pe", d.Kind)
	}
}

// TestPEDotnetFlag: the same container with a CLI header is managed code.
func TestPEDotnetFlag(t *testing.T) {
	d, err := Probe(buildCLIPE(t, true))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if d.Kind != "pe-dotnet" {
		t.Fatalf("kind = %q, want pe-dotnet", d.Kind)
	}
	if !containsStr(d.Capabilities, "managed") {
		t.Fatalf("capabilities = %v, want managed", d.Capabilities)
	}
	if !strings.Contains(d.Toolchain, "dotnet CLR") {
		t.Fatalf("toolchain = %q, want the CLR version", d.Toolchain)
	}
}

// TestProbeAppBundleResolvesAsar: a bundle directory points at its packed
// application instead of staying an opaque folder.
func TestProbeAppBundleResolvesAsar(t *testing.T) {
	root := t.TempDir()
	res := filepath.Join(root, "Test.app", "Contents", "Resources")
	if err := os.MkdirAll(res, 0o755); err != nil {
		t.Fatal(err)
	}
	writeAsarArchive(t, res, "app.asar", map[string][]byte{"main.js": []byte("console.log(1)\n")})
	d, err := Probe(filepath.Join(root, "Test.app"))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if d.Kind != "app" {
		t.Fatalf("kind = %q, want app", d.Kind)
	}
	if d.Format != "electron" {
		t.Fatalf("format = %q, want electron (the wrapper wins, the asar fields stay)", d.Format)
	}
	if d.AsarFiles < 1 {
		t.Fatalf("asar_files = %d, want the packed members", d.AsarFiles)
	}
}

// TestZipApkFlutterMarker: a packaged android app carrying the flutter engine.
func TestZipApkFlutterMarker(t *testing.T) {
	p := writeZip(t, "app.apk", []zipEntry{
		{"AndroidManifest.xml", []byte("manifest")},
		{"lib/arm64-v8a/libflutter.so", []byte("\x7fELF")},
	})
	d, err := Probe(p)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if d.Kind != "apk" {
		t.Fatalf("kind = %q, want apk", d.Kind)
	}
	if !containsStr(d.Capabilities, "flutter") {
		t.Fatalf("capabilities = %v, want flutter", d.Capabilities)
	}
}

// TestFlutterHashIs32Hex: the snapshot hash is 32 lowercase hex characters.
func TestFlutterHashIs32Hex(t *testing.T) {
	body := make([]byte, 64)
	copy(body, "\xf5\xf5\xdc\xdc")
	// The version is the 32-char MD5 hexdigest the header is followed by, not
	// the raw 16 bytes of the digest: the digest is already text in the file.
	copy(body[20:], "0123456789abcdef0123456789abcdef")
	d, err := Probe(writeTemp(t, "app.snapshot", body))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if d.Kind != "flutter" {
		t.Fatalf("kind = %q, want flutter", d.Kind)
	}
	if len(d.FlutterHash) != 32 {
		t.Fatalf("flutter_hash = %q, want 32 hex chars", d.FlutterHash)
	}
	if want := "0123456789abcdef0123456789abcdef"; d.FlutterHash != want {
		t.Fatalf("flutter_hash = %q, want the file's own version string %q", d.FlutterHash, want)
	}
	for _, c := range d.FlutterHash {
		if !strings.ContainsRune("0123456789abcdef", c) {
			t.Fatalf("flutter_hash = %q, want lowercase hex", d.FlutterHash)
		}
	}
}

// TestJSDetectSourcemap: a packed script names its source map.
func TestJSDetectSourcemap(t *testing.T) {
	d := probeAsar(t, map[string][]byte{
		"index.js": []byte("console.log(1)\n//# sourceMappingURL=index.js.map\n"),
	})
	if !containsStr(d.SourceMaps, "index.js.map (missing)") {
		t.Fatalf("source_map = %v, want index.js.map marked (missing)", d.SourceMaps)
	}
	if !notesContain(d, "deep: ") {
		t.Fatalf("no deep: handoff note: %v", d.Notes)
	}
}

// TestAsarNotesCarryNextStep: the packed scripts yield the ipc channels and
// the note that says what to do with them.
func TestAsarNotesCarryNextStep(t *testing.T) {
	d := probeAsar(t, map[string][]byte{
		"main.js": []byte("ipcRenderer.invoke(\"user:get\", null)\n"),
	})
	if !containsStr(d.ElectronIPC, "user:get") {
		t.Fatalf("electron_ipc = %v, want user:get", d.ElectronIPC)
	}
	if !notesContain(d, "deep: ") {
		t.Fatalf("no deep: handoff note: %v", d.Notes)
	}
}

// TestRustToolchainFromMachO: a rust version marker inside a mach-o names the
// toolchain. The Go fixture is cross-built by goFixtureDeps, so its build info
// always names go1 first and would win the toolchain slot before the marker.
// A Unity player carries no build info, so the appended marker is the answer.
func TestRustToolchainFromMachO(t *testing.T) {
	body, err := os.ReadFile("testdata/fixtures/il2cpp/player.bin")
	if err != nil {
		t.Skipf("no mach-o fixture: %v", err)
	}
	body = append(body, []byte("rustc version 1.75.0\x00")...)
	d, err := Probe(writeTemp(t, "rusty", body))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if d.Toolchain != "rustc 1.75.0" {
		t.Fatalf("toolchain = %q, want rustc 1.75.0", d.Toolchain)
	}
}

// TestProbePlistValues: the allowlisted bundle keys carry their string value,
// everything else stays a bare key and non-string values are not guessed.
func TestProbePlistValues(t *testing.T) {
	body := []byte(`<?xml version="1.0"?><plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>com.example.app</string>
<key>CFBundleShortVersionString</key><string>1.2.3</string>
<key>CFBundleIconFile</key><string>App</string>
<key>NSAllowsArbitraryLoads</key><true/>
</dict></plist>`)
	d, err := Probe(writeTemp(t, "Info.plist", body))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	for _, want := range []string{
		"CFBundleIdentifier = com.example.app",
		"CFBundleShortVersionString = 1.2.3",
		"CFBundleIconFile",
		"NSAllowsArbitraryLoads",
	} {
		if !containsStr(d.PlistKeys, want) {
			t.Fatalf("plist_key %q missing from %v", want, d.PlistKeys)
		}
	}
}

// bplistFixture writes a flat binary property list dictionary from key/value
// pairs, with one-byte offsets and references.
func bplistFixture(kv ...string) []byte {
	pairs := len(kv) / 2
	str := func(s string) []byte {
		if len(s) >= 15 {
			return append([]byte{0x5F, 0x10, byte(len(s))}, s...)
		}
		return append([]byte{0x50 | byte(len(s))}, s...)
	}
	dict := []byte{byte(0xD0 | pairs)}
	// a dictionary stores all key refs first, then all value refs
	for i := range pairs {
		dict = append(dict, byte(1+2*i))
	}
	for i := range pairs {
		dict = append(dict, byte(2+2*i))
	}
	body := append([]byte{}, dict...)
	offs := []byte{8}
	for _, s := range kv {
		offs = append(offs, byte(8+len(body)))
		body = append(body, str(s)...)
	}
	out := append([]byte("bplist00"), body...)
	out = append(out, offs...)
	tr := make([]byte, 32)
	tr[6], tr[7] = 1, 1 // one-byte object offsets and references
	binary.BigEndian.PutUint64(tr[8:16], uint64(1+2*pairs))
	binary.BigEndian.PutUint64(tr[24:32], uint64(8+len(body)))
	return append(out, tr...)
}

// TestProbeBplistValues: the binary path reports the same bundle identity and
// version the XML path does.
func TestProbeBplistValues(t *testing.T) {
	b := bplistFixture(
		"CFBundleIdentifier", "com.example.app",
		"CFBundleShortVersionString", "1.2.3",
		"CFBundleExecutable", "Demo",
	)
	d, err := Probe(writeTemp(t, "Info.plist", b))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if d.Kind != "plist" {
		t.Fatalf("kind = %q, want plist", d.Kind)
	}
	for _, want := range []string{
		"CFBundleIdentifier = com.example.app",
		"CFBundleShortVersionString = 1.2.3",
		"CFBundleExecutable = Demo",
	} {
		if !containsStr(d.PlistKeys, want) {
			t.Fatalf("plist_key %q missing from %v", want, d.PlistKeys)
		}
	}
}

// TestProbePlistKeyCap: a cut key list says it was cut.
func TestProbePlistKeyCap(t *testing.T) {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0"?><plist version="1.0"><dict>`)
	for i := range 70 {
		fmt.Fprintf(&b, "<key>K%c%c</key><string>v</string>", 'a'+i/26, 'a'+i%26)
	}
	b.WriteString("</dict></plist>")
	d, err := Probe(writeTemp(t, "Info.plist", []byte(b.String())))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if len(d.PlistKeys) != plistKeyCap {
		t.Fatalf("plist keys = %d, want %d", len(d.PlistKeys), plistKeyCap)
	}
	if !notesContain(d, "plist keys truncated to 64 of") {
		t.Fatalf("no truncation note: %v", d.Notes)
	}
}

// TestProbeZipDeepNote: a plain zip hands off the entry table through a deep:
// note, so the reader's next step fires for archives too.
func TestProbeZipDeepNote(t *testing.T) {
	path := writeZip(t, "plain.zip", []zipEntry{{name: "a.txt", data: []byte("hi")}})
	d, err := Probe(path)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if d.Kind != "zip" {
		t.Fatalf("kind = %q, want zip", d.Kind)
	}
	if !notesContain(d, "deep: zip container") {
		t.Fatalf("no deep: zip note: %v", d.Notes)
	}
}

// TestFatMachOLookalike: a Java class file carries the universal-binary magic
// and must not be reported as macho.
func TestFatMachOLookalike(t *testing.T) {
	class := make([]byte, 4096)
	binary.BigEndian.PutUint32(class[0:4], 0xcafebabe)
	binary.BigEndian.PutUint16(class[6:8], 60) // major version lands where nfat_arch sits
	d, err := Probe(writeTemp(t, "Main.class", class))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if d.Kind == "macho" {
		t.Fatalf("java class reported as macho: %+v", d)
	}

	huge := make([]byte, 4096)
	binary.BigEndian.PutUint32(huge[0:4], 0xcafebabe)
	binary.BigEndian.PutUint32(huge[4:8], 0x7fffffff)
	if d, _ := Probe(writeTemp(t, "huge.bin", huge)); d.Kind == "macho" {
		t.Fatalf("0x7fffffff architectures reported as macho")
	}

	// the header shape a real universal binary has: two slices whose table and
	// first slice both fit in the file
	fat := make([]byte, 4096)
	binary.BigEndian.PutUint32(fat[0:4], 0xcafebabe)
	binary.BigEndian.PutUint32(fat[4:8], 2)
	binary.BigEndian.PutUint32(fat[8:12], 0x0100000c) // arm64
	binary.BigEndian.PutUint32(fat[16:20], 48)        // offset of the first slice
	binary.BigEndian.PutUint32(fat[20:24], 1024)      // its size
	if !fatMachOOK(fat, int64(len(fat))) {
		t.Fatal("a valid two-slice header was rejected")
	}

	// a class file whose constant pool count lands where the CPU type goes
	javaclass := make([]byte, 4096)
	binary.BigEndian.PutUint32(javaclass[0:4], 0xcafebabe)
	binary.BigEndian.PutUint32(javaclass[4:8], 61) // major version
	binary.BigEndian.PutUint32(javaclass[8:12], 42)
	if fatMachOOK(javaclass, int64(len(javaclass))) {
		t.Fatal("java class header accepted as universal binary")
	}
	if d, _ := Probe(writeTemp(t, "Main.class", javaclass)); d.Kind == "macho" {
		t.Fatalf("java class reported as macho: %+v", d)
	}
}

// Benchmarks pin the two hot paths this lane touched: Probe re-reads the head
// after hashing, and xmlPlistKeys copies the whole plist into a string before
// matching. Both are measured so a "faster" claim is a number, not a guess.
func BenchmarkProbeSmallFile(b *testing.B) {
	p := filepath.Join(b.TempDir(), "hello")
	if err := os.WriteFile(p, bytes.Repeat([]byte{0x01}, 4096), 0o644); err != nil {
		b.Fatal(err)
	}
	b.SetBytes(4096)
	for b.Loop() {
		if _, err := Probe(p); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkXMLPlistKeys(b *testing.B) {
	var sb strings.Builder
	sb.WriteString(`<?xml version="1.0"?><plist version="1.0"><dict>`)
	for i := 0; sb.Len() < 4<<20; i++ {
		fmt.Fprintf(&sb, "<key>CFBundleKey%06d</key><string>value-%06d</string>", i, i)
	}
	sb.WriteString("</dict></plist>")
	blob := []byte(sb.String())
	b.SetBytes(int64(len(blob)))
	var d Digest
	b.ResetTimer()
	for b.Loop() {
		d.PlistKeys = nil
		xmlPlistKeys(blob, &d)
	}
}

// TestProbeBplistHugeCount: a string object whose 0xF length lives in an 8-byte
// integer can claim 2^63 bytes inside a 58-byte file. bplistCount narrows that
// to int, so the length arrives negative; the length check must refuse it
// instead of panicking on the slice. Both string encodings are covered: the
// ascii path slices with n and the utf-16 path makes a []uint16 of n.
func TestProbeBplistHugeCount(t *testing.T) {
	for _, marker := range []byte{0x5F, 0x6F} {
		body := []byte{0xD1, 0x01, 0x02}  // dict with one entry: key 1, value 2
		body = append(body, marker, 0x13) // string, length in an 8-byte int
		var huge [8]byte
		binary.BigEndian.PutUint64(huge[:], 1<<63)
		body = append(body, huge[:]...)
		body = append(body, 0x51, 'x') // the value: "x"
		b := append([]byte("bplist00"), body...)
		b = append(b, 0x08, 0x0b, 0x15) // offset table: objects at 8, 11, 21
		tr := make([]byte, 32)
		tr[6], tr[7] = 1, 1
		binary.BigEndian.PutUint64(tr[8:16], 3)
		binary.BigEndian.PutUint64(tr[24:32], uint64(8+len(body)))
		b = append(b, tr...)

		d, err := Probe(writeTemp(t, "huge.plist", b))
		if err != nil {
			t.Fatalf("marker %#02x: Probe: %v", marker, err)
		}
		if d.Kind != "plist" {
			t.Fatalf("marker %#02x: kind = %q, want plist", marker, d.Kind)
		}
		for _, k := range d.PlistKeys {
			if strings.Contains(k, "\x00") || len(k) > 200 {
				t.Fatalf("marker %#02x: garbage key %q", marker, k)
			}
		}
	}
}

// BenchmarkHeadCapture isolates the syscall pair Probe dropped: the old shape
// hashed the file, seeked back and read the head into a fresh buffer; the new
// one keeps those bytes during the hash pass. Probe itself has too many other
// readers on the path for one seek+read to show above the noise.
func BenchmarkHeadCapture(b *testing.B) {
	p := filepath.Join(b.TempDir(), "h")
	if err := os.WriteFile(p, bytes.Repeat([]byte{1}, 4096), 0o644); err != nil {
		b.Fatal(err)
	}
	b.Run("second-read", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			f, err := os.Open(p)
			if err != nil {
				b.Fatal(err)
			}
			if _, err := hashTargetN(f, 4096, 4096, nil); err != nil {
				b.Fatal(err)
			}
			if _, err := f.Seek(0, io.SeekStart); err != nil {
				b.Fatal(err)
			}
			buf := make([]byte, 512)
			f.Read(buf)
			f.Close()
		}
	})
	b.Run("one-pass", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			f, err := os.Open(p)
			if err != nil {
				b.Fatal(err)
			}
			var buf [512]byte
			hc := headCapture{buf: buf[:]}
			if _, err := hashTargetN(f, 4096, 4096, &hc); err != nil {
				b.Fatal(err)
			}
			f.Close()
		}
	})
}
