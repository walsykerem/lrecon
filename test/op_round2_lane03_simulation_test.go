package main

// Round 2 audit, lane 03: real behavior simulations inside the package.
// Each test runs a real path with meaningful input without loosening production code.

import (
	"context"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

// ---------- G1: extops + exttool ----------

func TestR2L03ExtOpRegistryDispatch(t *testing.T) {
	const n = "r2l03probe"
	if _, exists := extOps[n]; exists {
		t.Fatalf("probe name already registered")
	}
	called := 0
	registerExtOp(extOp{name: n, route: "L", desc: "lane03 probe", needs: true,
		run: func(path string, args []string) (any, error) {
			called++
			return path + "|" + strings.Join(args, ","), nil
		}})
	defer delete(extOps, n)

	got, err := runExtOp(n, "target.bin", []string{"a", "b"})
	if err != nil || got != "target.bin|a,b" || called != 1 {
		t.Fatalf("runExtOp = %v, %v (called=%d)", got, err, called)
	}

	_, err = runExtOp(n, "", nil)
	if err == nil || err.Error() != `op "r2l03probe" needs a target path` || called != 1 {
		t.Fatalf("missing path err = %v (called=%d)", err, called)
	}

	_, err = runExtOp("r2l03does-not-exist", "", nil)
	if err == nil || !strings.Contains(err.Error(), "unknown ext op") || !strings.Contains(err.Error(), "--list-ext-ops") {
		t.Fatalf("unknown err = %v", err)
	}

	names := extOpNames()
	if !slices.IsSorted(names) || !slices.Contains(names, n) {
		t.Fatalf("extOpNames not sorted/incomplete: %v", names)
	}

	panics := []struct {
		op   extOp
		want string
	}{
		{extOp{name: "", desc: "d", run: func(string, []string) (any, error) { return nil, nil }}, "without name or run"},
		{extOp{name: "x", desc: "d"}, "without name or run"},
		{extOp{name: "x", route: "L", run: func(string, []string) (any, error) { return nil, nil }}, "has no description"},
		{extOp{name: "x", route: "Z", desc: "d", run: func(string, []string) (any, error) { return nil, nil }}, "has route Z"},
	}
	for _, c := range panics {
		func() {
			defer func() {
				r := recover()
				if r == nil || !strings.Contains(String(r), c.want) {
					t.Errorf("registerExtOp(%q) panic = %v, want %q", c.op.name, r, c.want)
				}
			}()
			registerExtOp(c.op)
		}()
	}
	registerExtOp(extOp{name: "r2l03dup", route: "L", desc: "d", run: func(string, []string) (any, error) { return nil, nil }})
	defer delete(extOps, "r2l03dup")
	func() {
		defer func() {
			r := recover()
			if r == nil || !strings.Contains(String(r), "duplicate ext op: r2l03dup") {
				t.Errorf("duplicate panic = %v", r)
			}
		}()
		registerExtOp(extOp{name: "r2l03dup", route: "L", desc: "d", run: func(string, []string) (any, error) { return nil, nil }})
	}()
}

// String converts a recovered panic value (normally an error/string).
func String(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case error:
		return x.Error()
	default:
		return ""
	}
}

func TestR2L03ExtErrorLinePrefersCause(t *testing.T) {
	cases := []struct{ in, want string }{
		{"INFO banner\nerror: no device\nmore", "error: no device"},
		{"\n\n first line \nsecond", "first line"},
		{"", ""},
	}
	for _, c := range cases {
		if got := extErrorLine(c.in); got != c.want {
			t.Errorf("extErrorLine(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestR2L03ExtRunRefusalKinds(t *testing.T) {
	dir := t.TempDir()
	// Non-zero exit prints an "error:" banner on stderr: must be kindNoEngine
	// naming that banner, never kindInternal.
	bad := filepath.Join(dir, "bad.sh")
	if err := os.WriteFile(bad, []byte("#!/bin/sh\necho 'info line' >&2\necho 'error: wrong artifact' >&2\nexit 3\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	_, _, err := extRun(context.Background(), "fake", bad, "arg")
	var ref *extRefusal
	if !errors.As(err, &ref) || ref.kind != kindNoEngine || !strings.Contains(ref.msg, "error: wrong artifact") {
		t.Fatalf("extRun nonzero = %v", err)
	}
	if ref.Error() != ref.msg {
		t.Fatalf("extRefusal.Error = %q", ref.Error())
	}

	// Timeout with a real sleeping process: must be kindTimeout.
	slow := filepath.Join(dir, "slow.sh")
	if err := os.WriteFile(slow, []byte("#!/bin/sh\nsleep 5\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	_, _, err = extRun(ctx, "slow", slow)
	if !errors.As(err, &ref) || ref.kind != kindTimeout || !strings.Contains(ref.msg, "context deadline exceeded") {
		t.Fatalf("extRun timeout = %v", err)
	}
}

// ---------- G2: extract ----------

func TestR2L03CheckMemberSecurity(t *testing.T) {
	bad := []string{"", "/etc/passwd", "../x", "a/../b", `a\b`, "C:\\x"}
	for _, m := range bad {
		if err := checkMember(m); err == nil {
			t.Errorf("checkMember(%q) accepted", m)
		}
	}
	for _, m := range []string{"ok.bin", "a/b/c.bin", "a..b"} {
		if err := checkMember(m); err != nil {
			t.Errorf("checkMember(%q) = %v", m, err)
		}
	}
}

func TestR2L03CappedByEnvAndCapWords(t *testing.T) {
	t.Setenv("LRECON_BUNDLE_CAP_BYTES", "")
	if got := cappedByEnv(1000); got != 1000 {
		t.Fatalf("unset = %d", got)
	}
	t.Setenv("LRECON_BUNDLE_CAP_BYTES", "100")
	if got := cappedByEnv(1000); got != 100 {
		t.Fatalf("cap = %d", got)
	}
	t.Setenv("LRECON_BUNDLE_CAP_BYTES", "2000")
	if got := cappedByEnv(1000); got != 1000 {
		t.Fatalf("above ceiling = %d", got)
	}
	if got := capWords(512); got != "512 bytes" {
		t.Fatalf("capWords small = %q", got)
	}
	if got := capWords(2 << 20); !strings.HasSuffix(got, "MB") {
		t.Fatalf("capWords large = %q", got)
	}
}

func TestR2L03WriteCappedOverLimitKeepsTarget(t *testing.T) {
	dir := t.TempDir()
	payload := strings.Repeat("x", 64)
	n, err := writeCapped(dir, "out.bin", strings.NewReader(payload), 8)
	// writeCapped copies at most limit+1 bytes: n is 9, not the full payload.
	if err == nil || n != 9 || !strings.Contains(err.Error(), "above the") {
		t.Fatalf("writeCapped = %d, %v", n, err)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "out.bin")); !os.IsNotExist(statErr) {
		t.Fatalf("target left behind: %v", statErr)
	}
	left, _ := filepath.Glob(filepath.Join(dir, "*"))
	if len(left) != 0 {
		t.Fatalf("temp files left: %v", left)
	}
	n, err = writeCapped(dir, "ok.bin", strings.NewReader("abc"), 8)
	if err != nil || n != 3 {
		t.Fatalf("under cap = %d, %v", n, err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "ok.bin")); string(b) != "abc" {
		t.Fatalf("content = %q", b)
	}
}

func TestR2L03ExtractAllEmptyDirAndZeroSizeMember(t *testing.T) {
	var d Digest
	if err := ExtractAll("whatever.zip", "", &d); err == nil || !strings.Contains(err.Error(), "empty output directory") {
		t.Fatalf("empty dir err = %v", err)
	}

	dir := t.TempDir()
	zp := writeZip(t, "zero.zip", []zipEntry{{name: "empty.txt", data: []byte{}}, {name: "full.txt", data: []byte("hi")}})
	if err := ExtractAll(zp, dir, &d); err != nil {
		t.Fatalf("ExtractAll zero-size: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "empty.txt")); err != nil {
		t.Fatalf("zero-size member not extracted: %v", err)
	}
	if b, err := os.ReadFile(filepath.Join(dir, "full.txt")); err != nil || string(b) != "hi" {
		t.Fatalf("full member = %q, %v", b, err)
	}
}

// ---------- G3: firmware ----------

func TestR2L03FirmwareKindTable(t *testing.T) {
	cases := []struct {
		head []byte
		want string
	}{
		{[]byte{0x19, 0x85}, "jffs2"},
		{[]byte{0x1f, 0x8b, 0x08}, "gzip"},
		{[]byte{0xfd, '7', 'z', 'X', 'Z', 0}, "xz"},
		{[]byte{'h', 's', 'q', 's'}, "squashfs"},
		{[]byte{'U', 'B', 'I', '#'}, "ubi"},
		{[]byte("junk\x19\x85"), ""}, // short magics only at offset 0
	}
	for _, c := range cases {
		if got := firmwareKind(c.head); got != c.want {
			t.Errorf("firmwareKind(%x) = %q, want %q", c.head, got, c.want)
		}
	}
}

func TestR2L03FirmwareHitsSortedAndCapped(t *testing.T) {
	buf := append([]byte("xx"), []byte("hsqs")...) // off 2
	buf = append(buf, []byte("yy")...)
	buf = append(buf, []byte("HDR0")...) // off 8
	hits, capped := firmwareHits(buf)
	if capped {
		t.Fatalf("unexpected cap")
	}
	if len(hits) != 2 || hits[0].off != 2 || hits[0].name != "squashfs" || hits[1].off != 8 || hits[1].name != "trx" {
		t.Fatalf("hits = %+v", hits)
	}

	// Blob with >40 hits of one magic: firmwareHits must truncate and flag cap.
	var big []byte
	for i := 0; i < 45; i++ {
		big = append(big, []byte("hsqs")...)
	}
	_, capped = firmwareHits(big)
	if !capped {
		t.Fatalf("cap not reported")
	}
}

func TestR2L03FirmwareProbeAndBootimg(t *testing.T) {
	img := fxBootimg()
	d := fxProbe(t, "boot.img", img)
	if d.FirmwareKind == "" {
		t.Fatalf("firmware kind not set: %+v", d)
	}

	// Valid bootimg: parsed note. Corrupt page to 1024: fwExtInvalid skip.
	var good Digest
	good.FileSize = int64(len(img))
	fwExtBootimg(append([]byte(nil), img[:1660]...), &good)
	line := ""
	for _, n := range good.Notes {
		line += n + " "
	}
	if !strings.Contains(line, "bootimg v0") || good.Coverage == nil || good.Coverage.Parsed == 0 {
		t.Fatalf("good bootimg notes=%q cov=%+v", line, good.Coverage)
	}

	bad := append([]byte(nil), img[:1660]...)
	binary.LittleEndian.PutUint32(bad[36:], 1024)
	var invalid Digest
	invalid.FileSize = int64(len(img))
	fwExtBootimg(bad, &invalid)
	if !skippedReasons(invalid)["firmware-ext-header-invalid"] {
		t.Fatalf("page 1024 did not skip invalid: %+v", invalid.Skipped)
	}

	// Layout needs more bytes than FileSize: length disagreement is skipped.
	small := append([]byte(nil), img[:1660]...)
	var short Digest
	short.FileSize = 1
	fwExtBootimg(small, &short)
	if !skippedReasons(short)["firmware-ext-length-disagree"] {
		t.Fatalf("short file did not skip length: %+v", short.Skipped)
	}
}

// ---------- G4: formats ----------

func TestR2L03InspectSQLite(t *testing.T) {
	hdr := make([]byte, 100)
	copy(hdr, "SQLite format 3\x00")
	binary.BigEndian.PutUint16(hdr[16:], 4096)
	binary.BigEndian.PutUint32(hdr[96:], 3004005) // 3.4.5
	dir := t.TempDir()
	p := filepath.Join(dir, "db.sqlite")
	if err := os.WriteFile(p, hdr, 0o644); err != nil {
		t.Fatal(err)
	}
	var d Digest
	inspectSQLite(p, &d)
	if d.SQLitePageSize != 4096 || d.SQLiteVersion != "3.4.5" || d.SQLiteWAL {
		t.Fatalf("sqlite = page %d ver %q wal %v", d.SQLitePageSize, d.SQLiteVersion, d.SQLiteWAL)
	}

	// page size value 1 means 65536.
	binary.BigEndian.PutUint16(hdr[16:], 1)
	os.WriteFile(p, hdr, 0o644)
	d = Digest{}
	inspectSQLite(p, &d)
	if d.SQLitePageSize != 65536 {
		t.Fatalf("page1 = %d", d.SQLitePageSize)
	}

	// -wal file present -> WAL.
	binary.BigEndian.PutUint16(hdr[16:], 4096)
	os.WriteFile(p, hdr, 0o644)
	os.WriteFile(p+"-wal", []byte("wal"), 0o644)
	d = Digest{}
	inspectSQLite(p, &d)
	if !d.SQLiteWAL {
		t.Fatalf("wal not detected")
	}
}

func TestR2L03XMLPlistKeysDedupAndValue(t *testing.T) {
	b := []byte(`<?xml version="1.0"?><plist><dict>` +
		`<key>CFBundleName</key><string>MyApp</string>` +
		`<key>CFBundleName</key><string>MyApp</string>` +
		`<key>UnknownKey</key><string>nope</string>` +
		`</dict></plist>`)
	var d Digest
	keys := xmlPlistKeys(b, &d)
	if len(keys) != 2 || !strings.Contains(keys[0], "CFBundleName") || !strings.Contains(keys[0], "MyApp") {
		t.Fatalf("keys = %v", keys)
	}
	// xmlPlistKeys keeps unrecognised keys as bare names but never their values:
	// the allowlist gates value extraction, not the key itself.
	joined := strings.Join(keys, " ")
	if !strings.Contains(joined, "UnknownKey") || strings.Contains(joined, "nope") {
		t.Fatalf("keys = %v", keys)
	}
}

func TestR2L03IsCodeSignatureAndXMLPlist(t *testing.T) {
	cases := []struct {
		h    []byte
		want bool
	}{
		{[]byte{0xfa, 0xde, 0x0c, 0x00}, true},
		{[]byte{0xfa, 0xde, 0x0c, 0xff}, true},
		{[]byte{0xfa, 0xde, 0x0d, 0x00}, false},
		{[]byte{0xfa, 0xde}, false},
	}
	for _, c := range cases {
		if got := isCodeSignature(c.h); got != c.want {
			t.Errorf("isCodeSignature(%x) = %v", c.h, got)
		}
	}
	if !isXMLPlist([]byte("  <?xml version=\"1.0\"?><plist/>")) || isXMLPlist([]byte("bplist00")) {
		t.Fatalf("isXMLPlist misclassified")
	}
}

func TestR2L03BplistKeysDedup(t *testing.T) {
	objs := []sfBP{
		{kind: 'd', keys: []byte{1, 2, 1}, vals: []byte{3, 4, 4}}, // key ref 1 twice
		{kind: 's', str: "CFBundleIdentifier"},
		{kind: 's', str: "CFBundleVersion"},
		{kind: 's', str: "com.example.app"},
		{kind: 's', str: "1.2.3"},
	}
	b := sfBplist(objs)
	var d Digest
	keys := bplistKeys(b, &d)
	joined := strings.Join(keys, " ")
	if strings.Count(joined, "CFBundleIdentifier") != 1 || !strings.Contains(joined, "com.example.app") {
		t.Fatalf("bplistKeys = %v", keys)
	}
}

// ---------- G5: java + klib ----------

func TestR2L03JavaVersionAndMatch(t *testing.T) {
	cases := []struct {
		major int
		want  string
	}{
		{45, "jdk 1.1"},
		{48, "jdk 1.4"},
		{49, "java 5"},
		{52, "java 8"},
	}
	for _, c := range cases {
		if got := javaVersion(c.major); got != c.want {
			t.Errorf("javaVersion(%d) = %q", c.major, got)
		}
	}
	head := make([]byte, 10)
	binary.BigEndian.PutUint32(head, javaMagic)
	binary.BigEndian.PutUint16(head[6:], 52)
	binary.BigEndian.PutUint16(head[8:], 5)
	if !javaMatch(head, 100) {
		t.Fatalf("valid class not matched")
	}
	// A real fat Mach-O (cafebabe + valid arch count/CPU type) shares the
	// magic but must be rejected by javaMatch.
	fat := make([]byte, 24)
	binary.BigEndian.PutUint32(fat, 0xcafebabe)
	binary.BigEndian.PutUint32(fat[4:], 1)   // one arch
	binary.BigEndian.PutUint32(fat[8:], 7)   // CPU_TYPE_X86_64-ish (valid CPU type)
	binary.BigEndian.PutUint32(fat[16:], 28) // offset
	binary.BigEndian.PutUint32(fat[20:], 4)  // size
	if javaMatch(fat, 1024) {
		t.Fatalf("fat Mach-O was matched as java")
	}
	if javaMatch(head[:8], 100) {
		t.Fatalf("short header should not match")
	}
}

func TestR2L03InspectJavaClass(t *testing.T) {
	b := classBytes("com/example/Demo", 52, 0)
	p := writeTemp(t, "Demo.class", b)
	var d Digest
	inspectJava(p, &d)
	if d.Format != "class" || d.Names != "com/example/Demo" || d.Toolchain != "java 8" {
		t.Fatalf("java = fmt %q names %q toolchain %q", d.Format, d.Names, d.Toolchain)
	}
	// module-info must be skipped.
	modp := writeTemp(t, "module-info.class", classBytes("module-info", 53, javaACCModule))
	var md Digest
	inspectJava(modp, &md)
	if !skippedReasons(md)["module-info"] {
		t.Fatalf("module-info not skipped: %+v", md.Skipped)
	}
}

func TestR2L03KlibMajorAndNames(t *testing.T) {
	for _, v := range []string{"1.0", "2.1"} {
		if _, ok := klibMajor(v); !ok {
			t.Errorf("klibMajor(%q) rejected", v)
		}
	}
	// klibMajor only parses the leading component; the {1,2} allowlist is a
	// separate check in inspectKlib. 3.0 parses to major 3.
	if got, ok := klibMajor("3.0"); !ok || got != 3 {
		t.Fatalf("klibMajor(3.0) = %d, %v", got, ok)
	}
	frag := klibFragment("kotlin.text", "String", "List")
	names, err := knmNames(frag)
	if err != nil || len(names) == 0 {
		t.Fatalf("knmNames = %v, %v", names, err)
	}
	joined := strings.Join(names, " ")
	if !strings.Contains(joined, "kotlin.text") {
		t.Fatalf("package missing: %v", names)
	}
	// Out-of-range class_name id must error, not panic.
	bad := pbBytesField(1, pbBytesField(1, []byte("p")))
	bad = append(bad, pbBytesField(173, []byte("p"))...)
	bad = append(bad, pbBytesField(174, []byte{9})...)
	if _, err := knmNames(bad); err == nil {
		t.Fatalf("bad class id did not error")
	}
}

func TestR2L03InspectKlibArchive(t *testing.T) {
	files := map[string][]byte{
		"default/manifest":         klibManifest("2.0", "1.1", "2.0.0"),
		"default/linkdata/pkg.knm": klibFragment("kotlin.collections", "Map"),
	}
	p := klibArchive(t, "sample.klib", files)
	var d Digest
	inspectKlib(p, &d)
	if !slices.Contains(d.Imports, "kotlin.collections") && !strings.Contains(d.Names, "kotlin.collections") {
		t.Fatalf("klib imports=%v names=%q", d.Imports, d.Names)
	}
}

// ---------- G6: lua + lsda ----------

func TestR2L03LuaHeaders(t *testing.T) {
	cases := []struct {
		blob      []byte
		toolchain string
	}{
		{lua51(), "lua 5.1"},
		{lua52(), "lua 5.2"},
		{lua5x(0x53), "lua 5.3"},
		{lua5x(0x54), "lua 5.4"},
	}
	for _, c := range cases {
		var d Digest
		inspectLuac(c.blob, &d)
		if d.Toolchain != c.toolchain {
			t.Errorf("luac toolchain = %q, want %q", d.Toolchain, c.toolchain)
		}
	}
	for _, c := range []struct {
		flags []byte
		want  string
	}{
		{[]byte{0x1b, 'L', 'J', 1, 0x02}, "luajit 2.0"},
		{[]byte{0x1b, 'L', 'J', 2, 0x16}, "luajit 2.1"},
	} {
		var d Digest
		inspectLuaJIT(c.flags, &d)
		if d.Toolchain != c.want {
			t.Errorf("luajit = %q, want %q", d.Toolchain, c.want)
		}
	}
}

func TestR2L03ItaniumTypeName(t *testing.T) {
	cases := []struct{ in, want string }{
		{"N3foo3barE", "foo::bar"},
		{"St6vector", "std::vector"},
		{"N3foo7__cxx113barE", "foo::bar"}, // 7__cxx11 is an inline namespace, dropped
	}
	for _, c := range cases {
		got, ok := itaniumTypeName(c.in)
		if !ok || got != c.want {
			t.Errorf("itaniumTypeName(%q) = %q, %v; want %q", c.in, got, ok, c.want)
		}
	}
	if _, ok := itaniumTypeName("N3foo"); ok {
		t.Fatalf("unterminated name accepted")
	}
}

func TestR2L03DedupeStarts(t *testing.T) {
	got := dedupeStarts([]uint64{1, 1, 2, 2, 2, 3, 1, 1})
	want := []uint64{1, 2, 3, 1}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("dedupeStarts = %v, want %v", got, want)
	}
}

// ---------- G7: misc / robustness ----------

func TestR2L03CsVerifyPagesZeroAndMismatch(t *testing.T) {
	cd := &csCodeDirectory{HashType: "sha1", HashTypeID: 1, HashSize: 20, PageSize: 4096, CodeLimit: 0, CodeSlots: 0}
	got := csVerifyPages(cd, make([]byte, 8192))
	if got.HashesOK || got.PagesChecked != 0 || !strings.Contains(got.Reason, "seals no pages") {
		t.Fatalf("zero pages = %+v", got)
	}

	cd = &csCodeDirectory{HashType: "sha1", HashTypeID: 1, HashSize: 20, PageSize: 4096, CodeLimit: 4096, CodeSlots: 2}
	got = csVerifyPages(cd, make([]byte, 8192))
	if got.HashesOK || !strings.Contains(got.Reason, "slots") {
		t.Fatalf("slot mismatch = %+v", got)
	}
}

func TestR2L03GateAbsence(t *testing.T) {
	// BytesScanned < FileSize -> incomplete read, so gateAbsence downgrades
	// all not-found answers to not_scanned (including names).
	d := Digest{Constants: consts{constNotDetected}, JIT: jitNotDetected, Names: nameNotRecovered,
		FileSize: 100, BytesScanned: 10, Coverage: &Coverage{Parsed: 0, Skipped: 0}}
	d.gateAbsence()
	if !slices.Equal(d.Constants, consts{constNotScanned}) || d.JIT != constNotScanned || d.Names != constNotScanned {
		t.Fatalf("gateAbsence = consts %v jit %q names %q", d.Constants, d.JIT, d.Names)
	}
	// Complete read with no parse failure leaves the honest not_detected alone.
	full := Digest{Constants: consts{constNotDetected}, JIT: jitNotDetected, Names: nameNotRecovered,
		FileSize: 100, BytesScanned: 100}
	full.gateAbsence()
	if !slices.Equal(full.Constants, consts{constNotDetected}) || full.JIT != jitNotDetected {
		t.Fatalf("complete gateAbsence changed answers: %+v", full)
	}
}

func TestR2L03NoPanicOnTruncatedInputs(t *testing.T) {
	// Deterministic truncated inputs: the parsers must refuse, not panic.
	seeds := [][]byte{
		{0xca, 0xfe, 0xba, 0xbe},
		[]byte("PK\x03\x04"),
		[]byte("bplist00"),
		[]byte("SQLite format 3"),
		{0x1f, 0x8b, 0x08},
	}
	for _, s := range seeds {
		for n := 0; n <= len(s); n++ {
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Errorf("panic on %x[:%d]: %v", s, n, r)
					}
				}()
				javaConstantPool(s[:n], 5)
				firmwareHits(s[:n])
				var d Digest
				inspectLuac(s[:n], &d)
				xmlPlistKeys(s[:n], &d)
			}()
		}
	}
}
