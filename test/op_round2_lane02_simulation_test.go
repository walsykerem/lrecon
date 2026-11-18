package main

// Round 2 LANE 02 independent simulation tests. Each test verifies the real
// behavior of production code with meaningful input; production code is not relaxed.

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestR2L02DartVersionHash(t *testing.T) {
	if got := dartVersionHash([]byte("0123456789abcdef0123456789abcdef")); got != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("32 hex = %q", got)
	}
	if got := dartVersionHash([]byte("0123456789abcdef0123456789abcde")); got != "" {
		t.Fatalf("31 hex = %q, want empty", got)
	}
	if got := dartVersionHash([]byte("0123456789abcdef0123456789abcdeG")); got != "" {
		t.Fatalf("uppercase G = %q, want empty", got)
	}
	if got := dartVersionHash([]byte("0123456789abcdef0123456789abcde ")); got != "" {
		t.Fatalf("space = %q, want empty", got)
	}
}

func TestR2L02DartSnapshotHeader(t *testing.T) {
	// Valid kind + length fitting in the file -> parsed, kind noted.
	d := dartDigest(t, dartSnapshotBytes(dartMagic, 32, 2), "flutter")
	if len(d.Skipped) != 0 || d.Coverage == nil || d.Coverage.Parsed != 1 {
		t.Fatalf("valid snapshot: skipped=%v coverage=%+v", d.Skipped, d.Coverage)
	}
	if !strings.Contains(strings.Join(d.Notes, "\n"), "kind=full-aot") {
		t.Fatalf("notes = %v, want kind=full-aot", d.Notes)
	}

	// If length exceeds the file, skip, not parsed.
	d = dartDigest(t, dartSnapshotBytes(dartMagic, 4096, 0), "flutter")
	if len(d.Skipped) != 1 || !hasReason(d, "version-hash-unmapped") {
		t.Fatalf("oversize: skipped=%v", d.Skipped)
	}
	if d.Coverage != nil && d.Coverage.Parsed != 0 {
		t.Fatalf("oversize parsed = %+v", d.Coverage)
	}

	// unknown kind -> skip.
	d = dartDigest(t, dartSnapshotBytes(dartMagic, 32, 7), "flutter")
	if len(d.Skipped) != 1 || !strings.Contains(d.Skipped[0].Detail, "snapshot kind 7") {
		t.Fatalf("bad kind: skipped=%v", d.Skipped)
	}

	// Foreign magic is never handled by the post reader.
	d = dartDigest(t, dartSnapshotBytes(0xdeadbeef, 32, 0), "flutter")
	if len(d.Skipped) != 0 || (d.Coverage != nil && d.Coverage.Parsed != 0) {
		t.Fatalf("foreign magic: skipped=%v coverage=%+v", d.Skipped, d.Coverage)
	}

	// For a non-flutter Kind the dart reader writes nothing (other post
	// readers' skips are separate; only the dart-specific trace is sought).
	d = dartDigest(t, dartSnapshotBytes(dartMagic, 32, 0), "elf")
	if hasReason(d, "version-hash-unmapped") || strings.Contains(strings.Join(d.Notes, "\n"), "dart snapshot:") {
		t.Fatalf("non-flutter: dart reader acted: skipped=%v notes=%v", d.Skipped, d.Notes)
	}
}

func TestR2L02DigestAbsenceContract(t *testing.T) {
	// "" = absent, null = not measured, [] = measured none (final.md 106).
	raw, err := json.Marshal(Digest{})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte(`"rpaths":null`)) || !bytes.Contains(raw, []byte(`"minos":""`)) {
		t.Fatalf("empty digest JSON = %s", raw)
	}
	raw, err = json.Marshal(Digest{Rpaths: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte(`"rpaths":[]`)) {
		t.Fatalf("empty slice JSON = %s", raw)
	}
}

func TestR2L02DexMapWitness(t *testing.T) {
	const size = 300
	mk := func(n int, typ0, off0, typ1, off1 uint32) []byte {
		b := make([]byte, size)
		binary.LittleEndian.PutUint32(b[dexHeaderSize:], uint32(n))
		binary.LittleEndian.PutUint16(b[dexHeaderSize+4:], uint16(typ0))
		binary.LittleEndian.PutUint32(b[dexHeaderSize+12:], off0)
		binary.LittleEndian.PutUint16(b[dexHeaderSize+16:], uint16(typ1))
		binary.LittleEndian.PutUint32(b[dexHeaderSize+24:], off1)
		return b
	}
	var d Digest
	// map_off == 0: no map_list, but this is not a refusal.
	if !dexMapWitness(nil, 0, 0, &d) || len(d.Notes) == 0 || !strings.Contains(d.Notes[0], "map_list absent") {
		t.Fatalf("map_off=0: ok=false notes=%v", d.Notes)
	}
	// Valid: one full header item (typ 0, offset 0) + a second item.
	d = Digest{}
	if !dexMapWitness(mk(2, 0, 0, 1, 256), size, dexHeaderSize, &d) {
		t.Fatal("valid map_list refused")
	}
	note := strings.Join(d.Notes, "\n")
	if !strings.Contains(note, "items=2") || !strings.Contains(note, "header") {
		t.Fatalf("map note = %q", note)
	}
	// Header item offset not 0 -> rejected.
	if dexMapWitness(mk(2, 0, 4, 1, 256), size, dexHeaderSize, &Digest{}) {
		t.Fatal("header item with nonzero offset accepted")
	}
	// Two header items -> rejected.
	if dexMapWitness(mk(2, 0, 0, 0, 0), size, dexHeaderSize, &Digest{}) {
		t.Fatal("two header items accepted")
	}
	// Offset goes backwards -> rejected.
	if dexMapWitness(mk(2, 0, 100, 1, 50), size, dexHeaderSize, &Digest{}) {
		t.Fatal("descending item offsets accepted")
	}
	// map_off inside the header -> rejected.
	if dexMapWitness(mk(1, 0, 0, 0, 0), size, 8, &Digest{}) {
		t.Fatal("map_off inside header accepted")
	}
}

func TestR2L02DexNamesAndPackerClaim(t *testing.T) {
	for name, want := range map[string]bool{
		"classes.dex": true, "classes1.dex": true, "classes10.dex": true,
		"classes.dex.dex": false, "xclasses.dex": false, "classes1.apk": false,
		"classes1x.dex": false, "classes-1.dex": false,
	} {
		if got := dexStandardName(name); got != want {
			t.Errorf("dexStandardName(%q) = %v, want %v", name, got, want)
		}
	}
	seen := map[string]bool{}
	hits := archivePackerClaim(nil, seen, "lib/arm64/libjiagu.so", "lib/arm64/libjiagu.so")
	if len(hits) != 1 || !strings.Contains(hits[0], "Qihoo 360 Jiagu") || !strings.Contains(hits[0], "entry lib/arm64/libjiagu.so") {
		t.Fatalf("first claim = %v", hits)
	}
	hits = archivePackerClaim(hits, seen, "lib/arm64/libjiagu.so", "lib/arm64/libjiagu.so")
	if len(hits) != 1 {
		t.Fatalf("duplicate claim = %v", hits)
	}
	hits = archivePackerClaim(hits, seen, "lib/arm64/libsgmain.so", "lib/arm64/libsgmain.so")
	if len(hits) != 2 || !strings.Contains(hits[1], "Alibaba SecurityGuard") {
		t.Fatalf("second claim = %v", hits)
	}
}

func TestR2L02DispatchClaimAndVerify(t *testing.T) {
	restoreReaders(t)
	const format = "r2l02test"
	reasonRegistry[format] = reasonSet("r2l02-skip")
	t.Cleanup(func() { delete(reasonRegistry, format) })
	register(reader{
		format:  format,
		reasons: []string{"r2l02-skip"},
		match: func(head []byte, size int64) bool {
			return len(head) > 0 && head[0] == 0xAB
		},
		inspect: func(path string, d *Digest) { d.parsed() },
	})
	head := []byte{0xAB, 0x01}
	d := Digest{Kind: "unknown"}
	path := writeTemp(t, "claim.bin", head)
	if !dispatch(path, head, int64(len(head)), &d) {
		t.Fatal("dispatch did not claim matching file")
	}
	if d.Kind != format || d.Format != format || d.Coverage == nil || d.Coverage.Parsed != 1 {
		t.Fatalf("claimed digest = kind %q format %q coverage %+v", d.Kind, d.Format, d.Coverage)
	}

	// Unmatched head -> no claim.
	d = Digest{Kind: "unknown"}
	if dispatch(path, []byte{0x00}, 1, &d) || d.Kind != "unknown" {
		t.Fatalf("unmatched digest = %+v", d)
	}
}

func TestR2L02DispatchRevertsUnattributedClaim(t *testing.T) {
	restoreReaders(t)
	const format = "r2l02revert"
	reasonRegistry[format] = reasonSet("r2l02-skip")
	t.Cleanup(func() { delete(reasonRegistry, format) })
	register(reader{
		format:  format,
		reasons: []string{"r2l02-skip"},
		match: func(head []byte, size int64) bool {
			return len(head) > 0 && head[0] == 0xCD
		},
		inspect: func(path string, d *Digest) { d.unparsed() },
	})
	head := []byte{0xCD}
	d := Digest{Kind: "unknown"}
	if !dispatch(writeTemp(t, "revert.bin", head), head, 1, &d) {
		t.Fatal("dispatch did not claim")
	}
	// No unit attributed (Parsed=0, Unknown=1, no claim/toolchain) -> revert.
	if d.Kind != "unknown" || d.Format != "" {
		t.Fatalf("unattributed claim not reverted: kind %q format %q", d.Kind, d.Format)
	}
}

func TestR2L02DispatchPostNeverOverridesKind(t *testing.T) {
	restoreReaders(t)
	const format = "r2l02post"
	reasonRegistry[format] = reasonSet("r2l02-skip")
	t.Cleanup(func() { delete(reasonRegistry, format) })
	register(reader{
		format:     format,
		reasons:    []string{"r2l02-skip"},
		post:       true,
		claimsKind: true,
		match: func(head []byte, size int64) bool {
			return len(head) > 0 && head[0] == 0xEF
		},
		inspect: func(path string, d *Digest) { d.parsed() },
	})
	head := []byte{0xEF}
	d := Digest{Kind: "elf"}
	dispatchPost(writeTemp(t, "post.bin", head), head, 1, &d)
	if d.Kind != "elf" {
		t.Fatalf("post reader overrode magic kind: %q", d.Kind)
	}
	if d.Coverage == nil || d.Coverage.Parsed != 1 {
		t.Fatalf("post reader did not inspect: %+v", d.Coverage)
	}
}

func TestR2L02DispatchVerifyReadersPanics(t *testing.T) {
	restoreReaders(t)
	const format = "r2l02noset"
	delete(reasonRegistry, format) // guarantee: no set
	register(reader{
		format:  format,
		reasons: []string{"r2l02-skip"},
		post:    true,
		inspect: func(path string, d *Digest) {},
	})
	defer func() {
		if r := recover(); r == nil || !strings.Contains(fmt.Sprint(r), "has no reason set") {
			t.Fatalf("verifyReaders panic = %v", r)
		}
	}()
	verifyReaders()
}

func TestR2L02DotnetRead7AndHeader(t *testing.T) {
	if s, n, ok := read7([]byte{0x03, 'a', 'b', 'c'}, 0, 10); !ok || s != "abc" || n != 4 {
		t.Fatalf("read7 short = %q %d %v", s, n, ok)
	}
	if s, n, ok := read7([]byte{0x80, 0x01, 'x'}, 0, 1); ok || s != "" || n != 0 {
		t.Fatalf("read7 over max = %q %d %v", s, n, ok)
	}
	if _, _, ok := read7([]byte{0x84}, 0, 4096); ok {
		t.Fatal("read7 accepted truncated string")
	}
	if _, _, ok := read7([]byte{0x80, 0x80, 0x80, 0x80, 0x80}, 0, 10); ok {
		t.Fatal("read7 accepted 5 continuation bytes")
	}

	mkHeader := func(major uint32, files uint32) []byte {
		b := make([]byte, 64)
		binary.LittleEndian.PutUint32(b[0:], major)
		binary.LittleEndian.PutUint32(b[4:], 0) // minor
		binary.LittleEndian.PutUint32(b[8:], files)
		b[12], b[13] = 1, 'x' // id "x"
		if major >= 2 {
			binary.LittleEndian.PutUint64(b[14:], 100) // depOff
			binary.LittleEndian.PutUint64(b[22:], 10)  // depSize
			binary.LittleEndian.PutUint64(b[30:], 200) // rtOff
			binary.LittleEndian.PutUint64(b[38:], 20)  // rtSize
		}
		return b
	}
	h, ok := parseBundleHeader(mkHeader(6, 1))
	if !ok || h.major != 6 || h.files != 1 || h.id != "x" || h.depOff != 100 || h.entriesFrom != 54 {
		t.Fatalf("v6 header = %+v %v", h, ok)
	}
	h, ok = parseBundleHeader(mkHeader(1, 1))
	if !ok || h.major != 1 || h.entriesFrom != 14 {
		t.Fatalf("v1 header = %+v %v", h, ok)
	}
	if _, ok := parseBundleHeader(mkHeader(6, 0)); ok {
		t.Fatal("zero file count accepted")
	}
	if _, ok := parseBundleHeader(make([]byte, 8)); ok {
		t.Fatal("8-byte header accepted")
	}
}

func TestR2L02DotnetEntryAndRuntime(t *testing.T) {
	mk := func(major uint32) []byte {
		fixed := 16
		if major >= 6 {
			fixed = 24
		}
		b := make([]byte, fixed+1+6)
		binary.LittleEndian.PutUint64(b[0:], 100)
		binary.LittleEndian.PutUint64(b[8:], 50)
		if major >= 6 {
			binary.LittleEndian.PutUint64(b[16:], 40)
		}
		b[fixed] = 1 // assembly
		b[fixed+1] = 5
		copy(b[fixed+2:], "a.dll")
		return b
	}
	for _, major := range []uint32{2, 6} {
		e, next, ok := parseBundleEntry(mk(major), major)
		if !ok || e.offset != 100 || e.size != 50 || e.kind != 1 || e.path != "a.dll" {
			t.Fatalf("major %d entry = %+v %d %v", major, e, next, ok)
		}
		if major >= 6 && e.compressed != 40 {
			t.Fatalf("major %d compressed = %d, want 40", major, e.compressed)
		}
	}

	target := bundleRuntimeTarget([]byte(`{"runtimeTarget":{"name":"net6.0/linux-x64"}}`))
	if target != "net6.0" {
		t.Fatalf("runtimeTarget = %q", target)
	}
	if v := bundleRuntimeVersion([]byte(`{"framework":{"version":"6.0.1"}}`)); v != "6.0.1" {
		t.Fatalf("framework version = %q", v)
	}
	if v := bundleRuntimeVersion([]byte(`{"tfm":"net6.0"}`)); v != "net6.0" {
		t.Fatalf("tfm fallback = %q", v)
	}
	if v := bundleRuntimeVersion([]byte(`{}`)); v != "" {
		t.Fatalf("empty version = %q", v)
	}
}

func TestR2L02ErrorsClassifyAndFlags(t *testing.T) {
	cases := []struct {
		msg  string
		want errorKind
	}{
		{`job needs "address"`, kindNeedsArg},
		{"live target out of scope", kindOutOfScope},
		{"adb shell exit status 1", kindNoEngine},
		{"open /no/such/file: no such file", kindIO},
		{"state conflict: snapshot in use", kindStateConflict},
		{"runtime error: index out of range", kindInternal},
		{"read cap above the limit", kindBadArg},
		{"deadline exceeded after 5s", kindTimeout},
	}
	for _, c := range cases {
		if got := classify(c.msg); got != c.want {
			t.Errorf("classify(%q) = %q, want %q", c.msg, got, c.want)
		}
	}
	if !engineExitFailed("adb: exit status 1") || !engineExitFailed("cdp exit status 2") {
		t.Fatal("engineExitFailed missed engine prefix")
	}
	if engineExitFailed("exit status 1") || engineExitFailed("/bin/false: exit status 1") {
		t.Fatal("engineExitFailed flagged bare exit status")
	}
	if !containsAny("abc def", "zz", "de") || containsAny("abc", "de") {
		t.Fatal("containsAny wrong")
	}

	for args, want := range map[string]bool{
		"":               false,
		"--json":         true,
		"target --json":  true,
		"-- --json":      false,
		"--json=false":   false,
		"--json=garbage": true,
		"-x":             false,
	} {
		if got := sawJSON(strings.Fields(args)); got != want {
			t.Errorf("sawJSON(%q) = %v, want %v", args, got, want)
		}
	}

	fs := flag.NewFlagSet("r2l02", flag.ContinueOnError)
	fs.String("op", "", "")
	fs.Bool("json", false, "")
	if err := fs.Parse([]string{"--op", "--json"}); err != nil {
		t.Fatal(err)
	}
	name, value := swallowedFlag(fs)
	if name != "op" || value != "--json" {
		t.Fatalf("swallowedFlag = %q %q", name, value)
	}
}

func TestR2L02EvidenceCanonicalAndBudget(t *testing.T) {
	a := Digest{Kind: "elf", Path: "/one/place", Deps: []Dep{{Path: "b", Version: "2"}, {Path: "a", Version: "1"}}}
	b := a
	b.Path = "/another/place"
	ca, err := canonicalJSON(a)
	if err != nil {
		t.Fatal(err)
	}
	cb, err := canonicalJSON(b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ca, cb) {
		t.Fatalf("Path leaked into canonical JSON: %s vs %s", ca, cb)
	}
	ev, err := evidenceLine(a)
	if err != nil {
		t.Fatal(err)
	}
	if ev != evidenceLineFromCanonical(ca) || !strings.HasPrefix(ev, "evidence: sha256:") || !strings.HasSuffix(ev, "\n") {
		t.Fatalf("evidence line = %q", ev)
	}

	mark := "evidence: sha256:abc\n"
	if out := digestTextWith(Digest{Kind: "elf"}, mark, 0); out != "kind: elf\ncoverage: of N unknown\n"+mark {
		t.Fatalf("unbounded = %q", out)
	}
	out := digestTextWith(Digest{Kind: "elf"}, mark, 10)
	if !strings.HasPrefix(out, "note: truncated at 0 of ") || !strings.HasSuffix(out, mark) {
		t.Fatalf("zero-room budget = %q", out)
	}
	if !strings.HasSuffix(digestTextWith(Digest{Kind: "elf"}, mark, 4096), mark) {
		t.Fatal("evidence line missing from roomy budget")
	}
}

func TestR2L02EvidenceExplainField(t *testing.T) {
	d := Digest{
		Kind:    "elf",
		Claims:  []Claim{{Value: "solc 0.8.21", Source: "cbor-trailer", ByteOffset: 16}},
		Skipped: []Skip{{Reason: "dart-version-unmapped", Detail: "snapshot header truncated"}},
	}
	if out, err := ExplainField(d, "cbor-trailer"); err != nil || !strings.Contains(out, "claim: solc 0.8.21 (cbor-trailer @0x10)") || !strings.Contains(out, "rule_id: cbor-trailer") {
		t.Fatalf("claim field = %q %v", out, err)
	}
	if out, err := ExplainField(d, "dart"); err != nil || !strings.Contains(out, "reason: dart-version-unmapped: snapshot header truncated") {
		t.Fatalf("reason field = %q %v", out, err)
	}
	if out, err := ExplainField(d, "kind"); err != nil || !strings.Contains(out, "attribution: none") {
		t.Fatalf("contract field = %q %v", out, err)
	}
	if _, err := ExplainField(d, "no-such-field"); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unknown field err = %v", err)
	}
	if got := ruleIDVersion("x"); got != "lrecon rule x v"+version {
		t.Fatalf("ruleIDVersion = %q", got)
	}
}

func TestR2L02EvmSolcItemAndMetadata(t *testing.T) {
	if v, ok := evmSolc(2, []byte{0, 8, 21}); !ok || v != "0.8.21" {
		t.Fatalf("compact solc = %q %v", v, ok)
	}
	if v, ok := evmSolc(2, []byte{0, 8, 100}); ok || v != "" {
		t.Fatalf("out-of-range compact = %q %v", v, ok)
	}
	if v, ok := evmSolc(3, []byte("0.7.6")); !ok || v != "0.7.6" {
		t.Fatalf("semver solc = %q %v", v, ok)
	}
	if v, ok := evmSolc(3, []byte("0.8.21-rc1")); ok || v != "" {
		t.Fatalf("prerelease semver = %q %v", v, ok)
	}
	if _, ok := evmSolc(1, []byte{0, 8, 21}); ok {
		t.Fatal("unsupported major accepted")
	}

	if maj, body, next, ok := evmItem([]byte{0x42, 1, 2}, 0); !ok || maj != 2 || !bytes.Equal(body, []byte{1, 2}) || next != 3 {
		t.Fatalf("bytes item = %d %v %d %v", maj, body, next, ok)
	}
	if maj, body, next, ok := evmItem([]byte{0x63, 'a', 'b', 'c'}, 0); !ok || maj != 3 || string(body) != "abc" || next != 4 {
		t.Fatalf("text item = %d %q %d %v", maj, body, next, ok)
	}
	if maj, _, next, ok := evmItem([]byte{0xf4}, 0); !ok || maj != 7 || next != 1 {
		t.Fatalf("bool item = %d %d %v", maj, next, ok)
	}
	if _, _, _, ok := evmItem([]byte{0x82, 1}, 0); ok {
		t.Fatal("array item accepted")
	}
	if _, _, _, ok := evmItem([]byte{0x43, 1}, 0); ok {
		t.Fatal("truncated byte string accepted")
	}

	if n, size, ok := evmArg([]byte{0x07}, 0, 7); !ok || n != 7 || size != 1 {
		t.Fatalf("inline arg = %d %d %v", n, size, ok)
	}
	if n, size, ok := evmArg([]byte{0x18, 42}, 0, 24); !ok || n != 42 || size != 2 {
		t.Fatalf("1-byte arg = %d %d %v", n, size, ok)
	}
	if n, size, ok := evmArg([]byte{0x19, 0x01, 0x02}, 0, 25); !ok || n != 258 || size != 3 {
		t.Fatalf("2-byte arg = %d %d %v", n, size, ok)
	}
	if n, size, ok := evmArg([]byte{0x1a, 0, 0, 1, 0}, 0, 26); !ok || n != 256 || size != 5 {
		t.Fatalf("4-byte arg = %d %d %v", n, size, ok)
	}
	if _, _, ok := evmArg([]byte{0x1b, 0, 0, 0, 0, 0, 0, 0, 0}, 0, 27); ok {
		t.Fatal("8-byte arg accepted")
	}
	if _, _, ok := evmArg([]byte{0x18}, 0, 24); ok {
		t.Fatal("truncated 1-byte arg accepted")
	}

	// map(1): key text(4)="solc", value bytes(3)=00 08 15 -> 0.8.21
	meta := []byte{0xa1, 0x64, 's', 'o', 'l', 'c', 0x43, 0x00, 0x08, 0x15}
	m, ok := evmParseMetadata(meta)
	if !ok || m.solc != "0.8.21" || m.recognized != 1 || m.solcOff != 6 {
		t.Fatalf("metadata = %+v %v", m, ok)
	}
	// Single unknown key: recognized=0 -> rejected.
	if _, ok := evmParseMetadata([]byte{0xa1, 0x63, 'f', 'o', 'o', 0x01, 0x00}); ok {
		t.Fatal("unknown-only map accepted")
	}
	if _, ok := evmParseMetadata([]byte{0x81, 0x00}); ok {
		t.Fatal("array instead of map accepted")
	}
}

func TestR2L02CxxTableSymbols(t *testing.T) {
	for name, want := range map[string]string{
		"_ZTV3Foo":        "_ZTV",
		"_ZTI3Foo":        "_ZTI",
		"_ZTS3Foo":        "_ZTS",
		"__ZTV3Foo":       "_ZTV",
		"_ZTV3Foo.llvm.5": "_ZTV",
		"_ZN3Foo3barEv":   "",
		"_ZSt4cout":       "",
	} {
		if got := cxxTableKind(name); got != want {
			t.Errorf("cxxTableKind(%q) = %q, want %q", name, got, want)
		}
	}
	if got := cxxTableType("_ZTI3Foo"); got != "Foo" {
		t.Fatalf("cxxTableType(_ZTI3Foo) = %q", got)
	}
	if got := cxxTableType("_ZTVN3Foo3BarE"); got != "Foo::Bar" {
		t.Fatalf("cxxTableType(nested) = %q", got)
	}
	if got := cxxTableType("_ZTV3Foo.llvm.7"); got != "Foo" {
		t.Fatalf("cxxTableType(.llvm) = %q", got)
	}
	if got := cxxTableType("plain"); got != "" {
		t.Fatalf("cxxTableType(plain) = %q", got)
	}
	if got := cxxShorten("abcdef", 3); got != "abc…" {
		t.Fatalf("cxxShorten cut = %q", got)
	}
	if got := cxxShorten("abc", 3); got != "abc" {
		t.Fatalf("cxxShorten whole = %q", got)
	}
}

// r2l02ELF builds a real ELF64 image whose section table contains the named
// sections with the given sizes. debug/elf.Section fields are unexported, so a
// struct literal cannot stand in for a parsed file.
func r2l02ELF(t *testing.T, sections ...struct {
	name string
	size uint64
}) *elf.File {
	t.Helper()
	shstr := []byte{0}
	nameOff := map[string]uint32{}
	addName := func(s string) uint32 {
		off := uint32(len(shstr))
		shstr = append(shstr, s...)
		shstr = append(shstr, 0)
		return off
	}
	for _, s := range sections {
		nameOff[s.name] = addName(s.name)
	}
	shstrIdx := addName(".shstrtab")

	const ehsize, shentsize = 64, 64
	shstrOff := ehsize
	shoff := (shstrOff + len(shstr) + 7) &^ 7
	num := len(sections) + 2 // null + sections + shstrtab
	b := make([]byte, shoff+num*shentsize)
	le := binary.LittleEndian
	copy(b, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0})
	le.PutUint16(b[16:], 1)  // ET_REL
	le.PutUint16(b[18:], 62) // EM_X86_64
	le.PutUint32(b[20:], 1)  // EV_CURRENT
	le.PutUint64(b[40:], uint64(shoff))
	le.PutUint16(b[52:], ehsize)
	le.PutUint16(b[58:], shentsize)
	le.PutUint16(b[60:], uint16(num))
	le.PutUint16(b[62:], uint16(num-1))
	copy(b[shstrOff:], shstr)
	sh := func(i int) []byte { return b[shoff+i*shentsize : shoff+(i+1)*shentsize] }
	for i, s := range sections {
		h := sh(i + 1)
		le.PutUint32(h[0:], nameOff[s.name])
		le.PutUint32(h[4:], 1) // SHT_PROGBITS
		le.PutUint64(h[32:], s.size)
	}
	h := sh(num - 1)
	le.PutUint32(h[0:], shstrIdx)
	le.PutUint32(h[4:], 3) // SHT_STRTAB
	le.PutUint64(h[24:], uint64(shstrOff))
	le.PutUint64(h[32:], uint64(len(shstr)))

	f, err := elf.NewFile(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestR2L02CxxHasRelRo(t *testing.T) {
	type sec = struct {
		name string
		size uint64
	}
	if !cxxHasRelRo(r2l02ELF(t, sec{".data.rel.ro", 16})) {
		t.Fatal("16-byte .data.rel.ro not detected")
	}
	if cxxHasRelRo(r2l02ELF(t, sec{".data.rel.ro", 8})) {
		t.Fatal("8-byte .data.rel.ro accepted")
	}
	if cxxHasRelRo(r2l02ELF(t, sec{".text", 4096})) {
		t.Fatal("text-only object accepted")
	}
	if !cxxHasRelRo(r2l02ELF(t, sec{".data.rel.ro.local", 32})) {
		t.Fatal(".data.rel.ro.local not detected")
	}
	if cxxHasRelRo(r2l02ELF(t)) {
		t.Fatal("empty section table accepted")
	}
}

func TestR2L02DetectHashAndPlan(t *testing.T) {
	payload := []byte("hello")
	var headOut bytes.Buffer
	target, err := hashTargetN(bytes.NewReader(payload), int64(len(payload)), int64(len(payload)), &headOut)
	if err != nil {
		t.Fatal(err)
	}
	sum256 := sha256.Sum256(payload)
	sum1 := sha1.New()
	fmt.Fprintf(sum1, "blob %d\x00", len(payload))
	sum1.Write(payload)
	if target.Size != 5 || target.HashScope != "whole-file" || target.HashBytes != 5 ||
		target.FileSHA256 != hex.EncodeToString(sum256[:]) ||
		target.GitOID != "gitoid:blob:sha1:"+hex.EncodeToString(sum1.Sum(nil)) ||
		headOut.String() != "hello" {
		t.Fatalf("target = %+v head=%q", target, headOut.String())
	}
	if _, err := hashTargetN(bytes.NewReader(payload), 10, 10, nil); err == nil || !strings.Contains(err.Error(), "read stopped at 5") {
		t.Fatalf("short read err = %v", err)
	}
	if _, err := hashTargetN(bytes.NewReader(nil), maxDigest+2, maxDigest+1, nil); err == nil || !strings.Contains(err.Error(), fmt.Sprintf("cannot read %d bytes", maxDigest)) {
		t.Fatalf("cap err = %v", err)
	}

	for kind, want := range map[string]string{"macho": "macho", "elf": "elf", "pe": "pe", "apk": "mobile", "dex": "mobile", "dart": "generic"} {
		if got := digestPlan(kind); got != want {
			t.Errorf("digestPlan(%q) = %q, want %q", kind, got, want)
		}
	}
}

func TestR2L02ExportOutputContract(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "a.bin")
	if err := os.WriteFile(target, []byte("evidence me"), 0644); err != nil {
		t.Fatal(err)
	}
	before := outputEntries(t, dir)

	// Write op is refused without -o (exit 2, needs_arg) and does not write beside the target.
	stdout, code := runCLI(t, "--json", "--op", "export_evidence_bundle", target)
	if code != 2 || !strings.Contains(stdout, "needs_arg") {
		t.Fatalf("no -o: exit %d stdout %q", code, stdout)
	}
	outputSame(t, dir, before)

	// With -o DIR the bundle is written to that directory, not beside the target.
	outDir := filepath.Join(dir, "out")
	if err := os.MkdirAll(outDir, 0755); err != nil {
		t.Fatal(err)
	}
	if stdout, code := runCLI(t, "--json", "--op", "export_evidence_bundle", "-o", outDir, target); code != 0 {
		t.Fatalf("-o DIR: exit %d stdout %q", code, stdout)
	}
	if _, err := os.Stat(filepath.Join(outDir, "a.bin.evidence.json")); err != nil {
		t.Fatalf("-o DIR bundle missing: %v", err)
	}
	outputSame(t, dir, []string{"a.bin", "out"})

	// On a read-only op -o is not silently ignored; it is refused and no file is written.
	dest := filepath.Join(dir, "should-not-exist.json")
	_, stderr, code := runCLIAll(t, "-o", dest, "--op", "list_strings", fixtureMacho)
	if code != 2 || !strings.Contains(stderr, "-o") {
		t.Fatalf("read-only -o: exit %d stderr %q", code, stderr)
	}
	if _, err := os.Stat(dest); !os.IsNotExist(err) {
		t.Fatalf("read-only op wrote %s", dest)
	}

	// --extract without -o does not write to cwd; with -o DIR the member goes to the right place.
	archive := filepath.Join(dir, "a.zip")
	outputZip(t, archive, "m.txt", "member body")
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	cwdBefore := outputEntries(t, cwd)
	_, stderr, code = runCLIAll(t, "--extract", "m.txt", archive)
	if code != 2 || !strings.Contains(stderr, "-o") {
		t.Fatalf("--extract no -o: exit %d stderr %q", code, stderr)
	}
	outputSame(t, cwd, cwdBefore)
	if _, err := os.Stat(filepath.Join(cwd, "m.txt")); !os.IsNotExist(err) {
		t.Fatal("--extract wrote m.txt into cwd")
	}
	if stdout, code := runCLI(t, "--extract", "m.txt", "-o", outDir, archive); code != 0 {
		t.Fatalf("--extract -o DIR: exit %d stdout %q", code, stdout)
	}
	if body, err := os.ReadFile(filepath.Join(outDir, "m.txt")); err != nil || string(body) != "member body" {
		t.Fatalf("extracted member = %q, %v", body, err)
	}
}

func TestR2L02DetectAppBundleAndAbsence(t *testing.T) {
	if !isAppBundle("/tmp/Foo.app") || !isAppBundle("/tmp/foo.APP") {
		t.Fatal("case-insensitive .app suffix not recognized")
	}
	dir := t.TempDir()
	if isAppBundle(dir) {
		t.Fatal("plain directory accepted as bundle")
	}
	app := filepath.Join(dir, "X.app")
	if err := os.MkdirAll(filepath.Join(app, "Contents"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(app, "Contents", "Info.plist"), []byte("plist"), 0644); err != nil {
		t.Fatal(err)
	}
	if !isAppBundle(app) {
		t.Fatal("Contents/Info.plist bundle not recognized")
	}

	full := Digest{FileSize: 10, BytesScanned: 10, Constants: consts{constNotDetected}, JIT: jitNotDetected, Names: nameNotRecovered}
	if !full.complete() {
		t.Fatal("end-to-end read not complete")
	}
	full.gateAbsence()
	// On a full read "not detected" is a valid answer, not downgraded to not_scanned.
	if full.Constants[0] != constNotDetected || full.JIT != jitNotDetected || full.Names != nameNotRecovered {
		t.Fatalf("complete absence = %v %q %q", full.Constants, full.JIT, full.Names)
	}
	cut := Digest{FileSize: 10, BytesScanned: 5, Truncated: true, Constants: consts{constNotDetected}, JIT: jitNotDetected, Names: nameNotRecovered}
	if cut.complete() {
		t.Fatal("truncated read called complete")
	}
	cut.gateAbsence()
	if cut.Constants[0] != constNotScanned {
		t.Fatalf("truncated absence = %v", cut.Constants)
	}
	// Positive presence is preserved on a partial read.
	seen := Digest{FileSize: 10, BytesScanned: 5, Truncated: true, Constants: consts{"luajit 2.0"}, JIT: "luajit 2.0", Names: "local:3"}
	seen.gateAbsence()
	if seen.Constants[0] != "luajit 2.0" || seen.JIT != "luajit 2.0" || seen.Names != "local:3" {
		t.Fatalf("presence lost: %v %q %q", seen.Constants, seen.JIT, seen.Names)
	}
}

// firmwareHits carves only fwMagics (strong container signatures), never the
// short wrappers firmwareKind names. A gzip wrapper at offset 0 must therefore
// be absent from the parts list, while the containers after it carry real byte
// offsets in the digest's detail format.
func TestR2L02FirmwarePartLinesAndShortMagicExclusion(t *testing.T) {
	buf := []byte("\x1f\x8b\x08") // gzip, offset 0: short magic, must not be carved
	buf = append(buf, "ab"...)
	buf = append(buf, "hsqs"...) // offset 5
	buf = append(buf, "xx"...)
	buf = append(buf, "HDR0"...) // offset 11
	buf = append(buf, "yy"...)
	buf = append(buf, 0xd0, 0x0d, 0xfe, 0xed) // offset 17: dtb

	want := []string{"0x00000005 squashfs", "0x0000000b trx", "0x00000011 dtb"}
	if got := firmwarePartLines(buf); !reflect.DeepEqual(got, want) {
		t.Fatalf("firmwarePartLines = %v, want %v", got, want)
	}

	// The cap must cut the list itself, not only raise the flag: 45 squashfs
	// magics leave exactly maxFirmwareParts carved hits.
	var big []byte
	for i := 0; i < 45; i++ {
		big = append(big, "hsqs"...)
	}
	hits, capped := firmwareHits(big)
	if !capped || len(hits) != maxFirmwareParts {
		t.Fatalf("cap: capped=%v len=%d, want true/%d", capped, len(hits), maxFirmwareParts)
	}
}
