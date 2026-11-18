package main

// TUR2 AUDIT LANE 01 — independent simulation tests.
// Does not touch existing test files; only verifies real production behavior
// with meaningful inputs. Production code is not relaxed.

import (
	"bytes"
	"compress/zlib"
	"os"
	"path/filepath"
	"testing"
)

// ---- claims.go: witnessGap / confOf / emit ----

func TestR2L01WitnessGap(t *testing.T) {
	w := func(axis string, start int64) Witness {
		return Witness{Axis: axis, Class: axis, Start: start, End: start + 10}
	}
	cases := []struct {
		name string
		ws   []Witness
		want string
	}{
		{"empty", nil, "witness-count"},
		{"one", []Witness{w("parser", 0)}, "witness-count"},
		{"no-offset", []Witness{w("parser", -1), w("sig", 20)}, "witness-no-offset"},
		{"unknown-mech", []Witness{w("parser", 0), w("guess", 20)}, "witness-mech-unknown"},
		{"same-mech", []Witness{w("parser", 0), w("parser", 20)}, "witness-same-mech"},
		{"overlap", []Witness{w("parser", 0), w("sig", 5)}, "witness-overlap"},
		{"valid-two", []Witness{w("parser", 0), w("sig", 20)}, ""},
		{"valid-three", []Witness{w("parser", 0), w("sig", 20), w("passthrough", 40)}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := witnessGap(c.ws); got != c.want {
				t.Fatalf("witnessGap = %q, want %q", got, c.want)
			}
		})
	}
}

func TestR2L01ConfOf(t *testing.T) {
	cases := []struct {
		n    int
		want float64
	}{{0, 0}, {1, 0.5}, {2, 2.0 / 3.0}, {3, 0.75}}
	for _, c := range cases {
		if got := confOf(c.n); got != c.want {
			t.Fatalf("confOf(%d) = %v, want %v", c.n, got, c.want)
		}
	}
}

func TestR2L01EmitSettlesAndRefuses(t *testing.T) {
	ws := func(axis string, start int64) Witness {
		return Witness{Axis: axis, Class: axis, Start: start, End: start + 4}
	}
	good := []Witness{ws("parser", 0), ws("sig", 16)}
	var d Digest
	// producer has a single valid value and settles. language has two valid
	// but conflicting values -> no claim settles, both go to Unknown as
	// slot-conflict and the slot is kept in Conflicts. A one-witness proposal
	// lands in Unknown (witness-count); an unsupported slot is refused by name.
	d.emit(
		claimReq{Slot: "language", Value: "Go", Witnesses: good},
		claimReq{Slot: "producer", Value: "toolchain", Witnesses: good},
		claimReq{Slot: "language", Value: "Rust", Witnesses: good},
		claimReq{Slot: "language", Value: "weak", Witnesses: []Witness{ws("parser", 64)}},
		claimReq{Slot: "bogus", Value: "x", Witnesses: good},
	)
	if len(d.Claims) != 1 || d.Claims[0].Slot != "producer" || d.Claims[0].Value != "toolchain" {
		t.Fatalf("claims = %+v, want one settled producer", d.Claims)
	}
	if c := d.Claims[0]; c.Conf != confOf(len(c.Witnesses)) {
		t.Fatalf("claim conf = %v want %v", c.Conf, confOf(len(c.Witnesses)))
	}
	if len(d.Conflicts) != 1 || d.Conflicts[0].Slot != "language" {
		t.Fatalf("conflicts = %+v, want one on language", d.Conflicts)
	}
	if vals := d.Conflicts[0].Values; len(vals) != 2 || vals[0] != "Go" || vals[1] != "Rust" {
		t.Fatalf("conflict values = %v", vals)
	}
	reasons := map[string]bool{}
	for _, u := range d.Unknown {
		if len(u.Reasons) > 0 {
			reasons[u.Reasons[0]] = true
		}
	}
	for _, want := range []string{"witness-count", "slot-unsupported", "slot-conflict"} {
		if !reasons[want] {
			t.Fatalf("unknown reasons = %v, want %q present", reasons, want)
		}
	}
}

// ---- bound.go: allocCeil ----

func TestR2L01AllocCeilBoundaries(t *testing.T) {
	var d Digest
	if buf, ok := allocCeil(&d, "pe", maxPEHeader, "pe-too-big"); !ok || int64(len(buf)) != maxPEHeader {
		t.Fatalf("exact cap refused: ok=%v len=%d", ok, len(buf))
	}
	if buf, ok := allocCeil(&d, "pe", 0, "pe-too-big"); !ok || len(buf) != 0 {
		t.Fatalf("zero refused: ok=%v len=%d", ok, len(buf))
	}
	if buf, ok := allocCeil(&d, "pe", maxPEHeader+1, "pe-too-big"); ok || buf != nil {
		t.Fatalf("cap+1 accepted")
	}
	if buf, ok := allocCeil(&d, "pe", -1, "pe-too-big"); ok || buf != nil {
		t.Fatalf("negative accepted")
	}
	if buf, ok := allocCeil(&d, "no-such-field", 1, "pe-too-big"); ok || buf != nil {
		t.Fatalf("unknown field accepted")
	}
	if len(d.Skipped) != 3 {
		t.Fatalf("refusals = %d, want 3: %+v", len(d.Skipped), d.Skipped)
	}
	if err := d.checkReasons(); err != nil {
		t.Fatalf("unregistered reason: %v", err)
	}
}

// ---- beam.go: beamMatch / beamPrintable ----

func TestR2L01BeamMatchAndPrintable(t *testing.T) {
	head := make([]byte, 12)
	copy(head[0:4], "FOR1")
	copy(head[8:12], "BEAM")
	if !beamMatch(head, 12) {
		t.Fatal("valid BEAM head refused")
	}
	if beamMatch(head, 11) {
		t.Fatal("size below header accepted")
	}
	if beamMatch(head[:8], 12) {
		t.Fatal("short head accepted")
	}
	bad := append([]byte(nil), head...)
	bad[8] = 'X'
	if beamMatch(bad, 12) {
		t.Fatal("wrong magic accepted")
	}
	for _, s := range []string{"Mod", "erlang", "a b"} {
		if !beamPrintable(s) {
			t.Fatalf("%q not printable", s)
		}
	}
	for _, s := range []string{"a\x00b", "a\x7fb", string([]byte{0xff, 0xfe})} {
		if beamPrintable(s) {
			t.Fatalf("%q accepted as printable", s)
		}
	}
}

// ---- beamdbgi.go: beamDbgiTerm / etfTerm ----

func TestR2L01BeamDbgiTerm(t *testing.T) {
	// plain ETF: version byte 131, then a SMALL_INTEGER_EXT (tag 97, value 7).
	body, reason, detail := beamDbgiTerm([]byte{131, 97, 7})
	if reason != "" || detail != "" {
		t.Fatalf("plain refused: %q %q", reason, detail)
	}
	if !bytes.Equal(body, []byte{97, 7}) {
		t.Fatalf("plain body = %v, want [97 7]", body)
	}
	// raw zlib ETF with version byte inside.
	var z bytes.Buffer
	zw := zlib.NewWriter(&z)
	zw.Write([]byte{131, 97, 7})
	zw.Close()
	body, reason, _ = beamDbgiTerm(z.Bytes())
	if reason != "" || !bytes.Equal(body, []byte{97, 7}) {
		t.Fatalf("zlib term = %v reason=%q", body, reason)
	}
	// encrypted debug info: <<0:8, N:8, Mode:N/binary, ...>> must be refused.
	enc := append([]byte{131, 0, 4}, []byte("aes ")...)
	_, reason, detail = beamDbgiTerm(enc)
	if reason != "beamdbgi-etf-unsupported" {
		t.Fatalf("encrypted not refused: reason=%q detail=%q", reason, detail)
	}
	if !bytes.Contains([]byte(detail), []byte("encrypted")) {
		t.Fatalf("encrypted detail = %q", detail)
	}
	// a 1-byte unsupported payload is refused by name, not coerced.
	_, reason, _ = beamDbgiTerm([]byte{0x05})
	if reason != "beamdbgi-etf-unsupported" {
		t.Fatalf("unsupported reason = %q", reason)
	}
}

func TestR2L01EtfTerm(t *testing.T) {
	// SMALL_INTEGER_EXT
	term, off, err := etfTerm([]byte{97, 42}, 0, 0)
	if err != nil || term.n != 42 || off != 2 {
		t.Fatalf("small int = %+v off=%d err=%v", term, off, err)
	}
	// SMALL_ATOM_UTF8_EXT (tag 119): "hi"
	atom := []byte{119, 2, 'h', 'i'}
	term, off, err = etfTerm(atom, 0, 0)
	if err != nil || !term.atom("hi") || off != 4 {
		t.Fatalf("atom = %+v off=%d err=%v", term, off, err)
	}
	// SMALL_TUPLE_EXT (tag 104) with one integer element.
	tup := []byte{104, 1, 97, 9}
	term, off, err = etfTerm(tup, 0, 0)
	if err != nil || len(term.elems) != 1 || term.elems[0].n != 9 || off != 4 {
		t.Fatalf("tuple = %+v off=%d err=%v", term, off, err)
	}
	// NIL_EXT
	term, off, err = etfTerm([]byte{106}, 0, 0)
	if err != nil || term.tag != 106 || off != 1 {
		t.Fatalf("nil = %+v off=%d err=%v", term, off, err)
	}
	// unknown tag is refused, not coerced.
	if _, _, err := etfTerm([]byte{200}, 0, 0); err == nil {
		t.Fatal("unknown tag accepted")
	}
	// truncated payload is refused.
	if _, _, err := etfTerm([]byte{97}, 0, 0); err == nil {
		t.Fatal("truncated int accepted")
	}
}

// ---- bundle.go: nativeKind / bundleExecutable ----

func TestR2L01NativeKind(t *testing.T) {
	d := t.TempDir()
	cases := []struct {
		name         string
		magic        []byte
		kind, format string
	}{
		{"elf", []byte("\x7fELF"), "elf", ""},
		{"fat", []byte("\xca\xfe\xba\xbe"), "macho", "fat"},
		{"thin-32", []byte("\xce\xfa\xed\xfe"), "macho", "thin"},
		{"thin-64", []byte("\xcf\xfa\xed\xfe"), "macho", "thin"},
		{"pe", []byte("MZ\x90\x00"), "pe", ""},
		{"unknown", []byte("NOPE"), "unknown", ""},
	}
	for _, c := range cases {
		p := filepath.Join(d, c.name)
		if err := os.WriteFile(p, c.magic, 0644); err != nil {
			t.Fatal(err)
		}
		k, f := nativeKind(p)
		if k != c.kind || f != c.format {
			t.Fatalf("nativeKind(%s) = %q,%q want %q,%q", c.name, k, f, c.kind, c.format)
		}
	}
}

func TestR2L01BundleExecutable(t *testing.T) {
	root := t.TempDir()
	contents := filepath.Join(root, "Contents")
	if err := os.MkdirAll(contents, 0755); err != nil {
		t.Fatal(err)
	}
	plist := `<?xml version="1.0"?><plist><dict><key>CFBundleExecutable</key><string>Code</string></dict></plist>`
	if err := os.WriteFile(filepath.Join(contents, "Info.plist"), []byte(plist), 0644); err != nil {
		t.Fatal(err)
	}
	if got := bundleExecutable(root); got != "Code" {
		t.Fatalf("bundleExecutable = %q, want Code", got)
	}
	// path separator in the plist is refused: plist is untrusted input.
	bad := `<?xml version="1.0"?><plist><dict><key>CFBundleExecutable</key><string>../../evil</string></dict></plist>`
	if err := os.WriteFile(filepath.Join(contents, "Info.plist"), []byte(bad), 0644); err != nil {
		t.Fatal(err)
	}
	if got := bundleExecutable(root); got != "" {
		t.Fatalf("traversal accepted: %q", got)
	}
}

// ---- cdp.go: cdpQuoteMeta ----

func TestR2L01CdpQuoteMeta(t *testing.T) {
	in := `a.b*c+d?e^f$g{h}i(j)k|l[m]n\o`
	want := `a\.b\*c\+d\?e\^f\$g\{h\}i\(j\)k\|l\[m\]n\\o`
	if got := cdpQuoteMeta(in); got != want {
		t.Fatalf("cdpQuoteMeta = %q, want %q", got, want)
	}
	if got := cdpQuoteMeta("café.日本"); got != `café\.日本` {
		t.Fatalf("unicode mangled: %q", got)
	}
}

// ---- compress.go: compressFormatOf / compressInnerKind / compressSafeName ----

func TestR2L01CompressFormatOf(t *testing.T) {
	cases := []struct {
		name string
		h    []byte
		want string
	}{
		{"gzip", []byte{0x1f, 0x8b, 0x08}, "gzip"},
		{"bzip2", []byte("BZh9"), "bzip2"},
		{"xz", []byte{0xfd, '7', 'z', 'X', 'Z', 0x00}, "xz"},
		{"lzma", []byte{0x5d, 0, 0}, "lzma"},
		{"lz4", []byte{0x04, 0x22, 0x4d, 0x18}, "lz4"},
		{"zstd", []byte{0x28, 0xb5, 0x2f, 0xfd}, "zstd"},
		{"unknown", []byte("NOPE"), ""},
		{"bzip2-bad-level", []byte("BZh0"), ""},
	}
	for _, c := range cases {
		cf, ok := compressFormatOf(c.h)
		got := ""
		if ok {
			got = cf.name
		}
		if got != c.want {
			t.Fatalf("compressFormatOf(%s) = %q,%v want %q", c.name, got, ok, c.want)
		}
	}
}

func TestR2L01CompressInnerKind(t *testing.T) {
	cases := []struct {
		h    []byte
		want string
	}{
		{[]byte("\x7fELF..."), "elf"},
		{[]byte("MZ\x90\x00"), "pe"},
		{[]byte("PK\x03\x04"), "zip"},
		{[]byte("!<arch>\n"), "ar"},
		{[]byte("SQLite format 3\x00"), "sqlite"},
		{[]byte{0xce, 0xfa, 0xed, 0xfe}, "macho"},
		{[]byte{0xcf, 0xfa, 0xed, 0xfe}, "macho"},
		{[]byte{0x1f, 0x8b, 0x08}, "gzip"},
		{[]byte("????"), ""},
	}
	for _, c := range cases {
		if got := compressInnerKind(c.h); got != c.want {
			t.Fatalf("compressInnerKind(%v) = %q, want %q", c.h, got, c.want)
		}
	}
}

func TestR2L01CompressSafeName(t *testing.T) {
	if got := compressSafeName([]byte("a.txt")); got != "a.txt" {
		t.Fatalf("printable = %q", got)
	}
	if got := compressSafeName([]byte{'a', 0x00, 0x1f, 0x7f, 0xff, 'b'}); got != "a????b" {
		t.Fatalf("control bytes = %q", got)
	}
}

// ---- constants.go: jitToken / jitValue / namesValue ----

func TestR2L01JitToken(t *testing.T) {
	cases := []struct {
		name, token string
		ok          bool
	}{
		{"__ZN2v88internal4HeapD2Ev", "v8", true},
		{"libv8.dylib", "v8", true},
		{"mprotect@GLIBC_2.2.5", "mprotect", true},
		{"_pthread_jit_write_protect_np", "pthread_jit_write_protect_np", true},
		{"libJavaScriptCore.dylib", "JavaScriptCore", true},
		{"_malloc", "", false},
	}
	for _, c := range cases {
		tok, ok := jitToken(c.name)
		if tok != c.token || ok != c.ok {
			t.Fatalf("jitToken(%q) = %q,%v want %q,%v", c.name, tok, ok, c.token, c.ok)
		}
	}
}

func TestR2L01JitValueAndNamesValue(t *testing.T) {
	var d Digest
	if got := jitValue(&d, []string{"pthread_jit", "mprotect", "mprotect", "v8"}); got != "imports:mprotect,pthread_jit,v8" {
		t.Fatalf("jitValue = %q", got)
	}
	if got := jitValue(&d, nil); got != jitNotDetected {
		t.Fatalf("empty jitValue = %q", got)
	}
	if got := namesValue(0); got != nameNotRecovered {
		t.Fatalf("namesValue(0) = %q", got)
	}
	if got := namesValue(-3); got != nameNotRecovered {
		t.Fatalf("namesValue(-3) = %q", got)
	}
	if got := namesValue(12); got != "local:12" {
		t.Fatalf("namesValue(12) = %q", got)
	}
}

// ---- asar.go: listSample / containsStr ----

func TestR2L01ListSampleAndContains(t *testing.T) {
	names := []string{"a", "b", "c"}
	if got := listSample(names, 3); got != "a, b, c" {
		t.Fatalf("within cap = %q", got)
	}
	if got := listSample(names, 2); got != "a, b (+1 more)" {
		t.Fatalf("over cap = %q", got)
	}
	if got := listSample(nil, 2); got != "" {
		t.Fatalf("empty = %q", got)
	}
	if !containsStr(names, "b") || containsStr(names, "z") {
		t.Fatal("containsStr wrong")
	}
}
