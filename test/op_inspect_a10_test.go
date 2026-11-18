package main

// Lane A10 tests: one assert per owned op, fixtures built in t.TempDir, no
// network, no repo testdata. Helpers carry the a10 prefix so no other lane's
// test file can collide with or silently redefine them.

import (
	"encoding/asn1"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func a10Write(t *testing.T, name string, b []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return p
}

func a10JSON(t *testing.T, v any) map[string]any {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal result %s: %v", b, err)
	}
	return m
}

// a10Get walks a decoded result map: a10Get(t, m, "types", 0, "id").
func a10Get(t *testing.T, m map[string]any, path ...any) any {
	t.Helper()
	var cur any = m
	for _, k := range path {
		switch key := k.(type) {
		case string:
			mm, ok := cur.(map[string]any)
			if !ok {
				t.Fatalf("walk %v: %#v is not an object", path, cur)
			}
			cur = mm[key]
		case int:
			arr, ok := cur.([]any)
			if !ok || key >= len(arr) {
				t.Fatalf("walk %v: %#v is not an array of %d", path, cur, key+1)
			}
			cur = arr[key]
		}
	}
	return cur
}

func a10Num(t *testing.T, m map[string]any, path ...any) float64 {
	t.Helper()
	f, ok := a10Get(t, m, path...).(float64)
	if !ok {
		t.Fatalf("walk %v: not a number", path)
	}
	return f
}

// a10Refused accepts either refusal shape an op has: a Go error or a *skip.
func a10Refused(t *testing.T, got any, err error, want string) {
	t.Helper()
	if err != nil {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q does not mention %q", err, want)
		}
		return
	}
	sk, ok := got.(*skip)
	if !ok {
		t.Fatalf("expected a refusal mentioning %q, got %#v", want, got)
	}
	if !strings.Contains(sk.Reason, want) {
		t.Fatalf("refusal %q does not mention %q", sk.Reason, want)
	}
}

type a10Section struct {
	name string
	rva  uint32
	data []byte
}

func a10U32(v uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return b
}

func a10U64(v uint64) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, v)
	return b
}

// a10PE builds a PE32+ image whose sections start at RVA 0x1000 / file 0x400.
func a10PE(secs []a10Section, dirs map[int][2]uint32) []byte {
	const (
		peOff   = 0x80
		optSize = 0xF0
		hdrs    = 0x400
	)
	b := make([]byte, hdrs)
	b[0], b[1] = 'M', 'Z'
	binary.LittleEndian.PutUint32(b[0x3c:], peOff)
	copy(b[peOff:], "PE\x00\x00")
	binary.LittleEndian.PutUint16(b[peOff+4:], 0x8664)
	binary.LittleEndian.PutUint16(b[peOff+6:], uint16(len(secs)))
	binary.LittleEndian.PutUint16(b[peOff+20:], optSize)
	binary.LittleEndian.PutUint16(b[peOff+22:], 0x0022)
	opt := peOff + 24
	binary.LittleEndian.PutUint16(b[opt:], 0x20b)
	binary.LittleEndian.PutUint64(b[opt+24:], 0x140000000)
	binary.LittleEndian.PutUint32(b[opt+32:], 0x1000)
	binary.LittleEndian.PutUint32(b[opt+36:], 0x200)
	binary.LittleEndian.PutUint32(b[opt+56:], 0x4000)
	binary.LittleEndian.PutUint32(b[opt+60:], hdrs)
	binary.LittleEndian.PutUint16(b[opt+68:], 3)
	binary.LittleEndian.PutUint32(b[opt+108:], 16)
	secTab := opt + optSize
	off := hdrs
	for i, s := range secs {
		h := b[secTab+i*40:]
		copy(h[:8], s.name)
		raw := (len(s.data) + 0x1ff) &^ 0x1ff
		binary.LittleEndian.PutUint32(h[8:], uint32(len(s.data)))
		binary.LittleEndian.PutUint32(h[12:], s.rva)
		binary.LittleEndian.PutUint32(h[16:], uint32(raw))
		binary.LittleEndian.PutUint32(h[20:], uint32(off))
		b = append(b, s.data...)
		for pad := raw - len(s.data); pad > 0; pad-- {
			b = append(b, 0)
		}
		off += raw
	}
	for i, d := range dirs {
		binary.LittleEndian.PutUint32(b[opt+112+i*8:], d[0])
		binary.LittleEndian.PutUint32(b[opt+116+i*8:], d[1])
	}
	return b
}

func a10PEPlain(t *testing.T) string {
	return a10Write(t, "plain.exe", a10PE([]a10Section{{".text", 0x1000, make([]byte, 0x200)}}, nil))
}

func TestInspectPEImportsA10(t *testing.T) {
	// A PE with no import directory is still a valid answer: zero rows, not a
	// refusal, because the image really imports nothing.
	got, err := runOp("inspect_pe_imports", a10PEPlain(t))
	if err != nil {
		t.Fatalf("inspect_pe_imports: %v", err)
	}
	m := a10JSON(t, got)
	if n := a10Num(t, m, "total"); n != 0 {
		t.Fatalf("total = %v, want 0", n)
	}
	if n := a10Num(t, m, "shown"); n != 0 {
		t.Fatalf("shown = %v, want 0", n)
	}

	// A text file is not a PE: the op must refuse instead of inventing rows.
	got, err = runOp("inspect_pe_imports", a10Write(t, "not.txt", []byte("hello")))
	a10Refused(t, got, err, "not")
}

func TestInspectPELoadConfigA10(t *testing.T) {
	lc := make([]byte, 0x140)
	copy(lc[0:], a10U32(0x140))           // Size
	copy(lc[0x58:], a10U64(0x140008000))  // SecurityCookie
	copy(lc[0x68:], a10U64(3))            // SEHandlerCount
	copy(lc[0x88:], a10U64(4))            // GuardCFFunctionCount
	copy(lc[0x90:], a10U32(0x00000500))   // CF_INSTRUMENTED|CF_FUNCTION_TABLE_PRESENT
	copy(lc[0x108:], a10U64(0x14000d000)) // ExceptionTable
	copy(lc[0x110:], a10U64(7))           // ExceptionCount
	pe := a10PE([]a10Section{{".data", 0x1000, lc}}, map[int][2]uint32{10: {0x1000, uint32(len(lc))}})
	got, err := runOp("inspect_pe_load_config", a10Write(t, "lc.exe", pe))
	if err != nil {
		t.Fatalf("inspect_pe_load_config: %v", err)
	}
	m := a10JSON(t, got)
	if n := a10Num(t, m, "declared_size"); n != 0x140 {
		t.Fatalf("declared_size = %v, want %d", n, 0x140)
	}
	if n := a10Num(t, m, "seh_count"); n != 3 {
		t.Fatalf("seh_count = %v, want 3", n)
	}
	if n := a10Num(t, m, "cfg_function_count"); n != 4 {
		t.Fatalf("cfg_function_count = %v, want 4", n)
	}
	names, _ := a10Get(t, m, "guard_flag_names").([]any)
	if len(names) != 2 || names[0] != "CF_INSTRUMENTED" || names[1] != "CF_FUNCTION_TABLE_PRESENT" {
		t.Fatalf("guard_flag_names = %v", names)
	}
	got, err = runOp("inspect_pe_load_config", a10PEPlain(t))
	if err != nil {
		t.Fatalf("inspect_pe_load_config unsigned: %v", err)
	}
	m = a10JSON(t, got)
	if v := a10Get(t, m, "present"); v != false {
		t.Fatalf("present = %v, want false", v)
	}
}

func TestInspectPEResourcesA10(t *testing.T) {
	// type RT_RCDATA -> name 1 -> language 0x409 -> data entry -> "A10!".
	b := make([]byte, 0x80)
	binary.LittleEndian.PutUint16(b[14:], 1)
	binary.LittleEndian.PutUint32(b[16:], 10)
	binary.LittleEndian.PutUint32(b[20:], 0x80000018)
	binary.LittleEndian.PutUint16(b[0x18+14:], 1)
	binary.LittleEndian.PutUint32(b[0x18+16:], 1)
	binary.LittleEndian.PutUint32(b[0x18+20:], 0x80000030)
	binary.LittleEndian.PutUint16(b[0x30+14:], 1)
	binary.LittleEndian.PutUint32(b[0x30+16:], 0x409)
	binary.LittleEndian.PutUint32(b[0x30+20:], 0x48)
	binary.LittleEndian.PutUint32(b[0x48:], 0x1000+0x60)
	binary.LittleEndian.PutUint32(b[0x48+4:], 4)
	copy(b[0x60:], "A10!")
	pe := a10PE([]a10Section{{".rsrc", 0x1000, b}}, map[int][2]uint32{2: {0x1000, uint32(len(b))}})
	got, err := runOp("inspect_pe_resources", a10Write(t, "res.exe", pe))
	if err != nil {
		t.Fatalf("inspect_pe_resources: %v", err)
	}
	m := a10JSON(t, got)
	if n := a10Num(t, m, "leaves"); n != 1 {
		t.Fatalf("leaves = %v, want 1", n)
	}
	if n := a10Num(t, m, "types", 0, "id"); n != 10 {
		t.Fatalf("types[0].id = %v, want 10", n)
	}
	if s := a10Get(t, m, "types", 0, "kind"); s != "RCDATA" {
		t.Fatalf("types[0].kind = %v, want RCDATA", s)
	}
	if n := a10Num(t, m, "types", 0, "entries", 0, "languages", 0, "language"); n != 0x409 {
		t.Fatalf("language = %v, want 1033", n)
	}
	got, err = runOp("inspect_pe_resources", a10PEPlain(t))
	if err != nil {
		t.Fatalf("inspect_pe_resources unsigned: %v", err)
	}
	m = a10JSON(t, got)
	if v := a10Get(t, m, "present"); v != false {
		t.Fatalf("present = %v, want false", v)
	}
}

// a10TLV wraps body in one DER tag with a definite length.
func a10TLV(tag byte, body []byte) []byte {
	n := len(body)
	switch {
	case n < 0x80:
		return append([]byte{tag, byte(n)}, body...)
	case n < 0x100:
		return append([]byte{tag, 0x81, byte(n)}, body...)
	default:
		return append([]byte{tag, 0x82, byte(n >> 8), byte(n)}, body...)
	}
}

func a10Cat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// a10PKCS7 wraps one SignerInfo (with or without a messageDigest attribute) in
// the ContentInfo -> SignedData shape peParseSigners expects. The SignedData is
// assembled by hand: encoding it through the reader's own struct re-orders the
// SET members and the reader then rejects its own output.
func a10PKCS7(md []byte) []byte {
	sha256OID := asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	alg := mustASN1(asn1.Marshal(peAlgID{Algorithm: sha256OID}))
	si := peSignerInfoT{
		Version:            1,
		IssuerAndSerial:    asn1.RawValue{FullBytes: mustASN1(asn1.Marshal("a10"))},
		DigestAlgorithm:    peAlgID{Algorithm: sha256OID},
		SignatureAlgorithm: peAlgID{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}},
		Signature:          []byte{1},
	}
	if md != nil {
		oct := mustASN1(asn1.Marshal(md))
		attr := a10TLV(0x30, a10Cat(mustASN1(asn1.Marshal(peOIDMsgDigest)), a10TLV(0x31, oct)))
		si.AuthAttrs = asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: a10TLV(0x31, attr)}
	}
	sd := a10TLV(0x30, a10Cat(
		mustASN1(asn1.Marshal(1)),
		a10TLV(0x31, alg),
		mustASN1(asn1.Marshal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1})),
		a10TLV(0x31, mustASN1(asn1.Marshal(si))),
	))
	return mustASN1(asn1.Marshal(peContentInfoT{
		ContentType: peOIDSignedData,
		Content:     asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: sd},
	}))
}

func mustASN1(b []byte, err error) []byte {
	if err != nil {
		panic(err)
	}
	return b
}

func TestInspectPECertificatesA10(t *testing.T) {
	body := a10PKCS7([]byte{0xde, 0xad, 0xbe, 0xef})
	wc := make([]byte, 8+len(body))
	binary.LittleEndian.PutUint32(wc[0:], uint32(len(wc)))
	binary.LittleEndian.PutUint16(wc[4:], 0x0200)
	binary.LittleEndian.PutUint16(wc[6:], 0x0002)
	copy(wc[8:], body)
	pe := a10PE([]a10Section{{".text", 0x1000, make([]byte, 0x200)}}, map[int][2]uint32{4: {0x400, uint32(len(wc))}})
	// the WIN_CERTIFICATE lands in the first section's file bytes
	copy(pe[0x400:], wc)
	got, err := runOp("inspect_pe_certificates", a10Write(t, "cert.exe", pe))
	if err != nil {
		t.Fatalf("inspect_pe_certificates: %v", err)
	}
	m := a10JSON(t, got)
	if s := a10Get(t, m, "entries", 0, "type_name"); s != "pkcs7" {
		t.Fatalf("type_name = %v, want pkcs7", s)
	}
	if s := a10Get(t, m, "entries", 0, "revision_name"); s != "2.0" {
		t.Fatalf("revision_name = %v, want 2.0", s)
	}
	if s := a10Get(t, m, "entries", 0, "signers", 0, "digest_algorithm"); s != "sha256" {
		t.Fatalf("digest_algorithm = %v, want sha256", s)
	}
	if s := a10Get(t, m, "entries", 0, "signers", 0, "message_digest"); s != "deadbeef" {
		t.Fatalf("message_digest = %v, want deadbeef", s)
	}
	// The image digest must be computed, not copied: an unrelated digest is a
	// mismatch that names the hash it actually got.
	if s, _ := a10Get(t, m, "entries", 0, "image_digest").(string); !strings.HasPrefix(s, "mismatch: image is ") {
		t.Fatalf("image_digest = %q, want a mismatch line", s)
	}
	got, err = runOp("inspect_pe_certificates", a10PEPlain(t))
	if err != nil {
		t.Fatalf("inspect_pe_certificates unsigned: %v", err)
	}
	m = a10JSON(t, got)
	if v := a10Get(t, m, "signed"); v != false {
		t.Fatalf("signed = %v, want false", v)
	}
}

func TestInspectPlistA10(t *testing.T) {
	xml := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>com.a10.test</string>
<key>CFBundleVersion</key><string>42</string>
</dict></plist>`
	got, err := runOp("inspect_plist", a10Write(t, "info.plist", []byte(xml)))
	if err != nil {
		t.Fatalf("inspect_plist: %v", err)
	}
	m := a10JSON(t, got)
	keys, _ := a10Get(t, m, "keys").([]any)
	if len(keys) != 2 {
		t.Fatalf("keys = %v, want 2", keys)
	}
	if keys[0] != "CFBundleIdentifier = com.a10.test" {
		t.Fatalf("keys[0] = %v", keys[0])
	}
	got, err = runOp("inspect_plist", a10Write(t, "not.txt", []byte("hello")))
	a10Refused(t, got, err, "not a property list")
}

func TestInspectPythonPycA10(t *testing.T) {
	// 3550 is CPython 3.13; the marshal body is garbage, so the detector must
	// refuse rather than hand back an empty qualname list.
	b := []byte{0xde, 0x0d, 0x0d, 0x0a, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0xff}
	got, err := runOp("inspect_python_pyc", a10Write(t, "m.pyc", b))
	a10Refused(t, got, err, "pyc")
}

func TestInspectRecordedCrashA10(t *testing.T) {
	body := `{"exception":{"type":"EXC_BAD_ACCESS","signal":"SIGSEGV"},"faultingThread":0,` +
		`"threads":[{"frames":[{"imageIndex":0,"symbol":"main","imageOffset":16}]}],` +
		`"usedImages":[{"name":"Demo","path":"/x/Demo","base":4294967296,"uuid":"aa"}]}`
	text := `{"app_name":"Demo","bundleID":"com.a10.demo","os_version":"14.0","timestamp":"2026-11-03 10:00:00.00 +0300"}` + "\n" + body + "\n"
	got, err := runOp("inspect_recorded_crash", a10Write(t, "c.ips", []byte(text)))
	if err != nil {
		t.Fatalf("inspect_recorded_crash: %v", err)
	}
	m := a10JSON(t, got)
	if s := a10Get(t, m, "app"); s != "Demo" {
		t.Fatalf("app = %v, want Demo", s)
	}
	if s := a10Get(t, m, "bundle_id"); s != "com.a10.demo" {
		t.Fatalf("bundle_id = %v", s)
	}
	if s := a10Get(t, m, "threads", 0, "frames", 0, "symbol"); s != "main" {
		t.Fatalf("frame symbol = %v, want main", s)
	}
	got, err = runOp("inspect_recorded_crash", a10Write(t, "one.ips", []byte(`{"a":1}`)))
	a10Refused(t, got, err, "one JSON line")
}

func TestInspectRustBinaryA10(t *testing.T) {
	// A go binary carries no rustc marker; the op must say so instead of
	// reporting an empty crate list.
	exe, err := os.Executable()
	if err != nil {
		t.Skipf("no executable: %v", err)
	}
	got, err := runOp("inspect_rust_binary", exe)
	a10Refused(t, got, err, "not a Rust build")
}

func TestInspectSignalDecodersA10(t *testing.T) {
	table := `[{"name":"ais","family":"marine","modulation":"gmsk","symbol_rate":9600,"channel":"161.975"},` +
		`{"name":"lte-pbch","family":"cellular","modulation":"ofdm","symbol_rate":1920000,"channel":"0"}]`
	p := a10Write(t, "decoders.json", []byte(table))
	t.Setenv("LRECON_DECODERS", p)
	t.Setenv("LRECON_QUERY", "")
	got, err := runOp("inspect_signal_decoders", "ais")
	if err != nil {
		t.Fatalf("inspect_signal_decoders: %v", err)
	}
	m := a10JSON(t, got)
	if s := a10Get(t, m, "matches", 0, "name"); s != "ais" {
		t.Fatalf("matches[0].name = %v, want ais", s)
	}
	if n := a10Num(t, m, "matches", 0, "symbol_rate"); n != 9600 {
		t.Fatalf("symbol_rate = %v, want 9600", n)
	}
	// A bare symbol rate matches by number, not by name.
	got, err = runOp("inspect_signal_decoders", "1920000")
	if err != nil {
		t.Fatalf("numeric query: %v", err)
	}
	if s := a10Get(t, a10JSON(t, got), "matches", 0, "name"); s != "lte-pbch" {
		t.Fatalf("numeric match = %v, want lte-pbch", s)
	}
	t.Setenv("LRECON_DECODERS", filepath.Join(t.TempDir(), "absent.json"))
	got, err = runOp("inspect_signal_decoders", "ais")
	a10Refused(t, got, err, "not found")
}

func TestInspectSignatureA10(t *testing.T) {
	// A file that is neither a code-signature blob nor a Mach-O is refused by
	// name, not guessed at.
	got, err := runOp("inspect_signature", a10PEPlain(t))
	a10Refused(t, got, err, "neither a code-signature blob nor Mach-O")
}

func TestInspectSQLiteDatabaseA10(t *testing.T) {
	db := make([]byte, 4096)
	copy(db, "SQLite format 3\x00")
	binary.BigEndian.PutUint16(db[16:], 4096)
	db[18], db[19] = 1, 1
	binary.BigEndian.PutUint32(db[92:], 4096)
	binary.BigEndian.PutUint32(db[96:], 3051000)
	got, err := runOp("inspect_sqlite_database", a10Write(t, "t.db", db))
	if err != nil {
		t.Fatalf("inspect_sqlite_database: %v", err)
	}
	m := a10JSON(t, got)
	if n := a10Num(t, m, "page_size"); n != 4096 {
		t.Fatalf("page_size = %v, want 4096", n)
	}
	if s := a10Get(t, m, "version"); s != "1/1 lib 3.51.0" {
		t.Fatalf("version = %v", s)
	}
	got, err = runOp("inspect_sqlite_database", a10Write(t, "not.txt", []byte("hello")))
	a10Refused(t, got, err, "not a sqlite database")
}

func TestInspectWasmArtifactA10(t *testing.T) {
	// magic + version 1 + type section (0 entries) + memory section (1 x min 1)
	w := []byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
		0x01, 0x01, 0x00,
		0x05, 0x03, 0x01, 0x00, 0x01}
	got, err := runOp("inspect_wasm_artifact", a10Write(t, "m.wasm", w))
	if err != nil {
		t.Fatalf("inspect_wasm_artifact: %v", err)
	}
	m := a10JSON(t, got)
	if n := a10Num(t, m, "version"); n != 1 {
		t.Fatalf("version = %v, want 1", n)
	}
	sections, _ := a10Get(t, m, "sections").([]any)
	if len(sections) != 2 {
		t.Fatalf("sections = %v, want 2", sections)
	}
}

func TestInspectWebNetworkCaptureA10(t *testing.T) {
	har := `{"log":{"version":"1.2","creator":{"name":"a10","version":"1"},"entries":[` +
		`{"request":{"method":"GET","url":"https://example.test/a"},"response":{"status":200,"content":{"size":12,"mimeType":"text/plain"}},"time":5}]}}`
	got, err := runOp("inspect_web_network_capture", a10Write(t, "p.har", []byte(har)))
	if err != nil {
		t.Fatalf("inspect_web_network_capture: %v", err)
	}
	m := a10JSON(t, got)
	if s := a10Get(t, m, "version"); s != "1.2" {
		t.Fatalf("version = %v, want 1.2", s)
	}
	if n := a10Num(t, m, "entries"); n != 1 {
		t.Fatalf("entries = %v, want 1", n)
	}
	if n := a10Num(t, m, "requests", 0, "status"); n != 200 {
		t.Fatalf("requests[0].status = %v, want 200", n)
	}
	got, err = runOp("inspect_web_network_capture", a10Write(t, "bad.har", []byte(`{"log":{}}`)))
	a10Refused(t, got, err, "not a HAR 1.2 capture")
}

func TestInspectWebPageA10(t *testing.T) {
	// No DevTools endpoint is started here: the refusal shape is what the CLI
	// contract pins, and the live path was measured against headless Chrome.
	got, err := runOp("inspect_web_page", "127.0.0.1:abc")
	a10Refused(t, got, err, "is not a DevTools endpoint")
}

func TestInspectWebEventListenersA10(t *testing.T) {
	got, err := runOp("inspect_web_event_listeners", "127.0.0.1:0=pick")
	a10Refused(t, got, err, "cdp")

	// The $-refs the op sends must resolve against the step results as
	// webTransport stores them: cdpDeref walks out.Steps[n].Result, which is
	// already the CDP result object, so "$1.result.objectId" is the objectId.
	// $1 addresses the first step after Runtime.enable (index 1), exactly as
	// the op's own step list does.
	out := webOut{Steps: []webStepResult{
		{Method: "Runtime.enable", Ok: true, Result: map[string]any{}},
		{Method: "Runtime.evaluate", Ok: true, Result: map[string]any{
			"result": map[string]any{"type": "object", "objectId": "obj-1"},
		}},
	}}
	if v := cdpDeref(out, "$1.result.objectId"); v != "obj-1" {
		t.Fatalf("$1.result.objectId = %#v, want obj-1", v)
	}
	if v := cdpDeref(out, "$1.result.result.objectId"); v != nil {
		t.Fatalf("double-result ref resolved to %#v; the op would send a bogus objectId", v)
	}
}

func TestInspectWithObjdumpA10(t *testing.T) {
	// The test binary is a native image, so the pure-Go reader must answer with
	// a disassembly tool name rather than shelling out to objdump.
	exe, err := os.Executable()
	if err != nil {
		t.Skipf("no executable: %v", err)
	}
	got, err := runOp("inspect_with_objdump", exe)
	if err != nil {
		t.Fatalf("inspect_with_objdump: %v", err)
	}
	m := a10JSON(t, got)
	tool, _ := a10Get(t, m, "tool").(string)
	if !strings.HasPrefix(tool, "go:debug/") {
		t.Fatalf("tool = %q, want a go:debug/* reader", tool)
	}
	if s, _ := a10Get(t, m, "output").(string); len(s) < 32 {
		t.Fatalf("output too short: %q", s)
	}
}

// a10ResTree builds a resource directory with typ types, one name each and one
// language each, so the walk has real recursion to do.
func a10ResTree(typ int) []byte {
	const base = 0x1000
	dirBytes := 16 + typ*8
	nameDirs := dirBytes
	dataDirs := nameDirs + typ*(16+8)
	entries := dataDirs + typ*(16+8)
	b := make([]byte, entries+typ*16+0x20)
	binary.LittleEndian.PutUint16(b[14:], uint16(typ))
	for i := range typ {
		binary.LittleEndian.PutUint32(b[16+i*8:], uint32(i+1))
		binary.LittleEndian.PutUint32(b[20+i*8:], 0x80000000|uint32(nameDirs+i*(16+8)))
		nd := nameDirs + i*(16+8)
		binary.LittleEndian.PutUint16(b[nd+14:], 1)
		binary.LittleEndian.PutUint32(b[nd+16:], 1)
		binary.LittleEndian.PutUint32(b[nd+20:], 0x80000000|uint32(dataDirs+i*(16+8)))
		dd := dataDirs + i*(16+8)
		binary.LittleEndian.PutUint16(b[dd+14:], 1)
		binary.LittleEndian.PutUint32(b[dd+16:], 0x409)
		binary.LittleEndian.PutUint32(b[dd+20:], uint32(entries+i*16))
		de := entries + i*16
		binary.LittleEndian.PutUint32(b[de:], base+uint32(len(b)-0x10))
		binary.LittleEndian.PutUint32(b[de+4:], 4)
	}
	return b
}

func BenchmarkA10PEResources(b *testing.B) {
	buf := a10ResTree(64)
	sec := []a10Section{{".rsrc", 0x1000, buf}}
	pe := a10PE(sec, map[int][2]uint32{2: {0x1000, uint32(len(buf))}})
	path := filepath.Join(b.TempDir(), "res.exe")
	if err := os.WriteFile(path, pe, 0o644); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := runOp("inspect_pe_resources", path); err != nil {
			b.Fatal(err)
		}
	}
}
