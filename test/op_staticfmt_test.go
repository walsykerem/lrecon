package main

// Fixtures for the final.md STATIC-FORMAT items. Every byte here is built in
// the test: PE headers with real data directories, a WASM module section
// table, safetensors/GGUF headers and a Mach-O with page hashes that this test
// computes with crypto/sha256. No file outside t.TempDir() is read.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func sfWrite(t *testing.T, name string, b []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func sfDecode(t *testing.T, v any, dst any) {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, dst); err != nil {
		t.Fatalf("decode %s: %v", b, err)
	}
}

func sfRun(t *testing.T, name, path string) any {
	t.Helper()
	v, err := runOp(name, path)
	if err != nil {
		t.Fatalf("%s(%s): %v", name, path, err)
	}
	return v
}

func sfWantErr(t *testing.T, name, path, want string) {
	t.Helper()
	_, err := runOp(name, path)
	if err == nil {
		t.Fatalf("%s accepted malformed input", name)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("%s error %q does not mention %q", name, err, want)
	}
}

func sf32(v uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return b
}

func sf64(v uint64) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, v)
	return b
}

// --- PE ---

type sfSection struct {
	name string
	rva  uint32
	data []byte
}

// sfPE builds a PE32+ image with the given sections at 0x400 and the given
// data-directory entries. Section data is file-aligned to 0x200.
func sfPE(t *testing.T, secs []sfSection, dirs map[int][2]uint32) []byte {
	t.Helper()
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
	if secTab+len(secs)*40 > hdrs {
		t.Fatalf("%d sections do not fit the header", len(secs))
	}
	off := hdrs
	for i, s := range secs {
		h := b[secTab+i*40:]
		copy(h[:8], s.name)
		binary.LittleEndian.PutUint32(h[8:], uint32(len(s.data)))
		binary.LittleEndian.PutUint32(h[12:], s.rva)
		rawSize := (len(s.data) + 0x1ff) &^ 0x1ff
		binary.LittleEndian.PutUint32(h[16:], uint32(rawSize))
		binary.LittleEndian.PutUint32(h[20:], uint32(off))
		b = append(b, s.data...)
		b = append(b, make([]byte, rawSize-len(s.data))...)
		off += rawSize
	}
	for i, d := range dirs {
		if i < 0 || i >= 16 {
			t.Fatalf("data directory index %d", i)
		}
		binary.LittleEndian.PutUint32(b[opt+112+i*8:], d[0])
		binary.LittleEndian.PutUint32(b[opt+112+i*8+4:], d[1])
	}
	return b
}

func sfWinCert(der []byte) []byte {
	length := 8 + len(der)
	out := make([]byte, (length+7)&^7)
	binary.LittleEndian.PutUint32(out, uint32(length))
	binary.LittleEndian.PutUint16(out[4:], 0x0200)
	binary.LittleEndian.PutUint16(out[6:], 2)
	copy(out[8:], der)
	return out
}

// --- DER helpers for a real PKCS#7 SignedData fixture ---

var (
	sfOIDSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	sfOIDData       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	sfOIDSHA256     = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	sfOIDMsgDigest  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	sfOIDECDSASHA   = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
)

func sfDER(tag byte, parts ...[]byte) []byte {
	var body []byte
	for _, p := range parts {
		body = append(body, p...)
	}
	out := []byte{tag}
	switch n := len(body); {
	case n < 0x80:
		out = append(out, byte(n))
	default:
		var l []byte
		for n > 0 {
			l = append([]byte{byte(n)}, l...)
			n >>= 8
		}
		out = append(out, 0x80|byte(len(l)))
		out = append(out, l...)
	}
	return append(out, body...)
}

func sfOID(t *testing.T, oid asn1.ObjectIdentifier) []byte {
	t.Helper()
	b, err := asn1.Marshal(oid)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func sfInt(v int) []byte { return sfDER(0x02, []byte{byte(v)}) }

// sfPKCS7 builds a SignedData holding one self-signed certificate and one
// signer whose messageDigest is digest.
func sfPKCS7(t *testing.T, certDER []byte, subjectRaw, digest []byte) []byte {
	t.Helper()
	sha := sfDER(0x30, sfOID(t, sfOIDSHA256), []byte{0x05, 0x00})
	content := sfDER(0x30, sfOID(t, sfOIDData))
	certs := sfDER(0xA0, certDER)
	attr := sfDER(0x30, sfOID(t, sfOIDMsgDigest), sfDER(0x31, sfDER(0x04, digest)))
	signer := sfDER(0x30,
		sfInt(1),
		sfDER(0x30, subjectRaw, sfInt(42)),
		sha,
		sfDER(0xA0, attr),
		sfDER(0x30, sfOID(t, sfOIDECDSASHA)),
		sfDER(0x04, make([]byte, 64)),
	)
	sd := sfDER(0x30, sfInt(1), sfDER(0x31, sha), content, certs, sfDER(0x31, signer))
	return sfDER(0x30, sfOID(t, sfOIDSignedData), sfDER(0xA0, sd))
}

func sfSelfSigned(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "lrecon fixture", Organization: []string{"walsyrea"}},
		NotBefore:    time.Unix(1700000000, 0),
		NotAfter:     time.Unix(1800000000, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func sfAuthenticodeDigest(b []byte, certOff int) []byte {
	opt := int(binary.LittleEndian.Uint32(b[0x3c:])) + 24
	checksum, secDir := opt+64, opt+112+4*8
	h := sha256.New()
	h.Write(b[:checksum])
	h.Write(b[checksum+4 : secDir])
	h.Write(b[secDir+8 : certOff])
	return h.Sum(nil)
}

func TestStaticFmtPECertificates(t *testing.T) {
	certDER := sfSelfSigned(t)
	var cert *x509.Certificate
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}
	pe := sfPE(t, nil, nil)
	certOff := len(pe)
	tableSize := len(sfWinCert(sfPKCS7(t, certDER, cert.RawSubject, make([]byte, 32))))
	pe = sfPE(t, nil, map[int][2]uint32{peDirSecurity: {uint32(certOff), uint32(tableSize)}})
	digest := sfAuthenticodeDigest(pe, certOff)
	table := sfWinCert(sfPKCS7(t, certDER, cert.RawSubject, digest))
	if len(table) != tableSize {
		t.Fatalf("certificate table is %d bytes, header said %d", len(table), tableSize)
	}
	pe = append(pe, table...)

	var got struct {
		Offset  uint64 `json:"offset"`
		Size    uint32 `json:"size"`
		Entries []struct {
			Length       uint32 `json:"length"`
			RevisionName string `json:"revision_name"`
			TypeName     string `json:"type_name"`
			ImageDigest  string `json:"image_digest"`
			Certificates []struct {
				Subject string `json:"subject"`
				Serial  string `json:"serial"`
				SHA256  string `json:"sha256"`
			} `json:"certificates"`
			Signers []struct {
				DigestAlg string `json:"digest_algorithm"`
				Message   string `json:"message_digest"`
			} `json:"signers"`
		} `json:"entries"`
	}
	p := sfWrite(t, "cert.exe", pe)
	sfDecode(t, sfRun(t, "inspect_pe_certificates", p), &got)
	if got.Offset != uint64(certOff) || got.Size != uint32(len(table)) {
		t.Fatalf("certificate table %d+%d, want %d+%d", got.Offset, got.Size, certOff, len(table))
	}
	if len(got.Entries) != 1 {
		t.Fatalf("%d WIN_CERTIFICATE records, want 1", len(got.Entries))
	}
	e := got.Entries[0]
	if e.RevisionName != "2.0" || e.TypeName != "pkcs7" || e.Length != uint32(8+len(sfPKCS7(t, certDER, cert.RawSubject, digest))) {
		t.Fatalf("certificate header = %+v", e)
	}
	if len(e.Certificates) != 1 || !strings.Contains(e.Certificates[0].Subject, "lrecon fixture") ||
		e.Certificates[0].Serial != "2a" || len(e.Certificates[0].SHA256) != 64 {
		t.Fatalf("certificates = %+v", e.Certificates)
	}
	if len(e.Signers) != 1 || e.Signers[0].DigestAlg != "sha256" ||
		len(e.Signers[0].Message) != 64 {
		t.Fatalf("signers = %+v", e.Signers)
	}
	if e.ImageDigest != "match" {
		t.Fatalf("image digest = %q, want match", e.ImageDigest)
	}

	// A signer whose messageDigest is not the image hash is reported as a
	// mismatch, not silently accepted.
	badSize := len(sfWinCert(sfPKCS7(t, certDER, cert.RawSubject, make([]byte, 32))))
	bad := sfPE(t, nil, map[int][2]uint32{peDirSecurity: {uint32(certOff), uint32(badSize)}})
	badDigest := sfAuthenticodeDigest(bad, certOff)
	badTable := sfWinCert(sfPKCS7(t, certDER, cert.RawSubject, make([]byte, 32)))
	bad = append(bad, badTable...)
	sfDecode(t, sfRun(t, "inspect_pe_certificates", sfWrite(t, "bad.exe", bad)), &got)
	if got.Entries[0].ImageDigest != "mismatch: image is "+hexString(badDigest) {
		t.Fatalf("image digest = %q", got.Entries[0].ImageDigest)
	}

	// Cut certificate entry: the advertised length runs past the table.
	cut := sfPE(t, nil, map[int][2]uint32{peDirSecurity: {uint32(certOff), 8}})
	cut = append(cut, sfWinCert(sfPKCS7(t, certDER, cert.RawSubject, digest))...)
	binary.LittleEndian.PutUint32(cut[certOff:], 400)
	sfWantErr(t, "inspect_pe_certificates", sfWrite(t, "cut.exe", cut), "declares 400 bytes")
}

func hexString(b []byte) string {
	const hexd = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2], out[i*2+1] = hexd[c>>4], hexd[c&0xf]
	}
	return string(out)
}

func TestStaticFmtPELoadConfig(t *testing.T) {
	const rva = 0x1000
	lc := make([]byte, 0x120)
	binary.LittleEndian.PutUint32(lc[0:], 0x120)
	binary.LittleEndian.PutUint32(lc[4:], 0x11223344)
	binary.LittleEndian.PutUint16(lc[8:], 1)
	binary.LittleEndian.PutUint16(lc[10:], 2)
	binary.LittleEndian.PutUint32(lc[12:], 5)
	binary.LittleEndian.PutUint32(lc[16:], 7)
	binary.LittleEndian.PutUint64(lc[0x58:], 0x140001000) // security cookie
	binary.LittleEndian.PutUint64(lc[0x60:], 0x140002000) // SEH table
	binary.LittleEndian.PutUint64(lc[0x68:], 2)
	binary.LittleEndian.PutUint64(lc[0x70:], 0x140003000) // guard check
	binary.LittleEndian.PutUint64(lc[0x80:], 0x140004000) // CF table
	binary.LittleEndian.PutUint64(lc[0x88:], 3)
	binary.LittleEndian.PutUint32(lc[0x90:], 0x100|0x400|0x100000) // CF_INSTRUMENTED|CF_FUNCTION_TABLE|RETPOLINE
	binary.LittleEndian.PutUint64(lc[0xC0:], 0x140005000)
	binary.LittleEndian.PutUint64(lc[0x108:], 0x140006000)
	binary.LittleEndian.PutUint64(lc[0x110:], 1)
	binary.LittleEndian.PutUint32(lc[0xF0:], 0x40)
	pe := sfPE(t, []sfSection{{name: ".lc", rva: rva, data: lc}},
		map[int][2]uint32{peDirLoadConfig: {rva, 0x120}})

	var got struct {
		DeclaredSize  uint32   `json:"declared_size"`
		TimeDateStamp uint32   `json:"timestamp"`
		Security      uint64   `json:"security_cookie"`
		GS            bool     `json:"gs"`
		SafeSEH       bool     `json:"safe_seh"`
		SEHTable      uint64   `json:"seh_table"`
		SEHCount      uint64   `json:"seh_count"`
		CFG           bool     `json:"cfg"`
		CFFuncTable   uint64   `json:"cfg_function_table"`
		CFFuncCount   uint64   `json:"cfg_function_count"`
		GuardFlags    uint32   `json:"guard_flags"`
		GuardNames    []string `json:"guard_flag_names"`
		CastGuard     bool     `json:"cast_guard"`
		GuardCheck    uint64   `json:"guard_check_function"`
		DynamicReloc  uint64   `json:"dynamic_value_reloc_table"`
		HotPatch      uint32   `json:"hotpatch_table_offset"`
	}
	sfDecode(t, sfRun(t, "inspect_pe_load_config", sfWrite(t, "lc.exe", pe)), &got)
	if got.DeclaredSize != 0x120 || got.TimeDateStamp != 0x11223344 ||
		got.Security != 0x140001000 || got.GuardCheck != 0x140003000 ||
		got.DynamicReloc != 0x140005000 || got.HotPatch != 0x40 {
		t.Fatalf("load config = %+v", got)
	}
	if !got.GS || !got.CFG || !got.SafeSEH || got.CastGuard {
		t.Fatalf("flags = %+v", got)
	}
	if got.SEHTable != 0x140002000 || got.SEHCount != 2 || got.CFFuncTable != 0x140004000 || got.CFFuncCount != 3 {
		t.Fatalf("tables = %+v", got)
	}
	want := "CF_INSTRUMENTED,CF_FUNCTION_TABLE_PRESENT,RETPOLINE_PRESENT"
	if strings.Join(got.GuardNames, ",") != want {
		t.Fatalf("guard names = %v, want %s", got.GuardNames, want)
	}

	// Empty directory is absent structure: present=false, not an error.
	empty := sfPE(t, []sfSection{{name: ".lc", rva: rva, data: lc}}, nil)
	{
		var m struct {
			Present bool `json:"present"`
		}
		sfDecode(t, sfRun(t, "inspect_pe_load_config", sfWrite(t, "empty.exe", empty)), &m)
		if m.Present {
			t.Fatalf("present = %v, want false", m)
		}
	}
}

func TestStaticFmtPEResources(t *testing.T) {
	rsrc := make([]byte, 0xC4)
	dir := func(off int, nID int, entries ...[2]uint32) {
		binary.LittleEndian.PutUint16(rsrc[off+14:], uint16(nID))
		for i, e := range entries {
			binary.LittleEndian.PutUint32(rsrc[off+16+i*8:], e[0])
			binary.LittleEndian.PutUint32(rsrc[off+20+i*8:], e[1])
		}
	}
	// Root: type 3 and a named type whose UTF-16 name sits at 0x20.
	dir(0x00, 2, [2]uint32{3, 0x80000030}, [2]uint32{0x80000020, 0x80000048})
	binary.LittleEndian.PutUint16(rsrc[0x20:], 6)
	for i, r := range []rune("MYTYPE") {
		binary.LittleEndian.PutUint16(rsrc[0x22+i*2:], uint16(r))
	}
	dir(0x30, 1, [2]uint32{1, 0x80000060})
	dir(0x48, 1, [2]uint32{2, 0x80000078})
	dir(0x60, 1, [2]uint32{1033, 0x90})
	dir(0x78, 1, [2]uint32{1031, 0xA0})
	for _, leaf := range []int{0x90, 0xA0} {
		binary.LittleEndian.PutUint32(rsrc[leaf:], 0x10C0) // data RVA
		binary.LittleEndian.PutUint32(rsrc[leaf+4:], 4)
		binary.LittleEndian.PutUint32(rsrc[leaf+8:], 1252)
	}
	copy(rsrc[0xC0:], "ICON")
	pe := sfPE(t, []sfSection{{name: ".rsrc", rva: 0x1000, data: rsrc}},
		map[int][2]uint32{peDirResource: {0x1000, uint32(len(rsrc))}})

	var got struct {
		Section string `json:"section"`
		Types   []struct {
			ID    uint32 `json:"id"`
			Name  string `json:"name"`
			Kind  string `json:"kind"`
			Names []struct {
				ID    uint32 `json:"id"`
				Langs []struct {
					Language uint32 `json:"language"`
					Offset   uint64 `json:"file_offset"`
					Size     uint32 `json:"size"`
					CodePage uint32 `json:"codepage"`
				} `json:"languages"`
			} `json:"entries"`
		} `json:"types"`
	}
	sfDecode(t, sfRun(t, "inspect_pe_resources", sfWrite(t, "res.exe", pe)), &got)
	if got.Section != ".rsrc" || len(got.Types) != 2 {
		t.Fatalf("resources = %+v", got)
	}
	icon := got.Types[0]
	if icon.ID != 3 || icon.Kind != "ICON" || len(icon.Names) != 1 || icon.Names[0].ID != 1 {
		t.Fatalf("icon type = %+v", icon)
	}
	lang := icon.Names[0].Langs[0]
	if lang.Language != 1033 || lang.Offset != 0x4C0 || lang.Size != 4 || lang.CodePage != 1252 {
		t.Fatalf("icon language = %+v", lang)
	}
	named := got.Types[1]
	if named.Name != "MYTYPE" || len(named.Names) != 1 || named.Names[0].ID != 2 ||
		named.Names[0].Langs[0].Language != 1031 {
		t.Fatalf("named type = %+v", named)
	}

	// A leaf where a directory level is required is malformed, not empty.
	pe2 := sfPE(t, []sfSection{{name: ".rsrc", rva: 0x1000, data: rsrc}},
		map[int][2]uint32{peDirResource: {0x1000, uint32(len(rsrc))}})
	binary.LittleEndian.PutUint32(pe2[0x400+20:], 0) // type entry points at a leaf
	sfWantErr(t, "inspect_pe_resources", sfWrite(t, "badres.exe", pe2), "points at data")
}

// --- WASM ---

func sfLEB(v uint32) []byte {
	var out []byte
	for {
		b := byte(v & 0x7f)
		v >>= 7
		if v != 0 {
			out = append(out, b|0x80)
			continue
		}
		return append(out, b)
	}
}

func sfWasmSec(id byte, payload []byte) []byte {
	out := append([]byte{id}, sfLEB(uint32(len(payload)))...)
	return append(out, payload...)
}

func sfWasmString(s string) []byte {
	return append(sfLEB(uint32(len(s))), s...)
}

func sfWasmModule() []byte {
	b := []byte("\x00asm")
	b = append(b, sf32(1)...)
	b = append(b, sfWasmSec(1, []byte{1, 0x60, 0, 0})...)
	imp := []byte{1}
	imp = append(imp, sfWasmString("env")...)
	imp = append(imp, sfWasmString("log")...)
	imp = append(imp, 0, 0) // func, type index 0
	b = append(b, sfWasmSec(2, imp)...)
	b = append(b, sfWasmSec(3, []byte{1, 0})...)
	exp := []byte{1}
	exp = append(exp, sfWasmString("run")...)
	exp = append(exp, 0, 1) // func, index 1
	b = append(b, sfWasmSec(7, exp)...)
	custom := append(sfWasmString("producers"), 1, 0, 0)
	return append(b, sfWasmSec(0, custom)...)
}

func TestStaticFmtWasm(t *testing.T) {
	var got struct {
		Version  uint32 `json:"version"`
		Sections []struct {
			ID     uint8  `json:"id"`
			Name   string `json:"name"`
			Offset int    `json:"payload_offset"`
			Size   uint32 `json:"payload_bytes"`
		} `json:"sections"`
		Imports []struct {
			Module string `json:"module"`
			Field  string `json:"field"`
			Kind   string `json:"kind"`
			Type   uint32 `json:"type_index"`
		} `json:"imports"`
		Exports []struct {
			Name  string `json:"name"`
			Kind  string `json:"kind"`
			Index uint32 `json:"index"`
		} `json:"exports"`
	}
	sfDecode(t, sfRun(t, "inspect_wasm_artifact", sfWrite(t, "m.wasm", sfWasmModule())), &got)
	if got.Version != 1 || len(got.Sections) != 5 {
		t.Fatalf("wasm = %+v", got)
	}
	if got.Sections[0].ID != 1 || got.Sections[0].Name != "type" ||
		got.Sections[0].Offset != 10 || got.Sections[0].Size != 4 {
		t.Fatalf("first section = %+v", got.Sections[0])
	}
	if got.Sections[4].Name != "custom:producers" {
		t.Fatalf("custom section = %+v", got.Sections[4])
	}
	if len(got.Imports) != 1 || got.Imports[0].Module != "env" || got.Imports[0].Field != "log" ||
		got.Imports[0].Kind != "func" || got.Imports[0].Type != 0 {
		t.Fatalf("imports = %+v", got.Imports)
	}
	if len(got.Exports) != 1 || got.Exports[0].Name != "run" || got.Exports[0].Kind != "func" ||
		got.Exports[0].Index != 1 {
		t.Fatalf("exports = %+v", got.Exports)
	}

	m := sfWasmModule()
	sfWantErr(t, "inspect_wasm_artifact", sfWrite(t, "cut.wasm", m[:len(m)-1]), "declares")
}

// --- Model artifacts ---

func TestStaticFmtSafetensors(t *testing.T) {
	header := `{"__metadata__":{"format":"pt"},"a":{"dtype":"F16","shape":[2,3],"data_offsets":[0,12]}}`
	b := append(sf64(uint64(len(header))), header...)
	b = append(b, make([]byte, 12)...)

	var got struct {
		Format  string            `json:"format"`
		Header  uint64            `json:"header_bytes"`
		Data    uint64            `json:"data_bytes"`
		Meta    map[string]string `json:"metadata"`
		Tensors []struct {
			Name     string   `json:"name"`
			DType    string   `json:"dtype"`
			Shape    []uint64 `json:"shape"`
			Elements uint64   `json:"elements"`
			Begin    uint64   `json:"begin"`
			End      uint64   `json:"end"`
			Bytes    uint64   `json:"bytes"`
		} `json:"tensors"`
	}
	sfDecode(t, sfRun(t, "inspect_model_artifact", sfWrite(t, "s.safetensors", b)), &got)
	if got.Format != "safetensors" || got.Header != uint64(len(header)) || got.Data != 12 ||
		got.Meta["format"] != "pt" {
		t.Fatalf("safetensors header = %+v", got)
	}
	if len(got.Tensors) != 1 || got.Tensors[0].Name != "a" || got.Tensors[0].DType != "F16" ||
		len(got.Tensors[0].Shape) != 2 || got.Tensors[0].Elements != 6 ||
		got.Tensors[0].Begin != 0 || got.Tensors[0].End != 12 || got.Tensors[0].Bytes != 12 {
		t.Fatalf("tensors = %+v", got.Tensors)
	}

	bad := append(sf64(9000), []byte("{}")...)
	sfWantErr(t, "inspect_model_artifact", sfWrite(t, "bad.safetensors", bad), "header declares")

	// data_offsets that point past the payload are refused, not clamped.
	h := `{"a":{"dtype":"U8","shape":[2],"data_offsets":[0,3]}}`
	o := append(sf64(uint64(len(h))), h...)
	o = append(o, make([]byte, 2)...)
	sfWantErr(t, "inspect_model_artifact", sfWrite(t, "off.safetensors", o), "spans")
}

func sfGGUFString(s string) []byte {
	return append(sf64(uint64(len(s))), s...)
}

func TestStaticFmtGGUF(t *testing.T) {
	b := []byte("GGUF")
	b = append(b, sf32(3)...)
	b = append(b, sf64(1)...) // tensors
	b = append(b, sf64(3)...) // metadata entries
	kv := func(key string, typ uint32, value []byte) {
		b = append(b, sfGGUFString(key)...)
		b = append(b, sf32(typ)...)
		b = append(b, value...)
	}
	kv("general.name", 8, sfGGUFString("demo"))
	kv("llama.block_count", 4, sf32(32))
	arr := append(sf32(8), sf64(2)...)
	arr = append(arr, sfGGUFString("a")...)
	arr = append(arr, sfGGUFString("b")...)
	kv("tokenizer.ggml.tokens", 9, arr)
	b = append(b, sfGGUFString("blk.0.weight")...)
	b = append(b, sf32(2)...) // n_dims
	b = append(b, sf64(2)...)
	b = append(b, sf64(3)...)
	b = append(b, sf32(0)...) // F32
	b = append(b, sf64(0)...)

	var got struct {
		Format   string `json:"format"`
		Version  uint32 `json:"version"`
		Declared uint64 `json:"tensor_count"`
		Metadata []struct {
			Key   string `json:"key"`
			Type  string `json:"type"`
			Value any    `json:"value"`
		} `json:"metadata"`
		Tensors []struct {
			Name     string   `json:"name"`
			Shape    []uint64 `json:"shape"`
			TypeName string   `json:"ggml_type_name"`
			Offset   uint64   `json:"offset"`
		} `json:"tensors"`
	}
	sfDecode(t, sfRun(t, "inspect_model_artifact", sfWrite(t, "x.gguf", b)), &got)
	if got.Format != "gguf" || got.Version != 3 || got.Declared != 1 || len(got.Metadata) != 3 {
		t.Fatalf("gguf header = %+v", got)
	}
	if got.Metadata[0].Key != "general.name" || got.Metadata[0].Type != "string" || got.Metadata[0].Value != "demo" {
		t.Fatalf("metadata[0] = %+v", got.Metadata[0])
	}
	if got.Metadata[1].Value != float64(32) {
		t.Fatalf("metadata[1] = %+v", got.Metadata[1])
	}
	arrv, ok := got.Metadata[2].Value.([]any)
	if !ok || len(arrv) != 2 || arrv[0] != "a" || arrv[1] != "b" {
		t.Fatalf("metadata[2] = %+v", got.Metadata[2])
	}
	if len(got.Tensors) != 1 || got.Tensors[0].Name != "blk.0.weight" || got.Tensors[0].TypeName != "F32" ||
		len(got.Tensors[0].Shape) != 2 || got.Tensors[0].Shape[0] != 2 || got.Tensors[0].Shape[1] != 3 {
		t.Fatalf("tensors = %+v", got.Tensors)
	}

	cut := b[:20]
	sfWantErr(t, "inspect_model_artifact", sfWrite(t, "cut.gguf", cut), "shorter than the GGUF header")
}

// --- Mach-O code signature ---

func sfCodeDirectory(ident string, code []byte) []byte {
	const hdr = 88
	hashOff := hdr + len(ident) + 1
	total := hashOff + 32
	cd := make([]byte, total)
	be := binary.BigEndian
	be.PutUint32(cd[0:], csCodeDirMagic)
	be.PutUint32(cd[4:], uint32(total))
	be.PutUint32(cd[8:], 0x20400)
	be.PutUint32(cd[12:], 0)
	be.PutUint32(cd[16:], uint32(hashOff))
	be.PutUint32(cd[20:], hdr)
	be.PutUint32(cd[24:], 0) // special slots
	be.PutUint32(cd[28:], 1) // code slots
	be.PutUint32(cd[32:], uint32(len(code)))
	cd[36] = 32 // hash size
	cd[37] = 2  // sha256
	cd[38] = 0
	cd[39] = 12 // 4096-byte pages
	be.PutUint64(cd[56:], uint64(len(code)))
	copy(cd[hdr:], ident)
	sum := sha256.Sum256(code)
	copy(cd[hashOff:], sum[:])
	return cd
}

func sfSuperBlob(cd []byte) []byte {
	total := 20 + len(cd)
	b := make([]byte, total)
	be := binary.BigEndian
	be.PutUint32(b[0:], csSuperBlobMagic)
	be.PutUint32(b[4:], uint32(total))
	be.PutUint32(b[8:], 1)
	be.PutUint32(b[12:], 0) // CodeDirectory
	be.PutUint32(b[16:], 20)
	copy(b[20:], cd)
	return b
}

func sfMachOWithSignature(t *testing.T) []byte {
	t.Helper()
	const codeLen = 4096
	ident := "com.example.demo"
	cdLen := 88 + len(ident) + 1 + 32
	blobLen := 20 + cdLen
	code := make([]byte, codeLen)
	le := binary.LittleEndian
	le.PutUint32(code[0:], 0xfeedfacf)
	le.PutUint32(code[4:], 0x0100000c) // arm64
	le.PutUint32(code[8:], 0)
	le.PutUint32(code[12:], 2) // MH_EXECUTE
	le.PutUint32(code[16:], 1) // ncmds
	le.PutUint32(code[20:], 16)
	le.PutUint32(code[24:], 0)
	le.PutUint32(code[28:], 0)
	le.PutUint32(code[32:], uint32(lcCodeSignature))
	le.PutUint32(code[36:], 16)
	le.PutUint32(code[40:], codeLen) // LC_CODE_SIGNATURE dataoff
	le.PutUint32(code[44:], uint32(blobLen))
	blob := sfSuperBlob(sfCodeDirectory(ident, code))
	if len(blob) != blobLen {
		t.Fatalf("superblob is %d bytes, header said %d", len(blob), blobLen)
	}
	return append(code, blob...)
}

func TestStaticFmtSignature(t *testing.T) {
	macho := sfMachOWithSignature(t)
	var got struct {
		Source string `json:"source"`
		Length uint32 `json:"length"`
		Blobs  []struct {
			TypeName string `json:"type_name"`
			Magic    string `json:"magic"`
		} `json:"blobs"`
		CodeDirectory struct {
			Version    uint32 `json:"version"`
			Identifier string `json:"identifier"`
			HashType   string `json:"hash_type"`
			PageSize   uint32 `json:"page_size"`
			CodeLimit  uint64 `json:"code_limit"`
			CodeSlots  uint32 `json:"code_slots"`
			CDHash     string `json:"cdhash"`
		} `json:"code_directory"`
		Verification struct {
			PagesChecked uint32   `json:"pages_checked"`
			HashesOK     bool     `json:"hashes_ok"`
			Mismatched   []uint32 `json:"mismatched_pages"`
			Reason       string   `json:"reason"`
		} `json:"verification"`
	}
	p := sfWrite(t, "signed", macho)
	sfDecode(t, sfRun(t, "inspect_signature", p), &got)
	if got.Source != "macho" || len(got.Blobs) != 1 || got.Blobs[0].TypeName != "CodeDirectory" {
		t.Fatalf("signature = %+v", got)
	}
	if got.CodeDirectory.Version != 0x20400 || got.CodeDirectory.Identifier != "com.example.demo" ||
		got.CodeDirectory.HashType != "sha256" || got.CodeDirectory.PageSize != 4096 ||
		got.CodeDirectory.CodeLimit != 4096 || got.CodeDirectory.CodeSlots != 1 ||
		len(got.CodeDirectory.CDHash) != 64 {
		t.Fatalf("code directory = %+v", got.CodeDirectory)
	}
	if !got.Verification.HashesOK || got.Verification.PagesChecked != 1 || got.Verification.Reason != "" {
		t.Fatalf("verification = %+v", got.Verification)
	}

	// Tampering with one byte inside the sealed page must be caught.
	tampered := append([]byte(nil), macho...)
	tampered[100] ^= 0xff
	sfDecode(t, sfRun(t, "inspect_signature", sfWrite(t, "tampered", tampered)), &got)
	if got.Verification.HashesOK || len(got.Verification.Mismatched) != 1 || got.Verification.Mismatched[0] != 0 {
		t.Fatalf("tampered verification = %+v", got.Verification)
	}

	// A bare SuperBlob can be decoded but has no signed bytes to hash.
	blob := sfSuperBlob(sfCodeDirectory("bare", make([]byte, 4096)))
	sfDecode(t, sfRun(t, "inspect_signature", sfWrite(t, "bare.sig", blob)), &got)
	if got.Source != "superblob" || got.Verification.Reason == "" || got.Verification.HashesOK {
		t.Fatalf("bare signature = %+v", got)
	}

	// Truncated SuperBlob: the declared length is past the file.
	sfWantErr(t, "inspect_signature", sfWrite(t, "cut.sig", blob[:len(blob)-8]), "declares")
}
