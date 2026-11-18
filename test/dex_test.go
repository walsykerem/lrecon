package main

import (
	"crypto/sha1"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"hash/adler32"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf16"
)

// dexMethodRef is one method_id: class and proto indexes are only carried, the
// name string is what the reader dereferences.
type dexMethodRef struct {
	classIdx, protoIdx uint16
	nameIdx            uint32
}

type dexClassFixture struct {
	classIdx, superIdx uint32
	methods            []int // method_id indices, in class_data order
}

// dexFixture is a synthetic dex assembled byte by byte: no fixture files, no
// network. Tables are laid out header | string_ids | type_ids | method_ids |
// class_defs | data, and every offset is real, so the reader walks the same
// 3-deref chain a shipped classes.dex has.
type dexFixture struct {
	version string
	hdrSize int // 0 means 0x70; v041 uses 0x78
	strs    []string
	types   []uint32 // type_id[i] -> descriptor string index
	methods []dexMethodRef
	classes []dexClassFixture
}

func (f dexFixture) build() []byte {
	hdr := f.hdrSize
	if hdr == 0 {
		hdr = 0x70
	}
	strTab := hdr
	typTab := strTab + 4*len(f.strs)
	metTab := typTab + 4*len(f.types)
	clsTab := metTab + 8*len(f.methods)
	data := clsTab + 32*len(f.classes)
	le := binary.LittleEndian

	var body []byte
	classData := make([]int, len(f.classes))
	for i, c := range f.classes {
		classData[i] = data + len(body)
		body = append(body, 0, 0, byte(len(c.methods)), 0) // static/instance fields, direct/virtual methods
		prev := 0
		for _, m := range c.methods {
			body = append(body, byte(m-prev), 0x01, 0x00) // method_idx_diff, access_flags, code_off
			prev = m
		}
	}
	strData := make([]int, len(f.strs))
	for i, s := range f.strs {
		strData[i] = data + len(body)
		units := utf16.Encode([]rune(s))
		body = append(body, dexULEBEnc(len(units))...)
		body = append(body, dexMUTF8Enc(units)...)
		body = append(body, 0)
	}

	b := make([]byte, data+len(body))
	copy(b[data:], body)
	copy(b, "dex\n"+f.version+"\x00")
	le.PutUint32(b[0x24:], uint32(hdr))
	le.PutUint32(b[0x28:], 0x12345678)
	le.PutUint32(b[0x38:], uint32(len(f.strs)))
	le.PutUint32(b[0x3C:], uint32(strTab))
	le.PutUint32(b[0x40:], uint32(len(f.types)))
	le.PutUint32(b[0x44:], uint32(typTab))
	le.PutUint32(b[0x58:], uint32(len(f.methods)))
	le.PutUint32(b[0x5C:], uint32(metTab))
	le.PutUint32(b[0x60:], uint32(len(f.classes)))
	le.PutUint32(b[0x64:], uint32(clsTab))
	le.PutUint32(b[0x68:], uint32(len(body)))
	le.PutUint32(b[0x6C:], uint32(data))
	for i, off := range strData {
		le.PutUint32(b[strTab+4*i:], uint32(off))
	}
	for i, idx := range f.types {
		le.PutUint32(b[typTab+4*i:], idx)
	}
	for i, m := range f.methods {
		at := b[metTab+8*i:]
		le.PutUint16(at, m.classIdx)
		le.PutUint16(at[2:], m.protoIdx)
		le.PutUint32(at[4:], m.nameIdx)
	}
	for i, c := range f.classes {
		at := b[clsTab+32*i:]
		le.PutUint32(at, c.classIdx)
		le.PutUint32(at[8:], c.superIdx)
		le.PutUint32(at[24:], uint32(classData[i]))
	}
	return dexSeal(b)
}

// dexSeal writes what a dex writer writes: file_size, the SHA-1 signature and
// the adler32 checksum over bytes[0x0C:file_size].
func dexSeal(b []byte) []byte {
	binary.LittleEndian.PutUint32(b[0x20:], uint32(len(b)))
	sig := sha1.Sum(b[0x20:])
	copy(b[0x0C:0x20], sig[:])
	binary.LittleEndian.PutUint32(b[0x08:], adler32.Checksum(b[0x0C:]))
	return b
}

func dexULEBEnc(v int) []byte {
	var out []byte
	for {
		c := byte(v & 0x7F)
		v >>= 7
		if v != 0 {
			c |= 0x80
		}
		out = append(out, c)
		if v == 0 {
			return out
		}
	}
}

// dexMUTF8Enc writes UTF-16 units the way dex does: each unit on its own, so a
// surrogate pair becomes the CESU-8 6-byte form, never a 4-byte sequence.
func dexMUTF8Enc(units []uint16) []byte {
	var out []byte
	for _, u := range units {
		switch {
		case u != 0 && u < 0x80:
			out = append(out, byte(u))
		case u < 0x800:
			out = append(out, 0xC0|byte(u>>6), 0x80|byte(u&0x3F))
		default:
			out = append(out, 0xE0|byte(u>>12), 0x80|byte(u>>6&0x3F), 0x80|byte(u&0x3F))
		}
	}
	return out
}

// dexHappy is two classes: Foo carries an ASCII and a non-ASCII method name, Bar
// carries a name whose first rune is a surrogate pair.
func dexHappy() dexFixture {
	return dexFixture{
		version: "035",
		strs: []string{
			"Lcom/example/Foo;",
			"Ljava/lang/Object;",
			"Lcom/example/Bar;",
			"<init>",
			"run",
			"café",
			"𝒳run",
		},
		types: []uint32{0, 1, 2},
		methods: []dexMethodRef{
			{classIdx: 0, nameIdx: 3},
			{classIdx: 0, nameIdx: 4},
			{classIdx: 2, nameIdx: 5},
			{classIdx: 2, nameIdx: 6},
		},
		classes: []dexClassFixture{
			{classIdx: 0, superIdx: 1, methods: []int{0, 1}},
			{classIdx: 2, superIdx: 1, methods: []int{2, 3}},
		},
	}
}

func TestDexNames(t *testing.T) {
	d, err := Probe(writeTemp(t, "classes.dex", dexHappy().build()))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if d.Kind != "dex" {
		t.Fatalf("Kind = %q, want dex", d.Kind)
	}
	for _, want := range []string{
		"dex: version 035",
		"dex: strings=7 types=3 classes=2",
		"dex: class Lcom/example/Foo; super Ljava/lang/Object; methods 2: <init>, run",
		"dex: class Lcom/example/Bar; super Ljava/lang/Object; methods 2: café, 𝒳run",
	} {
		wantNote(t, d, want)
	}
	if !notesContain(d, "signature_verified:false") {
		t.Fatalf("signature_verified:false missing from %q", d.Notes)
	}
	if !containsStr(d.Capabilities, "dex-035") {
		t.Fatalf("Capabilities = %q, want dex-035", d.Capabilities)
	}
	if d.Coverage == nil || d.Coverage.Parsed != 2 || d.Coverage.Skipped != 0 || d.Coverage.Unknown != 0 {
		t.Fatalf("Coverage = %+v, want 2 parsed", d.Coverage)
	}
	if len(d.Skipped) != 0 {
		t.Fatalf("Skipped = %+v, want none", d.Skipped)
	}
	if d.BytesScanned != d.FileSize || d.FileSize == 0 {
		t.Fatalf("bytes %d/%d not truthful", d.BytesScanned, d.FileSize)
	}
}

// TestDexVersions covers the whitelist: every accepted version reads the same
// two classes, and 041's 0x78 header carries container_size/header_offset.
func TestDexVersions(t *testing.T) {
	cases := []struct {
		version string
		hdrSize int
	}{
		{"035", 0}, {"037", 0}, {"038", 0}, {"039", 0}, {"040", 0}, {"041", 0x78},
	}
	for _, c := range cases {
		t.Run(c.version, func(t *testing.T) {
			f := dexHappy()
			f.version, f.hdrSize = c.version, c.hdrSize
			d, err := Probe(writeTemp(t, "classes.dex", f.build()))
			if err != nil {
				t.Fatalf("Probe: %v", err)
			}
			if d.Coverage == nil || d.Coverage.Parsed != 2 || len(d.Skipped) != 0 {
				t.Fatalf("Coverage = %+v skipped %+v", d.Coverage, d.Skipped)
			}
			if !containsStr(d.Capabilities, "dex-"+c.version) {
				t.Fatalf("Capabilities = %q, want dex-%s", d.Capabilities, c.version)
			}
			if c.hdrSize == 0x78 {
				wantNote(t, d, "dex: container_size=0 header_offset=0")
			}
		})
	}
}

func TestDexRefusals(t *testing.T) {
	clsOff := func(b []byte) int { return int(binary.LittleEndian.Uint32(b[0x64:])) }
	strDataOff := func(b []byte) int {
		return int(binary.LittleEndian.Uint32(b[int(binary.LittleEndian.Uint32(b[0x3C:])):]))
	}
	cases := []struct {
		name   string
		reason string
		mutate func([]byte) []byte
	}{
		{"version 036", "dex-unsupported-magic", func(b []byte) []byte {
			copy(b[4:7], "036")
			return b
		}},
		{"endian tag 78563412", "dex-bad-endian", func(b []byte) []byte {
			binary.LittleEndian.PutUint32(b[0x28:], 0x78563412)
			return dexSeal(b)
		}},
		{"adler32 mismatch", "dex-checksum-mismatch", func(b []byte) []byte {
			b[len(b)-1] ^= 0xFF
			return b
		}},
		{"truncated class_defs", "dex-oob-section", func(b []byte) []byte {
			binary.LittleEndian.PutUint32(b[0x60:], 0x7FFF)
			return dexSeal(b)
		}},
		{"class_def offset past EOF", "dex-truncated-class", func(b []byte) []byte {
			binary.LittleEndian.PutUint32(b[clsOff(b)+24:], 0xFFFFF000)
			return dexSeal(b)
		}},
		{"mutf8 continuation truncated", "dex-bad-string", func(b []byte) []byte {
			// descriptor 0 is "Lcom/example/Foo;": a one-byte ULEB128 length of
			// 17 units, then a 3-byte lead whose continuation is cut by the NUL.
			p := strDataOff(b)
			b[p+1], b[p+2], b[p+3] = 0xE2, 0x80, 0x00
			return dexSeal(b)
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d, err := Probe(writeTemp(t, "classes.dex", c.mutate(dexHappy().build())))
			if err != nil {
				t.Fatalf("Probe: %v", err)
			}
			if len(d.Skipped) != 1 {
				t.Fatalf("Skipped = %+v, want exactly one", d.Skipped)
			}
			if d.Skipped[0].Reason != c.reason {
				t.Fatalf("reason = %q, want %q (detail %q)", d.Skipped[0].Reason, c.reason, d.Skipped[0].Detail)
			}
			if d.Coverage == nil || d.Coverage.Skipped != 1 {
				t.Fatalf("Coverage = %+v, want one skipped unit", d.Coverage)
			}
		})
	}
}

// TestDexHostileHeader feeds every offset field 0xFFFFFFFF one at a time, then
// all at once, then truncations: the digest must refuse, never panic.
func TestDexHostileHeader(t *testing.T) {
	base := dexHappy().build()
	for _, off := range []int{0x08, 0x0C, 0x20, 0x24, 0x28, 0x34, 0x38, 0x3C, 0x40, 0x44, 0x48, 0x4C, 0x50, 0x54, 0x58, 0x5C, 0x60, 0x64, 0x68, 0x6C} {
		b := append([]byte(nil), base...)
		binary.LittleEndian.PutUint32(b[off:], 0xFFFFFFFF)
		dexProbeNoPanic(t, fmt.Sprintf("field 0x%02x", off), b)
	}
	all := append([]byte(nil), base...)
	for _, off := range []int{0x34, 0x3C, 0x44, 0x4C, 0x54, 0x5C, 0x64, 0x6C} {
		binary.LittleEndian.PutUint32(all[off:], 0xFFFFFFFF)
	}
	for _, off := range []int{0x38, 0x40, 0x48, 0x50, 0x58, 0x60, 0x68} {
		binary.LittleEndian.PutUint32(all[off:], 0xFFFFFFFF)
	}
	dexProbeNoPanic(t, "every section hostile", all)
	for _, n := range []int{0, 1, 4, 0x6F, 0x70, len(base) / 2} {
		dexProbeNoPanic(t, fmt.Sprintf("truncated to %d bytes", n), base[:n])
	}
}

func dexProbeNoPanic(t *testing.T, name string, b []byte) {
	t.Helper()
	p := writeTemp(t, "classes.dex", b)
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("%s: panic: %v", name, r)
		}
	}()
	d, err := Probe(p)
	if err != nil {
		// A zero-byte target is refused with a typed error, not digested:
		// no magic, no hash, no identity to report.
		if len(b) == 0 {
			return
		}
		t.Fatalf("%s: %v", name, err)
	}
	if strings.Contains(d.Text(), "reason: ") {
		t.Fatalf("%s: free-text reason leaked: %s", name, d.Text())
	}
}

// TestListJebUnitsRefusesWhenEveryInputFails pins the refusal measured on a
// non-DEX target: zero readable dex is exit 2 with a kind, never an empty
// success carrying an errors list. A mixed dir answers (exit 0) and keeps the
// per-file error, so the good dex is not thrown away with the bad one.
func TestListJebUnitsRefusesWhenEveryInputFails(t *testing.T) {
	t.Run("not a dex", func(t *testing.T) {
		_, err := runOp("list_jeb_units", "/bin/ls")
		if err == nil {
			t.Fatal("list_jeb_units on /bin/ls = nil error, want a refusal")
		}
		if !strings.Contains(err.Error(), "not a readable DEX image") || !strings.Contains(err.Error(), "not a DEX image") {
			t.Fatalf("error = %v, want it to name the unreadable DEX input", err)
		}
		if got := classify(err.Error()); got != kindBadArg {
			t.Fatalf("kind = %v, want %v for a non-DEX input", got, kindBadArg)
		}
		stdout, stderr, rc := runCLIAll(t, "--op", "list_jeb_units", "--json", "/bin/ls")
		if rc != 2 || !strings.Contains(stderr, "not a DEX image") {
			t.Fatalf("CLI = rc %d, stderr %q; want rc 2 and the reason on stderr", rc, stderr)
		}
		if op, msg, kind := opEnvelope(t, stdout); op != "list_jeb_units" || kind != "bad_arg" || !strings.Contains(msg, "not a DEX image") {
			t.Fatalf("stdout envelope = op %q, msg %q, kind %q; want a bad_arg refusal naming the DEX input", op, msg, kind)
		}
	})
	t.Run("broken tables", func(t *testing.T) {
		b := dexHappy().build()
		binary.LittleEndian.PutUint32(b[0x60:], 0x7FFF) // class_defs_size past EOF
		_, err := runOp("list_jeb_units", writeTemp(t, "classes.dex", b))
		if err == nil || classify(err.Error()) != kindBadArg {
			t.Fatalf("error = %v (kind %v), want bad_arg", err, classify(err.Error()))
		}
		_, _, rc := runCLIAll(t, "--op", "list_jeb_units", writeTemp(t, "classes.dex", b))
		if rc != 2 {
			t.Fatalf("rc = %d, want 2 when the only dex will not open", rc)
		}
	})
	t.Run("mixed dir", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "classes.dex"), dexHappy().build(), 0o644); err != nil {
			t.Fatal(err)
		}
		bad := filepath.Join(dir, "classes2.dex")
		if err := os.WriteFile(bad, []byte("not a dex at all"), 0o644); err != nil {
			t.Fatal(err)
		}
		v, err := runOp("list_jeb_units", dir)
		if err != nil {
			t.Fatalf("mixed dir = %v, want the readable dex to answer", err)
		}
		res := v.(jebdUnits)
		if len(res.Units) != 2 {
			t.Fatalf("units = %+v, want the two classes from classes.dex", res.Units)
		}
		if want := bad + ": not a DEX image"; !strings.Contains(strings.Join(res.Errors, "\n"), want) {
			t.Fatalf("errors = %v, want %q kept beside the good dex", res.Errors, want)
		}
		stdout, _, rc := runCLIAll(t, "--op", "list_jeb_units", dir, "--json")
		if rc != 0 {
			t.Fatalf("rc = %d, want 0 for a mixed dir; stdout %q", rc, stdout)
		}
		var doc struct {
			Result jebdUnits `json:"result"`
		}
		if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
			t.Fatalf("mixed dir JSON: %v\n%s", err, stdout)
		}
		if len(doc.Result.Units) != 2 || len(doc.Result.Errors) != 1 {
			t.Fatalf("JSON units %d errors %v, want 2 units and the one bad file named", len(doc.Result.Units), doc.Result.Errors)
		}
	})
}
