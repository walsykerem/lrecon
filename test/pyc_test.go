package main

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Synthetic buffers only: a .pyc is a header plus one marshal stream, so the
// encoder below is the mirror of the decoder and no fixture binary is needed.

func pycLE32(v uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return b
}

// mShort writes TYPE_SHORT_ASCII, the form 3.7+ uses for short names.
func mShort(s string) []byte { return append([]byte{'z', byte(len(s))}, s...) }

// mBytes writes TYPE_STRING, the form bytes blobs (co_code, tables) use.
func mBytes(s string) []byte {
	b := []byte{'s'}
	b = append(b, pycLE32(uint32(len(s)))...)
	return append(b, s...)
}

// mTuple writes TYPE_SMALL_TUPLE.
func mTuple(items ...[]byte) []byte {
	b := []byte{')', byte(len(items))}
	for _, it := range items {
		b = append(b, it...)
	}
	return b
}

// mCode builds one code object in the field order of ver (306..314).
func mCode(ver int, name, qual, file string, consts ...[]byte) []byte {
	b := []byte{0xe3} // FLAG_REF | TYPE_CODE, what the writer emits for a top-level code
	ints := 5
	if ver >= 308 && ver <= 310 {
		ints = 6
	}
	for i := 0; i < ints; i++ {
		b = append(b, pycLE32(0)...)
	}
	b = append(b, mBytes("codebytes")...)
	b = append(b, mTuple(consts...)...)
	b = append(b, mTuple(mShort("print"))...) // co_names
	if ver <= 310 {
		b = append(b, mTuple()...) // varnames
		b = append(b, mTuple()...) // freevars
		b = append(b, mTuple()...) // cellvars
	} else {
		b = append(b, mTuple(mShort("self"))...) // localsplusnames
		b = append(b, mBytes("\x00")...)         // localspluskinds
	}
	b = append(b, mShort(file)...)
	b = append(b, mShort(name)...)
	if ver >= 311 {
		b = append(b, mShort(qual)...)
	}
	b = append(b, pycLE32(1)...) // co_firstlineno
	b = append(b, mBytes("")...) // co_linetable
	if ver >= 311 {
		b = append(b, mBytes("")...) // co_exceptiontable
	}
	return b
}

// pycBlob writes the magic plus the header size that version uses: 12 bytes for
// 3.6 (magic, mtime, size), 16 bytes from 3.7 (flags, then mtime+size or hash).
func pycBlob(magic int, flags uint32, body []byte) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint16(b, uint16(magic))
	b[2], b[3] = 0x0d, 0x0a
	if magic < 3390 {
		b = append(b, pycLE32(0)...)
		b = append(b, pycLE32(0)...)
	} else {
		b = append(b, pycLE32(flags)...)
		b = append(b, make([]byte, 8)...)
	}
	return append(b, body...)
}

func probePycBytes(t *testing.T, buf []byte) Digest {
	t.Helper()
	path := filepath.Join(t.TempDir(), "target.pyc")
	if err := os.WriteFile(path, buf, 0o644); err != nil {
		t.Fatal(err)
	}
	d, err := Probe(path)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestPycSyntheticCodeObject(t *testing.T) {
	cases := []struct {
		name      string
		ver       int
		magic     int
		flags     uint32
		toolchain string
	}{
		{"3.6 timestamp", 306, 3379, 0, "cpython 3.6"},
		{"3.11 timestamp", 311, 3495, 0, "cpython 3.11"},
		{"3.13 checked hash", 313, 3571, 3, "cpython 3.13"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			outer := mCode(tc.ver, "outer", "mod.outer", "src/mod.py",
				mShort("hello"),
				mCode(tc.ver, "inner", "mod.outer.inner", "src/mod.py"),
			)
			d := probePycBytes(t, pycBlob(tc.magic, tc.flags, outer))

			if d.Kind != "pyc" || d.Format != "pyc" {
				t.Fatalf("kind/format = %q/%q, want pyc/pyc", d.Kind, d.Format)
			}
			if d.Toolchain != tc.toolchain {
				t.Fatalf("toolchain = %q, want %q", d.Toolchain, tc.toolchain)
			}
			if len(d.Skipped) != 0 {
				t.Fatalf("clean blob refused: %+v", d.Skipped)
			}
			if len(d.Imports) == 0 {
				t.Fatal("no qualname recovered")
			}
			// 3.6 has no co_qualname, so only the plain name survives there.
			want := []string{"mod.outer", "mod.outer.inner"}
			if tc.ver < 311 {
				want = []string{"inner", "outer"}
			}
			if strings.Join(d.Imports, ",") != strings.Join(want, ",") {
				t.Fatalf("imports = %v, want %v", d.Imports, want)
			}
			if got := strings.Join(d.Capabilities, ","); !strings.Contains(got, "pyc:code_objects=2") {
				t.Fatalf("capabilities = %q, want pyc:code_objects=2", got)
			}
			if d.Coverage == nil || d.Coverage.Parsed != 2 || d.Coverage.Unknown != 0 {
				t.Fatalf("coverage = %+v, want parsed:2", d.Coverage)
			}
			if !strings.Contains(strings.Join(d.Notes, "\n"), `source "src/mod.py"`) {
				t.Fatalf("source filename missing from notes: %v", d.Notes)
			}
		})
	}
}

func TestPycRefusals(t *testing.T) {
	nested := []byte{}
	for range 1100 {
		nested = append(nested, ')', 1)
	}
	nested = append(nested, mShort("x")...)

	cases := []struct {
		name   string
		blob   []byte
		claim  bool   // the magic reader claims the file
		reason string // skip reason to find, "" = none
	}{
		{"wrong magic", []byte("plain text, no pyc magic at all\n"), false, ""},
		{"unknown magic number", pycBlob(3800, 0, mCode(311, "a", "a", "a.py")), true, "pyc-version-unverified"},
		{"truncated marshal", pycBlob(3495, 0, append([]byte{0xe3}, make([]byte, 8)...)), true, "pyc-marshal-truncated"},
		{"deep nesting", pycBlob(3495, 0, nested), true, "pyc-marshal-too-deep"},
		{"unsupported flags", pycBlob(3495, 0x100, mCode(311, "a", "a", "a.py")), true, "pyc-flags-unsupported"},
		{"not a code object", pycBlob(3495, 0, mShort("x")), true, "pyc-not-code"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := probePycBytes(t, tc.blob)
			claimed := d.Kind == "pyc"
			if claimed != tc.claim {
				t.Fatalf("claimed = %v (kind %q), want %v", claimed, d.Kind, tc.claim)
			}
			if tc.reason == "" {
				for _, s := range d.Skipped {
					if strings.HasPrefix(s.Reason, "pyc-") {
						t.Fatalf("unclaimed file got a pyc skip: %+v", s)
					}
				}
				return
			}
			found := false
			for _, s := range d.Skipped {
				if s.Reason == tc.reason {
					found = true
				}
			}
			if !found {
				t.Fatalf("skips = %+v, want reason %q", d.Skipped, tc.reason)
			}
			if d.Coverage == nil || d.Coverage.Skipped == 0 {
				t.Fatalf("skip not counted in coverage: %+v", d.Coverage)
			}
		})
	}
}
