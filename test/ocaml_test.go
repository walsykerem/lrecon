package main

import (
	"bytes"
	"encoding/binary"
	"slices"
	"strings"
	"testing"
)

// Synthetic bytes only: a 12-byte magic, or a section table plus the 16-byte
// trailer a .cmxs carries at EOF. No fixture binary is needed.

// ocamlTrailer builds `entry*` + `{u32 count; magic[12]}`.
func ocamlTOCBytes(entries [][2]any, count uint32, magic string) []byte {
	var b bytes.Buffer
	for _, e := range entries {
		var name [4]byte
		copy(name[:], e[0].(string))
		b.Write(name[:])
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], e[1].(uint32))
		b.Write(n[:])
	}
	var c [4]byte
	binary.BigEndian.PutUint32(c[:], count)
	b.Write(c[:])
	b.WriteString(magic)
	return b.Bytes()
}

func ocamlSkipped(d Digest, reason string) bool {
	for _, s := range d.Skipped {
		if s.Reason == reason {
			return true
		}
	}
	return false
}

func ocamlHasCap(d Digest, want string) bool {
	return slices.Contains(d.Capabilities, want)
}

func TestOcamlPrefixKinds(t *testing.T) {
	cases := map[string]string{
		"Caml1999O031": "cmo",
		"Caml1999A031": "cma",
		"Caml1999y031": "cmx",
		"Caml1999z031": "cmxa",
		"Caml1999D031": "cmxs",
	}
	for magic, want := range cases {
		path := writeTemp(t, "unit."+want, []byte(magic))
		d, err := Probe(path)
		if err != nil {
			t.Fatal(err)
		}
		if d.Kind != "ocaml" || d.Format != want {
			t.Errorf("%s: kind/format = %q/%q, want ocaml/%s", magic, d.Kind, d.Format, want)
		}
		if d.Toolchain != "ocaml 031" {
			t.Errorf("%s: toolchain = %q", magic, d.Toolchain)
		}
		if !ocamlHasCap(d, "ocaml:"+want) {
			t.Errorf("%s: missing capability ocaml:%s in %v", magic, want, d.Capabilities)
		}
		if len(d.Skipped) != 0 {
			t.Errorf("%s: unexpected refusals %+v", magic, d.Skipped)
		}
	}
}

func TestOcamlExecutableTrailerTOC(t *testing.T) {
	// Junk prefix, then two sections, the table, and the trailer at EOF-16.
	body := ocamlTOCBytes([][2]any{{"CODE", uint32(4)}, {"DATA", uint32(8)}}, 2, "Caml1999D031")
	raw := append(bytes.Repeat([]byte{0}, 24), body...)
	d, err := Probe(writeTemp(t, "plugin.cmxs", raw))
	if err != nil {
		t.Fatal(err)
	}
	if d.Kind != "ocaml" || d.Format != "cmxs" {
		t.Fatalf("kind/format = %q/%q, want ocaml/cmxs", d.Kind, d.Format)
	}
	if !ocamlHasCap(d, "ocaml:sections=CODE,DATA") {
		t.Errorf("capabilities = %v", d.Capabilities)
	}
	if d.Coverage == nil || d.Coverage.Parsed != 2 || d.Coverage.Skipped != 0 {
		t.Errorf("coverage = %+v", d.Coverage)
	}
	if !bytes.Contains([]byte(strings.Join(d.Notes, "\n")), []byte("2 sections")) {
		t.Errorf("notes = %v", d.Notes)
	}
}

func TestOcamlTOCTruncated(t *testing.T) {
	// The count says 4 sections but only one entry fits before the trailer.
	body := ocamlTOCBytes([][2]any{{"CODE", uint32(4)}}, 4, "Caml1999D031")
	d, err := Probe(writeTemp(t, "cut.cmxs", append(bytes.Repeat([]byte{0}, 8), body...)))
	if err != nil {
		t.Fatal(err)
	}
	if d.Kind != "ocaml" {
		t.Fatalf("kind = %q, want ocaml", d.Kind)
	}
	if !ocamlSkipped(d, "ocaml-toc-truncated") {
		t.Errorf("skipped = %+v", d.Skipped)
	}
}

func TestOcamlTOCNameInvalid(t *testing.T) {
	var b bytes.Buffer
	b.Write([]byte{0x01, 0x02, 0x03, 0x04}) // no printable name
	b.Write([]byte{0, 0, 0, 4})             // BE len
	b.Write(ocamlTOCBytes(nil, 1, "Caml1999D031"))
	d, err := Probe(writeTemp(t, "bad.cmxs", b.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if !ocamlSkipped(d, "ocaml-toc-name-invalid") {
		t.Errorf("skipped = %+v", d.Skipped)
	}
	if d.Coverage == nil || d.Coverage.Unknown != 1 {
		t.Errorf("coverage = %+v", d.Coverage)
	}
}

func TestOcamlMagicAndVersionRefused(t *testing.T) {
	d, err := Probe(writeTemp(t, "unknown.cmo", []byte("Caml1999Q031")))
	if err != nil {
		t.Fatal(err)
	}
	if !ocamlSkipped(d, "ocaml-magic-unverified") {
		t.Errorf("format byte: skipped = %+v", d.Skipped)
	}

	d, err = Probe(writeTemp(t, "version.cmo", []byte("Caml1999O03x")))
	if err != nil {
		t.Fatal(err)
	}
	if !ocamlSkipped(d, "ocaml-version-unverified") {
		t.Errorf("version: skipped = %+v", d.Skipped)
	}
}

func TestOcamlNoMagicUntouched(t *testing.T) {
	d, err := Probe(writeTemp(t, "plain.txt", []byte("hello world\n")))
	if err != nil {
		t.Fatal(err)
	}
	if d.Kind == "ocaml" || len(d.Skipped) != 0 {
		t.Errorf("non-OCaml file was touched: kind=%q skipped=%+v", d.Kind, d.Skipped)
	}
}
