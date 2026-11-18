package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"strings"
)

// OCaml bytecode containers share one 12-byte magic: "Caml1999", a format
// character and a three-digit magic version. A .cmxs is a native shared object
// that carries the same magic at EOF-12 instead of at offset 0, behind a u32
// section count; its section table sits just before that trailer. Only the
// container is read here: no value inside a section is decoded.
const (
	ocamlMagic      = "Caml1999"
	ocamlMagicLen   = 12
	ocamlTrailerLen = 16 // u32 num_sections + magic[12], magic at EOF-12
	ocamlEntryLen   = 8  // char name[4] + u32 BE len
	ocamlMaxSect    = 4096
	ocamlMaxNames   = 32
)

var ocamlKinds = map[byte]string{
	'O': "cmo",
	'A': "cma",
	'D': "cmxs",
	'y': "cmx",
	'z': "cmxa",
}

func init() {
	reasonRegistry["ocaml"] = reasonSet(
		"ocaml-magic-unverified",
		"ocaml-version-unverified",
		"ocaml-toc-truncated",
		"ocaml-toc-name-invalid",
		"ocaml-too-big",
	)
	register(reader{
		format: "ocaml",
		reasons: []string{
			"ocaml-magic-unverified",
			"ocaml-version-unverified",
			"ocaml-toc-truncated",
			"ocaml-toc-name-invalid",
			"ocaml-too-big",
		},
		// post: a .cmxs starts with ELF/Mach-O/PE, so the trailer is the only
		// witness and the native reader must keep the kind it already named.
		post:    true,
		match:   ocamlMatch,
		inspect: inspectOcaml,
	})
}

// ocamlMatch is a size gate only: the trailing magic cannot be seen from the
// head bytes, so the reader opens the file and tests both ends itself.
func ocamlMatch(_ []byte, size int64) bool { return size >= ocamlMagicLen }

func inspectOcaml(path string, d *Digest) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || st.Size() < ocamlMagicLen {
		return
	}
	size := st.Size()

	magic := make([]byte, ocamlMagicLen)
	exec, off := false, int64(0)
	switch {
	case ocamlReadAt(f, magic, 0) && bytes.HasPrefix(magic, []byte(ocamlMagic)):
		// .cmo/.cma/.cmx/.cmxa and a plain .cmxs prefix.
	case size >= ocamlTrailerLen && ocamlReadAt(f, magic, size-ocamlMagicLen) &&
		bytes.HasPrefix(magic, []byte(ocamlMagic)):
		exec, off = true, size-ocamlMagicLen
	default:
		return
	}
	d.scanned(ocamlMagicLen)
	// claim() leaves a post reader's kind alone, so name the container here and
	// never override a native kind the ELF/Mach-O/PE reader already set.
	if d.Kind == "unknown" || d.Kind == "text" {
		d.Kind = "ocaml"
	}

	kind, ok := ocamlKinds[magic[8]]
	if !ok {
		d.skip("ocaml-magic-unverified", fmt.Sprintf("format byte %#02x at %d", magic[8], off+8))
		return
	}
	if !ocamlDigits(magic[9:]) {
		d.skip("ocaml-version-unverified", fmt.Sprintf("version %q at %d", magic[9:], off+9))
		return
	}
	ver := string(magic[9:])

	if d.Format == "" || d.Format == "ocaml" {
		d.Format = kind
	}
	d.Toolchain = "ocaml " + ver
	d.Capabilities = append(d.Capabilities, "ocaml:"+kind)

	if !exec {
		d.parsed()
		deepNote(d, "walk the marshalled compilation unit to recover the module and the imported interfaces; this reader stops at the magic because the payload is not a self-describing table")
		return
	}

	num := ocamlSectionCount(f, size, d)
	if num < 0 {
		d.unparsed()
		d.skip("ocaml-toc-truncated", fmt.Sprintf("section count does not fit %d bytes", size))
		return
	}
	start := size - ocamlTrailerLen - num*ocamlEntryLen
	toc, ok := allocCeil(d, "ocaml", int64(num)*ocamlEntryLen, "ocaml-too-big")
	if !ok {
		d.unparsed()
		return
	}
	if !ocamlReadAt(f, toc, start) {
		d.unparsed()
		d.skip("ocaml-toc-truncated", fmt.Sprintf("%d sections at %d", num, start))
		return
	}
	d.scanned(int64(len(toc)))

	names := make([]string, 0, ocamlMaxNames)
	var total int64
	for i := range num {
		e := toc[i*ocamlEntryLen:]
		name, good := ocamlName(e[:4])
		total += int64(binary.BigEndian.Uint32(e[4:8]))
		if !good {
			d.unparsed()
			d.skip("ocaml-toc-name-invalid", fmt.Sprintf("entry %d name %q", i, e[:4]))
			continue
		}
		d.parsed()
		if len(names) < ocamlMaxNames {
			names = append(names, name)
		}
	}
	// Two independent warnings: the name cap and the section-length sum, so a
	// file with more than ocamlMaxNames sections still reports a TOC that
	// claims more bytes than exist.
	if len(names) < int(num) {
		d.Notes = append(d.Notes, fmt.Sprintf("ocaml: %d of %d section names kept", len(names), num))
	}
	if total > start {
		d.Notes = append(d.Notes, fmt.Sprintf("ocaml: sections claim %d bytes but the section table starts at %d", total, start))
	}
	if len(names) > 0 {
		d.Capabilities = append(d.Capabilities, "ocaml:sections="+strings.Join(names, ","))
	}
	d.Notes = append(d.Notes, fmt.Sprintf("ocaml: trailer at %d declares %d sections", off, num))
	deepNote(d, "map the sections to their code and data offsets, then read the marshalled units for the module names; this reader stops at the section table because no value is decoded")
}

// ocamlSectionCount reads the u32 before the magic. The runtime writes it in
// host order while section lengths are big-endian, so the plausible one wins.
func ocamlSectionCount(f *os.File, size int64, d *Digest) int64 {
	var b [4]byte
	if !ocamlReadAt(f, b[:], size-ocamlTrailerLen) {
		return -1
	}
	d.scanned(4)
	if n := int64(binary.BigEndian.Uint32(b[:])); ocamlTOCFits(n, size) {
		return n
	}
	if n := int64(binary.LittleEndian.Uint32(b[:])); ocamlTOCFits(n, size) {
		return n
	}
	return -1
}

func ocamlTOCFits(n, size int64) bool {
	return n >= 0 && n <= ocamlMaxSect && n*ocamlEntryLen <= size-ocamlTrailerLen
}

// ocamlName accepts the 4-byte section names the compiler emits: printable
// ASCII, NUL-padded.
func ocamlName(b []byte) (string, bool) {
	name, _, _ := bytes.Cut(b, []byte{0})
	if len(name) == 0 {
		return "", false
	}
	for _, c := range name {
		if c < 0x20 || c > 0x7e {
			return "", false
		}
	}
	return string(name), true
}

func ocamlDigits(b []byte) bool {
	for _, c := range b {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func ocamlReadAt(f *os.File, b []byte, off int64) bool {
	n, err := f.ReadAt(b, off)
	return n == len(b) && (err == nil || err == io.EOF)
}
