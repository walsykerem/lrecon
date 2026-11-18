package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode/utf8"
)

// Erlang BEAM: an IFF wrapper ("FOR1", u32 BE size, "BEAM") around a chunk
// table. Only the AtU8 atom table and the CInf compile-info chunk are read;
// the Code chunk and the literal tables stay opaque, so names and one version
// are this reader's whole ceiling.
const (
	beamHeaderLen = 12
	beamChunkLen  = 8
	beamMaxNames  = 256
	beamMaxRead   = 1 << 20
)

func init() {
	reasonRegistry["beam"] = reasonSet("no-iff-wrapper", "beam-name-cap", "beam-too-big", "beam-truncated")
	register(reader{
		format:  "beam",
		reasons: []string{"no-iff-wrapper", "beam-truncated", "beam-name-cap", "beam-too-big"},
		match:   beamMatch,
		inspect: inspectBeam,
	})
}

// beamMatch keys on the payload magic alone, so a file that lost its FOR1
// wrapper is still claimed and refused by name instead of falling to unknown.
func beamMatch(head []byte, size int64) bool {
	return size >= beamHeaderLen && len(head) >= beamHeaderLen && string(head[8:12]) == "BEAM"
}

func inspectBeam(path string, d *Digest) {
	f, err := os.Open(path)
	if err != nil {
		d.Notes = append(d.Notes, "beam: "+err.Error())
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return
	}
	size := st.Size()
	if size < beamHeaderLen {
		d.skip("beam-truncated", fmt.Sprintf("%d-byte file", size))
		return
	}
	var hdr [beamHeaderLen]byte
	if !beamReadAt(f, hdr[:], 0, d) {
		d.skip("beam-truncated", "short header")
		return
	}
	if string(hdr[:4]) != "FOR1" {
		d.skip("no-iff-wrapper", fmt.Sprintf("magic at 0 is %q", hdr[:4]))
		return
	}
	if string(hdr[8:12]) != "BEAM" {
		d.skip("no-iff-wrapper", "BEAM not at 8")
		return
	}
	// The size is a witness, not the walk bound: a wrong field must not hide
	// chunks that are physically present.
	if declared := int64(binary.BigEndian.Uint32(hdr[4:8])); declared != size-8 {
		d.Notes = append(d.Notes, fmt.Sprintf("beam: FOR1 size %d at 4, file carries %d; walking %d bytes", declared, size-8, size))
	}

	var chunks, atoms int
	for off := int64(beamHeaderLen); off < size; {
		if size-off < beamChunkLen {
			d.skip("beam-truncated", fmt.Sprintf("%d-byte chunk header at %d", size-off, off))
			break
		}
		var ch [beamChunkLen]byte
		if !beamReadAt(f, ch[:], off, d) {
			d.skip("beam-truncated", fmt.Sprintf("chunk header at %d", off))
			break
		}
		id := string(ch[:4])
		n := int64(binary.BigEndian.Uint32(ch[4:8]))
		data := off + beamChunkLen
		if n > size-data {
			d.skip("beam-truncated", fmt.Sprintf("chunk %q claims %d bytes at %d, %d left", id, n, off, size-data))
			break
		}
		chunks++
		switch {
		case id != "AtU8" && id != "CInf":
			d.unparsed()
		case id == "AtU8" && atoms > 0:
			// A second table would desync the name list from the code's atom
			// indices; the first one is the table the compiler wrote.
			d.unparsed()
		case id == "AtU8" && n > beamMaxRead:
			d.unparsed()
			d.Notes = append(d.Notes, fmt.Sprintf("beam: AtU8 chunk %d bytes exceeds %d, names not read", n, beamMaxRead))
		case id == "AtU8":
			atoms = beamAtoms(f, data, n, d)
		default: // CInf
			beamCinf(f, data, n, d)
		}
		next := data + n
		if pad := next % 4; pad != 0 {
			next += 4 - pad
		}
		if next > size {
			// The IFF pad of the final chunk may be absent; a real overrun was
			// already refused above.
			if data+n != size {
				d.skip("beam-truncated", fmt.Sprintf("padding of chunk %q at %d", id, off))
			}
			break
		}
		off = next
	}

	d.Capabilities = append(d.Capabilities, fmt.Sprintf("beam:chunks=%d", chunks))
	if atoms > 0 {
		d.Capabilities = append(d.Capabilities, fmt.Sprintf("beam:atoms=%d", atoms))
	}
	deepNote(d, "decode the Code chunk and the StrT/LitT tables to recover the bytecode, the function boundaries and the literal values; the atom table names what the module references, not what it does")
}

// beamAtoms reads the AtU8 table: u32 BE atom count, then each atom as a one
// byte length plus UTF-8 bytes. The module is the first atom; the rest are the
// function and import names the module references, in table order.
func beamAtoms(f *os.File, off, n int64, d *Digest) int {
	b, ok := allocCeil(d, "beam", n, "beam-too-big")
	if !ok {
		d.unparsed()
		return 0
	}
	if !beamReadAt(f, b, off, d) {
		d.unparsed()
		d.skip("beam-truncated", fmt.Sprintf("AtU8 chunk at %d", off))
		return 0
	}
	if len(b) < 4 {
		d.unparsed()
		d.skip("beam-truncated", fmt.Sprintf("AtU8 header %d bytes", len(b)))
		return 0
	}
	count := int(binary.BigEndian.Uint32(b[:4]))
	if count > len(b)-4 {
		d.unparsed()
		d.skip("beam-truncated", fmt.Sprintf("AtU8 count %d over %d bytes", count, len(b)-4))
		return 0
	}
	names := make([]string, 0, min(count, beamMaxNames))
	pos := 4
	for i := 0; i < count && len(names) < beamMaxNames; i++ {
		if pos >= len(b) {
			d.skip("beam-truncated", fmt.Sprintf("atom %d of %d at byte %d", i, count, pos))
			break
		}
		l := int(b[pos])
		pos++
		if pos+l > len(b) {
			d.skip("beam-truncated", fmt.Sprintf("atom %d of %d claims %d bytes at %d", i, count, l, pos))
			break
		}
		if name := string(b[pos : pos+l]); beamPrintable(name) {
			names = append(names, name)
		}
		pos += l
	}
	if count > beamMaxNames {
		d.skip("beam-name-cap", fmt.Sprintf("%d atoms, kept %d", count, len(names)))
	}
	if len(names) == 0 {
		d.unparsed()
		return 0
	}
	d.parsed()
	d.Mod = names[0]
	d.Imports = append(d.Imports, names[1:]...)
	d.claim(names[0], "atu8", off+4)
	return count
}

// beamCinf reads the compile-info chunk: one length byte plus the compiler
// version string. That version is the Erlang compiler's, not the OTP release.
func beamCinf(f *os.File, off, n int64, d *Digest) {
	if n > beamMaxRead {
		d.unparsed()
		d.Notes = append(d.Notes, fmt.Sprintf("beam: CInf chunk %d bytes exceeds %d, version not read", n, beamMaxRead))
		return
	}
	b, ok := allocCeil(d, "beam", n, "beam-too-big")
	if !ok {
		d.unparsed()
		return
	}
	if !beamReadAt(f, b, off, d) {
		d.unparsed()
		d.skip("beam-truncated", fmt.Sprintf("CInf chunk at %d", off))
		return
	}
	if len(b) == 0 {
		d.unparsed()
		d.Notes = append(d.Notes, "beam: CInf chunk is empty")
		return
	}
	l := int(b[0])
	if l == 0 || 1+l > len(b) {
		d.unparsed()
		d.Notes = append(d.Notes, fmt.Sprintf("beam: CInf length %d at %d does not fit %d bytes", l, off, len(b)-1))
		return
	}
	v := strings.TrimSpace(string(b[1 : 1+l]))
	if !beamPrintable(v) {
		d.unparsed()
		d.Notes = append(d.Notes, "beam: CInf version is not printable")
		return
	}
	d.Toolchain = "erlang " + v
	d.claim(d.Toolchain, "cinf", off)
	d.parsed()
}

func beamPrintable(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func beamReadAt(f *os.File, b []byte, off int64, d *Digest) bool {
	n, err := f.ReadAt(b, off)
	d.scanned(int64(n))
	return n == len(b) && (err == nil || err == io.EOF)
}
