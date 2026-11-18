package main

import (
	"bytes"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
)

// Static evidence budgets: one digest, one bounded read per section.
const (
	maxConstScan = 64 << 20 // bytes read per section; a bigger one is noted as capped
	maxConstHits = 24       // hits kept, strongest evidence first by offset order
	maxJITToks   = 8
)

// A section is scanned in windows so a big section never has to fit in memory.
// The overlap is the longest needle, so a needle that straddles a window seam
// is still found.
const (
	constWindow  = 1 << 20
	constOverlap = 64
)

// Honest answers for a scan that ran and found nothing, and for a name source
// that does not exist. Never an empty list and never a zero.
const (
	constNotDetected = "not_detected"
	constNotScanned  = "not_scanned"
	jitNotDetected   = "not_detected"
	nameNotRecovered = "not_recovered"
)

// cryptoTable is one constant table, matched as its in-file byte encoding
// (little-endian words on every target lrecon reads).
//
// strength is about the needle, not the algorithm: >=16 bytes is strong, a
// 4-byte immediate is weak. A label is a claim about a byte range ("this table
// sits here"), never about runtime use ("the binary computes AES").
type cryptoTable struct {
	label    string
	strength string
	needle   []byte // the table as a little-endian target stores it
	be       []byte // the same table word-swapped, for big-endian targets
}

// cryptoTables are the tables whose first bytes are stable enough to identify a
// table rather than a coincidence. SHA-256 IV == BLAKE2s IV == BLAKE3 IV, so its
// label lists all three rather than claiming one.
var cryptoTables = []cryptoTable{
	{
		label:    "aes_sbox",
		strength: "strong",
		needle: []byte{
			0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
			0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
			0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
			0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
			0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
			0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
			0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
			0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
		},
	},
	{
		label:    "sha256_K",
		strength: "strong",
		needle: []byte{
			0x98, 0x2f, 0x8a, 0x42, 0x91, 0x44, 0x37, 0x71,
			0xcf, 0xfb, 0xc0, 0xb5, 0xa5, 0xdb, 0xb5, 0xe9,
			0x5b, 0xc2, 0x56, 0x39, 0xf1, 0x11, 0xf1, 0x59,
			0xa4, 0x82, 0x3f, 0x92, 0xd5, 0x5e, 0x1c, 0xab,
		},
		be: []byte{
			0x42, 0x8a, 0x2f, 0x98, 0x71, 0x37, 0x44, 0x91,
			0xb5, 0xc0, 0xfb, 0xcf, 0xe9, 0xb5, 0xdb, 0xa5,
			0x39, 0x56, 0xc2, 0x5b, 0x59, 0xf1, 0x11, 0xf1,
			0x92, 0x3f, 0x82, 0xa4, 0xab, 0x1c, 0x5e, 0xd5,
		},
	},
	{
		label:    "chacha_sigma",
		strength: "strong",
		needle: []byte{
			0x65, 0x78, 0x70, 0x61, 0x6e, 0x64, 0x20, 0x33,
			0x32, 0x2d, 0x62, 0x79, 0x74, 0x65, 0x20, 0x6b,
		},
	},
	{
		label:    "md5_iv",
		strength: "strong",
		needle: []byte{
			0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
			0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
		},
		be: []byte{
			0x67, 0x45, 0x23, 0x01, 0xef, 0xcd, 0xab, 0x89,
			0x98, 0xba, 0xdc, 0xfe, 0x10, 0x32, 0x54, 0x76,
		},
	},
	{
		// SHA-256, BLAKE2s and BLAKE3 share this IV; naming one would be a lie.
		label:    "sha256|blake2s|blake3",
		strength: "strong",
		needle: []byte{
			0x67, 0xe6, 0x09, 0x6a, 0x85, 0xae, 0x67, 0xbb,
			0x72, 0xf3, 0x6e, 0x3c, 0x3a, 0xf5, 0x4f, 0xa5,
		},
		be: []byte{
			0x6a, 0x09, 0xe6, 0x67, 0xbb, 0x67, 0xae, 0x85,
			0x3c, 0x6e, 0xf3, 0x72, 0xa5, 0x4f, 0xf5, 0x3a,
		},
	},
	{
		label:    "curve25519_p",
		strength: "strong",
		needle: []byte{
			0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
		},
	},
	{
		// 0xedb88320 little-endian; 4 bytes can also be an x86 immediate, hence weak.
		label:    "crc32_poly",
		strength: "weak",
		needle: []byte{
			0x20, 0x83, 0xb8, 0xed,
		},
		be: []byte{
			0xed, 0xb8, 0x83, 0x20,
		},
	},
	{
		// The first 16 entries of the reflected table every CRC32 ships; the
		// polynomial is the same 4 bytes, but 64 bytes of table is not a coincidence.
		label:    "crc32_table",
		strength: "strong",
		needle:   crcNeedle(0xedb88320, 16),
		be:       beWords(crcNeedle(0xedb88320, 16)),
	},
}

func crcNeedle(poly uint32, n int) []byte {
	b := make([]byte, 4*n)
	for i := range n {
		c := uint32(i)
		for range 8 {
			if c&1 != 0 {
				c = poly ^ (c >> 1)
			} else {
				c >>= 1
			}
		}
		binary.LittleEndian.PutUint32(b[4*i:], c)
	}
	return b
}

// beWords swaps every 4-byte group, turning a little-endian word table into
// the same table as a big-endian target stores it.
func beWords(b []byte) []byte {
	out := make([]byte, len(b))
	for i := 0; i+4 <= len(b); i += 4 {
		out[i], out[i+1], out[i+2], out[i+3] = b[i+3], b[i+2], b[i+1], b[i]
	}
	return out
}

// constHit is one table at one file offset. where is "segment,section" on
// Mach-O and the section name elsewhere.
type constHit struct {
	label, strength, where string
	off                    int64
}

// scanConstants finds every needle in b, whose first byte is file offset base.
func scanConstants(b []byte, where string, base int64) []constHit {
	var out []constHit
	// Go on ELF/x86-64 emits chacha_sigma as four separate mov immediates
	// (~15 bytes apart in .text), never as a contiguous table in .rodata as
	// Mach-O does. Detect the four words in order within 64 bytes.
	if t := cryptoTables[2]; t.label == "chacha_sigma" {
		for i := 0; i+16 <= len(b); {
			j := bytes.Index(b[i:], t.needle[:4])
			if j < 0 {
				break
			}
			at := i + j
			pos, ok := at, true
			for _, w := range [][]byte{t.needle[4:8], t.needle[8:12], t.needle[12:16]} {
				k := bytes.Index(b[pos+4:], w)
				if k < 0 || pos+4+k > at+64 {
					ok = false
					break
				}
				pos += 4 + k
			}
			if ok {
				out = append(out, constHit{t.label, t.strength, where, base + int64(at)})
			}
			i = at + 4
		}
	}
	for _, t := range cryptoTables {
		// A word table has two forms on disk: little-endian and big-endian.
		for _, n := range [2][]byte{t.needle, t.be} {
			if len(n) == 0 {
				continue
			}
			for i := 0; ; {
				j := bytes.Index(b[i:], n)
				if j < 0 {
					break
				}
				at := i + j
				out = append(out, constHit{t.label, t.strength, where, base + int64(at)})
				i = at + len(n)
			}
		}
	}
	return out
}

// constLines sorts by file offset, drops exact duplicates and formats
// "label|strength|segment,section|0xoffset". A label may itself hold '|'
// (the shared IV), so a reader splits from the right.
func constLines(hits []constHit) []string {
	sort.Slice(hits, func(i, j int) bool {
		if hits[i].off != hits[j].off {
			return hits[i].off < hits[j].off
		}
		if hits[i].label != hits[j].label {
			return hits[i].label < hits[j].label
		}
		return hits[i].where < hits[j].where
	})
	var out []string
	for _, h := range hits {
		line := fmt.Sprintf("%s|%s|%s|0x%x", h.label, h.strength, h.where, h.off)
		if n := len(out); n > 0 && out[n-1] == line {
			continue
		}
		out = append(out, line)
	}
	return out
}

// setConstants fills the field: hits capped, an honest string when the scan
// found nothing, and a note when a section was only partly read.
func setConstants(d *Digest, hits []constHit, scanned, partial int) {
	if partial > 0 {
		d.Notes = append(d.Notes, fmt.Sprintf("constants: %d section(s) capped at %d bytes", partial, maxConstScan))
	}
	if len(hits) == 0 {
		if scanned == 0 {
			d.Constants = consts{constNotScanned}
		} else {
			d.Constants = consts{constNotDetected}
		}
		return
	}
	d.Constants = consts(capped(d, "constants", constLines(hits), maxConstHits))
}

// scanSection searches r for table needles. r holds the bytes of one section
// that starts at file offset base, so every hit offset is absolute. It reads
// the section in windows, up to maxConstScan bytes, and reports whether the
// section was cut at that budget.
func scanSection(r io.Reader, base, size int64, where string) ([]constHit, int64, bool) {
	var hits []constHit
	seen := map[string]bool{}
	buf := make([]byte, constWindow+constOverlap)
	carry, pos, read := 0, int64(0), int64(0)
	limit := min(size, maxConstScan)
	for read < limit {
		want := min(limit-read, int64(constWindow))
		n, err := io.ReadFull(r, buf[carry:carry+int(want)])
		if n > 0 {
			end := carry + n
			for _, h := range scanConstants(buf[:end], where, base+pos) {
				key := h.label + "@" + strconv.FormatInt(h.off, 10)
				if seen[key] {
					continue
				}
				seen[key] = true
				hits = append(hits, h)
			}
			read += int64(n)
			if end > constOverlap {
				copy(buf, buf[end-constOverlap:end]) // keep the seam bytes
				carry = constOverlap
				pos += int64(end - constOverlap)
			} else {
				carry = end
			}
		}
		if err != nil {
			break
		}
	}
	return hits, read, size > maxConstScan
}

// --- Mach-O ---

// machoConstants skips zero-fill sections (their bytes are not in the file) and
// returns the number of sections that were only partly scanned.
func machoConstants(path string, f *macho.File, base int64) ([]constHit, int, int) {
	var hits []constHit
	scanned, partial := 0, 0
	fh, err := os.Open(path)
	if err != nil {
		return hits, scanned, partial
	}
	defer fh.Close()
	for _, s := range f.Sections {
		if s.Size == 0 {
			continue
		}
		switch s.Flags & 0xff { // S_ZEROFILL, S_GB_ZEROFILL, S_THREAD_LOCAL_ZEROFILL
		case 0x1, 0xc, 0x12:
			continue
		}
		scanned++
		off := base + int64(s.Offset)
		h, _, p := scanSection(io.NewSectionReader(fh, off, int64(s.Size)), off, int64(s.Size), s.Seg+","+s.Name)
		hits = append(hits, h...)
		if p {
			partial++
		}
	}
	return hits, scanned, partial
}

func machoJIT(f *macho.File) []string {
	var out []string
	if l, err := f.ImportedLibraries(); err == nil {
		for _, s := range l {
			if t, ok := jitToken(base(s)); ok {
				out = append(out, t)
			}
		}
	}
	if s, err := f.ImportedSymbols(); err == nil {
		for _, name := range s {
			if t, ok := jitToken(name); ok {
				out = append(out, t)
			}
		}
	}
	if f.Symtab != nil {
		for _, s := range f.Symtab.Syms {
			if t, ok := jitToken(s.Name); ok {
				out = append(out, t)
			}
		}
	}
	return out
}

// machoLocalNames counts defined, non-exported names: a symbol table without
// them cannot be resolved by name, which is what names reports.
func machoLocalNames(f *macho.File) int {
	if f.Symtab == nil {
		return 0
	}
	n := 0
	for _, s := range f.Symtab.Syms {
		if s.Name == "" || s.Type&0x0e == 0 { // undefined
			continue
		}
		if s.Type&0x01 != 0 { // N_EXT
			continue
		}
		n++
	}
	return n
}

// wholeFileConstants searches the whole file for table needles. Formats
// without a native section map (wasm, zip/apk/ipa, plist, sqlite, pyc,
// asar, firmware...) carry no per-section reader to call scanSection on,
// so the file itself is the unit of evidence; a table byte inside any
// container member still lands at an absolute offset. Declared by kind so
// an unrecognised blob (unknown/text/g.bin) keeps its honest not_scanned:
// scanning arbitrary bytes would call a random string a table search.
func wholeFileConstants(path string, d *Digest) {
	switch d.Kind {
	case "unknown", "text", "":
		return
	}
	// Header-only readers (v8-cache, php-opcache) never scan the payload:
	// whole-file constants would inflate BytesScanned past the header the
	// tests pin, and payload bytes are unparsed bytecode, not a table search.
	// They keep the honest not_detected verdict from the header scan the
	// reader already did; gateAbsence only downgrades when incomplete, so
	// returning here leaves their BytesScanned at the header width.
	switch d.Kind {
	case "v8-cache", "php-opcache":
		return
	}
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	hits, scanned, partial := scanSection(f, 0, d.FileSize, "file")
	npartial := 0
	if partial {
		npartial = 1
	}
	setConstants(d, hits, int(scanned), npartial)
	// The whole file was read by this scan; without a witness BytesScanned
	// stays 0 for zip-family formats whose reader never touches d.scanned,
	// and gateAbsence would downgrade the honest not_detected back to
	// not_scanned. ponytail: counts whole file even when capped by
	// maxConstScan; partial note already flags the cap honestly.
	d.scanned(scanned)
}

// --- ELF ---

func elfConstants(f *elf.File) ([]constHit, int, int) {
	var hits []constHit
	scanned, partial := 0, 0
	for _, s := range f.Sections {
		// Every section with bytes in the file is searched, writable ones
		// included; NOBITS has no bytes at all.
		if s.Size == 0 || s.Type == elf.SHT_NOBITS {
			continue
		}
		scanned++
		h, _, p := scanSection(s.Open(), int64(s.Offset), int64(s.Size), s.Name)
		hits = append(hits, h...)
		if p {
			partial++
		}
	}
	return hits, scanned, partial
}

func elfJIT(f *elf.File) []string {
	var out []string
	if l, err := f.ImportedLibraries(); err == nil {
		for _, s := range l {
			if t, ok := jitToken(base(s)); ok {
				out = append(out, t)
			}
		}
	}
	if s, err := f.ImportedSymbols(); err == nil {
		for _, name := range s {
			if t, ok := jitToken(name.Name); ok {
				out = append(out, t)
			}
		}
	}
	if s, err := f.Symbols(); err == nil {
		for _, name := range s {
			if t, ok := jitToken(name.Name); ok {
				out = append(out, t)
			}
		}
	}
	return out
}

// elfLocalNames counts STB_LOCAL .symtab entries, excluding the file and
// section markers: those name the toolchain's inputs, not recovered code.
func elfLocalNames(f *elf.File) int {
	syms, err := f.Symbols()
	if err != nil {
		return 0
	}
	n := 0
	for _, s := range syms {
		if s.Name == "" || s.Section == elf.SHN_UNDEF || elf.ST_BIND(s.Info) != elf.STB_LOCAL {
			continue
		}
		switch elf.ST_TYPE(s.Info) {
		case elf.STT_FILE, elf.STT_SECTION:
			continue
		}
		n++
	}
	return n
}

// --- PE ---

func peConstants(path string, f *pe.File) ([]constHit, int, int) {
	var hits []constHit
	scanned, partial := 0, 0
	fh, err := os.Open(path)
	if err != nil {
		return hits, scanned, partial
	}
	defer fh.Close()
	for _, s := range f.Sections {
		size := int64(s.Size) // raw bytes; VirtualSize-only sections hold none
		if size <= 0 || s.Offset == 0 {
			continue
		}
		scanned++
		h, _, p := scanSection(io.NewSectionReader(fh, int64(s.Offset), size), int64(s.Offset), size, s.Name)
		hits = append(hits, h...)
		if p {
			partial++
		}
	}
	return hits, scanned, partial
}

func peJIT(f *pe.File) []string {
	var out []string
	if l, err := f.ImportedLibraries(); err == nil {
		for _, s := range l {
			if t, ok := jitToken(base(s)); ok {
				out = append(out, t)
			}
		}
	}
	if s, err := f.ImportedSymbols(); err == nil {
		for _, name := range s {
			if t, ok := jitToken(name); ok {
				out = append(out, t)
			}
		}
	}
	for _, s := range f.Symbols {
		if t, ok := jitToken(s.Name); ok {
			out = append(out, t)
		}
	}
	return out
}

// peLocalNames counts COFF statics; a section number of 0 means undefined, and
// storage class 3 is IMAGE_SYM_CLASS_STATIC, which debug/pe does not export.
func peLocalNames(f *pe.File) int {
	n := 0
	for _, s := range f.Symbols {
		if s.Name != "" && s.SectionNumber > 0 && s.StorageClass == 3 {
			n++
		}
	}
	return n
}

// --- shared fields ---

// jitValue turns evidence tokens into the field value. The prefix is "imports:"
// even for a dylib match: a linked library is an import too, and the wording
// stays at "this file imports", never "this file runs JIT code".
func jitValue(d *Digest, tokens []string) string {
	tokens = capped(d, "jit", uniqued(tokens), maxJITToks)
	if len(tokens) == 0 {
		return jitNotDetected
	}
	sort.Strings(tokens)
	return "imports:" + strings.Join(tokens, ",")
}

// jitToken maps one import/dylib/symbol name to a JIT evidence token. The
// token is evidence of intent, not of a live JIT mapping.
func jitToken(name string) (string, bool) {
	n := strings.ToLower(strings.TrimLeft(name, "_"))
	switch {
	case strings.Contains(n, "pthread_jit_write_protect"):
		return "pthread_jit_write_protect_np", true
	case strings.Contains(n, "pthread_jit"):
		return "pthread_jit", true
	case n == "mprotect" || strings.HasPrefix(n, "mprotect@"):
		return "mprotect", true
	case strings.Contains(n, "javascriptcore"):
		return "JavaScriptCore", true
	case strings.HasPrefix(n, "zn2v8") || strings.HasPrefix(n, "v8_") || strings.HasPrefix(n, "libv8"):
		return "v8", true
	}
	return "", false
}

func namesValue(local int) string {
	if local <= 0 {
		return nameNotRecovered
	}
	return "local:" + strconv.Itoa(local)
}
