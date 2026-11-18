package main

import (
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"strconv"
	"strings"
)

// Compression containers are single streams, not archives: the header names the
// codec, the payload is one byte range, and the interesting question is what the
// wrapper hides. gzip and xz are already claimed by the firmware kind, so this
// is a post reader: it verifies the header wherever the file is named and only
// takes ownership when nothing else did.
//
// Decompression is deliberately narrow: stdlib gzip/bzip2 only, one level.
// xz/lzma/lz4/zstd have no stdlib decoder, so they stay magic + verified header
// + a named external command. The caps are the bomb guard: a wrapper itself may
// be large, but the decoded payload is never buffered past compressMaxOut.
var (
	compressMaxInput int64 = 512 << 20 // bigger containers are refused, never inflated
	compressMaxOut   int64 = 64 << 20  // decoded payload cap; one byte past it is a bomb
)

const (
	compressHead    = 512  // header window, matches Probe's head buffer
	compressSniff   = 4096 // decompressed bytes read to name the inner format
	compressNameMax = 255  // gzip FNAME is a basename, not a path
)

func init() {
	reasonRegistry["compress"] = reasonSet(
		"compress-decompress-failed",
		"compress-header-invalid",
		"compress-header-truncated",
		"compress-too-big",
	)
	register(reader{
		format: "compress",
		reasons: []string{
			"compress-decompress-failed",
			"compress-header-invalid",
			"compress-header-truncated",
			"compress-too-big",
		},
		post:    true,
		match:   compressMatch,
		inspect: inspectCompress,
	})
}

// compressFormat is one codec's leading bytes. The magic is the cheap claim;
// the header parser below decides whether the file really is that codec.
type compressFormat struct {
	name  string
	match func([]byte) bool
}

var compressFormats = []compressFormat{
	{"gzip", func(h []byte) bool { return len(h) >= 3 && h[0] == 0x1f && h[1] == 0x8b && h[2] == 8 }},
	{"bzip2", func(h []byte) bool {
		return len(h) >= 4 && string(h[:3]) == "BZh" && h[3] >= '1' && h[3] <= '9'
	}},
	{"xz", func(h []byte) bool {
		return len(h) >= 6 && bytes.Equal(h[:6], []byte{0xfd, '7', 'z', 'X', 'Z', 0x00})
	}},
	{"lzma", func(h []byte) bool { return len(h) >= 3 && h[0] == 0x5d && h[1] == 0 && h[2] == 0 }},
	{"lz4", func(h []byte) bool {
		return len(h) >= 4 && bytes.Equal(h[:4], []byte{0x04, 0x22, 0x4d, 0x18})
	}},
	{"zstd", func(h []byte) bool {
		return len(h) >= 4 && bytes.Equal(h[:4], []byte{0x28, 0xb5, 0x2f, 0xfd})
	}},
}

func compressFormatOf(h []byte) (compressFormat, bool) {
	for _, f := range compressFormats {
		if f.match(h) {
			return f, true
		}
	}
	return compressFormat{}, false
}

func compressMatch(h []byte, _ int64) bool {
	_, ok := compressFormatOf(h)
	return ok
}

func inspectCompress(path string, d *Digest) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	var raw [compressHead]byte
	n, _ := io.ReadFull(f, raw[:])
	head := raw[:n]
	cf, ok := compressFormatOf(head)
	if !ok {
		return
	}
	d.scanned(int64(n))
	note, valid := compressHeader(cf.name, head, d)
	if !valid {
		return
	}
	if d.Kind == "unknown" || d.Kind == "text" || d.Kind == "compress" {
		d.Kind, d.Format = "compress", cf.name
	}
	d.parsed()
	d.Notes = append(d.Notes, "compress: "+cf.name+" "+note)
	switch cf.name {
	case "gzip", "bzip2":
		compressNested(path, d, cf.name)
	case "xz":
		// No stdlib xz reader: name the exact external command instead of a vague refusal.
		d.Notes = append(d.Notes, "compress: xz payload not decoded (no stdlib reader); use `xz -dc <file>`")
	}
}

// compressHeader verifies the fields the magic leaves unchecked. A bad field is
// a refusal, not a guess: the file may still be bytes from that codec family,
// but it is not a valid stream header.
func compressHeader(name string, h []byte, d *Digest) (string, bool) {
	switch name {
	case "gzip":
		return compressGzipHeader(h, d)
	case "bzip2":
		return compressBzip2Header(h, d)
	case "xz":
		return compressXZHeader(h, d)
	case "lzma":
		return compressLZMAHeader(h, d)
	case "lz4":
		return compressLZ4Header(h, d)
	case "zstd":
		return compressZstdHeader(h, d)
	}
	return "", false
}

// gzip: ID1 ID2 CM FLG MTIME[4] XFL OS, then optional extra/name/comment.
func compressGzipHeader(h []byte, d *Digest) (string, bool) {
	const hdr = 10
	if len(h) < hdr {
		d.skip("compress-header-truncated", fmt.Sprintf("gzip: %d of %d header bytes", len(h), hdr))
		return "", false
	}
	flg := h[3]
	if flg&0xe0 != 0 { // FTEXT/FHCRC/FEXTRA/FNAME/FCOMMENT are the low five bits
		d.skip("compress-header-invalid", fmt.Sprintf("gzip: reserved flg bits %#02x", flg&0xe0))
		return "", false
	}
	mtime := binary.LittleEndian.Uint32(h[4:8])
	parts := []string{
		fmt.Sprintf("cm=%d flg=%#02x xfl=%d os=%d", h[2], flg, h[8], h[9]),
	}
	switch {
	case mtime == 0 || mtime == 0xffffffff:
		parts = append(parts, "mtime=unset")
	case mtime < 315532800: // gzip shipped in 1980; earlier is a stale clock
		parts = append(parts, fmt.Sprintf("mtime=%d-pre1980", mtime))
	default:
		parts = append(parts, fmt.Sprintf("mtime=%d", mtime))
	}
	off := hdr
	if flg&0x04 != 0 { // FEXTRA: u16 length, then that many bytes
		if len(h) < off+2 {
			d.skip("compress-header-truncated", "gzip: extra length cut")
			return "", false
		}
		off += 2 + int(binary.LittleEndian.Uint16(h[off:]))
		if off > len(h) {
			d.skip("compress-header-truncated", "gzip: extra field cut")
			return "", false
		}
	}
	if flg&0x08 != 0 { // FNAME: NUL-terminated original name
		i := bytes.IndexByte(h[off:], 0)
		if i < 0 {
			d.skip("compress-header-truncated", "gzip: original name unterminated")
			return "", false
		}
		name := h[off : off+i]
		if len(name) > compressNameMax {
			// a long name is not a cut header: report the head of it and keep
			// reading, or a valid stream would be refused for its file name
			name = name[:compressNameMax]
			parts = append(parts, "name="+compressSafeName(name)+"...")
		} else {
			parts = append(parts, "name="+compressSafeName(name))
		}
		off += i + 1
	}
	if flg&0x10 != 0 { // FCOMMENT: NUL-terminated, not reported
		i := bytes.IndexByte(h[off:], 0)
		if i < 0 {
			d.skip("compress-header-truncated", "gzip: comment unterminated")
			return "", false
		}
		off += i + 1
	}
	return strings.Join(parts, " "), true
}

// bzip2: "BZh" + level digit, then the 48-bit block magic.
func compressBzip2Header(h []byte, d *Digest) (string, bool) {
	const hdr = 10
	if len(h) < hdr {
		d.skip("compress-header-truncated", fmt.Sprintf("bzip2: %d of %d header bytes", len(h), hdr))
		return "", false
	}
	if !bytes.Equal(h[4:10], []byte{0x31, 0x41, 0x59, 0x26, 0x53, 0x59}) {
		d.skip("compress-header-invalid", "bzip2: block magic missing")
		return "", false
	}
	level := int(h[3] - '0')
	return fmt.Sprintf("level=%d block=%dk", level, level*100), true
}

// xz: 6-byte magic, stream flags (2), CRC32 of those flags (4).
func compressXZHeader(h []byte, d *Digest) (string, bool) {
	const hdr = 12
	if len(h) < hdr {
		d.skip("compress-header-truncated", fmt.Sprintf("xz: %d of %d header bytes", len(h), hdr))
		return "", false
	}
	flags := h[6:8]
	if flags[0] != 0 {
		d.skip("compress-header-invalid", fmt.Sprintf("xz: reserved stream flag %#02x", flags[0]))
		return "", false
	}
	checks := map[byte]string{0x00: "none", 0x01: "crc32", 0x04: "crc64", 0x0a: "sha256"}
	check, ok := checks[flags[1]]
	if !ok {
		d.skip("compress-header-invalid", fmt.Sprintf("xz: check type %#02x", flags[1]))
		return "", false
	}
	if crc32.ChecksumIEEE(flags) != binary.LittleEndian.Uint32(h[8:12]) {
		d.skip("compress-header-invalid", "xz: stream flags crc32 mismatch")
		return "", false
	}
	return fmt.Sprintf("check=%s flags=%#02x", check, flags[1]), true
}

// .lzma alone: props byte, u32 dictionary size, u64 uncompressed size. The
// all-ones size means the encoder did not store it.
func compressLZMAHeader(h []byte, d *Digest) (string, bool) {
	const hdr = 5
	if len(h) < hdr {
		d.skip("compress-header-truncated", fmt.Sprintf("lzma: %d of %d header bytes", len(h), hdr))
		return "", false
	}
	props := int(h[0])
	if props >= 9*5*5 {
		d.skip("compress-header-invalid", fmt.Sprintf("lzma: props %#02x out of range", props))
		return "", false
	}
	lc, rest := props%9, props/9
	lp, pb := rest%5, rest/5
	dict := binary.LittleEndian.Uint32(h[1:5])
	if dict < 4096 || dict > 1<<30 {
		d.skip("compress-header-invalid", fmt.Sprintf("lzma: dictionary %d out of range", dict))
		return "", false
	}
	size := "unknown"
	if len(h) >= 13 {
		if u := binary.LittleEndian.Uint64(h[5:13]); u != 0xffffffffffffffff {
			size = strconv.FormatUint(u, 10)
		}
	}
	return fmt.Sprintf("lc=%d lp=%d pb=%d dict=%d size=%s", lc, lp, pb, dict, size), true
}

// lz4 frame: magic, FLG, BD, optional content size/dictionary id, header
// checksum. The checksum is xxhash32, which is not stdlib, so only the field
// layout and the reserved bits are verified.
func compressLZ4Header(h []byte, d *Digest) (string, bool) {
	const fields = 6       // magic, FLG, BD
	const hdr = fields + 1 // + header checksum, which is the last header byte
	if len(h) < hdr {
		d.skip("compress-header-truncated", fmt.Sprintf("lz4: %d of %d header bytes", len(h), hdr))
		return "", false
	}
	flg, bd := h[4], h[5]
	if flg>>6 != 1 {
		d.skip("compress-header-invalid", fmt.Sprintf("lz4: version %d", flg>>6))
		return "", false
	}
	if flg&0x02 != 0 {
		d.skip("compress-header-invalid", "lz4: reserved flg bit set")
		return "", false
	}
	blockMax := map[byte]string{4: "64k", 5: "256k", 6: "1m", 7: "4m"}
	bm, ok := blockMax[(bd>>4)&7]
	if !ok || bd&0x8f != 0 {
		d.skip("compress-header-invalid", fmt.Sprintf("lz4: reserved bd %#02x", bd))
		return "", false
	}
	want := hdr
	if flg&0x08 != 0 {
		want += 8 // content size
	}
	if flg&0x01 != 0 {
		want += 4 // dictionary id
	}
	if len(h) < want {
		d.skip("compress-header-truncated", fmt.Sprintf("lz4: %d of %d optional header bytes", len(h), want))
		return "", false
	}
	size := "none"
	if flg&0x08 != 0 {
		// the optional fields start right after BD; the checksum comes last
		size = strconv.FormatUint(binary.LittleEndian.Uint64(h[fields:fields+8]), 10)
	}
	return fmt.Sprintf("flg=%#02x bmax=%s independent=%t content-size=%s",
		flg, bm, flg&0x20 != 0, size), true
}

// zstd frame: magic, frame header descriptor, then a window descriptor unless
// the frame is single-segment.
func compressZstdHeader(h []byte, d *Digest) (string, bool) {
	const hdr = 5
	if len(h) < hdr {
		d.skip("compress-header-truncated", fmt.Sprintf("zstd: %d of %d header bytes", len(h), hdr))
		return "", false
	}
	fhd := h[4]
	if fhd&0x08 != 0 {
		d.skip("compress-header-invalid", "zstd: reserved frame header bit set")
		return "", false
	}
	if fhd&0x10 != 0 {
		d.skip("compress-header-invalid", "zstd: unused frame header bit set")
		return "", false
	}
	// the dictionary id field is 0, 1, 2 or 4 bytes wide; all four are valid
	dictFlag := fhd & 0x03
	single := fhd&0x20 != 0
	fcs := fhd >> 6
	// Single_Segment_flag overrides FCS_flag 0: the frame still carries a
	// one-byte content size, which is what every small frame written by the
	// reference encoder looks like.
	window := "single-segment"
	if !single {
		if len(h) < hdr+1 {
			d.skip("compress-header-truncated", "zstd: window descriptor cut")
			return "", false
		}
		wd := h[hdr]
		base := uint64(1) << (10 + wd>>3)
		window = strconv.FormatUint(base+(base/8)*uint64(wd&7), 10)
	}
	return fmt.Sprintf("fhd=%#02x fcs=%d single=%t checksum=%t dict-id=%d window=%s",
		fhd, fcs, single, fhd&0x04 != 0, dictFlag, window), true
}

// compressNested decodes one gzip/bzip2 level under a hard output cap and runs
// the firmware reader over the decoded bytes, so a rootfs inside a wrapper no
// longer needs an external `gzip -dc`. Only gzip/bzip2 have a stdlib decoder.
func compressNested(path string, d *Digest, name string) {
	if d.FileSize > compressMaxInput {
		d.skip("compress-too-big", fmt.Sprintf("%s: %d bytes over %d decompression cap",
			name, d.FileSize, compressMaxInput))
		return
	}
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	// Decode straight off the file: the codec only reads forward, so there is no
	// reason to mirror up to compressMaxInput bytes in memory first.
	src := io.LimitReader(f, compressMaxInput)
	var r io.Reader
	if name == "gzip" {
		zr, err := gzip.NewReader(src)
		if err != nil {
			d.skip("compress-decompress-failed", "gzip: "+err.Error())
			return
		}
		defer zr.Close()
		r = zr
	} else {
		r = bzip2.NewReader(src)
	}
	// +1 byte is what tells the cap from an exact-size payload.
	inner, err := io.ReadAll(io.LimitReader(r, compressMaxOut+1))
	if err != nil {
		d.skip("compress-decompress-failed", name+": "+err.Error())
		return
	}
	if int64(len(inner)) > compressMaxOut {
		d.Notes = append(d.Notes, fmt.Sprintf("compress: %s payload over %d MiB cap, not digested",
			name, compressMaxOut>>20))
		return
	}
	if len(inner) == 0 {
		d.skip("compress-decompress-failed", name+": empty payload")
		return
	}
	head := inner
	if len(head) > compressSniff {
		head = head[:compressSniff]
	}
	if kind := compressInnerKind(head); kind != "" {
		d.Notes = append(d.Notes, "compress: inner="+kind)
	}
	if fk := firmwareKind(inner); fk != "" {
		d.FirmwareKind = fk
		if parts := firmwarePartLines(inner); len(parts) > 0 {
			d.FirmwareParts = parts
			d.FirmwareEnd = len(parts)
		}
	}
	d.Notes = append(d.Notes, fmt.Sprintf("compress: %s payload %d bytes decompressed and digested",
		name, len(inner)))
}

// compressInnerKind is one magic-only look at decompressed leading bytes. It
// never recurses: a gzip inside a gzip is named, not unwrapped again.
func compressInnerKind(h []byte) string {
	if cf, ok := compressFormatOf(h); ok {
		return cf.name
	}
	switch {
	case bytes.HasPrefix(h, []byte("\x7fELF")):
		return "elf"
	case bytes.HasPrefix(h, []byte("MZ")):
		return "pe"
	case bytes.HasPrefix(h, []byte("PK\x03\x04")):
		return "zip"
	case bytes.HasPrefix(h, []byte("!<arch>\n")):
		return "ar"
	case bytes.HasPrefix(h, []byte("SQLite format 3\x00")):
		return "sqlite"
	}
	if len(h) >= 4 {
		if m := binary.LittleEndian.Uint32(h); m == 0xfeedface || m == 0xfeedfacf {
			return "macho"
		}
	}
	return ""
}

// compressSafeName keeps a gzip original name printable; a raw header must not
// inject control bytes into the digest text.
func compressSafeName(b []byte) string {
	var sb strings.Builder
	for _, c := range b {
		if c >= 0x20 && c < 0x7f {
			sb.WriteByte(c)
		} else {
			sb.WriteByte('?')
		}
	}
	return sb.String()
}
