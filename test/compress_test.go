package main

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"hash/crc32"
	"strings"
	"testing"
	"time"
)

// compressSkipped reports whether one registered refusal is in the digest.
func compressSkipped(d Digest, reason string) bool {
	for _, s := range d.Skipped {
		if s.Reason == reason {
			return true
		}
	}
	return false
}

func gzipFixture(t *testing.T, name string, payload []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	zw := gzip.NewWriter(&b)
	zw.Name = name
	zw.ModTime = time.Unix(1700000000, 0)
	if _, err := zw.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// gzip is claimed by the firmware kind before readers run, so this reader may
// only add evidence, never take the name away.
func TestCompressGzipVerifiedHeader(t *testing.T) {
	payload := append([]byte("\x7fELF"), bytes.Repeat([]byte{0}, 64)...)
	p := writeTemp(t, "app.gz", gzipFixture(t, "payload.bin", payload))
	d, err := Probe(p)
	if err != nil {
		t.Fatal(err)
	}
	if d.Kind != "firmware" || d.Format != "gzip" {
		t.Fatalf("kind/format = %q/%q, want firmware/gzip", d.Kind, d.Format)
	}
	for _, want := range []string{"compress: gzip cm=8", "name=payload.bin", "mtime=1700000000"} {
		if !notesContain(d, want) {
			t.Fatalf("notes = %v, want %q", d.Notes, want)
		}
	}
	if !notesContain(d, "compress: inner=elf") {
		t.Fatalf("notes = %v, want one-level inner=elf", d.Notes)
	}
}

// Real bzip2 stream (fixed bytes): header level, block magic, then the payload
// decompresses through the stdlib to an ELF magic.
func TestCompressBzip2VerifiedHeader(t *testing.T) {
	stream := []byte{
		0x42, 0x5a, 0x68, 0x39, 0x31, 0x41, 0x59, 0x26, 0x53, 0x59,
		0x1f, 0xb1, 0x88, 0x0a, 0x00, 0x00, 0x04, 0x05, 0x80, 0x03,
		0x04, 0x02, 0x44, 0x80, 0x00, 0xa0, 0x00, 0x21, 0x88, 0xc9,
		0xa1, 0x0c, 0x08, 0xbb, 0x91, 0xce, 0x17, 0xc5, 0xdc, 0x91,
		0x4e, 0x14, 0x24, 0x07, 0xec, 0x62, 0x02, 0x80,
	}
	d, err := Probe(writeTemp(t, "app.bz2", stream))
	if err != nil {
		t.Fatal(err)
	}
	if d.Kind != "compress" || d.Format != "bzip2" {
		t.Fatalf("kind/format = %q/%q, want compress/bzip2", d.Kind, d.Format)
	}
	if !notesContain(d, "compress: bzip2 level=9 block=900k") {
		t.Fatalf("notes = %v, want verified bzip2 header", d.Notes)
	}
	if !notesContain(d, "compress: inner=elf") {
		t.Fatalf("notes = %v, want one-level inner=elf", d.Notes)
	}
}

func xzHeader(check byte) []byte {
	flags := []byte{0x00, check}
	h := []byte{0xfd, '7', 'z', 'X', 'Z', 0x00}
	h = append(h, flags...)
	crc := crc32.ChecksumIEEE(flags)
	if check == 0xff { // crafted: flag byte written after the checksum
		h = append(h, byte(crc), byte(crc>>8), byte(crc>>16), byte(crc>>24))
		h[7] = check
		return h
	}
	return append(h, byte(crc), byte(crc>>8), byte(crc>>16), byte(crc>>24))
}

// xz is firmware-claimed too; the stream flags and their CRC32 are what can be
// verified without an xz decoder.
func TestCompressXZStreamFlags(t *testing.T) {
	good := append(xzHeader(0x01), bytes.Repeat([]byte{0}, 32)...)
	d, err := Probe(writeTemp(t, "app.xz", good))
	if err != nil {
		t.Fatal(err)
	}
	if d.Kind != "firmware" || d.Format != "xz" {
		t.Fatalf("kind/format = %q/%q, want firmware/xz", d.Kind, d.Format)
	}
	if !notesContain(d, "compress: xz check=crc32") {
		t.Fatalf("notes = %v, want verified xz stream flags", d.Notes)
	}

	bad := append(xzHeader(0xff), bytes.Repeat([]byte{0}, 32)...)
	bd, err := Probe(writeTemp(t, "bad.xz", bad))
	if err != nil {
		t.Fatal(err)
	}
	if !compressSkipped(bd, "compress-header-invalid") {
		t.Fatalf("skipped = %v, want compress-header-invalid", bd.Skipped)
	}
}

func TestCompressLZMAHeader(t *testing.T) {
	h := []byte{0x5d, 0x00, 0x00, 0x80, 0x00} // props, dict 8 MiB
	h = append(h, bytes.Repeat([]byte{0xff}, 8)...)
	d, err := Probe(writeTemp(t, "app.lzma", h))
	if err != nil {
		t.Fatal(err)
	}
	if d.Kind != "compress" || d.Format != "lzma" {
		t.Fatalf("kind/format = %q/%q, want compress/lzma", d.Kind, d.Format)
	}
	if !notesContain(d, "lc=3 lp=0 pb=2 dict=8388608 size=unknown") {
		t.Fatalf("notes = %v, want verified lzma properties", d.Notes)
	}
}

func TestCompressLZ4FrameHeader(t *testing.T) {
	h := []byte{0x04, 0x22, 0x4d, 0x18, 0x60, 0x70, 0x00}
	h = append(h, bytes.Repeat([]byte{0}, 16)...)
	d, err := Probe(writeTemp(t, "app.lz4", h))
	if err != nil {
		t.Fatal(err)
	}
	if d.Kind != "compress" || d.Format != "lz4" {
		t.Fatalf("kind/format = %q/%q, want compress/lz4", d.Kind, d.Format)
	}
	if !notesContain(d, "compress: lz4 flg=0x60 bmax=4m independent=true content-size=none") {
		t.Fatalf("notes = %v, want verified lz4 frame header", d.Notes)
	}

	reserved := []byte{0x04, 0x22, 0x4d, 0x18, 0x62, 0x70, 0x00}
	rd, err := Probe(writeTemp(t, "bad.lz4", reserved))
	if err != nil {
		t.Fatal(err)
	}
	if rd.Kind != "unknown" || !compressSkipped(rd, "compress-header-invalid") {
		t.Fatalf("kind/skipped = %q/%v, want unknown/compress-header-invalid", rd.Kind, rd.Skipped)
	}
}

func TestCompressZstdFrameHeader(t *testing.T) {
	h := []byte{0x28, 0xb5, 0x2f, 0xfd, 0x00, 0x48}
	h = append(h, bytes.Repeat([]byte{0}, 16)...)
	d, err := Probe(writeTemp(t, "app.zst", h))
	if err != nil {
		t.Fatal(err)
	}
	if d.Kind != "compress" || d.Format != "zstd" {
		t.Fatalf("kind/format = %q/%q, want compress/zstd", d.Kind, d.Format)
	}
	if !notesContain(d, "window=524288") {
		t.Fatalf("notes = %v, want the derived zstd window", d.Notes)
	}

	reserved := []byte{0x28, 0xb5, 0x2f, 0xfd, 0x08, 0x48}
	rd, err := Probe(writeTemp(t, "bad.zst", reserved))
	if err != nil {
		t.Fatal(err)
	}
	if rd.Kind != "unknown" || !compressSkipped(rd, "compress-header-invalid") {
		t.Fatalf("kind/skipped = %q/%v, want unknown/compress-header-invalid", rd.Kind, rd.Skipped)
	}
}

// The input cap is a refusal, not a silent partial read: a wrapper past the cap
// keeps its header evidence and says why it was not inflated. The cap is a var
// so the test lowers it instead of writing 512 MiB.
func TestCompressTooBigRefused(t *testing.T) {
	old := compressMaxInput
	compressMaxInput = 1 << 20
	defer func() { compressMaxInput = old }()
	big := gzipFixture(t, "big.bin", []byte("hello"))
	big = append(big, bytes.Repeat([]byte{0}, int(compressMaxInput))...)
	d, err := Probe(writeTemp(t, "big.gz", big))
	if err != nil {
		t.Fatal(err)
	}
	if !compressSkipped(d, "compress-too-big") {
		t.Fatalf("skipped = %v, want compress-too-big", d.Skipped)
	}
	if notesContain(d, "compress: inner=") {
		t.Fatalf("notes = %v, inner content must not be inflated past the cap", d.Notes)
	}
}

// TestCompressPayloadDigested: one gzip/bzip2 level is decoded in-process, the
// firmware layout inside it is reported, xz names the exact external command,
// and an output bomb stops at the cap instead of being buffered.
func TestCompressPayloadDigested(t *testing.T) {
	squash := append([]byte("hsqs"), bytes.Repeat([]byte{0}, 60)...)
	// bzip2 of the same 64-byte squashfs head: stdlib has no bzip2 writer.
	bzip := []byte{
		0x42, 0x5a, 0x68, 0x39, 0x31, 0x41, 0x59, 0x26, 0x53, 0x59,
		0x73, 0x51, 0x3b, 0x68, 0x00, 0x00, 0x02, 0xc9, 0x80, 0x40,
		0x00, 0x00, 0x40, 0x00, 0x40, 0x28, 0x00, 0x20, 0x00, 0x30,
		0xcd, 0x00, 0xc1, 0xa1, 0x12, 0xb4, 0x38, 0xbb, 0x92, 0x29,
		0xc2, 0x84, 0x83, 0x9a, 0x89, 0xdb, 0x40,
	}
	bomb := gzipFixture(t, "bomb.bin", make([]byte, int(compressMaxOut)+1))
	cases := []struct {
		name   string
		data   []byte
		kind   string
		part   string
		notes  []string
		absent string
	}{
		{"gzip", gzipFixture(t, "inner.bin", squash), "squashfs", "0x00000000 squashfs",
			[]string{"compress: gzip payload 64 bytes decompressed and digested"}, ""},
		{"bzip2", bzip, "squashfs", "0x00000000 squashfs",
			[]string{"compress: bzip2 payload 64 bytes decompressed and digested"}, ""},
		{"xz", append(xzHeader(0x01), bytes.Repeat([]byte{0}, 32)...), "xz", "",
			[]string{"use `xz -dc <file>`"}, ""},
		{"bomb", bomb, "gzip", "",
			[]string{"compress: gzip payload over 64 MiB cap, not digested"},
			"decompressed and digested"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d, err := Probe(writeTemp(t, tc.name, tc.data))
			if err != nil {
				t.Fatal(err)
			}
			if d.FirmwareKind != tc.kind {
				t.Fatalf("firmware_kind = %q, want %q (notes %v)", d.FirmwareKind, tc.kind, d.Notes)
			}
			if tc.part != "" && !containsStr(d.FirmwareParts, tc.part) {
				t.Fatalf("firmware_detail = %v, want %q", d.FirmwareParts, tc.part)
			}
			for _, want := range tc.notes {
				if !notesContain(d, want) {
					t.Fatalf("notes = %v, want %q", d.Notes, want)
				}
			}
			if tc.absent != "" && notesContain(d, tc.absent) {
				t.Fatalf("notes = %v, must not claim %q", d.Notes, tc.absent)
			}
		})
	}
}

// Truncated header is a refusal, so Probe still exits with a usable digest.
func TestCompressTruncatedHeader(t *testing.T) {
	d, err := Probe(writeTemp(t, "cut.gz", []byte{0x1f, 0x8b, 0x08, 0x00}))
	if err != nil {
		t.Fatal(err)
	}
	if !compressSkipped(d, "compress-header-truncated") {
		t.Fatalf("skipped = %v, want compress-header-truncated", d.Skipped)
	}
}

// Black box: the JSON contract names three codecs that have no stdlib decoder,
// so only the verified header can be claimed.
func TestCompressBlackBoxJSON(t *testing.T) {
	rows := []struct {
		name   string
		data   []byte
		format string
	}{
		{"magic.lzma", []byte{0x5d, 0x00, 0x00, 0x80, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, "lzma"},
		{"magic.lz4", []byte{0x04, 0x22, 0x4d, 0x18, 0x60, 0x70, 0x00}, "lz4"},
		{"magic.zst", []byte{0x28, 0xb5, 0x2f, 0xfd, 0x00, 0x48}, "zstd"},
		{"magic.bz2", []byte("BZh9\x31\x41\x59\x26\x53\x59"), "bzip2"},
	}
	for _, row := range rows {
		t.Run(row.format, func(t *testing.T) {
			out, code := runCLI(t, "--json", writeTemp(t, row.name, row.data))
			if code != 0 {
				t.Fatalf("exit %d: %s", code, out)
			}
			var d Digest
			if err := json.Unmarshal([]byte(out), &d); err != nil {
				t.Fatalf("stdout is not JSON: %v\n%s", err, out)
			}
			if d.Kind != "compress" || d.Format != row.format {
				t.Fatalf("kind/format = %q/%q, want compress/%q", d.Kind, d.Format, row.format)
			}
		})
	}
}

// TestCompressLZ4ContentSize: good, the content size in a real frame. The
// optional fields start right after BD and the header checksum is the last
// header byte, so reading it from h[7:] reported the checksum as the size.
// Fixture: lz4 -q -f --content-size -c of a 36-byte file (flg 0x6c, size 0x24).
func TestCompressLZ4ContentSize(t *testing.T) {
	h := []byte{0x04, 0x22, 0x4d, 0x18, 0x6c, 0x40, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xab}
	h = append(h, bytes.Repeat([]byte{0}, 16)...)
	d, err := Probe(writeTemp(t, "app.lz4", h))
	if err != nil {
		t.Fatal(err)
	}
	if d.Kind != "compress" || d.Format != "lz4" {
		t.Fatalf("kind/format = %q/%q, want compress/lz4", d.Kind, d.Format)
	}
	if !notesContain(d, "compress: lz4 flg=0x6c bmax=64k independent=true content-size=36") {
		t.Fatalf("notes = %v, want the frame's own content size", d.Notes)
	}
}

// TestCompressZstdSingleSegment: good, every small frame the reference encoder
// writes. Single_Segment_flag with FCS_flag 0 still carries a one-byte content
// size, so the frame is valid; refusing it left the file unnamed and skipped.
// Fixture: zstd -q -f of a 36-byte file.
func TestCompressZstdSingleSegment(t *testing.T) {
	h := []byte{0x28, 0xb5, 0x2f, 0xfd, 0x24, 0x24, 0x9d, 0x00, 0x00}
	h = append(h, bytes.Repeat([]byte{0}, 16)...)
	d, err := Probe(writeTemp(t, "small.zst", h))
	if err != nil {
		t.Fatal(err)
	}
	if d.Kind != "compress" || d.Format != "zstd" {
		t.Fatalf("kind/format = %q/%q, want compress/zstd", d.Kind, d.Format)
	}
	if !notesContain(d, "single=true") || !notesContain(d, "fcs=0") {
		t.Fatalf("notes = %v, want the single-segment frame reported", d.Notes)
	}
	for _, s := range d.Skipped {
		if s.Reason == "compress-header-invalid" {
			t.Fatalf("valid single-segment frame refused: %v", d.Skipped)
		}
	}
}

// TestCompressZstdDictID4: good, a frame whose dictionary id is the 4-byte
// form. All four values of the 2-bit flag are field widths, not a reserved
// code: 0b11 is 4 bytes.
func TestCompressZstdDictID4(t *testing.T) {
	h := []byte{0x28, 0xb5, 0x2f, 0xfd, 0x03, 0x48, 0x00, 0x00, 0x00, 0x01}
	h = append(h, bytes.Repeat([]byte{0}, 16)...)
	d, err := Probe(writeTemp(t, "dict.zst", h))
	if err != nil {
		t.Fatal(err)
	}
	if d.Kind != "compress" || d.Format != "zstd" {
		t.Fatalf("kind/format = %q/%q, want compress/zstd", d.Kind, d.Format)
	}
	if !notesContain(d, "dict-id=3") {
		t.Fatalf("notes = %v, want dict-id=3", d.Notes)
	}
}

// TestCompressZstdUnusedBit: bad, the unused bit must be zero.
func TestCompressZstdUnusedBit(t *testing.T) {
	h := []byte{0x28, 0xb5, 0x2f, 0xfd, 0x10, 0x48}
	rd, err := Probe(writeTemp(t, "unused.zst", h))
	if err != nil {
		t.Fatal(err)
	}
	if rd.Kind != "unknown" || !compressSkipped(rd, "compress-header-invalid") {
		t.Fatalf("kind/skipped = %q/%v, want unknown/compress-header-invalid", rd.Kind, rd.Skipped)
	}
}

// TestCompressGzipLongName: bad name length, good stream. A name past the
// report cap is not a cut header, so the payload still gets digested instead of
// the whole file being refused.
func TestCompressGzipLongName(t *testing.T) {
	name := strings.Repeat("n", compressNameMax+20) + ".bin"
	p := writeTemp(t, "long.gz", gzipFixture(t, name, []byte("\x7fELFhello")))
	d, err := Probe(p)
	if err != nil {
		t.Fatal(err)
	}
	if compressSkipped(d, "compress-header-truncated") {
		t.Fatalf("long name refused as a cut header: %v", d.Skipped)
	}
	if !notesContain(d, "name="+strings.Repeat("n", compressNameMax)+"...") {
		t.Fatalf("notes = %v, want the cut name reported", d.Notes)
	}
	if !notesContain(d, "payload 9 bytes decompressed") {
		t.Fatalf("notes = %v, want the payload digested", d.Notes)
	}
}
