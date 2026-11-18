package main

import (
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
)

// Synthetic caches only: the header is a fixed little-endian layout, so the test
// writes the bytes a serializer would and checks the reader's claims against them.

// v8cacheBuf builds one cache in the given generation's layout: the two constant
// magic bytes live at 2-3 and the payload length is chosen so header+payload is
// the file size, which is the only field that pins a generation down.
func v8cacheBuf(l v8cacheLayout, payload uint32) []byte {
	b := make([]byte, l.header+int(payload))
	b[0], b[1] = 0x34, 0x12 // build fingerprint; a prefix test on these is wrong
	b[2], b[3] = v8cacheMagic0, v8cacheMagic1
	binary.LittleEndian.PutUint32(b[4:], 0x11111111) // version hash
	for i := 0; i < l.sourceLen; i++ {
		b[8+i] = byte(0xa0 + i) // distinct source hash bytes
	}
	binary.LittleEndian.PutUint32(b[8+l.sourceLen:], 0x33333333) // flag hash
	if l.header > v8cacheMinHeader {
		// Keep the read-only checksum non-zero: it sits exactly where a 24-byte
		// header reads its payload length, and zero there would fake a match.
		binary.LittleEndian.PutUint32(b[l.payloadAt-4:], 0x44444444)
	}
	binary.LittleEndian.PutUint32(b[l.payloadAt:], payload)
	return b
}

// wantHash is the storage order each width uses, spelled out so a reader that
// mixed the two conventions fails here.
func wantHash(width int, b []byte) string {
	if width == 4 {
		return fmt.Sprintf("0x%08x", binary.LittleEndian.Uint32(b))
	}
	return fmt.Sprintf("0x%x", b)
}

// TestV8CacheHeaderSizes: all three shipped generations parse, and each one
// reports its own header width, payload and the exact hash hex it was given.
func TestV8CacheHeaderSizes(t *testing.T) {
	cases := []struct {
		layout  v8cacheLayout
		payload uint32
	}{
		{v8cacheLayouts[0], 16}, // 24-byte header, Node 16/18/20
		{v8cacheLayouts[1], 8},  // 32-byte header, Node 22/24/26
		{v8cacheLayouts[2], 8},  // 64-byte header, V8 main
	}
	for _, c := range cases {
		t.Run(fmt.Sprint(c.layout.header), func(t *testing.T) {
			d, err := Probe(writeTemp(t, "app.jsc", v8cacheBuf(c.layout, c.payload)))
			if err != nil {
				t.Fatalf("Probe error: %v", err)
			}
			if d.Kind != "v8-cache" {
				t.Fatalf("kind = %q, want v8-cache", d.Kind)
			}
			source := make([]byte, c.layout.sourceLen)
			for i := range source {
				source[i] = byte(0xa0 + i)
			}
			want := []string{
				fmt.Sprintf("v8cache:header=%d", c.layout.header),
				fmt.Sprintf("v8cache:payload=%d", c.payload),
				"v8cache:version_hash=0x11111111",
				"v8cache:source_hash=" + wantHash(c.layout.sourceLen, source),
				"v8cache:flag_hash=0x33333333",
			}
			joined := strings.Join(d.Capabilities, "\n")
			for _, w := range want {
				if !strings.Contains(joined, w) {
					t.Fatalf("capabilities missing %q: %v", w, d.Capabilities)
				}
			}
			if d.Coverage == nil || d.Coverage.Parsed != 1 {
				t.Fatalf("coverage = %+v, want one parsed record", d.Coverage)
			}
			if d.BytesScanned != int64(c.layout.header) {
				t.Fatalf("bytes scanned = %d, want the %d-byte header", d.BytesScanned, c.layout.header)
			}
			if !strings.Contains(strings.Join(d.Notes, " "), "not recoverable") {
				t.Fatalf("notes = %v, want the no-source claim", d.Notes)
			}
		})
	}
}

// TestV8CacheHashesDistinct reads one file whose three hashes differ: a reader
// that mixed up offsets would still pass a shape test, so the exact hex is pinned.
func TestV8CacheHashesDistinct(t *testing.T) {
	b := v8cacheBuf(v8cacheLayouts[1], 8)
	binary.LittleEndian.PutUint32(b[4:], 0x0badcafe)
	for i := range 4 {
		b[8+i] = byte(0xde - i)
	}
	binary.LittleEndian.PutUint32(b[12:], 0x00c0ffee)
	d, err := Probe(writeTemp(t, "distinct.jsc", b))
	if err != nil {
		t.Fatalf("Probe error: %v", err)
	}
	for _, want := range []string{
		"v8cache:version_hash=0x0badcafe",
		"v8cache:source_hash=0xdbdcddde", // little-endian u32, like the other hashes
		"v8cache:flag_hash=0x00c0ffee",
	} {
		if !strings.Contains(strings.Join(d.Capabilities, "\n"), want) {
			t.Fatalf("capabilities missing %q: %v", want, d.Capabilities)
		}
	}
	if d.Skipped != nil {
		t.Fatalf("skipped = %+v, want none", d.Skipped)
	}
}

// TestV8CacheMultiMatchRefused hand-writes a file that two generations both
// describe: a 24-byte header with payload 8 and a 32-byte header with payload 0.
// Picking either would invent the source-hash width, so the reader refuses.
func TestV8CacheMultiMatchRefused(t *testing.T) {
	b := make([]byte, 32)
	b[2], b[3] = v8cacheMagic0, v8cacheMagic1
	binary.LittleEndian.PutUint32(b[16:], 8) // 24-byte header reads this
	binary.LittleEndian.PutUint32(b[20:], 0) // 32-byte header reads this
	d, err := Probe(writeTemp(t, "ambiguous.jsc", b))
	if err != nil {
		t.Fatalf("Probe error: %v", err)
	}
	if len(d.Skipped) != 1 || d.Skipped[0].Reason != "v8cache-header-unverified" {
		t.Fatalf("skipped = %+v, want v8cache-header-unverified", d.Skipped)
	}
	if len(d.Capabilities) != 0 {
		t.Fatalf("capabilities = %v, want none for an unpinned header", d.Capabilities)
	}
}

// TestV8CacheSizeMismatch: a 40-byte file whose payload lengths account for
// nothing. Every generation is checked, so the detail names each reading.
func TestV8CacheSizeMismatch(t *testing.T) {
	b := make([]byte, 40)
	b[2], b[3] = v8cacheMagic0, v8cacheMagic1
	d, err := Probe(writeTemp(t, "short.jsc", b))
	if err != nil {
		t.Fatalf("Probe error: %v", err)
	}
	if len(d.Skipped) != 1 || d.Skipped[0].Reason != "v8cache-size-mismatch" {
		t.Fatalf("skipped = %+v, want v8cache-size-mismatch", d.Skipped)
	}
	if !strings.Contains(d.Skipped[0].Detail, "24 header: 0") {
		t.Fatalf("detail = %q, want the per-layout payload lengths", d.Skipped[0].Detail)
	}
}

// TestV8CacheTruncated: the magic fits but the smallest header does not.
func TestV8CacheTruncated(t *testing.T) {
	b := make([]byte, 16)
	b[2], b[3] = v8cacheMagic0, v8cacheMagic1
	d, err := Probe(writeTemp(t, "cut.jsc", b))
	if err != nil {
		t.Fatalf("Probe error: %v", err)
	}
	if len(d.Skipped) != 1 || d.Skipped[0].Reason != "v8cache-truncated" {
		t.Fatalf("skipped = %+v, want v8cache-truncated", d.Skipped)
	}
}

// TestV8CacheBrotliNotClaimed: a brotli-compressed .jsc (brotli framing, no V8
// magic) must never be reported as a code cache. Go has no brotli decoder, so the
// file stays unattributed here instead of being decoded or guessed at.
func TestV8CacheBrotliNotClaimed(t *testing.T) {
	brotli := []byte{0x1b, 0x0f, 0x00, 0x8b, 0x1a, 0x20, 0x30, 0x00, 0x00, 0x00}
	d, err := Probe(writeTemp(t, "compressed.jsc", brotli))
	if err != nil {
		t.Fatalf("Probe error: %v", err)
	}
	if d.Kind == "v8-cache" {
		t.Fatalf("kind = %q: brotli framing was read as a code cache", d.Kind)
	}
	for _, c := range d.Capabilities {
		if strings.HasPrefix(c, "v8cache:") {
			t.Fatalf("capability %q invented for a compressed file", c)
		}
	}
}

// TestV8CacheFingerprintIsNotMagic guards the offset fix: C0 DE at 0-1 is the
// build fingerprint, not the constant half, so that prefix must not claim a file.
func TestV8CacheFingerprintIsNotMagic(t *testing.T) {
	b := make([]byte, 64)
	b[0], b[1] = v8cacheMagic1, v8cacheMagic0
	d, err := Probe(writeTemp(t, "fingerprint.bin", b))
	if err != nil {
		t.Fatalf("Probe error: %v", err)
	}
	if d.Kind == "v8-cache" {
		t.Fatalf("kind = %q: the fingerprint's leading C0 DE claimed the file", d.Kind)
	}
}
