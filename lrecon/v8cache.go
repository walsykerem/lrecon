package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"strings"
)

// V8 code cache (R3 in notes-r.md): the magic's low half is fixed and the high
// half is a build fingerprint, so in a file it reads bytes 2-3 = DE C0. The
// payload is cached bytecode for one script: it holds no source text, so this
// reader reports header facts and refuses to promise more.
//
//	0  magic        u32le, only bytes 2-3 are constant
//	4  version_hash one-way engine ABI hash, never a Node version
//	8  source_hash  4 B on every release tag through V8 14.x, 32 B on V8 main
//	   flag_hash, [read-only snapshot checksum], payload_length,
//	   [trusted payload length], checksum
const (
	v8cacheMagic0    = 0xDE // offset 2
	v8cacheMagic1    = 0xC0 // offset 3
	v8cacheMaxHeader = 64
	v8cacheMinHeader = 24
)

// v8cacheLayout is one serialized-data header generation. The header size is not
// a constant: the payload length is only meaningful against the header it was
// written with, so a layout is accepted only when header+payload == file size.
type v8cacheLayout struct {
	header     int
	sourceLen  int
	payloadAt  int
	checksumAt int
	trustedAt  int // -1 when this generation has no trusted payload length
}

var v8cacheLayouts = []v8cacheLayout{
	{24, 4, 16, 20, -1},  // V8 up to 11.7: no read-only snapshot checksum (Node 10-20)
	{32, 4, 20, 24, -1},  // V8 11.8-14.x: snapshot checksum, padded to 8 (Node 21-26)
	{64, 32, 48, 56, 52}, // V8 main: 32-byte SHA-256 source hash plus trusted payload
}

func init() {
	register(reader{
		format:  "v8-cache",
		reasons: []string{"v8cache-header-unverified", "v8cache-truncated", "v8cache-size-mismatch", "v8cache-too-big"},
		match:   v8cacheMatch,
		inspect: inspectV8Cache,
	})
}

// v8cacheMatch takes the two constant magic bytes. The leading two are a build
// fingerprint, so a prefix test on them would reject real caches and claim
// unrelated binaries.
func v8cacheMatch(head []byte, size int64) bool {
	return len(head) >= 4 && head[2] == v8cacheMagic0 && head[3] == v8cacheMagic1
}

func inspectV8Cache(path string, d *Digest) {
	st, err := os.Stat(path)
	if err != nil {
		d.skip("v8cache-truncated", err.Error())
		return
	}
	size := st.Size()
	if size < v8cacheMinHeader {
		d.skip("v8cache-truncated", fmt.Sprintf("%d-byte file cannot hold a %d-byte header", size, v8cacheMinHeader))
		return
	}
	n := min(size, v8cacheMaxHeader)
	b, ok := allocCeil(d, "v8cache", n, "v8cache-too-big")
	if !ok {
		return
	}
	f, err := os.Open(path)
	if err != nil {
		d.skip("v8cache-truncated", err.Error())
		return
	}
	_, err = io.ReadFull(f, b)
	f.Close()
	if err != nil {
		d.skip("v8cache-truncated", err.Error())
		return
	}

	var fits []v8cacheLayout
	for _, l := range v8cacheLayouts {
		if int64(l.header) > size {
			continue
		}
		if int64(l.header)+int64(binary.LittleEndian.Uint32(b[l.payloadAt:])) == size {
			fits = append(fits, l)
		}
	}
	switch len(fits) {
	case 1:
	case 0:
		// 32-bit alignment writes 20/28/60-byte headers, which no shipped
		// desktop build does; they land here rather than in a guess.
		d.skip("v8cache-size-mismatch", fmt.Sprintf("no header accounts for %d bytes (%s)", size, v8cachePayloads(b)))
		return
	default:
		// Two generations can describe the same file when a field happens to be
		// zero; picking one would invent the source-hash width.
		d.skip("v8cache-header-unverified", fmt.Sprintf("%d and %d-byte headers both fit %d bytes", fits[0].header, fits[1].header, size))
		return
	}
	l := fits[0]
	payload := binary.LittleEndian.Uint32(b[l.payloadAt:])

	source := b[8 : 8+l.sourceLen]
	flagAt := 8 + l.sourceLen
	caps := []string{
		fmt.Sprintf("v8cache:header=%d", l.header),
		fmt.Sprintf("v8cache:version_hash=0x%08x", binary.LittleEndian.Uint32(b[4:8])),
		fmt.Sprintf("v8cache:source_hash=%s", hashValue(source)),
		fmt.Sprintf("v8cache:flag_hash=0x%08x", binary.LittleEndian.Uint32(b[flagAt:])),
		fmt.Sprintf("v8cache:payload=%d", payload),
		fmt.Sprintf("v8cache:checksum=0x%08x", binary.LittleEndian.Uint32(b[l.checksumAt:])),
	}
	if l.header > v8cacheMinHeader {
		caps = append(caps, fmt.Sprintf("v8cache:ro_snapshot_checksum=0x%08x", binary.LittleEndian.Uint32(b[l.payloadAt-4:])))
	}
	if l.trustedAt >= 0 {
		caps = append(caps, fmt.Sprintf("v8cache:trusted_payload=%d", binary.LittleEndian.Uint32(b[l.trustedAt:])))
	}
	d.Capabilities = append(d.Capabilities, caps...)
	d.Notes = append(d.Notes, fmt.Sprintf("v8-cache: %d-byte header, %d-byte payload: V8 cached bytecode for one script; the script source is not recoverable from it, and version_hash is a one-way engine ABI hash, not a runtime version", l.header, payload))
	deepNote(d, "match version_hash and the header width against a V8 build to name the engine, then read the source script or a bytecode dump of it: a code cache carries no source text")
	d.scanned(int64(l.header))
	d.parsed()
}

// v8cachePayloads lists the payload length each generation would read, so a
// mismatch names the numbers instead of only the file size.
func v8cachePayloads(b []byte) string {
	out := make([]string, 0, len(v8cacheLayouts))
	for _, l := range v8cacheLayouts {
		if len(b) < l.payloadAt+4 {
			out = append(out, fmt.Sprintf("%d header: unreadable", l.header))
			continue
		}
		out = append(out, fmt.Sprintf("%d header: %d", l.header, binary.LittleEndian.Uint32(b[l.payloadAt:])))
	}
	return strings.Join(out, ", ")
}

// hashValue prints each hash field the way it is stored: the 4-byte generations
// use a little-endian u32, V8 main widens the source hash to a 32-byte digest.
func hashValue(b []byte) string {
	if len(b) == 4 {
		return fmt.Sprintf("0x%08x", binary.LittleEndian.Uint32(b))
	}
	return fmt.Sprintf("0x%x", b)
}
