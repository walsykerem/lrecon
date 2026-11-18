package main

import (
	"encoding/binary"
	"fmt"
	"regexp"
)

// Solidity/EVM CBOR metadata trailer. EVM bytecode has no header magic, so this
// registers as a post reader: the last two bytes are a big-endian length and the
// metadata map sits immediately before them. No opcode is decoded here, and the
// declared length is never allocated before the file size and the spec cap both
// admit it.

const (
	// Solidity's metadata map is ~50-100 bytes; 4 KiB is far above any real map
	// and small enough that a bogus length cannot become a buffer.
	evmMaxMeta = 1 << 12
	// The trailer's first byte is 0xA0|n, which only covers short-form maps.
	evmMaxKeys = 23
	evmClaim   = "solidity"
)

var evmSemverRe = regexp.MustCompile(`^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$`)

func init() {
	reasonRegistry["evm"] = reasonSet(
		"evm-metadata-unverified",
		"evm-trailer-oob",
		"evm-version-unverified",
		"no-cbor-metadata",
	)
	register(reader{
		format: "evm",
		reasons: []string{
			"evm-metadata-unverified",
			"evm-trailer-oob",
			"evm-version-unverified",
			"no-cbor-metadata",
		},
		match:   evmPrefilter,
		inspect: inspectEvm,
		post:    true,
	})
}

// evmPrefilter is the cheap head check: the full trailer is only in the sniff
// window for small files, so a larger file is left to inspect, which reads the
// last two bytes itself.
func evmPrefilter(head []byte, size int64) bool {
	if size < 2 {
		return false
	}
	if int64(len(head)) < size {
		return true
	}
	return evmTrailerPlausible(head[:size]) || evmHeadLooks(head)
}

// evmTrailerPlausible validates the trailer shape without opening the map: the
// declared length fits before the footer and the first trailer byte is 0xA0|n.
func evmTrailerPlausible(b []byte) bool {
	if len(b) < 3 {
		return false
	}
	declared := int64(binary.BigEndian.Uint16(b[len(b)-2:]))
	if declared < 1 || declared > evmMaxMeta || declared > int64(len(b)-2) {
		return false
	}
	return b[len(b)-2-int(declared)]&0xe0 == 0xa0
}

// evmHeadLooks is one byte of a compiled contract's dispatcher (PUSH1/PUSH2/
// PUSH0). It is a prefix check, not an opcode walk.
func evmHeadLooks(head []byte) bool {
	if len(head) < 2 {
		return false
	}
	switch head[0] {
	case 0x5f:
		return head[1] == 0x5f || head[1] == 0x80 || head[1] == 0x40
	case 0x60:
		return head[1] == 0x80 || head[1] == 0x40 || head[1] == 0x00 ||
			head[1] == 0x60 || head[1] == 0x5f
	case 0x61, 0x62:
		return true
	}
	return false
}

// evmCandidate keeps a refusal honest: only a file nothing else claimed, whose
// first bytes look like a contract, is called EVM. A real ELF or Mach-O that
// happens to end in 0x0000 is not.
func evmCandidate(path string, d *Digest) bool {
	if d.Kind != "" && d.Kind != "unknown" && d.Kind != "text" {
		return false
	}
	return evmHeadLooks(readFileAt(path, 0, 2))
}

func inspectEvm(path string, d *Digest) {
	size := fileSize(d, path)
	if size < 4 {
		return
	}
	trailer := readFileAt(path, size-2, 2)
	if trailer == nil {
		return
	}
	declared := int64(binary.BigEndian.Uint16(trailer))
	candidate := evmCandidate(path, d)
	switch {
	case declared == 0:
		if candidate {
			d.skip("no-cbor-metadata", "trailer is 0000: metadata was not emitted")
		}
		return
	case declared > evmMaxMeta:
		if candidate {
			d.skip("no-cbor-metadata", fmt.Sprintf("declared metadata length %d exceeds the %d-byte cap", declared, evmMaxMeta))
		}
		return
	}
	start := size - 2 - declared
	if start < 0 {
		if candidate {
			d.skip("evm-trailer-oob", fmt.Sprintf("declared %d metadata bytes do not fit in a %d-byte file", declared, size))
		}
		return
	}
	meta := readFileAt(path, start, declared)
	if len(meta) != int(declared) {
		if candidate {
			d.skip("evm-metadata-unverified", "metadata range is unreadable")
		}
		return
	}
	if meta[0]&0xe0 != 0xa0 {
		// Not a CBOR map: this is the no-metadata shape (vyper, huff, a cut
		// trailer), not a damaged Solidity map.
		if candidate {
			d.skip("no-cbor-metadata", "bytes before the length are not a CBOR map")
		}
		return
	}
	m, ok := evmParseMetadata(meta)
	if !ok {
		if candidate {
			d.skip("evm-metadata-unverified", fmt.Sprintf("CBOR map at %#x does not validate", start))
		}
		return
	}

	d.Format = "evm"
	d.Capabilities = append(d.Capabilities, fmt.Sprintf("evm:metadata_bytes=%d", len(meta)))
	if m.ipfs {
		d.Capabilities = append(d.Capabilities, "evm:ipfs")
	}
	if m.bzzr0 {
		d.Capabilities = append(d.Capabilities, "evm:bzzr0")
	}
	if m.bzzr1 {
		d.Capabilities = append(d.Capabilities, "evm:bzzr1")
	}
	if m.experimental {
		d.Capabilities = append(d.Capabilities, "evm:experimental")
	}
	d.claim(evmClaim, "cbor-trailer", start)
	d.scanned(int64(len(meta)) + 2)
	if m.solc == "" {
		d.skip("evm-version-unverified", "metadata carries no readable solc version")
		d.Notes = append(d.Notes, fmt.Sprintf("evm: CBOR metadata %d bytes at %#x, version not recorded", len(meta), start))
		return
	}
	if d.Toolchain == "" {
		d.Toolchain = "solc " + m.solc
	} else {
		d.Notes = append(d.Notes, "solc "+m.solc)
	}
	d.claim(evmClaim, "solc:"+m.solc, start+m.solcOff)
	d.Notes = append(d.Notes, fmt.Sprintf("evm: CBOR metadata %d bytes at %#x, solc %s", len(meta), start, m.solc))
	d.parsed()
}

// evmMeta is the closed set of keys Solidity writes into the trailer map.
type evmMeta struct {
	ipfs, bzzr0, bzzr1, experimental bool
	solc                             string
	solcOff                          int64
	recognized                       int
}

// evmParseMetadata walks the short-form map only. Unknown keys are skipped by
// the caller's framing check; a recognized key whose value shape is wrong
// refuses the whole map instead of reading past it.
func evmParseMetadata(b []byte) (evmMeta, bool) {
	var m evmMeta
	if len(b) < 1 || b[0]&0xe0 != 0xa0 {
		return m, false
	}
	n := int(b[0] & 0x1f)
	if n == 0 || n > evmMaxKeys {
		return m, false
	}
	pos := 1
	for range n {
		kmaj, key, next, ok := evmItem(b, pos)
		if !ok || kmaj != 3 {
			return m, false
		}
		pos = next
		voff := pos
		vmaj, val, next, ok := evmItem(b, pos)
		if !ok {
			return m, false
		}
		pos = next
		switch string(key) {
		case "ipfs":
			if vmaj != 2 || len(val) != 34 || val[0] != 0x12 || val[1] != 0x20 {
				return m, false
			}
			m.ipfs = true
			m.recognized++
		case "bzzr0":
			if vmaj != 2 || len(val) != 32 {
				return m, false
			}
			m.bzzr0 = true
			m.recognized++
		case "bzzr1":
			if vmaj != 2 || len(val) != 32 {
				return m, false
			}
			m.bzzr1 = true
			m.recognized++
		case "experimental":
			if vmaj != 7 {
				return m, false
			}
			m.experimental = true
			m.recognized++
		case "solc":
			m.recognized++
			v, ok := evmSolc(vmaj, val)
			if !ok {
				continue // readable keys still describe the artifact; version stays unrecorded
			}
			m.solc, m.solcOff = v, int64(voff)
		}
	}
	if m.recognized == 0 {
		return m, false
	}
	return m, true
}

// evmSolc reads the compact 3-byte version Solidity writes (0.8.21 = 00 08 15)
// or the older strict semver text. Any other shape is refused, never guessed.
func evmSolc(major byte, body []byte) (string, bool) {
	switch major {
	case 2:
		if len(body) != 3 || body[0] > 99 || body[1] > 99 || body[2] > 99 {
			return "", false
		}
		return fmt.Sprintf("%d.%d.%d", body[0], body[1], body[2]), true
	case 3:
		if !evmSemverRe.Match(body) {
			return "", false
		}
		return string(body), true
	}
	return "", false
}

// evmItem decodes one item's framing: major type, the payload of a byte/text
// string, and the offset after it. Arrays, maps, tags, indefinite lengths and
// floats are refused; Solidity's trailer map uses none of them.
func evmItem(b []byte, off int) (major byte, body []byte, next int, ok bool) {
	if off < 0 || off >= len(b) {
		return 0, nil, 0, false
	}
	h := b[off]
	major = h >> 5
	n, size, ok := evmArg(b, off, h&0x1f)
	if !ok {
		return 0, nil, 0, false
	}
	switch major {
	case 0, 1:
		return major, nil, off + size, true
	case 2, 3:
		start := off + size
		if start > len(b) || n > len(b)-start {
			return 0, nil, 0, false
		}
		return major, b[start : start+n], start + n, true
	case 7:
		if ai := h & 0x1f; ai == 20 || ai == 21 || ai == 22 {
			return major, nil, off + 1, true
		}
	}
	return 0, nil, 0, false
}

// evmArg returns an item's declared length and header width. Widths above 4
// bytes cannot describe a map this reader accepts, so they are refused before
// any allocation could follow.
func evmArg(b []byte, off int, ai byte) (n, size int, ok bool) {
	switch {
	case ai < 24:
		return int(ai), 1, true
	case ai == 24:
		if off+1 >= len(b) {
			return 0, 0, false
		}
		return int(b[off+1]), 2, true
	case ai == 25:
		if off+2 >= len(b) {
			return 0, 0, false
		}
		return int(binary.BigEndian.Uint16(b[off+1:])), 3, true
	case ai == 26:
		if off+4 >= len(b) {
			return 0, 0, false
		}
		v := binary.BigEndian.Uint32(b[off+1:])
		if int64(v) > evmMaxMeta {
			return 0, 0, false
		}
		return int(v), 5, true
	}
	return 0, 0, false
}
