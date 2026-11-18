package main

// WebAssembly: detect.go owns the magic and pins the u32 LE version. This
// reader then walks the section directory with one LEB128 cursor to recover
// imports, exports, limits and the two custom sections that carry attribution
// (producers, name). Function bodies are never decoded, so nothing here claims
// the module is valid.

import (
	"bytes"
	"fmt"
	"os"
)

const (
	wasmVersion          = 1
	wasmComponentVersion = 0x1000d   // the component-model version the MVP never uses
	wasmMaxNames         = 64        // per-digest cap on names/limits copied out
	wasmLebMaxBytes      = 5         // ceil(32/7); a sixth byte is not a u32
	wasmLebMaxBytes64    = 10        // ceil(64/7); the memory64 limits are u64 LEB
	wasmMaxBytes         = 256 << 20 // whole-file read cap; a wasm module is read, never streamed
)

func init() {
	reasonRegistry["wasm"] = reasonSet(
		"no-disassembler",
		"wasm-producer-absent",
		"wasm-too-big",
		"wasm-too-many-names",
		"wasm-truncated",
		"wasm-version-unverified",
	)
	register(reader{
		format: "wasm",
		reasons: []string{
			"no-disassembler",
			"wasm-producer-absent",
			"wasm-too-big",
			"wasm-too-many-names",
			"wasm-truncated",
			"wasm-version-unverified",
		},
		post:    true, // detect.go's magic switch already owns wasm; this only enriches
		match:   func(h []byte, _ int64) bool { return bytes.HasPrefix(h, []byte("\x00asm")) },
		inspect: inspectWasm,
	})
}

// wasmCursor reads a byte slice front to back. Every size, count and index in a
// wasm module is a LEB128 u32, so one cursor type covers the whole walk.
type wasmCursor struct {
	b []byte
	i int
}

func (c *wasmCursor) u8() (byte, bool) {
	if c.i >= len(c.b) {
		return 0, false
	}
	v := c.b[c.i]
	c.i++
	return v, true
}

func (c *wasmCursor) bytes(n uint32) ([]byte, bool) {
	if uint64(n) > uint64(len(c.b)-c.i) {
		return nil, false
	}
	p := c.b[c.i : c.i+int(n)]
	c.i += int(n)
	return p, true
}

// u32 is one LEB128 read: at most five bytes, and the fifth byte may only
// carry the last four bits, so a 35-bit value is refused instead of truncated.
func (c *wasmCursor) u32() (uint32, bool) {
	var v uint32
	for n := range wasmLebMaxBytes {
		b, ok := c.u8()
		if !ok {
			return 0, false
		}
		if n == wasmLebMaxBytes-1 && b&0xf0 != 0 {
			return 0, false
		}
		v |= uint32(b&0x7f) << (7 * n)
		if b&0x80 == 0 {
			return v, true
		}
	}
	return 0, false
}

// u64 is the same LEB128 read widened for the memory64 limits: at most ten
// bytes, and the tenth may only carry the last bit, so a 65-bit value is
// refused instead of truncated.
func (c *wasmCursor) u64() (uint64, bool) {
	var v uint64
	for n := range wasmLebMaxBytes64 {
		b, ok := c.u8()
		if !ok {
			return 0, false
		}
		if n == wasmLebMaxBytes64-1 && b&0xfe != 0 {
			return 0, false
		}
		v |= uint64(b&0x7f) << (7 * n)
		if b&0x80 == 0 {
			return v, true
		}
	}
	return 0, false
}

func (c *wasmCursor) name() (string, bool) {
	n, ok := c.u32()
	if !ok {
		return "", false
	}
	p, ok := c.bytes(n)
	if !ok {
		return "", false
	}
	return string(p), true
}

// wasmWalk carries the per-file output state: the name cap and the two flags
// that become skip reasons at the end.
type wasmWalk struct {
	d         *Digest
	names     int
	capped    bool
	producers bool
	code      bool
}

// room accepts one more name/limit line, and says the cap once when it fills.
func (w *wasmWalk) room() bool {
	if w.names < wasmMaxNames {
		w.names++
		return true
	}
	if !w.capped {
		w.capped = true
		w.d.skip("wasm-too-many-names", fmt.Sprintf("capped at %d names", wasmMaxNames))
	}
	return false
}

func wasmShort(d *Digest, what string) bool {
	d.skip("wasm-truncated", what)
	return false
}

func inspectWasm(path string, d *Digest) {
	st, err := os.Stat(path)
	if err != nil {
		return
	}
	if st.Size() > wasmMaxBytes {
		d.skip("wasm-too-big", fmt.Sprintf("%d bytes, cap %d", st.Size(), wasmMaxBytes))
		return
	}
	b, err := readCapped(path, wasmMaxBytes)
	if err != nil || len(b) < 8 || !bytes.HasPrefix(b, []byte("\x00asm")) {
		return
	}
	d.scanned(int64(len(b)))
	ver := uint32(b[4]) | uint32(b[5])<<8 | uint32(b[6])<<16 | uint32(b[7])<<24
	if ver != wasmVersion {
		// The section grammar of the component model is not the MVP one, and
		// guessing it would produce plausible garbage.
		if ver == wasmComponentVersion {
			d.Format = "component"
			d.skip("wasm-version-unverified", "component model section layout")
		} else {
			d.skip("wasm-version-unverified", fmt.Sprintf("version 0x%x", ver))
		}
		return
	}
	if d.Format == "" {
		d.Format = "v1"
	}
	w := &wasmWalk{d: d}
	c := &wasmCursor{b: b, i: 8}
	for c.i < len(b) {
		at := c.i
		id, ok := c.u8()
		if !ok {
			break
		}
		size, ok := c.u32()
		if !ok {
			wasmShort(d, fmt.Sprintf("section size at %d", at))
			break
		}
		payload, ok := c.bytes(size)
		if !ok {
			wasmShort(d, fmt.Sprintf("section %d at %d needs %d bytes", id, at, size))
			break
		}
		s := &wasmCursor{b: payload}
		parsed, isCode, good := false, false, true
		switch id {
		case 0: // custom
			name, ok := s.name()
			if !ok {
				good = wasmShort(d, "custom section name")
				break
			}
			switch name {
			case "producers":
				w.producers = true
				good, parsed = wasmProducers(s, w), true
			case "name":
				good, parsed = wasmNames(s, w), true
			}
		case 2: // import
			good, parsed = wasmImports(s, w), true
		case 7: // export
			good, parsed = wasmExports(s, w), true
		case 10: // code
			isCode = true
		}
		if !good {
			d.unparsed()
			break
		}
		w.code = w.code || isCode
		switch {
		case parsed:
			d.parsed()
		case !isCode:
			d.unparsed()
		}
	}
	if w.code {
		d.skip("no-disassembler", "code section not decoded")
	}
	if !w.producers {
		d.skip("wasm-producer-absent", "no producers custom section")
	}
}

func wasmImports(s *wasmCursor, w *wasmWalk) bool {
	n, ok := s.u32()
	if !ok {
		return wasmShort(w.d, "import count")
	}
	for range n {
		mod, ok := s.name()
		if !ok {
			return wasmShort(w.d, "import module name")
		}
		fld, ok := s.name()
		if !ok {
			return wasmShort(w.d, "import field name")
		}
		kind, ok := s.u8()
		if !ok {
			return wasmShort(w.d, "import kind")
		}
		label := mod + "." + fld
		switch kind {
		case 0: // func
			_, ok = s.u32()
		case 1: // table
			ok = wasmRefType(s)
			if ok {
				ok = wasmLimits(s, w, label)
			}
		case 2: // memory
			ok = wasmLimits(s, w, label)
		case 3: // global
			if _, ok = s.u8(); ok {
				_, ok = s.u8()
			}
		case 4: // tag
			if _, ok = s.u8(); ok {
				_, ok = s.u32()
			}
		default:
			return wasmShort(w.d, fmt.Sprintf("import kind %d", kind))
		}
		if !ok {
			return wasmShort(w.d, "import descriptor")
		}
		if w.room() {
			w.d.Imports = append(w.d.Imports, label)
		}
	}
	return true
}

func wasmExports(s *wasmCursor, w *wasmWalk) bool {
	n, ok := s.u32()
	if !ok {
		return wasmShort(w.d, "export count")
	}
	for range n {
		name, ok := s.name()
		if !ok {
			return wasmShort(w.d, "export name")
		}
		if _, ok := s.u8(); !ok {
			return wasmShort(w.d, "export kind")
		}
		if _, ok := s.u32(); !ok {
			return wasmShort(w.d, "export index")
		}
		w.d.Exports++
		if w.room() {
			w.d.Notes = append(w.d.Notes, "wasm export: "+name)
		}
	}
	return true
}

// wasmProducers reads field -> [(tool, version)]. Item 80 reserves
// toolchain/mod/deps for Go/Rust native binaries, so producer attribution is
// kept in capabilities and notes, never in deps: a wasm module is not a Go
// module graph.
func wasmProducers(s *wasmCursor, w *wasmWalk) bool {
	n, ok := s.u32()
	if !ok {
		return wasmShort(w.d, "producers field count")
	}
	for range n {
		field, ok := s.name()
		if !ok {
			return wasmShort(w.d, "producers field name")
		}
		m, ok := s.u32()
		if !ok {
			return wasmShort(w.d, "producers entry count")
		}
		for range m {
			name, ok := s.name()
			if !ok {
				return wasmShort(w.d, "producers tool name")
			}
			ver, ok := s.name()
			if !ok {
				return wasmShort(w.d, "producers version")
			}
			if ver == "" {
				continue
			}
			tool := name
			if tool == "" {
				tool = field
			}
			// ponytail: producers recorded as caps, not deps; restore Deps
			// writes here once item 80's scope grows to wasm toolchains.
			if w.room() {
				w.d.Capabilities = append(w.d.Capabilities, "wasm:"+tool+"="+ver)
			}
		}
	}
	return true
}

// wasmNames reads the name custom section: subsection 0 is the module name and
// subsection 1 the function-name map. Other subsections (locals, labels) are
// skipped unread, not guessed.
func wasmNames(s *wasmCursor, w *wasmWalk) bool {
	for s.i < len(s.b) {
		id, ok := s.u8()
		if !ok {
			return true
		}
		size, ok := s.u32()
		if !ok {
			return wasmShort(w.d, "name subsection size")
		}
		sub, ok := s.bytes(size)
		if !ok {
			return wasmShort(w.d, "name subsection")
		}
		c := &wasmCursor{b: sub}
		switch id {
		case 0:
			name, ok := c.name()
			if !ok {
				return wasmShort(w.d, "module name")
			}
			w.d.Mod = name
		case 1:
			n, ok := c.u32()
			if !ok {
				return wasmShort(w.d, "function name count")
			}
			for range n {
				if _, ok := c.u32(); !ok {
					return wasmShort(w.d, "function name index")
				}
				name, ok := c.name()
				if !ok {
					return wasmShort(w.d, "function name")
				}
				if w.room() {
					w.d.Notes = append(w.d.Notes, "wasm function: "+name)
				}
			}
		}
	}
	return true
}

// wasmRefType walks an MVP funcref/externref byte plus the typed-reference
// forms that carry a trailing heap type.
func wasmRefType(s *wasmCursor) bool {
	b, ok := s.u8()
	if !ok {
		return false
	}
	if b == 0x63 || b == 0x64 {
		_, ok = s.u32()
	}
	return ok
}

// wasmLimits reads flags/min/(max) and records the pair under the import label.
// Bit 2 of the flags widens both bounds to LEB128 u64 (memory64/table64), so the
// width is read from the flags instead of assumed.
func wasmLimits(s *wasmCursor, w *wasmWalk, label string) bool {
	flags, ok := s.u8()
	if !ok {
		return false
	}
	wide := flags&0x04 != 0
	next := func() (uint64, bool) {
		if wide {
			return s.u64()
		}
		v, ok := s.u32()
		return uint64(v), ok
	}
	min, ok := next()
	if !ok {
		return false
	}
	max, hasMax := uint64(0), flags&0x01 != 0
	if hasMax {
		if max, ok = next(); !ok {
			return false
		}
	}
	if w.room() {
		m := "none"
		if hasMax {
			m = fmt.Sprint(max)
		}
		w.d.Notes = append(w.d.Notes, fmt.Sprintf("wasm limit: %s min=%d max=%s", label, min, m))
	}
	return true
}
