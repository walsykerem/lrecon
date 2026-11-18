package main

// Shared readers for the metadata-level inventory items (final.md 39-44): the
// DEX call-edge walker both android ops need, and the PE image base the P/Invoke
// verifier needs to turn an IAT RVA into the slot address imports report.

import (
	"fmt"
	"strings"
)

// metaBMethodLabel names one method_id as "Lcom/foo/Bar;->name". method_ids
// carry the owning class, so no class_def walk is needed for the name.
func metaBMethodLabel(r dexReader, idx int) (string, bool) {
	if idx < 0 || idx >= r.metSize {
		return "", false
	}
	at := r.metOff + 8*idx
	// method_id is {class_idx u16, proto_idx u16, name_idx u32}; reading the
	// class as a u32 folds proto_idx into the type index and fails on every
	// method whose proto is non-zero.
	class, ok := r.typeName(uint32(u16le(r.b, at)))
	if !ok {
		return "", false
	}
	name, ok := r.methodName(idx)
	if !ok {
		return "", false
	}
	return class + "->" + name, true
}

// metaBQuery matches a DEX identity against a query the way a reader types it:
// "com.foo.Bar", "Lcom/foo/Bar;", "Bar;->run" and case differences all hit.
func metaBQuery(s, query string) bool {
	n := func(v string) string {
		v = strings.TrimPrefix(v, "L")
		v = strings.ReplaceAll(v, "/", ".")
		return strings.ToLower(v)
	}
	q := n(query)
	return strings.Contains(n(s), q) || strings.Contains(n(strings.ReplaceAll(s, ";", "")), q)
}

// metaBInsnLen is the size in 16-bit units of one Dalvik instruction. Zero
// means the opcode is unused in every shipped dex, so a walk stops there
// instead of guessing a width and inventing call edges from data bytes.
func metaBInsnLen(op byte) int {
	switch {
	case op == 0x02 || op == 0x05 || op == 0x08, op == 0x13 || op == 0x15 || op == 0x16 || op == 0x19,
		op == 0x1a || op == 0x1c || op == 0x1f, op == 0x20 || op == 0x23,
		op == 0x22, op == 0x29, op >= 0x2d && op <= 0x3d,
		op >= 0x44 && op <= 0x6d, op >= 0x90 && op <= 0xaf, op >= 0xd0 && op <= 0xe2,
		op == 0xfe || op == 0xff:
		return 2
	case op == 0x03 || op == 0x06 || op == 0x09, op == 0x14 || op == 0x17 || op == 0x1b || op == 0x2a,
		op == 0x24 || op == 0x25 || op == 0x26, op == 0x2b || op == 0x2c,
		op >= 0x6e && op <= 0x72, op >= 0x74 && op <= 0x78, op == 0xfc || op == 0xfd:
		return 3
	case op == 0x18:
		return 5
	case op == 0xfa || op == 0xfb:
		return 4
	case op <= 0x12, op == 0x1d || op == 0x1e, op == 0x21, op == 0x27, op == 0x28, op >= 0x7b && op <= 0x8f, op >= 0xb0 && op <= 0xcf:
		return 1
	}
	return 0
}

// metaBIsInvoke reports the invoke-kind opcodes: 35c (0x6e-0x72) and 3rc
// (0x74-0x78). Their unit at +2 holds the method_ids index.
func metaBIsInvoke(op byte) bool {
	return op >= 0x6e && op <= 0x72 || op >= 0x74 && op <= 0x78
}

// metaBInvokes returns every method_ids index a code_item invokes. The code
// item is walked by instruction width, never scanned for byte patterns, so the
// edges come from decoded instructions.
func metaBInvokes(r dexReader, codeOff int) ([]int, error) {
	if codeOff < 0 || codeOff+16 > r.end {
		return nil, fmt.Errorf("code_item at %#x is outside the %#x-byte dex", codeOff, r.end)
	}
	units := int(u32le(r.b, codeOff+12))
	p := codeOff + 16
	if !dexIn(r.end, p, units, 2) {
		return nil, fmt.Errorf("code_item at %#x declares %d insns, past the dex", codeOff, units)
	}
	end := p + 2*units
	var out []int
	for p+2 <= end {
		u := u16le(r.b, p)
		// Pseudo-instructions sit inline: skip the payload so its data words are
		// not decoded as invoke opcodes.
		switch u {
		case 0x0100, 0x0200:
			if p+4 > end {
				return nil, fmt.Errorf("switch payload at %#x truncated", p)
			}
			n := int(u16le(r.b, p+2))
			w := 2 + 2*n
			if u == 0x0200 {
				w = 2 + 4*n
			}
			p += 2 * w
			continue
		case 0x0300:
			if p+8 > end {
				return nil, fmt.Errorf("array payload at %#x truncated", p)
			}
			elem, n := int(u16le(r.b, p+2)), int(u32le(r.b, p+4))
			p += 2 * (4 + (elem*n+1)/2)
			continue
		}
		op := byte(u & 0xFF)
		w := metaBInsnLen(op)
		if w == 0 {
			return nil, fmt.Errorf("unsupported Dalvik opcode 0x%02x at %#x", op, p)
		}
		if metaBIsInvoke(op) {
			if p+4 > end {
				return nil, fmt.Errorf("invoke at %#x truncated", p)
			}
			idx := int(u16le(r.b, p+2))
			if idx >= r.metSize {
				return nil, fmt.Errorf("invoke at %#x names method_id %d, table holds %d", p, idx, r.metSize)
			}
			out = append(out, idx)
		}
		p += 2 * w
	}
	if p != end {
		return nil, fmt.Errorf("code_item at %#x ends %d bytes past the last instruction", codeOff, p-end)
	}
	return out, nil
}

// metaBPEBase reads the image base and pointer width from a PE optional header.
// Thunks are RIP-relative on PE32+, absolute on PE32, so both values matter.
func metaBPEBase(b []byte) (base uint64, ptr int, ok bool) {
	if len(b) < 0x40 || b[0] != 'M' || b[1] != 'Z' {
		return 0, 0, false
	}
	lfan := int(u32le(b, 0x3c))
	if lfan+24+64 > len(b) || string(b[lfan:lfan+4]) != "PE\x00\x00" {
		return 0, 0, false
	}
	opt := lfan + 24
	switch u16le(b, opt) {
	case 0x20b:
		if opt+32 > len(b) {
			return 0, 0, false
		}
		return u64le(b, opt+24), 8, true
	case 0x10b:
		if opt+32 > len(b) {
			return 0, 0, false
		}
		return uint64(u32le(b, opt+28)), 4, true
	}
	return 0, 0, false
}
