package main

// Lua 5.3/5.4 prototype recovery. lua.go reads the header and stops; the
// prototype tree behind it carries the parts a reader wants next: the source
// name and line range of every function, the parameter count, the local
// variable names and the upvalue names. A stripped chunk keeps the tree but
// drops those debug sections, which is exactly the absence this reader reports.
//
// Only 5.3 and 5.4 have the layout parsed here. 5.1 and 5.2 use different
// headers and different field widths, so a real 5.1/5.2 chunk is refused by
// version instead of being fed to the wrong decoder. The post reader never
// claims the file: lua.go owns the kind and the header version.

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"strings"
)

const (
	luaProtoMaxRead = 8 << 20
	luaProtoMaxTree = 1024
	luaProtoMaxDeep = 64
	luaProtoMaxList = 8
)

var luaProtoReasons = []string{
	"luaproto-name-absent",
	"luaproto-truncated",
	"luaproto-version-unverified",
}

func init() {
	reasonRegistry["luaproto"] = reasonSet(luaProtoReasons...)
	register(reader{
		format:  "luaproto",
		reasons: luaProtoReasons,
		match:   luaProtoMatch,
		inspect: inspectLuaProto,
		post:    true,
	})
}

// luaChunkHeader is the verified luac header: version, byte order, the five
// target word sizes and the offset where the prototype tree starts. The order
// is proven by the LUAC_INT/LUAC_NUM sentinels, never assumed from the host.
type luaChunkHeader struct {
	version     byte
	order       binary.ByteOrder
	intSize     int
	sizeTSize   int
	instrSize   int
	integerSize int
	numSize     int
	body        int
}

// luaProtoMatch runs only on headers this reader can prove. The lua reader's
// synthetic fixtures in the test suite put their fields at other offsets; a
// loose match here would emit a skip on files that reader already answered.
func luaProtoMatch(head []byte, size int64) bool {
	_, ok := luaProtoHeader(head)
	return ok
}

func inspectLuaProto(path string, d *Digest) {
	b := head(path, luaProtoMaxRead)
	// lua.go already scanned the header from the same file; only the bytes this
	// pass reads past that cursor are new, so the digest never claims more bytes
	// than the file holds.
	if gap := int64(len(b)) - d.readEnd(); gap > 0 {
		d.scanned(gap)
	}
	h, ok := luaProtoHeader(b)
	if !ok {
		return
	}
	if h.version != 0x53 && h.version != 0x54 {
		d.skip("luaproto-version-unverified", fmt.Sprintf("lua 5.%d prototype layout is not decoded", h.version-0x50))
		return
	}
	p := &luaParser{b: b, off: h.body, h: h}
	// luaU_undump reads the main closure's upvalue count before the function;
	// the count is only useful to a VM, the debug sections below are what is
	// recovered here.
	if _, ok := p.u8(); !ok {
		d.skip("luaproto-truncated", p.err.Error())
		return
	}
	if !p.proto("", 0) {
		d.skip("luaproto-truncated", p.err.Error())
		return
	}
	d.parsed()
	cappedDeepNotes(d, "lua-proto ", p.notes)
	if p.names == 0 {
		// The tree was fully decoded; the debug sections are simply absent.
		// That is a finding about stripping, not a parse failure.
		d.skip("luaproto-name-absent", fmt.Sprintf("%d prototypes, no local or upvalue names", p.protos))
	}
}

// luaChunkHeader proves a real header for each version the Lua reader knows.
// 5.1 carries an explicit endianness byte, 5.2+ prove order with the integer
// and number sentinels after the word sizes.
func luaProtoHeader(b []byte) (luaChunkHeader, bool) {
	var h luaChunkHeader
	if len(b) < 6 || !bytes.HasPrefix(b, luaMagic) {
		return h, false
	}
	h.version = b[4]
	if b[5] != 0 {
		return h, false
	}
	switch h.version {
	case 0x51:
		// luaU_header: signature, version, format, endianness, int, size_t,
		// Instruction, number, then the integral-number flag. 5.1 has no
		// LUAC_DATA and no condition sentinel, so the order byte is the proof
		// and the dump body starts at 12.
		if len(b) < 12 {
			return h, false
		}
		h.intSize = int(b[7])
		h.sizeTSize = int(b[8])
		h.instrSize = int(b[9])
		h.numSize = int(b[10])
		h.integerSize = 4
		order := luaOrder(b[6])
		if order == nil || b[11] > 1 || !lua51Sizes(h) {
			return h, false
		}
		h.order = order
		h.body = 12
		return h, true
	case 0x52, 0x53:
		// LUAC_DATA at 6, five sizes at 12, sentinels at 17.
		if len(b) < 17 || !bytes.Equal(b[6:12], luaCheck) {
			return h, false
		}
		h.intSize = int(b[12])
		h.sizeTSize = int(b[13])
		h.instrSize = int(b[14])
		h.integerSize = int(b[15])
		h.numSize = int(b[16])
		if !luaSizes(byte(h.intSize), byte(h.sizeTSize), byte(h.instrSize), byte(h.integerSize), byte(h.numSize)) {
			return h, false
		}
		order := luaSentinelOrder(b, 17, h.integerSize, h.numSize)
		if order == nil {
			return h, false
		}
		h.order = order
		h.body = 17 + h.integerSize + h.numSize
		return h, true
	case 0x54:
		// LUAC_DATA at 6, three sizes at 12, sentinels at 15.
		if len(b) < 15 || !bytes.Equal(b[6:12], luaCheck) {
			return h, false
		}
		h.instrSize = int(b[12])
		h.integerSize = int(b[13])
		h.numSize = int(b[14])
		if h.instrSize != 4 ||
			(h.integerSize != 4 && h.integerSize != 8) ||
			(h.numSize != 4 && h.numSize != 8) {
			return h, false
		}
		order := luaSentinelOrder(b, 15, h.integerSize, h.numSize)
		if order == nil {
			return h, false
		}
		h.order = order
		h.body = 15 + h.integerSize + h.numSize
		return h, true
	}
	return h, false
}

func lua51Sizes(h luaChunkHeader) bool {
	return (h.intSize == 4 || h.intSize == 8) &&
		(h.sizeTSize == 4 || h.sizeTSize == 8) &&
		h.instrSize == 4 &&
		(h.numSize == 4 || h.numSize == 8)
}

func luaSentinelOrder(b []byte, off, integerSize, numSize int) binary.ByteOrder {
	if off+integerSize+numSize > len(b) {
		return nil
	}
	num := b[off+integerSize : off+integerSize+numSize]
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		if luaReadUint(b[off:off+integerSize], order) == 0x5678 &&
			luaFloat(num, order) == 370.5 {
			return order
		}
	}
	return nil
}

func luaFloat(b []byte, order binary.ByteOrder) float64 {
	if len(b) == 4 {
		return float64(math.Float32frombits(uint32(luaReadUint(b, order))))
	}
	return math.Float64frombits(luaReadUint(b, order))
}

// luaParser reads the prototype tree. All reads go through the same cursor and
// failure is sticky: the first short or malformed field ends the walk, and the
// caller reports one truncated reason with the exact field that failed.
type luaParser struct {
	b      []byte
	off    int
	h      luaChunkHeader
	err    error
	protos int
	names  int
	notes  []string
}

func (p *luaParser) fail(format string, args ...any) bool {
	if p.err == nil {
		p.err = fmt.Errorf(format, args...)
	}
	return false
}

func (p *luaParser) u8() (byte, bool) {
	if p.off >= len(p.b) {
		return 0, p.fail("truncated at byte %d", p.off)
	}
	v := p.b[p.off]
	p.off++
	return v, true
}

func (p *luaParser) uintN(n int) (uint64, bool) {
	if n <= 0 || p.off+n > len(p.b) {
		return 0, p.fail("%d-byte integer at byte %d, %d left", n, p.off, len(p.b)-p.off)
	}
	v := luaReadUint(p.b[p.off:p.off+n], p.h.order)
	p.off += n
	return v, true
}

// varint is the 5.4 encoding, not the protobuf one: seven bits per byte,
// most-significant group first, and the LAST byte has bit 7 set. Reading it as
// little-endian would turn every size into a different number.
func (p *luaParser) varint() (uint64, bool) {
	var x uint64
	for range 10 {
		b, ok := p.u8()
		if !ok {
			return 0, false
		}
		if x > 1<<56 {
			return 0, p.fail("varint overflow at byte %d", p.off)
		}
		x = x<<7 | uint64(b&0x7f)
		if b&0x80 != 0 {
			return x, true
		}
	}
	return 0, p.fail("varint longer than 10 bytes at %d", p.off)
}

func (p *luaParser) skip(n uint64) bool {
	if n > uint64(len(p.b)-p.off) {
		return p.fail("%d bytes at %d, %d left", n, p.off, len(p.b)-p.off)
	}
	p.off += int(n)
	return true
}

// skipN skips n units of unit bytes. The width is read from the chunk, so the
// product is refused rather than wrapped when a header claims an absurd count.
func (p *luaParser) skipN(n, unit uint64) bool {
	if unit != 0 && n > ^uint64(0)/unit {
		return p.fail("%d x %d bytes overflows at %d", n, unit, p.off)
	}
	return p.skip(n * unit)
}

// str53 reads a 5.3 string: one size byte, 0xFF escapes to a size_t, zero is
// NULL, and a non-zero size counts the terminating NUL the dump does not store.
func (p *luaParser) str53() (string, bool, bool) {
	size, ok := p.u8()
	if !ok {
		return "", false, false
	}
	n := uint64(size)
	if size == 0xff {
		if n, ok = p.uintN(p.h.sizeTSize); !ok {
			return "", false, false
		}
	}
	if n == 0 {
		return "", false, true
	}
	if n-1 > uint64(len(p.b)-p.off) {
		p.fail("string of %d bytes at %d, %d left", n-1, p.off, len(p.b)-p.off)
		return "", false, false
	}
	s := string(p.b[p.off : p.off+int(n-1)])
	p.off += int(n - 1)
	return s, true, true
}

// str54 reads a 5.4 string: a varint size, zero is NULL, and again the stored
// size includes a NUL that is not in the payload.
func (p *luaParser) str54() (string, bool, bool) {
	n, ok := p.varint()
	if !ok {
		return "", false, false
	}
	if n == 0 {
		return "", false, true
	}
	if n-1 > uint64(len(p.b)-p.off) {
		p.fail("string of %d bytes at %d, %d left", n-1, p.off, len(p.b)-p.off)
		return "", false, false
	}
	s := string(p.b[p.off : p.off+int(n-1)])
	p.off += int(n - 1)
	return s, true, true
}

func (p *luaParser) proto(parent string, depth int) bool {
	if depth > luaProtoMaxDeep {
		return p.fail("prototype nesting exceeds %d", luaProtoMaxDeep)
	}
	p.protos++
	if p.protos > luaProtoMaxTree {
		return p.fail("prototype count exceeds %d", luaProtoMaxTree)
	}
	if p.h.version == 0x53 {
		return p.proto53(parent, depth)
	}
	return p.proto54(parent, depth)
}

func (p *luaParser) proto53(parent string, depth int) bool {
	src, present, ok := p.str53()
	if !ok {
		return false
	}
	if !present {
		src = parent
	}
	line, ok := p.uintN(p.h.intSize)
	if !ok {
		return false
	}
	last, ok := p.uintN(p.h.intSize)
	if !ok {
		return false
	}
	params, ok := p.u8()
	if !ok {
		return false
	}
	if _, ok := p.u8(); !ok { // is_vararg
		return false
	}
	if _, ok := p.u8(); !ok { // maxstacksize
		return false
	}
	ncode, ok := p.uintN(p.h.intSize)
	if !ok || !p.skipN(ncode, 4) {
		return false
	}
	nk, ok := p.uintN(p.h.intSize)
	if !ok {
		return false
	}
	for i := range nk {
		tag, ok := p.u8()
		if !ok {
			return false
		}
		switch tag {
		case 0: // nil
		case 1: // boolean
			if _, ok := p.u8(); !ok {
				return false
			}
		case 3: // float
			if !p.skip(uint64(p.h.numSize)) {
				return false
			}
		case 19: // integer
			if !p.skip(uint64(p.h.integerSize)) {
				return false
			}
		case 4, 20: // short/long string
			if _, _, ok := p.str53(); !ok {
				return false
			}
		default:
			return p.fail("constant %d has tag %d at byte %d", i, tag, p.off-1)
		}
	}
	nup, ok := p.uintN(p.h.intSize)
	if !ok || !p.skipN(nup, 2) {
		return false
	}
	nproto, ok := p.uintN(p.h.intSize)
	if !ok {
		return false
	}
	for range nproto {
		if !p.proto(src, depth+1) {
			return false
		}
	}
	nline, ok := p.uintN(p.h.intSize)
	if !ok || !p.skipN(nline, uint64(p.h.intSize)) {
		return false
	}
	nloc, ok := p.uintN(p.h.intSize)
	if !ok {
		return false
	}
	var locals []string
	for range nloc {
		name, present, ok := p.str53()
		if !ok {
			return false
		}
		if !p.skip(uint64(p.h.intSize) * 2) {
			return false
		}
		if present && name != "" {
			locals = append(locals, name)
		}
	}
	nupname, ok := p.uintN(p.h.intSize)
	if !ok {
		return false
	}
	var ups []string
	for range nupname {
		name, present, ok := p.str53()
		if !ok {
			return false
		}
		if present && name != "" {
			ups = append(ups, name)
		}
	}
	p.record(src, line, last, params, locals, ups)
	return true
}

func (p *luaParser) proto54(parent string, depth int) bool {
	src, present, ok := p.str54()
	if !ok {
		return false
	}
	if !present {
		src = parent
	}
	line, ok := p.varint()
	if !ok {
		return false
	}
	last, ok := p.varint()
	if !ok {
		return false
	}
	params, ok := p.u8()
	if !ok {
		return false
	}
	if _, ok := p.u8(); !ok { // is_vararg
		return false
	}
	if _, ok := p.u8(); !ok { // maxstacksize
		return false
	}
	ncode, ok := p.varint()
	if !ok || !p.skipN(ncode, 4) {
		return false
	}
	nk, ok := p.varint()
	if !ok {
		return false
	}
	for i := range nk {
		tag, ok := p.u8()
		if !ok {
			return false
		}
		switch tag {
		case 0, 1, 17: // nil, false, true
		case 3: // float
			if !p.skip(uint64(p.h.numSize)) {
				return false
			}
		case 19: // integer, zigzag varint
			if _, ok := p.varint(); !ok {
				return false
			}
		case 4, 20: // short/long string
			if _, _, ok := p.str54(); !ok {
				return false
			}
		default:
			return p.fail("constant %d has tag %d at byte %d", i, tag, p.off-1)
		}
	}
	nup, ok := p.varint()
	if !ok || !p.skipN(nup, 3) {
		return false
	}
	nproto, ok := p.varint()
	if !ok {
		return false
	}
	for range nproto {
		if !p.proto(src, depth+1) {
			return false
		}
	}
	nline, ok := p.varint()
	if !ok || !p.skip(nline) {
		return false
	}
	// 5.4 adds absolute-line anchors; they only offset the byte lineinfo, which
	// is not decoded here.
	nabs, ok := p.varint()
	if !ok {
		return false
	}
	for range nabs {
		if _, ok := p.varint(); !ok {
			return false
		}
		if _, ok := p.varint(); !ok {
			return false
		}
	}
	nloc, ok := p.varint()
	if !ok {
		return false
	}
	var locals []string
	for range nloc {
		name, present, ok := p.str54()
		if !ok {
			return false
		}
		if _, ok := p.varint(); !ok {
			return false
		}
		if _, ok := p.varint(); !ok {
			return false
		}
		if present && name != "" {
			locals = append(locals, name)
		}
	}
	// The stored upvalue-name count is a flag in 5.4: the real count is
	// sizeupvalues, already read above.
	declared, ok := p.varint()
	if !ok {
		return false
	}
	var ups []string
	if declared != 0 {
		for range nup {
			name, present, ok := p.str54()
			if !ok {
				return false
			}
			if present && name != "" {
				ups = append(ups, name)
			}
		}
	}
	p.record(src, line, last, params, locals, ups)
	return true
}

func (p *luaParser) record(src string, line, last uint64, params byte, locals, ups []string) {
	if len(locals) > 0 || len(ups) > 0 {
		p.names++
	}
	s := fmt.Sprintf("%s:%d-%d params=%d", luaSourceLabel(src), line, last, params)
	if len(locals) > 0 {
		s += " locals=" + luaShortList(locals)
	}
	if len(ups) > 0 {
		s += " upvals=" + luaShortList(ups)
	}
	p.notes = append(p.notes, s)
}

// luaSourceLabel turns the chunk's source reference into the name a reader
// would type. Lua prefixes a file with '@', stdin with '=', and stores raw
// source text verbatim; only the first two are names.
func luaSourceLabel(src string) string {
	src = strings.TrimPrefix(strings.TrimPrefix(src, "@"), "=")
	if src == "" {
		return "?"
	}
	src = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' {
			return ' '
		}
		return r
	}, src)
	if len(src) > 48 {
		src = src[:48] + "..."
	}
	return src
}

func luaShortList(names []string) string {
	if len(names) <= luaProtoMaxList {
		return strings.Join(names, "/")
	}
	return strings.Join(names[:luaProtoMaxList], "/") + fmt.Sprintf("/+%d", len(names)-luaProtoMaxList)
}

// cappedDeepNotes keeps the digest readable: eight lines per reader, then one
// line saying how many stayed unprinted. The list is already truncated by the
// caller where an unbounded walk could grow it.
func cappedDeepNotes(d *Digest, prefix string, items []string) {
	const max = 8
	if len(items) > max {
		items = append(items[:max-1:max-1], fmt.Sprintf("+%d more", len(items)-(max-1)))
	}
	for _, item := range items {
		deepNote(d, prefix+item)
	}
}
