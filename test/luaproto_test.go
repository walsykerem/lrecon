package main

import (
	"encoding/binary"
	"math"
	"strings"
	"testing"
)

// Fixtures are hand-built from lundump.c/ldump.c: no lua or luac is installed
// here, so the chunk is written field by field and the assertion covers the
// real contract (5.4 varints, sizeupvalues, debug section order) rather than a
// captured blob. The refusal case uses a genuine 5.1 header, which is the only
// way to prove the version gate fires before the 5.4 decoder sees it.

func le64(v uint64) []byte {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], v)
	return b[:]
}

func leFloat(v float64) []byte { return le64(math.Float64bits(v)) }

// luaRealHeader is the verified luac header: signature, version, format,
// LUAC_DATA, target word sizes, then the two sentinels that prove byte order.
func luaRealHeader(version byte) []byte {
	b := append([]byte("\x1bLua"), version, 0)
	switch version {
	case 0x51:
		// 5.1: endianness, then sizes for int, size_t, Instruction and
		// number, then the integral-number flag. No LUAC_DATA, no sentinel.
		b = append(b, 1) // little-endian
		b = append(b, 4, 8, 4, 8)
		return append(b, 0)
	case 0x52, 0x53:
		b = append(b, luaCheck...)
		b = append(b, 4, 8, 4, 8, 8)
		b = append(b, le64(0x5678)...)
		return append(b, leFloat(370.5)...)
	default: // 0x54
		b = append(b, luaCheck...)
		b = append(b, 4, 8, 8)
		b = append(b, le64(0x5678)...)
		return append(b, leFloat(370.5)...)
	}
}

// v54 encodes the 5.4 size format: big-endian base 128, and the LAST byte has
// the high bit set. Reading it as little-endian silently shifts every size.
func v54(x uint64) []byte {
	var groups []byte
	for {
		groups = append([]byte{byte(x & 0x7f)}, groups...)
		x >>= 7
		if x == 0 {
			break
		}
	}
	groups[len(groups)-1] |= 0x80
	return groups
}

func s54(s string) []byte { return append(v54(uint64(len(s)+1)), s...) }

// proto54 writes one 5.4 prototype. Empty source means "inherit parent", the
// encoding luac uses for every nested function.
func proto54(source string, line, last uint64, locals, upnames []string, nested ...[]byte) []byte {
	var b []byte
	if source == "" {
		b = append(b, v54(0)...)
	} else {
		b = append(b, s54(source)...)
	}
	b = append(b, v54(line)...)
	b = append(b, v54(last)...)
	b = append(b, 0, 1, 4)    // numparams, is_vararg, maxstacksize
	b = append(b, v54(1)...)  // sizecode
	b = append(b, 0, 0, 0, 0) // one instruction
	b = append(b, v54(0)...)  // sizek
	b = append(b, v54(uint64(len(upnames)))...)
	for range upnames {
		b = append(b, 0, 0, 0) // instack, idx, kind
	}
	b = append(b, v54(uint64(len(nested)))...)
	for _, n := range nested {
		b = append(b, n...)
	}
	b = append(b, v54(1)...) // lineinfo count
	b = append(b, 0)         // one lineinfo byte
	b = append(b, v54(0)...) // abslineinfo count
	b = append(b, v54(uint64(len(locals)))...)
	for _, n := range locals {
		b = append(b, s54(n)...)
		b = append(b, v54(0)...)    // startpc
		b = append(b, v54(last)...) // endpc
	}
	b = append(b, v54(uint64(len(upnames)))...)
	for _, n := range upnames {
		b = append(b, s54(n)...)
	}
	return b
}

func lua54Chunk() []byte {
	b := luaRealHeader(0x54)
	b = append(b, 4) // sizeupvalues of the main closure
	b = append(b, proto54("@t.lua", 0, 4, []string{"x"}, []string{"a"},
		proto54("", 1, 2, nil, nil),
		proto54("", 2, 3, nil, nil))...)
	return b
}

// i53 is one 5.3 C int (4 bytes, chunk byte order).
func i53(v uint32) []byte {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], v)
	return b[:]
}

// str53w writes a 5.3 string: one size byte that counts the NUL, no varint.
func str53w(s string) []byte { return append([]byte{byte(len(s) + 1)}, s...) }

// proto53 mirrors lundump.c LoadFunction/LoadDebug for 5.3: int-sized counts,
// two-byte upvalue cells, and no absolute-line anchors.
func proto53(source string, line, last uint32, locals, upnames []string, nested ...[]byte) []byte {
	var b []byte
	if source == "" {
		b = append(b, 0)
	} else {
		b = append(b, str53w(source)...)
	}
	b = append(b, i53(line)...)
	b = append(b, i53(last)...)
	b = append(b, 0, 1, 4)   // numparams, is_vararg, maxstacksize
	b = append(b, i53(1)...) // sizecode
	b = append(b, 0, 0, 0, 0)
	b = append(b, i53(0)...) // sizek
	b = append(b, i53(uint32(len(upnames)))...)
	for range upnames {
		b = append(b, 0, 0) // instack, idx
	}
	b = append(b, i53(uint32(len(nested)))...)
	for _, n := range nested {
		b = append(b, n...)
	}
	b = append(b, i53(1)...) // lineinfo count
	b = append(b, i53(0)...) // one lineinfo int
	b = append(b, i53(uint32(len(locals)))...)
	for _, n := range locals {
		b = append(b, str53w(n)...)
		b = append(b, i53(0)...)
		b = append(b, i53(last)...)
	}
	b = append(b, i53(uint32(len(upnames)))...)
	for _, n := range upnames {
		b = append(b, str53w(n)...)
	}
	return b
}

// TestLuaProto53 exercises the older layout: same debug answers, int counts.
func TestLuaProto53(t *testing.T) {
	chunk := append(luaRealHeader(0x53), 2) // sizeupvalues
	chunk = append(chunk, proto53("@t.lua", 0, 3, []string{"y"}, []string{"a", "b"},
		proto53("", 1, 2, nil, nil))...)
	d, err := Probe(writeTemp(t, "t53.luac", chunk))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"deep: lua-proto t.lua:1-2 params=0",
		"deep: lua-proto t.lua:0-3 params=0 locals=y upvals=a/b",
	} {
		if !containsStr(d.Notes, want) {
			t.Fatalf("notes %v missing %q", d.Notes, want)
		}
	}
}

func TestLuaProtoNames(t *testing.T) {
	d, err := Probe(writeTemp(t, "t.luac", lua54Chunk()))
	if err != nil {
		t.Fatal(err)
	}
	if d.Kind != "lua" {
		t.Fatalf("kind = %q, want lua", d.Kind)
	}
	want := []string{
		"deep: lua-proto t.lua:1-2 params=0",
		"deep: lua-proto t.lua:2-3 params=0",
		"deep: lua-proto t.lua:0-4 params=0 locals=x upvals=a",
	}
	for _, w := range want {
		if !containsStr(d.Notes, w) {
			t.Fatalf("notes %v missing %q", d.Notes, w)
		}
	}
	for _, s := range d.Skipped {
		if strings.HasPrefix(s.Reason, "luaproto") {
			t.Fatalf("unexpected skip %+v", s)
		}
	}
}

// TestLuaProtoStripped keeps the tree but drops every debug section: the
// prototypes still parse, names are simply gone.
func TestLuaProtoStripped(t *testing.T) {
	chunk := append(luaRealHeader(0x54), 0) // sizeupvalues
	chunk = append(chunk, proto54("@t.lua", 0, 4, nil, nil)...)
	d, err := Probe(writeTemp(t, "s.luac", chunk))
	if err != nil {
		t.Fatal(err)
	}
	luaprotoSkip(t, d, "luaproto-name-absent")
}

func TestLuaProtoTruncated(t *testing.T) {
	chunk := append(luaRealHeader(0x54), 0)
	chunk = append(chunk, v54(7)...) // source claims 6 bytes, none present
	chunk = append(chunk, 0)
	d, err := Probe(writeTemp(t, "cut.luac", chunk))
	if err != nil {
		t.Fatal(err)
	}
	luaprotoSkip(t, d, "luaproto-truncated")
}

// TestLuaProtoRefuses51 drives a real 5.1 header through the match: the reader
// must name the version, never decode it with the 5.4 layout.
func TestLuaProtoRefuses51(t *testing.T) {
	chunk := append(luaRealHeader(0x51), 0, 0, 0, 0)
	d, err := Probe(writeTemp(t, "old.luac", chunk))
	if err != nil {
		t.Fatal(err)
	}
	luaprotoSkip(t, d, "luaproto-version-unverified")
}

// TestLuaProtoIgnoresSynthetic pins the post-reader contract that lets the
// existing lua tests stay green: a header this reader cannot prove produces no
// skip at all, so lua.go remains the one answering the file.
func TestLuaProtoIgnoresSynthetic(t *testing.T) {
	d, err := Probe(writeTemp(t, "syn.luac", lua5x(0x54)))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range d.Skipped {
		if strings.HasPrefix(s.Reason, "luaproto") {
			t.Fatalf("unexpected skip %+v", s)
		}
	}
}

func luaprotoSkip(t *testing.T, d Digest, want string) {
	t.Helper()
	for _, s := range d.Skipped {
		if s.Reason == want {
			return
		}
	}
	t.Fatalf("skips %+v missing %q; notes %v", d.Skipped, want, d.Notes)
}
