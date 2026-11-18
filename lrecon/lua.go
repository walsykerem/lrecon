package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
)

// Lua bytecode: luac chunks (5.1-5.4) and LuaJIT dumps share the "\x1bL"
// prefix but part right after it. Both carry a fixed header whose size bytes
// describe the target build; the prototype tree behind it is not decoded.

var (
	luaMagic    = []byte("\x1bLua")
	luajitMagic = []byte("\x1bLJ")
	luaCheck    = []byte("\x19\x93\r\n\x1a\n")
)

const (
	luaHeadRead = 64
	luaDataOff  = 12 // signature, version, format, endianness, five size bytes
	luajitMask  = 0x1f
)

var luaReasons = []string{
	"lua-header-unverified", "lua-truncated", "lua-version-unverified",
	"luajit-flags-unverified", "luajit-truncated", "luajit-version-unverified",
}

func init() {
	reasonRegistry["lua"] = reasonSet(luaReasons...)
	register(reader{
		format:  "lua",
		reasons: luaReasons,
		match: func(head []byte, size int64) bool {
			return bytes.HasPrefix(head, luaMagic) || bytes.HasPrefix(head, luajitMagic)
		},
		inspect: inspectLua,
	})
}

func inspectLua(path string, d *Digest) {
	b := head(path, luaHeadRead)
	d.scanned(int64(len(b)))
	if bytes.HasPrefix(b, luajitMagic) {
		inspectLuaJIT(b, d)
		return
	}
	inspectLuac(b, d)
}

// inspectLuac reads the header every luac version writes in the same order:
// signature, version, format, endianness, then the target's word sizes. 5.1 has
// four sizes and an integral-number flag at the end; 5.2+ add LUAC_DATA at 12,
// and 5.3/5.4 append the LUAC_INT and LUAC_NUM conversion sentinels (18).
func inspectLuac(b []byte, d *Digest) {
	if len(b) < 6 {
		d.skip("lua-truncated", fmt.Sprintf("%d bytes, need the 6-byte prefix", len(b)))
		return
	}
	ver := b[4]
	if ver < 0x51 || ver > 0x54 {
		d.skip("lua-version-unverified", fmt.Sprintf("%#02x", ver))
		return
	}
	if b[5] != 0 {
		d.skip("lua-header-unverified", fmt.Sprintf("format %#02x", b[5]))
		return
	}
	if len(b) < 7 {
		d.skip("lua-truncated", fmt.Sprintf("%d bytes, need the endianness byte", len(b)))
		return
	}
	order := luaOrder(b[6])
	if order == nil {
		d.skip("lua-header-unverified", fmt.Sprintf("endianness %#02x", b[6]))
		return
	}
	endian := "big"
	if b[6] == 1 {
		endian = "little"
	}
	name := fmt.Sprintf("5.%d", ver-0x50)
	if len(b) < 12 {
		d.skip("lua-truncated", fmt.Sprintf("%d bytes, %s header needs 12", len(b), name))
		return
	}

	intSize, sizeTSize, instrSize, integerSize, numSize := b[7], b[8], b[9], b[10], b[11]
	integral := -1
	if ver == 0x51 {
		// 5.1 has no lua_Integer and no sentinels: byte 10 is the number size
		// and byte 11 is the integral-number flag, not a size.
		integerSize, numSize = 4, b[10]
		integral = int(b[11])
		if integral > 1 {
			d.skip("lua-header-unverified", fmt.Sprintf("integral flag %d", integral))
			return
		}
	} else {
		if len(b) < 18 {
			d.skip("lua-truncated", fmt.Sprintf("%d bytes, %s header needs 18", len(b), name))
			return
		}
		if !bytes.Equal(b[luaDataOff:18], luaCheck) {
			d.skip("lua-header-unverified", "LUAC_DATA mismatch")
			return
		}
		if ver >= 0x53 {
			need := 18 + int(integerSize) + int(numSize)
			if len(b) < need {
				d.skip("lua-truncated", fmt.Sprintf("%d bytes, %s header needs %d", len(b), name, need))
				return
			}
			if luaReadUint(b[18:18+int(integerSize)], order) != 0x5678 {
				d.skip("lua-header-unverified", "LUAC_INT mismatch")
				return
			}
			num := b[18+int(integerSize) : need]
			got := math.Float64frombits(luaReadUint(num, order))
			if numSize == 4 {
				got = float64(math.Float32frombits(uint32(luaReadUint(num, order))))
			}
			if got != 370.5 {
				d.skip("lua-header-unverified", "LUAC_NUM mismatch")
				return
			}
		}
	}
	if !luaSizes(intSize, sizeTSize, instrSize, integerSize, numSize) {
		d.skip("lua-header-unverified", fmt.Sprintf("sizes %d/%d/%d/%d/%d", intSize, sizeTSize, instrSize, integerSize, numSize))
		return
	}

	d.Toolchain = "lua " + name
	d.Capabilities = append(d.Capabilities,
		"lua:version="+name,
		"lua:endianness="+endian,
		fmt.Sprintf("lua:int=%d", intSize),
		fmt.Sprintf("lua:size_t=%d", sizeTSize),
		fmt.Sprintf("lua:instruction=%d", instrSize),
		fmt.Sprintf("lua:number=%d", numSize))
	if ver != 0x51 {
		d.Capabilities = append(d.Capabilities, fmt.Sprintf("lua:integer=%d", integerSize))
	}
	if integral >= 0 {
		d.Capabilities = append(d.Capabilities, fmt.Sprintf("lua:number_integral=%t", integral == 1))
	}
	d.claim(d.Toolchain, "luac-header", 0)
	d.parsed()
	deepNote(d, "decode the prototype tree to recover the function names, the string constants and the source lines; this header stops at the version and the word sizes")
}

// inspectLuaJIT reads the 5-byte dump header. Byte 3 is the dump version, which
// names the LuaJIT release (1 = 2.0, 2 = 2.1), and byte 4 is the flag byte.
func inspectLuaJIT(b []byte, d *Digest) {
	if len(b) < 5 {
		d.skip("luajit-truncated", fmt.Sprintf("%d bytes, header is 5", len(b)))
		return
	}
	var name string
	switch b[3] {
	case 1:
		name = "2.0"
	case 2:
		name = "2.1"
	default:
		d.skip("luajit-version-unverified", fmt.Sprintf("%#02x", b[3]))
		return
	}
	flags := b[4]
	if flags&^byte(luajitMask) != 0 {
		d.skip("luajit-flags-unverified", fmt.Sprintf("%#02x", flags))
		return
	}
	d.Toolchain = "luajit " + name
	d.Capabilities = append(d.Capabilities, "luajit:version="+name, fmt.Sprintf("luajit:flags=%#02x", flags))
	for _, f := range []struct {
		bit  byte
		name string
	}{
		{0x01, "be"}, {0x02, "strip"}, {0x04, "ffi"}, {0x08, "fr2"}, {0x10, "bitop"},
	} {
		if flags&f.bit != 0 {
			d.Capabilities = append(d.Capabilities, "luajit:"+f.name)
		}
	}
	d.Notes = append(d.Notes, "luajit: STRIP only drops the debug chunk (names and line info); it never changes the magic or the flag bits, so a stripped dump still names the same release")
	d.claim(d.Toolchain, "luajit-header", 0)
	d.parsed()
	deepNote(d, "read the prototype tree and the LuaJIT string table to recover the chunk names, the constants and the bytecode")
}

// luaOrder maps the header endianness byte to a byte order; 0/1 only, anything
// else is a header we cannot read.
func luaOrder(v byte) binary.ByteOrder {
	switch v {
	case 0:
		return binary.BigEndian
	case 1:
		return binary.LittleEndian
	}
	return nil
}

// luaSizes accepts the word widths Lua actually dumps: 4/8-byte ints and
// size_t, 4-byte instructions, 4/8-byte integers and numbers.
func luaSizes(intSize, sizeTSize, instrSize, integerSize, numSize byte) bool {
	return (intSize == 4 || intSize == 8) &&
		(sizeTSize == 4 || sizeTSize == 8) &&
		instrSize == 4 &&
		(integerSize == 4 || integerSize == 8) &&
		(numSize == 4 || numSize == 8)
}

// luaReadUint reads a 4- or 8-byte field in the chunk's own byte order.
func luaReadUint(b []byte, order binary.ByteOrder) uint64 {
	switch len(b) {
	case 4:
		return uint64(order.Uint32(b))
	case 8:
		return order.Uint64(b)
	}
	return 0
}
