package main

import (
	"encoding/binary"
	"strconv"
)

// Move bytecode (.mv): 4-byte magic, u32 LE version, u8 table count, then one
// 9-byte directory entry per table (kind u8, offset u32 LE, count u32 LE). The
// tables live after the directory and are addressed by absolute file offset.
// Only the header and the module-handle name are read; no bytecode is decoded.
const (
	moveHeaderSize      = 9
	moveTableEntrySize  = 9
	moveModuleHandleLen = 4 // address index u16 + name index u16
	moveVersionMin      = 5
	moveVersionMax      = 6
	moveMaxName         = 1024
	moveMaxRead         = 64 << 20 // shortcut: a table past 64 MiB reads as truncated; raise if a real module exceeds it
)

// Table kinds this reader needs; every other kind is walked and counted only.
const (
	moveTableModuleHandles = 0x1
	moveTableIdentifiers   = 0x7
)

var moveMagic = []byte{0xa1, 0x1c, 0xeb, 0x0b}

func init() {
	reasonRegistry["move"] = reasonSet(
		"move-header-truncated",
		"move-table-truncated",
		"move-table-unverified",
		"move-version-unsupported",
	)
	register(reader{
		format: "move",
		reasons: []string{
			"move-header-truncated",
			"move-table-truncated",
			"move-table-unverified",
			"move-version-unsupported",
		},
		match:   moveMatch,
		inspect: inspectMove,
	})
}

func moveMatch(head []byte, _ int64) bool {
	return len(head) >= len(moveMagic) &&
		head[0] == moveMagic[0] && head[1] == moveMagic[1] &&
		head[2] == moveMagic[2] && head[3] == moveMagic[3]
}

func inspectMove(path string, d *Digest) {
	b := head(path, moveMaxRead)
	d.scanned(int64(len(b)))
	// The magic is reported even when the version is refused: it is the one
	// fact the file proves about itself.
	d.Capabilities = append(d.Capabilities, "move:magic=a11ceb0b")
	if len(b) < moveHeaderSize {
		d.skip("move-header-truncated", strconv.Itoa(len(b))+" bytes, header is "+strconv.Itoa(moveHeaderSize))
		return
	}
	version := binary.LittleEndian.Uint32(b[4:8])
	d.Capabilities = append(d.Capabilities, "move:version="+strconv.FormatUint(uint64(version), 10))
	if version < moveVersionMin || version > moveVersionMax {
		d.skip("move-version-unsupported", "version="+strconv.FormatUint(uint64(version), 10)+
			" supported="+strconv.Itoa(moveVersionMin)+".."+strconv.Itoa(moveVersionMax))
		return
	}
	count := int(b[8])
	if count == 0 {
		d.skip("move-table-unverified", "table directory is empty")
		return
	}
	dirEnd := moveHeaderSize + count*moveTableEntrySize
	if dirEnd > len(b) {
		d.skip("move-table-truncated", strconv.Itoa(count)+" table entries need "+strconv.Itoa(dirEnd)+
			" bytes, file has "+strconv.Itoa(len(b)))
		return
	}

	var (
		handleOff, identOff     int
		handleCount, identCount uint32
		haveHandle, haveIdent   bool
	)
	for i := range count {
		e := b[moveHeaderSize+i*moveTableEntrySize : moveHeaderSize+(i+1)*moveTableEntrySize]
		kind := e[0]
		off := int(binary.LittleEndian.Uint32(e[1:5]))
		n := binary.LittleEndian.Uint32(e[5:9])
		if off > len(b) {
			d.skip("move-table-truncated", "table kind=0x"+strconv.FormatUint(uint64(kind), 16)+
				" offset="+strconv.Itoa(off)+" past "+strconv.Itoa(len(b))+" bytes")
			return
		}
		d.parsed()
		switch kind {
		case moveTableModuleHandles:
			handleOff, handleCount, haveHandle = off, n, true
		case moveTableIdentifiers:
			identOff, identCount, haveIdent = off, n, true
		}
	}

	if !haveHandle {
		d.skip("move-table-unverified", "no module-handle table (kind 0x1)")
		return
	}
	if !haveIdent {
		d.skip("move-table-unverified", "no identifiers table (kind 0x7)")
		return
	}
	if handleCount == 0 {
		d.skip("move-table-unverified", "module-handle table declares no modules")
		return
	}
	if handleOff+moveModuleHandleLen > len(b) {
		d.skip("move-table-truncated", "module-handle table offset="+strconv.Itoa(handleOff)+
			" count="+strconv.FormatUint(uint64(handleCount), 10)+" past "+strconv.Itoa(len(b))+" bytes")
		return
	}

	nameIdx := binary.LittleEndian.Uint16(b[handleOff+2 : handleOff+moveModuleHandleLen])
	name, reason, detail := moveModuleName(b, identOff, identCount, nameIdx)
	if reason != "" {
		d.skip(reason, detail)
		return
	}
	d.Mod = name
	d.Capabilities = append(d.Capabilities, "move:module="+name)
}

// moveModuleName walks the identifiers table to the wanted entry. The declared
// count is only a bound to check the index against: a hostile u32 count never
// becomes an allocation or a loop, the walk stops at the wanted entry.
func moveModuleName(b []byte, off int, count uint32, want uint16) (string, string, string) {
	if count == 0 {
		return "", "move-table-unverified", "identifiers table declares no entries"
	}
	if uint32(want) >= count {
		return "", "move-table-unverified", "name index " + strconv.Itoa(int(want)) +
			" outside " + strconv.FormatUint(uint64(count), 10) + " identifiers"
	}
	at := off
	for i := 0; i <= int(want); i++ {
		if at >= len(b) {
			return "", "move-table-truncated", "identifier " + strconv.Itoa(i) + " starts past " + strconv.Itoa(len(b)) + " bytes"
		}
		l, n := binary.Uvarint(b[at:])
		if n <= 0 {
			return "", "move-table-truncated", "identifier " + strconv.Itoa(i) + " length at " + strconv.Itoa(at) + " is not uleb128"
		}
		at += n
		if l > uint64(len(b)-at) {
			return "", "move-table-truncated", "identifier " + strconv.Itoa(i) + " length " +
				strconv.FormatUint(l, 10) + " at " + strconv.Itoa(at) + " past " + strconv.Itoa(len(b)) + " bytes"
		}
		if l == 0 || l > moveMaxName {
			return "", "move-table-unverified", "identifier " + strconv.Itoa(i) + " length " +
				strconv.FormatUint(l, 10) + " outside 1.." + strconv.Itoa(moveMaxName)
		}
		if i == int(want) {
			s := string(b[at : at+int(l)])
			if !moveIdentifier(s) {
				return "", "move-table-unverified", "module name is not a move identifier"
			}
			return s, "", ""
		}
		at += int(l)
	}
	return "", "move-table-unverified", "name index not reached"
}

// moveIdentifier is the Move rule: ASCII letters, digits and underscore.
func moveIdentifier(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' {
			continue
		}
		return false
	}
	return true
}
