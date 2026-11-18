package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"regexp"
	"unicode/utf16"
)

// --- SQLite ---

// inspectSQLite reads the 100-byte header facts: page size, the library
// version that last wrote the file and whether a write-ahead log is in play.
func inspectSQLite(path string, d *Digest) {
	hdr := head(path, 100)
	if len(hdr) < 20 {
		d.Notes = append(d.Notes, "sqlite: header truncated")
		return
	}
	ps := int(binary.BigEndian.Uint16(hdr[16:18]))
	if ps == 1 {
		ps = 65536
	}
	d.SQLitePageSize = ps
	if len(hdr) >= 100 {
		if v := binary.BigEndian.Uint32(hdr[96:100]); v > 0 {
			d.SQLiteVersion = fmt.Sprintf("%d.%d.%d", v/1000000, (v/1000)%1000, v%1000)
		}
	}
	if len(hdr) > 18 && hdr[18] == 2 {
		d.SQLiteWAL = true
	}
	if _, err := os.Stat(path + "-wal"); err == nil {
		d.SQLiteWAL = true
	}
	deepNote(d, "open the database read-only together with its write-ahead log sidecar to recover the schema, the row contents and the freelist pages")
}

// --- property lists ---

const maxPlistBytes = 16 << 20

var xmlPlistKey = regexp.MustCompile(`(?s)<key>\s*([^<]{1,200}?)\s*</key>`)

// plistKeyCap bounds the property names a digest reports.
const plistKeyCap = 64

// plistValues is the fixed allowlist of keys whose string value is worth
// printing next to the key: the bundle identity and the version numbers.
var plistValues = map[string]bool{
	"CFBundleIdentifier":         true,
	"CFBundleName":               true,
	"CFBundleDisplayName":        true,
	"CFBundleExecutable":         true,
	"CFBundleShortVersionString": true,
	"CFBundleVersion":            true,
	"LSMinimumSystemVersion":     true,
	"MinimumOSVersion":           true,
	"DTSDKName":                  true,
}

// inspectPlist reports the property names of a property list, XML or binary.
func inspectPlist(path string, d *Digest) {
	b := head(path, maxPlistBytes)
	if bytes.HasPrefix(b, []byte("bplist00")) {
		d.PlistKeys = bplistKeys(b, d)
	} else {
		d.PlistKeys = xmlPlistKeys(b, d)
	}
	deepNote(d, "walk the property list object tree to recover the bundle identity, the version numbers, the url schemes and the entitlement keys")
}

func xmlPlistKeys(b []byte, d *Digest) []string {
	// Match the bytes, not a string copy: a 16 MiB plist is otherwise copied
	// once before the scan, and the submatch indices are the same either way.
	// one match past the cap is enough to know the list was cut and keeps the
	// scan bounded on a hostile file
	m := xmlPlistKey.FindAllSubmatchIndex(b, plistKeyCap+1)
	seen := make(map[string]bool, len(m))
	out := make([]string, 0, len(m))
	for _, g := range m {
		k := string(bytes.TrimSpace(b[g[2]:g[3]]))
		if k == "" || seen[k] {
			continue
		}
		seen[k] = true
		if plistValues[k] {
			if v, ok := xmlPlistString(b, g[1]); ok {
				out = append(out, k+" = "+v)
				continue
			}
		}
		out = append(out, k)
	}
	return capped(d, "plist keys", out, plistKeyCap)
}

// xmlPlistString reads the <string> element that directly follows a key.
func xmlPlistString(b []byte, from int) (string, bool) {
	i := bytes.IndexByte(b[from:], '<')
	if i < 0 {
		return "", false
	}
	rest := b[from+i:]
	if !bytes.HasPrefix(rest, []byte("<string>")) {
		return "", false
	}
	rest = rest[len("<string>"):]
	v, _, ok := bytes.Cut(rest, []byte("</string>"))
	if !ok {
		return "", false
	}
	v = bytes.TrimSpace(v)
	if len(v) == 0 || len(v) > 200 {
		return "", false
	}
	return string(v), true
}

// bplistKeys returns the dictionary keys of a binary property list. The
// trailer at the end of the file points at the object table; dictionaries
// (type 0xD) hold the keys as object references, each followed by its value.
func bplistKeys(b []byte, d *Digest) []string {
	if len(b) < 40 {
		return nil
	}
	tr := b[len(b)-32:]
	offSize := int(tr[6])
	refSize := int(tr[7])
	numObjects := int(binary.BigEndian.Uint64(tr[8:16]))
	tableOff := int(binary.BigEndian.Uint64(tr[24:32]))
	if offSize < 1 || offSize > 8 || refSize < 1 || refSize > 8 {
		return nil
	}
	if numObjects <= 0 || numObjects > 1<<20 || tableOff < 8 || tableOff+numObjects*offSize > len(b) {
		return nil
	}
	offsets := make([]int, numObjects)
	for i := range numObjects {
		o := tableOff + i*offSize
		offsets[i] = int(readUintBE(b[o : o+offSize]))
	}
	var keys []string
	// The XML walk reports each property name once, so the binary walk does too:
	// the same key can repeat across the dictionaries in one plist.
	seen := make(map[string]bool)
	for _, off := range offsets {
		if off <= 0 || off >= len(b) || b[off]>>4 != 0xD {
			continue
		}
		n, doff, ok := bplistCount(b, off, b[off]&0x0F)
		if !ok || n <= 0 || n > 1<<16 {
			continue
		}
		if doff+2*n*refSize > len(b) {
			continue
		}
		for i := range n {
			// a dictionary stores all key refs first, then all value refs
			p := doff + i*refSize
			// object references are zero-based indices into the offset table
			ref := int(readUintBE(b[p : p+refSize]))
			if ref < 0 || ref >= len(offsets) {
				continue
			}
			k, ok := bplistString(b, offsets[ref])
			if !ok || seen[k] {
				continue
			}
			seen[k] = true
			if plistValues[k] {
				if v, ok := bplistPairValue(b, offsets, doff+(n+i)*refSize, refSize); ok {
					k += " = " + v
				}
			}
			keys = append(keys, k)
		}
	}
	return capped(d, "plist keys", keys, plistKeyCap)
}

// bplistPairValue decodes the string value stored after a dictionary key.
// Non-string values (bools, ints, arrays, dicts) stay unreported.
func bplistPairValue(b []byte, offsets []int, p, refSize int) (string, bool) {
	if p < 0 || p+refSize > len(b) {
		return "", false
	}
	ref := int(readUintBE(b[p : p+refSize]))
	if ref < 0 || ref >= len(offsets) {
		return "", false
	}
	s, ok := bplistString(b, offsets[ref])
	if !ok || s == "" || len(s) > 200 {
		return "", false
	}
	return s, true
}

// bplistCount reads the length of the object at off and returns where its
// payload starts. A length of 0xF means the real count lives in the int
// object that follows the marker byte.
func bplistCount(b []byte, off int, info byte) (count, dataOff int, ok bool) {
	if info != 0x0F {
		return int(info), off + 1, true
	}
	if off+2 > len(b) {
		return 0, 0, false
	}
	m := b[off+1]
	if m>>4 != 0x1 {
		return 0, 0, false
	}
	size := 1 << (m & 0x0F)
	if size > 8 || off+2+size > len(b) {
		return 0, 0, false
	}
	return int(readUintBE(b[off+2 : off+2+size])), off + 2 + size, true
}

// bplistString decodes an ASCII or UTF-16 string object.
func bplistString(b []byte, off int) (string, bool) {
	if off <= 0 || off >= len(b) {
		return "", false
	}
	m := b[off]
	n, doff, ok := bplistCount(b, off, m&0x0F)
	// bplistCount narrows a 64-bit length to int: a hostile count is negative on
	// this platform, so the length is checked before it reaches either slice.
	if !ok || n < 0 || n > len(b) {
		return "", false
	}
	switch m >> 4 {
	case 0x5: // ascii
		if doff+n > len(b) {
			return "", false
		}
		return string(b[doff : doff+n]), true
	case 0x6: // utf-16be
		if doff+2*n > len(b) {
			return "", false
		}
		u := make([]uint16, n)
		for i := range u {
			u[i] = binary.BigEndian.Uint16(b[doff+2*i:])
		}
		return string(utf16.Decode(u)), true
	}
	return "", false
}

func readUintBE(b []byte) uint64 {
	var v uint64
	for _, c := range b {
		v = v<<8 | uint64(c)
	}
	return v
}

// isXMLPlist reports an XML property list. The document must start with an
// xml prologue, a doctype or the plist element itself.
func isXMLPlist(h []byte) bool {
	h = bytes.TrimLeft(h, " \t\r\n")
	if !bytes.Contains(h, []byte("<plist")) {
		return false
	}
	return bytes.HasPrefix(h, []byte("<?xml")) ||
		bytes.HasPrefix(h, []byte("<!DOCTYPE")) ||
		bytes.HasPrefix(h, []byte("<plist"))
}

// isCodeSignature reports a code-signature blob: magic 0xFADE0Cxx, big-endian.
func isCodeSignature(h []byte) bool {
	if len(h) < 4 {
		return false
	}
	m := binary.BigEndian.Uint32(h[:4])
	return m >= 0xfade0c00 && m <= 0xfade0cff
}
