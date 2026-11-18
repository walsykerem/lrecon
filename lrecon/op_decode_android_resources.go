package main

import (
	"archive/zip"
	"fmt"
)

// arscPackage is one package inside resources.arsc.
type arscPackage struct {
	ID      uint32   `json:"id"`
	Name    string   `json:"name"`
	Types   []string `json:"types,omitempty"`
	Entries int      `json:"entries"`
	Names   []string `json:"names,omitempty"`
}

func init() {
	registerOp(op{
		name:  "decode_android_resources",
		route: "L",
		needs: true,
		desc:  "parse resources.arsc out of an APK: packages, type tables and resource names",
		run: func(path string) (any, error) {
			zr, err := zip.OpenReader(path)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", path, err)
			}
			defer zr.Close()
			var arsc []byte
			found := false
			for _, f := range zr.File {
				if f.Name == "resources.arsc" {
					var ok bool
					arsc, ok = readEntry(f, 256<<20)
					if !ok {
						// The entry is there but cannot be read: saying the APK
						// "carries no resources.arsc" would be a false answer.
						return nil, fmt.Errorf("%s: resources.arsc is unreadable (corrupt zip entry or over %d bytes)", path, 256<<20)
					}
					found = true
					break
				}
			}
			if !found || len(arsc) == 0 {
				return skipf("%s carries no resources.arsc: not an APK with compiled resources", path), nil
			}
			return parseArsc(arsc)
		},
	})
}

// parseArsc walks RES_TABLE_TYPE: global string pool, then one package chunk per
// package, each with its own type/key pools and RES_TABLE_TYPE entry tables.
func parseArsc(b []byte) (any, error) {
	if len(b) < 12 || u16le(b, 0) != 0x0002 {
		return nil, fmt.Errorf("resources.arsc is not a RES_TABLE chunk")
	}
	if size := int(u32le(b, 4)); size > len(b) {
		return nil, fmt.Errorf("resources.arsc declares %d bytes, chunk has %d", size, len(b))
	}
	res := struct {
		HeaderSize int           `json:"header_size"`
		Packages   []arscPackage `json:"packages"`
	}{HeaderSize: int(u16le(b, 2))}
	off := int(u16le(b, 2))
	if off < 12 || off > len(b) {
		return nil, fmt.Errorf("header_size %d is not a RES_TABLE header", off)
	}
	// The package count at offset 8 is a hint from an untrusted file: cap the
	// preallocation and let the chunk walk below decide what is really there.
	if n := int(u32le(b, 8)); n > 0 {
		res.Packages = make([]arscPackage, 0, min(n, 64))
	}
	for off+8 <= len(b) {
		typ := u16le(b, off)
		hsize := int(u16le(b, off+2))
		size := int(u32le(b, off+4))
		if size < 8 || off+size > len(b) {
			return nil, fmt.Errorf("chunk %#x at %d declares %d bytes past the end", typ, off, size)
		}
		if typ == 0x0200 {
			pkg, err := parseArscPackage(b[off:off+size], hsize)
			if err != nil {
				return nil, err
			}
			res.Packages = append(res.Packages, pkg)
		}
		off += size
	}
	if len(res.Packages) == 0 {
		return nil, fmt.Errorf("no RES_TABLE_PACKAGE chunk")
	}
	return res, nil
}

func parseArscPackage(chunk []byte, hsize int) (arscPackage, error) {
	pkg := arscPackage{}
	if hsize < 284 || len(chunk) < hsize {
		return pkg, fmt.Errorf("package header is %d bytes, expected 284", hsize)
	}
	pkg.ID = u32le(chunk, 8)
	pkg.Name = utf16Name(chunk[12:268])
	typeStrOff := int(u32le(chunk, 268))
	keyStrOff := int(u32le(chunk, 276))
	types, ok := arscPool(chunk, typeStrOff)
	if !ok {
		return pkg, fmt.Errorf("package %q type string pool is unreadable", pkg.Name)
	}
	keys, ok := arscPool(chunk, keyStrOff)
	if !ok {
		return pkg, fmt.Errorf("package %q key string pool is unreadable", pkg.Name)
	}
	seenType := map[string]bool{}
	for off := hsize; off+8 <= len(chunk); {
		typ := u16le(chunk, off)
		hs := int(u16le(chunk, off+2))
		size := int(u32le(chunk, off+4))
		if size < 8 || off+size > len(chunk) {
			return pkg, fmt.Errorf("package %q: chunk %#x at %d declares %d bytes past the package", pkg.Name, typ, off, size)
		}
		if typ == 0x0202 {
			if hs >= 12 {
				if id := int(chunk[off+8]); id > 0 && id <= len(types) {
					name := types[id-1]
					if !seenType[name] {
						seenType[name] = true
						pkg.Types = append(pkg.Types, name)
					}
				}
			}
		}
		if typ == 0x0201 {
			entries, names, err := arscTypeEntries(chunk[off:off+size], hs, types, keys)
			if err != nil {
				return pkg, fmt.Errorf("package %q: %w", pkg.Name, err)
			}
			pkg.Entries += entries
			pkg.Names = append(pkg.Names, names...)
			if len(pkg.Names) > 32 {
				pkg.Names = pkg.Names[:32]
			}
		}
		off += size
	}
	return pkg, nil
}

// arscTypeEntries reads one RES_TABLE_TYPE chunk: entryCount offsets, then each
// entry's key index and value size. Names come back as "type/name".
//
// The offset table is not always u32. Android 14+ writes OFFSET16 (u16, in
// 4-byte units) and SPARSE tables (index/offset pairs); a compact entry keeps
// its key index in the first 16 bits instead of the usual u32. Ignoring those
// flags is what made a real Settings.apk report "entry 0 is past the chunk".
func arscTypeEntries(chunk []byte, hs int, types, keys []string) (int, []string, error) {
	if hs < 20 || hs > len(chunk) {
		return 0, nil, fmt.Errorf("type chunk header is %d bytes", hs)
	}
	id := int(chunk[8])
	flags := chunk[9]
	n := int(u32le(chunk, 12))
	entriesStart := int(u32le(chunk, 16))
	if n < 0 || entriesStart < 0 || entriesStart > len(chunk) {
		return 0, nil, fmt.Errorf("type %d entries start at %d, outside the %d-byte chunk", id, entriesStart, len(chunk))
	}
	// Sparse entries are (index, offset/4) pairs. OFFSET16 entries are a plain
	// u16 offset/4 table; the legacy table is u32 offsets.
	stride := 4
	if flags&0x02 != 0 && flags&0x01 == 0 {
		stride = 2
	}
	if hs+stride*n > len(chunk) {
		return 0, nil, fmt.Errorf("type %d declares %d entries past the %d-byte offset table", id, n, len(chunk)-hs)
	}
	typeName := ""
	if id > 0 && id <= len(types) {
		typeName = types[id-1]
	}
	count := 0
	var names []string
	for i := range n {
		var entry, rel int
		switch {
		case flags&0x01 != 0:
			entry = int(u16le(chunk, hs+4*i))
			rel = int(u16le(chunk, hs+4*i+2)) * 4
		case flags&0x02 != 0:
			entry = i
			rel = int(u16le(chunk, hs+2*i)) * 4
			if rel == 0xFFFF*4 { // no entry at this index
				continue
			}
		default:
			entry = i
			raw := u32le(chunk, hs+4*i)
			if raw == 0xFFFFFFFF { // no entry at this index
				continue
			}
			rel = int(raw)
		}
		p := entriesStart + rel
		if rel < 0 || p < 0 || p+8 > len(chunk) {
			return 0, nil, fmt.Errorf("type %d entry %d (index %d) at %d is past the %d-byte chunk", id, i, entry, p, len(chunk))
		}
		count++
		eflags := u16le(chunk, p+2)
		keyIdx := int(u32le(chunk, p+4))
		if eflags&0x0008 != 0 {
			// Compact entry: the 16-bit key index takes the place of the
			// size field, and the u32 holds the value data instead.
			keyIdx = int(u16le(chunk, p))
		}
		if keyIdx < 0 || keyIdx >= len(keys) {
			continue
		}
		name := keys[keyIdx]
		if typeName != "" {
			name = typeName + "/" + name
		}
		names = append(names, name)
	}
	return count, names, nil
}

func arscPool(chunk []byte, off int) ([]string, bool) {
	if off <= 0 || off+8 > len(chunk) || u16le(chunk, off) != 0x0001 {
		return nil, false
	}
	size := int(u32le(chunk, off+4))
	if size < 8 || off+size > len(chunk) {
		return nil, false
	}
	return axmlStrings(chunk[off:off+size], int(u16le(chunk, off+2)))
}

// utf16Name decodes the fixed 128-unit UTF-16 package name.
func utf16Name(b []byte) string {
	var runes []rune
	for i := 0; i+1 < len(b); i += 2 {
		u := u16le(b, i)
		if u == 0 {
			break
		}
		runes = append(runes, rune(u))
	}
	return string(runes)
}
