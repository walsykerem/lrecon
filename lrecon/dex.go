package main

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// dexMapHeaderItem is map_list type 0x0000: the one item the cross-check pins
// at offset 0, so a map that does not describe this file is visible.
const dexMapHeaderItem = 0x0000

// dexMapTypeNames labels the map_list type codes a dex actually uses; an
// unknown code is printed as its hex value.
var dexMapTypeNames = map[int]string{
	0x0000: "header",
	0x0001: "string_id",
	0x0002: "type_id",
	0x0003: "proto_id",
	0x0004: "field_id",
	0x0005: "method_id",
	0x0006: "class_def",
	0x0007: "call_site_id",
	0x0008: "method_handle",
	0x1000: "map_list",
	0x1001: "type_list",
	0x1002: "annotation_set_ref_list",
	0x1003: "annotation_set_item",
	0x2000: "class_data",
	0x2001: "code",
	0x2002: "string_data",
	0x2003: "debug_info",
	0x2004: "annotation",
	0x2005: "encoded_array",
	0x2006: "annotations_directory",
}

// dexMapWitness checks the map_list, the second witness the header numbers
// cannot fake: its item offsets are absolute, so a copy whose checksum and
// file_size were both recomputed still fails when the map is out of file or
// disagrees about where the header item lives. On success it notes the item
// count and the type codes in the order they appear.
func dexMapWitness(b []byte, size, off int, d *Digest) bool {
	if off == 0 {
		d.Notes = append(d.Notes, "dex: map_list absent (map_off=0)")
		return true
	}
	if off < dexHeaderSize || off+4 > size {
		return false
	}
	n := int(binary.LittleEndian.Uint32(b[off:]))
	if n <= 0 || n > dexMaxMapItems || !dexIn(size, off+4, n, 12) {
		return false
	}
	types := make([]string, n)
	prev, headers := 0, 0
	for i := range n {
		at := off + 4 + 12*i
		typ := int(binary.LittleEndian.Uint16(b[at:]))
		itemOff := int(binary.LittleEndian.Uint32(b[at+8:]))
		// Items are laid out in offset order; an offset that goes backwards or
		// past file_size is a map for a different file.
		if itemOff >= size || itemOff < prev {
			return false
		}
		prev = itemOff
		if typ == dexMapHeaderItem {
			headers++
			if itemOff != 0 {
				return false
			}
		}
		name, ok := dexMapTypeNames[typ]
		if !ok {
			name = fmt.Sprintf("0x%04x", typ)
		}
		types[i] = name
	}
	if headers != 1 {
		return false
	}
	d.Notes = append(d.Notes, fmt.Sprintf("dex: map_list items=%d types=%s", n, strings.Join(types, ",")))
	return true
}

// dexStringMarkers name a packer from a marker its own dex string table holds.
// Every marker is a string a stock build never ships.
var dexStringMarkers = []struct{ marker, packer string }{
	{"com/tencent/StubShell", "Tencent StubShell"},
	{"com/qihoo/util", "Qihoo 360 Jiagu"},
	{"com/stub/StubApp", "Qihoo 360 Jiagu"},
	{"libjiagu", "Qihoo 360 Jiagu"},
	{"com/baidu/protector", "Baidu Protector"},
	{"libbaiduprotect", "Baidu Protector"},
	{"libDexHelper", "Bangcle DexHelper"},
	{"libmobisec", "Alibaba Mobisec"},
	{"libsgmain", "Alibaba SecurityGuard"},
	{"libnesec", "NetEase Yidun"},
	{"alibaba/j/,", "Alibaba"},
}

// dexPackerMarker notes each packer whose marker appears in the string table,
// once, at the data offset of the first string that carries it. No marker, no
// note: the packer is never inferred from the file shape. A string that will
// not decode is not evidence and raises no refusal.
func (r dexReader) dexPackerMarker() {
	seen := map[string]bool{}
	budget := dexMarkerScanBytes
	for i := 0; i < r.strSize && i < dexMarkerScanStrings && budget > 0; i++ {
		s, ok := r.str(uint32(i))
		if !ok {
			continue
		}
		budget -= len(s) + 1
		p := int(binary.LittleEndian.Uint32(r.b[r.strOff+4*i:]))
		for _, m := range dexStringMarkers {
			if seen[m.packer] || !strings.Contains(s, m.marker) {
				continue
			}
			seen[m.packer] = true
			r.d.Notes = append(r.d.Notes, fmt.Sprintf("dex: packer claim %q (string marker %q at 0x%x)", m.packer, m.marker, p))
		}
	}
}

// archivePackerLibs name a packer from a native library path a stock build
// never carries. The key is matched against the lowercased entry name.
var archivePackerLibs = []struct{ key, packer string }{
	{"libjiagu", "Qihoo 360 Jiagu"},
	{"libdexhelper", "Bangcle DexHelper"},
	{"libbaiduprotect", "Baidu Protector"},
	{"libmobisec", "Alibaba Mobisec"},
	{"libsgmain", "Alibaba SecurityGuard"},
	{"libnesec", "NetEase Yidun"},
}

// archivePackerClaim appends one claim per packer, naming the zip entry that
// carried the evidence; a second entry for the same packer adds nothing.
func archivePackerClaim(hits []string, seen map[string]bool, low, name string) []string {
	for _, m := range archivePackerLibs {
		if seen[m.packer] || !strings.Contains(low, m.key) {
			continue
		}
		seen[m.packer] = true
		hits = append(hits, fmt.Sprintf("%q (entry %s)", m.packer, name))
	}
	return hits
}

// dexStandardName reports whether a zip entry is the classes.dex/classesN.dex
// name a stock Android build uses; anything else is a payload someone hid.
func dexStandardName(low string) bool {
	base, ok := strings.CutSuffix(low, ".dex")
	if !ok || !strings.HasPrefix(base, "classes") {
		return false
	}
	rest := base[len("classes"):]
	if rest == "" {
		return true
	}
	for _, c := range rest {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
