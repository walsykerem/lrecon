package main

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"encoding/xml"
	"fmt"
	"hash/adler32"
	"io"
	"os"
	pathpkg "path"
	"path/filepath"
	"strconv"
	"strings"
	"unicode/utf16"
)

// owned by agent C: mobile / app archives — apk, aab, dex, ipa

const axmlMagic = 0x00080003 // AndroidManifest.xml compiled ("binary") XML header

// Android DEX (R1 in notes-r.md): the header, the string pool and the
// class_data name chain only. Bytecode is never decoded and the SHA-1 signature
// is never recomputed, so a tampered-but-loadable file still reads as valid.
const (
	dexHeaderSize = 0x70
	dexHeaderV41  = 0x78 // v041 adds container_size/header_offset at 0x70/0x74
	dexEndianTag  = 0x12345678
	dexNoIndex    = 0xFFFFFFFF
	dexMaxIDs     = 0xFFFF // ART CheckSizeLimit on type and proto ids
	dexMaxClasses = 256
	dexMaxMethods = 10

	// Compact dex ("cdex001\0", version 001): same first 0x70 bytes, then six
	// feature/debug/owned-data fields, so the header is 0x88.
	dexCompactMagic   = "cdex001"
	dexCompactVersion = "001"
	dexHeaderCompact  = 0x88

	dexMaxMapItems = 256 // a shipped map_list carries ~20 items
	// dexMarkerScan* bound the string scan: an inside-dex marker past these
	// limits is missed rather than a guess being made.
	dexMarkerScanStrings = 1 << 16
	dexMarkerScanBytes   = 16 << 20
)

// dexVersions whitelists the versions ART has shipped; 036 is refused.
var dexVersions = map[string]bool{"035": true, "037": true, "038": true, "039": true, "040": true, "041": true}

// dexReasons is the closed set registered with the reader below.
var dexReasons = []string{
	"dex-truncated-header",
	"dex-unsupported-magic",
	"dex-bad-header-size",
	"dex-bad-endian",
	"dex-checksum-mismatch",
	"dex-bad-map",
	"dex-oob-section",
	"dex-too-many-ids",
	"dex-bad-string",
	"dex-truncated-class",
}

func init() {
	// detect.go's magic switch claims dex before dispatch runs, so this entry is
	// here to carry the closed reason set; inspectDex applies it itself.
	register(reader{format: "dex", reasons: dexReasons, match: func(h []byte, _ int64) bool { return isDex(h) }, inspect: inspectDex})
}

// isDex matches both magics: "dex\n" for a standard file and "cdex001" for a
// compact dex, which keeps the header layout but uses owned-data offsets.
func isDex(h []byte) bool {
	return bytes.HasPrefix(h, []byte("dex\n")) || bytes.HasPrefix(h, []byte(dexCompactMagic))
}

// isBinaryXML also checks the declared file size, so a random 4-byte match stays "unknown".
func isBinaryXML(h []byte) bool {
	if len(h) < 8 {
		return false
	}
	size := binary.LittleEndian.Uint32(h[4:8])
	return binary.LittleEndian.Uint32(h) == axmlMagic && size > 8 && size <= 64<<20
}

func mobileCap(d *Digest, cap string) {
	if !containsStr(d.Capabilities, cap) {
		d.Capabilities = append(d.Capabilities, cap)
	}
}

// inspectDex verifies the header, then dereferences the class and method names
// out of the string pool. Bytecode bodies, fields and annotations stay unread.
func inspectDex(path string, d *Digest) {
	if takeActiveReasons(activeReasonsFor("dex", dexReasons)) { // claimed by detect.go, not by dispatch: apply the set here
		defer clearActiveReasons()
	}
	mobileCap(d, "android")
	deepNote(d, "read the class and method names from the string pool; the bytecode bodies, the field names and the annotations are still unread")
	dexNames(path, d)
}

// dexNames parses the header, the string pool and the class_data name chain and
// reports false when a header-level check refused the file.
func dexNames(path string, d *Digest) bool {
	b, err := opRead(path, opMaxFile)
	if err != nil {
		d.Notes = append(d.Notes, "dex: open: "+err.Error())
		return false
	}
	d.scanned(int64(len(b)))
	if len(b) < dexHeaderSize {
		d.Notes = append(d.Notes, "dex: truncated header")
		d.skip("dex-truncated-header", fmt.Sprintf("%d bytes", len(b)))
		return false
	}
	le := binary.LittleEndian
	u32 := func(off int) uint32 { return le.Uint32(b[off:]) }
	compact := bytes.HasPrefix(b, []byte(dexCompactMagic))
	ver := strings.TrimRight(string(b[4:7]), "\x00")
	d.Notes = append(d.Notes, "dex: version "+ver)
	d.Notes = append(d.Notes, fmt.Sprintf("dex: strings=%d types=%d classes=%d", u32(0x38), u32(0x40), u32(0x60)))
	if compact {
		d.Notes = append(d.Notes, "dex: compact dex header ("+dexCompactMagic+")")
	}
	if (compact && ver != dexCompactVersion) || (!compact && !dexVersions[ver]) {
		d.skip("dex-unsupported-magic", "version "+ver)
		return false
	}
	mobileCap(d, "dex-"+ver)
	if compact {
		mobileCap(d, "compact-dex")
	}
	hsize := int(u32(0x24))
	okHdr := hsize == dexHeaderSize || (ver == "041" && hsize == dexHeaderV41)
	if compact {
		okHdr = hsize == dexHeaderCompact
	}
	if !okHdr {
		d.skip("dex-bad-header-size", fmt.Sprintf("header_size=0x%x", hsize))
		return false
	}
	if len(b) < hsize {
		d.skip("dex-truncated-header", fmt.Sprintf("%d bytes < header %d", len(b), hsize))
		return false
	}
	if hsize == dexHeaderV41 { // v041 only: both are 0 for a bare .dex file
		d.Notes = append(d.Notes, fmt.Sprintf("dex: container_size=%d header_offset=%d", u32(0x70), u32(0x74)))
	}
	if u32(0x28) != dexEndianTag {
		d.skip("dex-bad-endian", fmt.Sprintf("endian_tag=0x%x", u32(0x28)))
		return false
	}
	size := int(u32(0x20))
	if size < hsize || size > len(b) {
		d.skip("dex-oob-section", fmt.Sprintf("file_size=%d file=%d", size, len(b)))
		return false
	}
	if got := adler32.Checksum(b[0x0C:size]); got != u32(0x08) {
		d.skip("dex-checksum-mismatch", fmt.Sprintf("header=0x%08x computed=0x%08x", u32(0x08), got))
		return false
	}
	d.Notes = append(d.Notes,
		"dex: checksum adler32 ok",
		"dex: signature_verified:false (SHA-1 signature at 0x0C is not recomputed)")
	if !dexMapWitness(b, size, int(u32(0x34)), d) {
		d.skip("dex-bad-map", fmt.Sprintf("map_off=%d file_size=%d", u32(0x34), size))
		return false
	}
	r := dexReader{
		b: b, end: size, d: d, strs: map[uint32]string{},
		strSize: int(u32(0x38)), strOff: int(u32(0x3C)),
		typSize: int(u32(0x40)), typOff: int(u32(0x44)),
		metSize: int(u32(0x58)), metOff: int(u32(0x5C)),
	}
	if r.typSize > dexMaxIDs || int(u32(0x48)) > dexMaxIDs {
		d.skip("dex-too-many-ids", fmt.Sprintf("type_ids=%d proto_ids=%d", r.typSize, u32(0x48)))
		return false
	}
	for _, t := range []struct {
		name         string
		off, n, elem int
	}{
		{"string_ids", r.strOff, r.strSize, 4},
		{"type_ids", r.typOff, r.typSize, 4},
		{"method_ids", r.metOff, r.metSize, 8},
	} {
		if !dexIn(r.end, t.off, t.n, t.elem) {
			d.skip("dex-oob-section", fmt.Sprintf("%s %d@%d past %d", t.name, t.n, t.off, r.end))
			return false
		}
	}
	// v041 lets the data section run to EOF, so the bound is file_size, never
	// data_off+data_size: that pair truncates the string pool on v041.
	if !dexIn(r.end, int(u32(0x64)), int(u32(0x60)), 32) {
		d.skip("dex-oob-section", fmt.Sprintf("class_defs %d@%d past %d", u32(0x60), u32(0x64), r.end))
		return false
	}
	r.clsOff = int(u32(0x64))
	if compact {
		// Compact dex keeps class_data and code offsets relative to the owned
		// data region, not the file, so dereferencing them here would read the
		// wrong bytes; the header and the map_list are the honest part.
		d.Notes = append(d.Notes, "dex: compact dex: class_data uses owned-data offsets, class names not decoded")
		d.unparsed()
		return true
	}
	r.dexPackerMarker()
	r.parseClasses(int(u32(0x60)))
	return true
}

// dexIn reports whether n entries of elem bytes at off stay inside end.
func dexIn(end, off, n, elem int) bool {
	return off >= 0 && n >= 0 && elem > 0 && off <= end && n <= (end-off)/elem
}

// dexReader carries the tables one file needs while names are dereferenced.
type dexReader struct {
	b               []byte
	end             int // bound for every read: the declared file_size
	d               *Digest
	strs            map[uint32]string
	strSize, strOff int
	typSize, typOff int
	metSize, metOff int
	clsOff          int
}

// parseClasses walks class_defs and decodes one name line per class.
func (r dexReader) parseClasses(n int) {
	le := binary.LittleEndian
	capped := false
	if n > dexMaxClasses {
		n, capped = dexMaxClasses, true
	}
	for i := 0; i < n; i++ {
		at := r.clsOff + 32*i
		classIdx := le.Uint32(r.b[at:])
		if classIdx == dexNoIndex {
			r.d.unparsed()
			continue
		}
		desc, ok := r.typeName(classIdx)
		if !ok {
			r.d.skip("dex-bad-string", fmt.Sprintf("class_def %d type %d", i, classIdx))
			continue
		}
		line := "dex: class " + desc
		if s := le.Uint32(r.b[at+8:]); s != dexNoIndex {
			super, ok := r.typeName(s)
			if !ok {
				r.d.skip("dex-bad-string", fmt.Sprintf("class_def %d super %d", i, s))
				continue
			}
			line += " super " + super
		}
		names, more, ok := r.classMethods(int(le.Uint32(r.b[at+24:])))
		if !ok {
			r.d.skip("dex-truncated-class", fmt.Sprintf("class_def %d class_data@%d", i, le.Uint32(r.b[at+24:])))
			continue
		}
		capped = capped || more
		if len(names) == 0 {
			r.d.Notes = append(r.d.Notes, line+" methods 0")
		} else {
			r.d.Notes = append(r.d.Notes, fmt.Sprintf("%s methods %d: %s", line, len(names), strings.Join(names, ", ")))
		}
		r.d.parsed()
	}
	if capped {
		r.d.Notes = append(r.d.Notes, fmt.Sprintf("dex: capped at %d classes and %d methods per class", dexMaxClasses, dexMaxMethods))
	}
}

// classMethods reads class_data_item: four ULEB128 counts, the field lists, then
// the direct and virtual method lists whose cumulative diffs index method_ids.
func (r dexReader) classMethods(off int) (names []string, capped, ok bool) {
	if off == 0 {
		return nil, false, true
	}
	if off < 0 || off >= r.end {
		return nil, false, false
	}
	var counts [4]int
	p := off
	for i := range counts {
		v, n, good := dexULEB(r.b, p, r.end)
		if !good {
			return nil, false, false
		}
		counts[i], p = v, p+n
		if v > r.end { // every record costs at least 2 bytes, so this cannot fit
			return nil, false, false
		}
	}
	for _, c := range counts[:2] { // static, then instance fields
		for range c {
			for range 2 { // field_idx_diff, access_flags
				_, n, good := dexULEB(r.b, p, r.end)
				if !good {
					return nil, false, false
				}
				p += n
			}
		}
	}
	for _, c := range counts[2:] { // direct, then virtual methods
		idx := 0
		for range c {
			diff, n, good := dexULEB(r.b, p, r.end)
			if !good {
				return nil, false, false
			}
			p += n
			for range 2 { // access_flags, code_off
				_, n, good := dexULEB(r.b, p, r.end)
				if !good {
					return nil, false, false
				}
				p += n
			}
			idx += diff
			if len(names) >= dexMaxMethods {
				capped = true
				continue
			}
			name, good := r.methodName(idx)
			if !good {
				return nil, capped, false
			}
			names = append(names, name)
		}
	}
	return names, capped, true
}

// typeName is the 2-deref hop: type_id -> descriptor string.
func (r dexReader) typeName(idx uint32) (string, bool) {
	if int(idx) >= r.typSize {
		return "", false
	}
	return r.str(binary.LittleEndian.Uint32(r.b[r.typOff+4*int(idx):]))
}

// methodName is method_id -> name string.
func (r dexReader) methodName(idx int) (string, bool) {
	if idx < 0 || idx >= r.metSize {
		return "", false
	}
	return r.str(binary.LittleEndian.Uint32(r.b[r.metOff+8*idx+4:]))
}

// str is the last deref: string_id -> ULEB128 length + MUTF-8 bytes. The length
// is in UTF-16 units, so it is only used as a check, never as a byte count.
func (r dexReader) str(idx uint32) (string, bool) {
	if s, ok := r.strs[idx]; ok {
		return s, true
	}
	if int(idx) >= r.strSize {
		return "", false
	}
	p := int(binary.LittleEndian.Uint32(r.b[r.strOff+4*int(idx):]))
	units, n, ok := dexULEB(r.b, p, r.end)
	if !ok {
		return "", false
	}
	s, got, ok := dexMUTF8(r.b, p+n, r.end)
	if !ok || got != units {
		return "", false
	}
	r.strs[idx] = s
	return s, true
}

func dexULEB(b []byte, off, end int) (val, n int, ok bool) {
	for i := range 5 {
		if off+i >= end {
			return 0, 0, false
		}
		c := b[off+i]
		val |= int(c&0x7F) << (7 * i)
		if c&0x80 == 0 {
			return val, i + 1, true
		}
	}
	return 0, 0, false
}

// dexMUTF8 decodes one NUL-terminated MUTF-8 string and returns it with its
// UTF-16 unit count. A supplementary character is the CESU-8 6-byte form: two
// 3-byte surrogates, which utf16.Decode rejoins. A 4-byte lead is invalid here.
func dexMUTF8(b []byte, off, end int) (string, int, bool) {
	var units []uint16
	for off < end {
		c := b[off]
		switch {
		case c == 0:
			return string(utf16.Decode(units)), len(units), true
		case c < 0x80:
			units = append(units, uint16(c))
			off++
		case c&0xE0 == 0xC0:
			if off+1 >= end || b[off+1]&0xC0 != 0x80 {
				return "", 0, false
			}
			units = append(units, uint16(c&0x1F)<<6|uint16(b[off+1]&0x3F))
			off += 2
		case c&0xF0 == 0xE0:
			if off+2 >= end || b[off+1]&0xC0 != 0x80 || b[off+2]&0xC0 != 0x80 {
				return "", 0, false
			}
			units = append(units, uint16(c&0x0F)<<12|uint16(b[off+1]&0x3F)<<6|uint16(b[off+2]&0x3F))
			off += 3
		default:
			return "", 0, false
		}
	}
	return "", 0, false
}

// inspectArchive classifies a zip as apk/aab/ipa and reports it. It returns false
// for any other zip so the caller can keep the plain "zip" kind.
func inspectArchive(path string, d *Digest) bool {
	zr, err := zip.OpenReader(path)
	if err != nil {
		d.Notes = append(d.Notes, "zip: "+err.Error())
		return false
	}
	defer zr.Close()

	var (
		entries, dex, frameworks int
		arscSize                 int64
		flutter, hermes          bool
		binaryManifest, xmlMan   bool
		infoPlist, provision     bool
		payloadApp               bool
		fw                       = map[string]bool{}
		bundleConfig             bool
		infoPlistBody            []byte
		manifestBin              []byte
		manifestXML              []byte
		oddDex, packerHits       []string
		packerSeen               = map[string]bool{}
	)
	for _, f := range zr.File {
		name := f.Name
		if strings.HasSuffix(name, "/") {
			continue
		}
		entries++
		low := strings.ToLower(name)
		switch {
		case strings.HasPrefix(low, "classes") && strings.HasSuffix(low, ".dex"):
			dex++
		case low == "resources.arsc":
			arscSize = int64(f.UncompressedSize64)
		case pathpkg.Base(low) == "androidmanifest.xml":
			xmlMan = true
			if body, ok := readEntry(f, 8<<20); ok {
				if isBinaryXML(body) {
					binaryManifest = true
					manifestBin = body
				} else {
					manifestXML = body
				}
			}
		case strings.HasSuffix(low, "libflutter.so"):
			flutter = true
		case strings.HasSuffix(low, "libhermes.so"):
			hermes = true
		case low == "bundleconfig.pb":
			bundleConfig = true
		}
		if strings.HasSuffix(low, ".dex") && !dexStandardName(low) {
			oddDex = append(oddDex, name)
		}
		packerHits = archivePackerClaim(packerHits, packerSeen, low, name)
		if strings.HasPrefix(low, "payload/") {
			payloadApp = true
		}
		if strings.HasPrefix(low, "payload/") && strings.HasSuffix(low, ".app/info.plist") {
			infoPlist = true
			if body, ok := readEntry(f, 1<<20); ok {
				infoPlistBody = body
			}
		}
		if strings.HasPrefix(low, "payload/") && strings.HasSuffix(low, ".app/embedded.mobileprovision") {
			provision = true
		}
		if _, rest, ok := strings.Cut(low, ".app/frameworks/"); ok {
			if fwName, _, ok := strings.Cut(rest, "/"); ok && strings.HasSuffix(fwName, ".framework") && !fw[fwName] {
				fw[fwName] = true
				frameworks++
			}
		}
	}

	ext := strings.ToLower(filepath.Ext(path))
	var kind string
	switch {
	case ext == ".aab" || bundleConfig:
		kind = "aab"
	case ext == ".ipa" || (payloadApp && infoPlist):
		kind = "ipa"
	case ext == ".apk" || xmlMan || dex > 0:
		kind = "apk"
	default:
		d.Notes = append(d.Notes, fmt.Sprintf("zip: %d entries", entries))
		return false
	}
	d.Kind = kind

	switch kind {
	case "apk", "aab":
		mobileCap(d, "android")
		if flutter {
			mobileCap(d, "flutter")
		}
		if hermes {
			mobileCap(d, "react-native")
		}
		d.Notes = append(d.Notes, fmt.Sprintf("%s: %d entries", kind, entries))
		for _, n := range oddDex {
			d.Notes = append(d.Notes, fmt.Sprintf("%s: dex entry %s is not a standard classes*.dex name", kind, n))
		}
		for _, n := range packerHits {
			d.Notes = append(d.Notes, kind+": packer claim "+n)
		}
		if dex > 0 {
			d.Notes = append(d.Notes, fmt.Sprintf("%s: classes.dex: %d", kind, dex))
			deepNote(d, "decode the dex bytecode of the packed classes to recover the string, type and method names in-process")
		}
		if arscSize > 0 {
			d.Notes = append(d.Notes, fmt.Sprintf("%s: resources.arsc: %d bytes", kind, arscSize))
			deepNote(d, "decode the package resource table to recover the resource names and the layout references behind the manifest entries")
		}
		switch {
		case binaryManifest:
			d.Notes = append(d.Notes, kind+": AndroidManifest.xml: binary XML (0x00080003)")
			fillManifest(manifestBin, d)
		case xmlMan:
			d.Notes = append(d.Notes, kind+": AndroidManifest.xml: plain XML")
			fillPlainManifest(manifestXML, d)
		}
		if kind == "apk" {
			deepNote(d, "decode the package structure to recover the asset tree, the native libraries and the entry-point activity behind the manifest")
		}
	case "ipa":
		mobileCap(d, "ios")
		if provision {
			mobileCap(d, "signed-provision")
		}
		d.Notes = append(d.Notes, fmt.Sprintf("ipa: %d entries", entries))
		if infoPlist {
			d.Notes = append(d.Notes, "ipa: Info.plist present")
		}
		fillIPAPlist(d, infoPlistBody)
		if provision {
			d.Notes = append(d.Notes, "ipa: embedded.mobileprovision present")
		}
		if frameworks > 0 {
			d.Notes = append(d.Notes, fmt.Sprintf("ipa: frameworks: %d", frameworks))
		}
		deepNote(d, "read the bundle Info.plist keys, the embedded provisioning profile and the Mach-O slices of each framework to recover the app identity, the signing chain and the binary layout")
	}
	return true
}

// inspectAndroidManifest handles a standalone compiled AndroidManifest.xml.
func inspectAndroidManifest(path string, d *Digest) {
	mobileCap(d, "android")
	f, err := os.Open(path)
	if err != nil {
		d.Notes = append(d.Notes, "android-manifest: open: "+err.Error())
		return
	}
	defer f.Close()
	body, err := io.ReadAll(io.LimitReader(f, 8<<20))
	if err != nil || len(body) < 8 {
		d.Notes = append(d.Notes, "android-manifest: truncated header")
		return
	}
	d.Notes = append(d.Notes, "android-manifest: binary XML (0x00080003), "+strconv.FormatUint(uint64(binary.LittleEndian.Uint32(body[4:8])), 10)+" bytes declared")
	fillManifest(body, d)
	deepNote(d, "this manifest is one file of a package: decode the package resources and the classes to resolve the resource ids and the code behind the component names")
}

// fillManifest lifts package, uses-permission names, uses-sdk levels and the
// component names from a compiled AndroidManifest.xml. Malformed input is a
// note, never an error.
//
// shortcut: AXML string pool + start tags only; the component graph is
// name-level, the intent filters and the resource ids are not resolved.
// Upgrade: full resource-table resolution.
func fillManifest(data []byte, d *Digest) {
	m, ok := axmlManifestOf(data)
	if !ok {
		d.Notes = append(d.Notes, "manifest: AXML parse failed")
		return
	}
	applyManifest(d, m)
}

// fillPlainManifest reads the same fields from a plain-text AndroidManifest.xml.
func fillPlainManifest(data []byte, d *Digest) {
	m, ok := xmlManifestOf(data)
	if !ok {
		d.Notes = append(d.Notes, "manifest: XML parse failed")
		return
	}
	applyManifest(d, m)
}

// inspectPlainManifest fills the mobile fields of a standalone plain-text
// AndroidManifest.xml. The kind stays text: the file is XML, not compiled AXML.
func inspectPlainManifest(path string, d *Digest) bool {
	b, err := opRead(path, 8<<20)
	if err != nil || len(b) < 8 {
		return false
	}
	m, ok := xmlManifestOf(b)
	if !ok {
		return false
	}
	mobileCap(d, "android")
	d.Notes = append(d.Notes, "android-manifest: plain XML")
	applyManifest(d, m)
	return true
}

// fillIPAPlist lifts the package identity, the deployment target and the
// declared privacy keys from the bundle Info.plist. iOS has no android-style
// permission list: the usage descriptions are the permissions the app declares,
// so both are reported as they are written and never synthesized.
func fillIPAPlist(d *Digest, b []byte) {
	if len(b) == 0 {
		return
	}
	var pd Digest
	var keys []string
	if bytes.HasPrefix(b, []byte("bplist00")) {
		keys = bplistKeys(b, &pd)
	} else {
		keys = xmlPlistKeys(b, &pd)
	}
	var perms []string
	var bundleID, sdkName, minOS string
	for _, kv := range keys {
		k, v, _ := strings.Cut(kv, " = ")
		switch {
		case k == "CFBundleIdentifier" && v != "":
			bundleID = v
		case k == "DTSDKName" && v != "":
			sdkName = v
		case k == "MinimumOSVersion" && v != "":
			minOS = v
		case strings.HasSuffix(k, "UsageDescription"):
			perms = append(perms, k)
		}
	}
	if bundleID != "" {
		d.MobilePkg = bundleID
	}
	switch {
	case sdkName != "" && minOS != "":
		d.MobileSDK = sdkName + " min " + minOS
	case sdkName != "":
		d.MobileSDK = sdkName
	case minOS != "":
		d.MobileSDK = "min " + minOS
	}
	if len(perms) > 0 {
		d.MobilePerms = capped(d, "ipa permissions", perms, axmlListCap)
	}
}

func applyManifest(d *Digest, m manifestInfo) {
	d.MobilePkg = m.pkg
	d.MobilePerms = capped(d, "android permissions", m.perms, axmlListCap)
	var sdk []string
	if m.minSdk != "" {
		sdk = append(sdk, "min "+m.minSdk)
	}
	if m.targetSdk != "" {
		sdk = append(sdk, "target "+m.targetSdk)
	}
	d.MobileSDK = strings.Join(sdk, ", ")
	if comps := capped(d, "android components", m.components, axmlListCap); len(comps) > 0 {
		deepNote(d, "android components: "+strings.Join(comps, ", ")+
			"; decode the compiled manifest further to recover the intent filters and the exported entry points")
	}
}

// xmlManifestOf parses a plain-text AndroidManifest.xml. The root element must
// be <manifest>; any other XML is not a manifest and returns false.
func xmlManifestOf(data []byte) (manifestInfo, bool) {
	var doc struct {
		XMLName xml.Name `xml:"manifest"`
		Package string   `xml:"package,attr"`
		SDK     []struct {
			Min    string `xml:"minSdkVersion,attr"`
			Target string `xml:"targetSdkVersion,attr"`
		} `xml:"uses-sdk"`
		Perms []struct {
			Name string `xml:"name,attr"`
		} `xml:"uses-permission"`
	}
	if err := xml.Unmarshal(data, &doc); err != nil {
		return manifestInfo{}, false
	}
	m := manifestInfo{pkg: strings.TrimSpace(doc.Package)}
	for _, s := range doc.SDK {
		if v := strings.TrimSpace(s.Min); v != "" {
			m.minSdk = v
		}
		if v := strings.TrimSpace(s.Target); v != "" {
			m.targetSdk = v
		}
	}
	seen := map[string]bool{}
	for _, p := range doc.Perms {
		name := strings.TrimSpace(p.Name)
		if name == "" || seen[name] || len(m.perms) >= axmlListScan {
			continue
		}
		seen[name] = true
		m.perms = append(m.perms, name)
	}
	return m, true
}

type manifestInfo struct {
	pkg, minSdk, targetSdk string
	perms                  []string
	components             []string
}

// axmlListCap bounds the permissions and components a digest reports; the
// parser keeps more so a truncated list can say how many it dropped.
const (
	axmlListCap  = 64
	axmlListScan = 512
)

// axmlManifestOf walks chunk by chunk: string pool, skip resource map, start tags.
func axmlManifestOf(data []byte) (manifestInfo, bool) {
	var m manifestInfo
	u16 := func(b []byte, off int) uint16 { return binary.LittleEndian.Uint16(b[off:]) }
	u32 := func(b []byte, off int) uint32 { return binary.LittleEndian.Uint32(b[off:]) }
	if len(data) < 8 || u16(data, 0) != 0x0003 {
		return m, false
	}
	end, off := int(u32(data, 4)), int(u16(data, 2))
	if end > len(data) || end < 8 || off < 8 {
		return m, false
	}
	var pool []string
	seen := map[string]bool{}
	for off+8 <= end {
		typ, hsize, size := u16(data, off), int(u16(data, off+2)), int(u32(data, off+4))
		if hsize < 8 || size < hsize || off+size > end {
			return m, false
		}
		chunk := data[off : off+size]
		switch typ {
		case 0x0001: // string pool
			var ok bool
			if pool, ok = axmlStrings(chunk, hsize); !ok {
				return m, false
			}
		case 0x0102: // start tag
			name, attrs, ok := axmlStartTag(chunk, hsize, pool)
			if !ok {
				return m, false
			}
			switch name {
			case "manifest":
				m.pkg = attrs["package"]
			case "uses-permission":
				if p := attrs["name"]; p != "" && !seen[p] && len(m.perms) < axmlListScan {
					seen[p] = true
					m.perms = append(m.perms, p)
				}
			case "uses-sdk":
				m.minSdk = attrs["minSdkVersion"]
				m.targetSdk = attrs["targetSdkVersion"]
			case "activity", "activity-alias", "service", "receiver", "provider":
				if n := attrs["name"]; n != "" && !seen["c:"+n] && len(m.components) < axmlListScan {
					seen["c:"+n] = true
					m.components = append(m.components, name+" "+n)
				}
			}
		}
		off += size
	}
	return m, true
}

func axmlStrings(chunk []byte, hsize int) ([]string, bool) {
	if hsize < 28 || len(chunk) < hsize {
		return nil, false
	}
	u32 := func(off int) uint32 { return binary.LittleEndian.Uint32(chunk[off:]) }
	count, start := int(u32(8)), int(u32(20))
	if count < 0 || start < hsize || start > len(chunk) || hsize+4*count > len(chunk) {
		return nil, false
	}
	utf8 := u32(16)&0x100 != 0
	out := make([]string, count)
	for i := range out {
		p := start + int(u32(hsize+4*i))
		if p < 0 || p >= len(chunk) {
			return nil, false
		}
		s, ok := axmlString(chunk[p:], utf8)
		if !ok {
			return nil, false
		}
		out[i] = s
	}
	return out, true
}

// axmlString reads one pool entry: length prefix (1-2 bytes utf8, 1-4 utf16) then chars.
func axmlString(b []byte, utf8 bool) (string, bool) {
	if utf8 {
		if _, n, ok := axmlLen8(b); !ok {
			return "", false
		} else {
			b = b[n:]
		}
		l, n, ok := axmlLen8(b)
		if !ok || l > len(b)-n {
			return "", false
		}
		return string(b[n : n+l]), true
	}
	l, n, ok := axmlLen16(b)
	if !ok || l > (len(b)-n)/2 {
		return "", false
	}
	units := make([]uint16, l)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(b[n+2*i:])
	}
	return string(utf16.Decode(units)), true
}

func axmlLen8(b []byte) (int, int, bool) {
	if len(b) < 1 {
		return 0, 0, false
	}
	if b[0]&0x80 == 0 {
		return int(b[0]), 1, true
	}
	if len(b) < 2 {
		return 0, 0, false
	}
	return int(b[0]&0x7f)<<8 | int(b[1]), 2, true
}

func axmlLen16(b []byte) (int, int, bool) {
	if len(b) < 2 {
		return 0, 0, false
	}
	v := binary.LittleEndian.Uint16(b)
	if v&0x8000 == 0 {
		return int(v), 2, true
	}
	if len(b) < 4 {
		return 0, 0, false
	}
	return int(v&0x7fff)<<16 | int(binary.LittleEndian.Uint16(b[2:])), 4, true
}

// axmlStartTag returns the tag name and its attributes keyed by attribute name
// (namespace dropped); string and int typed values are kept, others skipped.
func axmlStartTag(chunk []byte, hsize int, pool []string) (string, map[string]string, bool) {
	if hsize < 16 || len(chunk) < hsize+20 {
		return "", nil, false
	}
	u16 := func(off int) uint16 { return binary.LittleEndian.Uint16(chunk[off:]) }
	u32 := func(off int) uint32 { return binary.LittleEndian.Uint32(chunk[off:]) }
	ref := func(i uint32) string {
		if int(i) < len(pool) {
			return pool[i]
		}
		return ""
	}
	name := ref(u32(hsize + 4))
	start, size, count := hsize+int(u16(hsize+8)), int(u16(hsize+10)), int(u16(hsize+12))
	if size < 20 || count < 0 || start+size*count > len(chunk) {
		return "", nil, false
	}
	attrs := make(map[string]string, count)
	for i := range count {
		at := chunk[start+i*size:]
		key := ref(binary.LittleEndian.Uint32(at[4:]))
		if key == "" {
			continue
		}
		if raw := binary.LittleEndian.Uint32(at[8:]); raw != 0xffffffff {
			attrs[key] = ref(raw)
			continue
		}
		switch at[15] {
		case 0x03: // string
			attrs[key] = ref(binary.LittleEndian.Uint32(at[16:]))
		case 0x10, 0x11: // int dec, int hex
			attrs[key] = strconv.FormatInt(int64(int32(binary.LittleEndian.Uint32(at[16:]))), 10)
		case 0x12: // boolean
			attrs[key] = strconv.FormatBool(binary.LittleEndian.Uint32(at[16:]) != 0)
		}
	}
	return name, attrs, true
}

func readEntry(f *zip.File, max int64) ([]byte, bool) {
	// An entry that does not fit the caller's budget is refused, never silently
	// truncated: a clipped AndroidManifest.xml or resources.arsc still parses
	// far enough to yield a confidently wrong answer.
	if max <= 0 || int64(f.UncompressedSize64) > max {
		return nil, false
	}
	rc, err := f.Open()
	if err != nil {
		return nil, false
	}
	defer rc.Close()
	b, err := io.ReadAll(io.LimitReader(rc, max+1))
	if err != nil || int64(len(b)) > max {
		return nil, false
	}
	return b, true
}
