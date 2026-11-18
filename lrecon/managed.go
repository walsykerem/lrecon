package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// managedReasons is the closed set managed.go emits. The single-file reader
// registers them alongside its own, since one reader claim owns both turns.
var managedReasons = []string{
	"ecma335-metadata-invalid",
	"ecma335-table-unverified",
	"ecma335-truncated",
	"ecma335-container-singlefile",
	"no-disassembler",
}

// Budgets: metadata is a few MB at most, and one window from the head is enough
// to spot Unity/IL2CPP markers in real players.
const (
	maxMetaRead    = 4 << 20 // CLI metadata root cap
	maxManagedScan = 8 << 20 // Unity/il2cpp marker window
	cliHeaderSize  = 72
	bsjbSignature  = 0x424A5342
)

// inspectManaged adds managed-runtime depth on top of the native digest:
// .NET/CLR for PE, Unity IL2CPP for any native image.
func inspectManaged(path string, d *Digest) {
	if base(path) == "global-metadata.dat" {
		d.Kind = "il2cpp-metadata"
		mobileCap(d, "il2cpp")
		deepNote(d, "metadata file holds type, method and string tables of compiled script assemblies; read them to recover managed api surface")
		return
	}
	if d.Kind == "pe" {
		dotnetDigest(path, d)
	}
	il2cppDigest(path, d)
}

// --- .NET / CLR ---

func dotnetDigest(path string, d *Digest) {
	// The outer image of a single-file app is the native host: it has no CLR
	// metadata, and the managed assemblies are bundle entries, not a defect.
	if containsStr(d.Capabilities, "dotnet-singlefile") {
		d.skip("ecma335-container-singlefile", "outer image is the native apphost; managed assemblies are bundled entries")
		return
	}
	src, err := os.Open(path)
	if err != nil {
		return
	}
	defer src.Close()
	img, ok := openPEImage(src)
	if !ok || img.cliRVA == 0 || img.cliSize < cliHeaderSize {
		return
	}
	cli, ok := img.at(img.cliRVA, cliHeaderSize)
	if !ok {
		return
	}

	metaRVA := binary.LittleEndian.Uint32(cli[8:12])
	metaSize := binary.LittleEndian.Uint32(cli[12:16])
	flags := binary.LittleEndian.Uint32(cli[16:20])
	nativeHdr := binary.LittleEndian.Uint32(cli[64:68])

	d.Kind = "pe-dotnet"
	mobileCap(d, "managed")

	read := min(metaSize, maxMetaRead)
	meta, metaOK := img.at(metaRVA, read)

	tc := "dotnet"
	if md, ok := parseMetadata(meta); ok {
		if md.version != "" {
			tc += " CLR " + md.version
		}
		if len(md.streams) > 0 {
			d.Notes = append(d.Notes, "metadata streams: "+strings.Join(md.streams, ", "))
		}
		if n := nativeModules(md.strings); n > 0 {
			mobileCap(d, "pinvoke")
			d.Notes = append(d.Notes, "pinvoke: "+strconv.Itoa(n)+" native module name(s) in #Strings (ImplMap table not decoded)")
		}
		applyCLITables(parseCLITables(md, d), d)
	} else if metaOK {
		d.Notes = append(d.Notes, "CLI header present, metadata root (BSJB) unreadable")
	}
	if tfm := targetFramework(meta); tfm != "" {
		tc += " " + tfm
	}
	d.Toolchain = tc

	if flags&1 == 0 && nativeHdr == 0 {
		d.Notes = append(d.Notes, "not IL-only: mixed-mode assembly (C++/CLI)")
	}
	if flags&4 != 0 {
		d.Notes = append(d.Notes, "IL_LIBRARY: netmodule, not a standalone assembly")
	}
	if nativeHdr != 0 {
		d.Notes = append(d.Notes, "ReadyToRun / managed native header present")
	}
	deepNote(d, "metadata root holds type, method and string tables; read metadata streams and interop declarations to recover managed api surface and native entry points")
}

// peImage maps RVA ranges to file offsets. Parsed by hand instead of through
// debug/pe: that package rejects machines it does not know (real .NET SDK
// assemblies carry 0xc020) and would leave every modern assembly undetected.
type peImage struct {
	src     io.ReaderAt
	sects   []peSection
	cliRVA  uint32
	cliSize uint32
}

type peSection struct{ va, span, off uint32 }

const maxPEHeader = 64 << 10

func openPEImage(src io.ReaderAt) (peImage, bool) {
	b := make([]byte, maxPEHeader)
	n, _ := src.ReadAt(b, 0)
	b = b[:n]
	if len(b) < 0x40 || b[0] != 'M' || b[1] != 'Z' {
		return peImage{}, false
	}
	peOff := int(binary.LittleEndian.Uint32(b[0x3c:]))
	if peOff < 4 || peOff+24 > len(b) || string(b[peOff:peOff+4]) != "PE\x00\x00" {
		return peImage{}, false
	}
	nsec := int(binary.LittleEndian.Uint16(b[peOff+6 : peOff+8]))
	optSize := int(binary.LittleEndian.Uint16(b[peOff+20 : peOff+22]))
	opt := peOff + 24
	if opt+optSize > len(b) {
		return peImage{}, false
	}
	var img peImage
	img.src = src
	switch binary.LittleEndian.Uint16(b[opt:]) {
	case 0x10b: // PE32: data directories start at 96
		img.cliRVA, img.cliSize = comDir(b[opt:opt+optSize], 96)
	case 0x20b: // PE32+
		img.cliRVA, img.cliSize = comDir(b[opt:opt+optSize], 112)
	default:
		return peImage{}, false
	}
	sec := opt + optSize
	for i := 0; i < nsec && sec+(i+1)*40 <= len(b); i++ {
		s := b[sec+i*40:]
		span := binary.LittleEndian.Uint32(s[8:]) // VirtualSize
		if raw := binary.LittleEndian.Uint32(s[16:]); raw > span {
			span = raw
		}
		img.sects = append(img.sects, peSection{
			va:   binary.LittleEndian.Uint32(s[12:]),
			span: span,
			off:  binary.LittleEndian.Uint32(s[20:]),
		})
	}
	return img, true
}

// comDir reads the COM descriptor entry (index 14) that starts at dirOff.
func comDir(opt []byte, dirOff int) (rva, size uint32) {
	const idx = 14
	if dirOff+idx*8+8 > len(opt) {
		return 0, 0
	}
	if binary.LittleEndian.Uint32(opt[dirOff-4:]) <= idx { // NumberOfRvaAndSizes
		return 0, 0
	}
	return binary.LittleEndian.Uint32(opt[dirOff+idx*8:]), binary.LittleEndian.Uint32(opt[dirOff+idx*8+4:])
}

func (p peImage) at(rva, size uint32) ([]byte, bool) {
	if size > maxMetaRead {
		// size comes from the image header (CLI directory, method body), so one
		// crafted header must not turn into a multi-GiB allocation.
		return nil, false
	}
	for _, s := range p.sects {
		if rva < s.va || uint64(rva)+uint64(size) > uint64(s.va)+uint64(s.span) {
			continue
		}
		b := make([]byte, size)
		if _, err := p.src.ReadAt(b, int64(s.off+rva-s.va)); err != nil {
			return nil, false
		}
		return b, true
	}
	return nil, false
}

type cliMetadata struct {
	version string
	major   uint16
	minor   uint16
	streams []string
	strings []byte // #Strings heap, bounded by the metadata root
	data    map[string][]byte
}

// parseMetadata walks the BSJB root: version string, stream headers, #Strings heap.
func parseMetadata(b []byte) (cliMetadata, bool) {
	var m cliMetadata
	if len(b) < 20 || binary.LittleEndian.Uint32(b) != bsjbSignature {
		return m, false
	}
	verLen := int(binary.LittleEndian.Uint32(b[12:16]))
	off := 16
	if verLen < 0 || verLen > 255 || off+verLen+4 > len(b) {
		return m, false
	}
	m.major = binary.LittleEndian.Uint16(b[4:6])
	m.minor = binary.LittleEndian.Uint16(b[6:8])
	m.version = strings.TrimRight(string(b[off:off+verLen]), "\x00")
	off += verLen
	n := int(binary.LittleEndian.Uint16(b[off+2 : off+4]))
	off += 4
	if m.data == nil {
		m.data = map[string][]byte{}
	}
	for i := 0; i < n && off+8 <= len(b); i++ {
		so := int(binary.LittleEndian.Uint32(b[off : off+4]))
		ss := int(binary.LittleEndian.Uint32(b[off+4 : off+8]))
		off += 8
		end := bytes.IndexByte(b[off:], 0)
		if end < 0 {
			break
		}
		name := string(b[off : off+end])
		off += (end + 4) &^ 3
		m.streams = append(m.streams, name)
		if so >= 0 && so < len(b) && ss > 0 {
			stop := min(so+ss, len(b))
			m.data[name] = b[so:stop]
			if name == "#Strings" {
				m.strings = b[so:stop]
			}
		}
	}
	return m, true
}

// targetFramework finds the TargetFrameworkAttribute value ("...Version=v8.0")
// in the metadata blob; the attribute itself is a custom attribute blob.
func targetFramework(b []byte) string {
	for _, p := range []string{".NETCoreApp,Version=v", ".NETFramework,Version=v", ".NETStandard,Version=v"} {
		i := bytes.Index(b, []byte(p))
		if i < 0 {
			continue
		}
		s := b[i:]
		end := 0
		for end < len(s) && s[end] >= 0x20 && s[end] < 0x7f {
			end++ // the value sits in a blob: length-prefixed, no terminator
		}
		return string(s[:end])
	}
	return ""
}

// nativeModules counts #Strings entries that look like native module names.
// shortcut: the heap also holds the assembly's own module name, so this is a
// DllImport hint, not an ImplMap row count; upgrade by decoding `#~` ImplMap.
func nativeModules(heap []byte) int {
	n := 0
	for s := range bytes.SplitSeq(heap, []byte{0}) {
		l := strings.ToLower(string(s))
		if strings.HasSuffix(l, ".dll") || strings.HasSuffix(l, ".dylib") || strings.HasSuffix(l, ".so") {
			n++
		}
	}
	if n > 0 {
		n-- // the module's own name
	}
	return n
}

// --- ECMA-335 metadata tables ---

// Table row schemas for all 39 ECMA-335 tables (0x00-0x2C). Fixed columns are
// u2/u4; heap columns follow the stream's heap-size bits; the rest are simple
// table indexes or coded indexes, sized from the row counts.
const (
	tableStreamMaxRows = 1 << 24
	maxCLITypeDefs     = 256
	maxCLIRefs         = 60
)

var tableColumn = map[string]int{
	"Module": 0x00, "TypeRef": 0x01, "TypeDef": 0x02, "Field": 0x04,
	"MethodDef": 0x06, "Param": 0x08, "Event": 0x14, "Property": 0x17,
	"ModuleRef": 0x1A, "AssemblyRef": 0x23, "GenericParam": 0x2A,
}

var tableSchema = [0x2D][]string{
	/* 0x00 Module */ {"u2", "str", "guid", "guid", "guid"},
	/* 0x01 TypeRef */ {"TypeDefOrRef", "str", "str"},
	/* 0x02 TypeDef */ {"u4", "str", "str", "TypeDefOrRef", "Field", "MethodDef"},
	/* 0x03 FieldPtr */ {"Field"},
	/* 0x04 Field */ {"u2", "str", "blob"},
	/* 0x05 MethodPtr */ {"MethodDef"},
	/* 0x06 MethodDef */ {"u4", "u2", "u2", "str", "blob", "Param"},
	/* 0x07 ParamPtr */ {"Param"},
	/* 0x08 Param */ {"u2", "u2", "str"},
	/* 0x09 InterfaceImpl */ {"TypeDef", "TypeDefOrRef"},
	/* 0x0A MemberRef */ {"MemberRefParent", "str", "blob"},
	/* 0x0B Constant */ {"u2", "HasConstant", "blob"},
	/* 0x0C CustomAttribute */ {"HasCustomAttribute", "CustomAttributeType", "blob"},
	/* 0x0D FieldMarshal */ {"HasFieldMarshal", "blob"},
	/* 0x0E DeclSecurity */ {"u2", "HasDeclSecurity", "blob"},
	/* 0x0F ClassLayout */ {"u2", "u4", "TypeDef"},
	/* 0x10 FieldLayout */ {"u4", "Field"},
	/* 0x11 StandAloneSig */ {"blob"},
	/* 0x12 EventMap */ {"TypeDef", "Event"},
	/* 0x13 EventPtr */ {"Event"},
	/* 0x14 Event */ {"u2", "str", "TypeDefOrRef"},
	/* 0x15 PropertyMap */ {"TypeDef", "Property"},
	/* 0x16 PropertyPtr */ {"Property"},
	/* 0x17 Property */ {"u2", "str", "blob"},
	/* 0x18 MethodSemantics */ {"u2", "MethodDef", "HasSemantics"},
	/* 0x19 MethodImpl */ {"TypeDef", "MethodDefOrRef", "MethodDefOrRef"},
	/* 0x1A ModuleRef */ {"str"},
	/* 0x1B TypeSpec */ {"blob"},
	/* 0x1C ImplMap */ {"u2", "MemberForwarded", "str", "ModuleRef"},
	/* 0x1D FieldRVA */ {"u4", "Field"},
	/* 0x1E EncLog */ {"u4", "u4"},
	/* 0x1F EncMap */ {"u4"},
	/* 0x20 Assembly */ {"u4", "u2", "u2", "u2", "u2", "u4", "blob", "str", "str"},
	/* 0x21 AssemblyProcessor */ {"u4"},
	/* 0x22 AssemblyOS */ {"u4", "u4", "u4"},
	/* 0x23 AssemblyRef */ {"u2", "u2", "u2", "u2", "u4", "blob", "str", "str", "blob"},
	/* 0x24 AssemblyRefProcessor */ {"u4", "AssemblyRef"},
	/* 0x25 AssemblyRefOS */ {"u4", "u4", "u4", "AssemblyRef"},
	/* 0x26 File */ {"u4", "str", "blob"},
	/* 0x27 ExportedType */ {"u4", "u4", "str", "str", "Implementation"},
	/* 0x28 ManifestResource */ {"u4", "u4", "str", "Implementation"},
	/* 0x29 NestedClass */ {"TypeDef", "TypeDef"},
	/* 0x2A GenericParam */ {"u2", "u2", "TypeOrMethodDef", "str"},
	/* 0x2B MethodSpec */ {"MethodDefOrRef", "blob"},
	/* 0x2C GenericParamConstraint */ {"GenericParam", "TypeDefOrRef"},
}

// codedTagTables lists the table each coded-index tag value points at; the
// slice length fixes the tag bits, and -1 marks a reserved tag.
var codedTagTables = map[string][]int{
	"TypeDefOrRef":        {0x02, 0x01, 0x1B},
	"HasConstant":         {0x04, 0x08, 0x17},
	"HasCustomAttribute":  {0x06, 0x04, 0x01, 0x02, 0x08, 0x09, 0x0A, 0x00, 0x0E, 0x17, 0x14, 0x11, 0x1A, 0x1B, 0x20, 0x23, 0x26, 0x27, 0x28, 0x2A, 0x2C, 0x2B},
	"HasFieldMarshal":     {0x04, 0x08},
	"HasDeclSecurity":     {0x02, 0x06, 0x20},
	"MemberRefParent":     {0x02, 0x01, 0x1A, 0x06, 0x1B},
	"HasSemantics":        {0x14, 0x17},
	"MethodDefOrRef":      {0x06, 0x0A},
	"MemberForwarded":     {0x04, 0x06},
	"CustomAttributeType": {-1, -1, 0x06, 0x0A, -1},
	"ResolutionScope":     {0x00, 0x1A, 0x23, 0x01},
	"Implementation":      {0x26, 0x23, 0x27, -1},
	"TypeOrMethodDef":     {0x02, 0x06},
}

type cliTables struct {
	ok                                       bool
	module, assembly                         string
	typedefs                                 []string
	refs                                     []Dep
	typedefRows, methodRows, assemblyRefRows int
}

func colWidth(spec string, hs uint8, rows *[0x2D]int) int {
	switch spec {
	case "u2":
		return 2
	case "u4":
		return 4
	case "str":
		return heapWidth(hs, 1)
	case "guid":
		return heapWidth(hs, 2)
	case "blob":
		return heapWidth(hs, 4)
	}
	if id, ok := tableColumn[spec]; ok {
		if rows[id] < 1<<16 {
			return 2
		}
		return 4
	}
	tags := codedTagTables[spec]
	if tags == nil {
		return 2 // unreachable while schema and maps stay in sync
	}
	bits := 0
	for len(tags) > 1<<bits {
		bits++
	}
	max := 0
	for _, tt := range tags {
		if tt >= 0 && rows[tt] > max {
			max = rows[tt]
		}
	}
	if max < 1<<(16-bits) {
		return 2
	}
	return 4
}

func heapWidth(hs, bit uint8) int {
	if hs&bit != 0 {
		return 4
	}
	return 2
}

func colWidths(schema []string, hs uint8, rows *[0x2D]int) ([]int, []int) {
	w := make([]int, len(schema))
	o := make([]int, len(schema))
	sum := 0
	for i, spec := range schema {
		w[i] = colWidth(spec, hs, rows)
		o[i] = sum
		sum += w[i]
	}
	return w, o
}

func idxAt(row []byte, off, w int) uint32 {
	if w == 4 {
		return binary.LittleEndian.Uint32(row[off:])
	}
	return uint32(binary.LittleEndian.Uint16(row[off:]))
}

func heapString(h []byte, i uint32) string {
	if i == 0 || int(i) >= len(h) {
		return ""
	}
	s := h[i:]
	if end := bytes.IndexByte(s, 0); end >= 0 {
		s = s[:end]
	}
	return string(s)
}

// parseCLITables decodes the #~ table stream: header, row counts, then the row
// groups this reader reports. Every refusal is a registered reason, and the
// table stream version is gated before any row is read.
func parseCLITables(md cliMetadata, d *Digest) cliTables {
	var t cliTables
	if md.major != 1 || (md.minor != 0 && md.minor != 1) {
		d.skip("ecma335-metadata-invalid", fmt.Sprintf("metadata root version %d.%d", md.major, md.minor))
		return t
	}
	raw, ok := md.data["#~"]
	if !ok {
		// #- is the uncompressed edit-and-continue shape with the same row layout.
		raw, ok = md.data["#-"]
	}
	if !ok {
		return t
	}
	if len(raw) < 24 {
		d.skip("ecma335-truncated", "table stream shorter than its header")
		return t
	}
	heapSizes := raw[6]
	if raw[4] != 2 || raw[5] != 0 {
		d.skip("ecma335-table-unverified", fmt.Sprintf("table stream version %d.%d", raw[4], raw[5]))
		return t
	}
	// raw[7] is reserved; CoreCLR writes 0x0a where the spec says 1, so it carries
	// nothing worth verifying.
	valid := binary.LittleEndian.Uint64(raw[8:])
	if valid>>0x2D != 0 {
		d.skip("ecma335-metadata-invalid", "valid mask names tables past GenericParamConstraint")
		return t
	}

	var rows [0x2D]int
	off := 24
	for id := 0; id <= 0x2C; id++ {
		if valid&(1<<uint(id)) == 0 {
			continue
		}
		if off+4 > len(raw) {
			d.skip("ecma335-truncated", "row count table cut")
			return t
		}
		n := int(binary.LittleEndian.Uint32(raw[off:]))
		off += 4
		if n < 0 || n > tableStreamMaxRows {
			d.skip("ecma335-truncated", fmt.Sprintf("row count %d for table %#x", n, id))
			return t
		}
		rows[id] = n
	}
	data := raw[off:]

	var tableOff, tableSize [0x2D]int
	cur := 0
	for id := 0; id <= 0x2C; id++ {
		if rows[id] > 0 && len(tableSchema[id]) == 0 {
			d.skip("ecma335-table-unverified", fmt.Sprintf("no layout for table %#x", id))
			return t
		}
		w, _ := colWidths(tableSchema[id], heapSizes, &rows)
		for _, x := range w {
			tableSize[id] += x
		}
		tableOff[id] = cur
		cur += tableSize[id] * rows[id]
	}
	if cur > len(data) {
		d.skip("ecma335-truncated", fmt.Sprintf("tables need %d bytes, stream has %d", cur, len(data)))
		return t
	}

	row := func(id, i int) []byte {
		p := tableOff[id] + i*tableSize[id]
		return data[p : p+tableSize[id]]
	}

	if n := rows[0x00]; n > 0 {
		w, o := colWidths(tableSchema[0x00], heapSizes, &rows)
		t.module = heapString(md.strings, idxAt(row(0x00, 0), o[1], w[1]))
		d.parsed()
	}
	if n := rows[0x02]; n > 0 {
		w, o := colWidths(tableSchema[0x02], heapSizes, &rows)
		capped := false
		for i := range n {
			r := row(0x02, i)
			name := heapString(md.strings, idxAt(r, o[1], w[1]))
			ns := heapString(md.strings, idxAt(r, o[2], w[2]))
			if name == "" || name == "<Module>" {
				continue
			}
			if ns != "" {
				name = ns + "." + name
			}
			if len(t.typedefs) >= maxCLITypeDefs {
				capped = true
				continue
			}
			t.typedefs = append(t.typedefs, name)
		}
		sort.Strings(t.typedefs)
		t.typedefRows = n
		if capped {
			d.Notes = append(d.Notes, fmt.Sprintf("ecma335: typedefs capped at %d of %d", maxCLITypeDefs, n))
		}
		d.parsed()
	}
	if t.methodRows = rows[0x06]; t.methodRows > 0 {
		d.parsed()
	}
	if n := rows[0x20]; n > 0 {
		w, o := colWidths(tableSchema[0x20], heapSizes, &rows)
		r := row(0x20, 0)
		ver := fmt.Sprintf("%d.%d.%d.%d",
			binary.LittleEndian.Uint16(r[o[1]:]), binary.LittleEndian.Uint16(r[o[2]:]),
			binary.LittleEndian.Uint16(r[o[3]:]), binary.LittleEndian.Uint16(r[o[4]:]))
		name := heapString(md.strings, idxAt(r, o[7], w[7]))
		t.assembly = strings.TrimSpace(name + " " + ver)
		d.parsed()
	}
	if t.assemblyRefRows = rows[0x23]; t.assemblyRefRows > 0 {
		w, o := colWidths(tableSchema[0x23], heapSizes, &rows)
		capped := false
		for i := 0; i < t.assemblyRefRows; i++ {
			r := row(0x23, i)
			name := heapString(md.strings, idxAt(r, o[6], w[6]))
			if name == "" {
				continue
			}
			if len(t.refs) >= maxCLIRefs {
				capped = true
				continue
			}
			t.refs = append(t.refs, Dep{Path: name, Version: fmt.Sprintf("%d.%d.%d.%d",
				binary.LittleEndian.Uint16(r[o[0]:]), binary.LittleEndian.Uint16(r[o[1]:]),
				binary.LittleEndian.Uint16(r[o[2]:]), binary.LittleEndian.Uint16(r[o[3]:]))})
		}
		if capped {
			d.Notes = append(d.Notes, fmt.Sprintf("ecma335: assembly refs capped at %d of %d", maxCLIRefs, t.assemblyRefRows))
		}
		d.parsed()
	}
	t.ok = true
	return t
}

// applyCLITables projects the decoded groups onto the digest contract.
func applyCLITables(t cliTables, d *Digest) {
	if !t.ok {
		return
	}
	mobileCap(d, "ecma335:typedefs="+strconv.Itoa(t.typedefRows))
	mobileCap(d, "ecma335:methoddefs="+strconv.Itoa(t.methodRows))
	mobileCap(d, "ecma335:assemblyrefs="+strconv.Itoa(t.assemblyRefRows))
	if t.assembly != "" {
		d.Notes = append(d.Notes, "assembly: "+t.assembly)
	}
	if t.module != "" {
		d.Notes = append(d.Notes, "module: "+t.module)
	}
	d.Notes = append(d.Notes, fmt.Sprintf("ecma335: %d typedefs, %d methods", t.typedefRows, t.methodRows))
	if t.methodRows > 0 {
		d.skip("no-disassembler", "IL method bodies not decoded")
	}
	d.Deps = append(d.Deps, t.refs...)
	d.Imports = append(d.Imports, t.typedefs...)
}

// --- Unity IL2CPP ---

func il2cppDigest(path string, d *Digest) {
	switch d.Kind {
	case "pe", "macho", "elf":
	default:
		return
	}
	ver, found := il2cppMarkers(head(path, maxManagedScan))
	if !found {
		return
	}
	mobileCap(d, "il2cpp")
	if ver != "" {
		if d.Toolchain == "" {
			d.Toolchain = "unity " + ver
		} else {
			d.Notes = append(d.Notes, "unity "+ver)
		}
	}
	deepNote(d, "binary references a global-metadata.dat file; read the metadata next to the image to recover managed types and methods")
	d.Notes = append(d.Notes, "unity scan capped at first "+strconv.Itoa(maxManagedScan>>20)+" MiB")
}

// il2cppMarkers scans one bounded image window for the il2cpp metadata file
// name plus a best-effort Unity version string. The name alone is not enough:
// lrecon's own op descriptions mention global-metadata.dat, and matching that
// literal tagged a plain Mach-O as IL2CPP. A real player also carries the
// metadata magic, an il2cpp_init entry point, or a Unity version string.
func il2cppMarkers(b []byte) (version string, found bool) {
	if !bytes.Contains(b, []byte("global-metadata.dat")) {
		return "", false
	}
	ver := unityVersion(b)
	if ver == "" && !bytes.Contains(b, []byte("il2cpp_init")) &&
		!bytes.Contains(b, []byte{0xaf, 0x1b, 0xb1, 0xfa}) {
		return "", false
	}
	return ver, true
}

var unityVersionRe = regexp.MustCompile(`\b(20\d\d\.\d{1,3}\.\d{1,5}[abfp]\d{1,3})\b`)

func unityVersion(b []byte) string {
	if !bytes.Contains(b, []byte("Unity")) && !bytes.Contains(b, []byte("il2cpp")) {
		return ""
	}
	if m := unityVersionRe.FindSubmatch(b); m != nil {
		return string(m[1])
	}
	return ""
}
