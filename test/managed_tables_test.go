package main

import (
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"
)

type testHeap struct{ b []byte }

func newTestHeap() *testHeap { return &testHeap{b: []byte{0}} }

func (h *testHeap) add(s string) uint32 {
	i := uint32(len(h.b))
	h.b = append(h.b, s...)
	h.b = append(h.b, 0)
	return i
}

// rowWriter writes a table row; wide selects the 4-byte heap index shape.
type rowWriter struct {
	b    []byte
	wide bool
}

func (w *rowWriter) u16(v uint16) { w.b = binary.LittleEndian.AppendUint16(w.b, v) }
func (w *rowWriter) u32(v uint32) { w.b = binary.LittleEndian.AppendUint32(w.b, v) }
func (w *rowWriter) idx(v uint32) {
	if w.wide {
		w.u32(v)
		return
	}
	w.u16(uint16(v))
}

// tablesMeta builds a BSJB root with a table stream and #Strings, matching the
// padded layout real toolchains emit.
func tablesMeta(rootMajor, rootMinor uint16, streamName string, tableStream, strHeap []byte) []byte {
	pad := func(s string) []byte {
		b := append([]byte(s), 0)
		for len(b)%4 != 0 {
			b = append(b, 0)
		}
		return b
	}
	version := "v4.0.30319\x00\x00"
	n1, n2 := pad(streamName), pad("#Strings")
	hdr := 32
	shdrs := 8 + len(n1) + 8 + len(n2)
	meta := make([]byte, hdr+shdrs+len(tableStream)+len(strHeap))
	binary.LittleEndian.PutUint32(meta[0:], bsjbSignature)
	binary.LittleEndian.PutUint16(meta[4:], rootMajor)
	binary.LittleEndian.PutUint16(meta[6:], rootMinor)
	binary.LittleEndian.PutUint32(meta[12:], uint32(len(version)))
	copy(meta[16:], version)
	binary.LittleEndian.PutUint16(meta[30:], 2)

	off := hdr
	binary.LittleEndian.PutUint32(meta[off:], uint32(hdr+shdrs))
	binary.LittleEndian.PutUint32(meta[off+4:], uint32(len(tableStream)))
	copy(meta[off+8:], n1)
	off += 8 + len(n1)
	binary.LittleEndian.PutUint32(meta[off:], uint32(hdr+shdrs+len(tableStream)))
	binary.LittleEndian.PutUint32(meta[off+4:], uint32(len(strHeap)))
	copy(meta[off+8:], n2)

	copy(meta[hdr+shdrs:], tableStream)
	copy(meta[hdr+shdrs+len(tableStream):], strHeap)
	return meta
}

func buildTableStream(heaps uint8, rows map[int]int, data []byte) []byte {
	var valid uint64
	for id := range rows {
		valid |= 1 << uint(id)
	}
	b := make([]byte, 24)
	b[4], b[5], b[6], b[7] = 2, 0, heaps, 1
	binary.LittleEndian.PutUint64(b[8:], valid)
	for id := 0; id <= 0x2C; id++ {
		if n, ok := rows[id]; ok {
			b = binary.LittleEndian.AppendUint32(b, uint32(n))
		}
	}
	return append(b, data...)
}

// managedTablesFixture hand-builds Module, two TypeDefs, three MethodDefs, one
// Assembly and two AssemblyRefs with 2-byte heap indexes.
func managedTablesFixture(t *testing.T) []byte {
	t.Helper()
	h := newTestHeap()
	module := h.add("Demo.dll")
	typeName := h.add("Widget")
	typeNS := h.add("Acme.Core")
	moduleType := h.add("<Module>")
	method1 := h.add("Run")
	method2 := h.add("Stop")
	method3 := h.add(".ctor")
	asm := h.add("Demo")
	ref1 := h.add("System.Runtime")
	ref2 := h.add("System.Text.Json")

	w := &rowWriter{}
	gen := func(mv, iv uint16, name uint32) {
		w.u32(0x2050)
		w.u16(mv)
		w.u16(iv)
		w.idx(name)
		w.idx(1) // signature blob
		w.u16(1) // ParamList
	}
	ref := func(name uint32) {
		w.u16(4)
		w.u16(0)
		w.u16(0)
		w.u16(0)
		w.u32(0)
		w.idx(0) // public key or token
		w.idx(name)
		w.idx(0) // culture
		w.idx(0) // hash
	}

	// Module: Generation, Name, Mvid, EncId, EncBaseId.
	w.u16(0)
	w.idx(module)
	w.idx(1)
	w.idx(0)
	w.idx(0)
	// TypeDef: Flags, Name, Namespace, Extends, FieldList, MethodList. Row 0 is
	// the <Module> type every assembly carries and opens both lists; a name
	// index of 0 would be the empty string, which no real writer emits.
	for _, row := range [][4]uint32{
		{0, moduleType, 0, 1},
		{0x100001, typeName, typeNS, 1},
	} {
		w.u32(row[0])
		w.idx(row[1])
		w.idx(row[2])
		w.u16(1)
		w.u16(1)
		w.u16(uint16(row[3]))
	}
	gen(0, 6, method1)
	gen(0, 6, method2)
	gen(0, 6, method3)
	// Assembly: HashAlgId, 4 versions, Flags, PublicKey, Name, Culture.
	w.u32(0x8004)
	w.u16(1)
	w.u16(2)
	w.u16(3)
	w.u16(4)
	w.u32(0)
	w.idx(0)
	w.idx(asm)
	w.idx(0)
	ref(ref1)
	ref(ref2)

	rows := map[int]int{0x00: 1, 0x02: 2, 0x06: 3, 0x20: 1, 0x23: 2}
	return tablesMeta(1, 1, "#~", buildTableStream(0, rows, w.b), h.b)
}

func TestCLITableDecode(t *testing.T) {
	md, ok := parseMetadata(managedTablesFixture(t))
	if !ok {
		t.Fatal("parseMetadata rejected the fixture root")
	}
	d := Digest{}
	tab := parseCLITables(md, &d)
	if !tab.ok {
		t.Fatalf("parseCLITables refused: %+v", d.Skipped)
	}
	if len(d.Skipped) != 0 {
		t.Fatalf("skipped = %+v, want none", d.Skipped)
	}
	if d.Coverage == nil || d.Coverage.Parsed != 5 {
		t.Fatalf("coverage = %+v, want 5 row groups parsed", d.Coverage)
	}
	if tab.module != "Demo.dll" {
		t.Fatalf("module = %q", tab.module)
	}
	if tab.assembly != "Demo 1.2.3.4" {
		t.Fatalf("assembly = %q", tab.assembly)
	}
	if tab.typedefRows != 2 || tab.methodRows != 3 || tab.assemblyRefRows != 2 {
		t.Fatalf("counts = %d/%d/%d, want 2/3/2", tab.typedefRows, tab.methodRows, tab.assemblyRefRows)
	}
	if strings.Join(tab.typedefs, ",") != "Acme.Core.Widget" {
		t.Fatalf("typedefs = %v, want only the named type (not <Module>)", tab.typedefs)
	}

	applyCLITables(tab, &d)
	for _, cap := range []string{"ecma335:typedefs=2", "ecma335:methoddefs=3", "ecma335:assemblyrefs=2"} {
		if !containsStr(d.Capabilities, cap) {
			t.Fatalf("capabilities = %v, want %s", d.Capabilities, cap)
		}
	}
	notes := strings.Join(d.Notes, "\n")
	if !strings.Contains(notes, "assembly: Demo 1.2.3.4") || !strings.Contains(notes, "module: Demo.dll") {
		t.Fatalf("notes = %v, want assembly and module names", d.Notes)
	}
	if !strings.Contains(notes, "ecma335: 2 typedefs, 3 methods") {
		t.Fatalf("notes = %v, want the TypeDef/MethodDef counts", d.Notes)
	}
	if len(d.Deps) != 2 || d.Deps[0].Path != "System.Runtime" || d.Deps[0].Version != "4.0.0.0" ||
		d.Deps[1].Path != "System.Text.Json" || d.Deps[1].Version != "4.0.0.0" {
		t.Fatalf("deps = %+v, want the two AssemblyRef identities", d.Deps)
	}
	if len(d.Imports) != 1 || d.Imports[0] != "Acme.Core.Widget" {
		t.Fatalf("imports = %v", d.Imports)
	}
	if !skippedReasons(d)["no-disassembler"] {
		t.Fatalf("skipped = %v, want no-disassembler for the 3 undecoded IL bodies", d.Skipped)
	}
}

func TestProbeDotNetTables(t *testing.T) {
	d, err := Probe(buildTablesPE(t, managedTablesFixture(t)))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if d.Kind != "pe-dotnet" {
		t.Fatalf("kind = %q, want pe-dotnet", d.Kind)
	}
	if !containsStr(d.Imports, "Acme.Core.Widget") {
		t.Fatalf("imports = %v, want the TypeDef full name", d.Imports)
	}
	for _, cap := range []string{"ecma335:typedefs=2", "ecma335:methoddefs=3", "ecma335:assemblyrefs=2"} {
		if !containsStr(d.Capabilities, cap) {
			t.Fatalf("capabilities = %v, want %s", d.Capabilities, cap)
		}
	}
	if d.Coverage == nil || d.Coverage.Parsed < 5 {
		t.Fatalf("coverage = %+v, want the five row groups counted", d.Coverage)
	}
	if notes := strings.Join(d.Notes, "\n"); !strings.Contains(notes, "assembly: Demo 1.2.3.4") {
		t.Fatalf("notes = %v, want the assembly version", d.Notes)
	}
	if len(d.Deps) != 2 || d.Deps[0].Path != "System.Runtime" || d.Deps[0].Version != "4.0.0.0" {
		t.Fatalf("deps = %+v, want AssemblyRef names and versions", d.Deps)
	}
}

func TestCLITablesVersionGate(t *testing.T) {
	meta := tablesMeta(2, 0, "#~", buildTableStream(0, nil, nil), []byte{0})
	md, ok := parseMetadata(meta)
	if !ok {
		t.Fatal("parseMetadata rejected the fixture root")
	}
	d := Digest{}
	if tab := parseCLITables(md, &d); tab.ok {
		t.Fatal("parseCLITables accepted a root version it should refuse")
	}
	if len(d.Skipped) != 1 || d.Skipped[0].Reason != "ecma335-metadata-invalid" {
		t.Fatalf("skipped = %+v, want ecma335-metadata-invalid", d.Skipped)
	}
}

func TestCLITablesUncompressedStream(t *testing.T) {
	meta := tablesMeta(1, 1, "#-", buildTableStream(0, nil, nil), []byte{0})
	md, _ := parseMetadata(meta)
	d := Digest{}
	if tab := parseCLITables(md, &d); !tab.ok {
		t.Fatalf("parseCLITables refused #-: %+v", d.Skipped)
	}
}

// TestCLITableSchemaCoverage walks every ECMA-335 table id and proves the
// schema names resolve, so a row-count walk never meets an untyped column.
func TestCLITableSchemaCoverage(t *testing.T) {
	var rows [0x2D]int
	known := func(s string) bool {
		switch s {
		case "u2", "u4", "str", "guid", "blob":
			return true
		}
		if _, ok := tableColumn[s]; ok {
			return true
		}
		_, ok := codedTagTables[s]
		return ok
	}
	for id := 0; id <= 0x2C; id++ {
		if len(tableSchema[id]) == 0 {
			t.Fatalf("table %#x has no layout", id)
		}
		for _, spec := range tableSchema[id] {
			if !known(spec) {
				t.Fatalf("table %#x names unknown column %q", id, spec)
			}
		}
		w, _ := colWidths(tableSchema[id], 0, &rows)
		for i, x := range w {
			if x != 2 && x != 4 {
				t.Fatalf("table %#x col %d width = %d, want 2 or 4", id, i, x)
			}
		}
	}
	for name, tags := range codedTagTables {
		for _, id := range tags {
			if id > 0x2C {
				t.Fatalf("coded index %s points past GenericParamConstraint: %#x", name, id)
			}
		}
	}
}

// TestCLITableCodedWidths pins the coded-index width rule: tag bits come from
// the tag count, and the index goes wide once a target table crosses 2^(16-bits).
func TestCLITableCodedWidths(t *testing.T) {
	var rows [0x2D]int
	if w := colWidth("TypeDefOrRef", 0, &rows); w != 2 {
		t.Fatalf("TypeDefOrRef width = %d, want 2", w)
	}
	rows[0x02] = 0x4000
	if w := colWidth("TypeDefOrRef", 0, &rows); w != 4 {
		t.Fatalf("TypeDefOrRef width = %d at 0x4000 TypeDefs, want 4", w)
	}
	if w := colWidth("TypeOrMethodDef", 0, &rows); w != 2 {
		t.Fatalf("TypeOrMethodDef width = %d, want 2", w)
	}
	rows[0x23] = 0x4000
	if w := colWidth("Implementation", 0, &rows); w != 4 {
		t.Fatalf("Implementation width = %d at 0x4000 AssemblyRefs, want 4", w)
	}
	if w := colWidth("str", 1, &rows); w != 4 {
		t.Fatalf("string heap width = %d with the 4-byte bit, want 4", w)
	}
}

// TestCLITablesLateTableTruncated proves the row walk sizes the tables past
// AssemblyRef too, so a late row group cannot hide a short stream.
func TestCLITablesLateTableTruncated(t *testing.T) {
	meta := tablesMeta(1, 1, "#~", buildTableStream(0, map[int]int{0x2C: 1000}, nil), []byte{0})
	md, _ := parseMetadata(meta)
	d := Digest{}
	if tab := parseCLITables(md, &d); tab.ok {
		t.Fatal("parseCLITables decoded GenericParamConstraint rows past the stream end")
	}
	if len(d.Skipped) != 1 || d.Skipped[0].Reason != "ecma335-truncated" {
		t.Fatalf("skipped = %+v, want ecma335-truncated", d.Skipped)
	}
}

func TestCLITablesTruncated(t *testing.T) {
	ts := buildTableStream(0, map[int]int{0x02: 1000}, nil)
	meta := tablesMeta(1, 1, "#~", ts, []byte{0})
	md, _ := parseMetadata(meta)
	d := Digest{}
	if tab := parseCLITables(md, &d); tab.ok {
		t.Fatal("parseCLITables decoded rows past the stream end")
	}
	if len(d.Skipped) != 1 || d.Skipped[0].Reason != "ecma335-truncated" {
		t.Fatalf("skipped = %+v, want ecma335-truncated", d.Skipped)
	}
}

// TestCLITablesHeapWidths proves the row widths follow the 4-byte heap-size
// bits instead of assuming 2-byte string indexes.
func TestCLITablesHeapWidths(t *testing.T) {
	h := newTestHeap()
	module := h.add("Wide.dll")
	typeName := h.add("Panel")
	typeNS := h.add("Acme.Wide")
	method := h.add("Draw")
	asm := h.add("Wide")

	w := &rowWriter{wide: true}
	w.u16(0)
	w.idx(module)
	w.idx(1)
	w.idx(0)
	w.idx(0)
	w.u32(0x100001)
	w.idx(typeName)
	w.idx(typeNS)
	w.u16(1)
	w.u16(1)
	w.u16(1)
	w.u32(0x2050)
	w.u16(0)
	w.u16(6)
	w.idx(method)
	w.idx(1)
	w.u16(1)
	w.u32(0x8004)
	w.u16(2)
	w.u16(0)
	w.u16(0)
	w.u16(0)
	w.u32(0)
	w.idx(0)
	w.idx(asm)
	w.idx(0)

	rows := map[int]int{0x00: 1, 0x02: 1, 0x06: 1, 0x20: 1}
	meta := tablesMeta(1, 1, "#~", buildTableStream(7, rows, w.b), h.b)
	md, _ := parseMetadata(meta)
	d := Digest{}
	tab := parseCLITables(md, &d)
	if !tab.ok {
		t.Fatalf("parseCLITables refused: %+v", d.Skipped)
	}
	if tab.module != "Wide.dll" || tab.assembly != "Wide 2.0.0.0" {
		t.Fatalf("module/assembly = %q/%q", tab.module, tab.assembly)
	}
	if strings.Join(tab.typedefs, ",") != "Acme.Wide.Panel" {
		t.Fatalf("typedefs = %v", tab.typedefs)
	}
}

// buildTablesPE wraps metadata in the same minimal PE32+ image buildPEWithMeta
// writes; the name keeps the op tests' fixture label.
func buildTablesPE(t *testing.T, meta []byte) string {
	t.Helper()
	return buildPEWithMeta(t, "tables.exe", meta, true)
}

// The table fixture carries the <Module> row every real writer emits and opens
// both owner lists there, so the member op must attribute every MethodDef to
// the TypeDef that owns it instead of dropping the ones whose owner is unnamed.
func TestManagedMembersFixtureOwners(t *testing.T) {
	path := buildPEWithMeta(t, "members.exe", managedTablesFixture(t), true)
	res, err := runOp("inspect_managed_members", path)
	if err != nil {
		t.Fatalf("inspect_managed_members: %v", err)
	}
	b, err := json.Marshal(res)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got struct {
		Types   int `json:"types"`
		Methods int `json:"methods"`
		Rows    []struct {
			Type    string   `json:"type"`
			Methods int      `json:"methods"`
			Names   []string `json:"method_names"`
		} `json:"rows"`
	}
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal %s: %v", b, err)
	}
	if got.Types != 2 || got.Methods != 3 {
		t.Fatalf("types/methods = %d/%d, want 2/3 (%s)", got.Types, got.Methods, b)
	}
	owner := map[string]string{}
	for _, r := range got.Rows {
		for _, n := range r.Names {
			owner[n] = r.Type
		}
	}
	for _, m := range []string{"Run", "Stop", ".ctor"} {
		if owner[m] != "Acme.Core.Widget" {
			t.Fatalf("method %s owner = %q, want Acme.Core.Widget (%s)", m, owner[m], b)
		}
	}
}
