package main

// Fixtures for the metadata-level inventory items. Every fixture is assembled
// byte by byte in t.TempDir(): no device, no network, no shipped sample.

import (
	"encoding/binary"
	"encoding/json"
	"fmt"

	"os"
	"path/filepath"
	"strings"
	"testing"
)

// metaBRes round-trips the op's JSON so the test asserts on the documented
// wire shape instead of on a duplicate of the op's private struct type.
func metaBRes(t *testing.T, raw any, dst any) {
	t.Helper()
	b, err := json.Marshal(raw)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	if err := json.Unmarshal(b, dst); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
}

// metaBPInvokeMeta is the smallest assembly that declares one P/Invoke:
// ModuleRef KERNEL32.dll <- ImplMap MessageBoxW <- MethodDef at RVA 0x1080.
func metaBPInvokeMeta(t *testing.T) []byte {
	t.Helper()
	h := newTestHeap()
	name := h.add("Native")
	ns := h.add("Acme")
	method := h.add("Say")
	module := h.add("KERNEL32.dll")
	importName := h.add("MessageBoxW")

	w := &rowWriter{}
	// TypeDef: flags, name, namespace, extends, FieldList, MethodList.
	w.u32(0x1001)
	w.idx(name)
	w.idx(ns)
	w.idx(0)
	w.idx(1)
	w.idx(1)
	// MethodDef: RVA 0x1080, impl flags, flags, name, signature, ParamList.
	w.u32(0x1080)
	w.u16(0)
	w.u16(0x0006)
	w.idx(method)
	w.idx(0)
	w.u16(1)
	// ModuleRef: name.
	w.idx(module)
	// ImplMap: flags, MemberForwarded((1<<1)|1 = MethodDef rid 1), ImportName, ImportScope.
	w.u16(0x0104) // cdecl | charset ansi
	w.idx(3)
	w.idx(importName)
	w.idx(1)

	rows := map[int]int{0x02: 1, 0x06: 1, 0x1A: 1, 0x1C: 1}
	return tablesMeta(1, 1, "#~", buildTableStream(0, rows, w.b), h.b)
}

// metaBBuildPInvokePE lays out a PE32+ image with a CLI header, one .text
// section, a one-entry import directory (KERNEL32!MessageBoxW) and the P/Invoke
// thunk `jmp qword ptr [base+0x1180]` at the MethodDef RVA.
// metaBPInvokeMetaN declares n P/Invokes: n MethodDefs, each forwarded by its
// own ImplMap row against ModuleRef 1, so the listing cap has rows to cut.
func metaBPInvokeMetaN(t *testing.T, n int) []byte {
	t.Helper()
	h := newTestHeap()
	name := h.add("Native")
	ns := h.add("Acme")
	module := h.add("KERNEL32.dll")
	importName := h.add("MessageBoxW")

	w := &rowWriter{}
	// TypeDef: flags, name, namespace, extends, FieldList, MethodList.
	w.u32(0x1001)
	w.idx(name)
	w.idx(ns)
	w.idx(0)
	w.idx(1)
	w.idx(1)
	for i := range n {
		// MethodDef: RVA 0x1080, impl flags, flags, name, signature, ParamList.
		w.u32(0x1080)
		w.u16(0)
		w.u16(0x0006)
		w.idx(h.add(fmt.Sprintf("Say%d", i)))
		w.idx(0)
		w.u16(1)
	}
	// ModuleRef: name.
	w.idx(module)
	for i := 1; i <= n; i++ {
		// ImplMap: flags, MemberForwarded(MethodDef rid i), ImportName, ImportScope.
		w.u16(0x0104)
		w.idx(uint32(i<<1) | 1)
		w.idx(importName)
		w.idx(1)
	}

	rows := map[int]int{0x02: 1, 0x06: n, 0x1A: 1, 0x1C: n}
	return tablesMeta(1, 1, "#~", buildTableStream(0, rows, w.b), h.b)
}

func metaBBuildPInvokePE(t *testing.T, meta []byte) string {
	t.Helper()
	const (
		base    = 0x140000000
		cliRVA  = 0x1000
		bodyRVA = 0x1080
		iatRVA  = 0x1180
		metaRVA = 0x1400
	)
	// The one section spans the CLI header through the metadata root, so its
	// size follows the metadata blob instead of a fixed 0x600.
	rawSize := 0x400 + (len(meta)+0x1ff)&^0x1ff
	img := make([]byte, 0x200+rawSize)
	copy(img, "MZ")
	binary.LittleEndian.PutUint32(img[0x3c:], 0x40)
	copy(img[0x40:], "PE\x00\x00")
	coff := img[0x44:]
	binary.LittleEndian.PutUint16(coff[0:], 0x8664)
	binary.LittleEndian.PutUint16(coff[2:], 1)
	binary.LittleEndian.PutUint16(coff[16:], 240)
	binary.LittleEndian.PutUint16(coff[18:], 0x0022)

	opt := coff[20:]
	binary.LittleEndian.PutUint16(opt[0:], 0x20b)
	binary.LittleEndian.PutUint64(opt[24:], base)
	binary.LittleEndian.PutUint32(opt[32:], 0x1000)
	binary.LittleEndian.PutUint32(opt[36:], 0x200)
	binary.LittleEndian.PutUint32(opt[56:], uint32(0x1000+rawSize))
	binary.LittleEndian.PutUint32(opt[60:], 0x200)
	binary.LittleEndian.PutUint16(opt[68:], 3)
	binary.LittleEndian.PutUint32(opt[108:], 16)
	binary.LittleEndian.PutUint32(opt[112+8:], 0x1100) // import directory
	binary.LittleEndian.PutUint32(opt[112+12:], 40)
	binary.LittleEndian.PutUint32(opt[112+14*8:], cliRVA)
	binary.LittleEndian.PutUint32(opt[112+14*8+4:], 0x48)

	sec := img[0x148:]
	copy(sec, ".text")
	binary.LittleEndian.PutUint32(sec[8:], uint32(rawSize))
	binary.LittleEndian.PutUint32(sec[12:], 0x1000)
	binary.LittleEndian.PutUint32(sec[16:], uint32(rawSize))
	binary.LittleEndian.PutUint32(sec[20:], 0x200)
	binary.LittleEndian.PutUint32(sec[36:], 0x60000020)

	file := func(rva int) int { return 0x200 + rva - 0x1000 }
	cli := img[file(cliRVA):]
	binary.LittleEndian.PutUint32(cli[0:], 0x48)
	binary.LittleEndian.PutUint32(cli[8:], metaRVA)
	binary.LittleEndian.PutUint32(cli[12:], uint32(len(meta)))
	binary.LittleEndian.PutUint32(cli[16:], 1)

	body := img[file(bodyRVA):]
	body[0] = 6<<2 | 2 // tiny header, six code bytes
	code := bodyRVA + 1
	body[1], body[2] = 0xFF, 0x25
	binary.LittleEndian.PutUint32(body[3:], uint32(iatRVA-(code+6)))

	desc := img[file(0x1100):]
	binary.LittleEndian.PutUint32(desc[0:], 0x1170)  // OriginalFirstThunk
	binary.LittleEndian.PutUint32(desc[12:], 0x1140) // Name
	binary.LittleEndian.PutUint32(desc[16:], iatRVA)
	copy(img[file(0x1140):], "KERNEL32.dll\x00")
	binary.LittleEndian.PutUint64(img[file(0x1170):], 0x1190)
	binary.LittleEndian.PutUint64(img[file(iatRVA):], 0x1190)
	copy(img[file(0x1190)+2:], "MessageBoxW\x00")

	copy(img[file(metaRVA):], meta)
	return writeTemp(t, "pinvoke.exe", img)
}

func TestMetaBVerifyManagedNativeBoundaries(t *testing.T) {
	if testing.Short() {
		t.Skip("fixture assembly")
	}
	path := metaBBuildPInvokePE(t, metaBPInvokeMeta(t))
	raw, err := runOp("verify_managed_native_boundaries", path)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	var res struct {
		Boundaries int    `json:"boundaries"`
		Verified   int    `json:"verified"`
		Imports    int    `json:"pe_imports"`
		Note       string `json:"note,omitempty"`
		Rows       []struct {
			Managed   string `json:"managed"`
			Native    string `json:"native"`
			Module    string `json:"module"`
			CallConv  string `json:"call_conv"`
			MethodRVA uint32 `json:"method_rva"`
			Thunk     string `json:"thunk"`
			Slot      uint64 `json:"iat_slot,omitempty"`
			Verified  bool   `json:"verified"`
			Note      string `json:"note,omitempty"`
		} `json:"rows"`
	}
	metaBRes(t, raw, &res)
	if res.Boundaries != 1 || res.Verified != 1 || res.Imports != 1 {
		t.Fatalf("boundaries/verified/imports = %d/%d/%d, want 1/1/1 (%+v)", res.Boundaries, res.Verified, res.Imports, res)
	}
	if len(res.Rows) != 1 {
		t.Fatalf("rows = %d", len(res.Rows))
	}
	r := res.Rows[0]
	if r.Managed != "Acme.Native::Say" || r.Native != "MessageBoxW" || r.Module != "KERNEL32.dll" {
		t.Fatalf("row identity = %+v", r)
	}
	if r.CallConv != "cdecl" || r.MethodRVA != 0x1080 || r.Slot != 0x140001180 {
		t.Fatalf("row thunk = %+v", r)
	}
	if r.Thunk != "ff 25 f9 00 00 00" {
		t.Fatalf("thunk bytes = %q", r.Thunk)
	}
}

func TestMetaBVerifyManagedNativeBoundariesRejectsNonPE(t *testing.T) {
	path := filepath.Join(t.TempDir(), "plain.bin")
	if err := os.WriteFile(path, []byte("not a PE image at all"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := runOp("verify_managed_native_boundaries", path); err == nil || !strings.Contains(err.Error(), "not a PE image") {
		t.Fatalf("non-PE input error = %v, want a PE-shaped refusal", err)
	}
}

func TestMetaBVerifyManagedNativeBoundariesRejectsTruncated(t *testing.T) {
	path := metaBBuildPInvokePE(t, metaBPInvokeMeta(t))
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Cut inside the section headers: the metadata root can no longer be mapped.
	cut := filepath.Join(t.TempDir(), "cut.exe")
	if err := os.WriteFile(cut, b[:0x300], 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := runOp("verify_managed_native_boundaries", cut); err == nil ||
		!strings.Contains(err.Error(), "metadata root at RVA") || !strings.Contains(err.Error(), "outside every section") {
		t.Fatalf("truncated image error = %v, want the unmapped metadata root", err)
	}
}

// metaBDex assembles a dex with two classes and three real code items, so both
// the class index and the invoke-based call edges have something to find.
func metaBDex(t *testing.T) string {
	t.Helper()
	strs := []string{
		"Lcom/example/A;", "Lcom/example/B;", "Ljava/lang/Object;",
		"run", "<init>", "foo", "bar",
	}
	types := []uint32{0, 1, 2} // A, B, Object
	methods := []dexMethodRef{ // class_idx is a type_id index
		{classIdx: 0, nameIdx: 3}, // 0: A.run
		{classIdx: 0, nameIdx: 4}, // 1: A.<init>
		{classIdx: 1, nameIdx: 5}, // 2: B.foo
		{classIdx: 1, nameIdx: 6}, // 3: B.bar
	}

	strTab := 0x70
	typTab := strTab + 4*len(strs)
	metTab := typTab + 4*len(types)
	clsTab := metTab + 8*len(methods)
	data := clsTab + 32*2

	code := func(invokeIdx int) []byte {
		var out []byte
		if invokeIdx >= 0 {
			out = append(out,
				0x71, 0, // invoke-static (35c, 1 arg word slot)
				byte(invokeIdx), 0, // method_id
				0, 0, // argument words
			)
		}
		out = append(out, 0x0e, 0) // return-void
		b := make([]byte, 16)
		binary.LittleEndian.PutUint32(b[12:], uint32(len(out)/2))
		return append(b, out...)
	}
	codeRun, codeFoo, codeBar := code(2), code(-1), code(0)

	var body []byte
	offRun := data
	body = append(body, codeRun...)
	offFoo := data + len(body)
	body = append(body, codeFoo...)
	offBar := data + len(body)
	body = append(body, codeBar...)

	classData := func(entries [][3]int) []byte {
		out := []byte{0, 0, byte(len(entries)), 0} // no fields, all direct methods
		prev := 0
		for _, e := range entries {
			out = append(out, dexULEBEnc(e[0]-prev)...)
			out = append(out, dexULEBEnc(e[1])...)
			out = append(out, dexULEBEnc(e[2])...)
			prev = e[0]
		}
		return out
	}
	cdA := data + len(body)
	body = append(body, classData([][3]int{{0, 1, offRun}, {1, 1, 0}})...)
	cdB := data + len(body)
	body = append(body, classData([][3]int{{2, 1, offFoo}, {3, 1, offBar}})...)

	strOff := make([]int, len(strs))
	for i, s := range strs {
		strOff[i] = data + len(body)
		units := make([]uint16, len(s))
		for j := range s {
			units[j] = uint16(s[j])
		}
		body = append(body, dexULEBEnc(len(units))...)
		body = append(body, dexMUTF8Enc(units)...)
		body = append(body, 0)
	}

	b := make([]byte, data+len(body))
	copy(b[data:], body)
	copy(b, "dex\n035\x00")
	le := binary.LittleEndian
	le.PutUint32(b[0x24:], 0x70)
	le.PutUint32(b[0x28:], 0x12345678)
	le.PutUint32(b[0x38:], uint32(len(strs)))
	le.PutUint32(b[0x3C:], uint32(strTab))
	le.PutUint32(b[0x40:], uint32(len(types)))
	le.PutUint32(b[0x44:], uint32(typTab))
	le.PutUint32(b[0x58:], uint32(len(methods)))
	le.PutUint32(b[0x5C:], uint32(metTab))
	le.PutUint32(b[0x60:], 2)
	le.PutUint32(b[0x64:], uint32(clsTab))
	le.PutUint32(b[0x68:], uint32(len(body)))
	le.PutUint32(b[0x6C:], uint32(data))
	for i, off := range strOff {
		le.PutUint32(b[strTab+4*i:], uint32(off))
	}
	for i, idx := range types {
		le.PutUint32(b[typTab+4*i:], idx)
	}
	for i, m := range methods {
		at := metTab + 8*i
		le.PutUint16(b[at:], m.classIdx)
		le.PutUint16(b[at+2:], m.protoIdx)
		le.PutUint32(b[at+4:], m.nameIdx)
	}
	for i, c := range []struct{ classIdx, superIdx uint32 }{{0, 2}, {1, 2}} {
		at := clsTab + 32*i
		le.PutUint32(b[at:], c.classIdx)
		le.PutUint32(b[at+8:], c.superIdx)
	}
	le.PutUint32(b[clsTab+24:], uint32(cdA))
	le.PutUint32(b[clsTab+32+24:], uint32(cdB))
	return writeTemp(t, "classes.dex", dexSeal(b))
}

func TestMetaBSearchAndroidClasses(t *testing.T) {
	t.Setenv("LRECON_QUERY", "com.example")
	path := metaBDex(t)
	raw, err := runOp("search_android_classes", path)
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	var res struct {
		Query   string `json:"query"`
		Strings int    `json:"string_ids"`
		Types   int    `json:"type_ids"`
		Matches int    `json:"class_matches"`
		Hits    []struct {
			Index uint32 `json:"string_idx"`
			Value string `json:"value"`
		} `json:"string_hits"`
		Classes []struct {
			Descriptor string `json:"descriptor"`
			TypeIdx    uint32 `json:"type_idx"`
			Access     uint32 `json:"access,omitempty"`
			Super      string `json:"super,omitempty"`
			Classes    int    `json:"class_defs"`
			Methods    int    `json:"methods"`
			Fields     int    `json:"fields"`
		} `json:"classes"`
	}
	metaBRes(t, raw, &res)
	if res.Strings != 7 || res.Types != 3 {
		t.Fatalf("tables = %d strings / %d types", res.Strings, res.Types)
	}
	if res.Matches != 2 || len(res.Classes) != 2 {
		t.Fatalf("matches = %d %+v", res.Matches, res.Classes)
	}
	a, b := res.Classes[0], res.Classes[1]
	if a.Descriptor != "Lcom/example/A;" || b.Descriptor != "Lcom/example/B;" {
		t.Fatalf("descriptors = %q %q", a.Descriptor, b.Descriptor)
	}
	if a.Super != "Ljava/lang/Object;" || a.Classes != 1 || a.Methods != 2 || a.Fields != 0 {
		t.Fatalf("class A = %+v", a)
	}
	if len(res.Hits) != 2 {
		t.Fatalf("string hits = %+v", res.Hits)
	}
}

func TestMetaBTraceAndroidReferences(t *testing.T) {
	t.Setenv("LRECON_QUERY", "com.example.B")
	raw, err := runOp("trace_android_references", metaBDex(t))
	if err != nil {
		t.Fatalf("trace: %v", err)
	}
	var res struct {
		Query     string   `json:"query"`
		Classes   int      `json:"class_defs"`
		Methods   int      `json:"methods_with_code"`
		CodeItems int      `json:"code_items"`
		Edges     int      `json:"edges"`
		Nodes     []string `json:"nodes"`
		Callers   []struct {
			From string `json:"from"`
			To   string `json:"to"`
		} `json:"callers"`
		Callees []struct {
			From string `json:"from"`
			To   string `json:"to"`
		} `json:"callees"`
	}
	metaBRes(t, raw, &res)
	if res.Classes != 2 || res.Methods != 3 || res.CodeItems != 3 || res.Edges != 2 {
		t.Fatalf("scan = %+v", res)
	}
	if len(res.Callers) != 1 || res.Callers[0].From != "Lcom/example/A;->run" || res.Callers[0].To != "Lcom/example/B;->foo" {
		t.Fatalf("callers = %+v", res.Callers)
	}
	if len(res.Callees) != 1 || res.Callees[0].From != "Lcom/example/B;->bar" || res.Callees[0].To != "Lcom/example/A;->run" {
		t.Fatalf("callees = %+v", res.Callees)
	}
}

func TestMetaBTraceAndroidReferencesRejectsTruncatedClassData(t *testing.T) {
	t.Setenv("LRECON_QUERY", "com.example")
	path := metaBDex(t)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Point class_def A's class_data at the very end of the file.
	binary.LittleEndian.PutUint32(b[0x64+24:], uint32(len(b)-1))
	cut := filepath.Join(t.TempDir(), "cut.dex")
	if err := os.WriteFile(cut, dexSeal(b), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := runOp("trace_android_references", cut); err == nil ||
		!strings.Contains(err.Error(), "class_def 0 method_id 0 unreadable") {
		t.Fatalf("cut class_data error = %v, want the unreadable class_def", err)
	}
}

// metaBBundle lays out a BOMStore bundle: CARHEADER, a RENDITIONS tree with a
// PDF rendition and an LZFSE-compressed one, and a FACETKEYS tree naming it.
func metaBBundle(t *testing.T) string {
	t.Helper()
	tree := func(child uint32) []byte {
		b := make([]byte, 24)
		copy(b, "tree")
		binary.BigEndian.PutUint32(b[4:], 1)
		binary.BigEndian.PutUint32(b[8:], child)
		binary.BigEndian.PutUint32(b[12:], 4096)
		binary.BigEndian.PutUint32(b[16:], 2)
		return b
	}
	leaf := func(pairs [][2]uint32) []byte {
		b := make([]byte, 12+8*len(pairs))
		binary.BigEndian.PutUint16(b[0:], 1)
		binary.BigEndian.PutUint16(b[2:], uint16(len(pairs)))
		for i, p := range pairs {
			binary.BigEndian.PutUint32(b[12+8*i:], p[0])
			binary.BigEndian.PutUint32(b[16+8*i:], p[1])
		}
		return b
	}
	istc := func(width, height, scale uint32, format, name, payload string) []byte {
		b := make([]byte, 0x80)
		copy(b, "ISTC")
		le := binary.LittleEndian
		le.PutUint32(b[4:], 1)
		le.PutUint32(b[0x0c:], width)
		le.PutUint32(b[0x10:], height)
		le.PutUint32(b[0x14:], scale)
		copy(b[0x18:], format)
		copy(b[0x28:], name+"\x00")
		copy(b[0x60:], payload)
		return b
	}
	key := func(id uint16) []byte {
		b := make([]byte, 16)
		binary.BigEndian.PutUint16(b[0:], 0x0055)
		binary.BigEndian.PutUint16(b[2:], 0x00b5)
		binary.BigEndian.PutUint16(b[4:], id)
		return b
	}
	header := make([]byte, 0x14+128)
	copy(header, "RATC")
	binary.LittleEndian.PutUint32(header[4:], 973)
	binary.LittleEndian.PutUint32(header[8:], 17)
	binary.LittleEndian.PutUint32(header[16:], 2)
	copy(header[0x14:], "@(#)PROGRAM:Test PROJECT:Test-1.0 [LAR]\x00")

	facetVal := append(make([]byte, 16), 0x36, 0xb2)
	blocks := [][]byte{
		{},
		header,
		tree(4),
		tree(6),
		leaf([][2]uint32{{9, 10}, {11, 12}}),
		{},
		leaf([][2]uint32{{8, 7}}),
		[]byte("icon\x00"),
		facetVal,
		istc(56, 56, 100, " FDP", "Icon.pdf", "%PDF-1.3"),
		key(0x36b2),
		istc(112, 112, 200, "BGRA", "Icon@2x", "bvx2 payload"),
		key(0x36b2),
	}

	// header | index | vars | blocks
	const hdrLen = 32
	idxLen := 4 + 8*len(blocks)
	var vars []byte
	for i, n := range []string{"CARHEADER", "RENDITIONS", "FACETKEYS"} {
		vars = binary.BigEndian.AppendUint32(vars, uint32(i+1))
		vars = append(vars, byte(len(n)))
		vars = append(vars, n...)
	}
	varsHdr := binary.BigEndian.AppendUint32(nil, 3)

	off := hdrLen + idxLen + 4 + len(vars)
	positions := make([][2]int, len(blocks))
	var body []byte
	for i, blk := range blocks {
		if i == 0 {
			continue
		}
		positions[i] = [2]int{off + len(body), len(blk)}
		body = append(body, blk...)
	}
	img := make([]byte, off+len(body))
	copy(img, "BOMStore")
	be := binary.BigEndian
	be.PutUint32(img[8:], 1)
	be.PutUint32(img[12:], uint32(len(blocks)))
	be.PutUint32(img[16:], hdrLen)
	be.PutUint32(img[20:], uint32(idxLen))
	be.PutUint32(img[24:], uint32(hdrLen+idxLen))
	be.PutUint32(img[28:], uint32(4+len(vars)))
	be.PutUint32(img[hdrLen:], uint32(len(blocks)))
	for i, p := range positions {
		be.PutUint32(img[hdrLen+4+8*i:], uint32(p[0]))
		be.PutUint32(img[hdrLen+8+8*i:], uint32(p[1]))
	}
	copy(img[hdrLen+idxLen:], varsHdr)
	copy(img[hdrLen+idxLen+4:], vars)
	copy(img[off:], body)
	return writeTemp(t, "Assets.car", img)
}

func TestMetaBOpenBundleResources(t *testing.T) {
	raw, err := runOp("open_bundle_resources", metaBBundle(t))
	if err != nil {
		t.Fatalf("bundle: %v", err)
	}
	var res struct {
		Container      string   `json:"container"`
		Version        uint32   `json:"version"`
		Blocks         int      `json:"blocks"`
		Vars           []string `json:"vars"`
		StorageVersion uint32   `json:"storage_version,omitempty"`
		MainVersion    string   `json:"main_version,omitempty"`
		Assets         []string `json:"assets"`
		Entries        []struct {
			Asset       string `json:"asset,omitempty"`
			Rendition   string `json:"rendition,omitempty"`
			Type        string `json:"type"`
			Compression string `json:"compression"`
			Offset      uint32 `json:"offset"`
			Size        uint32 `json:"size"`
			Width       uint32 `json:"width"`
			Height      uint32 `json:"height"`
			Scale       uint32 `json:"scale"`
		} `json:"entries"`
		TotalBytes uint64 `json:"total_bytes"`
	}
	metaBRes(t, raw, &res)
	if res.Container != "BOMStore" || res.Version != 1 || res.Blocks != 13 {
		t.Fatalf("container = %+v", res)
	}
	if res.StorageVersion != 17 || res.MainVersion != "@(#)PROGRAM:Test PROJECT:Test-1.0 [LAR]" {
		t.Fatalf("carheader = %d %q", res.StorageVersion, res.MainVersion)
	}
	if len(res.Assets) != 1 || res.Assets[0] != "icon" {
		t.Fatalf("assets = %v", res.Assets)
	}
	if len(res.Entries) != 2 {
		t.Fatalf("entries = %d", len(res.Entries))
	}
	pdf, img := res.Entries[0], res.Entries[1]
	if pdf.Asset != "icon" || pdf.Rendition != "Icon.pdf" || pdf.Type != "pdf" || pdf.Compression != "uncompressed" {
		t.Fatalf("pdf entry = %+v", pdf)
	}
	if pdf.Width != 56 || pdf.Height != 56 || pdf.Scale != 100 {
		t.Fatalf("pdf geometry = %+v", pdf)
	}
	if img.Type != "image" || img.Compression != "lzfse" || img.Scale != 200 {
		t.Fatalf("image entry = %+v", img)
	}
	if res.TotalBytes != uint64(pdf.Size)+uint64(img.Size) || res.TotalBytes != 0x80+0x80 {
		t.Fatalf("total bytes = %d", res.TotalBytes)
	}
	if pdf.Offset >= img.Offset {
		t.Fatalf("offsets not from the block table: %d %d", pdf.Offset, img.Offset)
	}
}

func TestMetaBOpenBundleResourcesRejectsBadInput(t *testing.T) {
	dir := t.TempDir()
	junk := filepath.Join(dir, "junk.car")
	if err := os.WriteFile(junk, []byte("BOMStore but far too short"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := runOp("open_bundle_resources", junk); err == nil {
		t.Fatal("truncated BOM header must be an error")
	}
	notCar := filepath.Join(dir, "not.car")
	if err := os.WriteFile(notCar, []byte("PNG\x00 not a bundle resource"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := runOp("open_bundle_resources", notCar)
	if err == nil {
		t.Fatal("foreign container must be an error")
	}
}

// The packed marker is an ISTC header prefix, so it is looked for in the header
// window only: a payload that happens to contain the same ASCII is image data,
// not a compression marker. Reading a 2 MiB payload to answer "unknown" was the
// measured cost this window removes.
func TestMetaBISTCPackedMarkerWindow(t *testing.T) {
	assets := map[string]string{}
	istc := func(tail int) []byte {
		b := make([]byte, 0x80+tail)
		copy(b, "ISTC")
		copy(b[0x18:], "BGRA")
		copy(b[0x28:], "Img\x00")
		return b
	}
	packed := istc(0)
	copy(packed[0x60:], "ZZZZPackedAsset-")
	if row, err := metaBISTC(packed, nil, assets); err != nil || row.Compression != "packed" {
		t.Fatalf("header marker = %+v %v, want packed", row, err)
	}
	deep := istc(2 << 20)
	copy(deep[0x80+(1<<20):], "ZZZZPackedAsset-")
	if row, err := metaBISTC(deep, nil, assets); err != nil || row.Compression != "unknown" {
		t.Fatalf("payload marker = %+v %v, want unknown", row, err)
	}
	lz := istc(0)
	copy(lz[0x60:], "bvx2")
	if row, err := metaBISTC(lz, nil, assets); err != nil || row.Compression != "lzfse" {
		t.Fatalf("bvx2 = %+v %v, want lzfse", row, err)
	}
}
