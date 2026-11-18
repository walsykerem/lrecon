package main

// The Mach-O half of inspect_kernel_module: a kext hands __kmod_info over as a
// section (or, on older toolchains, as a _kmod_info symbol in __DATA,__data).
// This builds the section form, so the name/version/id the op reads at
// op_inspect_kernel_module.go:93-98 are pinned to their documented offsets.
//
// The rest of the file covers lane A09's ops: the keyed-archive, model-artifact,
// managed-metadata, pcap and native-wrapper contracts, each pinned to the JSON
// field names the op table documents.

import (
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// kmodInfoRecord lays out struct kmod_info for a pointer width: next*, then
// info_version int32, id uint32, name[64], version[64]. The op must read
// info_version and id behind the next pointer, not at fixed offsets.
func kmodInfoRecord(ptr int, infoVer int32, id uint32, name, version string) []byte {
	b := make([]byte, ptr+8+128)
	le := binary.LittleEndian
	le.PutUint32(b[ptr:], uint32(infoVer))
	le.PutUint32(b[ptr+4:], id)
	copy(b[ptr+8:ptr+8+64], name)
	copy(b[ptr+8+64:], version)
	return b
}

func TestInspectKernelModuleMachoKmod(t *testing.T) {
	rec := kmodInfoRecord(8, 1, 0x1234, "com.example.driver", "2.4.1")
	img := objcMachO([]objcSect{{name: "__kmod_info", data: rec}})
	path := writeTemp(t, "ExampleKext", img)
	m := opStatic(t, "inspect_kernel_module", path)
	if got := opStaticStr(t, m, "os"); got != "macos" {
		t.Fatalf("os = %q, want macos", got)
	}
	if got := opStaticStr(t, m, "name"); got != "com.example.driver" {
		t.Fatalf("name = %q, want com.example.driver", got)
	}
	if got := opStaticStr(t, m, "version"); got != "2.4.1" {
		t.Fatalf("version = %q, want 2.4.1", got)
	}
	if got := opStaticNum(t, m, "info_version"); got != 1 {
		t.Fatalf("info_version = %d, want 1", got)
	}
	if got := opStaticNum(t, m, "id"); got != 0x1234 {
		t.Fatalf("id = %#x, want 0x1234", got)
	}
	if got := opStaticNum(t, m, "kmod_info_bytes"); got != len(rec) {
		t.Fatalf("kmod_info_bytes = %d, want %d", got, len(rec))
	}
}

// --- binary plist fixtures -------------------------------------------------

// a09PlistStr is an ASCII string object: marker 0x5n for a short payload, or
// 0x5F plus an integer count object once the payload no longer fits the nibble.
func a09PlistStr(s string) []byte {
	if len(s) < 15 {
		return append([]byte{0x50 | byte(len(s))}, s...)
	}
	return append([]byte{0x5F, 0x11, byte(len(s) >> 8), byte(len(s))}, s...)
}

// a09PlistDict takes refs for alternating keys and values and lays them out the
// way a bplist dict stores them: every key ref, then every value ref.
func a09PlistDict(kv ...int) []byte {
	n := len(kv) / 2
	b := []byte{0xD0 | byte(n)}
	for i := range n {
		b = append(b, byte(kv[2*i]))
	}
	for i := range n {
		b = append(b, byte(kv[2*i+1]))
	}
	return b
}

// a09PlistArray holds object references, one byte each (refSize 1).
func a09PlistArray(refs ...int) []byte {
	b := []byte{0xA0 | byte(len(refs))}
	for _, r := range refs {
		b = append(b, byte(r))
	}
	return b
}

// a09PlistUID is a UID object naming an index into $objects.
func a09PlistUID(i int) []byte { return []byte{0x80, byte(i)} }

// a09Bplist assembles the objects behind a bplist00 header plus offset table
// and trailer (offsetIntSize 1, refSize 1, one-byte offsets).
func a09Bplist(objs [][]byte, top int) []byte {
	b := []byte("bplist00")
	offs := make([]int, len(objs))
	for i, ob := range objs {
		offs[i] = len(b)
		b = append(b, ob...)
	}
	table := len(b)
	for _, o := range offs {
		b = append(b, byte(o))
	}
	tr := make([]byte, 32)
	tr[6] = 1 // offset int size
	tr[7] = 1 // object ref size
	binary.BigEndian.PutUint64(tr[8:], uint64(len(objs)))
	binary.BigEndian.PutUint64(tr[16:], uint64(top))
	binary.BigEndian.PutUint64(tr[24:], uint64(table))
	return append(b, tr...)
}

// a09Bld collects bplist objects so refs can point at real object-table slots.
type a09Bld struct{ objs [][]byte }

func (b *a09Bld) add(o []byte) int {
	b.objs = append(b.objs, o)
	return len(b.objs) - 1
}

func (b *a09Bld) str(s string) int      { return b.add(a09PlistStr(s)) }
func (b *a09Bld) dict(refs ...int) int  { return b.add(a09PlistDict(refs...)) }
func (b *a09Bld) array(refs ...int) int { return b.add(a09PlistArray(refs...)) }
func (b *a09Bld) uid(idx int) int       { return b.add(a09PlistUID(idx)) }

// a09PlistInt is a 4-byte signed integer object (100000 in $version).
func a09PlistInt(v uint32) []byte {
	return []byte{0x12, byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
}

// a09Archive builds a minimal NSKeyedArchiver: $objects[0] is the $null
// placeholder, [1] one instance of [2]'s class. $class is a UID naming the
// $objects index, not an object-table slot, so the UID must read 2.
func a09Archive() []byte {
	b := &a09Bld{}
	archiverK := b.str("$archiver")
	objectsK := b.str("$objects")
	versionK := b.str("$version")
	archiverV := b.str("NSKeyedArchiver")
	null := b.str("$null")
	classK := b.str("$class")
	classnameK := b.str("$classname")
	widget := b.str("Widget")
	versionV := b.add(a09PlistInt(100000))
	classDict := b.dict(classnameK, widget)
	instance := b.dict(classK, b.uid(2))
	objects := b.array(null, instance, classDict)
	top := b.dict(archiverK, archiverV, objectsK, objects, versionK, versionV)
	return a09Bplist(b.objs, top)
}

func TestInspectKeyedArchiveObjects(t *testing.T) {
	path := writeTemp(t, "archive.bplist", a09Archive())
	m := opStatic(t, "inspect_keyed_archive", path)
	if got := opStaticStr(t, m, "archiver"); got != "NSKeyedArchiver" {
		t.Fatalf("archiver = %q, want NSKeyedArchiver", got)
	}
	if got := opStaticNum(t, m, "objects"); got != 3 {
		t.Fatalf("objects = %d, want 3 ($null, instance, class)", got)
	}
	if got := opStaticNum(t, m, "classes"); got != 1 {
		t.Fatalf("classes = %d, want 1", got)
	}
	names, _ := m["class_names"].([]any)
	if len(names) != 1 || names[0] != "Widget" {
		t.Fatalf("class_names = %v, want [Widget]", m["class_names"])
	}
	hist, _ := m["class_histogram"].([]any)
	if len(hist) != 1 || hist[0] != "Widget=1" {
		t.Fatalf("class_histogram = %v, want [Widget=1]", m["class_histogram"])
	}
	keys, _ := m["top_keys"].([]any)
	if len(keys) != 3 {
		t.Fatalf("top_keys = %v, want 3 entries", m["top_keys"])
	}
}

func TestInspectKeyedArchiveEmptyObjects(t *testing.T) {
	b := &a09Bld{}
	archiverK := b.str("$archiver")
	objectsK := b.str("$objects")
	archiverV := b.str("NSKeyedArchiver")
	objects := b.array()
	top := b.dict(archiverK, archiverV, objectsK, objects)
	path := writeTemp(t, "empty.bplist", a09Bplist(b.objs, top))
	res, err := runOp("inspect_keyed_archive", path)
	if err != nil {
		t.Fatalf("inspect_keyed_archive: %v", err)
	}
	s, ok := res.(*skip)
	if !ok {
		t.Fatalf("result = %v, want a skip for an archive with no objects", res)
	}
	if !strings.Contains(s.Reason, "carries no $class references") {
		t.Fatalf("reason = %q, want the no-$class refusal", s.Reason)
	}
}

func TestInspectKeyedArchiveRejectsPlainPlist(t *testing.T) {
	path := opStaticFile(t, "plain", []byte("<?xml version=\"1.0\"?><plist/>"))
	_, err := runOp("inspect_keyed_archive", path)
	if err == nil || classify(err.Error()) != kindBadArg {
		t.Fatalf("err = %v, want bad_arg", err)
	}
	if !strings.Contains(err.Error(), path) {
		t.Fatalf("err = %q, want the target path", err)
	}
}

// --- model artifact fixtures ----------------------------------------------

// a09Safetensors writes an 8-byte header length, the JSON header padded to 8
// bytes and the raw data block.
func a09Safetensors(t *testing.T, hdr map[string]any, data []byte) []byte {
	t.Helper()
	raw, err := json.Marshal(hdr)
	if err != nil {
		t.Fatal(err)
	}
	for len(raw)%8 != 0 {
		raw = append(raw, ' ')
	}
	b := binary.LittleEndian.AppendUint64(nil, uint64(len(raw)))
	b = append(b, raw...)
	return append(b, data...)
}

func TestInspectModelArtifactSafetensors(t *testing.T) {
	body := a09Safetensors(t, map[string]any{
		"__metadata__": map[string]any{"format": "pt"},
		"w":            map[string]any{"dtype": "F32", "shape": []int{2, 2}, "data_offsets": []int{0, 16}},
	}, make([]byte, 16))
	path := opStaticFile(t, "model.safetensors", body)
	m := opStatic(t, "inspect_model_artifact", path)
	if got := opStaticStr(t, m, "format"); got != "safetensors" {
		t.Fatalf("format = %q, want safetensors", got)
	}
	if got := opStaticNum(t, m, "header_bytes"); got == 0 {
		t.Fatalf("header_bytes = %d, want the padded header length", got)
	}
	if got := opStaticNum(t, m, "data_bytes"); got != 16 {
		t.Fatalf("data_bytes = %d, want 16", got)
	}
	meta, _ := m["metadata"].(map[string]any)
	if meta["format"] != "pt" {
		t.Fatalf("metadata = %v, want __metadata__ lifted", meta)
	}
	tensors, _ := m["tensors"].([]any)
	if len(tensors) != 1 {
		t.Fatalf("tensors = %v, want one", m["tensors"])
	}
	tn, _ := tensors[0].(map[string]any)
	if tn["name"] != "w" || opStaticNum(t, tn, "elements") != 4 || opStaticNum(t, tn, "bytes") != 16 {
		t.Fatalf("tensor = %v, want w 4 elements / 16 bytes", tn)
	}
}

func TestInspectModelArtifactSafetensorsSpan(t *testing.T) {
	body := a09Safetensors(t, map[string]any{
		"w": map[string]any{"dtype": "F32", "shape": []int{1000}, "data_offsets": []int{0, 4000}},
	}, make([]byte, 8))
	path := opStaticFile(t, "span.safetensors", body)
	_, err := runOp("inspect_model_artifact", path)
	if err == nil || !strings.Contains(err.Error(), "spans 0..4000 of 8 data bytes") {
		t.Fatalf("err = %v, want the span refusal", err)
	}
}

// a09GGUF writes GGUF v3 with one string and one uint32 metadata entry and one
// F32 tensor.
func a09GGUF() []byte {
	le := binary.LittleEndian
	b := []byte("GGUF")
	b = le.AppendUint32(b, 3)
	b = le.AppendUint64(b, 1) // tensors
	b = le.AppendUint64(b, 2) // metadata entries
	putStr := func(s string) {
		b = le.AppendUint64(b, uint64(len(s)))
		b = append(b, s...)
	}
	putStr("general.architecture")
	b = le.AppendUint32(b, 8) // string
	putStr("llama")
	putStr("llama.block_count")
	b = le.AppendUint32(b, 4) // uint32
	b = le.AppendUint32(b, 32)
	putStr("token_embd.weight")
	b = le.AppendUint32(b, 2)             // n_dims
	b = le.AppendUint64(b, 4)             // dims
	b = le.AppendUint64(b, 2)             //
	b = le.AppendUint32(b, 0)             // F32
	b = le.AppendUint64(b, 0)             // offset
	return append(b, make([]byte, 32)...) // tensor data
}

func TestInspectModelArtifactGGUF(t *testing.T) {
	path := opStaticFile(t, "model.gguf", a09GGUF())
	m := opStatic(t, "inspect_model_artifact", path)
	if got := opStaticStr(t, m, "format"); got != "gguf" {
		t.Fatalf("format = %q, want gguf", got)
	}
	if got := opStaticNum(t, m, "version"); got != 3 {
		t.Fatalf("version = %d, want 3", got)
	}
	if got := opStaticNum(t, m, "tensor_count"); got != 1 {
		t.Fatalf("tensor_count = %d, want 1", got)
	}
	meta, _ := m["metadata"].([]any)
	if len(meta) != 2 {
		t.Fatalf("metadata = %v, want 2 entries", m["metadata"])
	}
	first, _ := meta[0].(map[string]any)
	if first["key"] != "general.architecture" || first["type"] != "string" || first["value"] != "llama" {
		t.Fatalf("metadata[0] = %v, want general.architecture=llama as a string", first)
	}
	tensors, _ := m["tensors"].([]any)
	if len(tensors) != 1 {
		t.Fatalf("tensors = %v, want one", m["tensors"])
	}
	tn, _ := tensors[0].(map[string]any)
	if tn["name"] != "token_embd.weight" || tn["ggml_type_name"] != "F32" {
		t.Fatalf("tensor = %v, want token_embd.weight as F32", tn)
	}
	shape, _ := tn["shape"].([]any)
	if len(shape) != 2 || shape[0] != float64(4) || shape[1] != float64(2) {
		t.Fatalf("shape = %v, want [4 2]", tn["shape"])
	}
}

// --- managed metadata fixture ---------------------------------------------

// a09ManagedPE builds a PE with a CLI header and ECMA-335 tables: two TypeDefs
// (Acme.Core.Widget and its nested Inner, one field, one method each), one
// ImplMap row pointing at Inner's Beep, one ModuleRef and one NestedClass row.
func a09ManagedPE(t *testing.T) string {
	t.Helper()
	h := newTestHeap()
	module := h.add("Demo.dll")
	widget := h.add("Widget")
	ns := h.add("Acme.Core")
	inner := h.add("Inner")
	field := h.add("Count")
	run := h.add("Run")
	beep := h.add("Beep")
	modref := h.add("kernel32.dll")

	var w rowWriter

	// 0x00 Module: u2 generation, str name, guid, guid, guid
	w.u16(0)
	w.idx(module)
	w.idx(0)
	w.idx(0)
	w.idx(0)
	moduleRow := w.b

	w = rowWriter{}
	// 0x02 TypeDef rows: u4 flags, str name, str namespace, coded extends,
	// FieldList, MethodList.
	typedef := func(flags uint32, name, space uint32, fieldList, methodList uint16) []byte {
		w = rowWriter{}
		w.u32(flags)
		w.idx(name)
		w.idx(space)
		w.idx(0)
		w.u16(fieldList)
		w.u16(methodList)
		return w.b
	}
	td := append(typedef(0x100001, widget, ns, 1, 1), typedef(0, inner, 0, 2, 2)...)

	w = rowWriter{}
	// 0x04 Field: u2 flags, str name, blob
	w.u16(0x8056)
	w.idx(field)
	w.idx(0)
	fieldRow := w.b

	method := func(name uint32) []byte {
		w = rowWriter{}
		w.u32(0x2050)
		w.u16(0)
		w.u16(0x1886) // public static pinvokeimpl
		w.idx(name)
		w.idx(0)
		w.u16(1)
		return w.b
	}
	md := append(method(run), method(beep)...)

	w = rowWriter{}
	// 0x1A ModuleRef: str
	w.idx(modref)
	modrefRow := w.b

	w = rowWriter{}
	// 0x1C ImplMap: u2 flags, MemberForwarded, str import name, ModuleRef
	w.u16(0x800)
	w.u16(uint16(2<<1 | 1)) // MethodDef 2 (Beep)
	w.idx(beep)
	w.u16(1)
	implMapRow := w.b

	w = rowWriter{}
	// 0x29 NestedClass: TypeDef, TypeDef
	w.u16(2)
	w.u16(1)
	nestedRow := w.b

	var tables []byte
	tables = append(tables, moduleRow...)
	tables = append(tables, td...)
	tables = append(tables, fieldRow...)
	tables = append(tables, md...)
	tables = append(tables, modrefRow...)
	tables = append(tables, implMapRow...)
	tables = append(tables, nestedRow...)

	stream := buildTableStream(0, map[int]int{
		0x00: 1, 0x02: 2, 0x04: 1, 0x06: 2, 0x1A: 1, 0x1C: 1, 0x29: 1,
	}, tables)
	meta := tablesMeta(2, 5, "#~", stream, h.b)
	return buildTablesPE(t, meta)
}

func TestInspectManagedArtifact(t *testing.T) {
	path := a09ManagedPE(t)
	m := opStatic(t, "inspect_managed_artifact", path)
	if got := opStaticStr(t, m, "kind"); got != "pe-dotnet" {
		t.Fatalf("kind = %q, want pe-dotnet", got)
	}
	if got := opStaticNum(t, m, "types"); got != 2 {
		t.Fatalf("types = %d, want 2", got)
	}
	if got := opStaticNum(t, m, "methods"); got != 2 {
		t.Fatalf("methods = %d, want 2", got)
	}
	if got := opStaticNum(t, m, "tables"); got != 7 {
		t.Fatalf("tables = %d, want 7", got)
	}
}

func TestInspectManagedMembers(t *testing.T) {
	path := a09ManagedPE(t)
	m := opStatic(t, "inspect_managed_members", path)
	if got := opStaticNum(t, m, "types"); got != 2 {
		t.Fatalf("types = %d, want 2", got)
	}
	rows, _ := m["rows"].([]any)
	if len(rows) != 2 {
		t.Fatalf("rows = %v, want 2", m["rows"])
	}
	first, _ := rows[0].(map[string]any)
	if first["type"] != "Acme.Core.Widget" {
		t.Fatalf("rows[0].type = %v, want Acme.Core.Widget", first["type"])
	}
	if opStaticNum(t, first, "fields") != 1 || opStaticNum(t, first, "methods") != 1 {
		t.Fatalf("rows[0] = %v, want 1 field / 1 method", first)
	}
	second, _ := rows[1].(map[string]any)
	if second["type"] != "Acme.Core.Widget+Inner" {
		t.Fatalf("rows[1].type = %v, want the nested Enclosing+Nested form", second["type"])
	}
	names, _ := second["method_names"].([]any)
	if len(names) != 1 || names[0] != "Beep" {
		t.Fatalf("method_names = %v, want [Beep]", second["method_names"])
	}
}

func TestInspectManagedNativeBoundaries(t *testing.T) {
	path := a09ManagedPE(t)
	m := opStatic(t, "inspect_managed_native_boundaries", path)
	if got := opStaticNum(t, m, "pinvokes"); got != 1 {
		t.Fatalf("pinvokes = %d, want 1", got)
	}
	mods, _ := m["modules"].([]any)
	if len(mods) != 1 || mods[0] != "kernel32.dll" {
		t.Fatalf("modules = %v, want [kernel32.dll]", m["modules"])
	}
	entries, _ := m["entries"].([]any)
	if len(entries) != 1 {
		t.Fatalf("entries = %v, want one", m["entries"])
	}
	e, _ := entries[0].(map[string]any)
	if e["managed"] != "Beep" || e["native"] != "Beep" || e["module"] != "kernel32.dll" || e["type"] != "Inner" {
		t.Fatalf("entry = %v, want Beep/Beep/kernel32.dll/Inner", e)
	}
}

func TestInspectManagedMembersRejectsPlainFile(t *testing.T) {
	path := opStaticFile(t, "plain.txt", []byte("not a PE image at all"))
	_, err := runOp("inspect_managed_members", path)
	if err == nil || classify(err.Error()) != kindBadArg {
		t.Fatalf("err = %v, want bad_arg", err)
	}
	if !strings.Contains(err.Error(), path) {
		t.Fatalf("err = %q, want the target path in front of the refusal", err)
	}
}

// --- pcap fixtures --------------------------------------------------------

// a09HTTPFrame is an Ethernet/IPv4/TCP frame carrying a raw HTTP request.
func a09HTTPFrame(req string) []byte {
	return frameIPv4(6, tcpSegment(80, []byte(req)))
}

func a09PCap() []byte {
	dns := frameIPv4(17, udpSegment(53, dnsQuery("example.com")))
	http := a09HTTPFrame("GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/8.4.0\r\nAccept: */*\r\n\r\n")
	tls := frameIPv4(6, tcpSegment(443, tlsClientHello("api.example.com")))
	return pcapLE(1, dns, http, tls)
}

func TestInspectPacketCapturePcap(t *testing.T) {
	path := opStaticFile(t, "app.pcap", a09PCap())
	m := opStatic(t, "inspect_packet_capture", path)
	if got := opStaticStr(t, m, "format"); got != "pcap" {
		t.Fatalf("format = %q, want pcap", got)
	}
	if got := opStaticNum(t, m, "packets"); got != 3 {
		t.Fatalf("packets = %d, want 3", got)
	}
	dnss, _ := m["dns"].([]any)
	if len(dnss) != 1 || dnss[0] != "example.com" {
		t.Fatalf("dns = %v, want [example.com]", m["dns"])
	}
	snis, _ := m["sni"].([]any)
	if len(snis) != 1 || snis[0] != "api.example.com" {
		t.Fatalf("sni = %v, want [api.example.com]", m["sni"])
	}
	uris, _ := m["uris"].([]any)
	if len(uris) != 1 || uris[0] != "/index.html" {
		t.Fatalf("uris = %v, want [/index.html]", m["uris"])
	}
}

func TestInspectPacketCaptureEmpty(t *testing.T) {
	path := opStaticFile(t, "empty.pcap", pcapLE(1))
	_, err := runOp("inspect_packet_capture", path)
	if err == nil || !strings.Contains(err.Error(), "has no packets") {
		t.Fatalf("err = %v, want the empty-capture refusal", err)
	}
}

func TestInspectPacketFieldsApp(t *testing.T) {
	path := opStaticFile(t, "app.pcap", a09PCap())
	m := opStatic(t, "inspect_packet_fields", path)
	frames, _ := m["frames"].([]any)
	if len(frames) != 3 {
		t.Fatalf("frames = %d, want 3", len(frames))
	}
	app, _ := m["app"].(map[string]any)
	if app["dns"] != float64(1) || app["http"] != float64(1) || app["tls"] != float64(1) {
		t.Fatalf("app = %v, want dns/http/tls 1 each", app)
	}
}

func TestInspectPcapClientFingerprints(t *testing.T) {
	path := opStaticFile(t, "app.pcap", a09PCap())
	m := opStatic(t, "inspect_pcap_client", path)
	http, _ := m["http_clients"].([]any)
	if len(http) != 1 {
		t.Fatalf("http_clients = %v, want one", m["http_clients"])
	}
	h, _ := http[0].(map[string]any)
	if h["host"] != "example.com" || h["method"] != "GET" || h["family"] != "curl" {
		t.Fatalf("http client = %v, want GET example.com / curl", h)
	}
	order, _ := h["header_order"].([]any)
	if len(order) != 3 || order[0] != "Host" || order[1] != "User-Agent" {
		t.Fatalf("header_order = %v, want [Host User-Agent Accept]", h["header_order"])
	}
	tls, _ := m["tls_clients"].([]any)
	if len(tls) != 1 {
		t.Fatalf("tls_clients = %v, want one", m["tls_clients"])
	}
	tc, _ := tls[0].(map[string]any)
	if tc["sni"] != "api.example.com" {
		t.Fatalf("tls sni = %v, want api.example.com", tc["sni"])
	}
	if _, ok := tc["ja3"].(string); !ok {
		t.Fatalf("ja3 = %v, want a string fingerprint", tc["ja3"])
	}
}

// --- native wrappers ------------------------------------------------------

func TestInspectNativeLoadImageRefusal(t *testing.T) {
	// The op refuses every target, but a path that is not there is an io error
	// before it is a refusal: stat runs first and every sibling op agrees.
	_, err := runOp("inspect_native_load_image", filepath.Join(t.TempDir(), "absent"))
	if err == nil || classify(err.Error()) != kindIO {
		t.Fatalf("missing target: err = %v, want io", err)
	}
	res, err := runOp("inspect_native_load_image", os.Args[0])
	if err != nil {
		t.Fatalf("existing target: %v", err)
	}
	s, ok := res.(*skip)
	if !ok || !strings.Contains(s.Reason, "reads on-disk headers only") {
		t.Fatalf("result = %v, want the load-image refusal", res)
	}
	if _, err := runOp("inspect_native_load_image", t.TempDir()); err == nil || classify(err.Error()) != kindIO {
		t.Fatalf("directory target: err = %v, want io", err)
	}
}

func TestInspectNativeExportsMachoRefusal(t *testing.T) {
	path := writeTemp(t, "thin", objcMachO(nil))
	res, err := runOp("inspect_native_exports", path)
	if err != nil {
		t.Fatalf("inspect_native_exports: %v", err)
	}
	s, ok := res.(*skip)
	if !ok || !strings.Contains(s.Reason, "covered by inspect_macho") {
		t.Fatalf("result = %v, want the inspect_macho handoff", res)
	}
	// A Mach-O handed to a PE/ELF reader is a wrong target, not an engine
	// failure: the handoff has to land in bad_arg without the caller seeing
	// "internal" and going looking for a broken install.
	if got := classify(s.Reason); got != kindBadArg {
		t.Fatalf("kind = %v, want bad_arg", got)
	}
}

func TestInspectManagedRefusesNativePE(t *testing.T) {
	// A PE with no CLI header is a native image, so both managed listings owe
	// the reader the same answer inspect_managed_artifact gives: not a managed
	// assembly, kind bad_arg, not an internal metadata failure.
	path := buildCLIPE(t, false)
	for _, op := range []string{"inspect_managed_members", "inspect_managed_native_boundaries"} {
		res, err := runOp(op, path)
		if err != nil {
			t.Fatalf("%s: %v", op, err)
		}
		s, ok := res.(*skip)
		if !ok || !strings.Contains(s.Reason, "is not a managed assembly") {
			t.Fatalf("%s: result = %v, want the not-a-managed-assembly refusal", op, res)
		}
		if got := classify(s.Reason); got != kindBadArg {
			t.Fatalf("%s: kind = %v, want bad_arg", op, got)
		}
	}
}

// TestInspectRefusalsAreBadArg pins the envelope contract for the whole lane:
// a target of the wrong shape is a bad argument, never "internal". The op
// table promises the kind, and classify reads the message text, so a reworded
// refusal that drops the phrase ("has no", "not a", "is not") silently turns
// into an internal error and sends the caller hunting for a broken install.
func TestInspectRefusalsAreBadArg(t *testing.T) {
	path := opStaticFile(t, "note.txt", []byte("just some text\n"))
	ops := []string{
		"inspect_keyed_archive", "inspect_macho", "inspect_managed_artifact",
		"inspect_managed_members", "inspect_managed_native_boundaries",
		"inspect_model_artifact", "inspect_native_api", "inspect_native_data_type",
		"inspect_native_dispatch_metadata", "inspect_native_exports",
		"inspect_native_instruction", "inspect_native_load_image",
		"inspect_packet_capture", "inspect_packet_fields", "inspect_pcap_capture",
		"inspect_pcap_client",
	}
	for _, op := range ops {
		res, err := runOp(op, path)
		reason := ""
		switch {
		case err != nil:
			reason = err.Error()
		default:
			s, ok := res.(*skip)
			if !ok {
				t.Fatalf("%s accepted a plain text file: %v", op, res)
			}
			reason = s.Reason
		}
		if got := classify(reason); got == kindInternal {
			t.Fatalf("%s: text target classifies internal: %s", op, reason)
		}
	}
}

func TestInspectMachoRejectsText(t *testing.T) {
	path := opStaticFile(t, "note.txt", []byte("just some text\n"))
	res, err := runOp("inspect_macho", path)
	if err != nil {
		t.Fatalf("inspect_macho: %v", err)
	}
	s, ok := res.(*skip)
	if !ok || !strings.Contains(s.Reason, "not Mach-O") {
		t.Fatalf("result = %v, want the not-Mach-O refusal", res)
	}
}

// BenchmarkInspectKeyedArchive pins the parse cost of the busiest owned op.
// It exists so a "no optimization" claim has a number behind it: the whole
// archive walk is microseconds, far under the file read and JSON encode.
func BenchmarkInspectKeyedArchive(b *testing.B) {
	path := filepath.Join(b.TempDir(), "archive.bplist")
	if err := os.WriteFile(path, a09Archive(), 0o600); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := runOp("inspect_keyed_archive", path); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkInspectManagedMembers is not here: its PE fixture comes from
// buildTablesPE(*testing.T) so it cannot run under *testing.B. The zeroed
// table walk it covers is the same shape as the archive walk above.
