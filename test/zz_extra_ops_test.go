package main

// Op-level coverage for paths no existing test reached: a real Objective-C
// class list, a source map given as the target, WASM import limits, zip script
// export with traversal and symlink members, Linux .modinfo, and static/runtime
// correlation against a thin Mach-O that actually carries an LC_UUID.

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// --- get_objc_classes ---

// objcClassListMachO lays out three sections whose addresses equal their file
// offsets: the class list (plain, chained-fixup and unmapped pointers), the
// class/class_ro records, and the name strings.
func objcClassListMachO() []byte {
	const (
		listSize = 3 * 8
		dataSize = 4 * 40 // classA, classB, roA, roB
		strSize  = 300
	)
	// Recompute objcMachO's offsets: 32-byte header + one 72-byte segment
	// command + 80 bytes per section, then 8-aligned bodies in order.
	cmdSize := 72 + 80*3
	base := 32 + cmdSize
	listOff := base
	dataOff := (listOff + listSize + 7) &^ 7
	strOff := (dataOff + dataSize + 7) &^ 7
	classA := dataOff
	classB := dataOff + 40
	roA := dataOff + 80
	roB := dataOff + 112

	list := make([]byte, listSize)
	binary.LittleEndian.PutUint64(list[0:], uint64(classA))
	binary.LittleEndian.PutUint64(list[8:], 1<<62|uint64(classB)) // chained-fixup encoding
	binary.LittleEndian.PutUint64(list[16:], 0xdead)              // maps nowhere
	data := make([]byte, dataSize)
	binary.LittleEndian.PutUint64(data[32:], uint64(roA)|3) // low bits are class_ro flags
	binary.LittleEndian.PutUint64(data[40+32:], uint64(roB))
	binary.LittleEndian.PutUint64(data[80+24:], uint64(strOff))    // Alpha
	binary.LittleEndian.PutUint64(data[112+24:], uint64(strOff+6)) // Beta
	strs := make([]byte, strSize)
	copy(strs, "Alpha\x00Beta\x00")
	return objcMachO([]objcSect{
		{name: "__objc_classlist", data: list},
		{name: "__data", data: data},
		{name: "__cstring", data: strs},
	})
}

func TestGetObjCClassesResolvesClassList(t *testing.T) {
	b := objcClassListMachO()
	path := writeTemp(t, "classes", b)
	f := metaMustRun(t, "get_objc_classes", path)
	if got := metaNum(t, f, "count"); got != 3 {
		t.Fatalf("count = %d, want 3 (two resolved, one unmapped)", got)
	}
	if got := metaNum(t, f, "unresolved"); got != 1 {
		t.Fatalf("unresolved = %d, want 1", got)
	}
	classes := numList(t, f["classes"])
	if !reflect.DeepEqual(classes, []string{"Alpha", "Beta"}) {
		t.Fatalf("classes = %v, want [Alpha Beta]", classes)
	}
}

// TestGetObjCClassesSkip pins the "no class list" envelope instead of treating
// an unsupported image as an error.
func TestGetObjCClassesSkip(t *testing.T) {
	path := writeTemp(t, "plain", objcMachO([]objcSect{{name: "__data", data: []byte("x")}}))
	m := metaMustRun(t, "get_objc_classes", path)
	if !strings.Contains(metaStr(t, m, "skipped"), "no Objective-C class list") {
		t.Fatalf("skip reason = %v", m)
	}
}

// --- trace_web_source_location ---

func TestTraceWebSourceLocationMapFile(t *testing.T) {
	const mappings = "AAAA,SAASA"
	body, err := json.Marshal(map[string]any{
		"version":    3,
		"file":       "out.js",
		"sourceRoot": "webpack:///",
		"sources":    []string{"src/app.ts"},
		"names":      []string{"foo"},
		"mappings":   mappings,
	})
	if err != nil {
		t.Fatal(err)
	}
	path := writeTemp(t, "out.js.map", body)
	f := fields(t, run(t, "trace_web_source_location", path))
	if f["version"] != float64(3) || f["segments"] != float64(2) || f["map"] != "out.js.map" {
		t.Fatalf("version/segments/map = %v/%v/%v", f["version"], f["segments"], f["map"])
	}
	if sources := numList(t, f["sources"]); !reflect.DeepEqual(sources, []string{"webpack:/src/app.ts"}) {
		t.Fatalf("sources = %v", sources)
	}
	rows := f["rows"].([]any)
	if len(rows) != 2 {
		t.Fatalf("rows = %v", rows)
	}
	second := rows[1].(map[string]any)
	if second["generated_line"] != float64(1) || second["generated_column"] != float64(9) ||
		second["original_column"] != float64(9) || second["name"] != "foo" ||
		second["source"] != "webpack:/src/app.ts" {
		t.Fatalf("second row = %v", second)
	}
}

func TestTraceWebSourceLocationRefusesNonV3(t *testing.T) {
	old := writeTemp(t, "old.map", []byte(`{"version":2,"mappings":""}`))
	if _, err := runOp("trace_web_source_location", old); err == nil || !strings.Contains(err.Error(), "only v3 maps") {
		t.Fatalf("version 2 map error = %v", err)
	}
	broken := writeTemp(t, "broken.map", []byte("not json"))
	if _, err := runOp("trace_web_source_location", broken); err == nil || !strings.Contains(err.Error(), "is not a JSON source map") {
		t.Fatalf("broken map error = %v", err)
	}
	if _, err := runOp("trace_web_source_location", t.TempDir()); err == nil || !strings.Contains(err.Error(), "is a directory") {
		t.Fatalf("directory target error = %v", err)
	}
}

// --- inspect_wasm_artifact ---

func wasmImportModule(t *testing.T, imports [][]byte) []byte {
	t.Helper()
	payload := append(sfLEB(uint32(len(imports))), bytes.Join(imports, nil)...)
	b := []byte("\x00asm")
	b = append(b, sf32(1)...)
	return append(b, sfWasmSec(2, payload)...)
}

func wasmImport(module, field string, kind byte, rest ...byte) []byte {
	b := append(sfWasmString(module), sfWasmString(field)...)
	b = append(b, kind)
	return append(b, rest...)
}

func zzWasmLimits(flag, min uint32, max ...uint32) []byte {
	b := append(sfLEB(flag), sfLEB(min)...)
	if flag&1 != 0 {
		b = append(b, sfLEB(max[0])...)
	}
	return b
}

func TestInspectWasmImportLimits(t *testing.T) {
	mod := wasmImportModule(t, [][]byte{
		wasmImport("env", "mem", 2, zzWasmLimits(1, 1, 16)...),
		wasmImport("env", "tbl", 1, append([]byte{0x70}, zzWasmLimits(0, 2)...)...),
		wasmImport("env", "g", 3, 0x7f, 1),
	})
	path := filepath.Join(t.TempDir(), "mod.wasm")
	if err := os.WriteFile(path, mod, 0o600); err != nil {
		t.Fatal(err)
	}
	f := metaMustRun(t, "inspect_wasm_artifact", path)
	imports, ok := f["imports"].([]any)
	if !ok || len(imports) != 3 {
		t.Fatalf("imports = %v", f["imports"])
	}
	mem := imports[0].(map[string]any)
	if mem["module"] != "env" || mem["field"] != "mem" || mem["kind"] != "memory" {
		t.Fatalf("memory import = %v", mem)
	}
	limits := mem["limits"].(map[string]any)
	if limits["flag"] != float64(1) || limits["min"] != float64(1) || limits["max"] != float64(16) {
		t.Fatalf("memory limits = %v", limits)
	}
	tbl := imports[1].(map[string]any)
	if tbl["kind"] != "table" {
		t.Fatalf("table import = %v", tbl)
	}
	tl := tbl["limits"].(map[string]any)
	if tl["flag"] != float64(0) || tl["min"] != float64(2) {
		t.Fatalf("table limits = %v", tl)
	}
	if _, has := tl["max"]; has {
		t.Fatalf("table limits invented a max: %v", tl)
	}
	if imports[2].(map[string]any)["kind"] != "global" {
		t.Fatalf("global import = %v", imports[2])
	}
}

func TestInspectWasmImportRefusals(t *testing.T) {
	// A memory import whose flag promises a max but the section stops.
	limits := zzWasmLimits(1, 1, 16)
	cut := wasmImportModule(t, [][]byte{wasmImport("env", "mem", 2, limits[:len(limits)-1]...)})
	if _, err := runOp("inspect_wasm_artifact", writeTemp(t, "mod.wasm", cut)); err == nil || !strings.Contains(err.Error(), "memory limits are cut") {
		t.Fatalf("cut limits error = %v", err)
	}
	unknown := wasmImportModule(t, [][]byte{wasmImport("env", "x", 9)})
	if _, err := runOp("inspect_wasm_artifact", writeTemp(t, "mod.wasm", unknown)); err == nil || !strings.Contains(err.Error(), "unknown kind 9") {
		t.Fatalf("unknown kind error = %v", err)
	}
	if _, err := runOp("inspect_wasm_artifact", writeTemp(t, "mod.wasm", []byte("not wasm"))); err == nil || !strings.Contains(err.Error(), "no wasm magic") {
		t.Fatalf("magic error = %v", err)
	}
}

// --- export_web_scripts (zip branch) ---

func zipScripts(t *testing.T, name string, files map[string][]byte, symlinks map[string]string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	for n, body := range files {
		w, err := zw.Create(n)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	for n, target := range symlinks {
		h := &zip.FileHeader{Name: n, Method: zip.Store}
		h.SetMode(os.ModeSymlink | 0o777)
		w, err := zw.CreateHeader(h)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(target)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return p
}

func withOpOutput(t *testing.T, dir string) {
	t.Helper()
	old := opOutput
	opOutput = dir
	t.Cleanup(func() { opOutput = old })
}

func TestExportWebScriptsZipTree(t *testing.T) {
	dir := t.TempDir()
	archive := zipScripts(t, "bundle.zip", map[string][]byte{
		"app.js":          []byte("console.log(1)\n"),
		"static/a.css":    []byte("body{}"),
		"nested/deep.mjs": []byte("export default 1\n"),
	}, map[string]string{"link.js": "app.js"})
	out := filepath.Join(dir, "out")
	withOpOutput(t, out)
	f := fields(t, run(t, "export_web_scripts", archive))
	if f["written"] != float64(2) || f["dir"] != out {
		t.Fatalf("written/dir = %v/%v", f["written"], f["dir"])
	}
	scripts := numList(t, f["scripts"])
	sort.Strings(scripts)
	if !reflect.DeepEqual(scripts, []string{"app.js", "nested/deep.mjs"}) {
		t.Fatalf("scripts = %v", scripts)
	}
	skipped := numList(t, f["skipped"])
	if !reflect.DeepEqual(skipped, []string{"link.js (symlink)"}) {
		t.Fatalf("skipped = %v", skipped)
	}
	body, err := os.ReadFile(filepath.Join(out, "nested", "deep.mjs"))
	if err != nil || string(body) != "export default 1\n" {
		t.Fatalf("exported body = %q/%v", body, err)
	}
}

func TestExportWebScriptsRefusesTraversal(t *testing.T) {
	dir := t.TempDir()
	archive := zipScripts(t, "evil.zip", map[string][]byte{"../../etc/x.js": []byte("pwn")}, nil)
	out := filepath.Join(dir, "out")
	withOpOutput(t, out)
	if _, err := runOp("export_web_scripts", archive); err == nil || !strings.Contains(err.Error(), "escapes the export directory") {
		t.Fatalf("traversal error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "etc", "x.js")); !os.IsNotExist(err) {
		t.Fatalf("traversal wrote outside the tree: %v", err)
	}
}

func TestExportWebScriptsNoMembers(t *testing.T) {
	dir := t.TempDir()
	archive := zipScripts(t, "docs.zip", map[string][]byte{"readme.txt": []byte("hi")}, nil)
	withOpOutput(t, filepath.Join(dir, "out"))
	if _, err := runOp("export_web_scripts", archive); err == nil || !strings.Contains(err.Error(), "holds no script members") {
		t.Fatalf("no-script error = %v", err)
	}
}

// --- inspect_kernel_module ---

func modinfoELF(modinfo []byte) []byte {
	const ehdr = 64
	strtab := []byte("\x00.modinfo\x00.shstrtab\x00")
	dataOff := ehdr
	strOff := dataOff + len(modinfo)
	shoff := (strOff + len(strtab) + 7) &^ 7
	b := make([]byte, shoff+3*64)
	le := binary.LittleEndian
	copy(b, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0})
	le.PutUint16(b[16:], 1)  // ET_REL
	le.PutUint16(b[18:], 62) // x86-64
	le.PutUint32(b[20:], 1)
	le.PutUint64(b[40:], uint64(shoff))
	le.PutUint16(b[52:], ehdr)
	le.PutUint16(b[58:], 64)
	le.PutUint16(b[60:], 3)
	le.PutUint16(b[62:], 2)
	copy(b[dataOff:], modinfo)
	copy(b[strOff:], strtab)
	section := func(i int, name, typ uint32, off, size, align uint64) {
		p := b[shoff+i*64:]
		le.PutUint32(p[0:], name)
		le.PutUint32(p[4:], typ)
		le.PutUint64(p[24:], off)
		le.PutUint64(p[32:], size)
		le.PutUint64(p[48:], align)
	}
	section(1, 1, 1, uint64(dataOff), uint64(len(modinfo)), 1)
	section(2, 10, 3, uint64(strOff), uint64(len(strtab)), 1)
	return b
}

func TestInspectKernelModuleModinfo(t *testing.T) {
	data := []byte("name=testmod\x00license=GPL\x00vermagic=6.1.0 SMP\x00\x00orphan")
	path := writeTemp(t, "testmod.ko", modinfoELF(data))
	f := metaMustRun(t, "inspect_kernel_module", path)
	if f["os"] != "linux" || f["module"] != "testmod" || f["bytes"] != float64(len(data)) {
		t.Fatalf("os/module/bytes = %v/%v/%v", f["os"], f["module"], f["bytes"])
	}
	pairs := f["fields"].([]any)
	if len(pairs) != 3 {
		t.Fatalf("fields = %v, want name/license/vermagic", pairs)
	}
	last := pairs[2].(map[string]any)
	if last["key"] != "vermagic" || last["value"] != "6.1.0 SMP" {
		t.Fatalf("vermagic field = %v", last)
	}
}

func TestInspectKernelModuleSkipsAndRefuses(t *testing.T) {
	plain := writeTemp(t, "plain.ko", elfWithComment(t, "clang"))
	m := metaMustRun(t, "inspect_kernel_module", plain)
	if !strings.Contains(metaStr(t, m, "skipped"), "no .modinfo section") {
		t.Fatalf("skip = %v", m)
	}
	other := writeTemp(t, "other.bin", []byte("not an object file"))
	if _, err := runOp("inspect_kernel_module", other); err == nil || !strings.Contains(err.Error(), "neither ELF nor Mach-O") {
		t.Fatalf("format error = %v", err)
	}
	empty := writeTemp(t, "empty.ko", modinfoELF([]byte("\x00\x00")))
	if _, err := runOp("inspect_kernel_module", empty); err == nil || !strings.Contains(err.Error(), "no key=value pairs") {
		t.Fatalf("empty modinfo error = %v", err)
	}
}

// --- correlate_static_and_runtime ---

// thinUUIDMachO builds a thin Mach-O whose only load command is LC_UUID. The
// digest keeps the uuid at the top level only for a thin image, which is what
// correlate_static_and_runtime needs.
func thinUUIDMachO(uuid [16]byte) []byte {
	b := make([]byte, 32+24)
	le := binary.LittleEndian
	le.PutUint32(b[0:], 0xfeedfacf)
	le.PutUint32(b[4:], 0x01000007) // x86_64
	le.PutUint32(b[8:], 3)
	le.PutUint32(b[12:], 2) // MH_EXECUTE
	le.PutUint32(b[16:], 1) // one load command
	le.PutUint32(b[20:], 24)
	le.PutUint32(b[32:], 0x1b) // LC_UUID
	le.PutUint32(b[36:], 24)
	copy(b[40:], uuid[:])
	return b
}

func uuidFromHex(s string) [16]byte {
	var out [16]byte
	for i := range 16 {
		out[i] = hexNibble(s[i*2])<<4 | hexNibble(s[i*2+1])
	}
	return out
}

func hexNibble(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	default:
		return c - 'A' + 10
	}
}

func TestCorrelateStaticAndRuntimeThinMachO(t *testing.T) {
	const wantUUID = "D4B9C2DB99983233A2BE5577126F0C8D"
	image := writeTemp(t, "demo", thinUUIDMachO(uuidFromHex(wantUUID)))
	d := probeFixture(t, image)
	if d.UUID != wantUUID {
		t.Fatalf("probe uuid = %q, want %q (kind %s)", d.UUID, wantUUID, d.Kind)
	}
	ips := func(uuid string) string {
		body := `{"name":"report","timestamp":"2026-01-01 00:00:00.00 +0000","app_name":"Demo"}` + "\n" +
			`{"procName":"Demo","usedImages":[{"name":"Demo","uuid":"` + uuid + `","arch":"x86_64"}]}`
		return writeTemp(t, "crash.ips", []byte(body))
	}

	match := metaMustRun(t, "correlate_static_and_runtime", metaTestArg(t, map[string]any{"file": image, "crash": ips(wantUUID)}))
	runtime := match["runtime"].(map[string]any)
	images := runtime["images"].([]any)
	img := images[0].(map[string]any)
	if img["match"] != true || img["uuid"] != wantUUID {
		t.Fatalf("matching image = %v", img)
	}
	if got := metaStr(t, match, "verdict"); !strings.Contains(got, "static image matches the crashing image uuid") {
		t.Fatalf("verdict = %q", got)
	}

	mismatch := metaMustRun(t, "correlate_static_and_runtime", metaTestArg(t, map[string]any{
		"file": image, "crash": ips("00000000000000000000000000000000"),
	}))
	if got := metaStr(t, mismatch, "verdict"); !strings.Contains(got, "different build") {
		t.Fatalf("mismatch verdict = %q", got)
	}
	if mismatch["runtime"].(map[string]any)["images"].([]any)[0].(map[string]any)["match"] != false {
		t.Fatalf("mismatch image = %v", mismatch["runtime"])
	}

	// A job without a crash report is a call error, not a verdict.
	if _, err := metaTestRun(t, "correlate_static_and_runtime", metaTestArg(t, map[string]any{"file": image})); err == nil || !strings.Contains(err.Error(), `needs "crash"`) {
		t.Fatalf("missing crash error = %v", err)
	}
}

// --- inspect_gpu_code_objects: CUBIN targets ---

func fatbinWithCubin(machine uint16, payload int) []byte {
	cubin := make([]byte, payload)
	copy(cubin, []byte{0x7f, 'E', 'L', 'F'})
	if payload >= 0x14 {
		binary.LittleEndian.PutUint16(cubin[0x12:], machine)
	}
	fat := make([]byte, 32+16+len(cubin))
	binary.LittleEndian.PutUint32(fat[0:], gpuFatbinMagic)
	binary.LittleEndian.PutUint16(fat[4:], 1)  // wrapper version
	binary.LittleEndian.PutUint16(fat[6:], 32) // header bytes
	binary.LittleEndian.PutUint64(fat[8:], uint64(len(fat)))
	binary.LittleEndian.PutUint32(fat[32:], 2)  // CUBIN
	binary.LittleEndian.PutUint16(fat[38:], 16) // entry header bytes
	binary.LittleEndian.PutUint64(fat[40:], uint64(len(cubin)))
	copy(fat[48:], cubin)
	return fat
}

func TestInspectGPUCodeObjectsCubinTargets(t *testing.T) {
	cases := []struct {
		machine uint16
		want    string
	}{
		{190, "sm_70+"}, {192, "sm_75+"}, {193, "sm_80+"},
		{194, "sm_86+"}, {200, "sm_89+"}, {201, "sm_90+"}, {999, "elf-machine-999"},
	}
	for _, c := range cases {
		if got := cubinArch(fatbinWithCubin(c.machine, 0x48)[48:]); got != c.want {
			t.Fatalf("cubinArch(machine %d) = %q, want %q", c.machine, got, c.want)
		}
	}
	if got := cubinArch([]byte("\x7fELF")); got != "" {
		t.Fatalf("truncated CUBIN arch = %q, want empty", got)
	}
	if got := cubinArch(make([]byte, 0x48)); got != "" {
		t.Fatalf("non-ELF CUBIN arch = %q, want empty", got)
	}

	path := writeTemp(t, "k.fatbin", fatbinWithCubin(201, 0x48))
	f := metaMustRun(t, "inspect_gpu_code_objects", path)
	if f["cubin"] != float64(1) || f["ptx"] != float64(0) {
		t.Fatalf("ptx/cubin = %v/%v", f["ptx"], f["cubin"])
	}
	entry := f["entries"].([]any)[0].(map[string]any)
	if entry["kind"] != "cubin" || entry["arch"] != "sm_90+" || entry["payload_bytes"] != float64(0x48) {
		t.Fatalf("cubin entry = %v", entry)
	}

	// A payload too short to hold e_machine still counts as an entry, with no arch.
	short := writeTemp(t, "short.fatbin", fatbinWithCubin(201, 0x30))
	fs := metaMustRun(t, "inspect_gpu_code_objects", short)
	se := fs["entries"].([]any)[0].(map[string]any)
	if _, has := se["arch"]; has {
		t.Fatalf("short CUBIN invented an arch: %v", se)
	}
}

// TestExportWebScriptsAllowsDotDotName: only a ".." path element escapes. A
// member whose name merely starts with two dots (..foo.js) is inside the tree
// and must be exported, not refused.
func TestExportWebScriptsAllowsDotDotName(t *testing.T) {
	dir := t.TempDir()
	archive := zipScripts(t, "dots.zip", map[string][]byte{
		"..foo.js": []byte("var a = 1\n"),
	}, nil)
	out := filepath.Join(dir, "out")
	withOpOutput(t, out)
	f := fields(t, run(t, "export_web_scripts", archive))
	if f["written"] != float64(1) {
		t.Fatalf("written = %v, want 1", f["written"])
	}
	if body, err := os.ReadFile(filepath.Join(out, "..foo.js")); err != nil || string(body) != "var a = 1\n" {
		t.Fatalf("..foo.js was not exported: %q, %v", body, err)
	}
	// A real escape is still refused.
	trav := zipScripts(t, "trav.zip", map[string][]byte{"../out.js": []byte("x")}, nil)
	if _, err := runOp("export_web_scripts", trav); err == nil || !strings.Contains(err.Error(), "escapes the export directory") {
		t.Fatalf(".. member error = %v", err)
	}
}

// TestExportWebScriptsLeavesNoDirectoryWhenInputIsNotAnArchive: -o names a tree
// this op fills from an archive; when the target is not one, a failed call must
// not leave an empty directory (or its parents) behind.
func TestExportWebScriptsLeavesNoDirectoryWhenInputIsNotAnArchive(t *testing.T) {
	dir := t.TempDir()
	notAnArchive := filepath.Join(dir, "note.txt")
	if err := os.WriteFile(notAnArchive, []byte("not a zip"), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "deep", "out")
	withOpOutput(t, out)
	if _, err := runOp("export_web_scripts", notAnArchive); err == nil || !strings.Contains(err.Error(), "neither a zip/apk/ipa nor an asar") {
		t.Fatalf("error = %v, want the not-an-archive refusal", err)
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatalf("failed export left %s behind: %v", out, err)
	}

	// The directory the caller already had is not ours to delete.
	existing := filepath.Join(dir, "mine")
	if err := os.MkdirAll(existing, 0o755); err != nil {
		t.Fatal(err)
	}
	keep := filepath.Join(existing, "keep.txt")
	if err := os.WriteFile(keep, []byte("caller data"), 0o644); err != nil {
		t.Fatal(err)
	}
	withOpOutput(t, existing)
	if _, err := runOp("export_web_scripts", notAnArchive); err == nil {
		t.Fatal("not-an-archive into an existing -o dir: want an error")
	}
	if body, err := os.ReadFile(keep); err != nil || string(body) != "caller data" {
		t.Fatalf("failed export touched the caller's directory: %q, %v", body, err)
	}
}

// TestInstallADBPackageKeepsStderrReason: a failed install exits non-zero with
// only "Performing Streamed Install" on stdout; the line that says why
// (INSTALL_FAILED_*, a java exception) is on stderr. The error must quote it
// instead of the progress line.
func TestInstallADBPackageKeepsStderrReason(t *testing.T) {
	dir := t.TempDir()
	apk := filepath.Join(dir, "app.apk")
	if err := os.WriteFile(apk, []byte("PK\x03\x04"), 0o644); err != nil {
		t.Fatal(err)
	}
	rtFakeTool(t, "adb", `if [ "$1" = "devices" ]; then printf 'List of devices attached\nemulator-5554\tdevice\n'; exit 0; fi
printf 'Performing Streamed Install\n'
printf 'adb: failed to install app.apk: \nandroid.os.ParcelableException: java.io.IOException: Requested internal only, but not enough space\n' >&2
exit 1`)
	_, err := runOp("install_adb_package", apk)
	if err == nil {
		t.Fatal("failed install: want an error")
	}
	if !strings.Contains(err.Error(), "not enough space") {
		t.Fatalf("error = %v, want the stderr reason", err)
	}
	if strings.Contains(err.Error(), "Performing Streamed Install") {
		t.Fatalf("error = %v, want the reason instead of the progress line", err)
	}
}
