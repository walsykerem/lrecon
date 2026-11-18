package main

// TUR3 audit — lane 29 independent simulation tests.
// Verifies real lrecon behavior; production code is not relaxed.

import (
	"encoding/binary"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	r3l29Test1 = "/Users/keremurhan/kalitetest/test1"
	r3l29Test2 = "/Users/keremurhan/kalitetest/test2"
	r3l29Own   = "/Users/keremurhan/walsyrea/lrecon/lrecon"
	r3l29Fx    = "/Users/keremurhan/walsyrea/lrecon/testdata/fixtures"
)

func r3l29Op(t *testing.T, name, path string) map[string]any {
	t.Helper()
	v, err := runOp(name, path)
	if err != nil {
		t.Fatalf("%s(%s): %v", name, path, err)
	}
	b, _ := json.Marshal(v)
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if r := m["result"]; r != nil {
		if rm, ok := r.(map[string]any); ok {
			return rm
		}
	}
	return m
}

// Route classes of the lane29 ops (skill Route table: L/Y/G).
func TestR3L29OpRoutes(t *testing.T) {
	for name, want := range map[string]string{
		"capture_browser_scenario":          "Y",
		"decode_interface_builder":          "L",
		"get_objc_protocols":                "L",
		"inspect_elf_notes":                 "L",
		"inspect_plist":                     "L",
		"list_names":                        "G",
		"project_android_application_graph": "L",
		"set_bookmark":                      "L",
	} {
		o, ok := ops[name]
		if !ok || o.route != want || !o.needs {
			t.Errorf("op %q: route=%q needs=%v registered=%v", name, o.route, o.needs, ok)
		}
	}
}

// lua.go: reader contract, magic/version/endian distinction, real header bytes.
func TestR3L29LuaReaderContract(t *testing.T) {
	verifyReaders()
	var lua reader
	for _, r := range readers {
		if r.format == "lua" {
			lua = r
		}
	}
	if lua.inspect == nil || len(lua.reasons) != 6 {
		t.Fatalf("lua reader contract: %+v", lua)
	}
	luac := []byte("\x1bLua\x54\x00\x01\x08\x08\x04\x08\x08")
	if !lua.match(luac, int64(len(luac))) {
		t.Error("valid luac 5.4 magic refused")
	}
	lj := []byte("\x1bLJ\x02\x02")
	if !lua.match(lj, int64(len(lj))) {
		t.Error("valid LuaJIT magic refused")
	}
	macho := head(r3l29Test1, 8)
	if lua.match(macho, 33640) {
		t.Error("Mach-O mistaken for lua")
	}
	if luaOrder(0) != binary.BigEndian || luaOrder(1) != binary.LittleEndian || luaOrder(2) != nil {
		t.Error("luaOrder wrong")
	}
	if !luaSizes(8, 8, 4, 8, 8) || luaSizes(8, 8, 4, 3, 8) || luaSizes(4, 4, 8, 4, 4) {
		t.Error("luaSizes wrong")
	}
	if luaReadUint([]byte{0x01, 0x00, 0x00, 0x00}, binary.LittleEndian) != 1 {
		t.Error("luaReadUint 4 bytes wrong")
	}
	if luaReadUint([]byte{0, 0, 0, 0, 0, 0, 0, 1}, binary.BigEndian) != 1 {
		t.Error("luaReadUint 8 bytes wrong")
	}
}

// lua.go: 5.4 header is parsed from real byte array, corrupt LUAC_DATA is refused.
func TestR3L29LuaHeaderRealBytes(t *testing.T) {
	b := make([]byte, 26)
	copy(b, []byte("\x1bLua\x54\x00\x01\x08\x08\x04\x08\x08"))
	copy(b[12:18], luaCheck)
	binary.LittleEndian.PutUint64(b[18:26], 0x5678)
	// LUAC_NUM little-endian float64 370.5.
	num := make([]byte, 8)
	binary.LittleEndian.PutUint64(num, math.Float64bits(370.5))
	b = append(b[:26], num...)
	var d Digest
	inspectLuac(b, &d)
	if d.Kind != "" || d.Toolchain != "lua 5.4" {
		t.Fatalf("inspectLuac toolchain=%q", d.Toolchain)
	}
	want := []string{"lua:version=5.4", "lua:endianness=little", "lua:int=8", "lua:size_t=8", "lua:instruction=4", "lua:number=8", "lua:integer=8"}
	for _, w := range want {
		found := false
		for _, c := range d.Capabilities {
			if c == w {
				found = true
			}
		}
		if !found {
			t.Errorf("capability %q missing: %v", w, d.Capabilities)
		}
	}
	// Corrupt LUAC_DATA -> reason.
	bad := append([]byte(nil), b...)
	bad[12] ^= 0xff
	var d2 Digest
	inspectLuac(bad, &d2)
	if len(d2.Skipped) == 0 || d2.Skipped[0].Reason != "lua-header-unverified" {
		t.Fatalf("corrupt header not refused: %+v", d2.Skipped)
	}
	// Reader does not work on a Mach-O file.
	var d3 Digest
	inspectLua(r3l29Test1, &d3)
	if len(d3.Skipped) == 0 || d3.Toolchain != "" {
		t.Fatalf("Mach-O mistaken for lua: %+v", d3.Skipped)
	}
}

// wasm.go: reader contract + LEB128 cursor (5/10 byte cap).
func TestR3L29WasmReaderContract(t *testing.T) {
	var wasm reader
	for _, r := range readers {
		if r.format == "wasm" {
			wasm = r
		}
	}
	if wasm.inspect == nil || !wasm.post || len(wasm.reasons) != 6 || !wasm.match([]byte("\x00asm\x01\x00\x00\x00"), 8) {
		t.Fatalf("wasm reader contract: %+v", wasm)
	}
	if wasm.match(head(r3l29Test1, 8), 33640) {
		t.Error("Mach-O mistaken for wasm")
	}
	c := &wasmCursor{b: []byte{0x80, 0x01}} // 128
	if v, ok := c.u32(); !ok || v != 128 {
		t.Fatalf("u32= %d %v", v, ok)
	}
	// 5th byte above 0xf0 -> 35-bit ref.
	over := &wasmCursor{b: []byte{0xff, 0xff, 0xff, 0xff, 0xff}}
	if _, ok := over.u32(); ok {
		t.Error("5-byte LEB128 overflow accepted")
	}
	// u64: 10th byte above 0x02 -> 65-bit ref.
	over64 := &wasmCursor{b: []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02}}
	if _, ok := over64.u64(); ok {
		t.Error("10-byte u64 LEB128 overflow accepted")
	}
	// refType: funcref/externref 1 byte, typed ref 1+LEB.
	if !wasmRefType(&wasmCursor{b: []byte{0x70}}) {
		t.Error("funcref refused")
	}
	if !wasmRefType(&wasmCursor{b: []byte{0x63, 0x00}}) {
		t.Error("typed ref refused")
	}
}

// wasm.go: real wasm.wasm digest — imports/exports/capabilities/skip.
func TestR3L29WasmRealFile(t *testing.T) {
	p := filepath.Join(r3l29Fx, "wasm.wasm")
	var d Digest
	inspectWasm(p, &d)
	if d.Format != "v1" || d.Kind != "" {
		t.Fatalf("inspectWasm format=%q kind=%q", d.Format, d.Kind)
	}
	if len(d.Imports) == 0 || len(d.Imports) != 20 {
		t.Errorf("imports=%d", len(d.Imports))
	}
	found := false
	for _, c := range d.Capabilities {
		if strings.HasPrefix(c, "wasm:Go cmd/compile=") {
			found = true
		}
	}
	if !found {
		t.Errorf("Go toolchain capability missing: %v", d.Capabilities)
	}
	reasons := map[string]bool{}
	for _, s := range d.Skipped {
		reasons[s.Reason] = true
	}
	if !reasons["no-disassembler"] {
		t.Errorf("no-disassembler skip missing: %v", d.Skipped)
	}
	// Corrupt magic -> nothing is claimed.
	bad := writeTemp(t, "bad.wasm", []byte("\x01asm\x01\x00\x00\x00"))
	var d2 Digest
	inspectWasm(bad, &d2)
	if d2.Format != "" || len(d2.Imports) != 0 {
		t.Fatalf("corrupt wasm produced a claim: %+v", d2)
	}
	// Component model version -> wasm-version-unverified.
	comp := writeTemp(t, "comp.wasm", []byte("\x00asm\x0d\x00\x01\x00"))
	var d3 Digest
	inspectWasm(comp, &d3)
	if d3.Format != "component" {
		t.Errorf("component format=%q", d3.Format)
	}
	has := false
	for _, s := range d3.Skipped {
		if s.Reason == "wasm-version-unverified" {
			has = true
		}
	}
	if !has {
		t.Errorf("component skip missing: %v", d3.Skipped)
	}
}

// op_decode_interface_builder: real NIBArchive + vInt + error path.
func TestR3L29NibRealFile(t *testing.T) {
	m := r3l29Op(t, "decode_interface_builder", filepath.Join(r3l29Fx, "nib/interface.nib"))
	if m["version"] != float64(1) || m["coder_version"] != float64(0) {
		t.Fatalf("nib version: %v", m)
	}
	if v, ok := m["outlets"].([]any); !ok || len(v) != 1 || v[0] != "myOutlet" {
		t.Fatalf("outlets: %v", m["outlets"])
	}
	if v, ok := m["actions"].([]any); !ok || len(v) != 1 || v[0] != "doAction:" {
		t.Fatalf("actions: %v", m["actions"])
	}
	// nibVInt: the high bit is in the LAST byte (most significant), not in continuation bytes.
	if v, n, err := nibVInt([]byte{0x7f, 0x80}, 0); err != nil || v != 127 || n != 2 {
		t.Fatalf("nibVInt(7f 80)=%d,%d,%v", v, n, err)
	}
	if v, n, err := nibVInt([]byte{0x81}, 0); err != nil || v != 1 || n != 1 {
		t.Fatalf("nibVInt(81)=%d,%d,%v", v, n, err)
	}
	// 5 continuation bytes, none with the final bit -> refuse longer than 5 bytes.
	if _, _, err := nibVInt([]byte{0x01, 0x01, 0x01, 0x01, 0x01}, 0); err == nil {
		t.Error("vInt longer than 5 bytes accepted")
	}
	if _, err := nibParse([]byte("not a nib at all")); err == nil {
		t.Error("fake NIBArchive accepted")
	}
}

// op_inspect_elf_notes: real ELF (Go build-id) + bytes0.
func TestR3L29ElfNotesRealFile(t *testing.T) {
	m := r3l29Op(t, "inspect_elf_notes", filepath.Join(r3l29Fx, "elf"))
	if m["machine"] != "EM_X86_64" {
		t.Fatalf("machine=%v", m["machine"])
	}
	bid, _ := m["build_id"].(string)
	if len(bid) != 40 {
		t.Fatalf("build_id=%q", bid)
	}
	owners, ok := m["owners"].([]any)
	if !ok || len(owners) < 2 {
		t.Fatalf("owners=%v", m["owners"])
	}
	hasGNU, hasGo := false, false
	for _, o := range owners {
		if o == "GNU" {
			hasGNU = true
		}
		if o == "Go" {
			hasGo = true
		}
	}
	if !hasGNU || !hasGo {
		t.Fatalf("owners GNU/Go missing: %v", owners)
	}
	if got := string(bytes0([]byte("abc\x00\x00"))); got != "abc" {
		t.Errorf("bytes0=%q", got)
	}
}

// op_inspect_plist: real plist fixture + Mach-O refusal.
func TestR3L29PlistRealFile(t *testing.T) {
	m := r3l29Op(t, "inspect_plist", filepath.Join(r3l29Fx, "keyed/archive.plist"))
	keys, ok := m["keys"].([]any)
	if !ok || len(keys) == 0 {
		t.Fatalf("keys=%v", m["keys"])
	}
	hasArchiver := false
	for _, k := range keys {
		if k == "$archiver" {
			hasArchiver = true
		}
	}
	if !hasArchiver {
		t.Errorf("$archiver key missing: %v", keys)
	}
	if s, err := runOp("inspect_plist", r3l29Test1); err != nil || s == nil {
		t.Fatalf("Mach-O plist refusal: %v / %v", s, err)
	} else if b, _ := json.Marshal(s); !strings.Contains(string(b), "not a property list") {
		t.Errorf("Mach-O refusal content: %s", b)
	}
}

// op_get_objc_protocols: no protocol list in real Mach-O -> skip/refusal.
func TestR3L29ObjcProtocolsReal(t *testing.T) {
	for _, p := range []string{r3l29Test1, r3l29Test2} {
		s, err := runOp("get_objc_protocols", p)
		if err != nil || s == nil {
			t.Errorf("%s: expected skip: %v / %v", p, s, err)
			continue
		}
		if b, _ := json.Marshal(s); !strings.Contains(string(b), "has no Objective-C protocol list") {
			t.Errorf("%s skip content: %s", p, b)
		}
	}
	if _, _, err := objcNameList(r3l29Test1, "__objc_protolist", []int{8}, false); err == nil || !strings.Contains(err.Error(), "has no __objc_protolist section") {
		t.Fatalf("objcNameList error: %v", err)
	}
}

// op_list_names: listNamesAnswer found/shown/truncated distinction + real G op.
func TestR3L29ListNamesAnswer(t *testing.T) {
	res := map[string]any{
		"names":  float64(250),
		"sample": []any{"a", "b", "c"},
	}
	out := listNamesAnswer(res).(map[string]any)
	if out["parsed"] != 250 || out["total"] != 250 {
		t.Errorf("parsed/total=%v/%v", out["parsed"], out["total"])
	}
	if out["shown"] != 3 || out["truncated"] != true {
		t.Errorf("shown/truncated=%v/%v", out["shown"], out["truncated"])
	}
	small := listNamesAnswer(map[string]any{"names": 2, "sample": []any{"a", "b"}}).(map[string]any)
	if small["truncated"] != false || small["shown"] != 2 {
		t.Errorf("small table: %v", small)
	}
	m := r3l29Op(t, "list_names", r3l29Test1)
	if m["total"] == nil || m["shown"] == nil || m["truncated"] == nil {
		t.Fatalf("real list_names envelope: %v", m)
	}
}

// op_project_android_application_graph: real APK graph.
func TestR3L29AndroidGraphRealFile(t *testing.T) {
	m := r3l29Op(t, "project_android_application_graph", filepath.Join(r3l29Fx, "apk/resources.apk"))
	if m["node_count"] == nil || m["edge_count"] == nil {
		t.Fatalf("graph.count: %v", m)
	}
	if m["package"] != "com.example.fix" {
		t.Fatalf("package=%v", m["mobile_package"])
	}
	if _, err := runOp("project_android_application_graph", r3l29Test1); err == nil {
		t.Error("Mach-O produced an Android graph")
	}
	if dexMaxClasses != 256 {
		t.Errorf("dexMaxClasses=%d", dexMaxClasses)
	}
}

// op_set_bookmark: real job file + state, created is preserved at the same address.
func TestR3L29SetBookmarkRealJob(t *testing.T) {
	dir := t.TempDir()
	jobPath := filepath.Join(dir, "job.json")
	job := map[string]any{
		"file":    r3l29Test1,
		"address": "0x1000",
		"text":    "first note",
		"state":   filepath.Join(dir, "state"),
	}
	b, _ := json.Marshal(job)
	if err := os.WriteFile(jobPath, b, 0o644); err != nil {
		t.Fatal(err)
	}
	m := r3l29Op(t, "set_bookmark", jobPath)
	if m["updated"] != false || m["count"] != float64(1) {
		t.Fatalf("first bookmark: %v", m)
	}
	first := m["bookmark"].(map[string]any)
	created, _ := first["created"].(string)
	if created == "" || first["note"] != "first note" {
		t.Fatalf("bookmark=%v", first)
	}
	// Same file/address -> updated, created is preserved.
	job["text"] = "second note"
	b, _ = json.Marshal(job)
	if err := os.WriteFile(jobPath, b, 0o644); err != nil {
		t.Fatal(err)
	}
	m2 := r3l29Op(t, "set_bookmark", jobPath)
	if m2["updated"] != true || m2["count"] != float64(1) {
		t.Fatalf("update: %v", m2)
	}
	second := m2["bookmark"].(map[string]any)
	if second["note"] != "second note" || second["created"] != created {
		t.Fatalf("created not preserved: %v", second)
	}
	// Missing field -> needs_arg error.
	if _, err := runOp("set_bookmark", r3l29Test1); err == nil || !strings.Contains(err.Error(), "needs \"file\" and \"address\"") {
		t.Fatalf("missing field error: %v", err)
	}
}

// op_web_util: webTarget gates, captureRequests, readWebText, lexJS.
func TestR3L29WebUtil(t *testing.T) {
	if ep, arg, err := webTarget("localhost:9222"); err != nil || ep != "127.0.0.1:9222" || arg != "" {
		t.Fatalf("localhost=%q,%q,%v", ep, arg, err)
	}
	if ep, arg, err := webTarget("127.0.0.1:9333=a.js"); err != nil || ep != "127.0.0.1:9333" || arg != "a.js" {
		t.Fatalf("endpoint+arg=%q,%q,%v", ep, arg, err)
	}
	if _, _, err := webTarget("https://example.com/app"); err == nil || !strings.Contains(err.Error(), websiteDecline) {
		t.Fatalf("website refusal: %v", err)
	}
	if _, _, err := webTarget("node"); err == nil || !strings.Contains(err.Error(), runtimeDecline) {
		t.Fatalf("process-name refusal: %v", err)
	}
	if _, _, err := webTarget("example.com:9222"); err == nil || !strings.Contains(err.Error(), "never a remote host") {
		t.Fatalf("remote host refusal: %v", err)
	}
	if _, _, err := webTarget(r3l29Test1); err == nil || !strings.Contains(err.Error(), "not a DevTools endpoint") {
		t.Fatalf("file path refusal: %v", err)
	}
	if !digitsOnly("9222") || digitsOnly("") || digitsOnly("9a") {
		t.Error("digitsOnly wrong")
	}
	// captureRequests: request/response matching.
	events := []webEvent{
		{Method: "Network.requestWillBeSent", Params: map[string]any{"requestId": "1", "request": map[string]any{"method": "GET", "url": "http://x/a"}}},
		{Method: "Network.responseReceived", Params: map[string]any{"requestId": "1", "response": map[string]any{"status": float64(200), "mimeType": "text/html"}}},
	}
	rows := captureRequests(events)
	if len(rows) != 1 || rows[0].Method != "GET" || rows[0].Status != 200 || rows[0].Mime != "text/html" {
		t.Fatalf("captureRequests=%+v", rows)
	}
	// readWebText: real file + cap flag.
	p := writeTemp(t, "a.js", []byte("var a=1;"))
	s, cut, err := readWebText(p)
	if err != nil || cut || s != "var a=1;" {
		t.Fatalf("readWebText=%q,%v,%v", s, cut, err)
	}
	if _, _, err := readWebText(filepath.Dir(p)); err == nil {
		t.Error("directory was read")
	}
	// lexJS: imports inside comments and strings are masked.
	masked, st := lexJS([]byte("// import x from 'fake'\nimport y from 'real';"))
	if st.Tokens == 0 || !strings.Contains(string(masked), "import") {
		t.Fatalf("lexJS=%q,%+v", masked, st)
	}
}

// op_capture_browser_scenario: Y op produces a DevTools refusal on the real target.
func TestR3L29CaptureBrowserScenarioReal(t *testing.T) {
	if _, err := runOp("capture_browser_scenario", r3l29Test1); err == nil || !strings.Contains(err.Error(), "not a DevTools endpoint") {
		t.Fatalf("capture_browser_scenario refusal: %v", err)
	}
	if _, err := runOp("capture_browser_scenario", "https://example.com"); err == nil || !strings.Contains(err.Error(), websiteDecline) {
		t.Fatalf("website refusal: %v", err)
	}
}

// An array-only plist has no dictionary keys. The op must say so instead of
// reporting an empty key list that reads like a failed parse.
func TestR3L29PlistArrayOnlyNote(t *testing.T) {
	xml := []byte(`<?xml version="1.0"?><plist version="1.0"><array><string>a</string><string>b</string></array></plist>`)
	m := r3l29Op(t, "inspect_plist", writeTemp(t, "Array.plist", xml))
	keys, ok := m["keys"].([]any)
	if !ok || len(keys) != 0 {
		t.Fatalf("array-only keys = %v, want empty", m["keys"])
	}
	notes, _ := m["notes"].([]any)
	want := "no dictionary keys in the first 16777216 bytes"
	found := false
	for _, n := range notes {
		if s, _ := n.(string); s == want {
			found = true
		}
	}
	if !found {
		t.Fatalf("notes = %v, want %q", notes, want)
	}
}

// A successful driver run with no Network events is a protocol error, not an
// empty capture: Network.enable must precede Page.navigate.
func TestR3L29CaptureBrowserScenarioNoRequests(t *testing.T) {
	tg := []webTargetRow{{ID: "T1", Type: "page", URL: "https://app.example.com/"}}
	fakeDriver(t, webOut{Target: &tg[0], Events: []webEvent{event("Page.loadEventFired", map[string]any{})}, Steps: []webStepResult{
		okStep("Network.enable", map[string]any{}), okStep("Page.enable", map[string]any{}),
		okStep("Page.setLifecycleEventsEnabled", map[string]any{}), okStep("Page.navigate", map[string]any{}),
	}})
	_, err := runOp("capture_browser_scenario", "127.0.0.1:9222=https://app.example.com/")
	if err == nil || !strings.Contains(err.Error(), "no Network.requestWillBeSent events") {
		t.Fatalf("empty capture must refuse: %v", err)
	}
}
