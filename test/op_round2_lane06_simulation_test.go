package main

// TUR2 AUDIT LANE06 — independent real-behavior simulation tests.
// Single test file; no other test file is touched, production code is not relaxed.

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// ---- op_capture_web_screenshot.go : stepFailure ----
func TestR2L06StepFailureBranches(t *testing.T) {
	steps := []webStepResult{
		{Method: "Page.captureScreenshot", Ok: true, Result: map[string]any{}},
		{Method: "Page.navigate", Ok: false},
		{Method: "Runtime.evaluate", Error: &webStepError{Code: 7, Message: "boom"}},
	}
	if got, want := stepFailure(steps, 0), "Page.captureScreenshot: no data"; got != want {
		t.Errorf("ok+no data = %q, want %q", got, want)
	}
	if got, want := stepFailure(steps, 1), "Page.navigate: rejected"; got != want {
		t.Errorf("!Ok = %q, want %q", got, want)
	}
	if got, want := stepFailure(steps, 2), "Runtime.evaluate: boom"; got != want {
		t.Errorf("Error = %q, want %q", got, want)
	}
	if got, want := stepFailure(steps, 3), "step never ran"; got != want {
		t.Errorf("i>=len = %q, want %q", got, want)
	}
}

// ---- op_check_deception.go : deceptionShadowState + decodeBase64JSON ----
func TestR2L06DeceptionShadowState(t *testing.T) {
	var win strings.Builder
	for i := 0; i < 8; i++ {
		fmt.Fprintf(&win, "root%dState ", i)
	}
	c := deceptionShadowState([]byte(win.String()))
	if len(c.Hits) != 1 || c.Hits[0].ID != "state-family" {
		t.Fatalf("8 state identifiers -> hits %v, want one state-family", c.Hits)
	}
	if c.Hits[0].Offset == nil || *c.Hits[0].Offset < 0 {
		t.Errorf("hit offset = %v, want a concrete non-negative offset", c.Hits[0].Offset)
	}

	var small strings.Builder
	for i := 0; i < 7; i++ {
		fmt.Fprintf(&small, "root%dState ", i)
	}
	if got := deceptionShadowState([]byte(small.String())); len(got.Hits) != 0 {
		t.Errorf("7 state identifiers -> hits %v, want none (min is 8)", got.Hits)
	}

	// Repeated identical names are deduplicated; 8 repeats do not count as one family.
	var dup strings.Builder
	for i := 0; i < 20; i++ {
		dup.WriteString("onlyOneState ")
	}
	if got := deceptionShadowState([]byte(dup.String())); len(got.Hits) != 0 {
		t.Errorf("repeated single name -> hits %v, want none (deduplicated)", got.Hits)
	}
}

func TestR2L06DecodeBase64JSON(t *testing.T) {
	payload := base64.StdEncoding.EncodeToString([]byte(`{"version":3,"file":"a.js","sources":["a"]}`))
	var sm webSourceMap
	if err := decodeBase64JSON(payload, &sm); err != nil {
		t.Fatalf("valid payload: %v", err)
	}
	if sm.Version != 3 || sm.File != "a.js" || len(sm.Sources) != 1 {
		t.Errorf("decoded map = %+v, want version 3 / a.js / one source", sm)
	}
	if err := decodeBase64JSON("!!!not-base64!!!", &sm); err == nil {
		t.Error("invalid base64 must error")
	}
}

// ---- op_check_runtime_evasion.go : evadeOffset + evasionFamilies ----
func TestR2L06EvadeOffset(t *testing.T) {
	win := []byte("prefix IsDebuggerPresent suffix")
	lit := evadePat{id: "p", lit: []byte("IsDebuggerPresent")}
	if off, ok := evadeOffset(win, lit); !ok || off != int64(strings.Index(string(win), "IsDebuggerPresent")) {
		t.Errorf("literal = (%d,%v), want (%d,true)", off, ok, strings.Index(string(win), "IsDebuggerPresent"))
	}

	reWin := []byte("xx ptrace(  PTRACE_TRACEME) yy")
	re := evadePat{id: "p", re: regexp.MustCompile(`ptrace\s*\(\s*PTRACE_TRACEME`)}
	if off, ok := evadeOffset(reWin, re); !ok || off != 3 {
		t.Errorf("regex = (%d,%v), want (3,true)", off, ok)
	}

	cancel := evadePat{id: "p", lit: []byte("IsDebuggerPresent"), not: [][]byte{[]byte("Xen")}}
	both := []byte("Xen IsDebuggerPresent")
	if off, ok := evadeOffset(both, cancel); ok || off != 0 {
		t.Errorf("cancellation candidate = (%d,%v), want (0,false)", off, ok)
	}
	if off, ok := evadeOffset(win, cancel); !ok || off == 0 {
		t.Errorf("no cancellation token = (%d,%v), want a real match", off, ok)
	}
}

func TestR2L06EvasionFamiliesSorted(t *testing.T) {
	fam := evasionFamilies()
	if len(fam) < 6 {
		t.Fatalf("evasionFamilies = %v, want at least 6 embedded families", fam)
	}
	for i := 1; i < len(fam); i++ {
		if fam[i-1] > fam[i] {
			t.Fatalf("evasionFamilies not sorted: %v", fam)
		}
	}
}

// ---- op_close_binary.go : legacy session preserved, proper session deleted ----
func TestR2L06CloseBinarySessionFiles(t *testing.T) {
	dir := metaTestState(t)
	sessionFile := filepath.Join(dir, "session.json")

	// Legacy session without kind: it closes but the file is NOT DELETED.
	legacy := []byte(`{"document":"/tmp/legacy.bin","project":"legacy"}`)
	if err := os.WriteFile(sessionFile, legacy, 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := runCloseBinary(filepath.Join(dir, "job.json"))
	if err != nil {
		t.Fatalf("legacy close: %v", err)
	}
	m := res.(map[string]any)
	if m["session_removed"] != false || m["removed"] != "" || m["closed"] != true {
		t.Errorf("legacy close = %v, want closed=true/session_removed=false", m)
	}
	if b, err := os.ReadFile(sessionFile); err != nil || string(b) != string(legacy) {
		t.Errorf("legacy session was touched: %q, %v", b, err)
	}

	// Proper session: it closes and the file is deleted.
	proper := []byte(`{"kind":"lrecon.session/1","document":"/tmp/proper.bin","project":"proper"}`)
	if err := os.WriteFile(sessionFile, proper, 0o600); err != nil {
		t.Fatal(err)
	}
	res, err = runCloseBinary(filepath.Join(dir, "job.json"))
	if err != nil {
		t.Fatalf("proper close: %v", err)
	}
	m = res.(map[string]any)
	if m["session_removed"] != true || m["closed"] != true {
		t.Errorf("proper close = %v, want closed=true/session_removed=true", m)
	}
	if _, err := os.Stat(sessionFile); !os.IsNotExist(err) {
		t.Errorf("proper session still on disk: %v", err)
	}
}

// ---- op_collect_adb_bugreport.go : local target validation before the device ----
func TestR2L06BugreportLocalValidation(t *testing.T) {
	if _, err := collectADBBugreport(""); err == nil || !strings.Contains(err.Error(), "local path") {
		t.Errorf("empty local = %v, want a local-path error", err)
	}
	if _, err := collectADBBugreport("some-serial"); err == nil || !strings.Contains(err.Error(), ".zip") {
		t.Errorf("non-zip local = %v, want a .zip error", err)
	}
}

// ---- op_comment.go : missing target stays an io error ----
func TestR2L06CommentMissingTargetIsIO(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "no-job.json")
	stdout, stderr, code := runCLIAll(t, "--op", "comment", "--json", missing)
	if code != 2 || !strings.HasPrefix(stderr, "lrecon: ") {
		t.Fatalf("comment missing target: code=%d stderr=%q stdout=%q", code, stderr, stdout)
	}
	op, msg, kind := opEnvelope(t, stdout)
	if op != "comment" || kind != "io" || !strings.Contains(msg, "no such file") {
		t.Fatalf("envelope = op %q msg %q kind %q; want io on missing target", op, msg, kind)
	}
}

// ---- op_compare_functions.go : LRECON_FROM/TO required ----
func TestR2L06CompareFunctionsNeedsEndpoints(t *testing.T) {
	t.Setenv("LRECON_FROM", "")
	t.Setenv("LRECON_TO", "")
	_, err := runOp("compare_functions", lsPath)
	if err == nil || !strings.Contains(err.Error(), "LRECON_FROM") {
		t.Errorf("compare_functions without endpoints = %v, want LRECON_FROM hint", err)
	}
}

// ---- op_compare_application_versions.go : metaIsAppField ----
func TestR2L06MetaIsAppField(t *testing.T) {
	for _, p := range []string{"mobile_package.x", "asar_version.v", "mobile_sdk.s", "kind.k"} {
		if !metaIsAppField(p) {
			t.Errorf("metaIsAppField(%q) = false, want true", p)
		}
	}
	for _, p := range []string{"random.x", "not_a_field", ""} {
		if metaIsAppField(p) {
			t.Errorf("metaIsAppField(%q) = true, want false", p)
		}
	}
}

// ---- op_compare_artifacts.go : saved digest is not rehashed ----
func TestR2L06MetaSideOfSavedDigest(t *testing.T) {
	const artifactHash = "1111111111111111111111111111111111111111111111111111111111111111"
	body, _ := json.Marshal(map[string]any{
		"contract_version": contractVersion,
		"kind":             "elf",
		"target":           map[string]any{"file_sha256": artifactHash, "size": 4242},
	})
	p := writeTemp(t, "r2l06.saved.digest.json", body)
	side, _, err := metaSideOf(p)
	if err != nil {
		t.Fatalf("metaSideOf(saved digest): %v", err)
	}
	if side.SHA256 != artifactHash || side.Size != 4242 {
		t.Errorf("side = %+v, want the stored artifact hash/size (no rehash)", side)
	}
}

// ---- op_compare_bundles.go : metaCountChange ----
func TestR2L06MetaCountChange(t *testing.T) {
	cs := []metaMemberChange{
		{Name: "a", Change: "added"},
		{Name: "b", Change: "added"},
		{Name: "c", Change: "removed"},
		{Name: "d", Change: "changed"},
		{Name: "e", Change: "changed"},
		{Name: "f", Change: "changed"},
	}
	if got := metaCountChange(cs, "added"); got != 2 {
		t.Errorf("added = %d, want 2", got)
	}
	if got := metaCountChange(cs, "removed"); got != 1 {
		t.Errorf("removed = %d, want 1", got)
	}
	if got := metaCountChange(cs, "changed"); got != 3 {
		t.Errorf("changed = %d, want 3", got)
	}
}

// ---- op_compare_javascript_export_shapes.go ----
func TestR2L06ExportTableArity(t *testing.T) {
	tbl := exportTable("exports.foo = function(a, b) {};\nexport const bar = (x) => x;\n")
	if got := tbl["foo"].Arity; got != 2 {
		t.Errorf("foo arity = %d, want 2", got)
	}
	if got := tbl["bar"].Arity; got != 1 {
		t.Errorf("bar arity = %d, want 1", got)
	}
}

func TestR2L06JavascriptExportShapeDiff(t *testing.T) {
	dir := t.TempDir()
	old := "exports.keep = function(a) {};\nexports.gone = function(x, y) {};\n"
	newSrc := "exports.keep = function(a, b) {};\nexports.fresh = function(z) {};\n"
	if err := os.WriteFile(filepath.Join(dir, "old.js"), []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "new.js"), []byte(newSrc), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := opCompareJavascriptExportShapes(dir)
	if err != nil {
		t.Fatalf("export shape diff: %v", err)
	}
	d := res.(exportShapeDiff)
	if len(d.Added) != 1 || d.Added[0].Name != "fresh" {
		t.Errorf("added = %+v, want [fresh]", d.Added)
	}
	if len(d.Removed) != 1 || d.Removed[0].Name != "gone" {
		t.Errorf("removed = %+v, want [gone]", d.Removed)
	}
	if len(d.Changed) != 1 || d.Changed[0].Name != "keep" || d.Changed[0].From != 1 || d.Changed[0].To != 2 {
		t.Errorf("changed = %+v, want keep 1->2", d.Changed)
	}
	if d.Identical {
		t.Error("different export tables reported identical")
	}

	emptyDir := t.TempDir()
	os.WriteFile(filepath.Join(emptyDir, "old.js"), []byte("// nothing exported\n"), 0o600)
	os.WriteFile(filepath.Join(emptyDir, "new.js"), []byte("var q = 1;\n"), 0o600)
	if _, err := opCompareJavascriptExportShapes(emptyDir); err == nil || !strings.Contains(err.Error(), "no exports found") {
		t.Errorf("empty export tables = %v, want a no-exports error", err)
	}
}

// ---- op_compare_managed_members.go : setKeys / cap50 ----
func TestR2L06SetKeysAndCap50(t *testing.T) {
	keys := setKeys(map[string]bool{"z": true, "a": true, "m": true})
	want := []string{"a", "m", "z"}
	if fmt.Sprint(keys) != fmt.Sprint(want) {
		t.Errorf("setKeys = %v, want %v", keys, want)
	}
	in := make([]string, 60)
	for i := range in {
		in[i] = fmt.Sprintf("k%d", i)
	}
	if got := cap50(in); len(got) != 50 {
		t.Errorf("cap50(60) len = %d, want 50", len(got))
	}
	if got := cap50([]string{"a", "b"}); len(got) != 2 {
		t.Errorf("cap50(short) len = %d, want 2", len(got))
	}
}

// ---- op_compare_process_captures.go ----
func TestR2L06CompareProcessCaptures(t *testing.T) {
	a := writeTemp(t, "r2l06.capA.json", []byte(`{"keep":[1,2],"onlyA":[9],"moved":[99]}`))
	b := writeTemp(t, "r2l06.capB.json", []byte(`{"keep":[1,2],"moved":[3],"newB":[7]}`))
	res, err := compareProcessCaptures(a + "," + b)
	if err != nil {
		t.Fatalf("compare captures: %v", err)
	}
	d := res.(rtCaptureDiff)
	if fmt.Sprint(d.OnlyInFirst) != "[onlyA]" || fmt.Sprint(d.OnlyInSecond) != "[newB]" {
		t.Errorf("only_in = %v / %v, want [onlyA]/[newB]", d.OnlyInFirst, d.OnlyInSecond)
	}
	if len(d.Changed) != 1 || d.Changed[0].Symbol != "moved" {
		t.Errorf("changed = %+v, want [moved]", d.Changed)
	}
	if d.Unchanged != 1 {
		t.Errorf("unchanged = %d, want 1", d.Unchanged)
	}
	if !rtSameValues([]string{"1", "2"}, []string{"1", "2"}) || rtSameValues([]string{"1"}, []string{"2"}) || rtSameValues([]string{"1"}, []string{"1", "2"}) {
		t.Error("rtSameValues edge cases wrong")
	}
}

// ---- op_compare_source_to_bundle.go : isScriptName / walkAsarFiles ----
func TestR2L06AsarScriptTree(t *testing.T) {
	for _, n := range []string{"a.js", "b.mjs", "c.cjs"} {
		if !isScriptName(n) {
			t.Errorf("isScriptName(%q) = false", n)
		}
	}
	if isScriptName("a.json") {
		t.Error("isScriptName(a.json) = true, want false")
	}
	root := &asarNode{Files: map[string]*asarNode{
		"main.js": {},
		"lib": {Files: map[string]*asarNode{
			"inner.cjs": {},
			"link.js":   {Link: "../../shared.js"},
		}},
	}}
	out := map[string]bool{}
	walkAsarFiles(root, "", out)
	for _, want := range []string{"main.js", "lib/inner.cjs"} {
		if !out[want] {
			t.Errorf("walkAsarFiles missing %q: %v", want, out)
		}
	}
	if out["lib/link.js"] {
		t.Errorf("symlink member should not be a file: %v", out)
	}
}

// ---- op_compare_wasm_interfaces.go : tag import u8 + u32 (A13) ----
func TestR2L06WasmTagImportSkip(t *testing.T) {
	// kind 4 = tag import: one attribute byte, then LEB128 typeidx.
	c := &wasmCursor{b: []byte{4, 0x00, 0x01, 0x60, 0, 0}}
	if !skipWasmKind(c, 4) {
		t.Fatal("skipWasmKind(kind=4) = false on a well-formed tag import")
	}
	if c.i != 2 {
		t.Errorf("cursor advanced %d bytes, want 2 (attribute + typeidx)", c.i)
	}
	if skipWasmKind(&wasmCursor{b: []byte{4}}, 4) {
		t.Error("truncated tag import accepted")
	}
}

// ---- op_compare_web_captures.go ----
func TestR2L06CaptureHelpers(t *testing.T) {
	if n, ok := captureIndex("capture-3.json"); !ok || n != 3 {
		t.Errorf("captureIndex(capture-3.json) = (%d,%v)", n, ok)
	}
	if _, ok := captureIndex("capture-0.json"); ok {
		t.Error("capture-0.json accepted (N must be > 0)")
	}
	if _, ok := captureIndex("other.json"); ok {
		t.Error("non-capture name accepted")
	}
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "capture-1.json"), []byte("{}"), 0o600)
	if got, want := nextCaptureName(dir, 1), filepath.Join(dir, "capture-2.json"); got != want {
		t.Errorf("nextCaptureName = %q, want %q", got, want)
	}
	lines := captureLines([]webRequestRow{
		{Method: "GET", URL: "/z", Status: 200},
		{Method: "GET", URL: "/a", Status: 404},
	})
	if fmt.Sprint(lines) != "[GET /a 404 GET /z 200]" {
		t.Errorf("captureLines = %v", lines)
	}
	added, removed := []string{}, []string{}
	same := twoPointer([]string{"a", "b"}, []string{"b", "c"}, &added, &removed)
	if same != 1 || fmt.Sprint(removed) != "[a]" || fmt.Sprint(added) != "[c]" {
		t.Errorf("twoPointer = same %d, added %v, removed %v", same, added, removed)
	}
}

// ---- op_compare_web_screenshots.go : RGBA fast path + generic path ----
func TestR2L06DiffScreenshots(t *testing.T) {
	a := image.NewRGBA(image.Rect(0, 0, 4, 3))
	b := image.NewRGBA(image.Rect(0, 0, 4, 3))
	b.Set(2, 1, color.RGBA{R: 200, G: 0, B: 0, A: 255})
	res, err := diffScreenshots(a, b)
	if err != nil {
		t.Fatalf("diff RGBA: %v", err)
	}
	d := res.(screenshotDiff)
	if d.Total != 12 || d.Different != 1 || d.Box == nil || d.Box.X0 != 2 || d.Box.Y0 != 1 || d.Box.X1 != 2 || d.Box.Y1 != 1 {
		t.Errorf("RGBA diff = %+v, want one changed pixel at (2,1)", d)
	}
	if _, err := diffScreenshots(a, a); err == nil || !strings.Contains(err.Error(), "pixel-identical") {
		t.Errorf("identical screens = %v, want a pixel-identical error", err)
	}

	ga := image.NewNRGBA(image.Rect(0, 0, 2, 2))
	gb := image.NewNRGBA(image.Rect(0, 0, 2, 2))
	gb.Set(0, 0, color.NRGBA{R: 255, G: 255, B: 255, A: 255})
	res, err = diffScreenshots(ga, gb)
	if err != nil {
		t.Fatalf("diff generic: %v", err)
	}
	if gd := res.(screenshotDiff); gd.Different != 1 {
		t.Errorf("generic diff = %+v, want one changed pixel", gd)
	}
}

// ---- op_correlate_static_and_runtime.go ----
func TestR2L06CrashImagesAndNorm(t *testing.T) {
	ips := []byte(`{"header":"ignored"}` + "\n" +
		`{"usedImages":[{"name":"App","uuid":"AAAA-BBBB","arch":"arm64"},{"name":"lib","uuid":"cccc","arch":"x86_64"}]}`)
	imgs, report, err := metaCrashImages(ips)
	if err != nil {
		t.Fatalf("metaCrashImages: %v", err)
	}
	if len(imgs) != 2 || imgs[0].Name != "App" || imgs[0].Arch != "arm64" {
		t.Errorf("images = %+v, want App/arm64 first", imgs)
	}
	if _, ok := report["usedImages"]; !ok {
		t.Errorf("body did not override header: %v", report)
	}
	if got, want := metaNormUUID(" AA-BB-CC "), "aabbcc"; got != want {
		t.Errorf("metaNormUUID = %q, want %q", got, want)
	}
}

// ---- op_current_address.go / op_current_document.go / op_current_procedure.go ----
func TestR2L06CurrentSessionOps(t *testing.T) {
	state := t.TempDir()
	t.Setenv("LRECON_STATE", state)
	t.Setenv("LRECON_SESSION", "")
	path := universalFixture(t)
	fns, err := nativeFunctions(path)
	if err != nil || len(fns) == 0 {
		t.Fatalf("nativeFunctions(%s) = %d, %v", path, len(fns), err)
	}
	cursor := fns[len(fns)/2].Start + 1
	if _, err := ops["binary_session"].run(path); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LRECON_AT", fmt.Sprintf("0x%x", cursor))
	if _, err := ops["goto_address"].run(path); err != nil {
		t.Fatalf("goto_address: %v", err)
	}

	addr := metaMustRun(t, "current_address", "")
	if got, want := metaStr(t, addr, "address"), nativeHexAddr(cursor); got != want {
		t.Errorf("current_address.address = %q, want %q", got, want)
	}
	if metaNum(t, addr, "functions") <= 0 || metaStr(t, addr, "procedure") == "" {
		t.Errorf("current_address = %v, want a resolved function", addr)
	}

	doc := metaMustRun(t, "current_document", "")
	if metaNum(t, doc, "documents") < 1 || metaNum(t, doc, "size") <= 0 {
		t.Errorf("current_document = %v, want documents>=1 and size>0", doc)
	}
	if got, want := metaStr(t, doc, "session"), filepath.Join(state, "session.json"); got != want {
		t.Errorf("current_document.session = %q, want %q", got, want)
	}

	proc := metaMustRun(t, "current_procedure", "")
	if !metaBool(t, proc, "found") || metaStr(t, proc, "procedure") == "" {
		t.Errorf("current_procedure = %v, want found=true", proc)
	}
}

// ---- wrappers: close_frida_session / close_rizin_debug_session (CLI refusal) ----
func TestR2L06LiveSessionRefusals(t *testing.T) {
	for _, name := range []string{"close_frida_session", "close_rizin_debug_session"} {
		stdout, stderr, code := runCLIAll(t, "--op", name, "--json", lsPath)
		if code != 2 || !strings.HasPrefix(stderr, "lrecon: ") {
			t.Errorf("%s: code=%d stderr=%q stdout=%q", name, code, stderr, stdout)
			continue
		}
		op, msg, kind := opEnvelope(t, stdout)
		if op != name || kind != "out_of_scope" || msg == "" {
			t.Errorf("%s envelope = op %q msg %q kind %q, want out_of_scope", name, op, msg, kind)
		}
	}
}

// ---- op_close_gdb_session.go : closeGdbSessionLLDB contract ----
func TestR2L06CloseGdbSessionContract(t *testing.T) {
	res, err := closeGdbSessionLLDB(lsPath)
	if err != nil {
		t.Fatalf("closeGdbSessionLLDB: %v", err)
	}
	if res == nil {
		t.Fatal("closeGdbSessionLLDB returned nil result")
	}
	if closed, ok := res.(rtGdbClosed); ok {
		if closed.Binary != lsPath || closed.Engine != "lldb" || closed.Exited || closed.Note == "" {
			t.Errorf("rtGdbClosed = %+v, want lldb / Exited=false / a note", closed)
		}
	}
	// Otherwise, if lldb is absent it returns a *skip; that is environment noise, not a source error.
}
