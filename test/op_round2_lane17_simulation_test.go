package main

// Tur 2 Lane 17 independent simulation tests. LSP gopls could not be started
// in this environment due to an fd/pipe error, so real behavior is verified here.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func r2l17Write(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// op_stop_adb_app.go / op_uninstall_adb_package.go: empty target refusal.
func TestR2L17AdbEmptyTargetRefused(t *testing.T) {
	if _, err := opStopAdbApp("   "); err == nil || !strings.Contains(err.Error(), "stop_adb_app needs a package name") {
		t.Fatalf("stop empty: %v", err)
	}
	if _, err := opUninstallAdbPackage(""); err == nil || !strings.Contains(err.Error(), "uninstall_adb_package needs a package name") {
		t.Fatalf("uninstall empty: %v", err)
	}
}

// op_verify_managed_native_boundaries.go: name matching rules.
func TestR2L17ManagedNativeNameMatching(t *testing.T) {
	if !sameModule("User32.dll", "/Windows/System32/user32.dll") || !sameModule("user32", "user32.dll") {
		t.Fatal("sameModule did not normalize suffix/path")
	}
	if sameModule("kernel32", "user32") {
		t.Fatal("sameModule equated different modules")
	}
	if !sameImport("_MessageBoxA@16", "MessageBoxA") {
		t.Fatal("sameImport did not normalize Win32 decoration")
	}
	if !sameImport("GetProcAddress", "getprocaddress") {
		t.Fatal("sameImport did not normalize case")
	}
	if sameImport("MessageBoxA", "MessageBoxW") {
		t.Fatal("sameImport equated different functions")
	}
	if joinNote("", "x") != "x" || joinNote("a", "b") != "a; b" {
		t.Fatalf("joinNote: %q / %q", joinNote("", "x"), joinNote("a", "b"))
	}
}

// op_verify_unknown_resolution.go: normalization and contradictory claim refusal.
func TestR2L17ResolutionNormalization(t *testing.T) {
	if !metaSameResolution("  MessageBoxA.  ", "messageboxa") {
		t.Fatal("metaSameResolution did not normalize")
	}
	if metaSameResolution("  ", "x") || metaSameResolution("a", "b") {
		t.Fatal("metaSameResolution matched incorrectly")
	}
	if metaNormResolution(" Foo   Bar.;:") != "foo bar" {
		t.Fatalf("metaNormResolution: %q", metaNormResolution(" Foo   Bar.;:"))
	}
	w, err := metaWantedResolution(metaJob{Resolution: "a", ResolvedAs: "A."})
	if err != nil || w != "a" {
		t.Fatalf("metaWantedResolution same: %q %v", w, err)
	}
	if _, err := metaWantedResolution(metaJob{Resolution: "a", ResolvedAs: "b"}); err == nil {
		t.Fatal("contradictory resolution was not refused")
	}
	w, err = metaWantedResolution(metaJob{ResolvedAs: "only"})
	if err != nil || w != "only" {
		t.Fatalf("only resolved_as: %q %v", w, err)
	}
}

// op_trace_dylib_resolution.go / op_netc_util.go: @rpath candidate generation and selection
// of the first existing file are verified with real files.
func TestR2L17DylibCandidateResolution(t *testing.T) {
	exeDir := t.TempDir()
	other := t.TempDir()
	target := filepath.Join(exeDir, "libfoo.dylib")
	if err := os.WriteFile(target, []byte("dylib"), 0o644); err != nil {
		t.Fatal(err)
	}
	cands := netcDylibCandidates("@rpath/libfoo.dylib", exeDir, other, []string{"@executable_path/", "@executable_path/"})
	if len(cands) != 2 || cands[0] != target {
		t.Fatalf("@rpath candidates: %#v", cands)
	}
	if got := netcFirstExisting(cands); got != target {
		t.Fatalf("netcFirstExisting: %q want %q", got, target)
	}
	if got := netcFirstExisting([]string{filepath.Join(other, "none.dylib")}); got != "" {
		t.Fatalf("non-existent file was selected: %q", got)
	}
	plain := netcDylibCandidates("/usr/lib/libSystem.B.dylib", exeDir, other, nil)
	if len(plain) != 1 || plain[0] != "/usr/lib/libSystem.B.dylib" {
		t.Fatalf("plain dylib: %#v", plain)
	}
}

// op_trace_native_ui_action.go: getevent header/value distinction.
func TestR2L17GeteventParsing(t *testing.T) {
	if !rt2GeteventHeader("add device 1: /dev/input/event0") || !rt2GeteventHeader("  name:\t\"qwerty\"") || rt2GeteventHeader("[  12.34] /dev/input/event0: EV_KEY KEY_A DOWN") {
		t.Fatal("rt2GeteventHeader classified incorrectly")
	}
	for in, want := range map[string]int64{"UP": 0, "OFF": 0, "DOWN": 1, "ON": 1, "REPEAT": 2, "1f": 31, "-1": -1} {
		got, ok := rt2EventValue(in)
		if !ok || got != want {
			t.Fatalf("rt2EventValue(%q)=%d,%v want %d", in, got, ok, want)
		}
	}
	if _, ok := rt2EventValue("BOGUS"); ok {
		t.Fatal("invalid value accepted")
	}
}

// op_trace_web_module_imports.go: relative spec, resolution and path safety.
func TestR2L17ModuleImportResolution(t *testing.T) {
	if !isRelativeSpec("./a") || !isRelativeSpec("../b") || isRelativeSpec("lodash") || isRelativeSpec(".") {
		t.Fatal("isRelativeSpec wrong")
	}
	dir := t.TempDir()
	a := filepath.Join(dir, "a.js")
	if err := os.WriteFile(a, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.mjs"), []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	if p, st := resolveRelative(filepath.Join(dir, "entry.js"), "./a"); st != "read" || p != a {
		t.Fatalf("extensionless .js: %q %q", p, st)
	}
	if p, st := resolveRelative(filepath.Join(dir, "entry.js"), "./b"); st != "read" || !strings.HasSuffix(p, "b.mjs") {
		t.Fatalf(".mjs: %q %q", p, st)
	}
	if _, st := resolveRelative(filepath.Join(dir, "entry.js"), "./nope"); st != "missing" {
		t.Fatalf("missing: %q", st)
	}
	if !within(dir, filepath.Join(dir, "x")) || within(dir, dir) || within(dir, filepath.Join(dir, "..", "x")) {
		t.Fatal("within wrong")
	}
	if r := relativeOrBase(a, filepath.Join(dir, "a.js")); r != "a.js" {
		t.Fatalf("relativeOrBase: %q", r)
	}
}

// op_trace_web_source_location.go: v3 gate and sourceRoot application.
func TestR2L17SourceMapDecode(t *testing.T) {
	if _, _, err := decodeMapFile("x.map", []byte(`{"version":2}`)); err == nil || !strings.Contains(err.Error(), "not a v3 source map") {
		t.Fatalf("v2 accepted: %v", err)
	}
	if _, _, err := decodeMapFile("x.map", []byte(`{bad`)); err == nil || !strings.Contains(err.Error(), "not a JSON source map") {
		t.Fatalf("malformed JSON accepted: %v", err)
	}
	sm, _, err := decodeMapFile("x.map", []byte(`{"version":3,"sourceRoot":"http://h/src","sources":["a.js","/abs.js"],"mappings":""}`))
	if err != nil {
		t.Fatal(err)
	}
	got := resolveMapSources(sm)
	if len(got) != 2 || got[0] != "http:/h/src/a.js" || got[1] != "/abs.js" {
		t.Fatalf("resolveMapSources: %#v", got)
	}
}

// op_web_util.go: VLQ, mappings, line index and endpoint validation.
func TestR2L17WebUtilCore(t *testing.T) {
	// AAc = [0,0,0] (3 field), AACA = [0,0,0,0] (4 field, name 0).
	segs, err := decodeMappings("AAAA;AACA", 0)
	if err != nil || len(segs) != 2 {
		t.Fatalf("decodeMappings: %#v %v", segs, err)
	}
	// AACA = [col 0, src 0, origLine +1, origCol 0]; no 4th field (name).
	if segs[0].GenLine != 0 || segs[1].GenLine != 1 || segs[1].Source != 0 || segs[1].OrigLine != 1 || segs[1].OrigCol != 0 || segs[1].Name != -1 {
		t.Fatalf("segment fields: %#v %#v", segs[0], segs[1])
	}
	lim, err := decodeMappings("AAAA;AACA", 1)
	if err != nil || len(lim) != 1 {
		t.Fatalf("limit: %#v %v", lim, err)
	}
	if _, _, err := decodeVLQ("!", 0); err == nil {
		t.Fatal("non-base64 byte accepted")
	}
	ix := newLineIndex("a\nb\nc")
	if ix.at(0) != 1 || ix.at(2) != 2 || ix.at(4) != 3 {
		t.Fatalf("lineIndex: %d %d %d", ix.at(0), ix.at(2), ix.at(4))
	}
	ep, arg, err := webTarget("127.0.0.1:9222=42")
	if err != nil || ep != "127.0.0.1:9222" || arg != "42" {
		t.Fatalf("endpoint+arg: %q %q %v", ep, arg, err)
	}
	// localhost is normalized.
	if ep, _, err := webTarget("localhost:9222"); err != nil || ep != "127.0.0.1:9222" {
		t.Fatalf("localhost: %q %v", ep, err)
	}
	if _, _, err := webTarget("127.0.0.1:/tmp/x"); err == nil {
		t.Fatal("path used as port accepted")
	}
	if _, _, err := webTarget("8.8.8.8:9222"); err == nil || !strings.Contains(err.Error(), "refusing") {
		t.Fatalf("remote host not refused: %v", err)
	}
	if _, _, err := webTarget("https://example.com"); err == nil {
		t.Fatal("website not refused")
	}
}

// op_table_test_helper_test.go: contract classification.
func TestR2L17TableContractClassification(t *testing.T) {
	if !opClassIsDefect(opClassPanic) || !opClassIsDefect(opClassBadJSON) || !opClassIsDefect(opClassTimeout) || !opClassIsDefect(opClassBadExit) {
		t.Fatal("defect classes were missed")
	}
	if opClassIsDefect(opClassOK) || opClassIsDefect(opClassSkippedTool) {
		t.Fatal("normal class mistaken for defect")
	}
	if c, _ := classifyOpRun(2, `{"kind":"needs_arg","error":"x"}`, ""); c != "needs_arg" {
		t.Fatalf("envelope kind: %q", c)
	}
	if c, _ := classifyOpRun(0, `{"op":"x","result":{"a":1}}`, ""); c != opClassOK {
		t.Fatalf("ok envelope: %q", c)
	}
	if c, _ := classifyOpRun(0, `{"op":"x","result":null}`, ""); c != opClassBadJSON {
		t.Fatalf("null result: %q", c)
	}
	if c, _ := classifyOpRun(2, "", "panic: boom\n"); c != opClassPanic {
		t.Fatalf("panic: %q", c)
	}
	if c, _ := classifyOpRun(7, "", ""); c != opClassBadExit {
		t.Fatalf("bad exit: %q", c)
	}
	if c, _ := classifyOpRun(2, "", "lrecon: something needs a target path"); c != opClassNeedsArg {
		t.Fatalf("prose needs: %q", c)
	}
	if c, _ := classifyOpRun(2, "", "foo"); c != "bad_arg" && c != opClassBadArg {
		// The last branch of the prose fallback is bad_arg; the constant name may be opClassBadArg.
		if c != opClassBadArg {
			t.Fatalf("prose fallback: %q", c)
		}
	}
	if m := opStderrMessage("\x1b[31mlrecon: real\x1b[0m\rpartial\nlrecon: real"); m != "lrecon: real" {
		t.Fatalf("opStderrMessage: %q", m)
	}
	if !opNeedsRe.MatchString("lrecon_analysis_dir not set") || !opNeedsRe.MatchString("lrecon_query is empty") {
		t.Fatal("opNeedsRe did not match")
	}
}

// op_verify_adversarial.go: literal sha256 acceptance and empty expect refusal.
func TestR2L17AdversarialRecordedHash(t *testing.T) {
	const sha = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	got, err := advRecordedSHA256("  " + strings.ToUpper(sha) + " ")
	if err != nil || got != sha {
		t.Fatalf("literal sha: %q %v", got, err)
	}
	if _, err := advRecordedSHA256("  "); err == nil || !strings.Contains(err.Error(), "expect") {
		t.Fatalf("empty expect: %v", err)
	}
	p := r2l17Write(t, "sample.bin", "abc")
	tgt, _, err := advFileSHA256(p)
	if err != nil || tgt.FileSHA256 == "" {
		t.Fatalf("advFileSHA256: %+v %v", tgt, err)
	}
	// Should produce a hash that matches the real file content.
	if _, err := advRecordedSHA256(tgt.FileSHA256); err != nil {
		t.Fatalf("its own hash was refused: %v", err)
	}
	// A short hex literal is not a digest of the file -> unreadable.
	if _, err := advRecordedSHA256("deadbeef"); err == nil {
		t.Fatal("short hex digest accepted")
	}
}

// op_verify_reconstruction.go: claim verification (via job file).
func TestR2L17VerifyReconstruction(t *testing.T) {
	bin := r2l17Write(t, "recon.bin", "ABCDEFGH")
	job := map[string]any{
		"file": bin,
		"claims": []map[string]any{
			{"offset": 1, "length": 2, "expect": "4243"},
			{"offset": 6, "length": 2, "expect": "ffff"},
		},
	}
	b, _ := json.Marshal(job)
	jp := r2l17Write(t, "job.json", string(b))
	res, err := runVerifyReconstruction(jp)
	if err != nil {
		t.Fatal(err)
	}
	m := res.(map[string]any)
	if m["verified"] != false || m["matched"] != 1 || m["mismatched"] != 1 {
		t.Fatalf("reconstruction result: %#v", m)
	}
	claims := m["claims"].([]metaClaimCheck)
	if !claims[0].Match || claims[1].Match {
		t.Fatalf("claim match: %#v %#v", claims[0], claims[1])
	}
}

// op_trace_feature.go: hit on a real binary file in string search mode.
func TestR2L17TraceFeatureString(t *testing.T) {
	bin := r2l17Write(t, "feat.bin", "xxTARGETyyTARGETzz")
	job := map[string]any{"file": bin, "string": "TARGET"}
	b, _ := json.Marshal(job)
	jp := r2l17Write(t, "job.json", string(b))
	res, err := runTraceFeature(jp)
	if err != nil {
		t.Fatal(err)
	}
	m := res.(map[string]any)
	if m["mode"] != "string" {
		t.Fatalf("mode: %v", m["mode"])
	}
	if m["count"] != 2 || m["truncated"] != false {
		t.Fatalf("count/truncated: %v %v", m["count"], m["truncated"])
	}
	// Explicit error when there is no argument.
	jp2 := r2l17Write(t, "job2.json", `{}`)
	if _, err := runTraceFeature(jp2); err == nil || !strings.Contains(err.Error(), "needs") {
		t.Fatalf("empty job: %v", err)
	}
}

// op_observe_native_ui.go: the tool exits 0 but writes no file (idle device).
func TestR2L17ObserveNativeUIIdle(t *testing.T) {
	rt2TestTools(t, map[string]string{"adb": `#!/bin/sh
if [ "$1" = "devices" ]; then printf 'List of devices attached\nemu-1\tdevice\n'; exit 0; fi
if [ "$1" = "shell" ] && [ "$2" = "uiautomator" ]; then
  printf 'UI not updated\n'
  exit 0
fi
exit 0
`})
	res, err := opObserveNativeUI("")
	if err != nil {
		t.Fatalf("idle dump: %v", err)
	}
	ui, ok := res.(rt2NativeUI)
	if !ok || ui.Dumped || ui.Nodes != 0 || ui.Bytes != 0 || ui.XML != "" {
		t.Fatalf("idle dump result = %+v", res)
	}
	if !strings.HasPrefix(ui.Path, "/data/local/tmp/ui-") || !strings.HasSuffix(ui.Path, ".xml") {
		t.Fatalf("idle dump path = %q", ui.Path)
	}
	if ui.Cleanup != "nothing written, nothing to remove" {
		t.Fatalf("idle dump cleanup = %q", ui.Cleanup)
	}
}

// op_trace_javascript_semantics.go: the CDP failure and pause branches.
func TestR2L17TraceJavascriptFailureBranches(t *testing.T) {
	for _, bad := range []string{"127.0.0.1:9222=0", "127.0.0.1:9222=abc"} {
		if _, err := opTraceJavascriptSemantics(bad); err == nil || !strings.Contains(err.Error(), "no line to break on") {
			t.Fatalf("bad line %q: %v", bad, err)
		}
	}

	const ep = "127.0.0.1:9222=42"
	enable := okStep("Debugger.enable", map[string]any{})
	pauseNone := okStep("Debugger.setPauseOnExceptions", map[string]any{})
	okBp := okStep("Debugger.setBreakpointByUrl", map[string]any{
		"breakpointId": "bp1",
		"locations": []any{
			map[string]any{"scriptId": "5", "lineNumber": float64(41), "columnNumber": float64(2)},
		},
	})

	fakeDriver(t, webOut{Steps: []webStepResult{enable, {Method: "Debugger.setBreakpointByUrl", Ok: false}}})
	if _, err := opTraceJavascriptSemantics(ep); err == nil || !strings.Contains(err.Error(), "setBreakpointByUrl") {
		t.Fatalf("failed breakpoint step: %v", err)
	}

	fakeDriver(t, webOut{Steps: []webStepResult{enable, okStep("Debugger.setBreakpointByUrl", map[string]any{"breakpointId": "bp1"}), pauseNone}})
	if _, err := opTraceJavascriptSemantics(ep); err == nil || !strings.Contains(err.Error(), "never resolved and never paused") {
		t.Fatalf("unresolved line: %v", err)
	}

	target := &webTargetRow{ID: "T1", URL: "file:///a.js"}
	paused := event("Debugger.paused", map[string]any{"callFrames": []any{
		map[string]any{"functionName": "go", "url": "file:///a.js"},
	}})
	fakeDriver(t, webOut{Steps: []webStepResult{enable, okBp, pauseNone}, Target: target, Events: []webEvent{paused}})
	if _, err := opTraceJavascriptSemantics(ep); err == nil || !strings.Contains(err.Error(), "never resumed") {
		t.Fatalf("paused but not resumed: %v", err)
	}

	fakeDriver(t, webOut{Resumed: true, Steps: []webStepResult{enable, okBp, pauseNone}, Target: target, Events: []webEvent{paused}})
	res, err := opTraceJavascriptSemantics(ep)
	if err != nil {
		t.Fatalf("paused and resumed: %v", err)
	}
	rep := res.(pauseReport)
	if !rep.Paused || !rep.Resumed || rep.Breakpoint != "bp1" || rep.Target != "T1" || rep.URL != "file:///a.js" {
		t.Fatalf("pause report = %+v", rep)
	}
	if len(rep.Locations) != 1 || rep.Locations[0].Line != 42 || rep.Locations[0].Column != 2 {
		t.Fatalf("locations = %+v", rep.Locations)
	}
	if len(rep.CallFrames) != 1 || rep.CallFrames[0] != "go@file:///a.js" {
		t.Fatalf("call frames = %+v", rep.CallFrames)
	}
}
