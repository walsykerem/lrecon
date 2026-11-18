package main

// Lane A13: the fifteen compare_current ops of the release sweep. Two of them
// carried a wrong answer worth a regression test (a saved digest was hashed as
// if it were the artifact, a wasm tag import was read as a func import); the
// rest get one cheap assertion each so the lane's whole surface stays covered.

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// a13Zip writes a zip with the given members, which is what compare_bundles reads.
func a13Zip(t *testing.T, name string, files map[string]string) string {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for n, body := range files {
		f, err := w.Create(n)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return writeTemp(t, name, buf.Bytes())
}

// a13WasmTag builds a module whose import section starts with a tag import
// (kind 0x04: attribute byte, then typeidx) followed by a func import. Reading
// the tag as one u32 ate the attribute and part of the index, so the whole
// section was refused as cut and the imports vanished from the answer.
func a13WasmTag(importName, tagName string, typeIdx byte) []byte {
	typeSec := []byte{2, 0x60, 0, 0, 0x60, 0, 0}
	imp := []byte{2}
	imp = append(imp, sfWasmString("env")...)
	imp = append(imp, sfWasmString(tagName)...)
	imp = append(imp, 4, 0x00, typeIdx)
	imp = append(imp, sfWasmString("env")...)
	imp = append(imp, sfWasmString(importName)...)
	imp = append(imp, 0, typeIdx)
	out := []byte("\x00asm")
	out = append(out, sf32(1)...)
	out = append(out, sfWasmSec(1, typeSec)...)
	return append(out, sfWasmSec(2, imp)...)
}

// TestA13WasmTagImport keeps the tag-import fix pinned: typeidx 1 is what the
// old one-u32 read swallowed, so a typeidx-0 fixture would pass either way.
func TestA13WasmTagImport(t *testing.T) {
	a := writeTemp(t, "tag_a.wasm", a13WasmTag("fn", "tag_c", 1))
	b := writeTemp(t, "tag_b.wasm", a13WasmTag("fn2", "tag_c", 1))
	m := metaMustRun(t, "compare_wasm_interfaces", a+","+b)
	if got := metaNum(t, m, "left_imports"); got != 2 {
		t.Fatalf("left_imports = %d, want 2 (the tag import was dropped)", got)
	}
	if got := metaNum(t, m, "right_imports"); got != 2 {
		t.Fatalf("right_imports = %d, want 2", got)
	}
	if got := fmt.Sprint(m["imports_only_left"]); !strings.Contains(got, "env.fn") {
		t.Errorf("imports_only_left = %v, want env.fn", got)
	}
	if got := fmt.Sprint(m["imports_only_right"]); !strings.Contains(got, "env.fn2") {
		t.Errorf("imports_only_right = %v, want env.fn2", got)
	}
	if metaBool(t, m, "identical") {
		t.Error("different func imports reported identical")
	}
}

// TestA13SavedDigestIdentity keeps the saved-digest fix pinned: a digest of T
// compared with T is the same bytes, never "the digest file changed".
func TestA13SavedDigestIdentity(t *testing.T) {
	artifact := probeFixture(t, lsPath)
	body, err := json.MarshalIndent(artifact, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	digest := writeTemp(t, "artifact.digest.json", body)
	job := metaTestArg(t, map[string]any{"old": digest, "new": lsPath})

	m := metaMustRun(t, "compare_artifacts", job)
	if !metaBool(t, m, "identical") || metaNum(t, m, "count") != 0 {
		t.Fatalf("digest of T vs T: identical = %v count = %d, want true/0",
			m["identical"], metaNum(t, m, "count"))
	}
	old, _ := m["old"].(map[string]any)
	if got, want := metaStr(t, old, "sha256"), artifact.Target.FileSHA256; got != want {
		t.Errorf("old.sha256 = %s, want the artifact hash %s", got, want)
	}
	if got, want := metaNum(t, old, "size"), int(artifact.Target.Size); got != want {
		t.Errorf("old.size = %d, want %d", got, want)
	}

	v := metaMustRun(t, "compare_application_versions", job)
	if got := metaStr(t, v, "verdict"); got != "same bytes" {
		t.Errorf("verdict = %q, want \"same bytes\"", got)
	}
	if !metaBool(t, v, "same_release") {
		t.Error("same_release = false for a digest of the artifact it was taken from")
	}
}

func TestA13CompareBundles(t *testing.T) {
	old := a13Zip(t, "old.zip", map[string]string{"index.js": "a", "gone.txt": "g"})
	new := a13Zip(t, "new.zip", map[string]string{"index.js": "b", "extra.js": "e"})
	m := metaMustRun(t, "compare_bundles", metaTestArg(t, map[string]any{"old": old, "new": new}))
	if metaBool(t, m, "identical") {
		t.Fatal("identical = true for two different bundles")
	}
	if metaNum(t, m, "added") != 1 || metaNum(t, m, "removed") != 1 || metaNum(t, m, "changed") != 1 {
		t.Errorf("added/removed/changed = %d/%d/%d, want 1/1/1",
			metaNum(t, m, "added"), metaNum(t, m, "removed"), metaNum(t, m, "changed"))
	}
	if fmt.Sprint(m["added"]) == "" || !strings.Contains(fmt.Sprint(m["changes"]), "extra.js") {
		t.Errorf("changes = %v, want extra.js added", m["changes"])
	}
}

func TestA13JavascriptExportShapes(t *testing.T) {
	dir := t.TempDir()
	oldSrc := "exports.alpha = function (x, y) {};\nexports.gamma = function (q) {};\n"
	newSrc := "exports.alpha = function (x, y, z) {};\nexports.delta = function () {};\n"
	for name, body := range map[string]string{"old.js": oldSrc, "new.js": newSrc} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	m := metaMustRun(t, "compare_javascript_export_shapes", dir)
	if metaBool(t, m, "identical") {
		t.Fatal("identical = true for changed arity plus a removed export")
	}
	if got := fmt.Sprint(m["changed"]); !strings.Contains(got, "alpha") {
		t.Errorf("changed = %v, want alpha's arity change", m["changed"])
	}
	if got := fmt.Sprint(m["removed"]); !strings.Contains(got, "gamma") {
		t.Errorf("removed = %v, want gamma", m["removed"])
	}
	if got := fmt.Sprint(m["added"]); !strings.Contains(got, "delta") {
		t.Errorf("added = %v, want delta", m["added"])
	}
	// A directory holding one script cannot be diffed against itself.
	if _, err := runOp("compare_javascript_export_shapes", t.TempDir()); err == nil ||
		!strings.Contains(err.Error(), "want 2") {
		t.Fatalf("one-file dir error = %v, want a want-2 refusal", err)
	}
}

func TestA13CompareProcessCaptures(t *testing.T) {
	first := writeTemp(t, "first.json", []byte(`{"sym_a":[1,2],"sym_b":[3]}`))
	second := writeTemp(t, "second.json", []byte(`{"sym_a":[1,9],"sym_c":[4]}`))
	m := metaMustRun(t, "compare_process_captures", first+","+second)
	if metaNum(t, m, "unchanged") != 0 {
		t.Errorf("unchanged = %d, want 0", metaNum(t, m, "unchanged"))
	}
	if got := fmt.Sprint(m["only_in_second"]); !strings.Contains(got, "sym_c") {
		t.Errorf("only_in_second = %v, want sym_c", m["only_in_second"])
	}
	if _, err := runOp("compare_process_captures", first); err == nil ||
		!strings.Contains(err.Error(), "two capture files") {
		t.Fatalf("single path error = %v, want the two-capture refusal", err)
	}
}

func TestA13CompareManagedMembers(t *testing.T) {
	pe := metaManagedPE(t)
	m := metaMustRun(t, "compare_managed_members", pe+","+pe)
	if got := metaNum(t, m, "left_types"); got == 0 {
		t.Fatal("left_types = 0: the managed fixture lost its TypeDef rows")
	}
	for _, key := range []string{"types_only_left", "types_only_right", "methods_only_left", "methods_only_right"} {
		if n := metaNum(t, m, key+"_total"); n != 0 {
			t.Errorf("%s_total = %d for a file compared with itself, want 0", key, n)
		}
	}
}

func TestA13CompareSourceToBundle(t *testing.T) {
	asar := writeAsar(t)
	m := metaMustRun(t, "compare_source_to_bundle", asar)
	if got := metaNum(t, m, "scripts"); got == 0 {
		t.Fatalf("scripts = 0: the asar's index.js and main.js were not seen")
	}
	if metaNum(t, m, "maps") != 0 {
		t.Errorf("maps = %d, want 0 for a bundle with no source maps", metaNum(t, m, "maps"))
	}
	if metaNum(t, m, "scripts_without_map_total") != metaNum(t, m, "scripts") {
		t.Errorf("scripts_without_map_total = %d, want every script (%d)",
			metaNum(t, m, "scripts_without_map_total"), metaNum(t, m, "scripts"))
	}
}

func TestA13CorrelateStaticAndRuntime(t *testing.T) {
	u := uuidFromHex("D4B9C2DB99983233A2BE5577126F0C8D")
	macho := writeTemp(t, "demo", thinUUIDMachO(u))
	ips := writeTemp(t, "crash.ips", []byte(
		`{"app_name":"Demo","timestamp":"2026-11-03 00:00:00.00 +0000"}`+"\n"+
			`{"usedImages":[{"name":"Demo","uuid":"D4B9C2DB-9998-3233-A2BE-5577126F0C8D","arch":"x86_64"}]}`))
	m := metaMustRun(t, "correlate_static_and_runtime", metaTestArg(t, map[string]any{"file": macho, "crash": ips}))
	if metaNum(t, m, "matches") != 1 || metaNum(t, m, "mismatches") != 0 {
		t.Fatalf("matches/mismatches = %d/%d, want 1/0", metaNum(t, m, "matches"), metaNum(t, m, "mismatches"))
	}
	if got := metaStr(t, m, "verdict"); !strings.Contains(got, "matches") {
		t.Errorf("verdict = %q, want a match", got)
	}
}

// TestA13CurrentOps drives the three needs=false ops off one written session:
// they must agree with each other and refuse an empty state, not answer from
// whatever session happens to be on the machine.
func TestA13CurrentOps(t *testing.T) {
	state := metaTestState(t)
	doc := writeTemp(t, "demo", thinUUIDMachO(uuidFromHex("00112233445566778899AABBCCDDEEFF")))
	s := nativeSession{Kind: "lrecon.session/1", Project: "a13", Document: doc, Cursor: 0x1000, Documents: []string{doc}}
	body, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(state, "session.json"), body, 0o644); err != nil {
		t.Fatal(err)
	}

	d := metaMustRun(t, "current_document", "")
	if metaStr(t, d, "document") != doc || metaStr(t, d, "project") != "a13" {
		t.Errorf("current_document = %v/%v, want %s/a13", d["document"], d["project"], doc)
	}
	a := metaMustRun(t, "current_address", "")
	if metaNum(t, a, "functions") != 0 {
		t.Errorf("current_address functions = %d for a macho with no symbol table, want 0",
			metaNum(t, a, "functions"))
	}
	// current_procedure degrades the same way: address still answered, no table.
	p := metaMustRun(t, "current_procedure", "")
	if metaNum(t, p, "functions") != 0 || metaBool(t, p, "found") {
		t.Errorf("current_procedure = %v, want functions 0 and found false", p)
	}
	if metaStr(t, p, "address") != metaStr(t, a, "address") || !strings.Contains(metaStr(t, p, "note"), "no function table") {
		t.Errorf("current_procedure = %v, want %s plus the no-table note", p, metaStr(t, a, "address"))
	}

	// An isolated empty state is the only way to see the no-session refusal.
	t.Setenv("LRECON_STATE", t.TempDir())
	for _, op := range []string{"current_address", "current_document", "current_procedure"} {
		if _, err := runOp(op, ""); err == nil || !strings.Contains(err.Error(), "no session:") {
			t.Errorf("%s on an empty state: err = %v, want the no-session refusal", op, err)
		}
	}
}

func TestA13DiffScreenshots(t *testing.T) {
	black := color.RGBA{0, 0, 0, 255}
	white := color.RGBA{255, 255, 255, 255}
	a := image.NewRGBA(image.Rect(0, 0, 8, 6))
	for y := range 6 {
		for x := range 8 {
			a.SetRGBA(x, y, black)
		}
	}
	b := image.NewRGBA(image.Rect(0, 0, 8, 6))
	for y := range 6 {
		for x := range 8 {
			b.SetRGBA(x, y, black)
		}
	}
	for y := 2; y <= 3; y++ {
		for x := 1; x <= 4; x++ {
			b.SetRGBA(x, y, white)
		}
	}
	got, err := diffScreenshots(a, b)
	if err != nil {
		t.Fatal(err)
	}
	d := got.(screenshotDiff)
	if d.Width != 8 || d.Height != 6 || d.Total != 48 {
		t.Fatalf("size = %dx%d (%d px), want 8x6 (48)", d.Width, d.Height, d.Total)
	}
	if d.Different != 8 || d.MeanDelta != 765 {
		t.Errorf("different/mean = %d/%v, want 8/765", d.Different, d.MeanDelta)
	}
	if d.Box == nil || *d.Box != (diffBox{X0: 1, Y0: 2, X1: 4, Y1: 3}) {
		t.Errorf("box = %v, want 1,2..4,3", d.Box)
	}
	// The RGBA fast path must answer exactly what the interface walk answers.
	var slowN int
	var slowSum float64
	var slowBox *diffBox
	for y := range 6 {
		for x := range 8 {
			ar, ag, ab, _ := a.At(x, y).RGBA()
			br, bg, bb, _ := b.At(x, y).RGBA()
			delta := absDiff(int(ar>>8), int(br>>8)) + absDiff(int(ag>>8), int(bg>>8)) + absDiff(int(ab>>8), int(bb>>8))
			if delta <= pixelThreshold {
				continue
			}
			slowN++
			slowSum += float64(delta)
			if slowBox == nil {
				slowBox = &diffBox{x, y, x, y}
			}
			slowBox.X0, slowBox.Y0 = min(slowBox.X0, x), min(slowBox.Y0, y)
			slowBox.X1, slowBox.Y1 = max(slowBox.X1, x), max(slowBox.Y1, y)
		}
	}
	if d.Different != slowN || d.MeanDelta != slowSum/float64(slowN) || d.Box == nil || *d.Box != *slowBox {
		t.Errorf("fast path %d/%v/%v != interface walk %d/%v/%v",
			d.Different, d.MeanDelta, d.Box, slowN, slowSum/float64(slowN), slowBox)
	}

	// The gray pair walks the generic image.Image path, not the RGBA fast one.
	ga := image.NewGray(image.Rect(0, 0, 4, 4))
	gb := image.NewGray(image.Rect(0, 0, 4, 4))
	gb.SetGray(3, 3, color.Gray{Y: 255})
	if got, err := diffScreenshots(ga, gb); err != nil {
		t.Fatal(err)
	} else if d := got.(screenshotDiff); d.Different != 1 {
		t.Errorf("gray pair different = %d, want 1", d.Different)
	}

	if _, err := diffScreenshots(a, a); err == nil || !strings.Contains(err.Error(), "pixel-identical") {
		t.Fatalf("identical captures err = %v, want the pixel-identical refusal", err)
	}
	if _, err := diffScreenshots(a, image.NewRGBA(image.Rect(0, 0, 9, 6))); err == nil ||
		!strings.Contains(err.Error(), "differ in size") {
		t.Fatalf("size mismatch err = %v, want the size refusal", err)
	}
}

func TestA13CaptureCompareHelpers(t *testing.T) {
	rows := []webRequestRow{
		{Method: "GET", URL: "http://a/1", Status: 200},
		{Method: "GET", URL: "http://a/2", Status: 404},
	}
	lines := captureLines(rows)
	if len(lines) != 2 || lines[0] != "GET http://a/1 200" {
		t.Fatalf("captureLines = %v, want a sorted GET <url> <status> line per request", lines)
	}
	var added, removed []string
	if same := twoPointer(lines, lines, &added, &removed); same != 2 || len(added) != 0 || len(removed) != 0 {
		t.Errorf("identical lists: same/added/removed = %d/%v/%v, want 2/[]/[]", same, added, removed)
	}
	added, removed = nil, nil
	if same := twoPointer(lines[:1], lines, &added, &removed); same != 1 || len(added) != 1 || len(removed) != 0 {
		t.Errorf("prefix compare: same/added/removed = %d/%v/%v, want 1/[http://a/2]/[]", same, added, removed)
	}
	if n, ok := captureIndex("capture-12.json"); !ok || n != 12 {
		t.Errorf("captureIndex(capture-12.json) = %d,%v want 12,true", n, ok)
	}
	if _, ok := captureIndex("capture-0.json"); ok {
		t.Error("captureIndex(capture-0.json) accepted a zero index")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "capture-1.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := nextCaptureName(dir, 1); filepath.Base(got) != "capture-2.json" {
		t.Errorf("nextCaptureName past an existing file = %s, want capture-2.json", got)
	}
}

func TestA13CompareFunctionsNeedsEnv(t *testing.T) {
	t.Setenv("LRECON_FROM", "")
	t.Setenv("LRECON_TO", "")
	if _, err := runOp("compare_functions", metaManagedPE(t)); err == nil ||
		!strings.Contains(err.Error(), "set LRECON_FROM") {
		t.Fatalf("err = %v, want the set-LRECON_FROM refusal before any Ghidra start", err)
	}
}

func TestA13CompareWebRefusals(t *testing.T) {
	// No capture dir given: refused before a connection is even attempted.
	if _, err := runOp("compare_web_captures", "127.0.0.1:9222"); err == nil ||
		!strings.Contains(err.Error(), "no capture directory") {
		t.Fatalf("err = %v, want the no-capture-directory refusal", err)
	}
	// A filesystem path is not a DevTools endpoint.
	if _, err := runOp("compare_web_screenshots", "/nonexistent-a13"); err == nil ||
		!strings.Contains(err.Error(), "not a DevTools endpoint") {
		t.Fatalf("err = %v, want the DevTools endpoint refusal", err)
	}
}

// BenchmarkA13DiffScreenshots measures the pixel walk on a screenshot-sized pair.
func BenchmarkA13DiffScreenshots(b *testing.B) {
	w, h := 760, 383
	mk := func(flip bool) *image.RGBA {
		img := image.NewRGBA(image.Rect(0, 0, w, h))
		for y := range h {
			for x := range w {
				c := color.RGBA{uint8(x), uint8(y), 0x40, 0xff}
				if flip && x > w/2 {
					c = color.RGBA{uint8(x), uint8(y), 0xd0, 0xff}
				}
				img.SetRGBA(x, y, c)
			}
		}
		return img
	}
	a, c := mk(false), mk(true)
	b.ResetTimer()
	for b.Loop() {
		if _, err := diffScreenshots(a, c); err != nil {
			b.Fatal(err)
		}
	}
}
