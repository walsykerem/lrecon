package main

// Round 2, lane 05 independent simulation tests. Verifies only the real
// behavior of the 26 files in this batch with meaningful input; does not rely on recognition/compilation.

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------- ocaml.go

func TestR2L05OcamlPure(t *testing.T) {
	if !ocamlMatch(nil, ocamlMagicLen) || ocamlMatch(nil, ocamlMagicLen-1) {
		t.Fatal("ocamlMatch size gate")
	}
	cases := []struct {
		n, size int64
		want    bool
	}{
		{-1, 100, false}, {0, 100, true}, {ocamlMaxSect, 100000, true},
		{ocamlMaxSect + 1, 100000, false}, {2, ocamlTrailerLen + 15, false},
		{2, ocamlTrailerLen + 16, true},
	}
	for _, c := range cases {
		if got := ocamlTOCFits(c.n, c.size); got != c.want {
			t.Errorf("ocamlTOCFits(%d,%d)=%v want %v", c.n, c.size, got, c.want)
		}
	}
	for _, c := range []struct {
		b    []byte
		want string
		ok   bool
	}{
		{[]byte("DATA\x00\x00\x00\x00"), "DATA", true},
		{[]byte("AB\x00\x00"), "AB", true},
		{[]byte("\x00\x00\x00\x00"), "", false},
		{[]byte("A\x01B\x00"), "", false},
	} {
		got, ok := ocamlName(c.b)
		if got != c.want || ok != c.ok {
			t.Errorf("ocamlName(%q)=(%q,%v) want (%q,%v)", c.b, got, ok, c.want, c.ok)
		}
	}
	if !ocamlDigits([]byte("019")) || ocamlDigits([]byte("01x")) || !ocamlDigits(nil) {
		t.Fatal("ocamlDigits")
	}
	for b, want := range map[byte]string{'O': "cmo", 'A': "cma", 'D': "cmxs", 'y': "cmx", 'z': "cmxa"} {
		if ocamlKinds[b] != want {
			t.Errorf("ocamlKinds[%q]=%q want %q", b, ocamlKinds[b], want)
		}
	}
}

func TestR2L05OcamlInspect(t *testing.T) {
	// .cmo: magic at offset 0, reader names the container and stops at magic.
	cmo := append([]byte("Caml1999O001"), []byte("payload")...)
	p := writeTemp(t, "unit.cmo", cmo)
	d := Digest{Kind: "unknown"}
	inspectOcaml(p, &d)
	if d.Kind != "ocaml" || d.Format != "cmo" || d.Toolchain != "ocaml 001" {
		t.Fatalf("cmo: kind=%q format=%q toolchain=%q", d.Kind, d.Format, d.Toolchain)
	}
	if d.Coverage == nil || d.Coverage.Parsed == 0 {
		t.Fatal("cmo: no parsed unit")
	}

	// .cmxs: trailer at EOF-12, u32 BE section count before it, one TOC entry.
	img := make([]byte, 36)
	copy(img[12:], "DATA\x00\x00\x00\x00")
	binary.BigEndian.PutUint32(img[20:], 5) // section length
	binary.BigEndian.PutUint32(img[24:], 1) // section count (at size-16=20? see below)
	copy(img[24:], "Caml1999D002")
	// The count must sit at size-16 = 20, but the TOC occupies 12..20. Rebuild
	// with a count slot at 20 and the trailer at 24 as intended above.
	binary.BigEndian.PutUint32(img[20:], 1)
	// Recompute: count at 20, TOC at 12..20 collides; use two sections layout.
	img = make([]byte, 44)
	copy(img[12:], "DATA\x00\x00\x00\x00")
	binary.BigEndian.PutUint32(img[16:], 5)
	copy(img[20:], "CODE\x00\x00\x00")
	binary.BigEndian.PutUint32(img[24:], 7)
	binary.BigEndian.PutUint32(img[28:], 2) // num sections at size-16 = 28
	copy(img[32:], "Caml1999D002")
	p2 := writeTemp(t, "plug.cmxs", img)
	var e Digest
	inspectOcaml(p2, &e)
	if e.Format != "cmxs" || e.Toolchain != "ocaml 002" {
		t.Fatalf("cmxs: format=%q toolchain=%q", e.Format, e.Toolchain)
	}
	joined := strings.Join(e.Capabilities, ",")
	if !strings.Contains(joined, "ocaml:sections=DATA,CODE") {
		t.Fatalf("cmxs sections: %v", e.Capabilities)
	}
	if !strings.Contains(strings.Join(e.Notes, " "), "declares 2 sections") {
		t.Fatalf("cmxs notes: %v", e.Notes)
	}
}

// ------------------------------------------- ghidra route ops (arg contract)

func TestR2L05GhidraArgContracts(t *testing.T) {
	target := writeTemp(t, "fake.bin", []byte("not a real binary, only arg parsing is under test"))

	t.Setenv("LRECON_AT", "")
	t.Setenv("LRECON_NAME", "")
	t.Setenv("LRECON_FROM", "")
	t.Setenv("LRECON_TO", "")
	t.Setenv("LRECON_ARGS", " , ")

	// An op that resolves its argument before the ghidra engine reports bad_arg.
	// One whose ghidraGate runs first honestly skips when the engine is absent.
	for _, c := range []struct {
		name, want string
	}{
		{"address_name", "LRECON_AT is not set"},
		{"address_to_file_offset", "is not set"},
		{"batch_decompile", "no address or symbol after splitting on commas"},
	} {
		_, err := runOp(c.name, target)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err=%v want substring %q", c.name, err, c.want)
			continue
		}
		if c.name == "batch_decompile" && classify(err.Error()) != kindBadArg {
			t.Errorf("batch_decompile kind=%v want bad_arg", classify(err.Error()))
		}
	}
	for _, name := range []string{"analyze_function", "build_call_path"} {
		res, err := runOp(name, target)
		if err != nil {
			t.Errorf("%s: unexpected error: %v", name, err)
			continue
		}
		sk, ok := res.(*skip)
		if !ok || sk.Reason == "" {
			t.Errorf("%s: res=%#v want a reasoned *skip", name, res)
		}
	}
	// Missing job file: an absent target makes ghidraGate defer, so the op's own
	// job validation is the answer.
	_, err := runOp("annotate_native_function", filepath.Join(t.TempDir(), "missing-job.json"))
	if err == nil || !strings.Contains(err.Error(), "job needs") {
		t.Errorf("annotate_native_function: err=%v want 'job needs'", err)
	}

	// Safe conversions the G ops feed into ghidraOp.
	if nativeHexAddr(0x1f4) != "0x1f4" {
		t.Fatal("nativeHexAddr")
	}
	if v, err := nativeParseNum("0x1f"); err != nil || v != 31 {
		t.Fatalf("nativeParseNum hex: %d %v", v, err)
	}
	if v, err := nativeParseNum("ff"); err != nil || v != 255 {
		t.Fatalf("nativeParseNum bare hex: %d %v", v, err)
	}
	if _, err := nativeParseNum("xyz"); err == nil {
		t.Fatal("nativeParseNum accepted junk")
	}
	t.Setenv("LRECON_ARGS", " a, ,b ")
	list, err := nativeList()
	if err != nil || len(list) != 2 || list[0] != "a" || list[1] != "b" {
		t.Fatalf("nativeList: %v %v", list, err)
	}
	t.Setenv("LRECON_NAME", "sym")
	if ref, err := nativeRef(); err != nil || ref != "sym" {
		t.Fatalf("nativeRef: %q %v", ref, err)
	}
	t.Setenv("LRECON_FROM", "f")
	t.Setenv("LRECON_TO", "t")
	if from, to, err := nativePair(); err != nil || from != "f" || to != "t" {
		t.Fatalf("nativePair: %q %q %v", from, to, err)
	}
}

// ----------------------------------------------------------- ADB + capture

func TestR2L05ADBLocateAndScreen(t *testing.T) {
	r1, r2 := t.TempDir(), t.TempDir()
	bad := filepath.Join(r1, "platform-tools")
	if err := os.MkdirAll(bad, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(bad, "adb"), 0o755); err != nil {
		t.Fatal(err)
	} // a directory named adb must be rejected
	good := filepath.Join(r2, "platform-tools")
	if err := os.MkdirAll(good, 0o755); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(good, "adb")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ANDROID_HOME", r1)
	t.Setenv("ANDROID_SDK_ROOT", r2)
	got, ok := findADBInSDK()
	if !ok || got != bin {
		t.Fatalf("findADBInSDK: %q %v want %q", got, ok, bin)
	}

	dir := t.TempDir()
	missing := filepath.Join(dir, "never.png")
	if err := pngOnlyOverwrite(missing); err != nil {
		t.Fatalf("nonexistent target: %v", err)
	}
	badPNG := filepath.Join(dir, "bad.png")
	os.WriteFile(badPNG, []byte("not a png at all"), 0o600)
	if err := pngOnlyOverwrite(badPNG); err == nil || !strings.Contains(err.Error(), "exists and is not a PNG") {
		t.Fatalf("bad png: %v", err)
	}
	goodPNG := filepath.Join(dir, "good.png")
	os.WriteFile(goodPNG, []byte("\x89PNG\r\n\x1a\nrest"), 0o600)
	if err := pngOnlyOverwrite(goodPNG); err != nil {
		t.Fatalf("good png: %v", err)
	}
}

func TestR2L05ReadUISteps(t *testing.T) {
	if steps, err := readUISteps(""); err != nil || steps != nil {
		t.Fatalf("empty: %v %v", steps, err)
	}
	p := writeTemp(t, "steps.txt", []byte("# comment\n  tap 1 2  \n\nswipe 1 2 3 4\n"))
	steps, err := readUISteps(p)
	if err != nil || len(steps) != 2 || steps[0] != "tap 1 2" || steps[1] != "swipe 1 2 3 4" {
		t.Fatalf("steps: %q %v", steps, err)
	}
	p2 := writeTemp(t, "nul.txt", []byte("tap 1\x002"))
	if _, err := readUISteps(p2); err == nil || !strings.Contains(err.Error(), "NUL byte at offset 5") {
		t.Fatalf("NUL: %v", err)
	}
	p3 := writeTemp(t, "utf8.txt", []byte{0xff, 0xfe, '\n'})
	if _, err := readUISteps(p3); err == nil || !strings.Contains(err.Error(), "invalid UTF-8") {
		t.Fatalf("UTF8: %v", err)
	}
}

// ------------------------------------------------ javascript + web bundle

func TestR2L05JSBehavior(t *testing.T) {
	for _, c := range []struct {
		params string
		want   int
	}{
		{"", 0}, {"   ", 0}, {"a", 1}, {"a, b", 2}, {"{a,b}, c", 2}, {"(...rest)", 1},
	} {
		if got := paramArity(c.params); got != c.want {
			t.Errorf("paramArity(%q)=%d want %d", c.params, got, c.want)
		}
	}
	for _, c := range []struct {
		h    []byte
		want bool
	}{
		{[]byte("MZ\x00\x00"), true},
		{[]byte("\x7fELF"), true},
		{[]byte{0xfe, 0xed, 0xfa, 0xce}, true},
		{[]byte{0xca, 0xfe, 0xba, 0xbe}, true},
		{[]byte("func"), false}, {[]byte("M"), false},
	} {
		if got := nativeMagic(c.h); got != c.want {
			t.Errorf("nativeMagic(%v)=%v want %v", c.h, got, c.want)
		}
	}

	src := `var s = "exports.hidden = (x) => 1;";
exports.real = (a, b) => {};`
	masked := bytes.Repeat([]byte{'x'}, len(src))
	// Blank the quoted string region so the hidden match is masked out.
	start := strings.Index(src, `"exports.hidden`)
	end := strings.Index(src, `";`) + 2
	for i := start; i < end && i < len(masked); i++ {
		masked[i] = ' '
	}
	exports := jsExports(src, masked)
	if len(exports) != 1 || exports[0].Name != "real" || exports[0].Arity != 2 || exports[0].Line != 2 {
		t.Fatalf("jsExports: %+v", exports)
	}

	lines := newLineIndex(src)
	if lines.at(0) != 1 || lines.at(strings.Index(src, "exports.real")) != 2 {
		t.Fatalf("lineIndex: %v", lines)
	}
	if got := uniqSorted([]string{"b", "a", "b"}); len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("uniqSorted: %v", got)
	}
	edges := []jsEdge{{Kind: "import", Spec: "x", Line: 1}, {Kind: "import", Spec: "x", Line: 1}}
	if got := dedupeEdges(edges); len(got) != 1 {
		t.Fatalf("dedupeEdges: %+v", got)
	}
}

// -------------------------------------------------------- asar budget ops

func TestR2L05AsarBudget(t *testing.T) {
	t.Setenv(opDeadlineEnv, "bogus")
	if opDeadline() != opDeadlineDefault {
		t.Fatal("opDeadline bogus env")
	}
	t.Setenv(opDeadlineEnv, "2s")
	if opDeadline() != 2*time.Second {
		t.Fatal("opDeadline valid env")
	}

	// Synthetic asar head: [4][pickle][payload][jsonLen]['{'...].
	head := make([]byte, 20)
	binary.LittleEndian.PutUint32(head, 4)
	binary.LittleEndian.PutUint32(head[12:], 5)
	copy(head[16:], `{"x":1}`)
	if !isAsar(head) {
		t.Fatal("isAsar head")
	}
	asarPath := writeTemp(t, "app.asar", append(head, bytes.Repeat([]byte{'x'}, 16)...))
	if stage := targetStage(asarPath); stage != "asar" {
		t.Fatalf("targetStage asar = %q", stage)
	}
	textPath := writeTemp(t, "app.js", []byte("exports.x = 1;"))
	if stage := targetStage(textPath); stage != "input" {
		t.Fatalf("targetStage input = %q", stage)
	}

	// Budget already spent: refusal, no body run, timeout kind, stage recorded.
	t.Setenv(opDeadlineEnv, "0")
	ran := false
	_, err := runOpDeadlineCtx(asarPath, func(context.Context) (any, error) {
		ran = true
		return nil, nil
	})
	if ran || !isOpTimeout(err) || err == nil || err.Error() != "timeout" {
		t.Fatalf("spent budget: ran=%v err=%v", ran, err)
	}
	if classify(err.Error()) != kindTimeout {
		t.Fatal("timeout class")
	}
	if stage := takeRefuseStage(); stage != "asar" {
		t.Fatalf("refuse stage = %q", stage)
	}

	// A live budget returns the body result unchanged.
	t.Setenv(opDeadlineEnv, "2s")
	res, err := runOpDeadline(asarPath, func() (any, error) { return "ok", nil })
	if err != nil || res != "ok" {
		t.Fatalf("live budget: %v %v", res, err)
	}

	// Oversized asar window is truncated at maxAsarWebText and says so.
	big := make([]byte, maxAsarWebText+32)
	copy(big, head)
	bigPath := writeTemp(t, "big.asar", big)
	s, trunc, err := readWebTargetText(bigPath)
	if err != nil || !trunc || len(s) != maxAsarWebText {
		t.Fatalf("readWebTargetText: len=%d trunc=%v err=%v", len(s), trunc, err)
	}
	s2, trunc2, err := readWebTargetText(textPath)
	if err != nil || trunc2 || !strings.Contains(s2, "exports.x") {
		t.Fatalf("plain text: %q %v %v", s2, trunc2, err)
	}
}

// ------------------------------------------------------- swift + overview

func TestR2L05SwiftDescriptor(t *testing.T) {
	// Synthetic VA space: descriptor reloc at 0x1000 points to a 12-byte header
	// at 0x1100 whose nameRel points at "MyClass" at 0x1108.
	mem := make([]byte, 0x1200)
	s := swiftSec{name: "types", addr: 0x1000, data: mem[0x1000:0x1008]}
	binary.LittleEndian.PutUint32(s.data, 0x100) // rel &^ mask(3) = 0x100 -> target 0x1100
	// 12-byte context header at 0x1100; nameRel at +8 points to the name at
	// target+8+0x10 = 0x1118.
	binary.LittleEndian.PutUint32(mem[0x1108:], 0x10)
	copy(mem[0x1118:], "MyClass\x00")
	va := func(a uint64, n int) []byte {
		if a >= uint64(len(mem)) {
			return nil
		}
		end := int(a) + n
		if end > len(mem) {
			end = len(mem)
		}
		return mem[a:end]
	}
	got, ok := swiftDescriptorName(va, s, 0, swiftMask["types"])
	if !ok || got != "MyClass" {
		t.Fatalf("swiftDescriptorName: %q %v", got, ok)
	}
	zero := swiftSec{name: "types", addr: 0x2000, data: make([]byte, 8)}
	if _, ok := swiftDescriptorName(va, zero, 0, swiftMask["types"]); ok {
		t.Fatal("zero reloc must be rejected")
	}
	short := swiftSec{name: "types", addr: 0x3000, data: make([]byte, 8)}
	binary.LittleEndian.PutUint32(short.data, 0x10)
	if _, ok := swiftDescriptorName(va, short, 0, swiftMask["types"]); ok {
		t.Fatal("one-character name must be rejected")
	}
	sec := swiftSec{name: "types", data: make([]byte, 12)}
	if n, size, ok := swiftSectionCount(sec); !ok || n != 3 || size != 4 {
		t.Fatalf("swiftSectionCount: %d %d %v", n, size, ok)
	}
	if !printableASCII([]byte("MyClass")) || printableASCII([]byte("A\x01B")) {
		t.Fatal("printableASCII")
	}
}

func TestR2L05BinaryOverview(t *testing.T) {
	p := writeTemp(t, "note.txt", []byte("just a plain text fixture\n"))
	res, err := runOp("binary_overview", p)
	if err != nil {
		t.Fatal(err)
	}
	m, err := metaTestRun(t, "binary_overview", p)
	if err != nil {
		t.Fatal(err)
	}
	summary, _ := m["summary"].(string)
	if !strings.Contains(summary, "hardening none reported") || !strings.Contains(summary, "slice(s)") {
		t.Fatalf("summary: %q", summary)
	}
	if m["kind"] == nil || m["format"] == nil || res == nil {
		t.Fatalf("overview keys: %v", m)
	}
}

// ---------------------------------------------------------- asset catalog

func TestR2L05AssetCatalog(t *testing.T) {
	p := assetCatalogFixture(t)
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	d, err := assetCatalog(p, b)
	if err != nil {
		t.Fatal(err)
	}
	if d.Container != "BOMStore" || d.BlocksUsed == 0 || d.IndexSlots == 0 {
		t.Fatalf("catalog: %+v", d)
	}
	var names []string
	for _, nb := range d.NamedBlocks {
		names = append(names, nb.Name)
	}
	joined := strings.Join(names, ",")
	for _, want := range []string{"CARHEADER", "RENDITIONS", "KEYFORMAT"} {
		if !strings.Contains(joined, want) {
			t.Errorf("named blocks %q missing %q", joined, want)
		}
	}
	if d.Renditions == 0 || d.MainVersion != "Test 1.0" {
		t.Fatalf("catalog detail: renditions=%d version=%q", d.Renditions, d.MainVersion)
	}
	if blockMagic([]byte("RATC!")) != "RATC" || blockMagic([]byte{0, 1, 2, 3}) != "other" || blockMagic([]byte("AB")) != "other" {
		t.Fatal("blockMagic")
	}
	if _, err := assetCatalog("short.car", []byte{1, 2, 3}); err == nil || !strings.Contains(err.Error(), "BOM header truncated") {
		t.Fatalf("short catalog: %v", err)
	}
}

// ------------------------------------------------------ session + ledger

func TestR2L05BinarySessionState(t *testing.T) {
	metaTestState(t)
	target := writeTemp(t, "prog.elf", []byte("\x7fELF\x02\x01\x01\x00"))
	m, err := metaTestRun(t, "binary_session", target)
	if err != nil {
		t.Fatal(err)
	}
	if m["state"] != "opened" || m["session_persisted"] != true {
		t.Fatalf("first open: %v", m)
	}
	abs, _ := filepath.Abs(target)
	if m["document"] != abs {
		t.Fatalf("document: %v want %s", m["document"], abs)
	}
	m2, err := metaTestRun(t, "binary_session", target)
	if err != nil {
		t.Fatal(err)
	}
	if m2["state"] != "reopened" {
		t.Fatalf("reopen: %v", m2)
	}

	leg := writeTemp(t, "legacy.json", []byte(`{"document":"/old/path"}`))
	if doc, ok := sessionLegacyDocument(leg); !ok || doc != "/old/path" {
		t.Fatalf("legacy doc: %q %v", doc, ok)
	}
	kinded := writeTemp(t, "kinded.json", []byte(`{"kind":"lrecon.session/1","document":"/old"}`))
	if _, ok := sessionLegacyDocument(kinded); ok {
		t.Fatal("kinded file must not be treated as legacy")
	}
}

func TestR2L05ObligationLedger(t *testing.T) {
	metaTestState(t)
	target := writeTemp(t, "art.bin", []byte("artifact one"))
	job := metaTestArg(t, map[string]any{
		"file": target,
		"unresolved": []map[string]any{
			{"symbol": "S1", "reason": ""},
		},
	})
	m, err := metaTestRun(t, "build_reconstruction_obligation_ledger", job)
	if err != nil {
		t.Fatal(err)
	}
	if m["count"] != float64(1) || m["replaced"] != false {
		t.Fatalf("first ledger: %v", m)
	}
	ledger, _ := m["ledger"].(map[string]any)
	by, _ := ledger["by_reason"].(map[string]any)
	if by["unstated"] != float64(1) {
		t.Fatalf("by_reason: %v", by)
	}
	m2, err := metaTestRun(t, "build_reconstruction_obligation_ledger", job)
	if err != nil || m2["replaced"] != true {
		t.Fatalf("second ledger: %v %v", m2, err)
	}
	other := writeTemp(t, "other.bin", []byte("artifact two, different sha"))
	job2 := metaTestArg(t, map[string]any{"file": other})
	_, err = runOp("build_reconstruction_obligation_ledger", job2)
	if err == nil || !strings.Contains(err.Error(), "state conflict") || classify(err.Error()) != kindStateConflict {
		t.Fatalf("conflict: %v", err)
	}
}

// -------------------------------------------------------- capture scenarios

func TestR2L05CaptureProcessAndTargets(t *testing.T) {
	caps, err := rtParseSample(`Path: /usr/bin/demo
Process: demo [123]

Call graph:
    1234 Thread_1
      900 work  (in demo) + 28,68  [0x1,0x2]
`)
	if err != nil {
		t.Fatal(err)
	}
	if caps.Path != "/usr/bin/demo" || len(caps.Threads) != 1 || caps.Threads[0].ID != "1" {
		t.Fatalf("caps: %+v", caps)
	}
	frames := caps.Threads[0].Frames
	if len(frames) != 1 || frames[0].Count != 900 || frames[0].Addr != "0x1" || frames[0].Sym != "work" {
		t.Fatalf("frames: %+v", frames)
	}
	if _, err := rtParseSample("Process: demo [123]\nno graph here\n"); err == nil ||
		!strings.Contains(err.Error(), "sample output has no Call graph") {
		t.Fatalf("no graph: %v", err)
	}

	ep, arg, err := webTarget("127.0.0.1:9222=http://app.local/x")
	if err != nil || !strings.Contains(ep, "9222") || arg != "http://app.local/x" {
		t.Fatalf("webTarget endpoint: %q %q %v", ep, arg, err)
	}
	// A loopback host:port with no '=arg' is accepted with an empty argument.
	ep2, arg2, err := webTarget("127.0.0.1:9333")
	if err != nil || arg2 != "" || !strings.Contains(ep2, "9333") {
		t.Fatalf("webTarget no-arg endpoint: %q %q %v", ep2, arg2, err)
	}
	if _, _, err := webTarget("https://example.com"); err == nil {
		t.Fatal("webTarget accepted a website")
	}
	// A bare word that does not exist on disk is read as a live process name and
	// refused as out of scope (not as a malformed endpoint).
	if _, _, err := webTarget("notaport"); err == nil || !strings.Contains(err.Error(), "live runtime targets") {
		t.Fatalf("webTarget junk: %v", err)
	}
	if _, err := runOp("capture_browser_scenario", "127.0.0.1:9222"); err == nil || !strings.Contains(err.Error(), "no page to load") {
		t.Fatalf("browser no-arg: %v", err)
	}
}

// ------------------------------------------------------------- JSON sanity

func TestR2L05JSONHelpers(t *testing.T) {
	b, err := json.Marshal(map[string]any{"k": "v"})
	if err != nil || !bytes.Contains(b, []byte(`"k":"v"`)) {
		t.Fatalf("json: %s %v", b, err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil || m["k"] != "v" {
		t.Fatalf("unmarshal: %v %v", m, err)
	}
	if exe, err := os.Executable(); err != nil {
		t.Fatal(err)
	} else if _, err := os.Stat(exe); err != nil {
		t.Fatalf("executable fixture: %v", err)
	}
}
