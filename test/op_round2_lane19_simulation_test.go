package main

// Round 2, lane 19 real behavior simulations. Single file; does not change
// production code. Reuses existing test helpers (le32, rlibWrite, rlibBlob,
// swiftFieldTestImage, hasSkip, ...).

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestR2L19ReadCap(t *testing.T) {
	p := filepath.Join(t.TempDir(), "cap.bin")
	if err := os.WriteFile(p, []byte("abcdefghij"), 0o644); err != nil {
		t.Fatal(err)
	}
	// readCapped does not truncate: if the file is larger than the limit it errors, if equal/smaller it returns it all.
	if _, err := readCapped(p, 3); err == nil || !strings.Contains(err.Error(), "larger than the 3-byte cap") {
		t.Fatalf("readCapped(3) error = %v", err)
	}
	b, err := readCapped(p, 10)
	if err != nil || string(b) != "abcdefghij" {
		t.Fatalf("readCapped(10) = %q, %v; want full file", b, err)
	}
	b, err = readCapped(p, 100)
	if err != nil || string(b) != "abcdefghij" {
		t.Fatalf("readCapped(100) = %q, %v", b, err)
	}
}

func TestR2L19Reasons(t *testing.T) {
	if got := fieldOf("rust-demangle-unverified"); got != "rust" {
		t.Fatalf("fieldOf = %q", got)
	}
	if got := fieldOf("pyc:not-code"); got != "pyc" {
		t.Fatalf("fieldOf colon = %q", got)
	}
	if got := fieldOf("nofield"); got != "nofield" {
		t.Fatalf("fieldOf plain = %q", got)
	}
	if !registeredReason("rlib-version-unverified") || registeredReason("zz-invented") {
		t.Fatal("registeredReason misclassified")
	}
	set := activeReasonsFor("rlib", []string{"rlib-version-unverified"})
	if !set["rlib-version-unverified"] {
		t.Fatalf("activeReasonsFor = %v", set)
	}
	func() {
		defer func() {
			if recover() == nil {
				t.Error("activeReasonsFor did not panic on unregistered reason")
			}
		}()
		activeReasonsFor("x", []string{"zz-invented"})
	}()

	clearActiveReasons()
	var d Digest
	fakeReason := "zz-invented" // non-literal: skip/claim registry lint scans literals
	d.skip(fakeReason, "crafted")
	if err := d.checkReasons(); err == nil || !strings.Contains(err.Error(), `reason "zz-invented" not in registry (field zz)`) {
		t.Fatalf("checkReasons = %v", err)
	}
}

func TestR2L19Rlib(t *testing.T) {
	if got, ok := rlibToolchain("rustc 1.92.0 (ded5c06cf 2025-12-08)"); !ok || got != "1.92.0" {
		t.Fatalf("rlibToolchain = %q, %v", got, ok)
	}
	if _, ok := rlibToolchain("gcc 12"); ok {
		t.Fatal("rlibToolchain accepted non-rustc")
	}
	if _, ok := rlibToolchain("rustc "); ok {
		t.Fatal("rlibToolchain accepted missing version")
	}
	if !rlibMatch([]byte("!<arch>\n"), 8) || rlibMatch([]byte("garbage"), 7) {
		t.Fatal("rlibMatch misclassified")
	}

	path := rlibWrite(t, "libfoo-"+rlibFooHash+".rlib", false, []rlibEntry{
		{name: "lib.rmeta", body: append(make([]byte, 64), rlibBlob(10, 16, "rustc 1.92.0")...)},
		{name: "libfoo.foo." + rlibFooHash + "-cgu.0.rcgu.o", body: rlibCgu("foo")},
	})
	got, err := Probe(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Kind != "rlib" || got.Toolchain != "rustc 1.92.0" || !rlibHasCap(got, "rlib:metadata=10") {
		t.Fatalf("Probe rlib = kind %q toolchain %q caps %v", got.Kind, got.Toolchain, got.Capabilities)
	}
}

func TestR2L19Roles(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"libcrypto.so.3", "crypto"},
		{"libsqlite3.dylib", "storage"},
		{"libnode_napi_x.node", "node-addon"},
		{"libfrida-agent.so", "instrumentation"},
		{"totally-unknown.so", ""},
	} {
		if got := RoleOf(c.in); got != c.want {
			t.Errorf("RoleOf(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	if !tufModule("github.com/theupdateframework/go-tuf/v5") || tufModule("future") || tufModule("tufa") {
		t.Fatal("tufModule segment matching wrong")
	}
	var d Digest
	AddUpdaterCapsFrom(&d, []string{"Squirrel", "Sparkle", "app/tuf/x", "future"})
	want := "updater:Sparkle,updater:Squirrel,updater:tuf"
	if got := strings.Join(d.Capabilities, ","); got != want {
		t.Fatalf("caps = %q, want %q", got, want)
	}
	a := Digest{Kind: "elf", Deps: []Dep{{Path: "libfoo"}}}
	b := Digest{Kind: "macho", Toolchain: "go1.22"}
	diff := strings.Join(DiffDigests(a, b), "|")
	for _, part := range []string{"kind elf -> macho", "-dep libfoo", "toolchain - -> go1.22"} {
		if !strings.Contains(diff, part) {
			t.Errorf("DiffDigests = %q, missing %q", diff, part)
		}
	}
}

func TestR2L19Rustsym(t *testing.T) {
	if got, ok := rustLegacyDemangle("_ZN14rustc_demangle12try_demangle17h648854d1156fd625E"); !ok || got != "rustc_demangle::try_demangle" {
		t.Fatalf("legacy = %q, %v", got, ok)
	}
	if _, ok := rustLegacyDemangle("_ZN3foo"); ok {
		t.Fatal("legacy accepted unterminated name")
	}
	if got, ok := rustV0Demangle("_RNvCsiGVaDesi5rv_7___rustc10rust_panic"); !ok || got != "__rustc::rust_panic" {
		t.Fatalf("v0 = %q, %v", got, ok)
	}
	if _, ok := rustV0Demangle("_R"); ok {
		t.Fatal("v0 accepted bare prefix")
	}
	if !rustSymGlue("core::ptr::drop_in_place<alloc::string::String>") || rustSymGlue("myapp::drop_the_ball") {
		t.Fatal("rustSymGlue wrong")
	}
	if !rustSymPanic("__rustc::rust_panic") || rustSymPanic("myapp::panic_handler") {
		t.Fatal("rustSymPanic wrong")
	}
	if !rustSymClosure("myapp::main::{{closure}}") {
		t.Fatal("rustSymClosure wrong")
	}
	if got := rustSymCrate("myapp::db::connect"); got != "myapp" {
		t.Fatalf("rustSymCrate = %q", got)
	}
	if got := rustSymCrate("std::io::stdio::print"); got != "" {
		t.Fatalf("rustSymCrate(std) = %q", got)
	}
	st := rustSymScan([]string{
		"_ZN5myapp3run17h0123456789abcdefE",
		"_RNvCsiGVaDesi5rv_7___rustc10rust_panic",
		"not-rust",
	})
	if st.total != 2 || st.legacy != 1 || st.v0 != 1 || len(st.crates) == 0 {
		t.Fatalf("rustSymScan = %+v", st)
	}
}

func TestR2L19Signals(t *testing.T) {
	if pid, ok := tempOwnerPid("lrecon-extract_artifact-p1234-5678"); !ok || pid != 1234 {
		t.Fatalf("tempOwnerPid = %d, %v", pid, ok)
	}
	if pid, ok := tempOwnerPid("lrecon-cli-123456789"); ok || pid != 0 {
		t.Fatalf("tempOwnerPid random = %d, %v", pid, ok)
	}
	dir, err := tempDir("lrecon-r2l19-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	if pid, ok := tempOwnerPid(filepath.Base(dir)); !ok || pid != os.Getpid() {
		t.Fatalf("tempDir owner = %d, %v, want %d", pid, ok, os.Getpid())
	}
}

func TestR2L19Sigpack(t *testing.T) {
	if !strongAtom([]byte("abcd")) || strongAtom([]byte("aabb")) || strongAtom([]byte("aaaa")) || strongAtom([]byte("abc")) {
		t.Fatal("strongAtom wrong")
	}
	win := []byte("XXabcdYYabcd")
	atZero := sigOffsets(win, sigPat{at: "0", lit: []byte("abcd")}, 10)
	if len(atZero) != 0 {
		t.Fatalf("sigOffsets(at=0) = %v, want empty", atZero)
	}
	any := sigOffsets(win, sigPat{at: "any", lit: []byte("abcd")}, 10)
	if len(any) != 2 || any[0] != 2 || any[1] != 8 {
		t.Fatalf("sigOffsets(any) = %v, want [2 8]", any)
	}
	sigOnce.Do(loadSigpack) // idempotent: sigpack_test.go shares this global
	if sigErr != nil || len(sigPats) == 0 || len(sigDrops) != 0 {
		t.Fatalf("loadSigpack: err=%v pats=%d drops=%v", sigErr, len(sigPats), sigDrops)
	}

	d := &Digest{FileSize: 200}
	d.witness(Witness{Axis: "sig", Class: "sig:r2l19", Value: "rust", Start: 10, End: 20})
	d.settleLanguage()
	if len(d.Claims) != 0 || len(d.Unknown) != 1 || d.Unknown[0].Slot != "language" {
		t.Fatalf("marker alone: claims=%+v unknown=%+v", d.Claims, d.Unknown)
	}
	d.witness(Witness{Axis: "mangling", Class: "mangling:r2l19", Value: "rust-legacy", Start: 100, End: 110})
	d.settleLanguage()
	found := false
	for _, c := range d.Claims {
		if c.Slot == "language" && c.Value == "rust" {
			found = true
		}
	}
	if !found {
		t.Fatalf("two mechanisms did not produce rust claim: %+v", d.Claims)
	}
}

func TestR2L19Skeleton(t *testing.T) {
	kept, sum := clampUnion([]interval{{10, 30}, {20, 40}, {50, 60}}, []interval{{0, 100}})
	if len(kept) != 2 || kept[0] != (interval{10, 40}) || kept[1] != (interval{50, 60}) || sum != 40 {
		t.Fatalf("clampUnion = %v, %d", kept, sum)
	}
	touch, _ := clampUnion([]interval{{10, 20}, {20, 30}}, []interval{{0, 100}})
	if len(touch) != 2 {
		t.Fatalf("touching intervals merged: %v", touch)
	}
	s := (&Skeleton{}).finish([]interval{{10, 30}, {20, 40}}, []interval{{0, 100}}, nil)
	if s.Intervals != 1 || s.TextBytes != 100 || s.Attributed != 30 || s.Status != skelOK || s.Ratio == nil || *s.Ratio != 0.3 {
		t.Fatalf("finish = %+v", s)
	}
	if line := s.line(); !strings.Contains(line, "skeleton:") || !strings.Contains(line, "1 intervals") {
		t.Fatalf("line = %q", line)
	}
	if got := resolveSkeleton("x", &Digest{Kind: "txt"}); got != nil {
		t.Fatalf("resolveSkeleton unsupported = %+v", got)
	}
}

func TestR2L19Skipped(t *testing.T) {
	clearActiveReasons()
	var d Digest
	d.skip("rlib-version-unverified", "x")
	if len(d.reasonErrs) != 0 || len(d.Skipped) != 1 || d.Coverage == nil || d.Coverage.Skipped != 1 {
		t.Fatalf("declared skip: errs=%v skipped=%+v cov=%+v", d.reasonErrs, d.Skipped, d.Coverage)
	}
	setActiveReasons(map[string]bool{})
	var d2 Digest
	d2.skip("rlib-version-unverified", "x")
	if len(d2.reasonErrs) != 1 || !strings.Contains(d2.reasonErrs[0], `not declared by reader (field rlib)`) {
		t.Fatalf("undeclared skip errs = %v", d2.reasonErrs)
	}
	clearActiveReasons()

	if !(Digest{FileSize: 10, BytesScanned: 10}).complete() {
		t.Fatal("complete full read false")
	}
	if (Digest{FileSize: 10, BytesScanned: 9}).complete() || (Digest{FileSize: 10, BytesScanned: 10, Truncated: true}).complete() {
		t.Fatal("complete cut read true")
	}
	cut := Digest{FileSize: 10, BytesScanned: 5, Constants: consts{constNotDetected}, JIT: jitNotDetected, Names: nameNotRecovered}
	cut.gateAbsence()
	if cut.Constants[0] != constNotScanned || cut.JIT != constNotScanned || cut.Names != constNotScanned {
		t.Fatalf("gateAbsence = %v / %q / %q", cut.Constants, cut.JIT, cut.Names)
	}
	cov := Digest{Coverage: &Coverage{Parsed: 1, Skipped: 1}}
	if got := cov.coverageClaim(); got != "parsed:1 skipped:1 unknown:0 N=2" {
		t.Fatalf("coverageClaim = %q", got)
	}
	if got := (Digest{}).coverageClaim(); got != "of N unknown" {
		t.Fatalf("coverageClaim(nil) = %q", got)
	}
	var d3 Digest
	fakeField := "foo" // non-literal: skip/claim registry lint scans literals
	d3.claim(fakeField, "bar", 10)
	d3.claim(fakeField, "bar", 20)
	if len(d3.Claims) != 1 || d3.Claims[0].ByteOffset != 10 {
		t.Fatalf("claim dedup = %+v", d3.Claims)
	}
}

func TestR2L19Swift(t *testing.T) {
	if name, ok := swiftSectionName("__swift5_types"); !ok || name != "types" {
		t.Fatalf("swiftSectionName = %q, %v", name, ok)
	}
	if _, ok := swiftSectionName("not_a_section"); ok {
		t.Fatal("swiftSectionName accepted unknown")
	}
	targets, nulls, ok := swiftTargets(le32(0x51, 0x52, 0xFFFFFFF0), 0x1000, 3)
	if !ok || nulls != 0 || len(targets) != 3 || targets[0] != 0x1050 || targets[1] != 0x1054 || targets[2] != 0xFF8 {
		t.Fatalf("swiftTargets = %x, nulls=%d, ok=%v", targets, nulls, ok)
	}
	targets, nulls, ok = swiftTargets(le32(0, 0x51), 0x1000, 3)
	if !ok || nulls != 1 || len(targets) != 1 || targets[0] != 0x1054 {
		t.Fatalf("swiftTargets null = %x, nulls=%d, ok=%v", targets, nulls, ok)
	}
	if _, _, ok := swiftTargets([]byte{1, 2, 3}, 0, 3); ok {
		t.Fatal("swiftTargets accepted cut word")
	}
	if n, ok := swiftEntryCount(nil, 0); !ok || n != 0 {
		t.Fatalf("swiftEntryCount(0) = %d, %v", n, ok)
	}
	if n, ok := swiftEntryCount(le32(0, 0, 0), 4); !ok || n != 3 {
		t.Fatalf("swiftEntryCount = %d, %v", n, ok)
	}
	if _, ok := swiftEntryCount([]byte{1, 2, 3, 4, 5}, 2); ok {
		t.Fatal("swiftEntryCount accepted cut record")
	}
	if v, ok := swiftReflectionVersion([]byte{0x10, 0x00}); !ok || v != 16 {
		t.Fatalf("swiftReflectionVersion = %d, %v", v, ok)
	}
	segs := []swiftSeg{{addr: 0x1000, size: 0x100}}
	if !vaInSegments(segs, 0x1050) || vaInSegments(segs, 0x1100) {
		t.Fatal("vaInSegments wrong")
	}
}

func TestR2L19SwiftField(t *testing.T) {
	if got := swiftFieldTargets(0, 0x1000); got != nil {
		t.Fatalf("swiftFieldTargets(0) = %v", got)
	}
	got := swiftFieldTargets(0x4200, 0x100000000)
	if len(got) != 2 || got[0] != 0x4200 || got[1] != 0x100000000+0x4200 {
		t.Fatalf("swiftFieldTargets = %v", got)
	}

	img := swiftFieldImage{sections: []swiftSec{{name: "__DATA,__data", addr: 0x5000, data: le32(0, 8, 12)}}}
	offs, ok := swiftFieldOffsets(img, 0x5000, 0, 3)
	if !ok || len(offs) != 3 || offs[0] != 0 || offs[1] != 8 || offs[2] != 12 {
		t.Fatalf("swiftFieldOffsets = %v, %v", offs, ok)
	}
	bad := swiftFieldImage{sections: []swiftSec{{name: "__DATA,__data", addr: 0x5000, data: le32(8, 4)}}}
	if _, ok := swiftFieldOffsets(bad, 0x5000, 0, 2); ok {
		t.Fatal("swiftFieldOffsets accepted decreasing offsets")
	}
	if b := mustAt(img, 0x5000, 4); len(b) != 4 || b[0] != 0 {
		t.Fatalf("mustAt = %v", b)
	}
	// mustAt returns a zero byte outside the range (must, not nil).
	if b := mustAt(img, 0x9999, 4); len(b) != 4 || !allZero(b) {
		t.Fatalf("mustAt out of range = %v", b)
	}
	if !allZero([]byte{0, 0, 0}) || allZero([]byte{0, 1}) {
		t.Fatal("allZero wrong")
	}

	var d Digest
	swiftFieldReport([]swiftFieldImage{swiftFieldTestImage()}, &d)
	if len(d.Notes) != 1 || !strings.Contains(d.Notes[0], "mod.Pt (x, y, z)") || len(d.Skipped) != 0 {
		t.Fatalf("swiftFieldReport = notes %v skipped %+v", d.Notes, d.Skipped)
	}
	missing := swiftFieldTestImage()
	keep := missing.sections[:0]
	for _, s := range missing.sections {
		if s.name != "__swift5_fieldmd" {
			keep = append(keep, s)
		}
	}
	missing.sections = keep
	var d2 Digest
	swiftFieldReport([]swiftFieldImage{missing}, &d2)
	if !hasSkip(d2.Skipped, swiftFieldAbsent) {
		t.Fatalf("swiftFieldReport absent = %+v", d2.Skipped)
	}
}

func TestR2L19TestHelpersAndFixture(t *testing.T) {
	// Capture the fixture path before Chdir.
	fixture := mustAbs(t, "testdata/fixtures/tiny/main.go")
	body, err := os.ReadFile(fixture)
	if err != nil || (!strings.Contains(string(body), "package main") || !strings.Contains(string(body), "func main")) {
		t.Fatalf("tiny fixture is not a Go program: %q, %v", body, err)
	}
	if got := mustAbs(t, "foo/bar"); !filepath.IsAbs(got) || !strings.HasSuffix(got, filepath.Join("foo", "bar")) {
		t.Fatalf("mustAbs = %q", got)
	}
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("LRECON_TARGET", "")
	if p, conf, ok := inferTarget(); ok || p != "" {
		t.Fatalf("inferTarget empty = %q, %v, %v", p, conf, ok)
	}
	if err := os.WriteFile("only.bin", []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if p, conf, ok := inferTarget(); !ok || p != "./only.bin" || conf != 0.6 {
		t.Fatalf("inferTarget one = %q, %v, %v", p, conf, ok)
	}
	t.Setenv("LRECON_TARGET", "only.bin")
	if p, conf, ok := inferTarget(); !ok || p != "only.bin" || conf != 0.9 {
		t.Fatalf("inferTarget env = %q, %v, %v", p, conf, ok)
	}
}

// ops.json is the published contract; the rows for this lane's ops must keep
// their route/needs/class instead of drifting silently with the registry.
func TestR2L19OpTableRouteContract(t *testing.T) {
	tbl, err := loadOpTable("testdata/ops.json")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]opTableRow{
		"close_gdb_session":           {Name: "close_gdb_session", Route: "Y", Needs: true, Expect: opExpectation{NoArgs: "needs_arg", WithTarget: "skipped_tool", Fixture: "macho"}},
		"gdb_session_status":          {Name: "gdb_session_status", Route: "Y", Needs: true, Expect: opExpectation{NoArgs: "needs_arg", WithTarget: "skipped_tool", Fixture: "macho"}},
		"demangle_swift":              {Name: "demangle_swift", Route: "L", Needs: true},
		"inspect_android_package":     {Name: "inspect_android_package", Route: "L", Needs: true},
		"inspect_web_network_capture": {Name: "inspect_web_network_capture", Route: "L", Needs: true},
		"list_segments":               {Name: "list_segments", Route: "G", Needs: true},
		"observe_web_session":         {Name: "observe_web_session", Route: "Y", Needs: true},
		"read_bytes":                  {Name: "read_bytes", Route: "L", Needs: true},
		"search_procedures":           {Name: "search_procedures", Route: "G", Needs: true},
		"trace_native_values":         {Name: "trace_native_values", Route: "Y", Needs: false, Expect: opExpectation{NoArgs: "out_of_scope", WithTarget: "not_applicable"}},
	}
	seen := map[string]bool{}
	for _, row := range tbl.Ops {
		w, ok := want[row.Name]
		if !ok {
			continue
		}
		seen[row.Name] = true
		if row.Route != w.Route || row.Needs != w.Needs {
			t.Errorf("%s: route/needs = %q/%v, want %q/%v", row.Name, row.Route, row.Needs, w.Route, w.Needs)
		}
		if w.Expect.NoArgs != "" && row.Expect.NoArgs != w.Expect.NoArgs {
			t.Errorf("%s: no_args = %q, want %q", row.Name, row.Expect.NoArgs, w.Expect.NoArgs)
		}
		if w.Expect.WithTarget != "" && row.Expect.WithTarget != w.Expect.WithTarget {
			t.Errorf("%s: with_target = %q, want %q", row.Name, row.Expect.WithTarget, w.Expect.WithTarget)
		}
	}
	for name := range want {
		if !seen[name] {
			t.Errorf("ops.json missing row %q", name)
		}
	}
}

// The HAR cap is a real boundary: one entry over maxHAREntries must be
// reported, not dropped silently, and the retained count stops at the cap.
func TestR2L19HAREntryCapReported(t *testing.T) {
	entries := make([]map[string]any, maxHAREntries+1)
	for i := range entries {
		entries[i] = map[string]any{
			"time":     1,
			"request":  map[string]any{"method": "GET", "url": "https://a.example/x"},
			"response": map[string]any{"status": 200, "content": map[string]any{"size": 1}},
		}
	}
	body, err := json.Marshal(map[string]any{"log": map[string]any{
		"version": "1.2", "creator": map[string]any{"name": "cap-test", "version": "1"}, "entries": entries,
	}})
	if err != nil {
		t.Fatal(err)
	}
	p := writeTemp(t, "cap.har", body)
	v, err := opInspectWebNetworkCapture(p)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var s harSummary
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	if s.Entries != maxHAREntries+1 || len(s.Requests) != maxHAREntries || !s.Truncated {
		t.Fatalf("capped HAR: entries=%d requests=%d truncated=%v, want %d/%d/true", s.Entries, len(s.Requests), s.Truncated, maxHAREntries+1, maxHAREntries)
	}
}

// LLDB console dialect scraping: the two regexes must pick ids and stop
// reason out of a real transcript while ignoring unrelated console lines.
func TestR2L19LLDBTranscriptScrape(t *testing.T) {
	line := `* thread #1: tid = 0x1234, 0x0000000100001234 main` + "\n" +
		`  stop reason = breakpoint 1.1` + "\n" +
		`* thread #42: tid = 0x5678, stopped`
	if m := rtLLDBThread.FindAllStringSubmatch(line, -1); len(m) != 2 || m[0][1] != "1" || m[1][1] != "42" {
		t.Fatalf("thread scrape = %v", m)
	}
	m := rtLLDBStop.FindStringSubmatch(line)
	if len(m) != 2 || strings.TrimSpace(m[1]) != "breakpoint 1.1" {
		t.Fatalf("stop scrape = %v", m)
	}
	if rtLLDBThread.MatchString("no thread here") || rtLLDBStop.MatchString("continued") {
		t.Fatal("regex matched unrelated console text")
	}
}

// demangle_swift's two-target argument is parsed by opPair; a leading comma
// is a bad argument, not a silent single target.
func TestR2L19SwiftPairAndMangle(t *testing.T) {
	if got, err := symbolPaths("a"); err != nil || len(got) != 1 || got[0] != "a" {
		t.Fatalf("single path = %v, %v", got, err)
	}
	if got, err := symbolPaths("a,b"); err != nil || len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("pair = %v, %v", got, err)
	}
	if _, err := symbolPaths(",b"); err == nil || !strings.Contains(err.Error(), "two targets") {
		t.Fatalf("empty left = %v", err)
	}
	if name, rest := demangleSwift("_$s3foo3bar"); name != "foo.bar" || rest != "" {
		t.Fatalf("demangle = %q, %q", name, rest)
	}
}
