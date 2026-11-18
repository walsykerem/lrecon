package main

// TUR 2 / LANE 08 independent simulation tests. Each TestR2L08* verifies the
// REAL behavior of a file group with meaningful input; production code is not loosened.

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func r2l08Job(t *testing.T, job map[string]any) string {
	t.Helper()
	b, err := json.Marshal(job)
	if err != nil {
		t.Fatal(err)
	}
	return writeTemp(t, "r2l08-job.json", b)
}

func r2l08Map(t *testing.T, v any) map[string]any {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("not a JSON object: %v (%s)", err, b)
	}
	return m
}

func r2l08Refusal(t *testing.T, err error, want errorKind) *extRefusal {
	t.Helper()
	var ref *extRefusal
	if !errors.As(err, &ref) || ref.kind != want {
		t.Fatalf("want refusal %s, got %v", want, err)
	}
	return ref
}

// ---- g1: lldb ext (op_ext_lldb_memory.go, op_ext_lldb_misc.go) -------------

func TestR2L08LldbRegisterMemoryExpressionArgs(t *testing.T) {
	target := writeTemp(t, "target.bin", []byte("MZ\x00\x00"))
	rtFakeTool(t, "lldb", `printf 'ran:%s\n' "$*"`)

	cases := []struct {
		name string
		run  func(string, []string) (any, error)
		args []string
		want string
	}{
		{"reg_read", runLldbRegisterRead, []string{"rax"}, "register read rax"},
		{"reg_write", runLldbRegisterWrite, []string{"rax", "1"}, "register write rax 1"},
		{"reg_write_no_val", runLldbRegisterWrite, []string{"rax"}, "register read rax"},
		{"reg_write_none", runLldbRegisterWrite, nil, "register read"},
		{"mem_read_size", runLldbMemoryRead, []string{"4", "0x1000"}, "memory read -s 4 0x1000"},
		{"mem_read", runLldbMemoryRead, []string{"0x1000"}, "memory read 0x1000"},
		{"mem_write_two", runLldbMemoryWrite, []string{"0x1000", "7"}, "memory write 0x1000 7"},
		{"mem_write_eq", runLldbMemoryWrite, []string{"0x1000=7"}, "memory write 0x1000 7"},
		{"mem_write_bare", runLldbMemoryWrite, []string{"0x1000"}, "memory read 0x1000"},
		{"expr", runLldbExpression, []string{"x", "+", "1"}, "expression x + 1"},
		{"launch", runLldbProcessLaunch, nil, "process launch"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v, err := c.run(target, c.args)
			if err != nil {
				t.Fatal(err)
			}
			out, ok := v.(extOut)
			if !ok || out.Tool != "lldb" {
				t.Fatalf("%s = %T", c.name, v)
			}
			if len(out.Args) != 2 || out.Args[0] != c.want || out.Args[1] != target {
				t.Fatalf("%s args = %v, want [%q %q]", c.name, out.Args, c.want, target)
			}
			if !strings.Contains(out.Output, "ran:") {
				t.Fatalf("%s output lost: %q", c.name, out.Output)
			}
		})
	}
}

func TestR2L08LldbArgumentAndNoProcessRefusals(t *testing.T) {
	target := writeTemp(t, "target.bin", []byte("MZ\x00\x00"))
	rtFakeTool(t, "lldb", `printf 'ran:%s\n' "$*"`)
	r2l08Refusal(t, func() error { _, e := runLldbMemoryRead(target, nil); return e }(), kindNeedsArg)
	r2l08Refusal(t, func() error { _, e := runLldbMemoryWrite(target, nil); return e }(), kindNeedsArg)
	r2l08Refusal(t, func() error { _, e := runLldbExpression(target, nil); return e }(), kindNeedsArg)
	r2l08Refusal(t, func() error { _, e := runLldbProcessAttach(target, []string{"-1"}); return e }(), kindBadArg)
	r2l08Refusal(t, func() error { _, e := runLldbProcessAttach(target, []string{" "}); return e }(), kindNeedsArg)
	r2l08Refusal(t, func() error { _, e := runLldbProcessAttach(target, []string{"999999"}); return e }(), kindNoEngine)

	// no-process stderr + non-zero exit must become no_engine WITH the note,
	// never a bare "lldb failed" internal error.
	rtFakeTool(t, "lldb", `printf 'error: Command requires a current process.\n' >&2; exit 1`)
	_, err := runLldbRegisterRead(target, nil)
	ref := r2l08Refusal(t, err, kindNoEngine)
	if !strings.Contains(ref.msg, "Command requires a current process") || !strings.Contains(ref.msg, "note:") {
		t.Fatalf("no-process refusal lost its message: %q", ref.msg)
	}
}

func TestR2L08LldbLaunchFailureLine(t *testing.T) {
	got := lldbLaunchFailureLine("banner\nerror: process launch failed: 'X' is not a valid executable\n")
	if got != "process launch failed: 'X' is not a valid executable" {
		t.Fatalf("launchFailureLine = %q", got)
	}
	if lldbLaunchFailureLine("all fine\n") != "" {
		t.Fatal("clean transcript reported a launch failure")
	}
	if lldbLaunchFailureLine("error: 'nope' is not a valid executable\n") != "'nope' is not a valid executable" {
		t.Fatal("missed the valid-executable variant")
	}
}

// ---- g2: extract (op_extract_artifact.go, op_extract_firmware.go) ---------

func TestR2L08ExtractArtifactZip(t *testing.T) {
	z := writeZip(t, "app.zip", []zipEntry{{"a.txt", []byte("hello")}, {"d/b.txt", []byte("world")}})
	outDir := filepath.Join(t.TempDir(), "out")
	a15SetOutput(t, outDir)
	v, err := runOp("extract_artifact", z)
	if err != nil {
		t.Fatal(err)
	}
	m := r2l08Map(t, v)
	if m["kind"] != "zip" || m["output"] != outDir {
		t.Fatalf("extract result = %v", m)
	}
	if b, err := os.ReadFile(filepath.Join(outDir, "a.txt")); err != nil || string(b) != "hello" {
		t.Fatalf("extracted a.txt = %q, %v", b, err)
	}
	if b, err := os.ReadFile(filepath.Join(outDir, "d", "b.txt")); err != nil || string(b) != "world" {
		t.Fatalf("extracted d/b.txt = %q, %v", b, err)
	}
	// A non-archive is skipped, not silently reported as an empty extraction.
	v, err = runOp("extract_artifact", writeTemp(t, "plain.bin", []byte("not an archive at all")))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := v.(*skip); !ok {
		t.Fatalf("non-archive = %T, want *skip", v)
	}
}

func TestR2L08ExtractFirmwareCarvesContainers(t *testing.T) {
	img := make([]byte, 64)
	copy(img[8:], "hsqs")
	copy(img[32:], "UBI#")
	outDir := filepath.Join(t.TempDir(), "fw")
	a15SetOutput(t, filepath.Join(outDir, "ignored-by-dir-dest"))
	// exportDirDest uses -o as the tree root itself.
	a15SetOutput(t, outDir)
	v, err := runOp("extract_firmware", writeTemp(t, "flash.bin", img))
	if err != nil {
		t.Fatal(err)
	}
	m := r2l08Map(t, v)
	parts, ok := m["parts"].([]any)
	if !ok || len(parts) != 2 {
		t.Fatalf("parts = %v", m["parts"])
	}
	first := parts[0].(map[string]any)
	if first["name"] != "squashfs" || first["file"] != "00-squashfs.bin" || first["offset"] != float64(8) {
		t.Fatalf("first part = %v", first)
	}
	if b, err := os.ReadFile(filepath.Join(outDir, "00-squashfs.bin")); err != nil || string(b[:4]) != "hsqs" {
		t.Fatalf("carved squashfs = %q, %v", b, err)
	}
	if b, err := os.ReadFile(filepath.Join(outDir, "01-ubi.bin")); err != nil || string(b[:4]) != "UBI#" {
		t.Fatalf("carved ubi = %q, %v", b, err)
	}
	if m["capped"] != false {
		t.Fatalf("capped = %v", m["capped"])
	}
}

// ---- g3: find (op_find_changed_behavior.go, op_find_xrefs_to_name.go) -----

func TestR2L08MetaBehaviorKindMapping(t *testing.T) {
	cases := map[string]string{
		"kind.json":            "executable-format",
		"minos.json":           "os-floor",
		"deps.json":            "dependency",
		"capabilities.json":    "capability",
		"mobile_permissions.x": "permission",
		"plist_keys.json":      "declared-key",
		"electron.json":        "application-identity",
		"hardening.json":       "hardening",
		"symbols.json":         "code-surface",
		"constants.json":       "crypto-constant",
		"ipc.json":             "runtime-surface",
		"totally_unknown.json": "other",
	}
	for path, want := range cases {
		if got := metaBehaviorKind(path); got != want {
			t.Fatalf("metaBehaviorKind(%q) = %q, want %q", path, got, want)
		}
	}
}

func TestR2L08FindChangedBehaviorRequiresPairAndFiltersOther(t *testing.T) {
	_, err := runFindChangedBehavior(r2l08Job(t, map[string]any{"file": "x"}))
	if err == nil || !strings.Contains(err.Error(), "old") || !strings.Contains(err.Error(), "new") {
		t.Fatalf("missing pair = %v", err)
	}
	// Real pair of DIFFERENT-FORMAT artifacts: the digest "kind"/"format"
	// fields change and map to executable-format, so a behavior is emitted.
	old := writeTemp(t, "old.bin", []byte("MZ\x00\x00old pe bytes"))
	newB := writeTemp(t, "new.bin", []byte("\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00 elf bytes"))
	v, err := runFindChangedBehavior(r2l08Job(t, map[string]any{"old": old, "new": newB}))
	if err != nil {
		t.Fatal(err)
	}
	m := r2l08Map(t, v)
	if m["count"] == nil || m["by_kind"] == nil {
		t.Fatalf("result missing fields: %v", m)
	}
	behaviors, ok := m["behaviors"].([]any)
	if !ok || len(behaviors) == 0 {
		t.Fatalf("no behavior for a format change: %v", m)
	}
	for _, b := range behaviors {
		if b.(map[string]any)["kind"] == "other" {
			t.Fatal("unfiltered 'other' behavior leaked")
		}
	}
}

func TestR2L08FindXrefsNameEnvHint(t *testing.T) {
	os.Unsetenv("LRECON_NAME")
	_, err := runOp("find_xrefs_to_name", writeTemp(t, "x.bin", []byte("MZ")))
	if err == nil || !strings.Contains(err.Error(), "LRECON_NAME is not set") {
		t.Fatalf("missing name = %v", err)
	}
	if v, err := nativeEnvHint("LRECON_NAME", "a symbol name"); err == nil || v != "" {
		t.Fatalf("env hint = %q, %v", v, err)
	}
	t.Setenv("LRECON_NAME", "targetFunc")
	if v, err := nativeEnvHint("LRECON_NAME", "a symbol name"); err != nil || v != "targetFunc" {
		t.Fatalf("env hint set = %q, %v", v, err)
	}
}

// ---- g4: fixture + format coverage ----------------------------------------

func TestR2L08FormatCoverageInventoryAndSqliteVirtualTables(t *testing.T) {
	v, err := runOp("inspect_format_coverage", "")
	if err != nil {
		t.Fatal(err)
	}
	m := r2l08Map(t, v)
	if opStaticNum(t, m, "reader_count") != len(readers) {
		t.Fatalf("reader_count = %v, readers = %d", m["reader_count"], len(readers))
	}
	if got := sqliteVirtualTables([]sqliteTable{
		{Name: "a", SQL: "create virtual table a using fts5(x)"},
		{Name: "b", SQL: "CREATE TABLE b(x)"},
		{Name: "c", SQL: "  CREATE VIRTUAL TABLE c USING rtree(i)"},
	}); got != 2 {
		t.Fatalf("sqliteVirtualTables = %d, want 2", got)
	}
}

func TestR2L08FixturePcapRegeneratesByteForByte(t *testing.T) {
	if _, err := os.Stat("testdata/fixtures/pcap/make.py"); err != nil {
		t.Skipf("fixture generator absent: %v", err)
	}
	committed, err := os.ReadFile("testdata/fixtures/pcap/fixture.pcap")
	if err != nil {
		t.Fatal(err)
	}
	if len(committed) != 513 {
		t.Fatalf("fixture.pcap is %d bytes, want 513", len(committed))
	}
	dir := t.TempDir()
	cmd := exec.Command("python3", mustAbs(t, "testdata/fixtures/pcap/make.py"))
	cmd.Dir = dir
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("make.py: %v (%s)", err, b)
	}
	got, err := os.ReadFile(filepath.Join(dir, "fixture.pcap"))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(committed) {
		t.Fatalf("regenerated %d bytes, want %d", len(got), len(committed))
	}
	for i := range got {
		if got[i] != committed[i] {
			t.Fatalf("fixture differs at byte %d", i)
		}
	}
}

// ---- g5: frida + gdb -------------------------------------------------------

func TestR2L08OpRegistrationsFridaGdb(t *testing.T) {
	for _, c := range []struct {
		name  string
		route string
		needs bool
	}{
		{"frida_session_status", "Y", false},
		{"gdb_console", "Y", true},
		{"gdb_session_status", "Y", true},
		{"close_gdb_session", "Y", true},
	} {
		o, ok := ops[c.name]
		if !ok || o.route != c.route || o.needs != c.needs || o.desc == "" {
			t.Fatalf("op %s = %+v (ok=%v)", c.name, o, ok)
		}
	}
	if !strings.Contains(ops["frida_session_status"].desc, "refuse") {
		t.Fatal("frida_session_status no longer describes a refusal")
	}
}

func TestR2L08GdbLldbConsoleAndStatusAndClose(t *testing.T) {
	bin := writeTemp(t, "target.bin", []byte("MZ"))
	// Real transcript with thread ids and a stop reason: the lldb engine must
	// scrape both, not answer "no-inferior".
	rtFakeTool(t, "lldb", `printf '%s\n' '(lldb) thread list' 'thread #3: tid = 0x3, stop reason = breakpoint 1.1'`)
	v, err := gdbSessionStatusLLDB(bin)
	if err != nil {
		t.Fatal(err)
	}
	st, ok := v.(rtGdbStatus)
	if !ok || st.Engine != "lldb" || len(st.Threads) != 1 || st.Threads[0].ID != "3" || st.Stopped != "breakpoint 1.1" {
		t.Fatalf("session status = %+v", v)
	}

	rtFakeTool(t, "lldb", `printf '%s\n' 'Target 1: target.bin' 'image list: 2 images'`)
	v, err = gdbConsoleLLDB(bin)
	if err != nil {
		t.Fatal(err)
	}
	console, ok := v.(rtGdbConsole)
	if !ok || console.Engine != "lldb" || len(console.Output) == 0 {
		t.Fatalf("console = %+v", v)
	}

	v, err = closeGdbSessionLLDB(bin)
	if err != nil {
		t.Fatal(err)
	}
	closed, ok := v.(rtGdbClosed)
	if !ok || closed.Exited || !strings.Contains(closed.Note, "nothing left to close") {
		t.Fatalf("close = %+v", v)
	}

	// No-process answer: empty list + an honest reason.
	rtFakeTool(t, "lldb", `printf 'error: Command requires a current process.\n' >&2; exit 1`)
	v, err = gdbSessionStatusLLDB(bin)
	if err != nil {
		t.Fatal(err)
	}
	st = v.(rtGdbStatus)
	if st.Stopped != "no-inferior" || !strings.Contains(st.Note, "no inferior exists") {
		t.Fatalf("no-process status = %+v", st)
	}
}

// ---- g6: get ops -----------------------------------------------------------

func TestR2L08EvidenceBundleRoundtripAndNoSiblingFallback(t *testing.T) {
	artifact := buildCLIPE(t, true)
	w, raw, err := metaBuildEvidence(artifact)
	if err != nil {
		t.Fatal(err)
	}
	bundle := writeTemp(t, "good.evidence.json", raw)
	m := r2l08Map(t, r2l08MustOp(t, "get_evidence_bundle", r2l08Job(t, map[string]any{"file": bundle})))
	if m["verified"] != true || !strings.HasPrefix(m["attestation"].(string), "sha256:") || m["bundle_sha256"] != metaSHA256(raw) {
		t.Fatalf("get bundle = %v", m)
	}

	// A corrupt named bundle must NOT be replaced by a valid sibling.
	sibling := bundle + ".evidence.json"
	if err := os.WriteFile(sibling, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	bad := w
	bad.Bundle.SHA256 = "deadbeef"
	badBytes, err := json.Marshal(bad)
	if err != nil {
		t.Fatal(err)
	}
	corrupt := writeTemp(t, "bad.evidence.json", append(badBytes, '\n'))
	if _, err := runOp("get_evidence_bundle", r2l08Job(t, map[string]any{"file": corrupt})); err == nil || !strings.Contains(err.Error(), "attestation mismatch") {
		t.Fatalf("corrupt bundle fell back to sibling? err=%v", err)
	}

	// Cap env is honored.
	t.Setenv("LRECON_BUNDLE_CAP_BYTES", "777")
	if evidenceBundleCap() != 777 {
		t.Fatalf("evidenceBundleCap = %d", evidenceBundleCap())
	}
}

func TestR2L08ObjcReadPtrAndNavigationHelpers(t *testing.T) {
	// Plain pointer: its target maps to a byte → returned as-is.
	plain := func(addr uint64, n int) []byte {
		if addr == 0x2000 && n == 1 {
			return []byte{0x41}
		}
		if addr == 0x1000 && n == 4 {
			return []byte{0x00, 0x20, 0x00, 0x00}
		}
		return nil
	}
	if v, ok := objcReadPtr(plain, 4, 0x1000, 0); !ok || v != 0x2000 {
		t.Fatalf("plain objcReadPtr = %#x, %v", v, ok)
	}
	// Chained fixup: raw does not map, base+off does.
	const base = uint64(0x100000000)
	chained := func(addr uint64, n int) []byte {
		if addr == 0x1000 && n == 4 {
			return []byte{0x00, 0x10, 0x00, 0x00}
		}
		if addr == base+0x1000 && n == 1 {
			return []byte{0x42}
		}
		return nil
	}
	if v, ok := objcReadPtr(chained, 4, 0x1000, base); !ok || v != base+0x1000 {
		t.Fatalf("chained objcReadPtr = %#x, %v, want %#x", v, ok, base+0x1000)
	}
	if v, ok := objcReadPtr(func(uint64, int) []byte { return nil }, 4, 0, 0); ok || v != 0 {
		t.Fatalf("unreadable objcReadPtr = %#x, %v", v, ok)
	}

	if nativeHexAddr(0xabc) != "0xabc" {
		t.Fatalf("nativeHexAddr = %q", nativeHexAddr(0xabc))
	}
	fns := []nativeFunc{{Name: "a", Start: 0x100, End: 0x200}, {Name: "b", Start: 0x300, End: 0x400}}
	if f := containingFunction(fns, 0x150); f == nil || f.Name != "a" {
		t.Fatalf("containingFunction(0x150) = %v", f)
	}
	if f := containingFunction(fns, 0x250); f != nil {
		t.Fatalf("containingFunction in a gap = %v", f)
	}
}

func TestR2L08GetNavigationContextWithoutSession(t *testing.T) {
	t.Setenv("LRECON_SESSION", filepath.Join(t.TempDir(), "none.json"))
	if o := ops["get_navigation_context"]; o.route != "L" || o.needs != false {
		t.Fatalf("get_navigation_context = %+v", o)
	}
	if _, err := runOp("get_navigation_context", ""); err == nil || !strings.Contains(err.Error(), "no session") {
		t.Fatalf("navigation without session = %v", err)
	}
}

func r2l08MustOp(t *testing.T, name, path string) any {
	t.Helper()
	v, err := runOp(name, path)
	if err != nil {
		t.Fatalf("%s(%s): %v", name, path, err)
	}
	return v
}

// ---- g7: ghidra gate -------------------------------------------------------

func TestR2L08GhidraGateOrderAndTarget(t *testing.T) {
	// Missing path: IO answer wins, the finder must never be consulted.
	old := ghidraFinder
	t.Cleanup(func() { ghidraFinder = old })
	ghidraFinder = func() (string, string, error) {
		t.Fatal("finder consulted for absent path")
		return "", "", errors.New("x")
	}
	if s := ghidraGate(filepath.Join(t.TempDir(), "absent.bin")); s != nil {
		t.Fatalf("absent path gate = %+v", s)
	}

	// Text kind: kind refusal wins before the finder.
	txt := writeTemp(t, "notes.txt", []byte("just prose, no job keys"))
	if s := ghidraGate(txt); s == nil || !strings.Contains(s.Reason, "text") {
		t.Fatalf("text gate = %+v", s)
	}

	// A JSON job's "file" is the target of the kind check, not the job itself.
	native := a15Artifact(t)
	job := r2l08Job(t, map[string]any{"file": native})
	if got := ghidraGateTarget(job); got != native {
		t.Fatalf("ghidraGateTarget = %q, want %q", got, native)
	}

	// No engine, native target: the gate answers about the missing tool.
	ghidraFinder = func() (string, string, error) { return "", "", errors.New("analyzeHeadless not found") }
	if s := ghidraGate(native); s == nil || !strings.Contains(s.Reason, "analyzeHeadless not found") {
		t.Fatalf("no-engine gate = %+v", s)
	}
}

// ---- g8: goto + flutter ----------------------------------------------------

func TestR2L08GotoAddressValidationAndFlutterDetection(t *testing.T) {
	os.Unsetenv("LRECON_AT")
	if _, err := nativeAddrArg(); err == nil || !strings.Contains(err.Error(), "LRECON_AT is not set") {
		t.Fatalf("missing address = %v", err)
	}
	t.Setenv("LRECON_AT", "0x1000")
	if v, err := nativeAddrArg(); err != nil || v != 0x1000 {
		t.Fatalf("nativeAddrArg = %#x, %v", v, err)
	}
	if o := ops["goto_address"]; o.route != "L" || !o.needs {
		t.Fatalf("goto_address = %+v", o)
	}

	// A real Dart snapshot header: magic + kind=2 (full-aot) + 32-hex hash.
	h := make([]byte, 52)
	copy(h[:4], []byte{0xf5, 0xf5, 0xdc, 0xdc})
	binary.LittleEndian.PutUint64(h[12:20], 2)
	copy(h[20:], []byte("0123456789abcdef0123456789abcdef"))
	v, err := runOp("identify_flutter_build", writeTemp(t, "app.flutter", h))
	if err != nil {
		t.Fatal(err)
	}
	m := r2l08Map(t, v)
	if m["kind"] != "flutter" || m["dart_snapshot_kind"] != "full-aot" || m["flutter_hash"] != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("flutter identity = %v", m)
	}
	// No marker: honest skip instead of a fabricated identity.
	v, err = runOp("identify_flutter_build", writeTemp(t, "plain.bin", []byte("nothing here")))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := v.(*skip); !ok {
		t.Fatalf("non-flutter = %T, want *skip", v)
	}
}

// ---- g9: import ------------------------------------------------------------

func TestR2L08ImportEvidenceBundleArtifactCheckAndDrift(t *testing.T) {
	artifact := buildCLIPE(t, true)
	_, raw, err := metaBuildEvidence(artifact)
	if err != nil {
		t.Fatal(err)
	}
	bundle := writeTemp(t, "artifact.evidence.json", raw)
	m := r2l08Map(t, r2l08MustOp(t, "import_evidence_bundle", r2l08Job(t, map[string]any{"file": bundle})))
	if m["verified"] != true || m["artifact_checked"] != true || m["artifact_match"] != true || m["size_match"] != true {
		t.Fatalf("clean import = %v", m)
	}

	// Drift the artifact bytes: attestation still verifies, artifact must not.
	f, err := os.OpenFile(artifact, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("X")); err != nil {
		t.Fatal(err)
	}
	f.Close()
	m = r2l08Map(t, r2l08MustOp(t, "import_evidence_bundle", r2l08Job(t, map[string]any{"file": bundle})))
	if m["verified"] != false || m["artifact_match"] != false || m["drift"] == nil {
		t.Fatalf("drifted import = %v", m)
	}
}

func TestR2L08ImportManagedReconstructionConflict(t *testing.T) {
	pe := metaManagedPE(t)
	state := t.TempDir()
	m := r2l08Map(t, r2l08MustOp(t, "import_managed_reconstruction", r2l08Job(t, map[string]any{"file": pe, "state": state})))
	if m["out"] != state || m["methods"] == nil || m["artifact"] != pe {
		t.Fatalf("managed import = %v", m)
	}
	if b, err := os.ReadFile(filepath.Join(state, "types.json")); err != nil || !strings.Contains(string(b), metaManagedKind) {
		t.Fatalf("types.json = %q, %v", b, err)
	}
	if _, err := os.Stat(filepath.Join(state, "README.md")); err != nil {
		t.Fatalf("README.md missing: %v", err)
	}
	// Idempotent for the same artifact, conflict for a different one.
	r2l08MustOp(t, "import_managed_reconstruction", r2l08Job(t, map[string]any{"file": pe, "state": state}))
	other := writeTemp(t, "other.dll", append(metaReadFile(t, pe), '\n'))
	if _, err := runOp("import_managed_reconstruction", r2l08Job(t, map[string]any{"file": other, "state": state})); err == nil || !strings.Contains(err.Error(), "state conflict") {
		t.Fatalf("different artifact into populated tree = %v", err)
	}
}
