//go:build unix

package main

// Tests for the final.md NATIVE items (45-90). The L items are checked against
// a real Go binary built here, so every assertion is an exact offset/address
// from bytes on disk; the G items assert the Go<->Ghidra script contract and
// the absent-tool skip, with at most one real import behind -short.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// nativeOpTable is the item list with the route final.md assigns. A wrong route
// is a lie about how the answer was produced, so it is asserted, not ignored.
var nativeOpTable = map[string]struct {
	route string
	needs bool
}{
	"address_name":                     {"G", true},
	"address_to_file_offset":           {"G", true},
	"analyze_function":                 {"G", true},
	"batch_decompile":                  {"G", true},
	"build_call_path":                  {"G", true},
	"compare_functions":                {"G", true},
	"current_address":                  {"L", false},
	"current_document":                 {"L", false},
	"current_procedure":                {"L", false},
	"cutter_command":                   {"Y", true},
	"decompile_all":                    {"G", true},
	"execute_rizin_command":            {"Y", true},
	"find_xrefs_to_name":               {"G", true},
	"get_call_graph":                   {"G", true},
	"get_navigation_context":           {"L", false},
	"goto_address":                     {"L", true},
	"inspect_address_context":          {"G", true},
	"inspect_native_api":               {"L", true},
	"inspect_native_data_type":         {"G", true},
	"inspect_native_dispatch_metadata": {"G", true},
	"inspect_native_instruction":       {"G", true},
	"list_cutter_sessions":             {"L", false}, // filesystem + kernel process table, no external tool
	"list_documents":                   {"L", false},
	"list_names":                       {"G", true},
	"list_procedures":                  {"G", true},
	"list_segments":                    {"G", true},
	"list_strings":                     {"L", true},
	"match_native_functions":           {"G", true},
	"next_address":                     {"L", false},
	"prev_address":                     {"L", false},
	"procedure_address":                {"G", true},
	"procedure_assembly":               {"G", true},
	"procedure_callees":                {"G", true},
	"procedure_callers":                {"G", true},
	"procedure_info":                   {"G", true},
	"procedure_pseudo_code":            {"G", true},
	"procedure_references":             {"G", true},
	"read_bytes":                       {"L", true},
	"read_function_instructions":       {"G", true},
	"resolve_containing_procedure":     {"G", true},
	"resolve_native_call_targets":      {"G", true},
	"search_bytes":                     {"L", true},
	"search_procedures":                {"G", true},
	"search_strings":                   {"L", true},
	"trace_call_path":                  {"G", true},
	"xrefs":                            {"G", true},
}

// The script carries the exit-code/stderr contract; losing it means the Go side
// can no longer tell a refusal from a crashed import.
var nativeScriptContract = []string{
	"exactly one JSON object is written to <outFile>",
	"analyzeHeadless still exits 0",
	"an uncaught exception leaves no file and a non-zero analyzeHeadless exit",
	`write(err.toString())`,
	"unknown NativeOp command",
}

const nativeFixtureSrc = `package main

import "fmt"

var marker = "lrecon-native-fixture-marker-0123456789"

func add(a, b int) int { return a + b }

func main() { fmt.Println(add(2, 3), marker) }
`

// nativeFixture builds the smallest real Go binary: pclntab supplies the
// function table, the marker gives the string scanner a known hit.
func nativeFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	src := filepath.Join(dir, "main.go")
	if err := os.WriteFile(src, []byte(nativeFixtureSrc), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "fixture")
	cmd := exec.Command("go", "build", "-o", out, src)
	cmd.Env = append(os.Environ(), "GO111MODULE=off", "GOFLAGS=", "GOOS=darwin", "GOARCH=arm64", "CGO_ENABLED=0")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build fixture: %v\n%s", err, b)
	}
	return out
}

func TestOpNativeRegistered(t *testing.T) {
	if len(nativeOpTable) != 46 {
		t.Fatalf("table has %d items, want 46", len(nativeOpTable))
	}
	for name, want := range nativeOpTable {
		o, ok := ops[name]
		if !ok {
			t.Errorf("%s is not registered", name)
			continue
		}
		if o.route != want.route {
			t.Errorf("%s route is %q, want %q", name, o.route, want.route)
		}
		if o.needs != want.needs {
			t.Errorf("%s needs is %v, want %v", name, o.needs, want.needs)
		}
		if strings.TrimSpace(o.desc) == "" {
			t.Errorf("%s has no description", name)
		}
	}
}

func TestOpNativeGhidraScriptContract(t *testing.T) {
	script, err := os.ReadFile(filepath.Join("ghidra", "scripts", "NativeOp.java"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(script)
	for _, marker := range nativeScriptContract {
		if !strings.Contains(s, marker) {
			t.Errorf("NativeOp.java lost the contract line %q", marker)
		}
	}
	for name, want := range nativeOpTable {
		if want.route != "G" {
			continue
		}
		if !strings.Contains(s, "case \""+name+"\":") {
			t.Errorf("%s has no NativeOp.java branch", name)
		}
	}
	if nativeOpScript != s {
		t.Error("embedded script differs from ghidra/scripts/NativeOp.java: the binary would run stale code")
	}
}

func TestOpNativeGhidraAbsent(t *testing.T) {
	// Build the fixture first: the Go toolchain needs the real PATH.
	bin := nativeFixture(t)
	// findGhidra also globs Homebrew install roots, so PATH alone is not enough:
	// the finder is swapped to prove the skip branch, and PATH is cleared here to
	// also cover exec.LookPath.
	t.Setenv("PATH", "")
	t.Setenv("GHIDRA_HOME", "")
	old := ghidraFinder
	ghidraFinder = func() (string, string, error) { return "", "", errors.New("not installed") }
	t.Cleanup(func() { ghidraFinder = old })
	t.Setenv("LRECON_AT", "0x1000")
	res, err := ops["list_segments"].run(bin)
	if err != nil {
		t.Fatalf("absent ghidra is a skip, not an error: %v", err)
	}
	skip, ok := res.(*skip)
	if !ok {
		t.Fatalf("absent ghidra answered %T, want *skip", res)
	}
	if !strings.Contains(skip.Reason, "analyzeHeadless not installed") {
		t.Errorf("skip reason %q does not name the missing tool", skip.Reason)
	}
}

func TestOpNativeGhidraRealImport(t *testing.T) {
	if testing.Short() {
		t.Skip("real ghidra import")
	}
	if _, _, err := findGhidra(); err != nil {
		t.Skip("ghidra analyzeHeadless not installed")
	}
	// A real import is the case the 50 s default refuses to gamble on: the
	// budget must outlast it or the test asserts on a timeout envelope.
	t.Setenv("LRECON_GHIDRA_TIMEOUT", "300s")
	res, err := ops["list_segments"].run("/usr/bin/true")
	if err != nil {
		t.Fatalf("list_segments on /usr/bin/true: %v", err)
	}
	m, ok := res.(map[string]any)
	if !ok {
		t.Fatalf("list_segments answered %T, want a map", res)
	}
	blocks, ok := m["blocks"].(float64)
	if !ok || blocks < 1 {
		t.Fatalf("list_segments blocks = %v, want a positive count", m["blocks"])
	}
	if segs, ok := m["segments"].([]any); !ok || len(segs) == 0 {
		t.Fatalf("list_segments segments = %T, want rows", m["segments"])
	}
	if m["ghidra_version"] == nil || m["script"] != "NativeOp.java list_segments" {
		t.Errorf("result does not prove the headless run: %v", m)
	}
}

func TestOpNativeLocalItems(t *testing.T) {
	bin := nativeFixture(t)
	t.Setenv("LRECON_SESSION", filepath.Join(t.TempDir(), "session.json"))

	kind, secs, err := nativeSections(bin)
	if err != nil {
		t.Fatal(err)
	}
	if kind != "macho" {
		t.Fatalf("fixture is %s, expected macho on darwin", kind)
	}
	var text *fileSection
	for i := range secs {
		if secs[i].Name == "__TEXT,__text" {
			text = &secs[i]
		}
	}
	if text == nil || text.Addr == 0 || text.Off == 0 || text.Size < 16 {
		t.Fatalf("fixture has no usable __TEXT,__text: %+v", text)
	}

	t.Run("functions", func(t *testing.T) {
		fns, err := nativeFunctions(bin)
		if err != nil {
			t.Fatal(err)
		}
		if len(fns) < 3 {
			t.Fatalf("fixture has %d functions, want at least 3", len(fns))
		}
		var mainFn *nativeFunc
		for i := range fns {
			if fns[i].Name == "main.main" {
				mainFn = &fns[i]
			}
		}
		if mainFn == nil {
			t.Fatalf("pclntab names are missing main.main: %v", fns[:min(len(fns), 5)])
		}
		if mainFn.Start < text.Addr || mainFn.End > text.Addr+text.Size {
			t.Errorf("main.main [%x,%x) is outside __TEXT,__text [%x,%x)",
				mainFn.Start, mainFn.End, text.Addr, text.Addr+text.Size)
		}
		if got := containingFunction(fns, mainFn.Start); got == nil || got.Name != "main.main" {
			t.Errorf("containingFunction at main.main start = %+v", got)
		}
	})

	t.Run("session", func(t *testing.T) {
		if _, err := ops["current_address"].run(""); err == nil ||
			!strings.Contains(err.Error(), "goto_address") {
			t.Fatalf("current_address without a session = %v, want a goto_address hint", err)
		}
		at := text.Addr + 1
		t.Setenv("LRECON_AT", fmt.Sprintf("0x%x", at))
		res, err := ops["goto_address"].run(bin)
		if err != nil {
			t.Fatal(err)
		}
		m := res.(map[string]any)
		if m["address"] != fmt.Sprintf("0x%x", at) {
			t.Errorf("goto_address address = %v", m["address"])
		}
		if m["section"] != "__TEXT,__text" {
			t.Errorf("goto_address section = %v", m["section"])
		}

		cur, err := ops["current_address"].run("")
		if err != nil {
			t.Fatal(err)
		}
		cm := cur.(map[string]any)
		if cm["address"] != m["address"] {
			t.Errorf("current_address = %v, want %v", cm["address"], m["address"])
		}
		if cm["procedure"] == "" {
			t.Errorf("current_address has no procedure: %v", cm)
		}
		from := cm["address"].(string)

		nxt, err := ops["next_address"].run("")
		if err != nil {
			t.Fatal(err)
		}
		nm := nxt.(map[string]any)
		if nm["found"] != true || nm["from"] != from || nm["to"] == from {
			t.Fatalf("next_address = %v, want a new cursor after %s", nm, from)
		}

		prv, err := ops["prev_address"].run("")
		if err != nil {
			t.Fatal(err)
		}
		pm := prv.(map[string]any)
		fns, ferr := nativeFunctions(bin)
		if ferr != nil {
			t.Fatal(ferr)
		}
		back := containingFunction(fns, at)
		if pm["found"] != true || back == nil || pm["to"] != hexAddrBack(back.Start) {
			t.Fatalf("prev_address = %v, want the function before %v at %x", pm, nm["to"], back.Start)
		}

		docs, err := ops["list_documents"].run("")
		if err != nil {
			t.Fatal(err)
		}
		rows := docs.(map[string]any)["documents"].([]map[string]any)
		if len(rows) != 1 || rows[0]["path"] != mustAbs(t, bin) || rows[0]["exists"] != true {
			t.Errorf("list_documents = %v", rows)
		}
	})

	t.Run("document_and_navigation", func(t *testing.T) {
		doc, err := ops["current_document"].run("")
		if err != nil {
			t.Fatal(err)
		}
		dm := doc.(map[string]any)
		if dm["document"] != mustAbs(t, bin) || dm["documents"] != 1 || dm["size"] == nil {
			t.Fatalf("current_document = %v", dm)
		}
		proc, err := ops["current_procedure"].run("")
		if err != nil {
			t.Fatal(err)
		}
		if pm := proc.(map[string]any); pm["procedure"] == "" || pm["document"] != mustAbs(t, bin) {
			t.Fatalf("current_procedure = %v", pm)
		}
		nav, err := ops["get_navigation_context"].run("")
		if err != nil {
			t.Fatal(err)
		}
		nm := nav.(map[string]any)
		if nm["document"] != mustAbs(t, bin) || nm["address"] == "" || nm["procedure"] == "" {
			t.Fatalf("get_navigation_context = %v", nm)
		}
	})

	t.Run("read_bytes", func(t *testing.T) {
		t.Setenv("LRECON_AT", fmt.Sprintf("0x%x", text.Addr))
		t.Setenv("LRECON_LEN", "16")
		res, err := ops["read_bytes"].run(bin)
		if err != nil {
			t.Fatal(err)
		}
		m := res.(map[string]any)
		if m["length"] != 16 || m["file_offset"] != text.Off || m["basis"] != "virtual_address" {
			t.Fatalf("read_bytes = %v, want 16 bytes at file offset %d", m, text.Off)
		}
		first, err := nativeReadAt(bin, text.Off, 1)
		if err != nil {
			t.Fatal(err)
		}
		if want := fmt.Sprintf("%08x  %02x ", 0, first[0]); !strings.HasPrefix(m["hex"].(string), want) {
			t.Errorf("hex dump starts %q, want prefix %q", m["hex"], want)
		}
	})

	t.Run("search_bytes", func(t *testing.T) {
		probe, err := nativeReadAt(bin, text.Off, 6)
		if err != nil {
			t.Fatal(err)
		}
		pat := make([]string, len(probe))
		for i, b := range probe {
			pat[i] = fmt.Sprintf("%02x", b)
		}
		t.Setenv("LRECON_PATTERN", strings.Join(pat, " "))
		res, err := ops["search_bytes"].run(bin)
		if err != nil {
			t.Fatal(err)
		}
		m := res.(map[string]any)
		matches := m["matches"].([]patternHit)
		found := false
		for _, hit := range matches {
			if hit.Addr == text.Addr {
				found = true
			}
		}
		if !found {
			t.Errorf("search_bytes missed the pattern at %x: %v", text.Addr, matches)
		}
		if m["normalized"] != strings.Join(pat, " ") {
			t.Errorf("normalized pattern = %v", m["normalized"])
		}
		// A few-KB fixture is scanned in full, so the answer may claim it.
		if m["scanned_whole"] != true {
			t.Errorf("search_bytes scanned_whole = %v for the tiny fixture", m["scanned_whole"])
		}
	})

	t.Run("strings", func(t *testing.T) {
		t.Setenv("LRECON_QUERY", "lrecon-native-fixture-marker")
		res, err := ops["search_strings"].run(bin)
		if err != nil {
			t.Fatal(err)
		}
		m := res.(map[string]any)
		if m["matched"].(int) < 1 {
			t.Fatalf("search_strings matched %v of %v strings", m["matched"], m["strings"])
		}
		first := m["matches"].([]stringHit)[0]
		if !strings.Contains(first.Value, "lrecon-native-fixture-marker") || first.Addr == 0 {
			t.Errorf("search_strings first hit = %+v", first)
		}
		if first.ASCII != true {
			t.Errorf("fixture marker should be an ASCII hit: %+v", first)
		}
		if m["scanned_whole"] != true || m["strings_scanned"] != m["strings"] {
			t.Errorf("search_strings scanned_whole=%v strings_scanned=%v strings=%v", m["scanned_whole"], m["strings_scanned"], m["strings"])
		}

		list, err := ops["list_strings"].run(bin)
		if err != nil {
			t.Fatal(err)
		}
		lm := list.(map[string]any)
		if lm["strings"].(int) < 1 || len(lm["rows"].([]stringHit)) < 1 {
			t.Errorf("list_strings = %v", lm)
		}
		if lm["scanned_whole"] != true {
			t.Errorf("list_strings scanned_whole = %v for a small fixture", lm["scanned_whole"])
		}
	})
}

func TestOpNativeImports(t *testing.T) {
	kind, rows, err := nativeImports(fixtureMacho)
	if err != nil {
		t.Fatal(err)
	}
	if kind != "macho" {
		t.Fatalf("%s is %s, expected macho", fixtureMacho, kind)
	}
	if len(rows) == 0 {
		t.Fatalf("no imports recovered from %s", fixtureMacho)
	}
	named := 0
	for _, r := range rows {
		if r.Name != "" {
			named++
		}
		if r.Basis == "" {
			t.Errorf("row %+v has no basis", r)
		}
	}
	if named == 0 {
		t.Fatal("every import row is unnamed")
	}
	res, err := ops["inspect_native_api"].run(fixtureMacho)
	if err != nil {
		t.Fatal(err)
	}
	m := res.(map[string]any)
	if m["format"] != "macho" || m["imports"].(int) != len(rows) {
		t.Errorf("inspect_native_api = %v, want %d imports", m, len(rows))
	}
}

// A target whose import table is really empty (a relocatable object has no
// .dynsym; a static image such as dyld imports nothing) answered rc=2 with an
// internal-kind "no imports" refusal, so a CI driver kept retrying a success.
// It must be a normal answer: zero imports, rc=0, a note saying why it is empty.
func TestInspectNativeAPIAcceptsEmptyImportTable(t *testing.T) {
	path := "testdata/fixtures/cxx/vtables.o"
	res, err := ops["inspect_native_api"].run(path)
	if err != nil {
		t.Fatalf("inspect_native_api(%s) refused an empty import table: %v", path, err)
	}
	m := res.(map[string]any)
	if m["format"] != "elf" {
		t.Errorf("format = %v, want elf", m["format"])
	}
	if m["imports"].(int) != 0 || m["shown"].(int) != 0 {
		t.Errorf("imports/shown = %v/%v, want 0/0", m["imports"], m["shown"])
	}
	if rows, ok := m["rows"].([]nativeAPI); !ok || len(rows) != 0 {
		t.Errorf("rows = %v, want an empty list", m["rows"])
	}
	if note, _ := m["note"].(string); note == "" {
		t.Errorf("empty answer carries no note: %v", m)
	}
}

func TestOpNativeBytePattern(t *testing.T) {
	pat, mask, err := parseBytePattern("48 8b ?? c3")
	if err != nil {
		t.Fatal(err)
	}
	if len(pat) != 4 || pat[0] != 0x48 || mask[2] {
		t.Fatalf("parse = %x mask %v", pat, mask)
	}
	if got := nativePatternString(pat, mask); got != "48 8b ?? c3" {
		t.Errorf("render = %q", got)
	}
	if _, _, err := parseBytePattern("48 zz"); err == nil {
		t.Error("non-hex byte was accepted")
	}
	if _, _, err := parseBytePattern("  "); err == nil {
		t.Error("empty pattern was accepted")
	}
	compact, cmask, err := parseBytePattern("c3")
	if err != nil || compact[0] != 0xc3 || !cmask[0] {
		t.Errorf("single byte = %x %v %v", compact, cmask, err)
	}
}

// hexAddrBack keeps the test independent of the production formatter.
func hexAddrBack(v uint64) string { return fmt.Sprintf("0x%x", v) }

// Ghidra logs the JVM banner and INFO chatter before the cause; the reported
// line must be the ERROR line a reviewer can search for.
func TestRtCauseLineSkipsLogNoise(t *testing.T) {
	stderr := "Picked up JAVA_TOOL_OPTIONS: -Xmx2g\nopenjdk version \"21.0.12.1\"\n" +
		"OpenJDK Runtime Environment Homebrew (build 21.0.12.1)\n" +
		"INFO  Using log config file: jar:file:/g/generic.log4j.xml\n" +
		"WARNING: A restricted method was called\n" +
		"ERROR The ProgramLoader could not successfully load file:///tmp/x.bin (HeadlessAnalyzer)\n"
	got := rtCauseLine(stderr, "")
	if !strings.HasPrefix(got, "ERROR The ProgramLoader could not load") &&
		!strings.HasPrefix(got, "ERROR The ProgramLoader") {
		t.Fatalf("got %q, want the ERROR line", got)
	}
	if strings.Contains(got, "openjdk") || strings.Contains(got, "INFO ") {
		t.Fatalf("log noise leaked: %q", got)
	}
	if got := rtCauseLine("", ""); got != "no output" {
		t.Fatalf("empty streams = %q", got)
	}
	if got := rtCauseLine("just a path\n"); got != "just a path" {
		t.Fatalf("no error marker = %q, want fallback", got)
	}
}

// TestGhidraExecKillsProcessGroup pins both ways a Ghidra run ends with java
// still alive, because analyzeHeadless is a wrapper script and java is its
// child holding our stdout pipe:
//   - deadline while the wrapper still runs: exec calls Cancel, so the process
//     group must die at the deadline instead of at WaitDelay;
//   - wrapper exits first: exec never calls Cancel, java keeps the pipe open and
//     Run only returns via WaitDelay with java alive, so ghidraReap must end it.
func TestGhidraExecKillsProcessGroup(t *testing.T) {
	cases := []struct {
		name    string
		script  string
		timeout time.Duration        // must outlast the shim's fork+echo, nothing more
		ends    func(err error) bool // how Run must have ended: the proof, not a clock
		why     string
		leaks   bool // java still running when Run returns, waiting for the reap
	}{
		{"deadline-with-wrapper-alive", "#!/bin/sh\nsleep 30 &\necho $! > \"$FAKE_CHILD_PID\"\nwait\n", 2 * time.Second, killedBySIGKILL, "SIGKILL from Cancel at the deadline", false},
		{"wrapper-exits-first", "#!/bin/sh\nsleep 30 &\necho $! > \"$FAKE_CHILD_PID\"\n", 700 * time.Millisecond, func(err error) bool { return errors.Is(err, exec.ErrWaitDelay) }, "exec.ErrWaitDelay with java still holding the pipe", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			fake := filepath.Join(dir, "analyzeHeadless")
			pidFile := filepath.Join(dir, "child.pid")
			if err := os.WriteFile(fake, []byte(tc.script), 0o755); err != nil {
				t.Fatal(err)
			}
			// The deadline only has to outrun the shim's fork+echo; the run is
			// ended by the kill below (the script sleeps 30s), so a wide margin
			// here removes the write-vs-kill race without weakening the check.
			ctx, cancel := context.WithTimeout(context.Background(), tc.timeout)
			defer cancel()
			// Run the wrapper through its interpreter instead of letting the
			// kernel read the shebang: macOS delays the first direct exec of a
			// freshly written script by 0.3-1.1s here (measured with
			// /usr/bin/time on a 2-line script; /bin/sh <script> is 0.01s), which
			// lands after the 700ms deadline and turns both cases into a coin
			// flip. The topology under test (group leader, child holding stdout,
			// Cancel, WaitDelay) is the same either way.
			cmd := ghidraExec(ctx, "/bin/sh", fake)
			cmd.Env = append(os.Environ(), "FAKE_CHILD_PID="+pidFile)
			var out bytes.Buffer
			cmd.Stdout = &out // a buffer forces the pipe exec's Wait has to drain
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			pgid := cmd.Process.Pid
			err := cmd.Wait()
			if err == nil {
				t.Fatal("fake analyzeHeadless reported success, want a failure")
			}
			// The end of Run is pinned by the error it returned, not by wall
			// clock: a slow host must not turn a correct kill into a failure.
			if !tc.ends(err) {
				t.Fatalf("Run ended with %v, want %s", err, tc.why)
			}
			pid, err := strconv.Atoi(strings.TrimSpace(readFileString(t, pidFile)))
			if err != nil {
				t.Fatalf("fake child pid: %v", err)
			}
			if tc.leaks {
				if !processAlive(pid) {
					t.Fatalf("grandchild %d was already gone when Run returned, so the reap has nothing to prove", pid)
				}
			} else if !processGone(pid) {
				syscall.Kill(pid, syscall.SIGKILL)
				t.Fatalf("grandchild %d alive after Run, want the deadline kill to have taken it", pid)
			}
			ghidraReap(pgid)
			if !processGone(pid) {
				syscall.Kill(pid, syscall.SIGKILL)
				t.Fatalf("grandchild %d survived ghidraReap", pid)
			}
		})
	}
}

// TestGhidraHeadlessReapsLeakedChild drives the real call site, not just the
// helpers: the fake analyzeHeadless spawns a child that inherits the pipes,
// writes the script's JSON itself, and exits. Without the reap, ghidraHeadless
// would return with that child still running on every Ghidra timeout.
func TestGhidraHeadlessReapsLeakedChild(t *testing.T) {
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "child.pid")
	headless := filepath.Join(dir, "analyzeHeadless")
	script := "#!/bin/sh\nsleep 30 &\necho $! > \"$FAKE_CHILD_PID\"\n" +
		"for a in \"$@\"; do case $a in *result.json) out=$a ;; esac; done\n" +
		"printf '%s' '{\"ok\":true}' > \"$out\"\n"
	if err := os.WriteFile(headless, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "target.bin")
	if err := os.WriteFile(target, []byte("MZ"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FAKE_CHILD_PID", pidFile)
	res, err := ghidraHeadless(headless, filepath.Join(dir, "work"), target, "digest", nil, "", true)
	if err != nil {
		t.Fatalf("ghidraHeadless: %v", err)
	}
	if ok, _ := res["ok"].(bool); !ok {
		t.Fatalf("ghidraHeadless did not read the script's answer: %v", res)
	}
	pid, convErr := strconv.Atoi(strings.TrimSpace(readFileString(t, pidFile)))
	if convErr != nil {
		t.Fatalf("fake child pid: %v", convErr)
	}
	if !processGone(pid) {
		syscall.Kill(pid, syscall.SIGKILL)
		t.Fatalf("child %d outlived ghidraHeadless: the run leaked a live process", pid)
	}
}

// processAlive reports whether pid is a live process. A killed child is a
// zombie until its parent reaps it and kill(pid, 0) still succeeds on one, so
// the state is read from ps: a container's PID 1 is often a bare sh that never
// reaps, and its zombies must not read as a leaked child. processGone polls
// because a fresh kill takes a moment to settle.
func processAlive(pid int) bool {
	if pid <= 0 || syscall.Kill(pid, 0) != nil {
		return false
	}
	out, err := exec.Command("ps", "-o", "stat=", "-p", strconv.Itoa(pid)).Output()
	if err != nil {
		return false
	}
	return !strings.HasPrefix(strings.TrimSpace(string(out)), "Z")
}

// killedBySIGKILL reports whether err is an exit caused by SIGKILL. That is the
// deadline's own fingerprint: Cancel kills the whole group, so the error names
// the signal instead of leaving a timing threshold to flake on a loaded host.
func killedBySIGKILL(err error) bool {
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		return false
	}
	ws, ok := ee.Sys().(syscall.WaitStatus)
	return ok && ws.Signaled() && ws.Signal() == syscall.SIGKILL
}

func processGone(pid int) bool {
	for range 100 {
		if !processAlive(pid) {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

func readFileString(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestStringsTruncationContract pins the two cuts apart. A small scan budget
// makes scanned_whole false while the row cap still hides the tail: truncated
// is total > shown, not "the scan was short". Without it a reader sees shown=2
// and no way to tell a 2-string file from a 20 000-string one.
func TestStringsTruncationContract(t *testing.T) {
	bin := nativeFixture(t)
	const scanCap = 64 << 10

	t.Run("list_strings row cap", func(t *testing.T) {
		res, err := listStringsAnswer(bin, 2, scanCap)
		if err != nil {
			t.Fatal(err)
		}
		m := res.(map[string]any)
		total := m["strings"].(int)
		rows := m["rows"].([]stringHit)
		if m["scanned_whole"] != false {
			t.Errorf("scanned_whole = %v, want false: the %d-byte budget was spent", m["scanned_whole"], scanCap)
		}
		if m["truncated"] != true {
			t.Errorf("truncated = %v, want true: %d strings found, %d shown", m["truncated"], total, len(rows))
		}
		if total <= len(rows) || len(rows) != 2 {
			t.Errorf("strings=%d rows=%d, want total > 2 rows", total, len(rows))
		}
	})

	t.Run("list_strings whole", func(t *testing.T) {
		res, err := listStringsAnswer(bin, 1<<20, 1<<30)
		if err != nil {
			t.Fatal(err)
		}
		m := res.(map[string]any)
		if m["scanned_whole"] != true || m["truncated"] != false {
			t.Errorf("scanned_whole=%v truncated=%v, want true/false for an uncapped read", m["scanned_whole"], m["truncated"])
		}
	})

	t.Run("search_strings match cap", func(t *testing.T) {
		res, err := searchStringsAnswer(bin, "a", 50000, 1, scanCap)
		if err != nil {
			t.Fatal(err)
		}
		m := res.(map[string]any)
		matches := m["matches"].([]stringHit)
		matched := m["matched"].(int)
		if m["scanned_whole"] != false {
			t.Errorf("scanned_whole = %v, want false", m["scanned_whole"])
		}
		if m["truncated"] != true {
			t.Errorf("truncated = %v, want true: %d matched, %d shown", m["truncated"], matched, len(matches))
		}
		if matched <= len(matches) || len(matches) != 1 {
			t.Errorf("matched=%d shown=%d, want matched > 1", matched, len(matches))
		}
	})

	t.Run("search_strings keep cap", func(t *testing.T) {
		res, err := searchStringsAnswer(bin, "a", 2, 1, scanCap)
		if err != nil {
			t.Fatal(err)
		}
		m := res.(map[string]any)
		if m["strings_truncated"] != true {
			t.Errorf("strings_truncated = %v, want true: %d strings, %d searched",
				m["strings_truncated"], m["strings"], m["strings_scanned"])
		}
		if m["strings_scanned"] != 2 {
			t.Errorf("strings_scanned = %v, want 2: the keep cap must be visible", m["strings_scanned"])
		}
		if m["strings"].(int) <= 2 {
			t.Errorf("strings = %d, want more than the 2 retained", m["strings"])
		}
		// keep only bounds the reported strings; matched must still count the
		// whole scanned prefix, or a keep cut silently shrinks the match count.
		if matched := m["matched"].(int); matched <= 2 {
			t.Errorf("matched = %d, want matches counted past the 2 retained strings", matched)
		}
	})
}

// A dump is a device-side render, not a probe: 37.36s measured on a working
// emulator. The 20s probe budget reported "timeout" for a UI that was there, so
// the dump must outlive it. The shim sleeps past the probe budget and answers
// the two device reads that follow.
func TestObserveNativeUIDumpOutlivesProbeBudget(t *testing.T) {
	if testing.Short() {
		t.Skip("21s shim proves the dump budget")
	}
	rtFakeTool(t, "adb", `if [ "$1" = "devices" ]; then printf 'List of devices attached\nfake-1\tdevice\n'; exit 0; fi
if [ "$2" = "uiautomator" ]; then sleep 21; echo "UI hierchary dumped to: /data/local/tmp/ui-1.xml"; exit 0; fi
if [ "$2" = "cat" ]; then printf '<hierarchy><node class="x"/></hierarchy>'; exit 0; fi
exit 0`)
	res, err := ops["observe_native_ui"].run("")
	if err != nil {
		t.Fatalf("a 21s dump must not read as a timeout: %v", err)
	}
	ui, ok := res.(rt2NativeUI)
	if !ok {
		t.Fatalf("observe_native_ui answered %T", res)
	}
	if !ui.Dumped || ui.Nodes != 1 || !strings.Contains(ui.XML, "<node") {
		t.Fatalf("dump = %+v, want dumped with one node", ui)
	}
}

// K7: a G answer names the slice Ghidra imports. Only the first slice of a
// universal binary is importable, so the name has to be the first slice's, not
// the host's or the caller's guess.
func TestGhidraSlice(t *testing.T) {
	arm := buildTarget(t, "darwin", "arm64", "slice-arm64")
	if arch, slices := ghidraSlice(arm); arch != "arm64" || slices != "" {
		t.Fatalf("thin = %q %q, want arm64 with no slice list", arch, slices)
	}
	if arch, _ := ghidraSlice(buildTarget(t, "linux", "amd64", "slice.elf")); arch != "" {
		t.Fatalf("ELF arch = %q, want none", arch)
	}
	if _, err := exec.LookPath("lipo"); err != nil {
		t.Skip("lipo not installed: no universal fixture")
	}
	amd := buildTarget(t, "darwin", "amd64", "slice-amd64")
	fat := filepath.Join(t.TempDir(), "fat")
	if out, err := exec.Command("lipo", "-create", arm, amd, "-output", fat).CombinedOutput(); err != nil {
		t.Fatalf("lipo: %v\n%s", err, out)
	}
	arch, slices := ghidraSlice(fat)
	if arch == "" || !strings.HasPrefix(slices, arch) || !strings.Contains(slices, "x86-64") || !strings.Contains(slices, "arm64") {
		t.Fatalf("fat = %q %q, want the first slice as arch and every slice listed", arch, slices)
	}
}
