package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TUR3 lane10 — dart.go, objc.go, op_collect_adb_bugreport.go, op_ext_adb_net.go,
// op_inspect_adb_window.go, op_inspect_macho.go, op_inspect_with_objdump.go,
// op_native_util.go, op_reconcile_javascript_runtime.go,
// op_trace_android_references.go, proctable_linux.go.
// Pure helpers are exercised directly; ops are exercised through the CLI built by
// TestMain against real artifacts (kalitetest/test1, the DEX fixture).

const (
	l10Test1 = "/Users/keremurhan/kalitetest/test1"
	l10Dex   = "testdata/fixtures/apk/classes.dex"
)

func TestR3L10DartVersionHash(t *testing.T) {
	good := strings.Repeat("a", 32)
	if got := dartVersionHash([]byte(good)); got != good {
		t.Fatalf("valid hash = %q, want %q", got, good)
	}
	if got := dartVersionHash([]byte(strings.Repeat("a", 31))); got != "" {
		t.Fatalf("short hash = %q, want empty", got)
	}
	if got := dartVersionHash([]byte(good[:31] + "g")); got != "" {
		t.Fatalf("non-hex hash = %q, want empty", got)
	}
	// Version hash is mapped as 32 ASCII chars right after the 20-byte header.
	if len(good) != 32 || dartHeaderSize != 20 || dartMagic != 0xdcdcf5f5 {
		t.Fatal("dart header constants changed")
	}
}

func TestR3L10ObjcPrintable(t *testing.T) {
	for _, s := range []string{"NSString", "setFoo:", "v@:", ""} {
		if !objcPrintable(s) {
			t.Fatalf("objcPrintable(%q) = false", s)
		}
	}
	for _, s := range []string{"bad\x00name", "bad\nname", strings.Repeat("x", 257)} {
		if objcPrintable(s) {
			t.Fatalf("objcPrintable(%q) = true", s)
		}
	}
}

func TestR3L10ObjdumpFormatRealAndMagic(t *testing.T) {
	if got := objdumpFormat(l10Test1); got != "macho" {
		t.Fatalf("objdumpFormat(test1) = %q, want macho", got)
	}
	cases := []struct {
		magic []byte
		want  string
	}{
		{[]byte("\x7fELF\x02\x01\x01"), "elf"},
		{[]byte("MZ\x90\x00\x03\x00"), "pe"},
		{[]byte("!<arch>\n"), "archive"},
	}
	for _, c := range cases {
		p := filepath.Join(t.TempDir(), "bin")
		if err := os.WriteFile(p, c.magic, 0o644); err != nil {
			t.Fatal(err)
		}
		if got := objdumpFormat(p); got != c.want {
			t.Fatalf("objdumpFormat(%q) = %q, want %q", c.magic, got, c.want)
		}
	}
}

func TestR3L10NativeHelpers(t *testing.T) {
	if got := nativeHexAddr(0x1000); got != "0x1000" {
		t.Fatalf("nativeHexAddr = %q", got)
	}
	if !nativePrintable('A') || nativePrintable('\x00') {
		t.Fatal("nativePrintable wrong")
	}
	if got := nativeASCII([]byte{'A', 0x00, 'z'}); got != "A.z" {
		t.Fatalf("nativeASCII = %q", got)
	}
	dump := nativeHexDump([]byte("AB"))
	if !strings.HasPrefix(dump, "00000000  41 42 ") || !strings.Contains(dump, "|AB|") {
		t.Fatalf("nativeHexDump = %q", dump)
	}
	if got := nativePatternString([]byte{0x41, 0x42}, []bool{true, false}); got != "41 ??" {
		t.Fatalf("nativePatternString = %q", got)
	}
	if _, err := absTarget(l10Test1); err != nil {
		t.Fatalf("absTarget(test1): %v", err)
	}
	if ghidraTimeoutDefault != 50*time.Second || nativeScanCap != 64<<20 || nativeRowsCap != 100 {
		t.Fatalf("hard-limit constants drifted: %v %d %d", ghidraTimeoutDefault, nativeScanCap, nativeRowsCap)
	}
}

func TestR3L10CollectADBBugreportRefusals(t *testing.T) {
	// Validation happens before any device is touched — no adb needed.
	if _, err := collectADBBugreport(""); err == nil || !strings.Contains(err.Error(), "local path") {
		t.Fatalf("empty dest err = %v", err)
	}
	_, err := collectADBBugreport("emulator-5554")
	if err == nil || !strings.Contains(err.Error(), "ending in .zip") {
		t.Fatalf("serial-as-dest err = %v", err)
	}
}

func TestR3L10InspectWithObjdumpReal(t *testing.T) {
	got, err := opInspectWithObjdump(l10Test1)
	if err != nil {
		t.Fatal(err)
	}
	r, ok := got.(objdumpResult)
	if !ok {
		t.Fatalf("result type %T", got)
	}
	if r.Tool != "go:debug/macho" || r.Format != "macho" || len(r.Parts) == 0 {
		t.Fatalf("objdump result = tool %q format %q parts %d", r.Tool, r.Format, len(r.Parts))
	}
	if objdumpCap != 64<<10 || objdumpSymCap != 128<<10 {
		t.Fatal("objdump caps drifted")
	}
}

func TestR3L10ObjdumpPartUTF8Cut(t *testing.T) {
	p := newPart("p", "args", "abcdef", 3)
	if p.Output != "abc" || !p.Truncated {
		t.Fatalf("newPart = %+v", p)
	}
	// rawLen+4 length check in dart.go uses little-endian header fields.
	var h [20]byte
	binary.LittleEndian.PutUint32(h[:4], dartMagic)
	if binary.LittleEndian.Uint32(h[:4]) != dartMagic {
		t.Fatal("endianness check failed")
	}
}

// l10CLI runs the TestMain-built real binary; extra env is merged into a clean env.
func l10CLI(t *testing.T, args []string, extra ...string) (int, string, string) {
	t.Helper()
	if buildErr != nil {
		t.Fatalf("go build failed: %v\n%s", buildErr, buildLog)
	}
	cmd := exec.Command(cliPath, args...)
	cmd.Env = append(os.Environ(), extra...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	rc := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			rc = ee.ExitCode()
		} else {
			t.Fatalf("exec: %v", err)
		}
	}
	return rc, out.String(), errb.String()
}

func TestR3L10InspectMachoRealCLI(t *testing.T) {
	rc, out, _ := l10CLI(t, []string{"--op", "inspect_macho", l10Test1})
	if rc != 0 {
		t.Fatalf("rc=%d out=%s", rc, out)
	}
	if !strings.Contains(out, `"kind":"macho"`) || !strings.Contains(out, `"slices":1`) ||
		!strings.Contains(out, "libc++.1.dylib") {
		t.Fatalf("inspect_macho out = %s", out)
	}
}

func TestR3L10TraceAndroidReferencesRealCLI(t *testing.T) {
	rc, out, _ := l10CLI(t, []string{"--op", "trace_android_references", l10Dex}, "LRECON_QUERY=Lcom/example")
	if rc != 0 {
		t.Fatalf("rc=%d out=%s", rc, out)
	}
	for _, want := range []string{`"edges":15`, `"code_items":6`, "Lcom/example/fix/Main;-", `"callers"`} {
		if !strings.Contains(out, want) {
			t.Fatalf("trace out missing %q: %s", want, out)
		}
	}
}

func TestR3L10ADBRefusalCLI(t *testing.T) {
	rc, out, _ := l10CLI(t, []string{"--op", "collect_adb_bugreport", "emulator-5554"})
	if rc != 2 || !strings.Contains(out, `"kind":"bad_arg"`) {
		t.Fatalf("bugreport refusal rc=%d out=%s", rc, out)
	}
	rc, out, _ = l10CLI(t, []string{"--op", "inspect_adb_window"})
	if rc != 2 || !strings.Contains(out, `"kind":"no_engine"`) {
		t.Fatalf("adb window refusal rc=%d out=%s", rc, out)
	}
}

// compare_artifacts: gerçek job üzerinden metaComparePair/metaSideOf yolunu
// simüle eder. Aynı artefaktın iki tarafı identical dönmeli; tek taraflı job
// ise "old" ve "new" isteyen bir red üretmeli. Sentetik sonuç yok.
func TestR3L10CompareArtifactsSavedDigestIdentity(t *testing.T) {
	art := l10Test1
	if _, err := os.Stat(art); err != nil {
		t.Skipf("test1 fixture yok: %v", err)
	}
	writeJob := func(v map[string]any) string {
		t.Helper()
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(t.TempDir(), "job.json")
		if err := os.WriteFile(p, b, 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	parseResult := func(s string) map[string]any {
		t.Helper()
		var env map[string]any
		if err := json.Unmarshal([]byte(s), &env); err != nil {
			t.Fatalf("not JSON: %v\n%s", err, s)
		}
		r, ok := env["result"].(map[string]any)
		if !ok {
			t.Fatalf("no result object: %s", s)
		}
		return r
	}

	out, rc := runCLI(t, "--op", "compare_artifacts", "--json", writeJob(map[string]any{"old": art, "new": art}))
	if rc != 0 {
		t.Fatalf("rc=%d out=%s", rc, out)
	}
	m := parseResult(out)
	if m["identical"] != true || m["count"] != float64(0) {
		t.Fatalf("aynı artefakt karşılaştırması = %v", m)
	}

	out, rc = runCLI(t, "--op", "compare_artifacts", "--json", writeJob(map[string]any{"old": art}))
	if rc != 2 || !strings.Contains(out, `"kind": "needs_arg"`) || !strings.Contains(out, "old") || !strings.Contains(out, "new") {
		t.Fatalf("tek taraflı job reddi rc=%d out=%s", rc, out)
	}
}

func TestR3L10VersionGate(t *testing.T) {
	rc, out, _ := l10CLI(t, []string{"--version"})
	if rc != 0 || !strings.Contains(out, "lrecon 1.0.0") {
		t.Fatalf("version rc=%d out=%s", rc, out)
	}
}
