package main

// TUR3 lane06 simulation: real binary + real fixtures for this lane's ops.
// Self-contained so it builds even while other lanes' test files are mid-write.

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

var (
	r3binOnce sync.Once
	r3bin     string
	r3binErr  error
)

func r3Build(t *testing.T) string {
	t.Helper()
	r3binOnce.Do(func() {
		dir, err := os.MkdirTemp("", "r3lane06-bin-")
		if err != nil {
			r3binErr = err
			return
		}
		r3bin = filepath.Join(dir, "lrecon-r3")
		cmd := exec.Command("go", "build", "-o", r3bin, ".")
		var out bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &out
		if err := cmd.Run(); err != nil {
			r3binErr = err
		}
	})
	if r3binErr != nil {
		t.Fatalf("build lrecon: %v", r3binErr)
	}
	return r3bin
}

func r3run(t *testing.T, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command(r3Build(t), args...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	rc := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			rc = ee.ExitCode()
		} else {
			t.Fatalf("run %v: %v", args, err)
		}
	}
	return out.String(), rc
}

func r3map(t *testing.T, args ...string) (map[string]any, int) {
	t.Helper()
	out, rc := r3run(t, args...)
	var v map[string]any
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		t.Fatalf("not JSON object: %v\n%s", err, out)
	}
	return v, rc
}

func r3array(t *testing.T, args ...string) ([]any, int) {
	t.Helper()
	out, rc := r3run(t, args...)
	var v []any
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		t.Fatalf("not JSON array: %v\n%s", err, out)
	}
	return v, rc
}

func TestR3LNNBinaryVersionAndOpCounts(t *testing.T) {
	out, rc := r3run(t, "--version")
	if rc != 0 || !strings.Contains(out, "1.0.0") {
		t.Fatalf("--version rc=%d out=%q", rc, out)
	}
	ops, rc := r3array(t, "--list-ops", "--json")
	if rc != 0 || len(ops) != 235 {
		t.Fatalf("--list-ops rc=%d count=%d, want 0/235", rc, len(ops))
	}
	ext, rc := r3array(t, "--list-ext-ops", "--json")
	if rc != 0 || len(ext) != 80 {
		t.Fatalf("--list-ext-ops rc=%d count=%d, want 0/80", rc, len(ext))
	}
}

func TestR3LNNRefusalOpsOnRealBinary(t *testing.T) {
	for _, tc := range []struct {
		op, kind string
	}{
		{"execute_rizin_command", "out_of_scope"},
		{"start_rizin_debug_session", "out_of_scope"},
	} {
		v, rc := r3map(t, "--op", tc.op, "--json", "./lrecon/lrecon")
		if rc != 2 || v["kind"] != tc.kind {
			t.Fatalf("%s rc=%d kind=%v, want 2/%s", tc.op, rc, v["kind"], tc.kind)
		}
		if err, _ := v["error"].(string); !strings.Contains(err, "out of scope") {
			t.Fatalf("%s error=%q", tc.op, err)
		}
	}
}

func TestR3LNNIL2CPPOnRealFixtures(t *testing.T) {
	v, rc := r3map(t, "--op", "inspect_il2cpp_metadata", "--json",
		"testdata/fixtures/il2cpp/global-metadata.dat")
	if rc != 0 {
		t.Fatalf("il2cpp fixture rc=%d %+v", rc, v)
	}
	res, _ := v["result"].(map[string]any)
	if res["kind"] != "il2cpp-metadata" || res["version"] != float64(31) {
		t.Fatalf("il2cpp result=%+v", res)
	}
	v, rc = r3map(t, "--op", "inspect_il2cpp_metadata", "--json",
		"testdata/fixtures/il2cpp/player.bin")
	if rc != 0 {
		t.Fatalf("player fixture rc=%d %+v", rc, v)
	}
	res, _ = v["result"].(map[string]any)
	if res["kind"] != "macho" {
		t.Fatalf("player kind=%v", res["kind"])
	}
	caps, _ := res["capabilities"].([]any)
	found := false
	for _, c := range caps {
		if c == "il2cpp" {
			found = true
		}
	}
	if !found {
		t.Fatalf("player capabilities=%v, want il2cpp", caps)
	}
	// A real Mach-O without any Unity marker is an honest bad_arg, not a claim.
	v, rc = r3map(t, "--op", "inspect_il2cpp_metadata", "--json",
		"/Users/keremurhan/kalitetest/test1")
	if rc != 2 || v["kind"] != "bad_arg" {
		t.Fatalf("non-Unity Mach-O rc=%d kind=%v, want 2/bad_arg", rc, v["kind"])
	}
}

func TestR3LNNWasmOnRealFixture(t *testing.T) {
	v, rc := r3map(t, "--op", "inspect_wasm_artifact", "--json",
		"testdata/fixtures/wasm.wasm")
	if rc != 0 {
		t.Fatalf("wasm fixture rc=%d %+v", rc, v)
	}
	res, _ := v["result"].(map[string]any)
	if res["version"] != float64(1) {
		t.Fatalf("wasm version=%v", res["version"])
	}
	imports, _ := res["imports"].([]any)
	exports, _ := res["exports"].([]any)
	if len(imports) == 0 || len(exports) == 0 {
		t.Fatalf("wasm imports=%d exports=%d, want both", len(imports), len(exports))
	}
	v, rc = r3map(t, "--op", "inspect_wasm_artifact", "--json",
		"/Users/keremurhan/kalitetest/test2")
	if rc != 2 || v["kind"] != "bad_arg" {
		t.Fatalf("non-wasm rc=%d kind=%v, want 2/bad_arg", rc, v["kind"])
	}
}

func r3le16(v uint16) []byte {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, v)
	return b
}

func r3le32(v uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return b
}

func r3uleb(s string) []byte {
	var b []byte
	n := len(s)
	for n >= 0x80 {
		b = append(b, byte(n)|0x80)
		n >>= 7
	}
	return append(append(b, byte(n)), s...)
}

func TestR3LNNMoveReaderOnSyntheticMagic(t *testing.T) {
	if !moveMatch([]byte{0xa1, 0x1c, 0xeb, 0x0b}, 0) {
		t.Fatal("moveMatch refused the real magic")
	}
	if moveMatch([]byte{0x0b, 0xeb, 0x1c, 0xa1}, 0) {
		t.Fatal("moveMatch accepted reversed magic")
	}
	// Minimal v5 module: header + one handle table + one identifier.
	handleOff := moveHeaderSize + 2*moveTableEntrySize
	identOff := handleOff + moveModuleHandleLen
	body := append([]byte{}, r3le16(0)...)
	body = append(body, r3le16(0)...)
	body = append(body, r3uleb("Foo")...)
	b := append([]byte{}, moveMagic...)
	b = append(b, r3le32(5)...)
	b = append(b, 2) // two table entries
	for _, e := range []struct {
		kind byte
		off  uint32
		cnt  uint32
	}{
		{moveTableModuleHandles, uint32(handleOff), 1},
		{moveTableIdentifiers, uint32(identOff), 1},
	} {
		b = append(b, e.kind)
		b = append(b, r3le32(e.off)...)
		b = append(b, r3le32(e.cnt)...)
	}
	b = append(b, body...)
	// Pad so identOff lies inside the file for the reader's bounds check.
	for len(b) < identOff+4 {
		b = append(b, 0)
	}
	p := filepath.Join(t.TempDir(), "sample.mv")
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	d, err := Probe(p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(d.Capabilities, ","), "move:magic=a11ceb0b") {
		t.Fatalf("capabilities=%v, want move magic", d.Capabilities)
	}
}

func r3w(mech string, off, ln int64) Witness {
	return Witness{Axis: mech, Class: mech, Value: mech + "@" + string(rune(off)), Start: off, End: off + ln}
}

func TestR3LNNWitnessGateAndConfidence(t *testing.T) {
	if g := witnessGap([]Witness{r3w("parser", 0, 4), r3w("sig", 8, 4)}); g != "" {
		t.Fatalf("valid witness set gap=%q", g)
	}
	if g := witnessGap([]Witness{r3w("parser", 0, 4)}); g != "witness-count" {
		t.Fatalf("gap=%q, want witness-count", g)
	}
	if g := witnessGap([]Witness{r3w("parser", 0, 4), r3w("parser", 8, 4)}); g != "witness-same-mech" {
		t.Fatalf("gap=%q, want witness-same-mech", g)
	}
	if g := witnessGap([]Witness{r3w("parser", 0, 8), r3w("sig", 4, 8)}); g != "witness-overlap" {
		t.Fatalf("gap=%q, want witness-overlap", g)
	}
	if confOf(2) != 2.0/3.0 || confOf(3) != 0.75 {
		t.Fatalf("confOf(2)=%v confOf(3)=%v", confOf(2), confOf(3))
	}
}

func TestR3LNNPlanRoutesLaneKinds(t *testing.T) {
	for kind, fixture := range map[string]string{
		"macho": "testdata/fixtures/macho",
		"elf":   "testdata/fixtures/elf",
		"pe":    "testdata/fixtures/pe.exe",
	} {
		d, err := Probe(fixture)
		if err != nil || d.Kind != kind {
			t.Fatalf("%s: kind=%q err=%v", fixture, d.Kind, err)
		}
		p := buildPlan(d, fixture)
		res, err := runOp(p.Op, fixture)
		if err != nil {
			t.Fatalf("%s planned op %q: %v", fixture, p.Op, err)
		}
		if res == nil {
			t.Fatalf("%s planned op %q returned nil", fixture, p.Op)
		}
	}
}

func TestR3LNNCloseBinaryHonestOnNoSession(t *testing.T) {
	// Isolate state: ~/.lrecon is shared and other tests write session.json
	// there, so an ambient assertion is flaky. An empty state dir must refuse,
	// never invent a closed session.
	t.Setenv("LRECON_STATE", t.TempDir())
	_, err := runCloseBinary("/Users/keremurhan/kalitetest/test1")
	if err == nil || !strings.Contains(err.Error(), "no session to close") {
		t.Fatalf("runCloseBinary err=%v, want no-session refusal", err)
	}
}
