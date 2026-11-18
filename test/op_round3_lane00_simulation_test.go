package main

// TUR3 AUDIT LANE00 — behavior simulation with the real lrecon binary.
// cliPath (cli_test.go TestMain) is built from the source tree; no fake/mock results.

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// r3l00RunIn runs the real binary inside dir (for bare relative targets).
func r3l00RunIn(t *testing.T, dir string, args ...string) (string, int) {
	t.Helper()
	if buildErr != nil {
		t.Fatalf("go build failed: %v\n%s", buildErr, buildLog)
	}
	cmd := exec.Command(cliPath, args...)
	cmd.Dir = dir
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	code := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			t.Fatalf("run %v: %v", args, err)
		}
	}
	return out.String(), code
}

func r3l00JSON(t *testing.T, s string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatalf("not JSON: %q\n%s", err, s)
	}
	return m
}

func r3l00Result(t *testing.T, s string) map[string]any {
	t.Helper()
	m := r3l00JSON(t, s)
	r, ok := m["result"].(map[string]any)
	if !ok {
		t.Fatalf("no result object: %s", s)
	}
	return r
}

const (
	r3l00Repo  = "/Users/keremurhan/walsyrea"
	r3l00Test1 = "/Users/keremurhan/kalitetest/test1"
	r3l00Pyc   = "testdata/fixtures/pyc/fixture_pyc.pyc"
	r3l00Beam  = "testdata/fixtures/beam/hello.beam"
	r3l00Asar  = "testdata/fixtures/electron/app.asar"
)

// Real identity: --version / --list-ops / --list-ext-ops counts.
func TestR3L00BinaryIdentity(t *testing.T) {
	out, code := runCLI(t, "--version")
	if code != 0 || !strings.Contains(out, "lrecon 1.0.0") {
		t.Fatalf("--version = %q rc=%d", out, code)
	}
	out, code = runCLI(t, "--list-ops")
	if code != 0 || len(strings.Split(strings.TrimSpace(out), "\n")) != 235 {
		t.Fatalf("--list-ops count != 235 (rc=%d)", code)
	}
	out, code = runCLI(t, "--list-ext-ops")
	if code != 0 || len(strings.Split(strings.TrimSpace(out), "\n")) != 80 {
		t.Fatalf("--list-ext-ops count != 80 (rc=%d)", code)
	}
}

// inspect_python_pyc: real .pyc success + macho refusal.
func TestR3L00InspectPythonPyc(t *testing.T) {
	out, code := runCLI(t, "--op", "inspect_python_pyc", "--json", r3l00Pyc)
	if code != 0 {
		t.Fatalf("pyc rc=%d: %s", code, out)
	}
	r := r3l00Result(t, out)
	if r["toolchain"] != "cpython 3.13" {
		t.Errorf("toolchain = %v", r["toolchain"])
	}
	q, _ := r["qualnames"].([]any)
	if len(q) == 0 {
		t.Errorf("qualnames empty: %s", out)
	}

	out, code = runCLI(t, "--op", "inspect_python_pyc", "--json", r3l00Test1)
	if code != 2 {
		t.Fatalf("macho pyc rc=%d, want 2: %s", code, out)
	}
	if k := r3l00JSON(t, out)["kind"]; k != "bad_arg" {
		t.Errorf("macho pyc kind = %v, want bad_arg", k)
	}
}

// inspect_erlang_beam: real BEAM success + macho refusal.
func TestR3L00InspectErlangBeam(t *testing.T) {
	out, code := runCLI(t, "--op", "inspect_erlang_beam", "--json", r3l00Beam)
	if code != 0 {
		t.Fatalf("beam rc=%d: %s", code, out)
	}
	r := r3l00Result(t, out)
	if r["atoms"] != float64(2) {
		t.Errorf("atoms = %v, want 2", r["atoms"])
	}
	out, code = runCLI(t, "--op", "inspect_erlang_beam", "--json", r3l00Test1)
	if code != 2 || r3l00JSON(t, out)["kind"] != "bad_arg" {
		t.Fatalf("macho beam rc=%d: %s", code, out)
	}
}

// project_apple_application_graph: real asar graph + macho refusal.
func TestR3L00ProjectAppleGraph(t *testing.T) {
	out, code := runCLI(t, "--op", "project_apple_application_graph", "--json", r3l00Asar)
	if code != 0 {
		t.Fatalf("asar graph rc=%d: %s", code, out)
	}
	r := r3l00Result(t, out)
	if r["node_count"] == nil || r["edge_count"] == nil {
		t.Errorf("no graph counts: %s", out)
	}
	nodes, _ := r["nodes"].([]any)
	found := false
	for _, n := range nodes {
		if nm, _ := n.(map[string]any); nm["kind"] == "asar" {
			found = true
		}
	}
	if !found {
		t.Errorf("no asar node in graph: %s", out)
	}
	out, code = runCLI(t, "--op", "project_apple_application_graph", "--json", r3l00Test1)
	if code != 2 || r3l00JSON(t, out)["kind"] != "bad_arg" {
		t.Fatalf("macho graph rc=%d: %s", code, out)
	}
}

// G ops: real Ghidra output on test1.
func TestR3L00GhidraOps(t *testing.T) {
	out, code := runCLI(t, "--op", "list_procedures", "--json", r3l00Test1)
	if code != 0 {
		t.Fatalf("list_procedures rc=%d: %s", code, out)
	}
	r := r3l00Result(t, out)
	if r["functions"] == nil || r["program"] != "test1" {
		t.Errorf("unexpected procedures: %s", out)
	}

	out, code = runCLI(t, "--op", "xrefs", "--json", r3l00Test1)
	if code != 2 || r3l00JSON(t, out)["kind"] != "needs_arg" {
		t.Fatalf("xrefs without LRECON_AT rc=%d: %s", code, out)
	}

	out, code = runCLI(t, "--op", "set_comment", "--json", r3l00Test1)
	if code != 2 || r3l00JSON(t, out)["kind"] != "needs_arg" {
		t.Fatalf("set_comment without job rc=%d: %s", code, out)
	}

	dir := t.TempDir()
	job := filepath.Join(dir, "job.json")
	if err := os.WriteFile(job, []byte(`{"file":"`+r3l00Test1+`","address":"0x1000004e8","text":"lane00 probe"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	out, code = runCLI(t, "--op", "set_comment", "--json", job)
	if code != 0 {
		t.Fatalf("set_comment job rc=%d: %s", code, out)
	}
	r = r3l00Result(t, out)
	if r["stored"] != "lane00 probe" {
		t.Errorf("comment not stored: %s", out)
	}
}

// capture_electron_scenario: real endpoint refusal.
func TestR3L00CaptureElectronScenario(t *testing.T) {
	out, code := runCLI(t, "--op", "capture_electron_scenario", "--json", r3l00Test1)
	if code != 2 || r3l00JSON(t, out)["kind"] != "bad_arg" {
		t.Fatalf("non-endpoint rc=%d: %s", code, out)
	}
}

// decode_signal_recording: bare relative meta + sibling dataset — real
// binary's DFT; traversal refusal is preserved. (TUR3 real bug fix.)
func TestR3L00DecodeSignalRecording(t *testing.T) {
	dir := t.TempDir()
	// Real cf32_le tone: 4096 samples, bin 410 → ~100 kHz @ 1 MHz.
	const n = 4096
	const bin = 410
	data := make([]byte, n*8)
	for i := range n {
		ph := 2 * math.Pi * bin * float64(i) / n
		binary.LittleEndian.PutUint32(data[i*8:], math.Float32bits(float32(math.Cos(ph))))
		binary.LittleEndian.PutUint32(data[i*8+4:], math.Float32bits(float32(math.Sin(ph))))
	}
	if err := os.WriteFile(filepath.Join(dir, "data.sigmf-data"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	meta := []byte(`{"global":{"core:datatype":"cf32_le","core:sample_rate":1000000,"core:dataset":"data.sigmf-data"},"captures":[],"annotations":[]}`)
	if err := os.WriteFile(filepath.Join(dir, "meta.sigmf-meta"), meta, 0o644); err != nil {
		t.Fatal(err)
	}

	// Bare relative target: old code incorrectly reported "escapes" here.
	out, code := r3l00RunIn(t, dir, "--op", "decode_signal_recording", "--json", "meta.sigmf-meta")
	if code != 0 {
		t.Fatalf("bare relative meta rc=%d: %s", code, out)
	}
	r := r3l00Result(t, out)
	if r["samples"] != float64(n) || r["dft_bins"] != float64(n) {
		t.Errorf("samples/bins = %v/%v, want %d/%d", r["samples"], r["dft_bins"], n, n)
	}
	if r["peak_measured"] != true {
		t.Errorf("peak not measured: %s", out)
	}
	if pk, _ := r["peak_hz"].(float64); math.Abs(pk-100000) > 5000 {
		t.Errorf("peak_hz = %v, want ~100000", pk)
	}

	// Traversal is still refused (no security regression).
	bad := []byte(`{"global":{"core:datatype":"cf32_le","core:sample_rate":1000000,"core:dataset":"../outside.sigmf-data"},"captures":[],"annotations":[]}`)
	if err := os.WriteFile(filepath.Join(dir, "bad.sigmf-meta"), bad, 0o644); err != nil {
		t.Fatal(err)
	}
	out, code = r3l00RunIn(t, dir, "--op", "decode_signal_recording", "--json", "bad.sigmf-meta")
	if code != 2 || !strings.Contains(out, "escapes the meta file's directory") {
		t.Fatalf("traversal rc=%d: %s", code, out)
	}
}

// asar digest: asar.go real read path (IPC / preload / capabilities).
func TestR3L00AsarDigest(t *testing.T) {
	out, code := runCLI(t, "--json", r3l00Asar)
	if code != 0 {
		t.Fatalf("asar digest rc=%d: %s", code, out)
	}
	d := r3l00JSON(t, out)
	if d["kind"] != "asar" {
		t.Errorf("kind = %v, want asar", d["kind"])
	}
	if d["asar_files"] != float64(8) {
		t.Errorf("asar_files = %v, want 8", d["asar_files"])
	}
	caps, _ := d["capabilities"].([]any)
	hasElectron := false
	for _, c := range caps {
		if strings.HasPrefix(c.(string), "preload-bridge:") {
			hasElectron = true
		}
	}
	if !hasElectron {
		t.Errorf("no preload-bridge capability: %v", caps)
	}
}

// ---- TUR5: gerçek davranış simülasyonları (pass-for-passing değil) ----

// apkSigningBlock: hata yolları gerçek bir blok inşa edilip bozularak sınanır.
func TestT5ApkSigningBlockRefusals(t *testing.T) {
	if _, _, err := apkSigningBlock([]byte("not a zip")); err == nil ||
		!strings.Contains(err.Error(), "no end-of-central-directory") {
		t.Fatalf("EOCD refused: %v", err)
	}

	// EOCD var ama central directory önünde imza bloğu yok.
	plain := make([]byte, 64)
	binary.LittleEndian.PutUint32(plain[42:], 0x06054b50)
	binary.LittleEndian.PutUint32(plain[58:], 40)
	if _, _, err := apkSigningBlock(plain); err == nil ||
		!strings.Contains(err.Error(), "no APK Signing Block") {
		t.Fatalf("magic refusal: %v", err)
	}

	// Geçerli blok; sonra başlık boyutu ayak iziyle uyuşmaz hale getirilir.
	pairs := binary.LittleEndian.AppendUint64(nil, 4)
	pairs = binary.LittleEndian.AppendUint32(pairs, 0x7109871a)
	size := len(pairs) + 8 + 16
	cdOff := size + 8
	b := make([]byte, cdOff+2+22)
	binary.LittleEndian.PutUint64(b[0:], uint64(size))
	copy(b[8:], pairs)
	binary.LittleEndian.PutUint64(b[cdOff-24:], uint64(size))
	copy(b[cdOff-16:], apkSigBlockID)
	binary.LittleEndian.PutUint32(b[cdOff+2:], 0x06054b50)
	binary.LittleEndian.PutUint32(b[cdOff+18:], uint32(cdOff))
	if _, _, err := apkSigningBlock(b); err != nil {
		t.Fatalf("valid block: %v", err)
	}
	binary.LittleEndian.PutUint64(b[0:], uint64(size+8))
	if _, _, err := apkSigningBlock(b); err == nil ||
		!strings.Contains(err.Error(), "disagrees with footer") {
		t.Fatalf("header/footer mismatch: %v", err)
	}
}

// metaBTree: yaprak çiftleri gerçek blok engelinden okunur; döngü reddedilir.
func TestT5MetaBTreeLeafWalkAndCycle(t *testing.T) {
	tree := make([]byte, 24)
	copy(tree, "tree")
	binary.BigEndian.PutUint32(tree[8:], 2)
	node := make([]byte, 28)
	binary.BigEndian.PutUint16(node[0:], 1) // leaf
	binary.BigEndian.PutUint16(node[2:], 2)
	for i, pair := range [][2]uint32{{10, 20}, {11, 21}} {
		binary.BigEndian.PutUint32(node[12+8*i:], pair[0])
		binary.BigEndian.PutUint32(node[16+8*i:], pair[1])
	}
	blobs := map[uint32][]byte{1: tree, 2: node, 10: {}, 11: {}, 20: {}, 21: {}}
	block := func(id uint32) ([]byte, error) {
		b, ok := blobs[id]
		if !ok {
			return nil, fmt.Errorf("block %d missing", id)
		}
		return b, nil
	}
	got, err := metaBTree(block, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != (metaBPair{value: 10, key: 20}) ||
		got[1] != (metaBPair{value: 11, key: 21}) {
		t.Fatalf("leaf pairs = %+v", got)
	}

	// Kök düğümü kendisine işaret ederse yürüyüş döngüyü yakalamalı.
	cycleTree := make([]byte, 24)
	copy(cycleTree, "tree")
	binary.BigEndian.PutUint32(cycleTree[8:], 4)
	cycleNode := make([]byte, 20)
	binary.BigEndian.PutUint16(cycleNode[2:], 1) // 1 child
	binary.BigEndian.PutUint32(cycleNode[12:], 3)
	cycleBlobs := map[uint32][]byte{3: cycleTree, 4: cycleNode}
	cycleBlock := func(id uint32) ([]byte, error) {
		b, ok := cycleBlobs[id]
		if !ok {
			return nil, fmt.Errorf("block %d missing", id)
		}
		return b, nil
	}
	if _, err := metaBTree(cycleBlock, 3); err == nil ||
		!strings.Contains(err.Error(), "tree revisits block 3") {
		t.Fatalf("cycle: %v", err)
	}
}

// trace_web_source_location: gerçek bir .map dosyası op seviyesinde çözülür.
func TestT5TraceWebSourceLocationRealMap(t *testing.T) {
	dir := t.TempDir()
	mapPath := filepath.Join(dir, "app.js.map")
	body := `{"version":3,"sources":["a.js","b.js"],"names":["foo"],"mappings":"AAAA;AACA,ACAA"}`
	if err := os.WriteFile(mapPath, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := opTraceWebSourceLocation(mapPath)
	if err != nil {
		t.Fatal(err)
	}
	m, ok := got.(sourceLocationMap)
	if !ok {
		t.Fatalf("result type %T", got)
	}
	if m.Version != 3 || m.Map != "app.js.map" || m.Segments != 3 ||
		!reflect.DeepEqual(m.Sources, []string{"a.js", "b.js"}) || m.Truncated {
		t.Fatalf("map meta = %+v", m)
	}
	if m.PerSource["a.js"] != 2 || m.PerSource["b.js"] != 1 {
		t.Fatalf("perSource = %v", m.PerSource)
	}
	if len(m.Rows) != 3 || m.Rows[0].GenLine != 1 || m.Rows[1].GenLine != 2 ||
		m.Rows[2].GenLine != 2 || m.Rows[2].Source != "b.js" {
		t.Fatalf("rows = %+v", m.Rows)
	}
}

// reconcile: eşleşen script yoksa status "no-matching-script" olur.
func TestT5ReconcileNoMatchingScript(t *testing.T) {
	bundle := writeTemp(t, "bundle.js", []byte("exports.foo = function() {}\n"))
	fakeDriver(t, webOut{
		Steps: []webStepResult{
			okStep("Debugger.enable", map[string]any{}),
			okStep("Runtime.enable", map[string]any{}),
			okStep("Runtime.evaluate", map[string]any{"result": map[string]any{"value": []any{}}}),
		},
		Events: []webEvent{event("Debugger.scriptParsed", map[string]any{
			"scriptId": "1", "url": "eval://1"})},
	})
	res, err := opReconcileJavascriptRuntime("127.0.0.1:9222=" + bundle)
	if err != nil {
		t.Fatal(err)
	}
	r, ok := res.(reconcileReport)
	if !ok {
		t.Fatalf("result type %T", res)
	}
	if r.Status != "no-matching-script" || r.Parsed != 1 || !r.Evaluated ||
		len(r.Matched) != 0 || len(r.RuntimeOnly) != 1 || len(r.DiskOnly) != 1 ||
		r.DiskOnly[0].Name != "foo" {
		t.Fatalf("reconcile = %+v", r)
	}
}

// get_evidence_bundle: kap aşımında tüm çıktı temp dosyaya taşır.
func TestT5CapEvidenceBundleSpillsWhole(t *testing.T) {
	t.Setenv("LRECON_BUNDLE_CAP_BYTES", "32")
	out := map[string]any{
		"verified": true, "bundle_sha256": "abc",
		"payload": strings.Repeat("x", 128),
	}
	got, err := capEvidenceBundle(out)
	if err != nil {
		t.Fatal(err)
	}
	m, ok := got.(map[string]any)
	if !ok || m["incomplete"] != false || m["coverage"] != "complete-in-file" ||
		m["cap_bytes"] != 32 || m["bundle_sha256"] != "abc" {
		t.Fatalf("spilled map = %+v", m)
	}
	dst, _ := m["written_to"].(string)
	if dst == "" || !strings.HasPrefix(filepath.Base(dst), "lrecon-bundle-") {
		t.Fatalf("written_to = %q, want lrecon-bundle-* temp", dst)
	}
	defer os.Remove(dst)
	b, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	var saved map[string]any
	if err := json.Unmarshal(b, &saved); err != nil || saved["payload"] != out["payload"] {
		t.Fatalf("spilled file = %q, err=%v", b, err)
	}
	if m["bytes"] != len(b) {
		t.Fatalf("bytes = %v, want %d", m["bytes"], len(b))
	}
}
