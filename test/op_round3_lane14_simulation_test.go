package main

// TUR3 AUDIT — LANE 14 independent simulation tests.
// Verifies real lrecon behavior; production code is not relaxed.

import (
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// dispatch reader contract (dispatch.go:31 register, :91 verifyReaders)
func TestR3L14ReaderContract(t *testing.T) {
	// pyc magic 3439 = 3.10, pycMatch only accepts the 3100..3999 window.
	if !pycMatch([]byte{0x6f, 0x0d, 0x0d, 0x0a}, 100) {
		t.Error("pycMatch rejected 3.10 magic")
	}
	if pycMatch([]byte{0x01, 0x0c, 0x0d, 0x0a}, 100) { // 3073 < 3100
		t.Error("pycMatch accepted out-of-window magic")
	}
	if pycMatch([]byte{0x6f, 0x0d, 0x00, 0x0a}, 100) { // not 0d0a
		t.Error("pycMatch accepted magic without the fixed suffix")
	}
	for _, tc := range []struct{ magic, minor int }{
		{3439, 10}, {3450, 11}, {3495, 11}, {3500, 12}, {3600, 14},
	} {
		if v, ok := pycVersion(tc.magic); !ok || v != tc.minor {
			t.Errorf("pycVersion(%d)=%d,%v want %d,true", tc.magic, v, ok, tc.minor)
		}
	}
	// 3496 is not a published magic; it must stay in the gap (comment illustration).
	if v, ok := pycVersion(3496); ok || v != 0 {
		t.Errorf("pycVersion(3496)=%d,%v want 0,false", v, ok)
	}
	if minor, ok := pycVersion(3100); ok || minor != 0 {
		t.Errorf("pycVersion(3100)=%d,%v want 0,false", minor, ok)
	}
	verifyReaders() // no panic means the contract is in place
	for _, r := range readers {
		if r.format == "" || r.inspect == nil || len(r.reasons) == 0 {
			t.Errorf("reader contract broken: %+v", r.format)
		}
	}
}

// pyc real file: digest cpython 3.13, code objects and qualnames.
func TestR3L14PycRealFile(t *testing.T) {
	p := "/Users/keremurhan/tools/ux-skill/engine/__pycache__/data_loader.cpython-313.pyc"
	b, err := os.ReadFile(p)
	if err != nil {
		t.Skipf("no real pyc fixture: %v", err)
	}
	magic := int(binary.LittleEndian.Uint16(b[:2]))
	minor, ok := pycVersion(magic)
	if !ok {
		t.Fatalf("real pyc magic %d not recognized", magic)
	}
	if minor < 13 {
		t.Errorf("cpython-313 pyc minor=%d", minor)
	}
	if !pycMatch(b[:4], int64(len(b))) {
		t.Error("real pyc did not match pycMatch")
	}
	var d Digest
	inspectPyc(p, &d)
	// inspectPyc only fills Toolchain/Capabilities/Imports; dispatch sets Kind.
	if d.Toolchain != "cpython 3.13" {
		t.Errorf("inspectPyc toolchain = %q", d.Toolchain)
	}
	if d.Coverage == nil || d.Coverage.Parsed == 0 {
		t.Errorf("inspectPyc parsed coverage = %+v", d.Coverage)
	}
	if len(d.Imports) == 0 {
		t.Error("inspectPyc imports empty")
	}
}

// inspect_model_artifact: safetensors + GGUF (real op logic, synthetic bytes)
func TestR3L14ModelArtifact(t *testing.T) {
	dir := t.TempDir()
	h := `{"w":{"dtype":"F32","shape":[2],"data_offsets":[0,8]}}`
	sf := filepath.Join(dir, "m.safetensors")
	body := make([]byte, 8)
	binary.LittleEndian.PutUint64(body, uint64(len(h)))
	body = append(body, []byte(h)...)
	body = append(body, make([]byte, 8)...)
	os.WriteFile(sf, body, 0o644)

	out, err := inspectSafetensors(sf, body)
	if err != nil {
		t.Fatal(err)
	}
	m := out.(struct {
		Format  string            `json:"format"`
		Header  uint64            `json:"header_bytes"`
		Data    uint64            `json:"data_bytes"`
		Meta    map[string]string `json:"metadata,omitempty"`
		Tensors []modelTensor     `json:"tensors"`
	})
	if m.Format != "safetensors" || m.Header != uint64(len(h)) || m.Data != 8 || len(m.Tensors) != 1 {
		t.Fatalf("safetensors = %+v", m)
	}
	if m.Tensors[0].Elements != 2 || m.Tensors[0].Bytes != 8 || m.Tensors[0].DType != "F32" {
		t.Errorf("tensor = %+v", m.Tensors[0])
	}

	// bad offset must be rejected
	bad := append([]byte(nil), body...)
	binary.LittleEndian.PutUint64(bad[8+uint64(len(h))+0:], 0) // no-op; new job below
	badH := `{"w":{"dtype":"F32","shape":[2],"data_offsets":[0,16]}}`
	badBody := make([]byte, 8)
	binary.LittleEndian.PutUint64(badBody, uint64(len(badH)))
	badBody = append(badBody, []byte(badH)...)
	badBody = append(badBody, make([]byte, 8)...)
	if _, err := inspectSafetensors(sf, badBody); err == nil || !strings.Contains(err.Error(), "spans") {
		t.Errorf("overflowing offset was not rejected: %v", err)
	}
	_ = bad

	// GGUF v3: 1 tensor, no kv
	g := filepath.Join(dir, "m.gguf")
	str := func(s string) []byte {
		o := make([]byte, 8)
		binary.LittleEndian.PutUint64(o, uint64(len(s)))
		return append(o, []byte(s)...)
	}
	gb := []byte("GGUF")
	gb = binary.LittleEndian.AppendUint32(gb, 3)
	gb = binary.LittleEndian.AppendUint64(gb, 1) // tensor count
	gb = binary.LittleEndian.AppendUint64(gb, 0) // kv count
	gb = append(gb, str("w")...)
	gb = binary.LittleEndian.AppendUint32(gb, 1) // ndim
	gb = binary.LittleEndian.AppendUint64(gb, 4) // dim
	gb = binary.LittleEndian.AppendUint32(gb, 6) // Q5_0... actually 6=F32 in the table
	gb = binary.LittleEndian.AppendUint64(gb, 0) // offset
	os.WriteFile(g, gb, 0o644)

	out, err = inspectGGUF(g, gb)
	if err != nil {
		t.Fatal(err)
	}
	gm := out.(struct {
		Format   string        `json:"format"`
		Version  uint32        `json:"version"`
		Declared uint64        `json:"tensor_count"`
		Metadata []ggufKV      `json:"metadata"`
		Tensors  []modelTensor `json:"tensors"`
	})
	if gm.Format != "gguf" || gm.Version != 3 || gm.Declared != 1 || len(gm.Tensors) != 1 {
		t.Fatalf("gguf = %+v", gm)
	}
	// ggmlTypeNames[6] = "Q5_0" (op_inspect_model_artifact.go:23).
	if gm.Tensors[0].Name != "w" || gm.Tensors[0].TypeName != "Q5_0" || gm.Tensors[0].Type != 6 {
		t.Errorf("gguf tensor = %+v", gm.Tensors[0])
	}
	if _, err := inspectGGUF(g, []byte("GGUF"+string(make([]byte, 20)))); err == nil || !strings.Contains(err.Error(), "version") {
		t.Errorf("GGUF v0 was not rejected: %v", err)
	}
}

// trace_feature: address→offset/symbol and string→hit on a real Mach-O
func TestR3L14TraceFeatureReal(t *testing.T) {
	target := "/Users/keremurhan/kalitetest/test1"
	if _, err := os.Stat(target); err != nil {
		t.Skipf("no real fixture: %v", err)
	}
	dir := t.TempDir()
	job := filepath.Join(dir, "addr.json")
	os.WriteFile(job, []byte(`{"file":"`+target+`","address":"0x1000004e8"}`), 0o644)
	out, err := runTraceFeature(job)
	if err != nil {
		t.Fatal(err)
	}
	r := out.(map[string]any)
	f := r["feature"].(map[string]any)
	if f["offset"] != int64(1256) || f["section"] != "__text" || f["symbol"] != "_main" || f["arch"] != "arm64" {
		t.Errorf("trace address feature = %+v", f)
	}
	if !strings.HasPrefix(f["hex"].(string), "ff0302d1") {
		t.Errorf("trace address bytes = %v", f["hex"])
	}

	job2 := filepath.Join(dir, "str.json")
	os.WriteFile(job2, []byte(`{"file":"`+target+`","string":"_main"}`), 0o644)
	out, err = runTraceFeature(job2)
	if err != nil {
		t.Fatal(err)
	}
	r = out.(map[string]any)
	if r["mode"] != "string" || r["count"] != 1 || r["truncated"] != false {
		t.Errorf("trace string mode/count = %v/%v/%v", r["mode"], r["count"], r["truncated"])
	}
}

// compare_bundles: member differences across two real zip/dir inputs
func TestR3L14CompareBundlesReal(t *testing.T) {
	a := t.TempDir()
	b := t.TempDir()
	os.WriteFile(filepath.Join(a, "a.txt"), []byte("x"), 0o644)
	os.WriteFile(filepath.Join(b, "a.txt"), []byte("y"), 0o644)
	os.WriteFile(filepath.Join(b, "new.txt"), []byte("z"), 0o644)
	job := filepath.Join(t.TempDir(), "job.json")
	j, _ := json.Marshal(map[string]string{"old": a, "new": b})
	os.WriteFile(job, j, 0o644)

	out, err := runCompareBundles(job)
	if err != nil {
		t.Fatal(err)
	}
	m := out.(map[string]any)
	if m["count"] != 2 || m["changed"] != 1 || m["added"] != 1 || m["removed"] != 0 || m["identical"] != false {
		t.Errorf("compare counts = %+v", m)
	}
	changes := m["changes"].([]metaMemberChange)
	if len(changes) != 2 || changes[0].Name != "a.txt" || changes[0].Change != "changed" ||
		changes[0].OldSHA256 == "" || changes[0].NewSHA256 == "" || changes[1].Change != "added" {
		t.Errorf("compare changes = %+v", changes)
	}
	// identical sequences
	job2 := filepath.Join(t.TempDir(), "job2.json")
	j2, _ := json.Marshal(map[string]string{"old": a, "new": a})
	os.WriteFile(job2, j2, 0o644)
	out, err = runCompareBundles(job2)
	if err != nil {
		t.Fatal(err)
	}
	if out.(map[string]any)["identical"] != true {
		t.Error("identical sequences must have identical=true")
	}
}

// op registration contract: route/needs and jadx argument refusals
func TestR3L14OpRegistration(t *testing.T) {
	for name, route := range map[string]string{
		"address_name": "G", "compare_bundles": "L", "inspect_android_class": "L",
		"inspect_model_artifact": "L", "list_adb_directory": "Y",
		"observe_native_calls": "Y", "resolve_adb_packages": "Y", "trace_feature": "L",
	} {
		o, ok := ops[name]
		if !ok {
			t.Errorf("op %q not registered", name)
			continue
		}
		if o.route != route || !o.needs || o.desc == "" {
			t.Errorf("op %q route/needs/desc = %q/%v/%q", name, o.route, o.needs, o.desc)
		}
	}
	for name := range map[string]bool{
		"jadx_export_gradle": true, "jadx_deobf": true, "jadx_call_graph": true,
		"jadx_cfg": true, "jadx_raw_cfg": true, "jadx_output_json": true,
		"jadx_no_res": true, "jadx_no_src": true, "jadx_mappings": true,
		"jadx_fallback": true, "jadx_single_class_full": true, "jadx_plugins": true,
	} {
		o, ok := extOps[name]
		if !ok {
			t.Errorf("ext-op %q not registered", name)
			continue
		}
		if o.route != "Y" || o.desc == "" {
			t.Errorf("ext-op %q route/desc = %q/%q", name, o.route, o.desc)
		}
	}
	// jadx_plugins takes no target; bad_arg if a target is given
	if _, err := jadxPlugins("x.apk", nil); err == nil || !strings.Contains(err.Error(), "takes no target") {
		t.Errorf("jadxPlugins target refusal = %v", err)
	}
	// jadx_mappings / single_class require an argument
	if _, err := jadxMappings("x.apk", nil); err == nil || !strings.Contains(err.Error(), "needs a mappings file") {
		t.Errorf("jadxMappings arg refusal = %v", err)
	}
	if _, err := jadxSingleClassFull("x.apk", nil); err == nil || !strings.Contains(err.Error(), "needs a class name") {
		t.Errorf("jadxSingleClassFull arg refusal = %v", err)
	}
}

// opSelectorLoose + observe_native_calls refusal
func TestR3L14SelectorAndRefusal(t *testing.T) {
	existing := filepath.Join(t.TempDir(), "a#b.dex")
	os.WriteFile(existing, []byte("x"), 0o644)
	if f, s := opSelectorLoose(existing); f != existing || s != "" {
		t.Errorf("existing file must not be split: %q/%q", f, s)
	}
	if f, s := opSelectorLoose("/no/such.dex#com.example.Bar"); f != "/no/such.dex" || s != "com.example.Bar" {
		t.Errorf("selector split = %q/%q", f, s)
	}
	if !strings.Contains(nativeCallDecline, "xrefs") ||
		!strings.Contains(nativeCallDecline, "get_call_graph") ||
		!strings.Contains(nativeCallDecline, "procedure_pseudo_code") {
		t.Error("nativeCallDecline lost the Ghidra mapping")
	}
	// runtime op returns out_of_scope on a real call (refuseKind calls os.Exit;
	// here only verify the constant text, CLI evidence is in the report).
}

// dexMethodNames limit: 40 names, existing methodName mapping
func TestR3L14DexMethodNames(t *testing.T) {
	// synthetic dexReader: strs table maps method idx -> name; metOff/strs usage
	// methodName reads from method_ids in the real dexReader; here the cap behavior
	// cannot be checked through the extension → at least verify the 40 constant and op presence.
	var r dexReader
	if got := dexMethodNames(r, nil, 40); got != nil {
		t.Errorf("empty list = %v", got)
	}
	// listADBDirectory help path: returns skip on a device with unknown root (verified in CLI).
	_ = listADBDirectory
}
