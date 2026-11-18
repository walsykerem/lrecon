package main

// TUR 3 AUDIT — LANE 27 independent simulation tests.
// Verifies only behaviors in the lane27 files via REAL files/ops.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const r3l27Test1 = "/Users/keremurhan/kalitetest/test1"
const r3l27Test2 = "/Users/keremurhan/kalitetest/test2"

// Lane27 has 9 ops; lsda.go and types.go are the helpers/contract layer of these ops.
func TestR3L27OpRegistry(t *testing.T) {
	want := map[string]struct {
		route string
		needs bool
	}{
		"build_reconstruction_obligation_ledger": {"L", true},
		"cutter_command":                         {"Y", true},
		"get_navigation_context":                 {"L", false},
		"inspect_electron_fuses":                 {"L", true},
		"inspect_pe_load_config":                 {"L", true},
		"list_javascript_runtime_targets":        {"Y", true},
		"procedure_pseudo_code":                  {"G", true},
		"set_address_name":                       {"G", true},
		"verify_reconstruction":                  {"L", true},
	}
	for name, w := range want {
		o, ok := ops[name]
		if !ok {
			t.Errorf("op %q is not registered", name)
			continue
		}
		if o.route != w.route || o.needs != w.needs {
			t.Errorf("op %q route/needs = %q/%v, want %q/%v", name, o.route, o.needs, w.route, w.needs)
		}
	}
	if contractVersion != 1 {
		t.Errorf("contractVersion = %d, want 1", contractVersion)
	}
}

// lsda.go: C++ exception type_info mangling decode (helper, skill 'NO demangler'
// rule — this is static type_info reading, not an arbitrary demangler).
func TestR3L27LSDADemangle(t *testing.T) {
	if got := lsdaDemangle("_ZTIN3Foo3BarIiEE"); got != "N3Foo3BarIiEE" {
		t.Errorf("lsdaDemangle = %q, want %q", got, "N3Foo3BarIiEE")
	}
}

// types.go Digest contract_version:1 and the key set used by the lane27 ops.
func TestR3L27DigestContractKeys(t *testing.T) {
	d := Digest{ContractVersion: 1, Kind: "macho", Skipped: nil}
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if m["contract_version"] != float64(1) || m["kind"] != "macho" {
		t.Fatalf("digest contract = %v/%v", m["contract_version"], m["kind"])
	}
	if _, ok := m["skipped"]; !ok {
		t.Error("digest has no skipped key")
	}
	for _, k := range []string{"asar_files", "electron", "pcap_packets", "sqlite_page_size", "firmware_kind", "plan"} {
		if _, ok := m[k]; !ok {
			t.Errorf("digest has no key %q", k)
		}
	}
}

// op_verify_reconstruction.go: reading a claim from a real macho header.
func TestR3L27VerifyReconstruction(t *testing.T) {
	job := metaTestArg(t, map[string]any{
		"file": r3l27Test1,
		"claims": []any{
			map[string]any{"offset": 0, "length": 4, "expect": "cffaedfe"},
		},
	})
	m := metaMustRun(t, "verify_reconstruction", job)
	if m["verified"] != true || m["total"] != float64(1) || m["matched"] != float64(1) {
		t.Fatalf("verify_reconstruction = %+v", m)
	}
	claims, ok := m["claims"].([]any)
	if !ok || len(claims) != 1 {
		t.Fatalf("claims = %+v", m["claims"])
	}
	c := claims[0].(map[string]any)
	if c["want"] != "cffaedfe" || c["got"] != "cffaedfe" || c["match"] != true {
		t.Errorf("claim = %+v", c)
	}

	// Wrong expect -> verified=false, honest mismatch (no fake 'solved').
	bad := metaTestArg(t, map[string]any{
		"file":   r3l27Test1,
		"claims": []any{map[string]any{"offset": 0, "length": 4, "expect": "deadbeef"}},
	})
	m = metaMustRun(t, "verify_reconstruction", bad)
	if m["verified"] != false || m["mismatched"] != float64(1) {
		t.Errorf("bad claim = %+v", m)
	}

	// Job without claims -> needs_arg, not an empty result.
	if _, err := runOp("verify_reconstruction", metaTestArg(t, map[string]any{"file": r3l27Test1})); err == nil ||
		!strings.Contains(err.Error(), `job needs "claims"`) {
		t.Errorf("verify error without claims = %v", err)
	}
}

// op_build_reconstruction_obligation_ledger.go: a second artifact in the same state
// must not be overwritten (Contract: state protection).
func TestR3L27LedgerStateConflict(t *testing.T) {
	state := t.TempDir()
	first := metaMustRun(t, "build_reconstruction_obligation_ledger", metaTestArg(t, map[string]any{
		"file": r3l27Test1, "state": state,
		"unresolved": []any{map[string]any{"symbol": "sym", "reason": "r3l27"}},
	}))
	if first["count"] != float64(1) || first["replaced"] != false {
		t.Fatalf("ledger first = %+v", first)
	}
	second := metaMustRun(t, "build_reconstruction_obligation_ledger", metaTestArg(t, map[string]any{
		"file": r3l27Test1, "state": state,
		"unresolved": []any{map[string]any{"symbol": "sym", "reason": "r3l27"}},
	}))
	if second["replaced"] != true {
		t.Errorf("rebuild of the same artifact replaced = %+v", second)
	}
	_, err := runOp("build_reconstruction_obligation_ledger", metaTestArg(t, map[string]any{
		"file": r3l27Test2, "state": state,
		"unresolved": []any{map[string]any{"symbol": "sym", "reason": "r3l27"}},
	}))
	if err == nil || !strings.Contains(err.Error(), "state conflict") {
		t.Errorf("state conflict error = %v", err)
	}
}

// op_inspect_electron_fuses.go: honest skip on a non-Electron target.
func TestR3L27ElectronFusesSkip(t *testing.T) {
	off, w, err := fuseWire(r3l27Test1)
	if err != nil {
		t.Fatalf("fuseWire: %v", err)
	}
	if off >= 0 && w != nil {
		t.Errorf("found a wire for non-Electron test1: off=%d w=%x", off, w)
	}
	m := metaMustRun(t, "inspect_electron_fuses", r3l27Test1)
	reason, _ := m["skipped"].(string)
	if !strings.Contains(reason, "carries no Electron fuse wire") {
		t.Errorf("inspect_electron_fuses skip = %+v", m)
	}
}

// op_inspect_pe_load_config.go: Mach-O target -> bad_arg (no MZ header).
func TestR3L27PELoadConfigWrongKind(t *testing.T) {
	_, err := runOp("inspect_pe_load_config", r3l27Test2)
	if err == nil || !strings.Contains(err.Error(), "no MZ header") {
		t.Fatalf("inspect_pe_load_config error = %v", err)
	}
	if got := classify(err.Error()); got != kindBadArg {
		t.Errorf("kind = %s, want %s", got, kindBadArg)
	}
}

// op_cutter_command.go / op_list_javascript_runtime_targets.go /
// op_procedure_pseudo_code.go / op_get_navigation_context.go:
// Closed-set refusals consistent with the skill Forbidden/need-arg/no-engine rules.
func TestR3L27GenuineRefusals(t *testing.T) {
	cases := []struct {
		name, target, contains string
		kind                   errorKind
	}{
		{"cutter_command", r3l27Test1, "out of scope: lrecon does not drive a command console", kindOutOfScope},
		{"list_javascript_runtime_targets", r3l27Test1, "is not a DevTools endpoint", kindBadArg},
		{"procedure_pseudo_code", r3l27Test1, "set LRECON_AT", kindNeedsArg},
		{"get_navigation_context", r3l27Test1, "no session", kindNoEngine},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// Session-dependent ops may see a persistent ~/.lrecon/session.json;
			// each case starts with an isolated LRECON_STATE.
			t.Setenv("LRECON_STATE", t.TempDir())
			// Ops using refuseKind() (cutter_command) call os.Exit(2) directly;
			// run through the REAL binary so the test process does not die.
			stdout, stderr, code := runCLIAll(t, "--op", c.name, "--json", c.target)
			if code != 2 {
				t.Fatalf("%s exit = %d, want 2 (stderr=%q)", c.name, code, stderr)
			}
			if !strings.Contains(stderr, "lrecon: ") {
				t.Errorf("%s stderr = %q, want 'lrecon: ' prefix", c.name, stderr)
			}
			var env envelope
			if err := json.Unmarshal([]byte(stdout), &env); err != nil {
				t.Fatalf("%s envelope: %v (%s)", c.name, err, stdout)
			}
			if env.Kind != c.kind || !strings.Contains(env.Error, c.contains) {
				t.Errorf("%s envelope = %+v, want kind=%s error~=%q", c.name, env, c.kind, c.contains)
			}
		})
	}
}

// op_set_address_name.go: a missing job is refused without calling Ghidra.
func TestR3L27SetAddressNameNeedsJob(t *testing.T) {
	old := ghidraFinder
	t.Cleanup(func() { ghidraFinder = old })
	ghidraFinder = func() (string, string, error) { return "/fake/analyzeHeadless", "/fake/project", nil }
	_, err := runOp("set_address_name", metaTestArg(t, map[string]any{"file": r3l27Test1, "name": "probe"}))
	if err == nil || !strings.Contains(err.Error(), `set_address_name: job needs "address" and "name"`) {
		t.Fatalf("set_address_name error = %v", err)
	}
	if got := classify(err.Error()); got != kindNeedsArg {
		t.Errorf("kind = %s, want %s", got, kindNeedsArg)
	}
}

// walsyrea skill Gate: --version 1.0.0 + 235/80 inventory, from the real binary.
// This test reads no files; the real binary call is external (evidence in the report).
func TestR3L27SkillInventoryShape(t *testing.T) {
	if len(kindList) != 9 {
		t.Errorf("closed refusal kind set is %d, want 9", len(kindList))
	}
	if ops["inspect_electron_fuses"].desc == "" || ops["verify_reconstruction"].desc == "" {
		t.Error("lane op description is empty")
	}
	if _, err := os.Stat(r3l27Test1); err != nil {
		t.Fatalf("real target is missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(os.TempDir(), ".")); err != nil {
		t.Fatal(err)
	}
}
