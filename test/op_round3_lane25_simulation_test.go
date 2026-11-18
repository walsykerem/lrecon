package main

// TUR 3 audit, lane 25: simulation tests on real artifacts.
// Production code is not relaxed; each test exercises a real path with meaningful input.

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	r3l25Test1 = "/Users/keremurhan/kalitetest/test1"
	r3l25Test2 = "/Users/keremurhan/kalitetest/test2"
	r3l25Own   = "/Users/keremurhan/walsyrea/lrecon/lrecon"
)

func r3l25Op(t *testing.T, name, path string) map[string]any {
	t.Helper()
	v, err := runOp(name, path)
	if err != nil {
		t.Fatalf("%s(%s): %v", name, path, err)
	}
	b, _ := json.Marshal(v)
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if r := m["result"]; r != nil {
		if rm, ok := r.(map[string]any); ok {
			return rm
		}
	}
	return m
}

// java.go: class magic/version distinction and constant pool on a real byte array.
func TestR3L25JavaReader(t *testing.T) {
	b := classBytes("Fixture", 65, 0x0021)
	if !javaMatch(b, int64(len(b))) {
		t.Fatal("valid class header rejected")
	}
	if v := javaVersion(65); v != "java 21" {
		t.Fatalf("javaVersion(65)=%q", v)
	}
	if v := javaVersion(48); v != "jdk 1.4" {
		t.Fatalf("javaVersion(48)=%q", v)
	}
	// A real Mach-O header must not be mistaken for a class.
	if head, err := os.ReadFile(r3l25Test1); err != nil || javaMatch(head[:min(16, len(head))], int64(len(head))) {
		t.Fatalf("Mach-O mistaken for a class: %v", err)
	}
	names, classes, _, ok := javaConstantPool(b, 5)
	if !ok || names[1] != "Fixture" || names[3] != "java/lang/Object" || classes[2] != 1 || classes[4] != 3 {
		t.Fatalf("constant pool: ok=%v names=%v classes=%v", ok, names, classes)
	}
	p := writeTemp(t, "Fixture.class", b)
	if got, err := readJavaFile(p); err != nil || len(got) != len(b) {
		t.Fatalf("readJavaFile: %v", err)
	}
	if !javaMatch(classBytes("Mod", 53, javaACCModule), int64(len(classBytes("Mod", 53, javaACCModule)))) {
		t.Fatal("module class header rejected")
	}
}

// swiftfield.go: post-reader constants and host kind are preserved, no false claims.
func TestR3L25SwiftFieldPostReader(t *testing.T) {
	if swiftFieldAbsent != "swiftfield-absent" || swiftFieldDescriptorUnreadable == "" ||
		swiftFieldTyperefOutsideTypes == "" || swiftFieldReflstrMissing == "" ||
		swiftFieldNameOutsideReflstr == "" || swiftFieldLayoutUnknown == "" {
		t.Fatal("swiftfield reason constants empty")
	}
	d, err := Probe(r3l25Test1)
	if err != nil || d.Kind != "macho" {
		t.Fatalf("Probe(test1): kind=%q err=%v", d.Kind, err)
	}
}

// binary_session: adapter opens on a real file, session is written.
func TestR3L25BinarySessionReal(t *testing.T) {
	m := r3l25Op(t, "binary_session", r3l25Test1)
	if m["adapter"] != "macho" || m["adapter_ok"] != true {
		t.Fatalf("binary_session: %v", m)
	}
	if m["session_persisted"] != true || m["state"] != "opened" && m["state"] != "reopened" {
		t.Fatalf("session: %v", m)
	}
	if name, ok, _ := sessionAdapter(r3l25Test1); !ok || name != "macho" {
		t.Fatalf("sessionAdapter=%q %v", name, ok)
	}
}

// current_document: session cursor resolves against the real function table.
func TestR3L25CurrentDocumentReal(t *testing.T) {
	r3l25Op(t, "binary_session", r3l25Test1)
	m := r3l25Op(t, "current_document", r3l25Test1)
	if m["document"] != r3l25Test1 || m["size"] != float64(33640) || m["documents"] == nil {
		t.Fatalf("current_document: %v", m)
	}
}

// get_call_graph: real Ghidra graph, different edge counts on two targets.
func TestR3L25GetCallGraphReal(t *testing.T) {
	for path, wantEdges := range map[string]float64{r3l25Test1: 7, r3l25Test2: 6} {
		m := r3l25Op(t, "get_call_graph", path)
		if m["arch"] != "arm64" || m["functions"] != float64(7) || m["edges"] != wantEdges {
			t.Fatalf("%s: %v", path, m)
		}
		if !strings.Contains(fmt.Sprint(m["ghidra_version"]), "12.1.4") {
			t.Fatalf("ghidra_version: %v", m["ghidra_version"])
		}
	}
}

// procedure_callers: needs_arg without an argument, real symbol reaches Ghidra.
func TestR3L25ProcedureCallersReal(t *testing.T) {
	if _, err := runOp("procedure_callers", r3l25Test1); err == nil || !strings.Contains(err.Error(), "LRECON_AT") {
		t.Fatalf("procedure_callers needs_arg refusal: %v", err)
	}
	t.Setenv("LRECON_NAME", "entry")
	m := r3l25Op(t, "procedure_callers", r3l25Test1)
	if m["function"] != "entry" || m["count"] != float64(0) {
		t.Fatalf("procedure_callers: %v", m)
	}
}

// search_procedures: needs_arg without an argument, two functions in the real pattern.
func TestR3L25SearchProceduresReal(t *testing.T) {
	if _, err := runOp("search_procedures", r3l25Test1); err == nil || !strings.Contains(err.Error(), "LRECON_PATTERN") {
		t.Fatalf("search_procedures needs_arg refusal: %v", err)
	}
	t.Setenv("LRECON_PATTERN", "FUN")
	m := r3l25Op(t, "search_procedures", r3l25Test1)
	if m["matches"] != float64(2) || m["pattern"] != "FUN" {
		t.Fatalf("search_procedures: %v", m)
	}
}

// L ops: honest refusal on an unsuitable real file, real device in Frida.
func TestR3L25HonestRefusalsAndFrida(t *testing.T) {
	// The op layer returns a correct refusal as {"skipped": "..."}, not as an error;
	// the CLI turns it into bad_arg in the stdout envelope (real CLI evidence also obtained).
	dm := r3l25Op(t, "inspect_desktop_application", r3l25Test1)
	if s := dm["skipped"]; s == nil || !strings.Contains(fmt.Sprint(s), "not a desktop app bundle or Electron asar") {
		t.Fatalf("desktop app skip: %v", dm)
	}
	if _, err := runOp("inspect_pe_certificates", r3l25Test1); err == nil || !strings.Contains(err.Error(), "no MZ header") {
		t.Fatalf("PE certificate refusal: %v", err)
	}
	m := r3l25Op(t, "list_frida_devices", r3l25Test1)
	if m["count"] != float64(1) {
		t.Fatalf("list_frida_devices: %v", m)
	}
	devices, ok := m["devices"].([]any)
	if !ok || len(devices) != 1 {
		t.Fatalf("devices: %v", m["devices"])
	}
}

// verify ops: immutability and equivalence decisions using the real file's SHA.
func TestR3L25AdversarialVerifyReal(t *testing.T) {
	b, err := os.ReadFile(r3l25Test1)
	if err != nil {
		t.Fatal(err)
	}
	sha := fmt.Sprintf("%x", sha256.Sum256(b))
	dir := t.TempDir()

	imm := filepath.Join(dir, "imm.json")
	if err := os.WriteFile(imm, []byte(`{"file":"`+r3l25Test1+`","expect":"`+sha+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	m := r3l25Op(t, "verify_target_immutability", imm)
	if m["match"] != true || m["mutated"] != false || m["hash_scope"] != "whole-file" || m["target_sha256"] != sha {
		t.Fatalf("immutability: %v", m)
	}

	eq := filepath.Join(dir, "eq.json")
	if err := os.WriteFile(eq, []byte(`{"old":"`+r3l25Test1+`","new":"`+r3l25Test1+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if m = r3l25Op(t, "verify_output_equivalence", eq); m["equivalent"] != true {
		t.Fatalf("equivalence same: %v", m)
	}

	div := filepath.Join(dir, "div.json")
	if err := os.WriteFile(div, []byte(`{"old":"`+r3l25Test1+`","new":"`+r3l25Test2+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	m = r3l25Op(t, "verify_output_equivalence", div)
	if m["equivalent"] != false || !strings.Contains(fmt.Sprint(m["notes"]), "equivalence-diverged") {
		t.Fatalf("equivalence diverge: %v", m)
	}
}

// Contract: lane25 ops registered, routes consistent, total op count 235.
func TestR3L25RegisteredOpsAndContract(t *testing.T) {
	for name, want := range map[string]string{
		"binary_session": "L", "current_document": "L",
		"inspect_desktop_application": "L", "inspect_pe_certificates": "L",
		"verify_target_immutability": "L", "verify_output_equivalence": "L",
		"list_frida_devices": "Y",
		"get_call_graph":     "G", "procedure_callers": "G", "search_procedures": "G",
	} {
		o, ok := ops[name]
		if !ok {
			t.Fatalf("op not registered: %s", name)
		}
		if o.route != want {
			t.Fatalf("%s route=%q want %q", name, o.route, want)
		}
	}
	if len(ops) != 235 {
		t.Fatalf("op count %d (expected 235)", len(ops))
	}
}
