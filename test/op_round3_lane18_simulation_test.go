package main

// TUR3 lane18: skill-interaction sim tests. 11 source files; real binary
// behavior verified with TUR3_COMMON.md simulation evidence. Production code is unchanged.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func r3l18JSON(t *testing.T, v any) map[string]any {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

const (
	r3l18Test1  = "/Users/keremurhan/kalitetest/test1"
	r3l18Lrecon = "/Users/keremurhan/walsyrea/lrecon/lrecon"
	r3l18ELF    = "testdata/fixtures/cxx/vtables.o"
	r3l18UBI    = "testdata/fixtures/ubi/flash-ubi.img"
)

// Skill op-index.md routes: lane18 ops must be registered on the correct route.
func TestR3L18OpsRegisteredRoutes(t *testing.T) {
	want := map[string]string{
		"analyze_swift_types":      "L",
		"compare_process_captures": "L",
		"extract_firmware":         "L",
		"inspect_native_exports":   "L",
		"open_binary":              "L",
		"trace_web_module_imports": "L",
		"inspect_apktool_client":   "Y",
		"list_adb_services":        "Y",
		"rizin_debug_command":      "Y",
	}
	for name, route := range want {
		o, ok := ops[name]
		if !ok {
			t.Fatalf("op %q not registered", name)
		}
		if o.route != route {
			t.Fatalf("op %q route = %q, want %q", name, o.route, route)
		}
		if o.run == nil || o.desc == "" {
			t.Fatalf("op %q missing run/desc", name)
		}
	}
}

// evm.go: evmTrailerPlausible last 2 bytes big-endian length + 4 KiB cap.
func TestR3L18EvmTrailerAndArg(t *testing.T) {
	meta := evmTestMeta([]byte{0x00, 0x08, 0xc0})
	bin := evmTestBin(evmTestCode, meta)
	if !evmTrailerPlausible(bin) {
		t.Fatal("evmTrailerPlausible rejected a hand-built valid trailer")
	}
	if evmTrailerPlausible([]byte{0x60, 0x80, 0x00}) {
		t.Fatal("evmTrailerPlausible accepted junk")
	}
	// ai == 26 = 4-byte uint (b[off+1:off+5]); must refuse values exceeding evmMaxMeta (0x1000).
	if _, _, ok := evmArg([]byte{0x00, 0x00, 0x10, 0x00, 0x01}, 0, 26); ok {
		t.Fatal("evmArg accepted a value above evmMaxMeta")
	}
	if n, size, ok := evmArg([]byte{0x00, 0x00, 0x00, 0x00, 0x02}, 0, 26); !ok || n != 2 || size != 5 {
		t.Fatalf("evmArg in-range = %d,%d,%v", n, size, ok)
	}
}

// roles.go: RoleOf / updater caps / DiffDigests basic contract.
func TestR3L18RolesContract(t *testing.T) {
	for in, want := range map[string]string{
		"libcrypto.dylib": "crypto", "socket": "network",
		"SecTrustEvaluate": "codesign", "frida-agent.dylib": "instrumentation",
	} {
		if got := RoleOf(in); got != want {
			t.Fatalf("RoleOf(%q) = %q, want %q", in, got, want)
		}
	}
	var d Digest
	AddUpdaterCapsFrom(&d, []string{"electron-updater", "github.com/x/tuf", "future"})
	joined := strings.Join(d.Capabilities, ",")
	for _, c := range []string{"updater:electron-updater", "updater:tuf"} {
		if !strings.Contains(joined, c) {
			t.Fatalf("caps = %v, want %s", d.Capabilities, c)
		}
	}
	if strings.Contains(joined, "future") {
		t.Fatalf("caps = %v, false-positive tuf", d.Capabilities)
	}
	if got := DiffDigests(Digest{Kind: "macho"}, Digest{Kind: "elf"}); len(got) == 0 {
		t.Fatal("DiffDigests missed kind change")
	}
}

// op_open_binary.go: stateless handle "none", identity fields filled (real binary).
func TestR3L18OpenBinaryIdentity(t *testing.T) {
	for _, path := range []string{r3l18Test1, r3l18Lrecon, r3l18ELF} {
		got, err := ops["open_binary"].run(path)
		if err != nil {
			t.Fatalf("open_binary(%s): %v", path, err)
		}
		m := r3l18JSON(t, got)
		if m["handle"] != "none" || m["hash_scope"] != "whole-file" {
			t.Fatalf("open_binary(%s) = %v", path, m)
		}
		for _, k := range []string{"kind", "format", "sha256", "gitoid", "size", "binary_size"} {
			if m[k] == nil || m[k] == "" {
				t.Fatalf("open_binary(%s) missing %s", path, k)
			}
		}
	}
}

// op_analyze_swift_types.go: vaReader can be built for real Mach-O/ELF;
// reading starts from a section VA (VA 0 is not always inside a section).
func TestR3L18VaReaderRealBinaries(t *testing.T) {
	for _, path := range []string{r3l18Test1, r3l18Lrecon, r3l18ELF} {
		rd, err := vaReader(path, 0)
		if err != nil {
			t.Fatalf("vaReader(%s): %v", path, err)
		}
		if rd == nil {
			t.Fatalf("vaReader(%s) gave nil reader", path)
		}
	}
}

// op_compare_process_captures.go: real capture files produce join + diff.
func TestR3L18CompareProcessCapturesReal(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.json")
	b := filepath.Join(dir, "b.json")
	if err := os.WriteFile(a, []byte(`{"foo":[1,2],"onlyA":[3]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(b, []byte(`{"foo":[1,9],"onlyB":[4]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := compareProcessCaptures(a + "," + b)
	if err != nil {
		t.Fatal(err)
	}
	d, ok := got.(rtCaptureDiff)
	if !ok {
		t.Fatalf("compareProcessCaptures type = %T", got)
	}
	if len(d.Changed) != 1 || len(d.OnlyInFirst) != 1 || len(d.OnlyInSecond) != 1 {
		t.Fatalf("capture diff = %+v", d)
	}
	if d.Changed[0].Symbol != "foo" || d.Unchanged != 0 {
		t.Fatalf("changed = %+v", d.Changed[0])
	}
}

// op_trace_web_module_imports.go: relative spec + extension candidates + outside guard.
func TestR3L18WebModuleResolve(t *testing.T) {
	dir := t.TempDir()
	entry := filepath.Join(dir, "entry.js")
	if err := os.WriteFile(entry, []byte("import './dep'\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "dep.js"), []byte("export const x=1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !isRelativeSpec("./dep") || isRelativeSpec("lodash") || !isRelativeSpec("../x") {
		t.Fatal("isRelativeSpec wrong")
	}
	p, status := resolveRelative(entry, "./dep")
	if status != "read" || p != filepath.Join(dir, "dep.js") {
		t.Fatalf("resolveRelative = %q/%q", p, status)
	}
	if _, status := resolveRelative(entry, "../../etc/passwd"); status == "read" {
		t.Fatalf("outside guard let a read through: %q", status)
	}
	if relativeOrBase(entry, filepath.Join(dir, "dep.js")) != "dep.js" {
		t.Fatal("relativeOrBase")
	}
}

// op_extract_firmware.go: carving works on the real UBI fixture (in-process temp dir).
func TestR3L18ExtractFirmwareReal(t *testing.T) {
	got, err := ops["extract_firmware"].run(r3l18UBI)
	if err != nil {
		t.Fatal(err)
	}
	m := r3l18JSON(t, got)
	if m["capped"] != false {
		t.Fatalf("capped = %v", m["capped"])
	}
	parts, ok := m["parts"].([]any)
	if !ok || len(parts) == 0 {
		t.Fatalf("parts = %#v", m["parts"])
	}
	first := parts[0].(map[string]any)
	if first["name"] != "ubi" {
		t.Fatalf("first part = %v", first)
	}
}

// op_inspect_apktool_client.go: extracts smali + caps from help output, does not start a process.
func TestR3L18ApktoolHelpParsing(t *testing.T) {
	// jebdApktoolHelp looks for the version on the line following "with smali ".
	help := "apktool d|decode  decode\napktool b|build  build\nwith smali 3.0.9-dev and baksmali\n"
	smali, caps := jebdApktoolHelp(help)
	if smali != "3.0.9-dev" {
		t.Fatalf("smali = %q", smali)
	}
	joined := strings.Join(caps, ",")
	if !strings.Contains(joined, "decode") || !strings.Contains(joined, "build") {
		t.Fatalf("caps = %v", caps)
	}
}

// op_list_adb_services.go: returns a skip when no device is attached (does not kill a process).
// rizin_debug_command, on the other hand, calls refuseKind -> os.Exit(2) so it cannot be
// called in-process; the out_of_scope envelope was verified with the real binary.
func TestR3L18RefusalKinds(t *testing.T) {
	got, err := ops["list_adb_services"].run("")
	if err != nil {
		t.Fatalf("list_adb_services err = %v", err)
	}
	sk, ok := got.(*skip)
	if !ok || !strings.Contains(sk.Reason, "no device attached") {
		t.Fatalf("list_adb_services skip = %#v", got)
	}
}
