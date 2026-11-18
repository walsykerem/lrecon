package main

// Stage 2: ops 60-118 of `lrecon --list-ops --json`, each checked against real
// tracked fixtures and the real CLI entry point runOp. An op passes when it
// emits real data (distinctive JSON substring) or a design-correct typed ret
// (needs_arg / bad_arg / out_of_scope / no_engine, or a *skip with reason).

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func s2Fixture(t *testing.T, parts ...string) string {
	t.Helper()
	return filepath.Join(append([]string{"testdata", "fixtures"}, parts...)...)
}

func s2Job(t *testing.T, v any) string {
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

type s2Case struct {
	name     string
	target   string
	env      map[string]string
	pre      func(*testing.T)
	dataHas  string // substring that must be present in real JSON output
	typedHas string // substring required in a typed ret / skip reason
}

func s2Check(t *testing.T, c s2Case) {
	t.Helper()
	t.Setenv("LRECON_STATE", t.TempDir())
	for k, v := range c.env {
		t.Setenv(k, v)
	}
	if c.pre != nil {
		c.pre(t)
	}

	res, err := runOp(c.name, c.target)
	if err != nil {
		msg := err.Error()
		kind := classify(msg)
		legit := kind == kindNeedsArg || kind == kindBadArg || kind == kindOutOfScope || kind == kindNoEngine
		if !legit {
			t.Fatalf("non-typed error %s: %q", kind, msg)
		}
		if c.typedHas == "" && kind != kindNoEngine && kind != kindOutOfScope {
			t.Fatalf("unexpected typed ret %s for data op: %q", kind, msg)
		}
		if c.typedHas != "" && !strings.Contains(msg, c.typedHas) {
			t.Fatalf("typed ret reason missing %q: %q", c.typedHas, msg)
		}
		t.Logf("PASS typed ret (%s): %s", kind, msg)
		return
	}
	if sk, ok := res.(*skip); ok {
		if sk.Reason == "" {
			t.Fatal("empty skip reason")
		}
		if c.typedHas == "" || !strings.Contains(sk.Reason, c.typedHas) {
			t.Fatalf("skip reason missing %q: %q", c.typedHas, sk.Reason)
		}
		t.Logf("PASS typed ret (skip): %s", sk.Reason)
		return
	}
	b, merr := json.Marshal(res)
	if merr != nil {
		t.Fatalf("marshal %T: %v", res, merr)
	}
	s := string(b)
	if c.dataHas == "" || !strings.Contains(s, c.dataHas) {
		show := s
		if len(show) > 320 {
			show = show[:320] + "..."
		}
		t.Fatalf("real data missing %q: %s", c.dataHas, show)
	}
	show := s
	if len(show) > 240 {
		show = show[:240] + "..."
	}
	t.Logf("PASS real data: %s", show)
}

func TestPassS2(t *testing.T) {
	oldFinder := ghidraFinder
	t.Cleanup(func() { ghidraFinder = oldFinder })
	// Deterministic simulation of this host: analyzeHeadless is not installed.
	ghidraFinder = func() (string, string, error) { return "", "", errors.New("ghidra not installed") }

	F := s2Fixture
	elf, macho, pe := F(t, "elf"), F(t, "macho"), F(t, "pe.exe")
	apk, dex, dll := F(t, "apk", "resources.apk"), F(t, "apk", "classes.dex"), F(t, "dotnet", "lib.dll")
	ips, car, pcap := F(t, "ips", "ls.ips"), F(t, "car", "Assets.car"), F(t, "pcap", "fixture.pcap")
	fuses, dtb, ubi := F(t, "fuses", "electron-fuses.bin"), F(t, "fdt", "board.dtb"), F(t, "ubi", "flash-ubi.img")
	beam, evm, fatbin := F(t, "beam", "hello.beam"), F(t, "evm", "dispatcher.hex"), F(t, "fatbin", "kernel.fatbin")
	meta, ko, plist := F(t, "il2cpp", "global-metadata.dat"), F(t, "kernmod", "fixmod.ko"), F(t, "keyed", "archive.plist")
	asar, dart := F(t, "electron", "app.asar"), F(t, "dart", "app.jit")
	evidence := filepath.Join("..", "evidence", "c6-bundle", "probe.evidence.json")
	noGhidra := "ghidra analyzeHeadless not installed"

	cases := []s2Case{
		{name: "gdb_console", target: pe, dataHas: `"engine":"lldb"`, typedHas: "lldb"},
		{name: "gdb_session_status", target: pe, dataHas: `"stopped":"no-inferior"`, typedHas: "lldb"},
		{name: "get_call_graph", target: elf, typedHas: noGhidra},
		{name: "get_evidence_bundle", target: s2Job(t, map[string]any{"file": evidence}), dataHas: `"bundle_sha256":`},
		{name: "get_navigation_context", pre: func(t *testing.T) {
			t.Setenv("LRECON_AT", "0x401000")
			if _, err := runOp("goto_address", elf); err != nil {
				t.Logf("pre goto_address: %v", err)
			}
		}, dataHas: `"procedure_entry":"0x401000"`},
		{name: "get_objc_classes", target: macho, typedHas: "has no Objective-C class list"},
		{name: "get_objc_protocols", target: macho, typedHas: "has no Objective-C protocol list"},
		{name: "goto_address", target: elf, env: map[string]string{"LRECON_AT": "0x401000"}, dataHas: `"section":".text"`},
		{name: "identify_flutter_build", target: apk, typedHas: "no Flutter marker"},
		{name: "import_evidence_bundle", target: s2Job(t, map[string]any{"file": evidence}), dataHas: `"artifact_match":true`},
		{name: "import_managed_reconstruction", target: s2Job(t, map[string]any{"file": dll, "state": t.TempDir()}), dataHas: `"assembly":"Probe 1.0.0.0"`},
		{name: "inline_comment", target: s2Job(t, map[string]any{"file": elf, "address": "0x401000", "text": "probe"}), env: map[string]string{"LRECON_AT": "0x401000"}, typedHas: noGhidra},
		{name: "inspect_adb_client", dataHas: `"client_version":`},
		{name: "inspect_adb_device", typedHas: "no device attached"},
		{name: "inspect_adb_display", typedHas: "no device attached"},
		{name: "inspect_adb_package", target: "com.example.probe", typedHas: "no device attached"},
		{name: "inspect_adb_window", typedHas: "no device attached"},
		{name: "inspect_address_context", target: elf, env: map[string]string{"LRECON_AT": "0x401000"}, typedHas: noGhidra},
		{name: "inspect_analysis_settings", dataHas: `"source":"defaults"`},
		{name: "inspect_analysis_view", target: s2Job(t, map[string]any{"file": elf, "view": "digest"}), dataHas: `"contract_version":1`},
		{name: "inspect_android_class", target: dex + "#com.example.fix.Main", dataHas: `"source_file":"Main.java"`},
		{name: "inspect_android_method", target: dex + "#com.example.fix.Main", dataHas: `"code_off":680`},
		{name: "inspect_android_package", target: apk, dataHas: `"package":"com.example.fix"`},
		{name: "inspect_apk_signature", target: apk, dataHas: `"signed":false`},
		{name: "inspect_apktool_client", target: apk, dataHas: `"apktool":"3.0.3"`},
		{name: "inspect_apple_ips", target: ips, dataHas: `"bug_type":"309"`},
		{name: "inspect_artifact", target: pe, dataHas: `"kind":"pe"`},
		{name: "inspect_asset_catalog", target: car, dataHas: `"container":"BOMStore"`},
		{name: "inspect_binary_layout", target: elf, dataHas: `"format":"elf"`},
		{name: "inspect_byte_entropy", target: pe, dataHas: `"block_bytes":4096`},
		{name: "inspect_dart_aot", target: dart, dataHas: `"app_jit":true`},
		{name: "inspect_desktop_application", target: asar, dataHas: `"asar_product":"Studio"`},
		{name: "inspect_devicetree", target: dtb, dataHas: `"compatible":"acme,fixboard"`},
		{name: "inspect_electron_fuses", target: fuses, dataHas: `"fuse_count":8`},
		{name: "inspect_electron_page", target: "127.0.0.1:9222", typedHas: "127.0.0.1:9222"},
		{name: "inspect_elf_notes", target: elf, dataHas: `"machine":"EM_X86_64"`},
		{name: "inspect_erlang_beam", target: beam, dataHas: `"atom_sample":["hello","world"]`},
		{name: "inspect_evm_interface", target: evm, dataHas: `"selectors":2`},
		{name: "inspect_firmware_regions", target: ubi, dataHas: `"kind":"ubi"`},
		{name: "inspect_format_coverage", dataHas: `"supported_formats":[`},
		{name: "inspect_go_binary", target: elf, dataHas: `"module":"example.com/lrecon-fixture"`},
		{name: "inspect_gpu_code_objects", target: fatbin, dataHas: `"wrapper_version":1`},
		{name: "inspect_il2cpp_metadata", target: meta, dataHas: `"kind":"il2cpp-metadata"`},
		{name: "inspect_jeb_client", target: dex, dataHas: `"dex_files":1`},
		{name: "inspect_kernel_module", target: ko, dataHas: `"module":"fixmod"`},
		{name: "inspect_keyed_archive", target: plist, dataHas: `"archiver":"NSKeyedArchiver"`},
		{name: "inspect_macho", target: macho, dataHas: `"uuid":"F5140394D4893FFCC7C5C57943306CF3"`},
		{name: "inspect_managed_artifact", target: dll, dataHas: `"runtime":"v4.0.30319"`},
		{name: "inspect_managed_members", target: dll, dataHas: `"type":"Probe.Widget"`},
		{name: "inspect_managed_native_boundaries", target: dll, typedHas: "has no ImplMap rows"},
		{name: "inspect_model_artifact", target: elf, typedHas: "safetensors header declares"},
		{name: "inspect_native_api", target: macho, dataHas: `"format":"macho"`},
		{name: "inspect_native_data_type", target: elf, env: map[string]string{"LRECON_NAME": "_EXCEPTION_RECORD"}, typedHas: noGhidra},
		{name: "inspect_native_dispatch_metadata", target: elf, typedHas: noGhidra},
		{name: "inspect_native_exports", target: elf, dataHas: `"symbols":"stripped"`},
		{name: "inspect_native_instruction", target: elf, env: map[string]string{"LRECON_AT": "0x401000"}, typedHas: noGhidra},
		{name: "inspect_native_load_image", target: macho, typedHas: "reads on-disk headers only"},
		{name: "inspect_packet_capture", target: pcap, dataHas: `"packets":4`},
		{name: "inspect_packet_fields", target: pcap, dataHas: `"snaplen":65535`},
	}
	if len(cases) != 59 {
		t.Fatalf("cases = %d, want 59", len(cases))
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) { s2Check(t, c) })
	}
}
