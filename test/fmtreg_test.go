package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestKeyedArchiveResolvesUIDThroughObjects pins the real NSKeyedArchiver
// shape: "$class" is a UID whose target is an index into the "$objects" array,
// not an object-table slot. A whole-number UID must still land on the class
// dict, otherwise every class histogram comes back with zero counts.
func TestKeyedArchiveResolvesUIDThroughObjects(t *testing.T) {
	p := opStaticFile(t, "keyed-uid", sfBplist([]sfBP{
		{kind: 'd', keys: []byte{1, 2}, vals: []byte{3, 4}}, // top: $archiver, $objects
		{kind: 's', str: "$archiver"},
		{kind: 's', str: "$objects"},
		{kind: 's', str: "NSKeyedArchiver"},
		{kind: 'a', refs: []byte{8, 5, 9}},            // $objects: $null, instance, class dict
		{kind: 'd', keys: []byte{6}, vals: []byte{7}}, // instance {"$class": UID(2)}
		{kind: 's', str: "$class"},
		{kind: 'u', uid: 2}, // UID(2) -> $objects[2] -> ref 9
		{kind: 's', str: "$null"},
		{kind: 'd', keys: []byte{10}, vals: []byte{11}}, // class dict
		{kind: 's', str: "$classname"},
		{kind: 's', str: "NSString"},
	}))
	m := opStatic(t, "inspect_keyed_archive", p)
	if got := opStaticNum(t, m, "classes"); got != 1 {
		t.Fatalf("classes = %d, want 1", got)
	}
	hist, _ := m["class_histogram"].([]any)
	if len(hist) != 1 || hist[0] != "NSString=1" {
		t.Fatalf("class_histogram = %v, want [NSString=1]", m["class_histogram"])
	}
}

// TestInspectPlistDedupesBinaryKeys keeps the binary walk on the same contract
// as the XML walk: one entry per property name even when several dictionaries
// in the plist carry the same key.
func TestInspectPlistDedupesBinaryKeys(t *testing.T) {
	p := opStaticFile(t, "nested.bplist", sfBplist([]sfBP{
		{kind: 'd', keys: []byte{1, 2}, vals: []byte{3, 4}},
		{kind: 's', str: "A"},
		{kind: 's', str: "B"},
		{kind: 'd', keys: []byte{5}, vals: []byte{6}}, // {"label": "one"}
		{kind: 'd', keys: []byte{5}, vals: []byte{7}}, // {"label": "two"}
		{kind: 's', str: "label"},
		{kind: 's', str: "one"},
		{kind: 's', str: "two"},
	}))
	m := opStatic(t, "inspect_plist", p)
	keys, _ := m["keys"].([]any)
	if len(keys) != 3 {
		t.Fatalf("keys = %v, want A, B and one label", keys)
	}
	seen := map[string]bool{}
	for _, k := range keys {
		s, _ := k.(string)
		if seen[s] {
			t.Fatalf("duplicate key %q in %v", s, keys)
		}
		seen[s] = true
	}
}

// TestEVMSelectorScanSkipsPushData: a PUSH immediate may hold dispatcher-shaped
// bytes; only opcode positions count.
func TestEVMSelectorScanSkipsPushData(t *testing.T) {
	p := opStaticFile(t, "decoy.bin", []byte{
		0x7f, 'c', 0xde, 0xad, 0xbe, 0xef, 0x14, // PUSH32 with "63 deadbeef 14"
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x60, 0x00, 0x35, 0x60, 0xe0, 0x1c, // PUSH1 0 CALLDATALOAD PUSH1 e0 SHR
		0x80, 0x63, 0x01, 0x02, 0x03, 0x04, 0x14, 0x60, 0x10, 0x57, // PUSH4 01020304 EQ JUMPI
	})
	m := opStatic(t, "inspect_evm_interface", p)
	sels, _ := m["values"].([]any)
	if got := opStaticNum(t, m, "selectors"); got != 1 || len(sels) != 1 || sels[0] != "0x01020304" {
		t.Fatalf("selectors = %v (%v), want only 0x01020304", m["selectors"], sels)
	}
}

// TestEVMHexAcceptsLineBreaks: solc prints runtime bytecode with newlines and
// indentation; that is still hex, not raw bytes.
func TestEVMHexAcceptsLineBreaks(t *testing.T) {
	p := opStaticFile(t, "pretty.hex", []byte("0x63aabbccdd14\n  6311223344 14\n"))
	m := opStatic(t, "inspect_evm_interface", p)
	if got := opStaticNum(t, m, "code_bytes"); got != 12 {
		t.Fatalf("code_bytes = %d, want 12", got)
	}
	if got := opStaticNum(t, m, "selectors"); got != 2 {
		t.Fatalf("selectors = %d, want 2", got)
	}
}

// TestBundleExecutableReadsInfoPlist: the binary name need not equal the .app
// stem (Visual Studio Code.app keeps Contents/MacOS/Code).
func TestBundleExecutableReadsInfoPlist(t *testing.T) {
	xml := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>com.example.faketool</string>
<key>CFBundleExecutable</key><string>FakeBin</string>
</dict></plist>`
	bin := sfBplist([]sfBP{
		{kind: 'd', keys: []byte{1, 2}, vals: []byte{3, 4}},
		{kind: 's', str: "CFBundleIdentifier"},
		{kind: 's', str: "CFBundleExecutable"},
		{kind: 's', str: "com.example.faketool"},
		{kind: 's', str: "FakeBin"},
	})
	for name, plist := range map[string]string{"xml": xml, "binary": string(bin)} {
		dir := filepath.Join(t.TempDir(), "FakeTool.app")
		if err := os.MkdirAll(filepath.Join(dir, "Contents"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "Contents", "Info.plist"), []byte(plist), 0o644); err != nil {
			t.Fatal(err)
		}
		if got := bundleExecutable(dir); got != "FakeBin" {
			t.Fatalf("%s: bundleExecutable = %q, want FakeBin", name, got)
		}
	}

	dir := filepath.Join(t.TempDir(), "Evil.app")
	if err := os.MkdirAll(filepath.Join(dir, "Contents"), 0o755); err != nil {
		t.Fatal(err)
	}
	evil := strings.Replace(xml, "<string>FakeBin</string>", "<string>../evil</string>", 1)
	if err := os.WriteFile(filepath.Join(dir, "Contents", "Info.plist"), []byte(evil), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := bundleExecutable(dir); got != "" {
		t.Fatalf("path traversal accepted: %q", got)
	}
}
