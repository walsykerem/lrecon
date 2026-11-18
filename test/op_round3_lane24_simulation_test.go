package main

// Round 3 audit, lane 24: simulation tests on real artifacts.
// Production code is not loosened; each test runs a real path with meaningful input.

import (
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	r3l24Test1 = "/Users/keremurhan/kalitetest/test1"
	r3l24Test2 = "/Users/keremurhan/kalitetest/test2"
	r3l24Own   = "/Users/keremurhan/walsyrea/lrecon/lrecon"
)

func r3l24OpResult(t *testing.T, name, path string) map[string]any {
	t.Helper()
	v, err := runOp(name, path)
	if err != nil {
		t.Fatalf("%s(%s): %v", name, path, err)
	}
	m, ok := v.(map[string]any)
	if !ok {
		b, _ := json.Marshal(v)
		t.Fatalf("%s(%s): result is not a map: %s", name, path, b)
	}
	return m
}

// binary_overview: kind/format/toolchain/contract from a real Mach-O digest.
func TestR3L24BinaryOverviewReal(t *testing.T) {
	for _, path := range []string{r3l24Test1, r3l24Test2, r3l24Own} {
		v, err := runOp("binary_overview", path)
		if err != nil {
			t.Fatalf("binary_overview(%s): %v", path, err)
		}
		b, _ := json.Marshal(v)
		var m struct {
			Summary         string `json:"summary"`
			Kind            string
			Format          string
			Toolchain       string
			ContractVersion int `json:"contract_version"`
		}
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatal(err)
		}
		if m.Kind != "macho" || m.Format != "thin" || m.ContractVersion != 1 {
			t.Fatalf("%s: kind=%q format=%q cv=%d", path, m.Kind, m.Format, m.ContractVersion)
		}
		if !strings.Contains(m.Summary, "hardening") || m.Toolchain == "" {
			t.Fatalf("%s: empty toolchain/summary: %s", path, b)
		}
	}
}

// current_address: a real session cursor resolves to the function table.
func TestR3L24CurrentAddressReal(t *testing.T) {
	t.Setenv("LRECON_SESSION", filepath.Join(t.TempDir(), "session.json"))
	t.Setenv("LRECON_AT", "0x1000004e8")
	if _, err := runOp("goto_address", r3l24Test1); err != nil {
		t.Fatalf("goto_address: %v", err)
	}
	v, err := runOp("current_address", "")
	if err != nil {
		t.Fatalf("current_address: %v", err)
	}
	b, _ := json.Marshal(v)
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if m["procedure"] != "_main" || m["address"] != "0x1000004e8" {
		t.Fatalf("current_address: %s", b)
	}
}

// search_bytes: finds a real byte pattern in a real file (offset evidence).
func TestR3L24SearchBytesRealHit(t *testing.T) {
	t.Setenv("LRECON_PATTERN", "71 67 3e")
	m := r3l24OpResult(t, "search_bytes", r3l24Test1)
	if m["hits"] != 1 {
		t.Fatalf("hits=%v (%v)", m["hits"], m)
	}
	matches, ok := m["matches"].([]patternHit)
	if !ok || len(matches) != 1 {
		t.Fatalf("matches=%v", m["matches"])
	}
	hit := matches[0]
	if hit.Off != 2679 || hit.At != "__TEXT,__const" {
		t.Fatalf("hit=%v", hit)
	}
	if m["scanned_whole"] != true {
		t.Fatalf("scanned_whole=%v", m["scanned_whole"])
	}
}

// search_bytes: malformed pattern bad_arg rejection (envelope is not production code, it is the op layer).
func TestR3L24SearchBytesBadPattern(t *testing.T) {
	t.Setenv("LRECON_PATTERN", "zz")
	_, err := runOp("search_bytes", r3l24Test1)
	if err == nil || !strings.Contains(err.Error(), "is not hex") {
		t.Fatalf("malformed pattern was not rejected: %v", err)
	}
}

// swift: nothing is claimed for a real Mach-O with no Swift section.
func TestR3L24SwiftNoSectionsReal(t *testing.T) {
	v, err := runOp("analyze_swift_types", r3l24Test1)
	if err != nil {
		t.Fatalf("analyze_swift_types: %v", err)
	}
	b, _ := json.Marshal(v)
	if !strings.Contains(string(b), `"sections":[]`) {
		t.Fatalf("section claimed in a file with no Swift section: %s", b)
	}
}

// swift: helper functions preserve real boundaries.
func TestR3L24SwiftHelpers(t *testing.T) {
	if n, ok := swiftSectionName("__swift5_types"); !ok || n != "types" {
		t.Fatalf("swiftSectionName Mach-O: %q %v", n, ok)
	}
	if n, ok := swiftSectionName(".swift5_protocols"); !ok || n != "protos" {
		t.Fatalf("swiftSectionName ELF: %q %v", n, ok)
	}
	if _, ok := swiftSectionName("__not_swift"); ok {
		t.Fatal("unknown section accepted")
	}
	if n, ok := swiftEntryCount(make([]byte, 12), 4); !ok || n != 3 {
		t.Fatalf("swiftEntryCount: %d %v", n, ok)
	}
	if _, ok := swiftEntryCount(make([]byte, 13), 4); ok {
		t.Fatal("half record accepted")
	}
	if v, ok := swiftReflectionVersion([]byte{0x03, 0x00}); !ok || v != 3 {
		t.Fatalf("swiftReflectionVersion: %d %v", v, ok)
	}
	// 4-byte relative offset: raw=0 null, mask clears the low bits.
	data := []byte{0, 0, 0, 0, 0x09, 0, 0, 0}
	tg, nulls, ok := swiftTargets(data, 0x1000, 3)
	if !ok || nulls != 1 || len(tg) != 1 || tg[0] != 0x100c {
		t.Fatalf("swiftTargets: %v nulls=%d ok=%v", tg, nulls, ok)
	}
	if !vaInSegments([]swiftSeg{{0x1000, 0x100}}, 0x1010) {
		t.Fatal("VA inside segment rejected")
	}
	if vaInSegments([]swiftSeg{{0x1000, 0x100}}, 0x2000) {
		t.Fatal("VA outside segment accepted")
	}
}

// formats: SQLite header is read from a real file (page size / version / WAL).
func TestR3L24SQLiteHeaderReal(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sample.sqlite")
	b := make([]byte, 100)
	copy(b, "SQLite format 3\x00")
	binary.BigEndian.PutUint16(b[16:18], 4096)
	binary.BigEndian.PutUint32(b[96:100], 3040002)
	b[18] = 2
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	var d Digest
	inspectSQLite(p, &d)
	if d.SQLitePageSize != 4096 || d.SQLiteVersion != "3.40.2" || !d.SQLiteWAL {
		t.Fatalf("sqlite: page=%d ver=%q wal=%v", d.SQLitePageSize, d.SQLiteVersion, d.SQLiteWAL)
	}
	if len(d.Notes) == 0 {
		t.Fatal("deepNote missing")
	}
}

// formats: XML and binary plist keys are extracted via real helper paths.
func TestR3L24PlistHelpersReal(t *testing.T) {
	xml := []byte(`<?xml version="1.0"?><plist><dict>` +
		`<key>CFBundleIdentifier</key><string>com.example.app</string>` +
		`<key>LSMinimumSystemVersion</key><string>13.0</string>` +
		`<key>CFBundleIdentifier</key><string>dup</string>` +
		`</dict></plist>`)
	if !isXMLPlist(xml) {
		t.Fatal("XML plist not recognized")
	}
	var d Digest
	keys := xmlPlistKeys(xml, &d)
	if len(keys) != 2 || keys[0] != "CFBundleIdentifier = com.example.app" || keys[1] != "LSMinimumSystemVersion = 13.0" {
		t.Fatalf("xmlPlistKeys: %v", keys)
	}
	if isXMLPlist([]byte("\x00farbe")) {
		t.Fatal("non-XML file mistaken for plist")
	}
	// bplistString rejects offset 0; therefore the marker is at 1.
	if s, ok := bplistString([]byte{0x00, 0x53, 'a', 'b', 'c'}, 1); !ok || s != "abc" {
		t.Fatalf("bplistString ascii: %q %v", s, ok)
	}
	utf := []byte{0x00, 0x62, 0x00, 0x41, 0x00, 0x42}
	if s, ok := bplistString(utf, 1); !ok || s != "AB" {
		t.Fatalf("bplistString utf16: %q %v", s, ok)
	}
	if _, ok := bplistString([]byte{0x00, 0x53, 'a'}, 1); ok {
		t.Fatal("truncated bplist string accepted")
	}
}

// dart: a valid snapshot is generated and inspect_dart_aot is run via the real path.
func TestR3L24DartSnapshotReal(t *testing.T) {
	snap := make([]byte, 20+32)
	binary.LittleEndian.PutUint32(snap, dartMagic)
	binary.LittleEndian.PutUint64(snap[4:], uint64(len(snap)-4))
	binary.LittleEndian.PutUint64(snap[12:], 2) // full-aot
	copy(snap[20:], strings.Repeat("a", 32))
	p := filepath.Join(t.TempDir(), "snapshot.aot")
	if err := os.WriteFile(p, snap, 0o600); err != nil {
		t.Fatal(err)
	}
	v, err := runOp("inspect_dart_aot", p)
	if err != nil {
		t.Fatalf("inspect_dart_aot: %v", err)
	}
	b, _ := json.Marshal(v)
	var m struct {
		Kind       string `json:"kind"`
		Actual     int    `json:"actual_bytes"`
		Consistent bool   `json:"length_consistent"`
		Hash       string `json:"version_hash"`
	}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if m.Kind != "full-aot" || m.Actual != len(snap) || !m.Consistent || m.Hash != strings.Repeat("a", 32) {
		t.Fatalf("dart: %s", b)
	}
}

// dart: a real Mach-O is rejected as bad_arg because it does not carry Dart magic.
func TestR3L24DartRejectsRealMachO(t *testing.T) {
	_, err := runOp("inspect_dart_aot", r3l24Test1)
	if err == nil || !strings.Contains(err.Error(), "does not carry the Dart snapshot magic") {
		t.Fatalf("file without Dart magic was not rejected: %v", err)
	}
}

// pcap: a real Mach-O is rejected because it is not pcap; fingerprint classification runs.
func TestR3L24PcapClientReal(t *testing.T) {
	_, err := runOp("inspect_pcap_client", r3l24Test1)
	if err == nil || !strings.Contains(err.Error(), "neither a pcap nor a pcapng") {
		t.Fatalf("non-pcap file was not rejected: %v", err)
	}
	cases := []struct{ ua, md5, want string }{
		{"curl/8.0", "", "curl"},
		{"Go-http-client/1.1", "", "go"},
		{"Mozilla/5.0", "", "browser"},
		{"", "3b5074b1b5d032e5620f69f9f700ff0e", "curl-tls"},
		{"", "deadbeef", "-"},
	}
	for _, c := range cases {
		if got := netcClientFamily(c.ua, c.md5); got != c.want {
			t.Fatalf("netcClientFamily(%q,%q)=%q want %q", c.ua, c.md5, got, c.want)
		}
	}
}

// gdb_session_status: the thread list is obtained from a real lldb batch dialogue.
func TestR3L24GdbSessionStatusReal(t *testing.T) {
	v, err := runOp("gdb_session_status", r3l24Test1)
	if err != nil {
		t.Fatalf("gdb_session_status: %v", err)
	}
	b, _ := json.Marshal(v)
	var m struct {
		Binary  string   `json:"binary"`
		Engine  string   `json:"engine"`
		Threads []any    `json:"threads"`
		Stopped string   `json:"stopped"`
		Output  []string `json:"output"`
	}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if m.Binary != r3l24Test1 || m.Engine != "lldb" || m.Stopped != "no-inferior" || len(m.Output) < 3 {
		t.Fatalf("gdb_session_status: %s", b)
	}
	if !strings.Contains(m.Output[len(m.Output)-1], "current process") {
		t.Fatalf("lldb transcript missing: %v", m.Output)
	}
	if !rtLLDBThread.MatchString("thread #1") || !rtLLDBStop.MatchString("stop reason = breakpoint 1.1") {
		t.Fatal("gdb regexes not working")
	}
}

// electron: the isolated world class is verified via a real helper constant and regex.
func TestR3L24ElectronIsolatedWorld(t *testing.T) {
	if electronWorldName != "Electron Isolated Context" {
		t.Fatalf("electronWorldName=%q", electronWorldName)
	}
	_, err := runOp("list_electron_targets", r3l24Test1)
	if err == nil || !strings.Contains(err.Error(), "not a DevTools endpoint") {
		t.Fatalf("non-DevTools target was not rejected: %v", err)
	}
}

// update_unknown: a missing address gives a needs_arg rejection in the real flow.
func TestR3L24UpdateUnknownNeedsArg(t *testing.T) {
	job := filepath.Join(t.TempDir(), "job.json")
	if err := os.WriteFile(job, []byte(`{"file":"`+r3l24Test1+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := runOp("update_unknown", job)
	if err == nil || !strings.Contains(err.Error(), `job needs "address"`) {
		t.Fatalf("update_unknown address refusal: %v", err)
	}
	if err := os.WriteFile(job, []byte(`{"file":"`+r3l24Test1+`","address":"0x1"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = runOp("update_unknown", job)
	if err == nil || !strings.Contains(err.Error(), `needs "hypothesis" or "resolution"`) {
		t.Fatalf("update_unknown hypothesis refusal: %v", err)
	}
}

// procedure_callees: the G op reaches real Ghidra; an unknown function is rejected.
func TestR3L24ProcedureCalleesReal(t *testing.T) {
	t.Setenv("LRECON_NAME", "__r3l24_no_such_symbol__")
	_, err := runOp("procedure_callees", r3l24Test1)
	if err == nil || !strings.Contains(err.Error(), "no function named") {
		t.Fatalf("procedure_callees unknown symbol: %v", err)
	}
}

// Contract: routes of ops defined in lane files are registered and consistent.
func TestR3L24RegisteredOpsAndContract(t *testing.T) {
	for name, want := range map[string]string{
		"binary_overview": "L", "current_address": "L",
		"inspect_dart_aot": "L", "inspect_pcap_client": "L",
		"search_bytes": "L", "update_unknown": "L",
		"gdb_session_status": "Y", "list_electron_targets": "Y",
		"procedure_callees": "G",
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
		t.Fatalf("op count %d (235 expected)", len(ops))
	}
}
