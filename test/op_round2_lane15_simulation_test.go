package main

// Tur 2 audit, lane 15: independent real simulation tests.
// Only this file was written; production code and other test files were unchanged.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	elfbin "debug/elf"
)

// ---------- op_project_managed_application_graph.go ----------

func TestR2L15ManagedApplicationGraph(t *testing.T) {
	pe := buildTablesPE(t, managedTablesFixture(t))
	res, err := runProjectManagedGraph(pe)
	if err != nil {
		t.Fatalf("runProjectManagedGraph: %v", err)
	}
	b, _ := json.Marshal(res)
	var got struct {
		NodeCount int    `json:"node_count"`
		EdgeCount int    `json:"edge_count"`
		File      string `json:"file"`
	}
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got.NodeCount < 4 || got.EdgeCount < 3 || got.File != pe {
		t.Fatalf("graph = %s, want >=4 nodes, >=3 edges, file=%s", b, pe)
	}
	if !strings.Contains(string(b), "assembly-ref") || !strings.Contains(string(b), "\"kind\":\"type\"") {
		t.Fatalf("graph lacks assembly-ref/type nodes: %s", b)
	}
	// A file without CLI/metadata must be refused by metaCLI (no relaxation).
	text := writeTemp(t, "not-cli.txt", []byte("plain text"))
	if _, err := runProjectManagedGraph(text); err == nil ||
		!strings.Contains(err.Error(), "no CLR header") {
		t.Fatalf("non-CLI file: got %v, want 'no CLR header' refusal", err)
	}
}

// ---------- op_pull_adb_file.go / op_pull_adb_package.go / op_push_adb_file.go ----------

func TestR2L15PullAdbFileVerified(t *testing.T) {
	dir := t.TempDir()
	local := filepath.Join(dir, "pulled.txt")
	rt2TestTools(t, map[string]string{"adb": `#!/bin/sh
if [ "$1" = "devices" ]; then printf 'List of devices attached\nemu-1\tdevice\n'; exit 0; fi
if [ "$1" = "pull" ]; then printf 'hello' > "$3"; exit 0; fi
if [ "$1" = "shell" ] && [ "$2" = "stat" ]; then printf '5\n'; exit 0; fi
exit 0
`})
	res, err := opPullAdbFile("/data/local/tmp/x.txt:" + local)
	if err != nil {
		t.Fatalf("opPullAdbFile: %v", err)
	}
	f, ok := res.(rt2PulledFile)
	if !ok {
		t.Fatalf("result %T, want rt2PulledFile", res)
	}
	if !f.Verified || f.RemoteBytes != 5 || f.LocalBytes != 5 || f.SHA256 == "" {
		t.Fatalf("pull = %+v, want verified 5/5 with sha256", f)
	}
}

func TestR2L15PushAdbFileAndDirectoryRefusal(t *testing.T) {
	dir := t.TempDir()
	local := filepath.Join(dir, "up.txt")
	if err := os.WriteFile(local, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	rt2TestTools(t, map[string]string{"adb": `#!/bin/sh
if [ "$1" = "devices" ]; then printf 'List of devices attached\nemu-1\tdevice\n'; exit 0; fi
if [ "$1" = "shell" ] && [ "$2" = "stat" ]; then printf '5\n'; exit 0; fi
exit 0
`})
	res, err := opPushAdbFile(local + ":/data/local/tmp/y.txt")
	if err != nil {
		t.Fatalf("opPushAdbFile: %v", err)
	}
	f, ok := res.(rt2PushedFile)
	if !ok || !f.Verified || f.LocalBytes != 5 || f.RemoteBytes != 5 {
		t.Fatalf("push = %+v, want verified 5/5", res)
	}
	if _, err := opPushAdbFile(dir + ":/data/local/tmp/y.txt"); err == nil ||
		!strings.Contains(err.Error(), "is a directory") {
		t.Fatalf("directory push: got %v, want directory refusal", err)
	}
}

func TestR2L15PullAdbPackageSplits(t *testing.T) {
	old := opOutput
	opOutput = ""
	t.Cleanup(func() { opOutput = old })
	rt2TestTools(t, map[string]string{"adb": `#!/bin/sh
if [ "$1" = "devices" ]; then printf 'List of devices attached\nemu-1\tdevice\n'; exit 0; fi
if [ "$1" = "shell" ] && [ "$2" = "pm" ]; then
  printf 'package:/data/app/base.apk\npackage:/data/app/split_config.apk\n'; exit 0; fi
if [ "$1" = "pull" ]; then printf 'apk' > "$3"; exit 0; fi
exit 0
`})
	res, err := opPullAdbPackage("com.example.app")
	if err != nil {
		t.Fatalf("opPullAdbPackage: %v", err)
	}
	p, ok := res.(rt2PulledPackage)
	if !ok || p.Count != 2 || len(p.Splits) != 2 || p.Package != "com.example.app" {
		t.Fatalf("pull package = %+v, want 2 splits", res)
	}
	for _, s := range p.Splits {
		if s.Bytes != 3 || !filepath.IsAbs(s.Local) {
			t.Fatalf("split = %+v, want 3 bytes and an absolute path", s)
		}
	}
	if _, err := opPullAdbPackage("  "); err == nil ||
		!strings.Contains(err.Error(), "needs an argument") {
		t.Fatalf("empty pkg: got %v, want needs-argument error", err)
	}
}

// ---------- op_read_adb_logcat.go / op_read_adb_setting.go / op_resolve_adb_packages.go ----------

func TestR2L15ReadAdbLogcat(t *testing.T) {
	rt2TestTools(t, map[string]string{"adb": `#!/bin/sh
if [ "$1" = "devices" ]; then printf 'List of devices attached\nemu-1\tdevice\n'; exit 0; fi
if [ "$1" = "shell" ] && [ "$2" = "logcat" ]; then
  printf '10-15 12:34:56.789  1234  5678 I MyTag: first line\n'
  printf '10-15 12:34:57.001  1234  5678 E Other: second\n'
  printf 'garbage line\n'
  exit 0; fi
exit 0
`})
	res, err := opReadAdbLogcat("")
	if err != nil {
		t.Fatalf("opReadAdbLogcat: %v", err)
	}
	l, ok := res.(rt2Logcat)
	if !ok || l.Count != 2 || l.Unparsed != 1 || len(l.Entries) != 2 {
		t.Fatalf("logcat = %+v, want 2 parsed + 1 unparsed", res)
	}
	if l.Entries[0].Tag != "MyTag" || l.Entries[0].PID != 1234 || l.Entries[0].TID != 5678 ||
		l.Entries[0].Level != "I" || l.Entries[0].Msg != "first line" || l.Entries[0].Time != "10-15 12:34:56.789" {
		t.Fatalf("entry[0] = %+v", l.Entries[0])
	}
}

func TestR2L15ReadAdbSetting(t *testing.T) {
	rt2TestTools(t, map[string]string{"adb": `#!/bin/sh
if [ "$1" = "devices" ]; then printf 'List of devices attached\nemu-1\tdevice\n'; exit 0; fi
if [ "$1" = "shell" ] && [ "$2" = "settings" ]; then
  if [ "$5" = "airplane_mode_on" ]; then printf '1\n'; else printf 'null\n'; fi
  exit 0; fi
exit 0
`})
	res, err := opReadAdbSetting("secure:airplane_mode_on")
	if err != nil {
		t.Fatalf("opReadAdbSetting: %v", err)
	}
	s, ok := res.(rt2AdbSetting)
	if !ok || s.Namespace != "secure" || s.Key != "airplane_mode_on" || !s.Set ||
		s.Value == nil || *s.Value != "1" {
		t.Fatalf("setting = %+v, want secure/airplane_mode_on=1 Set", res)
	}
	res, err = opReadAdbSetting("system:missing_key")
	if err != nil {
		t.Fatalf("opReadAdbSetting null: %v", err)
	}
	s, ok = res.(rt2AdbSetting)
	if !ok || s.Set || s.Value != nil {
		t.Fatalf("null setting = %+v, want Set=false, Value=nil", res)
	}
	if _, err := opReadAdbSetting("bogus:key"); err == nil ||
		!strings.Contains(err.Error(), "is not system, secure or global") {
		t.Fatalf("bad namespace: got %v", err)
	}
}

func TestR2L15ResolveAdbPackages(t *testing.T) {
	rt2TestTools(t, map[string]string{"adb": `#!/bin/sh
if [ "$1" = "devices" ]; then printf 'List of devices attached\nemu-1\tdevice\n'; exit 0; fi
if [ "$1" = "shell" ] && [ "$2" = "cmd" ]; then
  printf 'priority=0\n'
  printf 'com.example.app/.MainActivity\n'
  printf 'com.other.app/.Viewer extra\n'
  printf 'com.third.app/.Activity\n'
  exit 0; fi
exit 0
`})
	res, err := opResolveAdbPackages("android.intent.action.SEND,https://example.com")
	if err != nil {
		t.Fatalf("opResolveAdbPackages: %v", err)
	}
	r, ok := res.(rt2ResolvedIntents)
	if !ok || r.Action != "android.intent.action.SEND" || r.URI != "https://example.com" ||
		r.Count != 2 || len(r.Components) != 2 {
		t.Fatalf("resolve = %+v, want 2 components", res)
	}
	if r.Components[0].Package != "com.example.app" || r.Components[0].Activity != ".MainActivity" {
		t.Fatalf("component[0] = %+v", r.Components[0])
	}
	if _, err := opResolveAdbPackages("  "); err == nil ||
		!strings.Contains(err.Error(), "needs an argument") {
		t.Fatalf("empty target: got %v", err)
	}
}

// ---------- op_read_bytes.go ----------

func TestR2L15ReadBytes(t *testing.T) {
	elf := buildTarget(t, "linux", "amd64", "byteself")
	ef, err := elfbin.Open(elf)
	if err != nil {
		t.Fatal(err)
	}
	defer ef.Close()
	sec := ef.Section(".text")
	if sec == nil {
		t.Fatal("fixture ELF has no .text section")
	}
	data, err := sec.Data()
	if err != nil || ef.Entry < sec.Addr || ef.Entry+4 > sec.Addr+uint64(len(data)) {
		t.Fatalf(".text data = %d bytes err %v, entry %#x outside it", len(data), err, ef.Entry)
	}
	// Read from the real entry address inside .text: section mapping + virtual_address basis.
	t.Setenv("LRECON_AT", fmt.Sprintf("%#x", ef.Entry))
	t.Setenv("LRECON_LEN", "4")
	res, err := runOp("read_bytes", elf)
	if err != nil {
		t.Fatalf("read_bytes at entry: %v", err)
	}
	b, _ := json.Marshal(res)
	var got struct {
		Address    string `json:"address"`
		FileOffset uint64 `json:"file_offset"`
		Section    string `json:"section"`
		Mapping    string `json:"mapping"`
		Basis      string `json:"basis"`
		Length     int    `json:"length"`
		Truncated  bool   `json:"truncated"`
		Hex        string `json:"hex"`
	}
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got.Address != fmt.Sprintf("0x%x", ef.Entry) || got.Section != ".text" ||
		got.Mapping != "section" || got.Basis != "virtual_address" ||
		got.Length != 4 || got.Truncated || got.FileOffset == 0 {
		t.Fatalf("read_bytes = %s, want .text/virtual_address 4 bytes at entry", b)
	}
	// Hex must carry the real bytes from the ELF's .text.
	wantHex := fmt.Sprintf("%02x", data[ef.Entry-sec.Addr])
	if !strings.Contains(strings.ToLower(got.Hex), wantHex) {
		t.Fatalf("read_bytes hex = %q, want first byte %q", got.Hex, wantHex)
	}
	// An address outside the file size must not look like a success.
	t.Setenv("LRECON_AT", "0xffffffffffffffff")
	if _, err := runOp("read_bytes", elf); err == nil ||
		!strings.Contains(err.Error(), "is not inside any file-backed section or segment") {
		t.Fatalf("out-of-range address: got %v, want range error", err)
	}
}

// ---------- op_read_function_instructions.go / op_resolve_containing_procedure.go / op_resolve_native_call_targets.go ----------

func TestR2L15GhidraOpRefusalKinds(t *testing.T) {
	cache := t.TempDir()
	t.Setenv("LRECON_GHIDRA_CACHE", cache)
	t.Setenv("LRECON_AT", "0x1000")
	t.Setenv("LRECON_NAME", "main")
	t.Setenv("LRECON_PATTERN", "main")
	text := writeTemp(t, "plain.txt", []byte("not a binary"))
	for _, name := range []string{
		"read_function_instructions", "resolve_containing_procedure", "resolve_native_call_targets",
	} {
		a21WantKind(t, name, "", kindNeedsArg)
		a21WantKind(t, name, "/nonexistent-xyz", kindIO)
		// A text file must return a no_engine skip, NOT an error.
		got, err := runOp(name, text)
		if err != nil {
			t.Errorf("%s on text: %v, want a no_engine skip", name, err)
			continue
		}
		reason := reaSkip(t, got)
		if classify(reason) != kindNoEngine || !strings.Contains(reason, "no decompiler") {
			t.Errorf("%s text skip = %q, want no decompiler/no_engine", name, reason)
		}
	}
	if ents, err := os.ReadDir(cache); err != nil || len(ents) != 0 {
		t.Errorf("Ghidra cache = %v, %v; want empty (no engine started)", ents, err)
	}
}

// ---------- op_reconcile_javascript_runtime.go ----------

func TestR2L15ReconcileJavascriptRuntime(t *testing.T) {
	bundle := writeTemp(t, "bundle.js", []byte(
		"exports.foo = function(a) { return a; }\nexports.bar = function() {}\n"))
	fakeDriver(t, webOut{
		Steps: []webStepResult{
			okStep("Debugger.enable", map[string]any{}),
			okStep("Runtime.enable", map[string]any{}),
			okStep("Runtime.evaluate", map[string]any{"result": map[string]any{
				"value": []any{"foo", "bar2"}}}),
		},
		Events: []webEvent{
			event("Debugger.scriptParsed", map[string]any{
				"scriptId": "1", "url": "file:///app.asar/dist/bundle.js"}),
			event("Debugger.scriptParsed", map[string]any{
				"scriptId": "2", "url": "eval://1"}),
		},
	})
	res, err := opReconcileJavascriptRuntime("127.0.0.1:9222=" + bundle)
	if err != nil {
		t.Fatalf("opReconcileJavascriptRuntime: %v", err)
	}
	b, _ := json.Marshal(res)
	var got struct {
		Static       string   `json:"static"`
		Parsed       int      `json:"scripts_parsed"`
		Matched      []string `json:"matched"`
		RuntimeNames []string `json:"runtime_exports_only"`
		DiskOnly     []struct {
			Name string `json:"name"`
		} `json:"disk_only_not_parsed"`
		Evaluated bool   `json:"exports_evaluated"`
		Status    string `json:"status"`
	}
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got.Static != "bundle.js" || got.Parsed != 2 || got.Status != "matched" || !got.Evaluated {
		t.Fatalf("reconcile = %s, want matched/evaluated/2 scripts", b)
	}
	if len(got.Matched) != 1 || got.Matched[0] != "foo" ||
		len(got.RuntimeNames) != 1 || got.RuntimeNames[0] != "bar2" ||
		len(got.DiskOnly) != 1 || got.DiskOnly[0].Name != "bar" {
		t.Fatalf("reconcile = %s, want foo matched, bar2 runtime-name, bar disk-only", b)
	}
	if _, err := opReconcileJavascriptRuntime("127.0.0.1:9222"); err == nil ||
		!strings.Contains(err.Error(), "no static bundle") {
		t.Fatalf("no bundle: got %v", err)
	}
}

// ---------- op_record_unknown.go / op_recover_javascript_sources.go ----------

func TestR2L15RecordUnknownState(t *testing.T) {
	t.Setenv("LRECON_STATE", t.TempDir())
	job := writeTemp(t, "job.json", []byte(`{"address":"0x1000","bytes":"deadbeef"}`))
	res, err := runOp("record_unknown", job)
	if err != nil {
		t.Fatalf("record_unknown: %v", err)
	}
	b, _ := json.Marshal(res)
	var got struct {
		Count      int `json:"count"`
		Unresolved int `json:"unresolved"`
	}
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got.Count != 1 || got.Unresolved != 1 {
		t.Fatalf("record_unknown = %s, want count=1 unresolved=1", b)
	}
	if _, err := runOp("record_unknown", job); err == nil ||
		!strings.Contains(err.Error(), "state conflict") {
		t.Fatalf("duplicate: got %v, want state conflict", err)
	}
}

func TestR2L15RecoverJavascriptSources(t *testing.T) {
	m := writeTemp(t, "app.js.map", []byte(`{"version":3,"file":"app.js",`+
		`"sources":["safe/a.js","../evil.js","missing.js"],`+
		`"sourcesContent":["safe content","malicious",null],"mappings":""}`))
	res, err := opRecoverJavascriptSources(m)
	if err != nil {
		t.Fatalf("opRecoverJavascriptSources: %v", err)
	}
	b, _ := json.Marshal(res)
	var got struct {
		Recovered []string `json:"recovered"`
		Missing   []string `json:"missing"`
		Refused   []string `json:"refused"`
		Bytes     int      `json:"bytes"`
		Dir       string   `json:"dir"`
	}
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Recovered) != 1 || got.Recovered[0] != "safe/a.js" ||
		len(got.Missing) != 1 || len(got.Refused) != 1 || got.Bytes != len("safe content") {
		t.Fatalf("recover = %s, want safe/a.js recovered, 1 missing, 1 refused", b)
	}
	written, err := os.ReadFile(filepath.Join(got.Dir, "safe", "a.js"))
	if err != nil || string(written) != "safe content" {
		t.Fatalf("recovered file = %q, err=%v", written, err)
	}
	if _, err := os.Stat(filepath.Join(got.Dir, "evil.js")); !os.IsNotExist(err) {
		t.Fatalf("traversal target was written: %v", err)
	}
}

// ---------- op_refuse_util.go + 3 live-session ops ----------

func TestR2L15LiveSessionRefusals(t *testing.T) {
	cases := []struct{ name, target string }{
		{"resume_frida_session", ""},
		{"rizin_debug_command", "/bin/ls:dr"},
		{"rizin_debug_session_status", "/bin/ls"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			stdout, stderr, code := runCLIAll(t, "--op", c.name, "--json", c.target)
			if code != 2 {
				t.Fatalf("exit %d, want 2; stdout=%s stderr=%s", code, stdout, stderr)
			}
			var env struct {
				Op    string `json:"op"`
				Kind  string `json:"kind"`
				Error string `json:"error"`
			}
			if err := json.Unmarshal([]byte(stdout), &env); err != nil {
				t.Fatalf("not a JSON envelope: %v\n%s", err, stdout)
			}
			if env.Op != c.name || env.Kind != "out_of_scope" ||
				!strings.Contains(env.Error, "out of scope") {
				t.Fatalf("envelope = %+v, want op=%s out_of_scope", env, c.name)
			}
		})
	}
}

// ---------- op_rt_util.go / op_rt_test.go ----------

func TestR2L15RtHelpers(t *testing.T) {
	devices := rtParseDevices("List of devices attached\n" +
		"R58M\tdevice product:beyond1lte model:SM_G973F transport_id:1\n" +
		"EMU1\tunauthorized\n*\ngarbage\n")
	// rtParseDevices returns all devices; the ready filter is applied in rtAdbSerial.
	if len(devices) != 2 {
		t.Fatalf("rtParseDevices = %+v, want 2 devices (header/*/garbage skipped)", devices)
	}
	d := devices[0]
	if d.Serial != "R58M" || d.State != "device" || d.Product != "beyond1lte" ||
		d.Model != "SM_G973F" || d.TransportID != "1" {
		t.Fatalf("device = %+v", d)
	}
	if empty := rtParseDevices("List of devices attached\n"); empty == nil || len(empty) != 0 {
		t.Fatalf("empty devices = %v, want non-nil empty slice", empty)
	}
	w, h, err := rtPNGInfo(rtTestPNG(t, 32, 24))
	if err != nil || w != 32 || h != 24 {
		t.Fatalf("rtPNGInfo = %d,%d,%v; want 32,24,nil", w, h, err)
	}
	if _, _, err := rtPNGInfo([]byte("not a png")); err == nil {
		t.Fatal("rtPNGInfo accepted malformed PNG")
	}
	a, b, err := rt2Pair(" /data/x.txt : /local/x.txt ", ":")
	if err != nil || a != "/data/x.txt" || b != "/local/x.txt" {
		t.Fatalf("rt2Pair = %q,%q,%v", a, b, err)
	}
	if _, _, err := rt2Pair("noseparator", ":"); err == nil {
		t.Fatal("rt2Pair accepted a target with no separator")
	}
}

// ---------- exercise of existing test files (op_rea_*_test.go, op_repair_test.go) ----------

func TestR2L15ExistingTestFixturesIntact(t *testing.T) {
	if got := reaObject(t, map[string]any{"answer": 1}); got["answer"] != float64(1) {
		t.Fatalf("reaObject = %v", got)
	}
	meta := managedTablesFixture(t)
	_, ok := parseMetadata(meta)
	if !ok {
		t.Fatal("managedTablesFixture no longer parses as CLI metadata")
	}
	if len(sfDartSnapshot(make([]byte, 32))) < 32 || len(sfBplist(nil)) == 0 || len(sfArsc()) == 0 {
		t.Fatal("repair fixture builders returned empty data")
	}
}
