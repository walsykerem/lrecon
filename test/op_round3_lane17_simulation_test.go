package main

import (
	"encoding/json"
	"strings"
	"testing"
)

const (
	l17JS    = "/Users/keremurhan/walsyrea/env/probe20/fixtures/web/flat/bundle.js"
	l17DLL1  = "/Users/keremurhan/walsyrea/env/probe20/fixtures/managed/dotnet/Acme.Managed.v1.dll"
	l17DLL2  = "/Users/keremurhan/walsyrea/env/probe20/fixtures/managed/dotnet/Acme.Managed.v2.dll"
	l17APK   = "/Users/keremurhan/walsyrea/env/stub.apk"
	l17MachO = "/Users/keremurhan/kalitetest/test1"
)

// TUR3 lane17: evidence.go attestation on a real probe.
func TestR3L17EvidenceAttestation(t *testing.T) {
	d, err := Probe(l17MachO)
	if err != nil {
		t.Fatal(err)
	}
	ev, err := evidenceLine(d)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(ev, "evidence: sha256:") || len(strings.TrimSpace(ev)) != len("evidence: sha256:")+64 {
		t.Fatalf("evidence line = %q", ev)
	}
	out := digestText(d, 4096)
	if !strings.HasSuffix(out, ev) {
		t.Fatal("digestText did not keep the evidence line last")
	}
	if len(out) > 4096 {
		t.Fatalf("digestText %d bytes over budget", len(out))
	}
	if _, err := ExplainField(d, "kind"); err != nil {
		t.Fatalf("ExplainField(kind): %v", err)
	}
	if _, err := ExplainField(d, "no-such-field"); err == nil {
		t.Fatal("unknown field must be a refusal")
	}
}

// TUR3 lane17: JS lexer on a real bundle, no mock.
func TestR3L17AnalyzeJavascriptRealBundle(t *testing.T) {
	if err := refuseCodeCache(l17JS); err != nil {
		t.Fatalf("real JS refused: %v", err)
	}
	got, err := opAnalyzeJavascriptApplication(l17JS)
	if err != nil {
		t.Fatal(err)
	}
	a, ok := got.(jsApplication)
	if !ok || a.Bytes == 0 || a.Tokens == 0 {
		t.Fatalf("result = %+v, want a lexed application", got)
	}
	if err := refuseCodeCache(l17MachO); err == nil {
		t.Fatal("native binary must be refused by the JS lexer")
	}
}

// TUR3 lane17: two-target managed diff on real ECMA-335 assemblies.
func TestR3L17CompareManagedMembersReal(t *testing.T) {
	got, err := runOp("compare_managed_members", l17DLL1+","+l17DLL2)
	if err != nil {
		t.Fatal(err)
	}
	out, _ := json.Marshal(got)
	for _, key := range []string{`"left_types":12`, `"right_types":13`, `"types_only_right":["Acme.Core.Extra"]`, `"methods_only_left":["Acme.Core.Native::getuid","Acme.Core.Utils::Helper"]`} {
		if !strings.Contains(string(out), key) {
			t.Fatalf("result missing %s: %s", key, out)
		}
	}
	if _, err := runOp("compare_managed_members", l17DLL1); err == nil {
		t.Fatal("one target must be bad_arg")
	}
}

// TUR3 lane17: APK signature gate on a real archive and a real non-archive.
func TestR3L17InspectApkSignatureReal(t *testing.T) {
	got, err := runOp("inspect_apk_signature", l17APK)
	if err != nil {
		t.Fatal(err)
	}
	out, _ := json.Marshal(got)
	if !strings.Contains(string(out), `"signed":false`) {
		t.Fatalf("result = %s, want signed:false", out)
	}
	if _, err := runOp("inspect_apk_signature", l17MachO); err == nil ||
		!strings.Contains(err.Error(), "no end-of-central-directory") {
		t.Fatalf("non-zip err = %v, want EOCD refusal", err)
	}
}

// TUR3 lane17: adb ps layout helpers, including the legacy fixed-column shape.
func TestR3L17AdbPSTable(t *testing.T) {
	l, ok := adbPSHeader([]string{"PID", "USER", "NAME", "ARGS"})
	if !ok || l.pid != 0 || l.user != 1 || l.name != 2 || l.args != 3 {
		t.Fatalf("header layout = %+v ok=%v", l, ok)
	}
	_, rows := adbPSTable("PID USER NAME ARGS\n1 root init /init\n2 shell sh -\n")
	if len(rows) != 2 || rows[0].PID != "1" || rows[0].User != "root" || rows[0].Name != "init" || rows[0].Args != "/init" {
		t.Fatalf("rows = %+v", rows)
	}
	_, legacy := adbPSTable("USER PID PPID NAME\nshell 42 1 com.x\n")
	if len(legacy) != 1 || legacy[0].PID != "42" || legacy[0].User != "shell" || legacy[0].Name != "com.x" {
		t.Fatalf("legacy rows = %+v", legacy)
	}
}

// TUR3 lane17: rlib helpers and JS export arity, pure logic no fixture needed.
func TestR3L17RlibAndJSHelpers(t *testing.T) {
	if c, ok := rlibFileCrate("libfoo-abc123.rlib"); !ok || c != "foo" {
		t.Fatalf("rlibFileCrate = %q,%v", c, ok)
	}
	if v, ok := rlibToolchain("rustc 1.92.0 (hash 2026-01-01)"); !ok || v != "1.92.0" {
		t.Fatalf("rlibToolchain = %q,%v", v, ok)
	}
	if rlibMetadataVersions[10] != "1.92" || rlibMetadataVersions[11] != "master" {
		t.Fatalf("versions = %+v", rlibMetadataVersions)
	}
	if got := paramArity("a, b"); got != 2 {
		t.Fatalf("paramArity = %d, want 2", got)
	}
	if got := paramArity(""); got != 0 {
		t.Fatalf("paramArity empty = %d, want 0", got)
	}
	if !nativeMagic([]byte{'M', 'Z', 0, 0}) || nativeMagic([]byte{'(', 'f', 'u', 'n'}) {
		t.Fatal("nativeMagic misclassified")
	}
}

// TUR3 lane17: live-session ops refuse by exiting with an out_of_scope
// envelope, so in-process they are checked at registration; the CLI refusal
// was verified separately (see report).
func TestR3L17LiveOpsRegistration(t *testing.T) {
	for _, name := range []string{"resume_frida_session", "trace_native_values"} {
		o, ok := ops[name]
		if !ok {
			t.Fatalf("%s not registered", name)
		}
		if o.route != "Y" || o.needs {
			t.Fatalf("%s route=%q needs=%v, want Y/false", name, o.route, o.needs)
		}
		if !strings.Contains(o.desc, "refuse") {
			t.Fatalf("%s desc = %q, want a refusal desc", name, o.desc)
		}
	}
	if !strings.Contains(liveFridaSessionDecline, "out of scope") {
		t.Fatal("live refusal body lost its out of scope reason")
	}
}
