package main

// TUR 2 AUDIT — LANE 09. Real simulation tests: each op's own behavior
// is verified with meaningful, deterministic input. Production code is not relaxed.
// Helpers are defined with the r2l09 prefix; existing lane helpers (a07*, meta*,
// rea*, opStatic*, assetCatalogFixture, writeZip, dexFile) are reused.

import (
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func r2l09Write(t *testing.T, name string, b []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return p
}

func r2l09ADB(t *testing.T, body string) {
	t.Helper()
	dir := t.TempDir()
	a07FakeTool(t, dir, "adb", `if [ "$1" = "devices" ]; then printf 'List of devices attached\nFAKE123\tdevice\n\n'; exit 0; fi
`+body)
	t.Setenv("PATH", dir)
}

// ---- op_inline_comment.go ----

// A badly shaped job must not be masked by ghidraGate: opLoadJob runs first.
func TestR2L09InlineCommentBadJobNotMasked(t *testing.T) {
	p := metaTestArg(t, map[string]any{"deep": "yes"})
	_, err := ops["inline_comment"].run(p)
	if err == nil {
		t.Fatal("wrong-shaped job must refuse")
	}
	if got := classify(err.Error()); got != kindBadArg {
		t.Fatalf("kind = %s, want %s: %v", got, kindBadArg, err)
	}
}

// Valid job, missing text: after passing ghidraGate, job validation must catch it.
func TestR2L09InlineCommentMissingTextIsNeedsArg(t *testing.T) {
	t.Setenv("LRECON_ANALYZEHEADLESS", metaFakeHeadless(t))
	t.Setenv("LRECON_GHIDRA_CACHE", t.TempDir())
	pe := buildTarget(t, "windows", "amd64", "meta.exe")
	p := metaTestArg(t, map[string]any{"file": pe, "address": "0x1400"})
	_, err := ops["inline_comment"].run(p)
	if err == nil {
		t.Fatal("a job without text must refuse")
	}
	if got := classify(err.Error()); got != kindNeedsArg {
		t.Fatalf("kind = %s, want %s: %v", got, kindNeedsArg, err)
	}
}

// Real EOL flow: must store the fake headless job fields.
func TestR2L09InlineCommentStoresEOL(t *testing.T) {
	t.Setenv("LRECON_ANALYZEHEADLESS", metaFakeHeadless(t))
	t.Setenv("LRECON_GHIDRA_CACHE", t.TempDir())
	pe := buildTarget(t, "windows", "amd64", "meta.exe")
	p := metaTestArg(t, map[string]any{"file": pe, "address": "0x1400", "text": "eol note"})
	m, err := metaTestRun(t, "inline_comment", p)
	if err != nil {
		t.Fatalf("inline_comment: %v", err)
	}
	if metaStr(t, m, "address") != "0x1400" || metaStr(t, m, "comment") != "eol note" || metaStr(t, m, "stored") != "eol note" {
		t.Fatalf("inline_comment result = %v", m)
	}
}

// ---- op_inspect_address_context.go ----

// nativeHexArg is the op's LRECON_AT parser: hex and decimal both resolve to the same 0x format.
func TestR2L09AddressContextHexArg(t *testing.T) {
	t.Setenv("LRECON_AT", "0x401000")
	if got, err := nativeHexArg(); err != nil || got != "0x401000" {
		t.Fatalf("hex arg = %q, %v", got, err)
	}
	t.Setenv("LRECON_AT", "4198400")
	if got, err := nativeHexArg(); err != nil || got != "0x401000" {
		t.Fatalf("decimal arg = %q, %v", got, err)
	}
	t.Setenv("LRECON_AT", "")
	if _, err := nativeHexArg(); err == nil || classify(err.Error()) != kindNeedsArg {
		t.Fatalf("missing LRECON_AT: got %v, want needs_arg", err)
	}
}

// ---- op_inspect_analysis_settings.go ----

func TestR2L09AnalysisSettingsDefaultsAndConfig(t *testing.T) {
	state := metaTestState(t)
	m := metaMustRun(t, "inspect_analysis_settings", "")
	if metaStr(t, m, "source") != "defaults" {
		t.Fatalf("fresh state source = %v", m["source"])
	}
	st, _ := m["settings"].(map[string]any)
	if metaNum(t, st, "maxBytes") != 8<<20 || metaNum(t, st, "minString") != 4 || metaStr(t, st, "kind") != metaSettingsKind {
		t.Fatalf("defaults = %v", st)
	}

	cfg := `{"kind":"lrecon.config/1","deep":true,"maxBytes":1024,"minString":8}`
	if err := os.WriteFile(filepath.Join(state, "config.json"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	m = metaMustRun(t, "inspect_analysis_settings", "")
	if metaStr(t, m, "source") != "config" {
		t.Fatalf("configured source = %v", m["source"])
	}
	st, _ = m["settings"].(map[string]any)
	if !metaBool(t, st, "deep") || metaNum(t, st, "maxBytes") != 1024 || metaNum(t, st, "minString") != 8 {
		t.Fatalf("configured settings = %v", st)
	}
}

// ---- op_inspect_analysis_view.go ----

func TestR2L09AnalysisViews(t *testing.T) {
	body, err := json.Marshal(map[string]any{
		"contract_version": contractVersion, "kind": "elf", "format": "ELF",
		"symbols": "present", "names": "local:3", "exports": 7,
		"notes": []string{"n1"}, "skipped": []any{}, "plan": strings.Repeat("x", 200),
	})
	if err != nil {
		t.Fatal(err)
	}
	p := r2l09Write(t, "digest.json", body)

	for view, key := range map[string]string{
		"digest": "text", "json": "json", "symbols": "symbols",
		"notes": "notes", "skipped": "skipped", "raw": "hex",
	} {
		m, err := metaTestRun(t, "inspect_analysis_view", metaTestArg(t, map[string]any{"file": p, "view": view}))
		if err != nil {
			t.Fatalf("view %s: %v", view, err)
		}
		if _, ok := m[key]; !ok {
			t.Fatalf("view %s missing %q: %v", view, key, m)
		}
	}
	m := metaMustRun(t, "inspect_analysis_view", metaTestArg(t, map[string]any{"file": p, "view": "symbols"}))
	if metaStr(t, m, "symbols") != "present" || metaStr(t, m, "names") != "local:3" {
		t.Fatalf("symbols view = %v", m)
	}
	m = metaMustRun(t, "inspect_analysis_view", metaTestArg(t, map[string]any{"file": p, "view": "raw"}))
	if metaNum(t, m, "bytes_shown") != 128 {
		t.Fatalf("raw view must cap at 128 bytes: %v", m["bytes_shown"])
	}
	if _, err := metaTestRun(t, "inspect_analysis_view", metaTestArg(t, map[string]any{"file": p, "view": "nope"})); err == nil || !strings.Contains(err.Error(), "view") {
		t.Fatalf("unknown view: got %v", err)
	}
}

// ---- op_inspect_adb_client.go ----

func TestR2L09ADBClientParsesVersionAndDevices(t *testing.T) {
	r2l09ADB(t, `if [ "$1" = "version" ]; then printf 'Android Debug Bridge version 1.0.41\nVersion 35.0.2-13114751\nInstalled as /opt/adb\n'; exit 0; fi
if [ "$1" = "devices" ]; then printf 'List of devices attached\nFAKE123\tdevice product:foo model:Bar\n\n'; exit 0; fi`)
	m := reaMobileMap(t, reaMobileRun(t, "inspect_adb_client", ""))
	if metaStr(t, m, "client_version") != "1.0.41" || metaStr(t, m, "build") != "35.0.2-13114751" || metaStr(t, m, "path") != "/opt/adb" {
		t.Fatalf("client = %v", m)
	}
	devs, _ := m["devices"].([]any)
	if len(devs) != 1 {
		t.Fatalf("devices = %v, want one", m["devices"])
	}
}

func TestR2L09ADBClientEmptyTableIsAnswer(t *testing.T) {
	dir := t.TempDir()
	a07FakeTool(t, dir, "adb", `if [ "$1" = "version" ]; then printf 'Android Debug Bridge version 1.0.41\n'; exit 0; fi
if [ "$1" = "devices" ]; then printf 'List of devices attached\n\n'; exit 0; fi`)
	t.Setenv("PATH", dir)
	m := reaMobileMap(t, reaMobileRun(t, "inspect_adb_client", ""))
	if devs, ok := m["devices"].([]any); !ok || len(devs) != 0 {
		t.Fatalf("empty device table must be []: %v", m["devices"])
	}
}

// ---- op_inspect_adb_device.go ----

// The empty fingerprint slot must be preserved; if rtLines skipped empties, debuggable would shift.
func TestR2L09ADBDeviceKeepsEmptySlot(t *testing.T) {
	r2l09ADB(t, `if [ "$3" = "shell" ]; then printf 'Pixel 7\n33\n\n0\n'; exit 0; fi`)
	m := reaMobileMap(t, reaMobileRun(t, "inspect_adb_device", ""))
	if metaStr(t, m, "model") != "Pixel 7" || metaStr(t, m, "sdk") != "33" ||
		metaStr(t, m, "fingerprint") != "" || metaStr(t, m, "debuggable") != "0" {
		t.Fatalf("device props shifted: %v", m)
	}
}

// ---- op_inspect_adb_display.go ----

func TestR2L09ADBDisplayOverrides(t *testing.T) {
	r2l09ADB(t, `if [ "$3" = "shell" ]; then printf 'Physical size: 1080x2400\nOverride size: 720x1600\nPhysical density: 420\nOverride density: 320\n'; exit 0; fi`)
	m := reaMobileMap(t, reaMobileRun(t, "inspect_adb_display", ""))
	if metaStr(t, m, "physical_size") != "1080x2400" || metaStr(t, m, "override_size") != "720x1600" ||
		metaStr(t, m, "physical_density") != "420" || metaStr(t, m, "override_density") != "320" {
		t.Fatalf("display = %v", m)
	}
}

// ---- op_inspect_adb_package.go ----

func TestR2L09ADBPackageSentinelAndIsolation(t *testing.T) {
	a07FakeADBWithDump(t, "Unable to find package: com.nope\n")
	m := reaMobileMap(t, reaMobileRun(t, "inspect_adb_package", "com.nope"))
	if metaStr(t, m, "state") != "not-installed" {
		t.Fatalf("sentinel state = %v", m["state"])
	}

	a07FakeADBWithDump(t, `Packages:
  Package [com.other.pkg] (111):
    versionCode=9 minSdk=21
    versionName=9.9
  Package [com.example.app] (222):
    versionCode=7 minSdk=21
    versionName=1.2.3
`)
	m = reaMobileMap(t, reaMobileRun(t, "inspect_adb_package", "com.example.app"))
	if metaStr(t, m, "version_name") != "1.2.3" || metaStr(t, m, "version_code") != "7" {
		t.Fatalf("borrowed another package's version: %v", m)
	}
}

// ---- op_inspect_adb_window.go ----

func TestR2L09ADBWindowCountsBothShapesOnce(t *testing.T) {
	r2l09ADB(t, `if [ "$3" = "shell" ]; then printf 'mCurrentFocus=Window{abc}\nWindow #0 Window{abc}\nWindow{def}\nmFocusedApp=App{xyz}\n'; exit 0; fi`)
	m := reaMobileMap(t, reaMobileRun(t, "inspect_adb_window", ""))
	if metaNum(t, m, "windows") != 2 {
		t.Fatalf("windows = %v, want 2 (two shapes, no double count)", m["windows"])
	}
	if !strings.Contains(metaStr(t, m, "current_focus"), "abc") || !strings.Contains(metaStr(t, m, "focused_app"), "xyz") {
		t.Fatalf("focus fields = %v", m)
	}
}

// ---- op_inspect_android_class.go / op_inspect_android_method.go ----

func TestR2L09SelectorLooseSplit(t *testing.T) {
	existing := filepath.Join(t.TempDir(), "a#b.dex")
	if err := os.WriteFile(existing, dexFile(), 0o644); err != nil {
		t.Fatal(err)
	}
	if file, sel := opSelectorLoose(existing); file != existing || sel != "" {
		t.Fatalf("existing path with # split wrongly: %q / %q", file, sel)
	}
	if file, sel := opSelectorLoose("/no/such.dex#com.example.Bar"); file != "/no/such.dex" || sel != "com.example.Bar" {
		t.Fatalf("missing path selector split: %q / %q", file, sel)
	}
}

func TestR2L09AndroidMethodMemberHint(t *testing.T) {
	p := r2l09Write(t, "x.dex", dexFile())
	_, err := ops["inspect_android_method"].run(p + "#com.example.Foo.bar")
	if err == nil {
		t.Fatal("member selector must refuse")
	}
	if got := classify(err.Error()); got != kindBadArg {
		t.Fatalf("kind = %s, want %s: %v", got, kindBadArg, err)
	}
	if !strings.Contains(err.Error(), "drop the member name") {
		t.Fatalf("missing member-name hint: %v", err)
	}
}

// ---- op_inspect_android_package.go / op_inspect_artifact.go ----

func TestR2L09AndroidPackageNonAPKSkips(t *testing.T) {
	p := opStaticFile(t, "plain.bin", []byte("hello, not an apk"))
	reason := reaMobileSkip(t, "inspect_android_package", p)
	if !strings.Contains(reason, "not an Android package") {
		t.Fatalf("skip reason = %q", reason)
	}
}

func TestR2L09ArtifactInventory(t *testing.T) {
	pe := metaManagedPE(t)
	m, err := metaTestRun(t, "inspect_artifact", pe)
	if err != nil {
		t.Fatalf("inspect_artifact: %v", err)
	}
	if metaStr(t, m, "kind") == "" || metaNum(t, m, "size") <= 0 || len(metaStr(t, m, "sha256")) != 64 {
		t.Fatalf("inventory = %v", m)
	}
	if _, err := ops["inspect_artifact"].run("/nonexistent-xyz"); err == nil || classify(err.Error()) != kindIO {
		t.Fatalf("missing artifact: got %v, want io", err)
	}
}

// ---- op_inspect_apk_signature.go ----

func TestR2L09BytesHasEOCD(t *testing.T) {
	if bytesHasEOCD([]byte("no zip here")) {
		t.Fatal("plain bytes must not carry EOCD")
	}
	b := make([]byte, 32)
	binary.LittleEndian.PutUint32(b[10:], 0x06054b50)
	if !bytesHasEOCD(b) {
		t.Fatal("EOCD signature not found")
	}
}

// Synthetic APK Signing Block: two ID-value pairs (v2, v3) + footer + EOCD.
func TestR2L09ApkSigningBlockPairs(t *testing.T) {
	pairs := []byte{}
	for _, id := range []uint32{0x7109871a, 0xf05368c0} {
		pairs = binary.LittleEndian.AppendUint64(pairs, 4)
		pairs = binary.LittleEndian.AppendUint32(pairs, id)
	}
	const start = 0
	size := len(pairs) + 8 + 16 // pairs + second uint64 + 16 bytes magic
	cdOff := start + size + 8
	b := make([]byte, cdOff+2+22)
	binary.LittleEndian.PutUint64(b[start:], uint64(size))
	copy(b[start+8:], pairs)
	binary.LittleEndian.PutUint64(b[cdOff-24:], uint64(size))
	copy(b[cdOff-16:], apkSigBlockID)
	copy(b[cdOff:], []byte("CD"))
	eocd := cdOff + 2
	binary.LittleEndian.PutUint32(b[eocd:], 0x06054b50)
	binary.LittleEndian.PutUint32(b[eocd+16:], uint32(cdOff))

	ids, blockLen, err := apkSigningBlock(b)
	if err != nil {
		t.Fatalf("apkSigningBlock: %v", err)
	}
	if len(ids) != 2 || ids[0] != 0x7109871a || ids[1] != 0xf05368c0 {
		t.Fatalf("ids = %x, want v2/v3", ids)
	}
	if blockLen != size+8 {
		t.Fatalf("blockLen = %d, want %d", blockLen, size+8)
	}
}

// ---- op_inspect_apktool_client.go ----

func TestR2L09ApktoolHelpAndJava(t *testing.T) {
	smali, caps := jebdApktoolHelp(`Apktool v2.9.3
apktool d|decode  decode an apk
apktool b|build  rebuild
apktool if|install-framework  install
apktool e|empty-framework-dir  empty
Uses with smali 3.0 and dexdump for baksmali.`)
	if smali != "3.0" || len(caps) != 4 || caps[0] != "decode" || caps[3] != "empty-framework-dir" {
		t.Fatalf("help parse = %q / %v", smali, caps)
	}

	empty := t.TempDir()
	t.Setenv("PATH", empty)
	home := t.TempDir()
	if err := os.WriteFile(filepath.Join(home, "release"), []byte("JAVA_VERSION=\"17.0.1\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("JAVA_HOME", home)
	v, ok := jebdJavaVersion()
	if !ok || !strings.Contains(v, "17.0.1") {
		t.Fatalf("java version = %q / %v", v, ok)
	}
}

// ---- op_inspect_apple_ips.go ----

func TestR2L09AppleIPSHeaderAndBody(t *testing.T) {
	header := `{"bug_type":"309","app_version":"1.2","os_version":"23.1","timestamp":"2026-01-01","name":"app"}`
	both := r2l09Write(t, "both.ips", []byte(header+"\n"+`{"incident":"abc"}`))
	m := reaMobileMap(t, reaMobileRun(t, "inspect_apple_ips", both))
	if metaStr(t, m, "bug_type") != "309" || metaStr(t, m, "app_version") != "1.2" || !metaBool(t, m, "body_parsed") {
		t.Fatalf("header+body = %v", m)
	}
	onlyHeader := r2l09Write(t, "header.ips", []byte(header))
	m = reaMobileMap(t, reaMobileRun(t, "inspect_apple_ips", onlyHeader))
	if metaStr(t, m, "bug_type") != "309" || !metaBool(t, m, "body_parsed") {
		t.Fatalf("header-only = %v", m)
	}
	badBody := r2l09Write(t, "bad.ips", []byte(header+"\nnot json"))
	m = reaMobileMap(t, reaMobileRun(t, "inspect_apple_ips", badBody))
	if metaBool(t, m, "body_parsed") {
		t.Fatalf("unparseable body must not set body_parsed: %v", m)
	}
	noBug := r2l09Write(t, "nobug.ips", []byte(`{"app_version":"1.2"}`))
	if _, err := ops["inspect_apple_ips"].run(noBug); err == nil {
		t.Fatal("header without bug_type must refuse")
	}
	junk := r2l09Write(t, "junk.ips", []byte("not json at all\nbody"))
	if _, err := ops["inspect_apple_ips"].run(junk); err == nil || !strings.Contains(err.Error(), "not an .ips report") {
		t.Fatalf("junk header: got %v", err)
	}
}

// ---- op_inspect_asset_catalog.go ----

func TestR2L09AssetCatalogSyntheticAndSkip(t *testing.T) {
	p := assetCatalogFixture(t)
	var res assetCatalogOut
	metaBRes(t, reaMobileRun(t, "inspect_asset_catalog", p), &res)
	if res.Container != "BOMStore" || res.Version != 1 || res.BlocksDeclared != 6 || len(res.NamedBlocks) != 3 {
		t.Fatalf("catalog = %+v", res)
	}
	plain := opStaticFile(t, "plain.bin", []byte("not a catalog"))
	reason := reaMobileSkip(t, "inspect_asset_catalog", plain)
	if !strings.Contains(reason, "not an asset catalog") {
		t.Fatalf("skip reason = %q", reason)
	}
}

// ---- tur1 fix verification (op_web_util.go, another lane) ----

func TestR2L09WebTargetLocalhostAccepted(t *testing.T) {
	ep, _, err := webTarget("localhost:9222")
	if err != nil || ep != "127.0.0.1:9222" {
		t.Fatalf("localhost:9222 = %q, %v", ep, err)
	}
	// The tur1 fix targets localhost:port; a bare port intentionally produces
	// runtimeDecline (process-name gate) — this is not a production error.
	if _, _, err := webTarget("9222"); err == nil || !strings.Contains(err.Error(), runtimeDecline) {
		t.Fatalf("bare port must stay out of scope: %v", err)
	}
	if _, _, err := webTarget("http://example.com"); err == nil {
		t.Fatal("remote website must be refused")
	}
}
