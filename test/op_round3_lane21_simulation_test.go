package main

// ROUND 3, lane 21: real behavior simulation tests for 11 source files.
// No fake/mock results: real fixtures, real pure functions and real command
// shims are used. Production code is not modified.

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

const (
	r3l21Test1 = "/Users/keremurhan/kalitetest/test1"
	r3l21PCAP  = "/Users/keremurhan/walsyrea/lrecon/testdata/fixtures/pcap/fixture.pcap"
)

func r3l21Refuse(t *testing.T, err error, wantKind errorKind, wantMsg string) {
	t.Helper()
	if err == nil {
		t.Fatalf("want refusal %s, got nil", wantKind)
	}
	var ref *extRefusal
	if !errors.As(err, &ref) {
		t.Fatalf("want *extRefusal, got %T: %v", err, err)
	}
	if ref.kind != wantKind || !strings.Contains(ref.msg, wantMsg) {
		t.Fatalf("refusal = %q/%q, want %q/%q", ref.kind, ref.msg, wantKind, wantMsg)
	}
}

// --- register + app.model ---

func TestR3L21RegistryRoutesAndNeeds(t *testing.T) {
	want := map[string]struct {
		route string
		needs bool
	}{
		"compare_web_captures":   {"Y", true},
		"frida_session_status":   {"Y", false},
		"inspect_asset_catalog":  {"L", true},
		"inspect_packet_capture": {"L", true},
		"list_browser_targets":   {"Y", true},
		"prev_address":           {"L", false},
		"unload_frida_script":    {"Y", false},
	}
	for name, w := range want {
		o, ok := ops[name]
		if !ok || o.route != w.route || o.needs != w.needs {
			t.Fatalf("%s registry = %+v, want %+v", name, o, w)
		}
	}
	live := reflect.ValueOf(refuseLiveFridaSession).Pointer()
	for _, name := range []string{"frida_session_status", "unload_frida_script"} {
		if got := reflect.ValueOf(ops[name].run).Pointer(); got != live {
			t.Fatalf("%s run is not the shared live-session refusal", name)
		}
	}
}

// --- exttool.go ---

func TestR3L21ExtRefusalAndErrorLine(t *testing.T) {
	if got := extErrorLine("INFO banner\n  error: bad artifact  \ntrailing"); got != "error: bad artifact" {
		t.Fatalf("extErrorLine = %q", got)
	}
	if got := extErrorLine("first line\nsecond line"); got != "first line" {
		t.Fatalf("extErrorLine fallback = %q", got)
	}
	r3l21Refuse(t, extRefuse(kindNoEngine, "adb: %s", "gone"), kindNoEngine, "adb: gone")
	if extTimeoutY != 60*time.Second || extTimeoutG != 50*time.Second {
		t.Fatalf("ext deadlines = %s/%s", extTimeoutY, extTimeoutG)
	}
}

func TestR3L21ExtToolNoEngineNamesAlternative(t *testing.T) {
	rtNoTools(t)
	_, _, err := extTool(context.Background(), "adb", extAdbAlt, "devices")
	r3l21Refuse(t, err, kindNoEngine, extAdbAlt)
	_, _, err = extLldb(context.Background(), []string{"bt"}, "")
	r3l21Refuse(t, err, kindNoEngine, extLldbAlt)
}

func TestR3L21ExtRunMapsToolFailureAndDeadline(t *testing.T) {
	rtFakeTool(t, "adb", "printf 'INFO banner\\nerror: device offline\\n' >&2; exit 1")
	_, _, err := extAdb(context.Background(), "devices")
	r3l21Refuse(t, err, kindNoEngine, "error: device offline")

	rtFakeTool(t, "adb", "sleep 5")
	ctx, cancel := extCtx(40 * time.Millisecond)
	defer cancel()
	_, _, err = extAdb(ctx, "shell", "sleep")
	r3l21Refuse(t, err, kindTimeout, "context deadline exceeded")
}

func TestR3L21ExtGhidraMissingNamesInstall(t *testing.T) {
	t.Setenv("LRECON_GHIDRA", filepath.Join(t.TempDir(), "no-ghidra"))
	_, _, err := extGhidra(context.Background(), "proj", "-import", "x")
	r3l21Refuse(t, err, kindNoEngine, "install Ghidra 12.1.4")
}

// --- op_asar_budget.go ---

func TestR3L21OpDeadlineAndStage(t *testing.T) {
	if opDeadline() != opDeadlineDefault {
		t.Fatalf("default deadline = %s", opDeadline())
	}
	t.Setenv(opDeadlineEnv, "garbage")
	if opDeadline() != opDeadlineDefault {
		t.Fatalf("bad deadline should fall back, got %s", opDeadline())
	}
	t.Setenv(opDeadlineEnv, "0")
	if opDeadline() != 0 {
		t.Fatalf("zero deadline = %s", opDeadline())
	}
	called := false
	_, err := runOpDeadline(r3l21Test1, func() (any, error) { called = true; return "x", nil })
	if called {
		t.Fatal("expired deadline must not run the body")
	}
	if !isOpTimeout(err) || err.Error() != "timeout" || classify(err.Error()) != kindTimeout {
		t.Fatalf("deadline error = %v / %s", err, classify(err.Error()))
	}
	var te *opTimeoutError
	if !errors.As(err, &te) || te.stage != "input" {
		t.Fatalf("stage = %+v, want input", te)
	}

	asar := filepath.Join(t.TempDir(), "app.asar")
	h := make([]byte, 24)
	binary.LittleEndian.PutUint32(h, 4)
	binary.LittleEndian.PutUint32(h[12:], 8)
	h[16] = '{'
	if err := os.WriteFile(asar, h, 0o644); err != nil {
		t.Fatal(err)
	}
	if targetStage(asar) != "asar" || targetStage(r3l21Test1) != "input" || targetStage(filepath.Join(t.TempDir(), "none")) != "input" {
		t.Fatal("targetStage misclassified a shape")
	}
	_, err = runOpDeadline(asar, func() (any, error) { return nil, nil })
	if errors.As(err, &te) && te.stage != "asar" {
		t.Fatalf("asar stage = %q", te.stage)
	}
}

func TestR3L21ReadWebTargetTextTruncatesAsarWindow(t *testing.T) {
	asar := filepath.Join(t.TempDir(), "big.asar")
	b := make([]byte, maxAsarWebText+16)
	binary.LittleEndian.PutUint32(b, 4)
	binary.LittleEndian.PutUint32(b[12:], 8)
	b[16] = '{'
	if err := os.WriteFile(asar, b, 0o644); err != nil {
		t.Fatal(err)
	}
	s, truncated, err := readWebTargetText(asar)
	if err != nil || !truncated || len(s) != maxAsarWebText {
		t.Fatalf("asar text len=%d truncated=%v err=%v", len(s), truncated, err)
	}
	s, truncated, err = readWebTargetText(r3l21Test1)
	if err != nil || truncated || s == "" {
		t.Fatalf("plain text len=%d truncated=%v err=%v", len(s), truncated, err)
	}
}

// --- op_compare_web_captures.go ---

func TestR3L21CaptureIndexAndBaselineOrder(t *testing.T) {
	for _, tc := range []struct {
		name string
		n    int
		ok   bool
	}{
		{"capture-1.json", 1, true},
		{"capture-10.json", 10, true},
		{"capture-0.json", 0, false},
		{"capture-x.json", 0, false},
		{"x.json", 0, false},
	} {
		n, ok := captureIndex(tc.name)
		if n != tc.n || ok != tc.ok {
			t.Fatalf("captureIndex(%s) = %d,%v", tc.name, n, ok)
		}
	}
	// capture-10 must lose to capture-2 numerically, not lexicographically.
	if n, _ := captureIndex("capture-10.json"); n < 2 {
		t.Fatal("numeric baseline order regressed")
	}
	dir := t.TempDir()
	if got := nextCaptureName(dir, 1); got != filepath.Join(dir, "capture-1.json") {
		t.Fatalf("first name = %s", got)
	}
	if err := os.WriteFile(filepath.Join(dir, "capture-1.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := nextCaptureName(dir, 1); got != filepath.Join(dir, "capture-2.json") {
		t.Fatalf("hole skipped = %s", got)
	}
}

func TestR3L21CaptureLinesAndTwoPointer(t *testing.T) {
	rows := []webRequestRow{
		{Method: "POST", URL: "/b", Status: 200},
		{Method: "GET", URL: "/a", Status: 404},
	}
	lines := captureLines(rows)
	want := []string{"GET /a 404", "POST /b 200"}
	if !reflect.DeepEqual(lines, want) {
		t.Fatalf("captureLines = %v", lines)
	}
	var added, removed []string
	same := twoPointer(want, []string{"GET /a 404", "GET /c 200"}, &added, &removed)
	if same != 1 || !reflect.DeepEqual(removed, []string{"POST /b 200"}) || !reflect.DeepEqual(added, []string{"GET /c 200"}) {
		t.Fatalf("twoPointer same=%d added=%v removed=%v", same, added, removed)
	}
}

// --- op_inspect_asset_catalog.go ---

func TestR3L21InspectAssetCatalogRealAndSkip(t *testing.T) {
	o := ops["inspect_asset_catalog"]
	got, err := o.run(assetCatalogFixture(t))
	if err != nil {
		t.Fatalf("BOMStore fixture: %v", err)
	}
	d, ok := got.(assetCatalogDigest)
	if !ok || d.Container != "BOMStore" || len(d.NamedBlocks) == 0 {
		t.Fatalf("BOMStore digest = %+v", got)
	}
	b, _ := json.Marshal(d)
	if !strings.Contains(string(b), "BOMStore") {
		t.Fatalf("digest lacks container: %s", b)
	}
	got, err = o.run(r3l21Test1)
	if err != nil {
		t.Fatalf("non-catalog: %v", err)
	}
	s, ok := got.(*skip)
	if !ok || !strings.Contains(s.Reason, "not an asset catalog") {
		t.Fatalf("skip = %+v", got)
	}
}

// --- op_inspect_packet_capture.go ---

func TestR3L21InspectPacketCaptureRealAndSkip(t *testing.T) {
	o := ops["inspect_packet_capture"]
	got, err := o.run(r3l21PCAP)
	if err != nil {
		t.Fatalf("pcap fixture: %v", err)
	}
	s, ok := got.(captureSummary)
	if !ok || s.Format != "pcap" || s.Packets != 4 || len(s.DNS) == 0 {
		t.Fatalf("capture summary = %+v", got)
	}
	got, err = o.run(r3l21Test1)
	if err != nil {
		t.Fatalf("non-pcap: %v", err)
	}
	sk, ok := got.(*skip)
	if !ok || !strings.Contains(sk.Reason, "not a packet capture") {
		t.Fatalf("skip = %+v", got)
	}
}

// --- op_prev_address.go ---

func TestR3L21PrevAddressOnRealSession(t *testing.T) {
	state := t.TempDir()
	t.Setenv("LRECON_STATE", state)
	t.Setenv("LRECON_SESSION", filepath.Join(state, "session.json"))
	target := "/Users/keremurhan/walsyrea/lrecon/lrecon"
	if err := saveSession(nativeSession{Kind: "lrecon.session/1", Document: target, Cursor: 0}); err != nil {
		t.Fatal(err)
	}
	got, err := runOp("prev_address", target)
	if err != nil {
		t.Fatalf("prev_address: %v", err)
	}
	m, ok := got.(map[string]any)
	if !ok || m["found"] != false || m["document"] != target || !strings.Contains(m["note"].(string), "no previous function start") {
		t.Fatalf("prev_address = %+v", got)
	}
}

// --- op_rt2_util.go ---

func TestR3L21Rt2AMStatusAndAdbGate(t *testing.T) {
	if s, err := rt2AMStatus("Starting: Intent\nStatus: ok\nComplete"); err != nil || s != "ok" {
		t.Fatalf("rt2AMStatus = %q / %v", s, err)
	}
	if _, err := rt2AMStatus("no status here"); err == nil || !strings.Contains(err.Error(), "no Status: line") {
		t.Fatalf("missing Status: err = %v", err)
	}
	rtFakeTool(t, "adb", rtTwoDevices)
	_, err := rt2AdbReady("shell", "ls")
	if err == nil || !strings.Contains(err.Error(), "set ANDROID_SERIAL") {
		t.Fatalf("two-device gate err = %v", err)
	}
	t.Setenv("ANDROID_SERIAL", "EMU1")
	sk, err := rt2AdbReady("shell", "ls")
	if err != nil || sk != nil {
		t.Fatalf("picked serial gate = %v / %v", sk, err)
	}
}

// --- sigpack.go ---

func TestR3L21SigpackLanguageSettlement(t *testing.T) {
	sigOnce.Do(loadSigpack)
	if sigErr != nil || len(sigPats) == 0 {
		t.Fatalf("shipped pack: %v, %d rules", sigErr, len(sigPats))
	}
	for family, lang := range langFromFamily {
		if lang == "" {
			t.Fatalf("family %s has no language", family)
		}
	}
	if langFromFamily["itanium"] != "c++" || langFromFamily["rust-v0"] != "rust" {
		t.Fatalf("langFromFamily = %v", langFromFamily)
	}
	langs := sortedSigLangs(map[string][]sigHit{"go": nil, "c++": nil, "rust": nil})
	if !reflect.DeepEqual(langs, []string{"c++", "go", "rust"}) {
		t.Fatalf("sortedSigLangs = %v", langs)
	}

	// Two distinct mechanisms on disjoint ranges settle a language claim.
	d := &Digest{}
	d.witnesses = []Witness{
		{Axis: "sig", Class: "sig", Value: "go", Start: 0, End: 4},
		{Axis: "mangling", Class: "parser", Value: "go", Start: 8, End: 12},
	}
	d.settleLanguage()
	if len(d.Claims) != 1 || d.Claims[0].Slot != "language" || d.Claims[0].Value != "go" {
		t.Fatalf("claims = %+v, unknown = %+v", d.Claims, d.Unknown)
	}
	// One mechanism stays unknown: a marker alone is not a finding.
	d2 := &Digest{}
	d2.witnesses = []Witness{{Axis: "sig", Class: "sig", Value: "go", Start: 0, End: 4}}
	d2.settleLanguage()
	if len(d2.Claims) != 0 || len(d2.Unknown) != 1 {
		t.Fatalf("single witness claims = %+v unknown = %+v", d2.Claims, d2.Unknown)
	}
}
