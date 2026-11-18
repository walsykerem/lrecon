package main

// TUR3, lane 11: real artifact + pure function simulation tests for 11 source files.
// Production code is not changed; fixtures are read, t.TempDir() is written.

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const (
	r3l11Test1 = "/Users/keremurhan/kalitetest/test1"
	r3l11PE    = "/Users/keremurhan/walsyrea/lrecon/testdata/fixtures/pe.exe"
	r3l11DLL   = "/Users/keremurhan/walsyrea/lrecon/testdata/fixtures/dotnet/lib.dll"
	r3l11PCAP  = "/Users/keremurhan/walsyrea/lrecon/testdata/fixtures/pcap/fixture.pcap"
)

func r3l11Map(t *testing.T, v any) map[string]any {
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

func r3l11Num(t *testing.T, v any) float64 {
	t.Helper()
	f, ok := v.(float64)
	if !ok {
		t.Fatalf("%v is not number", v)
	}
	return f
}

func r3l11Job(t *testing.T, job map[string]any) string {
	t.Helper()
	b, err := json.Marshal(job)
	if err != nil {
		t.Fatal(err)
	}
	return writeTemp(t, "r3l11-job.json", b)
}

func r3l11Refuse(t *testing.T, err error, wantKind errorKind, wantMsg string) {
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

// --- detect.go ---

func TestR3L11ProbeRealArtifacts(t *testing.T) {
	d, err := Probe(r3l11Test1)
	if err != nil {
		t.Fatalf("Probe(test1): %v", err)
	}
	if d.Kind != "macho" || d.Plan != "macho" || d.Format != "thin" {
		t.Fatalf("test1 kind/plan/format = %q/%q/%q", d.Kind, d.Plan, d.Format)
	}
	if d.Target.HashScope != "whole-file" || d.Target.HashBytes != d.Target.Size {
		t.Fatalf("test1 hash scope/bytes = %q/%d (size %d)", d.Target.HashScope, d.Target.HashBytes, d.Target.Size)
	}
	raw, err := os.ReadFile(r3l11Test1)
	if err != nil {
		t.Fatal(err)
	}
	h256 := sha256.Sum256(raw)
	h1 := sha1.New()
	h1.Write([]byte("blob " + strconv.Itoa(len(raw)) + "\x00"))
	h1.Write(raw)
	wantOID := "gitoid:blob:sha1:" + hex.EncodeToString(h1.Sum(nil))
	if d.Target.FileSHA256 != hex.EncodeToString(h256[:]) || d.Target.GitOID != wantOID {
		t.Fatalf("test1 hash = %s / %s, want %s / %s", d.Target.FileSHA256, d.Target.GitOID, hex.EncodeToString(h256[:]), wantOID)
	}

	for _, c := range []struct{ path, kind, plan string }{
		{r3l11PE, "pe", "pe"},
		{r3l11DLL, "pe-dotnet", "generic"},
		{r3l11PCAP, "pcap", "generic"},
	} {
		d, err := Probe(c.path)
		if err != nil {
			t.Fatalf("Probe(%s): %v", c.path, err)
		}
		if d.Kind != c.kind || d.Plan != c.plan {
			t.Fatalf("%s kind/plan = %q/%q, want %q/%q", c.path, d.Kind, d.Plan, c.kind, c.plan)
		}
	}

	empty := writeTemp(t, "empty.bin", nil)
	if _, err := Probe(empty); err == nil || !strings.Contains(err.Error(), "0 bytes") {
		t.Fatalf("empty Probe = %v", err)
	}
	if _, err := Probe(filepath.Dir(r3l11Test1)); err == nil || !strings.Contains(err.Error(), "not an app bundle") {
		t.Fatalf("dir Probe = %v", err)
	}
}

func TestR3L11DigestPlanAndMagicGuards(t *testing.T) {
	for kind, want := range map[string]string{
		"macho": "macho", "elf": "elf", "pe": "pe",
		"apk": "mobile", "ipa": "mobile", "dex": "mobile", "android-manifest": "mobile",
		"pcap": "generic", "text": "generic", "pe-dotnet": "generic",
	} {
		if got := digestPlan(kind); got != want {
			t.Fatalf("digestPlan(%q) = %q, want %q", kind, got, want)
		}
	}

	if !isMachO([]byte{0xcf, 0xfa, 0xed, 0xfe}) || isMachO([]byte{0x00, 0x01}) {
		t.Fatal("isMachO magic check broken")
	}
	if !isFatMachO([]byte{0xca, 0xfe, 0xba, 0xbe}) || isFatMachO([]byte{0xbe, 0xba, 0xfe, 0xca}) {
		t.Fatal("isFatMachO byte order broken")
	}
	for _, cpu := range []uint32{1, 7, 12, 0x01000007, 0x0100000c, 0x01000012} {
		if !machoCPUType(cpu) {
			t.Fatalf("machoCPUType(%#x) false", cpu)
		}
	}
	for _, cpu := range []uint32{0, 0xdeadbeef, 0x01000099} {
		if machoCPUType(cpu) {
			t.Fatalf("machoCPUType(%#x) true", cpu)
		}
	}

	fat := make([]byte, 64)
	binary.BigEndian.PutUint32(fat, 0xcafebabe)
	binary.BigEndian.PutUint32(fat[4:], 1)
	binary.BigEndian.PutUint32(fat[8:], 0x0100000c) // arm64
	binary.BigEndian.PutUint32(fat[16:], 32)
	binary.BigEndian.PutUint32(fat[20:], 16)
	if !fatMachOOK(fat, 64) {
		t.Fatal("valid fat header rejected")
	}
	if fatMachOOK(fat, 40) {
		t.Fatal("slice past EOF accepted")
	}
	binary.BigEndian.PutUint32(fat[16:], 60) // slice starts after the 64-byte header
	binary.BigEndian.PutUint32(fat[20:], 16)
	if !fatMachOTruncated(fat, 64) || fatMachOOK(fat, 64) {
		t.Fatal("out-of-range slice fat must be truncated, not OK")
	}

	asar := make([]byte, 24)
	binary.LittleEndian.PutUint32(asar, 4)
	binary.LittleEndian.PutUint32(asar[12:], 10)
	asar[16] = '{'
	if !isAsar(asar) {
		t.Fatal("asar header rejected")
	}
	if looksText([]byte("hello world\n")) != true || looksText([]byte{0, 1, 2, 3}) {
		t.Fatal("looksText broken")
	}
	if base("/a/b/c") != "c" {
		t.Fatal("base broken")
	}
}

func TestR3L11HashTargetNShortReadAndScope(t *testing.T) {
	data := bytes.Repeat([]byte("x"), 100)
	got, err := hashTargetN(bytes.NewReader(data), 100, 100, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(data)
	if got.FileSHA256 != hex.EncodeToString(h[:]) || got.HashBytes != 100 || got.HashScope != "whole-file" {
		t.Fatalf("identity = %+v", got)
	}
	if _, err := hashTargetN(bytes.NewReader(data[:50]), 100, 100, nil); err == nil || !strings.Contains(err.Error(), "file changed") {
		t.Fatalf("short read = %v", err)
	}
	cap := &headCapture{buf: make([]byte, 8)}
	if _, err := hashTargetN(bytes.NewReader(data), 100, 100, cap); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(cap.buf, data[:8]) {
		t.Fatalf("head = %q", cap.buf)
	}
	big := bytes.Repeat([]byte("x"), maxDigest+1)
	if got, err := hashTargetN(bytes.NewReader(big), int64(len(big)), maxDigest+1, nil); err != nil || got.HashScope != "first-67108864-bytes" || got.HashBytes != maxDigest {
		t.Fatalf("capped scope = %+v / %v", got, err)
	}
}

func TestR3L11NoteAndBundleGuards(t *testing.T) {
	if !nativeParseFailed(Digest{Notes: []string{"native: bad slice"}}) || nativeParseFailed(Digest{Notes: []string{"asar: open: no"}}) {
		t.Fatal("nativeParseFailed broken")
	}
	if !parseFailed(Digest{Notes: []string{"dex: open: nope"}}) || !parseFailed(Digest{Notes: []string{"java: bad"}}) || parseFailed(Digest{Notes: []string{"info"}}) {
		t.Fatal("parseFailed prefix set broken")
	}
	in := []string{"keep", "native: drop", "keep2"}
	out := dropNotes(in, "native: ")
	if len(out) != 2 || out[0] != "keep" || out[1] != "keep2" {
		t.Fatalf("dropNotes = %v", out)
	}
	if !isAppBundle("/tmp/Foo.app") {
		t.Fatal(".app suffix not a bundle")
	}
	plain := t.TempDir()
	if isAppBundle(plain) {
		t.Fatal("plain dir accepted as bundle")
	}
}

// --- objectsyms.go ---

func TestR3L11ObjectSymbolTableRealBinaries(t *testing.T) {
	for _, path := range []string{r3l11Test1, "testdata/fixtures/cxx/vtables.o"} {
		syms, err := objectSymbolTable(path)
		if err != nil {
			t.Fatalf("objectSymbolTable(%s): %v", path, err)
		}
		if len(syms) == 0 {
			t.Fatalf("%s: no symbols", path)
		}
		for i := 1; i < len(syms); i++ {
			if syms[i-1].Value > syms[i].Value {
				t.Fatalf("%s: symbols not sorted", path)
			}
		}
		line := syms[0].line()
		if len(line) < 18 || line[16] != ' ' {
			t.Fatalf("symbol line = %q", line)
		}
	}
	if _, err := objectSymbolTable(writeTemp(t, "plain.txt", []byte("hello"))); err == nil {
		t.Fatal("text accepted as object file")
	}
}

// --- op_inspect_managed_artifact.go ---

func TestR3L11ManagedArtifactRealAssembly(t *testing.T) {
	m := r3l11Map(t, mustR3L11Op(t, "inspect_managed_artifact", r3l11DLL))
	if m["kind"] != "pe-dotnet" || r3l11Num(t, m["tables"]) < 1 || r3l11Num(t, m["types"]) < 1 {
		t.Fatalf("managed artifact = %v", m)
	}
	bad, err := runOp("inspect_managed_artifact", r3l11Test1)
	if err != nil {
		t.Fatalf("wrong-kind op should skip, got %v", err)
	}
	s := r3l11Map(t, bad)["skipped"]
	if s == nil || !strings.Contains(s.(string), "not a managed assembly") {
		t.Fatalf("wrong-kind skip = %v", s)
	}
}

func mustR3L11Op(t *testing.T, name, path string) any {
	t.Helper()
	v, err := runOp(name, path)
	if err != nil {
		t.Fatalf("%s(%s): %v", name, path, err)
	}
	return v
}

// --- op_netc_util.go ---

func TestR3L11NetCRealCaptureAndDylibPaths(t *testing.T) {
	var frames int
	info, err := netcReadCapture(r3l11PCAP, netcFrameCap, func(f netcFrame) error {
		if len(f.data) == 0 {
			t.Fatal("empty frame")
		}
		p := netcDecode(f)
		if p.Link == "" {
			t.Errorf("frame %d has no link layer", f.n)
		}
		frames++
		return nil
	})
	if err != nil {
		t.Fatalf("netcReadCapture: %v", err)
	}
	if info.Packets != 4 || frames != 4 || info.Decoded != 4 || info.CapHit || info.Truncated {
		t.Fatalf("capture info = %+v, frames=%d", info, frames)
	}

	if got := netcExpandPath("@executable_path/../Frameworks/lib.dylib", "/app/MacOS", "/app/Plugins"); got != "/app/Frameworks/lib.dylib" {
		t.Fatalf("executable_path = %q", got)
	}
	if got := netcExpandPath("@loader_path/lib.dylib", "/app/MacOS", "/app/Plugins"); got != "/app/Plugins/lib.dylib" {
		t.Fatalf("loader_path = %q", got)
	}
	cands := netcDylibCandidates("@rpath/lib.dylib", "/app/MacOS", "/app/Plugins", []string{"@executable_path/../Frameworks", "@loader_path/Frameworks"})
	if len(cands) != 2 || cands[0] != "/app/Frameworks/lib.dylib" || cands[1] != "/app/Plugins/Frameworks/lib.dylib" {
		t.Fatalf("rpath candidates = %v", cands)
	}
	dir := t.TempDir()
	f := filepath.Join(dir, "lib.dylib")
	if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := netcFirstExisting([]string{filepath.Join(dir, "missing"), f}); got != f {
		t.Fatalf("first existing = %q, want %q", got, f)
	}
}

// --- op_record_unknown.go ---

func TestR3L11RecordUnknownStateLifecycle(t *testing.T) {
	state := t.TempDir()
	t.Setenv("LRECON_STATE", state)
	job := r3l11Job(t, map[string]any{
		"file": r3l11PE, "address": "0x1000", "bytes": "de ad be ef", "hypothesis": "TUR3 lane11",
	})
	rec := r3l11Map(t, mustR3L11Op(t, "record_unknown", job))
	if r3l11Num(t, rec["count"]) != 1 || r3l11Num(t, rec["unresolved"]) != 1 {
		t.Fatalf("record counters = %v", rec)
	}
	entry := r3l11Map(t, rec["recorded"])
	if entry["bytes"] != "de ad be ef" || entry["hypothesis"] != "TUR3 lane11" {
		t.Fatalf("recorded entry = %v", entry)
	}
	if rec["unknowns_file"] == nil {
		t.Fatal("no unknowns_file in result")
	}
	raw, err := os.ReadFile(rec["unknowns_file"].(string))
	if err != nil {
		t.Fatal(err)
	}
	var st metaUnknownState
	if err := json.Unmarshal(raw, &st); err != nil {
		t.Fatal(err)
	}
	if st.Kind != metaUnknownsKind || len(st.Unknowns) != 1 {
		t.Fatalf("state = %+v", st)
	}
	if _, err := runOp("record_unknown", r3l11Job(t, map[string]any{"address": "0x1000", "bytes": "00"})); err == nil || !strings.Contains(err.Error(), "already recorded") {
		t.Fatalf("duplicate = %v", err)
	}
	if _, err := runOp("record_unknown", r3l11Job(t, map[string]any{"hypothesis": "no address"})); err == nil || !strings.Contains(err.Error(), "job needs") {
		t.Fatalf("missing address = %v", err)
	}
}

// --- op_ext_adb_state.go / op_install_adb_package.go ---

func TestR3L11AdbStateArgValidation(t *testing.T) {
	rtNoTools(t)
	if _, err := runAdbTcpip("dev", nil); err == nil || !strings.Contains(err.Error(), "needs a port") {
		t.Fatalf("tcpip missing port = %v", err)
	}
	for _, bad := range []string{"abc", "0", "65536", "-1"} {
		_, err := runAdbTcpip("dev", []string{bad})
		r3l11Refuse(t, err, kindBadArg, "not a port number")
	}
	_, err := runAdbEmu("dev", []string{" "})
	r3l11Refuse(t, err, kindNeedsArg, "emulator console command")
	_, err = runAdbReboot("dev", []string{"explode"})
	r3l11Refuse(t, err, kindBadArg, "not a reboot mode")
}

func TestR3L11AdbStateFakeToolExactArgs(t *testing.T) {
	rtFakeTool(t, "adb", `printf 'ran:%s\n' "$*"`)
	for _, c := range []struct {
		op, target string
		args       []string
		want       string
	}{
		{"adb_disconnect", "", nil, "disconnect"},
		{"adb_tcpip", "dev", []string{"5555"}, "tcpip 5555"},
		{"adb_emu", "dev", []string{"sms send 1 hi"}, "emu sms send 1 hi"},
		{"adb_wait_for_device", "", nil, "wait-for-device"},
		{"adb_get_state", "", nil, "get-state"},
		{"adb_get_serialno", "", nil, "get-serialno"},
		{"adb_reboot", "", []string{"recovery"}, "reboot recovery"},
	} {
		t.Run(c.op, func(t *testing.T) {
			v, err := runExtOp(c.op, c.target, c.args)
			if err != nil {
				t.Fatalf("%s: %v", c.op, err)
			}
			out, ok := v.(extOut)
			if !ok || out.Tool != "adb" || strings.Join(out.Args, " ") != c.want || !strings.Contains(out.Output, "ran:") {
				t.Fatalf("%s output = %+v, want adb/%q", c.op, v, c.want)
			}
		})
	}
}

func TestR3L11InstallReasonAndMissingAPK(t *testing.T) {
	for _, tc := range []struct{ stderr, want string }{
		{"adb: failed to install /x.apk:\nINSTALL_FAILED_NO_MATCHING_ABIS\n", "INSTALL_FAILED_NO_MATCHING_ABIS"},
		{"adb: failed to install /x.apk:\nException occurred while executing 'install':\njava.lang.RuntimeException: boom\n", "java.lang.RuntimeException: boom"},
		{"Serving...\n", "Serving..."},
		{"", ""},
	} {
		if got := installReason(tc.stderr); got != tc.want {
			t.Fatalf("installReason(%q) = %q, want %q", tc.stderr, got, tc.want)
		}
	}
	if _, err := installADBPackage(filepath.Join(t.TempDir(), "missing.apk")); err == nil {
		t.Fatal("missing APK accepted")
	}
}

// --- G route arg guards (op_comment.go, op_inspect_address_context.go, op_trace_application_feature.go) ---

func TestR3L11GRouteArgGuards(t *testing.T) {
	t.Setenv("LRECON_AT", "")
	t.Setenv("LRECON_NAME", "")
	if _, err := runOp("inspect_address_context", r3l11Test1); err == nil || !strings.Contains(err.Error(), "LRECON_AT") {
		t.Fatalf("inspect_address_context no-arg = %v", err)
	}
	if _, err := runOp("trace_application_feature", r3l11Test1); err == nil || !strings.Contains(err.Error(), "job needs") {
		t.Fatalf("trace_application_feature no-job = %v", err)
	}
	// comment's ghidraGate kicks in before the JSON job path: since the target is not native
	// it returns skip (it never reaches the job field check): both are valid refusals.
	cv, cerr := runOp("comment", r3l11Job(t, map[string]any{"address": "0x1000"}))
	if cerr != nil {
		if !strings.Contains(cerr.Error(), "text") {
			t.Fatalf("comment missing text error = %v", cerr)
		}
	} else {
		m := r3l11Map(t, cv)
		if m["skipped"] == nil || !strings.Contains(m["skipped"].(string), "decompiler") {
			t.Fatalf("comment skip = %v", m)
		}
	}
	t.Setenv("LRECON_AT", "0x401000")
	if got, err := nativeHexArg(); err != nil || got != "0x401000" {
		t.Fatalf("nativeHexArg = %q / %v", got, err)
	}
	t.Setenv("LRECON_AT", "4198400")
	if got, err := nativeHexArg(); err != nil || got != "0x401000" {
		t.Fatalf("nativeHexArg decimal = %q / %v", got, err)
	}
}
