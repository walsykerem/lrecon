package main

// Tur 5, lane 03: gercek simulasyon testleri. Her test uretim kodundaki gercek
// bir yolu, anlamli girdiyle, gozlemlenebilir bir ciktiyi iddia ederek calistirir.

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---------- op_inspect_adb_device.go:其一 getprop cagrisi, 4 konumlu alan ----------

// fakeADBDeviceProps, inspect_adb_device'in tek shell cagrisinda dondurulen
// getprop satirlarini uretir: bos bir alan kaydirilmamali.
func fakeADBDeviceProps(t *testing.T, props string) {
	t.Helper()
	body := `case "$*" in
  version|"version") printf 'Android Debug Bridge version 1.0.41\n' ;;
  devices|"devices -l") printf 'List of devices attached\nR58M\tdevice\n\n' ;;
  *"getprop ro.product.model"*) printf '%b' '` + props + `' ;;
  *) printf '' ;;
esac`
	rtFakeTool(t, "adb", body)
}

func TestTur5Go03InspectADBDeviceFourProps(t *testing.T) {
	// 2. satir bos: fingerprint bos kalir, debuggable 4. slotta durur.
	fakeADBDeviceProps(t, "Pixel 9\n35\n\n1\n")
	v, err := inspectADBDevice("")
	if err != nil {
		t.Fatal(err)
	}
	p, ok := v.(rtADBDeviceProps)
	if !ok {
		t.Fatalf("result type %T", v)
	}
	if p.Serial != "R58M" || p.Model != "Pixel 9" || p.SDK != "35" || p.Fingerprint != "" || p.Debuggable != "1" {
		t.Fatalf("props = %+v, want serial/model/sdk set, empty fingerprint, debuggable=1", p)
	}
}

func TestTur5Go03InspectADBDeviceNoToolRefuses(t *testing.T) {
	rtNoTools(t)
	v, err := inspectADBDevice("")
	if err != nil {
		t.Fatalf("no-tool must be a skip, not an error: %v", err)
	}
	if v == nil {
		t.Fatal("no-tool must return a skip result")
	}
}

// ---------- op_list_architectures.go: thin/fat/skip ----------

func TestTur5Go03ListArchitecturesThinRealSlice(t *testing.T) {
	// /Users/keremurhan/kalitetest/test1 gercek bir Mach-O dosyasi.
	const target = "/Users/keremurhan/kalitetest/test1"
	if _, err := os.Stat(target); err != nil {
		t.Skipf("gercek hedef yok: %v", err)
	}
	v, err := runOp("list_architectures", target)
	if err != nil {
		t.Fatal(err)
	}
	b, err := metaCanonical(v)
	if err != nil {
		t.Fatal(err)
	}
	var res struct {
		Format        string `json:"format"`
		Slices        int    `json:"slices"`
		Architectures []struct {
			Arch  string `json:"arch"`
			Align uint32 `json:"align"`
			Size  int64  `json:"size"`
		} `json:"architectures"`
	}
	if err := json.Unmarshal(b, &res); err != nil {
		t.Fatal(err)
	}
	if res.Slices != 1 || res.Format == "" || len(res.Architectures) != 1 {
		t.Fatalf("thin result = %+v, want 1 slice", res)
	}
	if res.Architectures[0].Arch == "" || res.Architectures[0].Size <= 0 {
		t.Fatalf("thin row = %+v, want a real arch and positive size", res.Architectures[0])
	}
}

func TestTur5Go03ListArchitecturesRejectsNonMacho(t *testing.T) {
	// Duz metin dosyasi: op skipf ile "not Mach-O" donmeli, hata degil.
	p := writeTemp(t, "plain.txt", []byte("not a macho at all\n"))
	v, err := runOp("list_architectures", p)
	if err != nil {
		t.Fatal(err)
	}
	b, err := metaCanonical(v)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "not Mach-O") {
		t.Fatalf("non-macho result = %s, want an honest skip", b)
	}
}

// ---------- op_correlate_static_and_runtime.go: .ips uuid birlestirme ----------

func TestTur5Go03MetaNormUUID(t *testing.T) {
	for in, want := range map[string]string{
		"  AB-CD-EF  ": "abcdef",
		"abcdef":       "abcdef",
		"":             "",
	} {
		if got := metaNormUUID(in); got != want {
			t.Errorf("metaNormUUID(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestTur5Go03MetaCrashImagesTwoJSONObjects(t *testing.T) {
	// Bir .ips dosyasi: baslik JSON'u + rapor JSON'u. usedImages ikincisinde.
	b := []byte(`{"app_name":"Fixture"}` + "\n" +
		`{"procName":"Fixture","osVersion":"24.1","usedImages":[{"name":"A","uuid":"AA-BB","arch":"arm64"},7,{"name":"B","uuid":"ccdd"}]}`)
	imgs, report, err := metaCrashImages(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(imgs) != 2 || imgs[0].Name != "A" || imgs[0].UUID != "AA-BB" || imgs[1].Name != "B" {
		t.Fatalf("images = %+v, want 2 well-formed records (non-object skipped)", imgs)
	}
	if report["procName"] != "Fixture" || report["osVersion"] != "24.1" {
		t.Fatalf("report = %+v, want the body JSON", report)
	}
}

func TestTur5Go03MetaStaticImagesUUIDSources(t *testing.T) {
	// Fat: slice satirlarindaki uuid; thin: ust dizeyi UUID.
	fat := Digest{SliceInfo: []string{
		"arm64 minos=14.0 uuid AA-BB exports=1",
		"x86_64 minos=13.0 uuid CCDD exports=2",
		"armv7 minos=13.0 exports=1",
	}}
	got := metaStaticImages(fat)
	if len(got) != 2 || got[0].Arch != "arm64" || got[0].UUID != "AA-BB" || got[1].UUID != "CCDD" {
		t.Fatalf("fat images = %+v", got)
	}
	thin := Digest{UUID: "eeff"}
	got = metaStaticImages(thin)
	if len(got) != 1 || got[0].UUID != "eeff" {
		t.Fatalf("thin images = %+v", got)
	}
}

func TestTur5Go03CorrelateVerdicts(t *testing.T) {
	// Gercek bir Mach-O uzerinden statik UUID elde et, then crash report ile
	// birebir / hic / birden fazla eslesme durumlarini ayri ayri besle.
	const target = "/Users/keremurhan/kalitetest/test1"
	if _, err := os.Stat(target); err != nil {
		t.Skipf("gercek hedef yok: %v", err)
	}
	d, err := loadDigest(target)
	if err != nil || d.UUID == "" {
		t.Skipf("hedefin UUID'si okunamadi: %v", err)
	}
	crash := func(uuids ...string) string {
		var imgs []string
		for _, u := range uuids {
			imgs = append(imgs, `{"name":"X","uuid":"`+u+`","arch":"arm64"}`)
		}
		return writeTemp(t, "crash.ips", []byte(`{"app_name":"F"}`+"\n"+
			`{"procName":"F","usedImages":[`+strings.Join(imgs, ",")+`]}`))
	}
	metaTestState(t)

	// 1 eslesme -> match.
	m, err := runOp("correlate_static_and_runtime", metaTestArg(t, map[string]any{"file": target, "crash": crash(d.UUID)}))
	if err != nil {
		t.Fatal(err)
	}
	mj, _ := metaCanonical(m)
	var r struct {
		Matches int    `json:"matches"`
		Verdict string `json:"verdict"`
	}
	if err := json.Unmarshal(mj, &r); err != nil {
		t.Fatal(err)
	}
	if r.Matches != 1 || !strings.Contains(r.Verdict, "matches the crashing") {
		t.Fatalf("single-match = %s", mj)
	}

	// 0 eslesme -> different build.
	m, err = runOp("correlate_static_and_runtime", metaTestArg(t, map[string]any{"file": target, "crash": crash("0000-0000")}))
	if err != nil {
		t.Fatal(err)
	}
	mj, _ = metaCanonical(m)
	if err := json.Unmarshal(mj, &r); err != nil {
		t.Fatal(err)
	}
	if r.Matches != 0 || !strings.Contains(r.Verdict, "different build") {
		t.Fatalf("zero-match = %s", mj)
	}

	// crash arg yok -> hiren red.
	if _, err := runOp("correlate_static_and_runtime", metaTestArg(t, map[string]any{"file": target})); err == nil ||
		!strings.Contains(err.Error(), `needs "crash"`) {
		t.Fatalf("missing crash = %v, want an honest refusal", err)
	}
}

// ---------- op_binary_session.go: session yazimi, reopen, cursor ----------

func TestTur5Go03BinarySessionPersistReopenAndSwitch(t *testing.T) {
	metaTestState(t)
	const t1 = "/Users/keremurhan/kalitetest/test1"
	const t2 = "/Users/keremurhan/kalitetest/test2"
	for _, p := range []string{t1, t2} {
		if _, err := os.Stat(p); err != nil {
			t.Skipf("gercek hedef yok: %v", err)
		}
	}
	res, err := runOp("binary_session", t1)
	if err != nil {
		t.Fatal(err)
	}
	m, _ := metaCanonical(res)
	var first map[string]any
	if err := json.Unmarshal(m, &first); err != nil {
		t.Fatal(err)
	}
	if first["state"] != "opened" || first["adapter_ok"] != true || first["session_persisted"] != true {
		t.Fatalf("first session = %s", m)
	}
	sessionFile, _ := first["session_file"].(string)
	if _, err := os.Stat(sessionFile); err != nil {
		t.Fatalf("session not persisted: %v", err)
	}

	// cursor yaz, sonra ayni dosyayi tekrar ac: cursor korunmali.
	var s nativeSession
	b, _ := os.ReadFile(sessionFile)
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	s.Cursor = 0x1234
	s.Procedure = "entry"
	if err := saveSession(s); err != nil {
		t.Fatal(err)
	}
	res, err = runOp("binary_session", t1)
	if err != nil {
		t.Fatal(err)
	}
	m, _ = metaCanonical(res)
	var reopened map[string]any
	if err := json.Unmarshal(m, &reopened); err != nil {
		t.Fatal(err)
	}
	if reopened["state"] != "reopened" {
		t.Fatalf("same-target reopen = %s, want reopened", m)
	}
	b, _ = os.ReadFile(sessionFile)
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	if s.Cursor != 0x1234 || s.Procedure != "entry" {
		t.Fatalf("reopen dropped the cursor: cursor=%#x procedure=%q", s.Cursor, s.Procedure)
	}

	// Baska dosyaya gecis: cursor sifirlanmali, onceki belge raporlanmali.
	res, err = runOp("binary_session", t2)
	if err != nil {
		t.Fatal(err)
	}
	m, _ = metaCanonical(res)
	var switched map[string]any
	if err := json.Unmarshal(m, &switched); err != nil {
		t.Fatal(err)
	}
	if switched["state"] != "opened" || switched["previous_document"] != t1 {
		t.Fatalf("switch = %s, want opened with previous_document", m)
	}
	b, _ = os.ReadFile(switchedSessionFile(t, switched))
	var s2 nativeSession
	if err := json.Unmarshal(b, &s2); err != nil {
		t.Fatal(err)
	}
	if s2.Cursor != 0 || s2.Procedure != "" {
		t.Fatalf("switch kept a stale cursor: cursor=%#x procedure=%q", s2.Cursor, s2.Procedure)
	}
}

func TestTur5Go03SessionLegacyDocument(t *testing.T) {
	// "kind" tasimayan eski session dosyasi taninmali; kind tasayan sahte
	// dosya reddedilmeli.
	dir := t.TempDir()
	legacy := filepath.Join(dir, "legacy.json")
	if err := os.WriteFile(legacy, []byte(`{"document":"/old/a.out"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if doc, ok := sessionLegacyDocument(legacy); !ok || doc != "/old/a.out" {
		t.Fatalf("legacy = %q,%v", doc, ok)
	}
	good := filepath.Join(dir, "kind.json")
	if err := os.WriteFile(good, []byte(`{"kind":"lrecon.session/1","document":"/b.out"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, ok := sessionLegacyDocument(good); ok {
		t.Fatal("a file carrying kind must not be treated as legacy")
	}
}

// ---------- op_ext_lldb_memory.go: arg kuralari, preflight ----------

func TestTur5Go03LldbPreflightRefusals(t *testing.T) {
	// Olmayan hedef -> kindIO.
	err := lldbPreflight(filepath.Join(t.TempDir(), "missing"))
	if err == nil || !strings.Contains(err.Error(), "lldb target") {
		t.Fatalf("missing preflight = %v", err)
	}
	if r, ok := err.(*extRefusal); !ok || r.kind != kindIO {
		t.Fatalf("missing preflight kind = %v", err)
	}
	// Var olan hedef, lldb yok -> kindNoEngine.
	p := writeTemp(t, "target", []byte("x"))
	rtNoTools(t)
	err = lldbPreflight(p)
	if err == nil {
		t.Fatal("preflight with no lldb must refuse")
	}
	if r, ok := err.(*extRefusal); !ok || r.kind != kindNoEngine {
		t.Fatalf("no-engine preflight kind = %v", err)
	}
}

func TestTur5Go03LldbMemoryAndExpressionNeedsArg(t *testing.T) {
	// Hedef var, lldb var (shim) ama arg yok -> needsArg; hicbir sey calistirilmaz.
	p := writeTemp(t, "target", []byte("x"))
	rtFakeTool(t, "lldb", `printf 'unexpected lldb call\n' >&2; exit 99`)
	for _, c := range []struct {
		name string
		run  func(string, []string) (any, error)
		want string
	}{
		{"lldb_memory_read", runLldbMemoryRead, "needs an address"},
		{"lldb_memory_write", runLldbMemoryWrite, "needs ADDR BYTE or ADDR=BYTE"},
		{"lldb_expression", runLldbExpression, "needs an expression"},
		{"lldb_process_attach", runLldbProcessAttach, "needs a pid"},
	} {
		_, err := c.run(p, nil)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s no args = %v, want %q", c.name, err, c.want)
			continue
		}
		if r, ok := err.(*extRefusal); !ok || r.kind != kindNeedsArg {
			t.Errorf("%s no args kind = %v, want needsArg", c.name, err)
		}
	}
}

func TestTur5Go03LldbMemoryWriteForms(t *testing.T) {
	// lldb shim, verilen komutu bir dosyaya yazsin; writer'in hangi formu
	// sectigini gozlemlemek icin ( writes / reads / none ).
	p := writeTemp(t, "target", []byte("x"))
	seen := filepath.Join(t.TempDir(), "cmd.txt")
	rtFakeTool(t, "lldb", `cmd=""; prev=""; for a in "$@"; do if [ "$prev" = "-o" ]; then cmd="$a"; fi; prev="$a"; done; printf '%s\n' "$cmd" > `+seen+`; exit 0`)

	readForm := func() string {
		t.Helper()
		b, err := os.ReadFile(seen)
		if err != nil {
			return ""
		}
		return strings.Split(string(b), "\n")[0]
	}
	// Bare address -> read formu ( mutate etmez ).
	if _, err := runLldbMemoryWrite(p, []string{"0x1000"}); err != nil {
		t.Fatal(err)
	}
	if got := readForm(); !strings.HasPrefix(got, "memory read ") {
		t.Fatalf("bare address command = %q, want a read", got)
	}
	// ADDR=BYTE -> write formu.
	if _, err := runLldbMemoryWrite(p, []string{"0x1000=0x41"}); err != nil {
		t.Fatal(err)
	}
	if got := readForm(); !strings.HasPrefix(got, "memory write ") {
		t.Fatalf("ADDR=BYTE command = %q, want a write", got)
	}
	// Iki arg -> write formu.
	if _, err := runLldbMemoryWrite(p, []string{"0x1000", "0x41"}); err != nil {
		t.Fatal(err)
	}
	if got := readForm(); got != "memory write 0x1000 0x41" {
		t.Fatalf("two-arg command = %q", got)
	}
}

// ---------- op_inspect_elf_notes.go: bytes0 gercek NUL temizleme ----------

func TestTur5Go03Bytes0TrimsTrailingNulsOnly(t *testing.T) {
	for in, want := range map[string]string{
		"Go\x00\x00": "Go",
		"a\x00b\x00": "a\x00b",
		"\x00\x00":   "",
		"plain":      "plain",
	} {
		if got := string(bytes0([]byte(in))); got != want {
			t.Errorf("bytes0(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestTur5Go03InspectELFNotesSkipOnNoNotes(t *testing.T) {
	// Duz metin: ELF degil -> hata, skip degil.
	p := writeTemp(t, "plain.txt", []byte("not elf\n"))
	if _, err := runOp("inspect_elf_notes", p); err == nil || !strings.Contains(err.Error(), "not ELF") {
		t.Fatalf("non-ELF = %v, want a not-ELF error", err)
	}
}

// ---------- op_inspect_pe_certificates.go: digest karari ----------

func TestTur5Go03PeVerifyDigestDecisions(t *testing.T) {
	// Bir PE uzerinde gercek image hash'ini hesapla, sonra signer'in messageDigest
	// alanini bilerek match/mismatch yap.
	b := peFixtureMinimal(t)
	p, err := openPEBytes(b)
	if err != nil {
		t.Skipf("fixture PE acilamadi: %v", err)
	}
	want, err := peImageHash(p, "sha256", 0, 0)
	if err != nil || len(want) != 32 {
		t.Fatalf("peImageHash = %x, %v", want, err)
	}
	hexWant := hex.EncodeToString(want)
	match, err := peVerifyDigest(p, []peCertSigner{{MessageDigest: hexWant, DigestAlgorithm: oidSHA256}}, 0, 0)
	if err != nil || match != "match" {
		t.Fatalf("matching digest = %q, %v; want match", match, err)
	}
	mm, err := peVerifyDigest(p, []peCertSigner{{MessageDigest: strings.Repeat("00", 32), DigestAlgorithm: oidSHA256}}, 0, 0)
	if err != nil || !strings.HasPrefix(mm, "mismatch:") {
		t.Fatalf("mismatching digest = %q, %v", mm, err)
	}
	none, err := peVerifyDigest(p, nil, 0, 0)
	if err != nil || none != "no signer" {
		t.Fatalf("no signer = %q, %v", none, err)
	}
}

// peFixtureMinimal, openPEBytes'in kabul ettigi en kucuk PE'yi uretir.
func peFixtureMinimal(t *testing.T) []byte {
	t.Helper()
	b := make([]byte, 0x300)
	copy(b, []byte("MZ"))
	binary.LittleEndian.PutUint32(b[0x3c:], 0x80) // e_lfanew
	copy(b[0x80:], []byte("PE\x00\x00"))
	// COFF header: machine amd64, 1 section, optional header 0xf0 boyutunda.
	binary.LittleEndian.PutUint16(b[0x84:], 0x8664)
	binary.LittleEndian.PutUint16(b[0x86:], 1)
	binary.LittleEndian.PutUint16(b[0x94:], 0xf0)
	binary.LittleEndian.PutUint16(b[0x96:], 0x22) // EXECUTABLE_IMAGE
	// Optional header magic PE32+, sizeOfHeaders 0x200, checksum at opt+64.
	binary.LittleEndian.PutUint16(b[0x98:], 0x20b)
	binary.LittleEndian.PutUint32(b[0x98+60:], 0x200)
	// Data directory[4] (security) offset: optOff+112+4*8 = 0x108.
	// Section header at 0x188: .text, raw offset 0x200, raw size 0x100.
	copy(b[0x188:], []byte(".text\x00\x00\x00"))
	binary.LittleEndian.PutUint32(b[0x188+16:], 0x100) // VirtualSize
	binary.LittleEndian.PutUint32(b[0x188+20:], 0x1000)
	binary.LittleEndian.PutUint32(b[0x188+24:], 0x100) // SizeOfRawData
	binary.LittleEndian.PutUint32(b[0x188+28:], 0x200) // PointerToRawData
	for i := 0x200; i < 0x300; i++ {
		b[i] = byte(i)
	}
	return b
}

// oidSHA256, 2.16.840.1.101.3.4.2.1 (peDigestNames icindeki sha256 anahtari).
var oidSHA256 = "sha256"

// ---------- op_project_apple_application_graph.go: bundle/plist/canli graph ----------

func TestTur5Go03AppleBundlePlistLookup(t *testing.T) {
	root := t.TempDir()
	// Once Contents/Info.plist, yoksa Info.plist.
	mac := filepath.Join(root, "App.app")
	if err := os.MkdirAll(filepath.Join(mac, "Contents"), 0o755); err != nil {
		t.Fatal(err)
	}
	macPlist := filepath.Join(mac, "Contents", "Info.plist")
	if err := os.WriteFile(macPlist, []byte("plist"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := appleBundlePlist(mac); got != macPlist {
		t.Fatalf("macOS plist = %q, want %q", got, macPlist)
	}
	ios := filepath.Join(root, "iOS.app")
	if err := os.MkdirAll(ios, 0o755); err != nil {
		t.Fatal(err)
	}
	iosPlist := filepath.Join(ios, "Info.plist")
	if err := os.WriteFile(iosPlist, []byte("plist"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := appleBundlePlist(ios); got != iosPlist {
		t.Fatalf("iOS plist = %q, want %q", got, iosPlist)
	}
	if got := appleBundlePlist(writeTemp(t, "file", []byte("x"))); got != "" {
		t.Fatalf("plist of a regular file = %q, want empty", got)
	}
}

func TestTur5Go03ProjectAppleGraphNoKeysRefuses(t *testing.T) {
	// Hic plist key'i, asari veya unpacked node'u olmayan bir dosya reddedilir.
	p := writeTemp(t, "plain.txt", []byte("nothing here\n"))
	_, err := runOp("project_apple_application_graph", p)
	if err == nil || !strings.Contains(err.Error(), "has no Info.plist keys") {
		t.Fatalf("no-keys = %v, want an honest refusal", err)
	}
}

// ---------- msvcrti.go: gercek COFF uretimi, reason rejimi ----------

func TestTur5Go03MsvcRDTPureHelpers(t *testing.T) {
	// Saf fonksiyonlar uzerinde gercek girdi/deger iddiasi; cross-compile
	// zincirine bagli degil.
	if !msvcMachine(0x8664) || !msvcMachine(0x14c) {
		t.Fatal("msvcMachine must accept amd64 and i386")
	}
	for _, machine := range []uint16{0, 0x14d, 0xffff} {
		if msvcMachine(machine) {
			t.Fatalf("msvcMachine(%#x) must refuse an unsupported machine", machine)
		}
	}
	if got := msvcPointerSize(0x8664); got != 8 {
		t.Fatalf("msvcPointerSize(amd64)=%d, want 8", got)
	}
	if got := msvcPointerSize(0x14c); got != 4 {
		t.Fatalf("msvcPointerSize(i386)=%d, want 4", got)
	}
	if msvcReasonAbsent == "" || msvcReasonCol == "" || msvcReasonImage == "" || msvcReasonName == "" {
		t.Fatal("msvcrti reason constants must be non-empty")
	}
}

// ---------- testdata/ops.json yonlendirmesi: kayitli op'lar ----------

func TestTur5Go03OpsJSONRoutesForMyOps(t *testing.T) {
	// lrecon'un testdata/ops.json contract tablosu, register edilmis op'larin
	// route'larini kapsar. Test, tablodaki gercek satirlari okur.
	b, err := os.ReadFile("testdata/ops.json")
	if err != nil {
		t.Skipf("ops.json yok: %v", err)
	}
	var doc struct {
		Ops []struct {
			Name  string `json:"name"`
			Route string `json:"route"`
		} `json:"ops"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("ops.json decode: %v", err)
	}
	table := make(map[string]string, len(doc.Ops))
	for _, o := range doc.Ops {
		table[o.Name] = o.Route
	}
	for name, wantRoute := range map[string]string{
		"list_architectures":              "L",
		"inspect_elf_notes":               "L",
		"inspect_pe_certificates":         "L",
		"inspect_adb_device":              "Y",
		"binary_session":                  "L",
		"correlate_static_and_runtime":    "L",
		"project_apple_application_graph": "L",
	} {
		r, ok := table[name]
		if !ok {
			t.Fatalf("ops.json has no row for %s", name)
		}
		if r != wantRoute {
			t.Fatalf("ops.json %s route = %q, want %q", name, r, wantRoute)
		}
	}
}

// switchedSessionFile reads session_file from the second binary_session result:
// a document switch reopens the session in a different state file.
func switchedSessionFile(t *testing.T, res map[string]any) string {
	t.Helper()
	p, _ := res["session_file"].(string)
	if p == "" {
		t.Fatalf("no session_file in switch result: %v", res)
	}
	return p
}
