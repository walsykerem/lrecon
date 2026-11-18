package main

// Round 2, lane 11: real simulation tests for 26 files. All fixtures are
// created under t.TempDir(); production code is not modified.

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

func r2l11Run(t *testing.T, name, path string) any {
	t.Helper()
	v, err := runOp(name, path)
	if err != nil {
		t.Fatalf("%s(%s): %v", name, path, err)
	}
	return v
}

func r2l11Map(t *testing.T, v any) map[string]any {
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

func r2l11Get(t *testing.T, m map[string]any, path ...any) any {
	t.Helper()
	var cur any = m
	for _, k := range path {
		switch key := k.(type) {
		case string:
			mm, ok := cur.(map[string]any)
			if !ok {
				t.Fatalf("walk %v: %#v not object", path, cur)
			}
			cur = mm[key]
		case int:
			a, ok := cur.([]any)
			if !ok || key >= len(a) {
				t.Fatalf("walk %v: %#v not array[%d]", path, cur, key)
			}
			cur = a[key]
		}
	}
	return cur
}

func r2l11Num(t *testing.T, v any) float64 {
	t.Helper()
	f, ok := v.(float64)
	if !ok {
		t.Fatalf("%v is not number", v)
	}
	return f
}

func r2l11Skip(t *testing.T, v any) string {
	t.Helper()
	m := r2l11Map(t, v)
	s, _ := m["skipped"].(string)
	if s == "" {
		t.Fatalf("not a skip: %+v", v)
	}
	return s
}

// --- STATIC FORMAT (G1): safetensors/GGUF, PE, wasm, Mach-O ---

func TestR2L11ModelArtifact(t *testing.T) {
	// Safetensors: real JSON header + dtype/shape/offset; bad offset is rejected.
	h := []byte(`{"w":{"dtype":"F32","shape":[2,3],"data_offsets":[0,24]},"__metadata__":{"format":"pt"}}`)
	b := append(sf64(uint64(len(h))), h...)
	b = append(b, make([]byte, 24)...)
	p := sfWrite(t, "m.safetensors", b)
	m := r2l11Map(t, r2l11Run(t, "inspect_model_artifact", p))
	if m["format"] != "safetensors" {
		t.Fatalf("format=%v", m["format"])
	}
	tensors := r2l11Get(t, m, "tensors").([]any)
	if len(tensors) != 1 || r2l11Get(t, m, "tensors", 0, "dtype") != "F32" {
		t.Fatalf("tensors=%v", tensors)
	}

	bad := append(sf64(uint64(len(h))), h...)
	bad = append(bad, make([]byte, 2)...)
	if _, err := runOp("inspect_model_artifact", sfWrite(t, "bad.safetensors", bad)); err == nil || !strings.Contains(err.Error(), "spans") {
		t.Fatalf("bad safetensors error=%v", err)
	}

	// GGUF: version, typed KV + array, tensor shape/type.
	g := []byte("GGUF")
	g = append(g, sf32(3)...)
	g = append(g, sf64(1)...)
	g = append(g, sf64(2)...)
	kv := func(key string, typ uint32, value []byte) {
		g = append(g, sfGGUFString(key)...)
		g = append(g, sf32(typ)...)
		g = append(g, value...)
	}
	kv("general.name", 8, sfGGUFString("demo"))
	arr := append(sf32(8), sf64(2)...)
	arr = append(arr, sfGGUFString("a")...)
	arr = append(arr, sfGGUFString("b")...)
	kv("tokens", 9, arr)
	g = append(g, sfGGUFString("blk.0.weight")...)
	g = append(g, sf32(2)...)
	g = append(g, sf64(2)...)
	g = append(g, sf64(3)...)
	g = append(g, sf32(0)...)
	g = append(g, sf64(0)...)
	gm := r2l11Map(t, r2l11Run(t, "inspect_model_artifact", sfWrite(t, "m.gguf", g)))
	if gm["format"] != "gguf" || r2l11Num(t, gm["version"]) != 3 {
		t.Fatalf("gguf header=%v", gm)
	}
	if r2l11Get(t, gm, "metadata", 0, "value") != "demo" {
		t.Fatalf("metadata=%v", gm["metadata"])
	}
	if r2l11Get(t, gm, "tensors", 0, "ggml_type_name") != "F32" {
		t.Fatalf("tensors=%v", gm["tensors"])
	}
}

func TestR2L11PELoadConfigAndResources(t *testing.T) {
	// Load config: SecurityCookie + SEH + GuardFlags CFG/CastGuard bits.
	lc := make([]byte, 0x120)
	binary.LittleEndian.PutUint32(lc, uint32(len(lc)))
	binary.LittleEndian.PutUint64(lc[0x58:], 0x140008000)
	binary.LittleEndian.PutUint64(lc[0x60:], 0x140009000)
	binary.LittleEndian.PutUint64(lc[0x68:], 3)
	binary.LittleEndian.PutUint32(lc[0x90:], 0x100|0x800000)
	pe := sfPE(t, []sfSection{{".lc", 0x1000, lc}}, map[int][2]uint32{peDirLoadConfig: {0x1000, uint32(len(lc))}})
	m := r2l11Map(t, r2l11Run(t, "inspect_pe_load_config", sfWrite(t, "lc.exe", pe)))
	if m["present"] != true || m["gs"] != true || m["safe_seh"] != true || m["cfg"] != true || m["cast_guard"] != true {
		t.Fatalf("load config=%v", m)
	}
	found := false
	for _, n := range r2l11Get(t, m, "guard_flag_names").([]any) {
		if n == "CASTGUARD_PRESENT" {
			found = true
		}
	}
	if !found {
		t.Fatalf("guard names=%v", m["guard_flag_names"])
	}

	// Resource tree: type -> name -> language, sizes checked.
	rsrc := make([]byte, 0x200)
	binary.LittleEndian.PutUint16(rsrc[14:], 1)          // 1 ID entry
	binary.LittleEndian.PutUint32(rsrc[16:], 3)          // RT_MANIFEST
	binary.LittleEndian.PutUint32(rsrc[20:], 0x80000040) // child at 0x40
	binary.LittleEndian.PutUint16(rsrc[0x40+14:], 1)
	binary.LittleEndian.PutUint32(rsrc[0x40+16:], 1)
	binary.LittleEndian.PutUint32(rsrc[0x40+20:], 0x80000080) // child at 0x80
	binary.LittleEndian.PutUint16(rsrc[0x80+12:], 1)          // 1 named lang
	binary.LittleEndian.PutUint32(rsrc[0x80+16:], 1033)
	binary.LittleEndian.PutUint32(rsrc[0x80+20:], 0xC0) // data entry
	binary.LittleEndian.PutUint32(rsrc[0xC0:], 0x1100)  // data RVA (inside section)
	binary.LittleEndian.PutUint32(rsrc[0xC4:], 4)
	copy(rsrc[0x100:], "ICON")
	pe2 := sfPE(t, []sfSection{{".rsrc", 0x1000, rsrc}}, map[int][2]uint32{peDirResource: {0x1000, uint32(len(rsrc))}})
	rm := r2l11Map(t, r2l11Run(t, "inspect_pe_resources", sfWrite(t, "rsrc.exe", pe2)))
	if r2l11Get(t, rm, "types", 0, "kind") != "ICON" {
		t.Fatalf("resource types=%v", rm["types"])
	}
	if r2l11Num(t, r2l11Get(t, rm, "types", 0, "entries", 0, "languages", 0, "size")) != 4 {
		t.Fatalf("lang size=%v", rm["types"])
	}
}

func TestR2L11PEImportsAndCertificates(t *testing.T) {
	// Imports: allowed PE, no imports -> 0 rows; text -> skip.
	pe := sfPE(t, []sfSection{{".text", 0x1000, make([]byte, 0x200)}}, nil)
	im := r2l11Map(t, r2l11Run(t, "inspect_pe_imports", sfWrite(t, "plain.exe", pe)))
	if r2l11Num(t, im["total"]) != 0 {
		t.Fatalf("imports=%v", im)
	}
	if !strings.Contains(r2l11Skip(t, r2l11Run(t, "inspect_pe_imports", sfWrite(t, "x.txt", []byte("hello")))), "not PE") {
		t.Fatal("text must skip PE imports")
	}

	// Certificates: real self-signed PKCS#7 + Authenticode digest match/mismatch.
	certDER := sfSelfSigned(t)
	xc, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}
	certOff := len(sfPE(t, nil, nil)) // sectionless PE end = 0x400, enough space inside security dir
	tableSize := len(sfWinCert(sfPKCS7(t, certDER, xc.RawSubject, make([]byte, 32))))
	pe2 := sfPE(t, nil, map[int][2]uint32{peDirSecurity: {uint32(certOff), uint32(tableSize)}})
	digest := sfAuthenticodeDigest(pe2, certOff)
	table := sfWinCert(sfPKCS7(t, certDER, xc.RawSubject, digest))
	pe2 = append(pe2, table...)
	cm := r2l11Map(t, r2l11Run(t, "inspect_pe_certificates", sfWrite(t, "signed.exe", pe2)))
	if r2l11Get(t, cm, "entries", 0, "image_digest") != "match" {
		t.Fatalf("cert digest=%v", cm["entries"])
	}
	if !strings.Contains(r2l11Get(t, cm, "entries", 0, "certificates", 0, "subject").(string), "lrecon fixture") {
		t.Fatalf("cert subject=%v", cm["entries"])
	}

	// Corrupt messageDigest -> mismatch, not silently accepted.
	bad := sfPE(t, nil, map[int][2]uint32{peDirSecurity: {uint32(certOff), uint32(tableSize)}})
	bad = append(bad, sfWinCert(sfPKCS7(t, certDER, xc.RawSubject, make([]byte, 32)))...)
	bm := r2l11Map(t, r2l11Run(t, "inspect_pe_certificates", sfWrite(t, "bad.exe", bad)))
	if d, _ := r2l11Get(t, bm, "entries", 0, "image_digest").(string); !strings.HasPrefix(d, "mismatch:") {
		t.Fatalf("bad digest=%q", d)
	}
}

func TestR2L11WasmAndMachOSignature(t *testing.T) {
	// Wasm: real module, section table + import/export; truncated module rejected.
	wm := r2l11Map(t, r2l11Run(t, "inspect_wasm_artifact", sfWrite(t, "a.wasm", sfWasmModule())))
	if r2l11Num(t, wm["version"]) != 1 || len(r2l11Get(t, wm, "sections").([]any)) != 5 {
		t.Fatalf("wasm=%v", wm)
	}
	if r2l11Get(t, wm, "imports", 0, "module") != "env" || r2l11Get(t, wm, "exports", 0, "name") != "run" {
		t.Fatalf("wasm import/export=%v / %v", wm["imports"], wm["exports"])
	}
	if _, err := runOp("inspect_wasm_artifact", sfWrite(t, "cut.wasm", sfWasmModule()[:12])); err == nil {
		t.Fatal("cut wasm must fail")
	}

	// Mach-O page hash: a valid SuperBlob is verified, single-byte corruption is detected.
	sm := r2l11Map(t, r2l11Run(t, "inspect_signature", sfWrite(t, "signed", sfMachOWithSignature(t))))
	v := sm["verification"].(map[string]any)
	if v["hashes_ok"] != true || r2l11Num(t, v["pages_checked"]) != 1 {
		t.Fatalf("signature=%v", v)
	}
	broken := sfMachOWithSignature(t)
	broken[100] ^= 0xff
	tm := r2l11Map(t, r2l11Run(t, "inspect_signature", sfWrite(t, "tampered", broken)))
	tv := tm["verification"].(map[string]any)
	if tv["hashes_ok"] != false || len(r2l11Get(t, tv, "mismatched_pages").([]any)) == 0 {
		t.Fatalf("tampered verification=%v", tv)
	}
}

// --- NATIVE (G2) ---

func TestR2L11NativeAPI(t *testing.T) {
	// 150 dynamic symbols -> 100 rows + truncated; 5 -> no truncation.
	big := r2l11Map(t, r2l11Run(t, "inspect_native_api", nativeAPIDynELF(t, 150)))
	if r2l11Num(t, big["imports"]) != 150 || r2l11Num(t, big["shown"]) != 100 || big["truncated"] != true {
		t.Fatalf("native api big=%v", big)
	}
	small := r2l11Map(t, r2l11Run(t, "inspect_native_api", nativeAPIDynMachO(t, 5)))
	if r2l11Num(t, small["imports"]) != 5 {
		t.Fatalf("native api small=%v", small)
	}
	empty := r2l11Map(t, r2l11Run(t, "inspect_native_api", sfWrite(t, "plain.exe", sfPE(t, nil, nil))))
	if r2l11Num(t, empty["imports"]) != 0 || !strings.Contains(empty["note"].(string), "no imported symbols") {
		t.Fatalf("native api empty=%v", empty)
	}
}

func TestR2L11NativeExportsLoadImageAndGate(t *testing.T) {
	// PE -> normal response; text -> skip; Mach-O -> forward to inspect_macho.
	pe := sfWrite(t, "p.exe", sfPE(t, nil, nil))
	em := r2l11Map(t, r2l11Run(t, "inspect_native_exports", pe))
	if em["kind"] != "pe" {
		t.Fatalf("exports PE=%v", em)
	}
	if !strings.Contains(r2l11Skip(t, r2l11Run(t, "inspect_native_exports", sfWrite(t, "x.txt", []byte("hi")))), "not a PE") {
		t.Fatal("text should skip exports")
	}

	// load_image: read refused for an on-disk file; directory -> error.
	if !strings.Contains(r2l11Skip(t, r2l11Run(t, "inspect_native_load_image", pe)), "never maps a loaded image") {
		t.Fatal("load_image must skip on-disk reads")
	}
	if _, err := runOp("inspect_native_load_image", t.TempDir()); err == nil || !strings.Contains(err.Error(), "is a directory") {
		t.Fatalf("load_image dir error=%v", err)
	}

	// route-G arg requirement (LRECON_NAME / LRECON_AT) — without ghidra an arg error must come.
	t.Setenv("LRECON_NAME", "")
	t.Setenv("LRECON_AT", "")
	if _, err := runOp("inspect_native_data_type", pe); err == nil || !strings.Contains(err.Error(), "LRECON_NAME") {
		t.Fatalf("data_type missing name error=%v", err)
	}
	if _, err := runOp("inspect_native_instruction", pe); err == nil || !strings.Contains(err.Error(), "LRECON_AT") {
		t.Fatalf("instruction missing at error=%v", err)
	}
	// dispatch_metadata takes no arg: without the ghidra engine it returns skip, not an io error.
	orig := ghidraFinder
	ghidraFinder = func() (string, string, error) { return "", "", errors.New("analyzeHeadless not found") }
	v, err := runOp("inspect_native_dispatch_metadata", pe)
	ghidraFinder = orig
	if err != nil {
		t.Fatalf("dispatch_metadata: %v", err)
	}
	if s := r2l11Skip(t, v); !strings.Contains(s, "analyzeHeadless not found") {
		t.Fatalf("dispatch_metadata skip=%q", s)
	}
}

// --- PCAP (G3) ---

func TestR2L11PcapCaptureAndFields(t *testing.T) {
	p := netcTestClassicPcap(t)
	c := r2l11Map(t, r2l11Run(t, "inspect_packet_capture", p))
	if r2l11Num(t, c["packets"]) != 4 {
		t.Fatalf("capture=%v", c)
	}
	// The alias uses the same implementation.
	c2 := r2l11Map(t, r2l11Run(t, "inspect_pcap_capture", p))
	if r2l11Num(t, c2["packets"]) != 4 || c["format"] != c2["format"] {
		t.Fatalf("alias=%v", c2)
	}
	f := r2l11Map(t, r2l11Run(t, "inspect_packet_fields", p))
	if len(r2l11Get(t, f, "frames").([]any)) != 4 {
		t.Fatalf("fields frames=%v", f["frames"])
	}
	// Among the 4 packets there should be one HTTP + one DNS + one TLS.
	app := r2l11Get(t, f, "app").(map[string]any)
	if r2l11Num(t, app["http"]) < 1 || r2l11Num(t, app["dns"]) < 1 || r2l11Num(t, app["tls"]) < 1 {
		t.Fatalf("app counts=%v", app)
	}

	// Empty capture rejection.
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runOp("inspect_packet_fields", sfWrite(t, "empty.pcap", b[:24])); err == nil || !strings.Contains(err.Error(), "no packets") {
		t.Fatalf("empty pcap error=%v", err)
	}
}

func TestR2L11PcapClientFamilyAndDedup(t *testing.T) {
	cases := []struct{ ua, ja3, want string }{
		{"curl/8.4.0", "", "curl"},
		{"Mozilla/5.0 (X11; Linux)", "", "browser"},
		{"", "3b5074b1b5d032e5620f69f9f700ff0e", "curl-tls"},
		{"", "c12f54a3f91dc7bafd92cb59fe009a35", "go-tls"},
		{"", "cd08e31494f9531f560d64c695473da9", "mozilla-tls"},
		{"X/1", "", "other"},
		{"", "", "-"},
	}
	for _, c := range cases {
		if got := netcClientFamily(c.ua, c.ja3); got != c.want {
			t.Fatalf("family(%q,%q)=%q want %q", c.ua, c.ja3, got, c.want)
		}
	}

	// Client rows from a real pcap: curl HTTP + TLS, JA3 populated.
	m := r2l11Map(t, r2l11Run(t, "inspect_pcap_client", netcTestClassicPcap(t)))
	httpRows := r2l11Get(t, m, "http_clients").([]any)
	if len(httpRows) != 1 || r2l11Get(t, m, "http_clients", 0, "family") != "curl" {
		t.Fatalf("http clients=%v", m["http_clients"])
	}
	tlsRows := r2l11Get(t, m, "tls_clients").([]any)
	if len(tlsRows) != 1 || r2l11Get(t, m, "tls_clients", 0, "sni") != "api.example.com" {
		t.Fatalf("tls clients=%v", m["tls_clients"])
	}
}

// --- DATA / WEB (G4) ---

func TestR2L11RecordedCrash(t *testing.T) {
	body := `{"exception":{"type":"EXC_BAD_ACCESS","signal":"SIGSEGV"},"faultingThread":0,` +
		`"threads":[{"frames":[{"imageIndex":0,"imageOffset":16,"symbol":"main"}]}],` +
		`"usedImages":[{"name":"Demo","path":"/x/Demo","base":4294967296}]}`
	text := `{"app_name":"Demo","bundleID":"com.demo.app","os_version":"14.0"}` + "\n" + body + "\n"
	m := r2l11Map(t, r2l11Run(t, "inspect_recorded_crash", sfWrite(t, "c.ips", []byte(text))))
	if m["app"] != "Demo" || m["bundle_id"] != "com.demo.app" {
		t.Fatalf("crash header=%v", m)
	}
	exc := r2l11Get(t, m, "exception").(map[string]any)
	if exc["type"] != "EXC_BAD_ACCESS" || r2l11Num(t, m["faulting_thread"]) != 0 {
		t.Fatalf("crash exception=%v", exc)
	}
	frame := r2l11Get(t, m, "threads", 0, "frames", 0).(map[string]any)
	if frame["offset_hex"] != "0x10" || frame["address"] != "0x100000010" {
		t.Fatalf("crash frame=%v", frame)
	}
	if _, err := runOp("inspect_recorded_crash", sfWrite(t, "one.ips", []byte(`{"a":1}`))); err == nil || !strings.Contains(err.Error(), "one JSON line") {
		t.Fatalf("one-line crash error=%v", err)
	}
}

func TestR2L11SignalDecoders(t *testing.T) {
	// Substring (name/family/modulation/channel) and numeric symbol_rate matching.
	t.Setenv("LRECON_QUERY", "")
	res := r2l11Map(t, mustSignal(t, "OOK"))
	// "OOK" appears in both name (ook-433) and family (ASK/OOK) -> 2 matches.
	if len(r2l11Get(t, res, "matches").([]any)) != 2 || r2l11Get(t, res, "matches", 0, "name") != "ook-433" {
		t.Fatalf("OOK matches=%v", res["matches"])
	}
	res = r2l11Map(t, mustSignal(t, "4800"))
	if len(r2l11Get(t, res, "matches").([]any)) != 1 || r2l11Get(t, res, "matches", 0, "name") != "fsk-narrow" {
		t.Fatalf("rate matches=%v", res["matches"])
	}
	res = r2l11Map(t, mustSignal(t, "FSK"))
	if len(r2l11Get(t, res, "matches").([]any)) != 2 {
		t.Fatalf("FSK matches=%v", res["matches"])
	}
	if _, err := inspectSignalDecoders(""); err == nil || !strings.Contains(err.Error(), "needs a query") {
		t.Fatalf("empty query error=%v", err)
	}
	// A custom decoder table: LRECON_QUERY override + file-based table.
	tbl := `[{"name":"custom","family":"X","modulation":"Y","symbol_rate":7,"channel":"Z"}]`
	t.Setenv("LRECON_DECODERS", sfWrite(t, "decoders.json", []byte(tbl)))
	t.Setenv("LRECON_QUERY", "custom")
	res = r2l11Map(t, mustSignal(t, "ignored"))
	if len(r2l11Get(t, res, "matches").([]any)) != 1 || r2l11Get(t, res, "matches", 0, "name") != "custom" {
		t.Fatalf("custom table=%v", res["matches"])
	}
}

func mustSignal(t *testing.T, q string) any {
	t.Helper()
	v, err := inspectSignalDecoders(q)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestR2L11WebNetworkCapture(t *testing.T) {
	// HAR 1.2: 2 entry, content.size + bodySize fallback, host extraction, toplamlar.
	har := `{"log":{"version":"1.2","creator":{"name":"probe","version":"2"},"entries":[` +
		`{"request":{"method":"GET","url":"https://a.example/x"},"response":{"status":200,"content":{"size":12}},"time":5},` +
		`{"request":{"method":"GET","url":"http://b.example/y?q=1"},"response":{"status":404,"bodySize":8,"content":{"size":0}},"time":7}]}}`
	m := r2l11Map(t, r2l11Run(t, "inspect_web_network_capture", sfWrite(t, "c.har", []byte(har))))
	if m["version"] != "1.2" || m["creator"] != "probe 2" || r2l11Num(t, m["entries"]) != 2 {
		t.Fatalf("har header=%v", m)
	}
	if r2l11Num(t, m["total_ms"]) != 12 || r2l11Num(t, m["total_bytes"]) != 20 {
		t.Fatalf("har totals=%v", m)
	}
	hosts := r2l11Get(t, m, "hosts").([]any)
	if len(hosts) != 2 || hosts[0] != "a.example" || hosts[1] != "b.example" {
		t.Fatalf("har hosts=%v", hosts)
	}
	if r2l11Num(t, r2l11Get(t, m, "requests", 1, "status")) != 404 {
		t.Fatalf("har requests=%v", m["requests"])
	}
	if _, err := runOp("inspect_web_network_capture", sfWrite(t, "bad.har", []byte(`{"log":{}}`))); err == nil || !strings.Contains(err.Error(), "not a HAR 1.2 capture") {
		t.Fatalf("bad HAR error=%v", err)
	}
}

func TestR2L11ProbeSkipOps(t *testing.T) {
	// plist/pyc/rust: skip on unsuitable input; answer on the real type.
	if !strings.Contains(r2l11Skip(t, r2l11Run(t, "inspect_plist", sfWrite(t, "x.txt", []byte("hi")))), "not a property list") {
		t.Fatal("plist should skip text")
	}
	plist := []byte(`<?xml version="1.0"?><plist><dict><key>CFBundleIdentifier</key><string>com.x</string></dict></plist>`)
	pm := r2l11Map(t, r2l11Run(t, "inspect_plist", sfWrite(t, "Info.plist", plist)))
	if len(r2l11Get(t, pm, "keys").([]any)) == 0 {
		t.Fatalf("plist keys=%v", pm["keys"])
	}
	// pyc: valid magic but corrupt marshal -> skip (Probe Skipped).
	pyc := []byte{0xde, 0x0d, 0x0d, 0x0a, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0xff}
	r2l11Skip(t, r2l11Run(t, "inspect_python_pyc", sfWrite(t, "m.pyc", pyc)))
	// rust: binary without a rustc marker -> skip.
	if !strings.Contains(r2l11Skip(t, r2l11Run(t, "inspect_rust_binary", sfWrite(t, "p.exe", sfPE(t, nil, nil)))), "not a Rust build") {
		t.Fatal("rust should skip non-rust binary")
	}
	// sqlite: text that is not a database -> skip.
	if !strings.Contains(r2l11Skip(t, r2l11Run(t, "inspect_sqlite_database", sfWrite(t, "x.txt", []byte("hi")))), "not a sqlite database") {
		t.Fatal("sqlite should skip text")
	}
}

func TestR2L11SQLiteValuesAndVarint(t *testing.T) {
	// sqliteValue: serial types (null, integer, float, text, blob).
	if v, _, err := sqliteValue([]byte{}, 0); err != nil || v != nil {
		t.Fatalf("serial 0=%v %v", v, err)
	}
	v, n, err := sqliteValue([]byte{0x7f}, 1)
	if err != nil || n != 1 || v != int64(127) {
		t.Fatalf("serial 1=%v n=%d err=%v", v, n, err)
	}
	v, _, err = sqliteValue([]byte{0x3f, 0xf0, 0, 0, 0, 0, 0, 0}, 7) // big-endian 1.0
	if err != nil || v != float64(1.0) {
		t.Fatalf("serial 7=%v %v", v, err)
	}
	v, _, err = sqliteValue([]byte("abc"), 18) // even -> text, n=(18-12)/2=3
	if err != nil || v != "abc" {
		t.Fatalf("serial text=%v %v", v, err)
	}
	v, _, err = sqliteValue([]byte{1, 2}, 17) // odd -> blob, n=(17-13)/2=2
	if err != nil || !bytes.Equal(v.([]byte), []byte{1, 2}) {
		t.Fatalf("serial blob=%v %v", v, err)
	}
	// sqliteVarint: 1 byte and 9 bytes (last byte contributes 8 bits).
	if got, used := sqliteVarint([]byte{0x7f}); got != 127 || used != 1 {
		t.Fatalf("varint 1=%d used=%d", got, used)
	}
	full := []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0xff}
	if got, used := sqliteVarint(full); got != 255 || used != 9 {
		t.Fatalf("varint 9=%d used=%d", got, used)
	}
}

// capture_electron_scenario: with =<url> the op must add lifecycle+navigate to
// the CDP spec and report the requested URL, not the renderer's own URL. The
// transport seam lets us assert the actual steps instead of only the JSON.
func TestR2L11CaptureElectronScenarioNavigate(t *testing.T) {
	const reload = "https://app.example.com/index.html"
	var seen webSpec
	prev := webTransport
	webTransport = func(_ context.Context, spec webSpec) (webOut, error) {
		seen = spec
		return webOut{
			Target: &webTargetRow{ID: "T1", Type: "page", URL: "file:///app.asar/index.html"},
			Steps: []webStepResult{
				okStep("Network.enable", map[string]any{}), okStep("Page.enable", map[string]any{}),
				okStep("Page.setLifecycleEventsEnabled", map[string]any{}), okStep("Page.navigate", map[string]any{}),
			},
			Events: []webEvent{
				event("Network.requestWillBeSent", map[string]any{"requestId": "1", "request": map[string]any{"method": "GET", "url": reload}}),
				event("Network.responseReceived", map[string]any{"requestId": "1", "response": map[string]any{"status": float64(200), "mimeType": "text/html"}}),
				event("Page.loadEventFired", map[string]any{}),
			},
		}, nil
	}
	t.Cleanup(func() { webTransport = prev })

	m := r2l11Map(t, r2l11Run(t, "capture_electron_scenario", "127.0.0.1:9222="+reload))
	if seen.Endpoint != "127.0.0.1:9222" || seen.Mode != "session" || seen.Collect == nil ||
		seen.Collect.Ms != 1500 || len(seen.Collect.Prefixes) != 1 || seen.Collect.Prefixes[0] != "Network." {
		t.Fatalf("cdp spec endpoint/collect = %+v", seen)
	}
	wantSteps := []string{"Network.enable", "Page.enable", "Page.setLifecycleEventsEnabled", "Page.navigate"}
	if len(seen.Steps) != len(wantSteps) {
		t.Fatalf("steps = %+v, want %v", seen.Steps, wantSteps)
	}
	for i, want := range wantSteps {
		if seen.Steps[i].Method != want {
			t.Fatalf("step[%d] = %q, want %q", i, seen.Steps[i].Method, want)
		}
	}
	if seen.Steps[2].Params["enabled"] != true || seen.Steps[3].Params["url"] != reload {
		t.Fatalf("navigate params = %+v / %+v", seen.Steps[2].Params, seen.Steps[3].Params)
	}
	if m["mode"] != "attach" || m["url"] != reload || m["count"] != float64(1) || m["load_event"] != true {
		t.Fatalf("result = %+v", m)
	}
	rows := m["requests"].([]any)
	if len(rows) != 1 {
		t.Fatalf("requests = %+v", rows)
	}
	row := rows[0].(map[string]any)
	if row["url"] != reload || row["status"] != float64(200) || row["mime_type"] != "text/html" {
		t.Fatalf("request row = %+v", row)
	}
}

func TestR2L11WebEventListenersTargetGuard(t *testing.T) {
	// route Y target guard: website/PID/remote host rejected; local endpoint accepted.
	if _, _, err := webTarget("https://example.com"); err == nil {
		t.Fatal("website must be declined")
	}
	if _, _, err := webTarget("1.2.3.4:9222"); err == nil || !strings.Contains(err.Error(), "remote host") {
		t.Fatalf("remote host error=%v", err)
	}
	ep, _, err := webTarget("127.0.0.1:9222")
	if err != nil || ep != "127.0.0.1:9222" {
		t.Fatalf("local endpoint=%q err=%v", ep, err)
	}
	// opInspectWebEventListeners uses the same guard: without an endpoint a
	// connection error, with a website an immediate refusal — neither fakes a
	// produced listener.
	if _, err := opInspectWebEventListeners("https://example.com"); err == nil {
		t.Fatal("listeners must decline website target")
	}
}
