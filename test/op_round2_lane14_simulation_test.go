package main

// TUR 2 AUDIT — LANE 14 independent simulation tests.
// Verifies only real behavior; production code is not loosened.

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// ---------- op_netc_util.go / op_netc_test.go ----------

func TestR2L14NetCHelpers(t *testing.T) {
	t.Run("tcpflags", func(t *testing.T) {
		cases := []struct {
			f    byte
			want string
		}{
			{0x02, "S"}, {0x12, "SA"}, {0x18, "PA"}, {0x04, "R"}, {0x00, ""},
		}
		for _, c := range cases {
			if got := netcTCPFlags(c.f); got != c.want {
				t.Errorf("netcTCPFlags(%#x) = %q, want %q", c.f, got, c.want)
			}
		}
	})

	t.Run("tsresol", func(t *testing.T) {
		opts := []byte{9, 0, 1, 0, 6} // little-endian: code 9, olen 1, value 6
		if got := netcTSResol(opts, binary.LittleEndian); got != 6 {
			t.Errorf("netcTSResol = %d, want 6", got)
		}
		clamped := []byte{9, 0, 1, 0, 0x94} // high bit set, 0x14=20 -> clamped to 18
		if got := netcTSResol(clamped, binary.LittleEndian); got != 18 {
			t.Errorf("netcTSResol clamp = %d, want 18", got)
		}
		if got := netcTSResol(nil, binary.LittleEndian); got != 6 {
			t.Errorf("netcTSResol default = %d, want 6", got)
		}
	})

	t.Run("epbtime", func(t *testing.T) {
		if got := netcEpbTime(1_000_000, 6); !got.Equal(time.Unix(1, 0).UTC()) {
			t.Errorf("netcEpbTime(us) = %v", got)
		}
		if got := netcEpbTime(1, 9); !got.Equal(time.Unix(0, 1).UTC()) {
			t.Errorf("netcEpbTime(ns) = %v", got)
		}
	})

	t.Run("dns", func(t *testing.T) {
		msg := netcTestDNSQuery(0x1234, "Example.COM", 1)
		d := netcDNS(msg)
		if d == nil || d.ID != 0x1234 || d.Response || len(d.Questions) != 1 {
			t.Fatalf("netcDNS header = %+v", d)
		}
		q := d.Questions[0]
		if q.Name != "example.com" || q.Type != 1 || q.Class != 1 {
			t.Errorf("netcDNS question = %+v", q)
		}
		if netcDNS([]byte{1, 2}) != nil {
			t.Error("netcDNS short buffer must be nil")
		}
	})

	t.Run("clienthello", func(t *testing.T) {
		seg := netcTestHello("api.example.com", []uint16{0x1301}, []uint16{29}, []byte{0}, []string{"h2"})
		h := netcClientHello(seg)
		if h == nil {
			t.Fatal("netcClientHello returned nil on real ClientHello bytes")
		}
		if h.Version != 0x0303 || h.SNI != "api.example.com" {
			t.Errorf("hello version/sni = %#x/%q", h.Version, h.SNI)
		}
		if !reflect.DeepEqual(h.ALPN, []string{"h2"}) {
			t.Errorf("hello alpn = %v", h.ALPN)
		}
		if len(h.Ciphers) != 1 || h.Ciphers[0] != 0x1301 {
			t.Errorf("hello ciphers = %v", h.Ciphers)
		}
		wantJA3 := "771,4865,0-16-10-11,29,0"
		if h.JA3 != wantJA3 {
			t.Errorf("JA3 = %q, want %q", h.JA3, wantJA3)
		}
		if len(h.JA3MD5) != 32 {
			t.Errorf("JA3MD5 = %q", h.JA3MD5)
		}
		if netcClientHello([]byte{0x17, 0x03, 0x03}) != nil {
			t.Error("non-handshake record must be nil")
		}
	})

	t.Run("decode", func(t *testing.T) {
		f := netcFrame{n: 1, ts: time.Unix(1_700_000_000, 0), link: 1,
			data: netcTestEth(6, netcTestTCP(49152, 80, 0x02, nil))}
		p := netcDecode(f)
		if p.Frame != 1 || p.IP == nil || p.TCP == nil {
			t.Fatalf("netcDecode = %+v", p)
		}
		if p.TCP.SrcPort != 49152 || p.TCP.DstPort != 80 || p.TCP.Flags != "S" {
			t.Errorf("decoded tcp = %+v", p.TCP)
		}
	})

	t.Run("dylib-paths", func(t *testing.T) {
		if g := netcExpandPath("@executable_path/../Frameworks/libX.dylib", "/opt/bin", "/opt/app"); g != "/opt/Frameworks/libX.dylib" {
			t.Errorf("executable_path expansion = %q", g)
		}
		if g := netcExpandPath("@loader_path/lib/libX.dylib", "/opt/bin", "/opt/app"); g != "/opt/app/lib/libX.dylib" {
			t.Errorf("loader_path expansion = %q", g)
		}
		if g := netcExpandPath("/usr/lib/libX.dylib", "/opt/bin", "/opt/app"); g != "/usr/lib/libX.dylib" {
			t.Errorf("absolute path changed to %q", g)
		}

		cands := netcDylibCandidates("@rpath/libX.dylib", "/opt/bin", "/opt/app",
			[]string{"@executable_path/../Frameworks", "@loader_path/Frameworks", "/abs"})
		want := []string{"/opt/Frameworks/libX.dylib", "/opt/app/Frameworks/libX.dylib", "/abs/libX.dylib"}
		if !reflect.DeepEqual(cands, want) {
			t.Errorf("candidates = %v, want %v", cands, want)
		}

		dir := t.TempDir()
		first := filepath.Join(dir, "a.dylib")
		second := filepath.Join(dir, "b.dylib")
		os.WriteFile(second, []byte("x"), 0o644)
		if g := netcFirstExisting([]string{first, second}); g != second {
			t.Errorf("netcFirstExisting = %q, want %q", g, second)
		}
		if g := netcFirstExisting([]string{first}); g != "" {
			t.Errorf("netcFirstExisting missing = %q", g)
		}
	})
}

// ---------- op_next_address.go / op_prev_address.go ----------

func TestR2L14NextPrevFunction(t *testing.T) {
	fns := []nativeFunc{{Name: "a", Start: 0x1000, End: 0x1100}, {Name: "b", Start: 0x2000, End: 0x2100}, {Name: "c", Start: 0x3000, End: 0x3100}}
	cases := []struct {
		addr uint64
		next string
		prev string
	}{
		{0x0fff, "a", ""},
		{0x1000, "b", ""}, // prevFunction uses strict Start < addr
		{0x1500, "b", "a"},
		{0x3000, "", "b"},
		{0x4000, "", "c"},
	}
	for _, c := range cases {
		n, p := nextFunction(fns, c.addr), prevFunction(fns, c.addr)
		nn, pp := "", ""
		if n != nil {
			nn = n.Name
		}
		if p != nil {
			pp = p.Name
		}
		if nn != c.next || pp != c.prev {
			t.Errorf("addr %#x: next=%q prev=%q, want %q/%q", c.addr, nn, pp, c.next, c.prev)
		}
	}
	if got := nativeHexAddr(0x1234); got != "0x1234" {
		t.Errorf("nativeHexAddr = %q", got)
	}
}

// ---------- observe_* ----------

func TestR2L14Observations(t *testing.T) {
	events := []webEvent{
		{Method: "Debugger.scriptParsed", Params: map[string]any{"url": "http://x/app.js", "startLine": float64(42)}},
		{Method: "Runtime.consoleAPICalled", Params: map[string]any{"type": "error", "args": []any{
			map[string]any{"value": "oops"},
			map[string]any{"description": "Error: bad"},
		}}},
		{Method: "Runtime.exceptionThrown", Params: map[string]any{"exceptionDetails": map[string]any{
			"text": "Uncaught", "url": "http://x/app.js", "lineNumber": float64(7),
		}}},
		{Method: "Page.loadEventFired", Params: map[string]any{}},
	}

	got := observationsFrom(events, "Debugger.scriptParsed", "Runtime.consoleAPICalled", "Runtime.exceptionThrown")
	if len(got) != 3 {
		t.Fatalf("observationsFrom len = %d, want 3: %+v", len(got), got)
	}
	if got[0].URL != "http://x/app.js" || got[0].Line != 42 {
		t.Errorf("scriptParsed = %+v", got[0])
	}
	if got[1].Level != "error" || got[1].Text != "oops Error: bad" {
		t.Errorf("console = %+v", got[1])
	}
	if got[2].Text != "Uncaught" || got[2].URL != "http://x/app.js" || got[2].Line != 7 {
		t.Errorf("exception = %+v", got[2])
	}
	if a := argText([]any{map[string]any{"value": "a"}, map[string]any{"description": "b"}}); a != "a b" {
		t.Errorf("argText = %q", a)
	}
	// The out-of-scope refusal message must stay intact (the static answer is Ghidra).
	if !strings.Contains(nativeCallDecline, "procedure_pseudo_code") {
		t.Error("nativeCallDecline lost the Ghidra pointer")
	}
}

// ---------- op_open_bundle_resources.go ----------

func TestR2L14BundleResources(t *testing.T) {
	if !printable("CARV") || printable("") || printable("a\x00b") || printable("é") {
		t.Error("printable classification wrong")
	}
	if g := firstBytes([]byte("abcdef"), 3); g != "abc" {
		t.Errorf("firstBytes = %q", g)
	}
	if g := firstBytes([]byte("ab"), 3); g != "ab" {
		t.Errorf("firstBytes short = %q", g)
	}
	if g := varsSorted(map[string]uint32{"z": 1, "a": 2}); !reflect.DeepEqual(g, []string{"a", "z"}) {
		t.Errorf("varsSorted = %v", g)
	}

	val := make([]byte, 0x40)
	copy(val[:4], "ISTC")
	binary.LittleEndian.PutUint32(val[0x0c:], 100)
	binary.LittleEndian.PutUint32(val[0x10:], 200)
	binary.LittleEndian.PutUint32(val[0x14:], 2)
	copy(val[0x28:], "rendition\x00")
	assets := map[string]string{"AB": "icon.png"}
	key := []byte("xxxxAB") // key[4:6] == "AB"

	row, err := metaBISTC(val, key, assets)
	if err != nil {
		t.Fatal(err)
	}
	if row.Width != 100 || row.Height != 200 || row.Scale != 2 || row.Rendition != "rendition" || row.Asset != "icon.png" {
		t.Errorf("metaBISTC row = %+v", row)
	}
	if row.Type != "image" || row.Compression != "unknown" {
		t.Errorf("metaBISTC type/compression = %s/%s", row.Type, row.Compression)
	}

	copy(val[0x18:0x1c], "FDP ")
	row, _ = metaBISTC(val, key, assets)
	if row.Type != "pdf" || row.Compression != "uncompressed" {
		t.Errorf("pdf row = %+v", row)
	}

	copy(val[0x18:0x1c], "    ")
	copy(val[0x28:], "bvx2\x00")
	row, _ = metaBISTC(val, key, assets)
	if row.Compression != "lzfse" {
		t.Errorf("lzfse row = %+v", row)
	}
	copy(val[0x28:], "ZZZZPackedAsset-1\x00")
	row, _ = metaBISTC(val, key, assets)
	if row.Compression != "packed" {
		t.Errorf("packed row = %+v", row)
	}
	if _, err := metaBISTC([]byte("short"), key, assets); err == nil {
		t.Error("short ISTC must error")
	}

	carv := []byte("CARV")
	carv = append(carv, []byte("REND")...)
	carv = binary.BigEndian.AppendUint32(carv, 3)
	carv = append(carv, 'a', 'b', 'c')
	res, err := metaBCarv("x.car", carv)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.TrimSpace(sprint(res)), `"tag":"REND"`) {
		t.Errorf("metaBCarv result = %+v", res)
	}
	if _, err := metaBCarv("x.car", []byte("CARV\x00\x01\x02\x03\x00\x00\x00\x01x")); err == nil {
		t.Error("non-printable CARV tag must error")
	}
}

func sprint(v any) string {
	b, _ := jsonMarshal(v)
	return string(b)
}

// ---------- op_open_jeb_project.go ----------

func TestR2L14JebProject(t *testing.T) {
	if s := jebProjectNote(true); !strings.Contains(s, "JEB is installed") {
		t.Errorf("jebProjectNote(true) = %q", s)
	}
	if s := jebProjectNote(false); !strings.Contains(s, "JEB is not installed") {
		t.Errorf("jebProjectNote(false) = %q", s)
	}

	dir := t.TempDir()
	apk := filepath.Join(dir, "app.apk")
	f, err := os.Create(apk)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	for name, body := range map[string]string{
		"AndroidManifest.xml": "manifest",
		"classes.dex":         "dex-bytes",
	} {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		w.Write([]byte(body))
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	f.Close()

	mark, dexSum, dex, err := jebdAPKMark(apk)
	if err != nil {
		t.Fatal(err)
	}
	if string(dex) != "dex-bytes" {
		t.Errorf("dex = %q", dex)
	}
	wantSum := sha256Hex([]byte("dex-bytes"))
	if dexSum != wantSum {
		t.Errorf("dexSum = %q, want %q", dexSum, wantSum)
	}
	if len(mark) != 64 {
		t.Errorf("mark = %q", mark)
	}
	mark2, _, _, _ := jebdAPKMark(apk)
	if mark2 != mark {
		t.Error("jebdAPKMark is not deterministic")
	}
}

// ---------- procedure_* (7 op'lar) ----------

func TestR2L14ProcedureOps(t *testing.T) {
	t.Setenv("LRECON_AT", "")
	t.Setenv("LRECON_NAME", "")
	if _, err := nativeRef(); err == nil || !strings.Contains(err.Error(), "LRECON_AT") {
		t.Errorf("nativeRef no-env error = %v", err)
	}
	t.Setenv("LRECON_AT", " 0x1234 ")
	if got, err := nativeRef(); err != nil || got != "0x1234" {
		t.Errorf("nativeRef AT = %q, %v", got, err)
	}
	t.Setenv("LRECON_AT", "")
	t.Setenv("LRECON_NAME", "_main")
	if got, err := nativeRef(); err != nil || got != "_main" {
		t.Errorf("nativeRef NAME = %q, %v", got, err)
	}

	for _, name := range []string{"procedure_address", "procedure_assembly", "procedure_callees", "procedure_callers", "procedure_info", "procedure_pseudo_code", "procedure_references"} {
		o, ok := ops[name]
		if !ok {
			t.Errorf("op %q not registered", name)
			continue
		}
		if o.route != "G" || !o.needs {
			t.Errorf("op %q route/needs = %q/%v", name, o.route, o.needs)
		}
	}
}

// ---------- project_* ----------

func TestR2L14ProjectGraphs(t *testing.T) {
	t.Run("dexclasslines", func(t *testing.T) {
		d := Digest{Notes: []string{
			"dex: class Lcom/x/Main; super Ljava/lang/Object; methods onCreate,onDestroy:line 10",
			"unrelated note",
		}}
		nodes := dexClassLines(d)
		if len(nodes) != 1 {
			t.Fatalf("dexClassLines = %+v", nodes)
		}
		n := nodes[0]
		if n.Kind != "class" || n.Name != "Lcom/x/Main;" || n.Super != "Ljava/lang/Object;" {
			t.Errorf("class node = %+v", n)
		}
		if !reflect.DeepEqual(n.Methods, []string{"onCreate", "onDestroy"}) {
			t.Errorf("methods = %v", n.Methods)
		}
	})

	t.Run("graphresult", func(t *testing.T) {
		g := metaGraphResult(nil, nil)
		if g["node_count"] != 0 || g["edge_count"] != 0 {
			t.Errorf("metaGraphResult = %+v", g)
		}
		if _, ok := g["nodes"].([]metaNode); !ok {
			t.Error("nil nodes must marshal as empty []metaNode")
		}
	})

	t.Run("appleplist", func(t *testing.T) {
		dir := t.TempDir()
		if got := appleBundlePlist(dir); got != "" {
			t.Errorf("empty bundle plist = %q", got)
		}
		p := filepath.Join(dir, "Contents")
		os.MkdirAll(p, 0o755)
		plist := filepath.Join(p, "Info.plist")
		os.WriteFile(plist, []byte("plist"), 0o644)
		if got := appleBundlePlist(dir); got != plist {
			t.Errorf("appleBundlePlist = %q, want %q", got, plist)
		}
		if got := appleBundlePlist(plist); got != "" {
			t.Errorf("file target plist = %q", got)
		}
	})

	t.Run("harmony", func(t *testing.T) {
		dir := t.TempDir()
		hap := filepath.Join(dir, "app.hap")
		f, err := os.Create(hap)
		if err != nil {
			t.Fatal(err)
		}
		zw := zip.NewWriter(f)
		entries := map[string]string{
			"module.json":        `{"module":{"name":"entry","mainElement":"MainAbility","deviceTypes":["phone"],"abilities":[{"name":"MainAbility"}]},"app":{"bundleName":"com.x.app","versionName":"1.0"}}`,
			"ets/modules.abc":    "abc-bytes",
			"entry/libs/libx.so": "so-bytes",
		}
		for name, body := range entries {
			w, err := zw.Create(name)
			if err != nil {
				t.Fatal(err)
			}
			w.Write([]byte(body))
		}
		if err := zw.Close(); err != nil {
			t.Fatal(err)
		}
		f.Close()

		res, err := runProjectHarmonyGraph(hap)
		if err != nil {
			t.Fatal(err)
		}
		m := res.(map[string]any)
		if m["node_count"] != 5 || m["edge_count"] != 4 {
			t.Errorf("harmony graph counts = %v/%v", m["node_count"], m["edge_count"])
		}
		if m["format"] != "zip" {
			t.Errorf("harmony format = %v", m["format"])
		}
		nodes := m["nodes"].([]metaNode)
		kinds := map[string]bool{}
		for _, n := range nodes {
			kinds[n.Kind] = true
		}
		for _, k := range []string{"hap", "module", "ability", "abc", "native-lib"} {
			if !kinds[k] {
				t.Errorf("missing node kind %q in %+v", k, nodes)
			}
		}
	})

	t.Run("harmony-empty", func(t *testing.T) {
		dir := t.TempDir()
		hap := filepath.Join(dir, "empty.hap")
		f, _ := os.Create(hap)
		zw := zip.NewWriter(f)
		w, _ := zw.Create("readme.txt")
		w.Write([]byte("x"))
		zw.Close()
		f.Close()
		if _, err := runProjectHarmonyGraph(hap); err == nil {
			t.Error("HAP with no module/.abc/libs must error")
		}
	})
}

// ---------- op_open_binary.go ----------

func TestR2L14OpenBinary(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "sample.bin")
	body := []byte{0x7f, 'E', 'L', 'F', 1, 2, 3, 4}
	os.WriteFile(f, body, 0o644)

	out, err := runOp("open_binary", f)
	if err != nil {
		t.Fatal(err)
	}
	m := out.(struct {
		Document   string `json:"document"`
		Handle     string `json:"handle"`
		Kind       string `json:"kind"`
		Format     string `json:"format"`
		Size       int64  `json:"size"`
		SHA256     string `json:"sha256,omitempty"`
		GitOID     string `json:"gitoid,omitempty"`
		HashScope  string `json:"hash_scope"`
		BinarySize int64  `json:"binary_size"`
	})
	if m.Handle != "none" || m.Document != f || m.BinarySize != int64(len(body)) {
		t.Errorf("open_binary = %+v", m)
	}
	if m.Size <= 0 || m.SHA256 == "" || m.Kind == "" {
		t.Errorf("open_binary identity = %+v", m)
	}

	out, err = runOp("open_binary", dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := out.(*skip); !ok {
		t.Errorf("directory target must yield *skip, got %T", out)
	}
}

// The op_pass_s1..s4_test.go files are contract tests, not production code.
// They were not touched; they are derived along with their own TestPassS1..S4
// tests (full suite subject to environment noise, see report).

// Test-only helpers so this file stays self-contained without importing extra deps.
func jsonMarshal(v any) ([]byte, error) { return json.Marshal(v) }
func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}
