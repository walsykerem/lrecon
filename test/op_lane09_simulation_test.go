package main

// LANE09 genuine simulation tests. Each test drives a real helper or an op
// through a fake tool seam and asserts on measured output, edge cases and error
// paths — never a bare "no error" pass.

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func TestLane09CSHashFor(t *testing.T) {
	data := []byte("lane09-hash")
	cases := []struct {
		id   uint8
		want []byte
	}{
		{1, func() []byte { s := sha1.Sum(data); return s[:] }()},
		{2, func() []byte { s := sha256.Sum256(data); return s[:] }()},
		{3, func() []byte { s := sha256.Sum256(data); return s[:20] }()},
		{4, func() []byte { s := sha512.Sum384(data); return s[:] }()},
	}
	for _, c := range cases {
		f := csHashFor(c.id)
		if f == nil {
			t.Fatalf("hash type %d: nil", c.id)
		}
		if got := f(data); !bytes.Equal(got, c.want) {
			t.Errorf("hash type %d = %x, want %x", c.id, got, c.want)
		}
	}
	if csHashFor(99) != nil {
		t.Fatal("unsupported hash type must return nil")
	}
}

func TestLane09CSVerifyPagesRealHash(t *testing.T) {
	page := uint32(512)
	code := make([]byte, page*2)
	for i := range code {
		code[i] = byte(i % 251)
	}
	s := sha256.Sum256(code[:page])
	s2 := sha256.Sum256(code[page:])
	slots := append(append([]byte{}, s[:]...), s2[:]...)
	cd := &csCodeDirectory{HashType: "sha256", HashTypeID: 2, HashSize: 32, PageSize: page, CodeLimit: uint64(len(code)), CodeSlots: 2, slots: slots}
	v := csVerifyPages(cd, code)
	if !v.HashesOK || v.PagesChecked != 2 || len(v.Mismatched) != 0 || v.Reason != "" {
		t.Fatalf("valid signature rejected: %+v", v)
	}
	bad := append([]byte{}, slots...)
	bad[10] ^= 0xff
	cd.slots = bad
	v = csVerifyPages(cd, code)
	if v.HashesOK || !reflect.DeepEqual(v.Mismatched, []uint32{0}) {
		t.Fatalf("tampered page not detected: %+v", v)
	}
	// A limit past the signed bytes also changes the page count; keep slots
	// consistent so the length check is the one that fires.
	cd.slots = append(append([]byte{}, s[:]...), s[:]...)
	cd.slots = append(cd.slots, make([]byte, 32)...)
	cd.CodeSlots = 3
	cd.CodeLimit = uint64(len(code)) + 512 // 3 full pages, still past the bytes
	v = csVerifyPages(cd, code)
	if v.HashesOK || !strings.Contains(v.Reason, "past the 1024 signed bytes") {
		t.Fatalf("out-of-range limit not rejected: %+v", v)
	}
	cd.slots = slots
	cd.CodeLimit = 0
	cd.CodeSlots = 0
	if v = csVerifyPages(cd, code); v.HashesOK || !strings.Contains(v.Reason, "seals no pages") {
		t.Fatalf("empty seal not rejected: %+v", v)
	}
	cd.CodeLimit, cd.CodeSlots = uint64(len(code)), 2
	cd.HashTypeID = 99
	if v = csVerifyPages(cd, code); v.HashesOK || !strings.Contains(v.Reason, "unsupported hash type") {
		t.Fatalf("unsupported hash not rejected: %+v", v)
	}
}

func TestLane09CSParseCodeDirectory(t *testing.T) {
	b := make([]byte, 128)
	binary.BigEndian.PutUint32(b[0:], csCodeDirMagic)
	binary.BigEndian.PutUint32(b[8:], 0x20200) // version with team-id field
	binary.BigEndian.PutUint32(b[12:], 0x10000)
	binary.BigEndian.PutUint32(b[16:], 128) // hash offset
	binary.BigEndian.PutUint32(b[20:], 64)  // identifier offset
	binary.BigEndian.PutUint32(b[48:], 90)  // team id offset
	binary.BigEndian.PutUint32(b[24:], 1)   // special slots
	binary.BigEndian.PutUint32(b[28:], 2)   // code slots
	binary.BigEndian.PutUint32(b[32:], 1024)
	b[36] = 32
	b[37] = 2
	b[39] = 9 // 2^9 = 512
	copy(b[64:], "com.apple.lrecon\x00")
	copy(b[90:], "TEAMID10\x00")
	blob := append(append([]byte{}, b...), make([]byte, 64)...)
	for i := 0; i < 16; i++ {
		binary.BigEndian.PutUint32(blob[128+i*4:], 0xdeadbeef)
	}
	cd, err := csParseCodeDirectory(blob)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cd.Identifier != "com.apple.lrecon" || cd.TeamID != "TEAMID10" || cd.CodeLimit != 1024 || cd.CodeSlots != 2 || cd.HashSize != 32 || cd.PageSize != 512 {
		t.Fatalf("wrong parse: %+v", cd)
	}
	if _, err := csParseCodeDirectory(b[:40]); err == nil {
		t.Fatal("short blob accepted")
	}
}

func TestLane09SQLiteValueVarint(t *testing.T) {
	cases := []struct {
		serial int
		b      []byte
		want   any
	}{
		{0, nil, nil},
		{1, []byte{0xff}, int64(-1)},
		{2, []byte{0x01, 0x02}, int64(258)},
		{3, []byte{0xff, 0xff, 0xff}, int64(-1)},
		{4, []byte{0x01, 0x02, 0x03, 0x04}, int64(0x01020304)},
		{5, []byte{1, 2, 3, 4, 5, 6}, int64(0x010203040506)},
		{6, []byte{0, 0, 0, 0, 0, 0, 0, 1}, int64(1)},
		{7, []byte{0x40, 0x09, 0x21, 0xfb, 0x54, 0x44, 0x2d, 0x18}, float64(3.141592653589793)},
		{8, nil, int64(0)},
		{9, nil, int64(1)},
		{24, []byte("lane09"), "lane09"},
		{17, []byte{0xde, 0xad}, []byte{0xde, 0xad}},
	}
	for _, c := range cases {
		got, n, err := sqliteValue(c.b, c.serial)
		if err != nil || n != len(c.b) || !reflect.DeepEqual(got, c.want) {
			t.Errorf("serial %d: got %#v n=%d err=%v, want %#v n=%d", c.serial, got, n, err, c.want, len(c.b))
		}
	}
	for _, s := range []int{10, 11, 99} {
		if _, _, err := sqliteValue(nil, s); err == nil {
			t.Errorf("reserved serial %d accepted", s)
		}
	}
	// varint: 300 -> 0x82 0x2c; the 9-byte form carries 1 in byte nine.
	for _, c := range []struct {
		b    []byte
		want int64
		n    int
	}{{[]byte{0x82, 0x2c, 0xff}, 300, 2}, {[]byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01}, 1, 9}, {[]byte{0x7f}, 127, 1}} {
		v, n := sqliteVarint(c.b)
		if v != c.want || n != c.n {
			t.Errorf("varint %x = %d n=%d, want %d n=%d", c.b, v, n, c.want, c.n)
		}
	}
}

func TestLane09NetcCrashThreadsAndInt(t *testing.T) {
	if v, ok := netcInt(json.Number("42")); !ok || v != 42 {
		t.Fatalf("json.Number = %d %v", v, ok)
	}
	if v, ok := netcInt(float64(7)); !ok || v != 7 {
		t.Fatalf("float64 = %d %v", v, ok)
	}
	if v, ok := netcInt("16"); !ok || v != 16 {
		t.Fatalf("string ParseInt = %d %v", v, ok)
	}
	if _, ok := netcInt("0x10"); ok {
		t.Fatal("netcInt accepted a hex string (base10 only)")
	}
	imgs := []netcCrashImage{{Index: 0, Name: "app", Base: 0x100000000}}
	frames := []any{
		map[string]any{"image_index": json.Number("0"), "image_offset": json.Number("4660"), "symbol": "crash", "symbolLocation": json.Number("4660")},
		map[string]any{"imageIndex": json.Number("9"), "imageOffset": json.Number("8")}, // bad index: fields stay empty
	}
	v := []any{map[string]any{
		"frames": frames, "triggered": true, "id": "thread-1", "name": "main", "queue": "com.apple.main-thread",
	}}
	threads, idx, ok := netcCrashThreads(v, imgs)
	if !ok || idx != 0 || len(threads) != 1 {
		t.Fatalf("threads=%+v idx=%d ok=%v", threads, idx, ok)
	}
	f := threads[0].Frames[0]
	if f.Image != "app" || f.Offset != "0x1234" || f.Address != "0x100001234" || f.Symbol != "crash" || f.SymbolLoc != 0x1234 {
		t.Fatalf("frame projected wrong: %+v", f)
	}
	if f2 := threads[0].Frames[1]; f2.Image != "" || f2.Address != "" {
		t.Fatalf("bad index invented: %+v", f2)
	}
	if threads[0].Name != "main" || threads[0].Queue != "com.apple.main-thread" || !threads[0].Triggered {
		t.Fatalf("thread meta wrong: %+v", threads[0])
	}
}

func TestLane09URLHostAndWebTarget(t *testing.T) {
	for _, c := range []struct{ u, want string }{
		{"https://example.com/a?b#c", "example.com"},
		{"http://127.0.0.1:9222/json", "127.0.0.1:9222"},
		{"file:///tmp/x", ""},
	} {
		if got := urlHost(c.u); got != c.want {
			t.Errorf("urlHost(%q)=%q want %q", c.u, got, c.want)
		}
	}
	if got, arg, err := webTarget("127.0.0.1:9222"); err != nil || got != "127.0.0.1:9222" || arg != "" {
		t.Errorf("loopback endpoint: %q %q %v", got, arg, err)
	}
	if got, arg, err := webTarget("127.0.0.1:9223=page1"); err != nil || got != "127.0.0.1:9223" || arg != "page1" {
		t.Errorf("endpoint arg: %q %q %v", got, arg, err)
	}
	// localhost and host:port must not be mistaken for a process name
	// (op_web_util.go:379); the loopback rewrite at :396 must be reachable.
	if got, arg, err := webTarget("localhost:9223=page1"); err != nil || got != "127.0.0.1:9223" || arg != "page1" {
		t.Errorf("localhost endpoint: %q %q %v", got, arg, err)
	}
	for _, bad := range []string{"http://example.com", "127.0.0.1:notaport", "/tmp/app.asar"} {
		if _, _, err := webTarget(bad); err == nil {
			t.Errorf("bad target %q accepted", bad)
		}
	}
}

func TestLane09RTDecoderMatchesAndQuery(t *testing.T) {
	d := rtDecoder{Name: "RTTY", Family: "ham", Modulation: "FSK", SymbolRate: 45.45, Channel: "HF"}
	if !rtDecoderMatches(d, "fsk", 0, false) || !rtDecoderMatches(d, "zzz", 45.45, true) || rtDecoderMatches(d, "zzz", 45.46, true) {
		t.Fatal("decoder match wrong")
	}
	dir := t.TempDir()
	table := filepath.Join(dir, "decoders.json")
	if err := os.WriteFile(table, []byte(`[{"name":"RTTY","family":"ham","modulation":"FSK","symbol_rate":45.45,"channel":"HF"},{"name":"CW","family":"ham","modulation":"OOK","symbol_rate":20,"channel":"HF"}]`), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LRECON_DECODERS", table)
	t.Setenv("LRECON_QUERY", "hf")
	v, err := inspectSignalDecoders("ignored")
	if err != nil {
		t.Fatal(err)
	}
	h := v.(rtDecoderHits)
	if h.Query != "hf" || h.Table != table || len(h.Matches) != 2 {
		t.Fatalf("hits wrong: %+v", h)
	}
	t.Setenv("LRECON_QUERY", "45.45")
	v, err = inspectSignalDecoders("")
	if err != nil || len(v.(rtDecoderHits).Matches) != 1 || v.(rtDecoderHits).Matches[0].Name != "RTTY" {
		t.Fatalf("rate query: %+v %v", v, err)
	}
	t.Setenv("LRECON_QUERY", "")
	if _, err := inspectSignalDecoders("  "); err == nil || !strings.Contains(err.Error(), "needs a query") {
		t.Fatalf("empty query: %v", err)
	}
	t.Setenv("LRECON_DECODERS", filepath.Join(dir, "nope.json"))
	if _, err := inspectSignalDecoders("hf"); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("missing table: %v", err)
	}
}

func TestLane09ADBPSLayouts(t *testing.T) {
	l, ok := adbPSHeader([]string{"PID", "USER", "NAME", "ARGS"})
	if !ok || l.pid != 0 || l.user != 1 || l.name != 2 || l.args != 3 {
		t.Fatalf("header: %+v %v", l, ok)
	}
	l, ok = adbPSInfer([]string{"1234", "u0_a12", "com.example", "--", "-a"})
	if !ok || l.pid != 0 || l.user != 1 || l.name != 2 || l.args != 3 {
		t.Fatalf("infer -o: %+v %v", l, ok)
	}
	// legacy 9-column table: second field is pid, last is name.
	l, ok = adbPSInfer([]string{"root", "1", "2", "3", "4", "5", "6", "S", "init"})
	if !ok || l.pid != 1 || l.user != 0 || l.name != 8 || len(l.Columns) != 9 {
		t.Fatalf("legacy infer: %+v %v", l, ok)
	}
	out := "PID USER NAME ARGS\n1 root init /init\n2 u0_a1 com.x app_process -X\n"
	l, rows := adbPSTable(out)
	if len(rows) != 2 || rows[0].PID != "1" || rows[0].Name != "init" || rows[0].Args != "/init" || rows[1].User != "u0_a1" || rows[1].Args != "app_process -X" {
		t.Fatalf("table: %+v rows=%+v", l, rows)
	}
}

func TestLane09HARSummaryRealParse(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "capture.har")
	har := `{"log":{"version":"1.2","creator":{"name":"lrecon-test","version":"1"},"entries":[
		{"time":10,"request":{"method":"GET","url":"https://a.example/x"},"response":{"status":200,"content":{"size":100,"mimeType":"text/html"}}},
		{"time":5.5,"request":{"method":"POST","url":"https://b.example:8443/y?q=1"},"response":{"status":404,"bodySize":42,"content":{"size":0,"mimeType":"text/plain"}}}
	]}}`
	if err := os.WriteFile(p, []byte(har), 0o644); err != nil {
		t.Fatal(err)
	}
	v, err := opInspectWebNetworkCapture(p)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(v)
	var s harSummary
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	if s.Version != "1.2" || s.Creator != "lrecon-test 1" || s.Entries != 2 || s.TotalMs != 15.5 || s.TotalSize != 142 {
		t.Fatalf("summary wrong: %+v", s)
	}
	if !reflect.DeepEqual(s.Hosts, []string{"a.example", "b.example:8443"}) {
		t.Fatalf("hosts wrong: %v", s.Hosts)
	}
	if s.Requests[0].Method != "GET" || s.Requests[1].Status != 404 || s.Requests[1].Bytes != 42 {
		t.Fatalf("requests wrong: %+v", s.Requests)
	}
	bad := filepath.Join(dir, "bad.har")
	if err := os.WriteFile(bad, []byte(`{"log":{"entries":[]}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := opInspectWebNetworkCapture(bad); err == nil || !strings.Contains(err.Error(), "no log.version") {
		t.Fatalf("missing version: %v", err)
	}
}

func TestLane09WasmImportParser(t *testing.T) {
	// module "env", field "log", kind func(0), type index 7.
	b := []byte{3, 'e', 'n', 'v', 3, 'l', 'o', 'g', 0, 7}
	c := &wsCursor{b: b}
	imp, err := readWasmImport(c)
	if err != nil || imp.Module != "env" || imp.Field != "log" || imp.Kind != "func" || imp.Type != 7 || c.i != len(b) {
		t.Fatalf("import=%+v err=%v consumed=%d", imp, err, c.i)
	}
	// memory kind(2) with limits flag 1 min 2 max 5.
	b2 := []byte{1, 'm', 1, 'x', 2, 1, 2, 5}
	c2 := &wsCursor{b: b2}
	imp2, err := readWasmImport(c2)
	if err != nil || imp2.Kind != "memory" || imp2.Limits == nil || imp2.Limits.Min != 2 || imp2.Limits.Max != 5 || imp2.Limits.Flag != 1 {
		t.Fatalf("memory import=%+v err=%v", imp2, err)
	}
	// truncated: no field terminator.
	if _, err := readWasmImport(&wsCursor{b: []byte{1, 'm', 1, 'x'}}); err == nil {
		t.Fatal("truncated import accepted")
	}
	// u32 LEB: 300 -> ac 02; 5-byte continuation beyond max is rejected.
	if v, ok := (&wsCursor{b: []byte{0xac, 0x02}}).u32(); !ok || v != 300 {
		t.Fatalf("leb128 = %d %v", v, ok)
	}
	if _, ok := (&wsCursor{b: []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x01}}).u32(); ok {
		t.Fatal("overlong leb128 accepted")
	}
}

func TestLane09WebTargetHelpers(t *testing.T) {
	if got := str(nil); got != "" {
		t.Fatalf("str(nil)=%q", got)
	}
	if got := str("hello"); got != "hello" {
		t.Fatalf("str(string)=%q", got)
	}
	if got := str(float64(3)); got != "" {
		t.Fatalf("str(non-string)=%q", got)
	}
	if got, truncated := cutUTF8("abc", 2); got != "ab" || !truncated {
		t.Fatalf("cutUTF8 ascii = %q %v", got, truncated)
	}
	if got, truncated := cutUTF8("a\xc3\xa9b", 2); got != "a" || !truncated {
		t.Fatalf("cutUTF8 multibyte = %q %v", got, truncated)
	}
}

func TestLane09BookmarkStateAndMeta(t *testing.T) {
	dir := metaTestState(t)
	p := filepath.Join(dir, "bookmarks.json")
	marks := []metaBookmark{{File: "/bin/ls", Address: "0x1000", Note: "first", Created: "2026-01-01"}}
	b, _ := json.Marshal(marks)
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	job := metaTestArg(t, map[string]any{"file": "/bin/ls"})
	v, err := runListBookmarks(job)
	if err != nil {
		t.Fatal(err)
	}
	m := v.(map[string]any)
	if m["count"] != 1 || m["total"] != 1 || m["exists"] != true {
		t.Fatalf("bookmarks: %+v", m)
	}
	job2 := metaTestArg(t, map[string]any{"file": "/other"})
	v, err = runListBookmarks(job2)
	if err != nil || v.(map[string]any)["count"] != 0 || v.(map[string]any)["total"] != 1 {
		t.Fatalf("filter: %+v %v", v, err)
	}
	if err := os.WriteFile(p, []byte(`{"not":"array"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := runListBookmarks(job); err == nil || !strings.Contains(err.Error(), "not a bookmark array") {
		t.Fatalf("conflict: %v", err)
	}
	if err := metaRequireBookmarkAddress(metaJob{}); err == nil {
		t.Fatal("missing address accepted")
	}
}

func TestLane09SessionDocumentsErrorPath(t *testing.T) {
	t.Setenv("LRECON_STATE", t.TempDir())
	t.Setenv("LRECON_SESSION", "")
	if _, err := ops["list_documents"].run(""); err == nil || !strings.Contains(err.Error(), "no session") {
		t.Fatalf("missing session: %v", err)
	}
	sp := sessionPath()
	b, _ := json.Marshal(nativeSession{Project: "p", Document: "/nope/missing", Documents: []string{"/nope/missing", "testdata/fixtures/fatbin/universal.fat"}})
	if err := os.WriteFile(sp, b, 0o644); err != nil {
		t.Fatal(err)
	}
	v, err := ops["list_documents"].run("")
	if err != nil {
		t.Fatal(err)
	}
	m := v.(map[string]any)
	rows := m["documents"].([]map[string]any)
	if len(rows) != 2 || rows[0]["exists"] != false || rows[0]["selected"] != true || !strings.Contains(rows[0]["error"].(string), "no such file") {
		t.Fatalf("rows: %+v", rows)
	}
	if rows[1]["exists"] != true || rows[1]["size"].(int64) <= 0 {
		t.Fatalf("real file not measured: %+v", rows[1])
	}
}

func TestLane09ObjdumpFormatAndArchive(t *testing.T) {
	elfPath := buildTarget(t, "linux", "amd64", "hello-elf")
	if got := objdumpFormat(elfPath); got != "elf" {
		t.Fatalf("elf format = %q", got)
	}
	pePath := buildTarget(t, "windows", "amd64", "hello.exe")
	if got := objdumpFormat(pePath); got != "pe" {
		t.Fatalf("pe format = %q", got)
	}
	// Unknown bytes are reported as "macho" by the permissive format sniffer;
	// that is why the op's detailed reader, not this label, decides validity.
	txt := writeTemp(t, "notes.txt", []byte("not a binary"))
	if got := objdumpFormat(txt); got != "macho" {
		t.Fatalf("text format = %q", got)
	}
	// ar archive with one member "a.o" holding 3 bytes.
	var ar bytes.Buffer
	ar.WriteString("!<arch>\n")
	hdr := make([]byte, 60)
	copy(hdr[0:16], []byte("a.o/            "))
	copy(hdr[16:28], []byte("0           "))
	copy(hdr[28:34], []byte("0   "))
	copy(hdr[34:40], []byte("0   "))
	copy(hdr[40:48], []byte("100644  "))
	copy(hdr[48:58], []byte("3         "))
	copy(hdr[58:60], []byte("`\n"))
	ar.Write(hdr)
	ar.WriteString("abc")
	arPath := writeTemp(t, "lib.a", ar.Bytes())
	if got := objdumpFormat(arPath); got != "archive" {
		t.Fatalf("archive format = %q", got)
	}
	members, err := archiveMembers(arPath)
	if err != nil || !strings.Contains(members, "a.o") {
		t.Fatalf("archive members: %q %v", members, err)
	}
}

func TestLane09ADBFeaturesPackagesDevicesProcesses(t *testing.T) {
	rtFakeTool(t, "adb", `while [ "$1" = "-s" ]; do shift 2; done
case "$1" in
 host-features) printf 'sendfile_v2,apex, \r\n';;
 devices) printf 'List of devices attached\nR58M\tdevice product:beyond1lte model:SM_G973F transport_id:1\n';;
 shell) shift; case "$1" in cmd) printf 'package:/data/app/com.x~~abc==/base.apk=com.x\npackage:com.y\n';; ps) printf 'PID USER NAME ARGS\n1 root init /init\n';; *) printf 'nothing\n';; esac;;
esac`)
	v, err := listADBFeatures("")
	if err != nil {
		t.Fatal(err)
	}
	if f := v.(rtADBFeatures); f.Count != 2 || f.Features[0] != "sendfile_v2" || f.Features[1] != "apex" {
		t.Fatalf("features: %+v", f)
	}
	v, err = listADBDevices("")
	if err != nil || !strings.Contains(fmt.Sprint(v), "R58M") {
		t.Fatalf("devices: %+v %v", v, err)
	}
	v, err = listADBPackages("")
	if err != nil {
		t.Fatal(err)
	}
	if p := v.(rtADBPackages); p.Count != 2 || p.Packages[0].Package != "com.x" || p.Packages[0].APK != "/data/app/com.x~~abc==/base.apk" || p.Packages[1].Package != "com.y" {
		t.Fatalf("packages: %+v", p)
	}
	v, err = listADBProcesses("")
	if err != nil || v.(rtADBProcesses).Count != 1 || v.(rtADBProcesses).Rows[0].Name != "init" {
		t.Fatalf("processes: %+v %v", v, err)
	}
}

func TestLane09ADBServices(t *testing.T) {
	rtFakeTool(t, "adb", `case "$1" in
 devices) printf 'List of devices attached\nR58M\tdevice\n';;
 shell) printf 'List of services:\nactivity\npackage\nwindow\n';;
esac`)
	v, err := opListAdbServices("")
	if err != nil {
		t.Fatal(err)
	}
	s := v.(rt2AdbServices)
	if s.Count != 3 || s.Services[0].Name != "activity" || s.Services[2].Name != "window" {
		t.Fatalf("services: %+v", s)
	}
}

func TestLane09FridaDevicesHostRowAndNote(t *testing.T) {
	rtFakeTool(t, "adb", "#!/bin/sh\nprintf 'List of devices attached\n'")
	v, err := opListFridaDevices("")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(v)
	var s struct {
		Devices []struct {
			ID   string `json:"id"`
			Type string `json:"type"`
		} `json:"devices"`
		Note string `json:"note"`
	}
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	if len(s.Devices) != 1 || s.Devices[0].ID != "local" || s.Devices[0].Type != "local" {
		t.Fatalf("devices: %+v", s)
	}
	if !strings.Contains(s.Note, "no rows") {
		t.Fatalf("missing note: %q", s.Note)
	}
}

func TestLane09RecordedCrashImageAddressAndReject(t *testing.T) {
	p := writeTemp(t, "crash.ips", []byte(`{"app_name":"app","timestamp":"2026-01-01"}
{"exception":{"type":"EXC_BAD_ACCESS","signal":11,"codes":"KERN_INVALID_ADDRESS"},"usedImages":[{"base":4294967296,"name":"app","uuid":"U1","arch":"arm64"}],"threads":[{"triggered":true,"frames":[{"imageIndex":0,"imageOffset":4660,"symbol":"crash"}]}]}`))
	v, err := ops["inspect_recorded_crash"].run(p)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(v)
	var s struct {
		Threads []struct {
			Triggered bool `json:"triggered"`
			Frames    []struct {
				Image   string `json:"image"`
				Address string `json:"address"`
			} `json:"frames"`
		} `json:"threads"`
	}
	if err := json.Unmarshal(b, &s); err != nil || len(s.Threads) != 1 || !s.Threads[0].Triggered || s.Threads[0].Frames[0].Address != "0x100001234" {
		t.Fatalf("crash: %s %v", b, err)
	}
	if _, ok := netcCrashExceptionOf(map[string]any{}); ok {
		t.Fatal("empty exception accepted")
	}
	if e, ok := netcCrashExceptionOf(map[string]any{"type": "EXC_BAD_ACCESS"}); !ok || e.Type != "EXC_BAD_ACCESS" {
		t.Fatalf("partial exception = %+v %v", e, ok)
	}
	if v, ok := netcInt64("0x10"); !ok || v != 16 {
		t.Fatalf("netcInt64 base0 = %d %v", v, ok)
	}
}

func TestLane09FridaProcessesFallbackToHost(t *testing.T) {
	rtNoTools(t) // no adb: real host process list fallback
	v, err := opListFridaProcesses("")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(v)
	var s struct {
		Processes []struct {
			PID  int    `json:"pid"`
			Name string `json:"name"`
		} `json:"processes"`
		Count int `json:"count"`
	}
	if err := json.Unmarshal(b, &s); err != nil || s.Count == 0 || s.Processes[0].PID <= 0 || s.Processes[0].Name == "" {
		t.Fatalf("host fallback: %s %v", b, err)
	}
	for i := 1; i < len(s.Processes); i++ {
		if s.Processes[i-1].PID > s.Processes[i].PID {
			t.Fatalf("not sorted by pid: %+v", s.Processes)
		}
	}
}

func TestLane09RegistrationsAndNumberParsing(t *testing.T) {
	for _, name := range []string{
		"inspect_plist", "inspect_python_pyc", "inspect_recorded_crash", "inspect_rust_binary",
		"inspect_signal_decoders", "inspect_signature", "inspect_sqlite_database", "inspect_wasm_artifact",
		"inspect_web_event_listeners", "inspect_web_network_capture", "inspect_web_page", "inspect_with_objdump",
		"install_adb_package", "instrument_with_frida", "list_adb_devices", "list_adb_directory",
		"list_adb_features", "list_adb_packages", "list_adb_processes", "list_adb_services",
		"list_architectures", "list_bookmarks", "list_browser_targets", "list_cutter_sessions",
		"list_documents", "list_electron_targets", "list_frida_devices", "list_frida_processes",
		"list_javascript_runtime_targets", "list_jeb_units",
	} {
		o, ok := ops[name]
		if !ok || o.run == nil {
			t.Fatalf("op %s not registered with a run function", name)
		}
	}
	if v, err := strconv.ParseFloat("45.45", 64); err != nil || math.Abs(v-45.45) > 1e-9 {
		t.Fatalf("float parse: %v %v", v, err)
	}
}

// ---- LANE09 op-level simulation: real ops driven through file / fake-tool /
// fake-CDP seams, asserting on measured fields, edge cases and error paths. ----

func lane09RunMap(t *testing.T, name, target string) map[string]any {
	t.Helper()
	v, err := runOp(name, target)
	if err != nil {
		t.Fatalf("runOp(%s,%s): %v", name, target, err)
	}
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

func lane09StrArray(t *testing.T, v any) []string {
	t.Helper()
	a, ok := v.([]any)
	if !ok {
		t.Fatalf("not a JSON array: %T %v", v, v)
	}
	out := make([]string, len(a))
	for i := range a {
		out[i], _ = a[i].(string)
	}
	return out
}

func TestLane09OpInspectPlist(t *testing.T) {
	xml := []byte(`<?xml version="1.0"?><plist version="1.0"><dict><key>CFBundleIdentifier</key><string>com.example.app</string><key>CFBundleVersion</key><string>3.2</string></dict></plist>`)
	m := lane09RunMap(t, "inspect_plist", writeTemp(t, "Info.plist", xml))
	keys := lane09StrArray(t, m["keys"])
	want := []string{"CFBundleIdentifier = com.example.app", "CFBundleVersion = 3.2"}
	if !reflect.DeepEqual(keys, want) {
		t.Fatalf("plist keys = %v, want %v", keys, want)
	}
	// non-plist input must be skipped with a reason, not silently empty
	v, err := runOp("inspect_plist", writeTemp(t, "x.txt", []byte("hello")))
	if err != nil {
		t.Fatal(err)
	}
	s, ok := v.(*skip)
	if !ok || !strings.Contains(s.Reason, "is not a property list") {
		t.Fatalf("non-plist = %+v, want a skip with a reason", v)
	}
}

func TestLane09OpInspectPythonPyc(t *testing.T) {
	body := mCode(311, "outer", "mod.outer", "src/mod.py",
		mShort("hello"), mCode(311, "inner", "mod.outer.inner", "src/mod.py"))
	p := writeTemp(t, "m.pyc", pycBlob(3495, 0, body))
	m := lane09RunMap(t, "inspect_python_pyc", p)
	if m["toolchain"] != "cpython 3.11" {
		t.Fatalf("toolchain = %v", m["toolchain"])
	}
	q := lane09StrArray(t, m["qualnames"])
	if !reflect.DeepEqual(q, []string{"mod.outer", "mod.outer.inner"}) {
		t.Fatalf("qualnames = %v", q)
	}
	caps := lane09StrArray(t, m["capabilities"])
	if len(caps) == 0 || caps[0] != "pyc:code_objects=2" {
		t.Fatalf("capabilities = %v", caps)
	}
	notes := lane09StrArray(t, m["notes"])
	found := false
	for _, n := range notes {
		if strings.Contains(n, `pyc: source "src/mod.py"`) {
			found = true
		}
	}
	if !found {
		t.Fatalf("notes missing the recovered source file: %v", notes)
	}
	// corrupt magic -> skip, never a bogus success
	v, err := runOp("inspect_python_pyc", writeTemp(t, "bad.pyc", []byte("not a pyc at all")))
	if err != nil {
		t.Fatal(err)
	}
	s, ok := v.(*skip)
	if !ok || !strings.Contains(s.Reason, "not a CPython .pyc") {
		t.Fatalf("bad pyc = %+v, want a skip", v)
	}
}

func TestLane09OpInspectRustBinary(t *testing.T) {
	m := lane09RunMap(t, "inspect_rust_binary", fixtureRust)
	if m["kind"] != "macho" || !strings.HasPrefix(fmt.Sprint(m["toolchain"]), "rustc") {
		t.Fatalf("kind/toolchain = %v/%v", m["kind"], m["toolchain"])
	}
	crates := lane09StrArray(t, m["crates"])
	has := false
	for _, c := range crates {
		if c == "gimli-0.32.0" {
			has = true
		}
	}
	if !has {
		t.Fatalf("crates missing gimli-0.32.0: %v", crates)
	}
	syms := lane09StrArray(t, m["symbols"])
	if len(syms) == 0 || !strings.HasPrefix(syms[0], "rustsym:") {
		t.Fatalf("symbols = %v", syms)
	}
	// a Go Mach-O has no rustc marker and must be skipped, not mislabeled
	v, err := runOp("inspect_rust_binary", fixtureFat)
	if err != nil {
		t.Fatal(err)
	}
	s, ok := v.(*skip)
	if !ok || !strings.Contains(s.Reason, "not a Rust build") {
		t.Fatalf("Go fat macho = %+v, want a skip", v)
	}
}

func TestLane09OpInspectWasmArtifact(t *testing.T) {
	w := []byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0, 0, 0, 0x01, 0x01, 0x00, 0x05, 0x03, 0x01, 0x00, 0x01}
	m := lane09RunMap(t, "inspect_wasm_artifact", writeTemp(t, "m.wasm", w))
	if m["magic"] != `\0asm` || m["version"] != float64(1) {
		t.Fatalf("magic/version = %v/%v", m["magic"], m["version"])
	}
	secs, ok := m["sections"].([]any)
	if !ok || len(secs) != 2 {
		t.Fatalf("sections = %v", m["sections"])
	}
	first := secs[0].(map[string]any)
	if first["name"] != "type" || first["payload_offset"] != float64(10) || first["payload_bytes"] != float64(1) {
		t.Fatalf("section 0 = %+v", first)
	}
	second := secs[1].(map[string]any)
	if second["name"] != "memory" || second["entries"] != float64(1) {
		t.Fatalf("section 1 = %+v", second)
	}
	// no wasm magic -> hard error, not an empty result
	_, err := runOp("inspect_wasm_artifact", writeTemp(t, "bad.wasm", []byte("hello")))
	if err == nil || !strings.Contains(err.Error(), "has no wasm magic") {
		t.Fatalf("bad wasm error = %v", err)
	}
}

func TestLane09OpListArchitectures(t *testing.T) {
	m := lane09RunMap(t, "list_architectures", fixtureFat)
	if m["format"] != "fat" || m["slices"] != float64(2) {
		t.Fatalf("format/slices = %v/%v", m["format"], m["slices"])
	}
	arches, ok := m["architectures"].([]any)
	if !ok || len(arches) != 2 {
		t.Fatalf("architectures = %v", m["architectures"])
	}
	a0 := arches[0].(map[string]any)
	if a0["arch"] != "arm64" || a0["offset"] != float64(4096) || a0["align"] != float64(12) {
		t.Fatalf("slice 0 = %+v", a0)
	}
	// non-Mach-O must skip
	v, err := runOp("list_architectures", writeTemp(t, "x.txt", []byte("hello")))
	if err != nil {
		t.Fatal(err)
	}
	s, ok := v.(*skip)
	if !ok || !strings.Contains(s.Reason, "not Mach-O") {
		t.Fatalf("non-macho = %+v, want a skip", v)
	}
}

func TestLane09OpInspectSignature(t *testing.T) {
	// No CodeDirectory: must error, never a passing empty result.
	bare := make([]byte, 12)
	binary.BigEndian.PutUint32(bare, csSuperBlobMagic)
	binary.BigEndian.PutUint32(bare[4:], 12)
	binary.BigEndian.PutUint32(bare[8:], 0)
	_, err := runOp("inspect_signature", writeTemp(t, "bare.bin", bare))
	if err == nil || !strings.Contains(err.Error(), "carries no CodeDirectory") {
		t.Fatalf("bare superblob error = %v", err)
	}
	// A real CodeDirectory blob in a bare superblob: parses, but page hashes
	// cannot be recomputed without the signed image, so verification says so.
	cd := make([]byte, 128+64)
	binary.BigEndian.PutUint32(cd[0:], csCodeDirMagic)
	binary.BigEndian.PutUint32(cd[4:], uint32(len(cd)))
	binary.BigEndian.PutUint32(cd[8:], 0x20200)
	binary.BigEndian.PutUint32(cd[16:], 128)
	binary.BigEndian.PutUint32(cd[20:], 64)
	binary.BigEndian.PutUint32(cd[48:], 90)
	binary.BigEndian.PutUint32(cd[32:], 0) // code limit 0 avoids page checks
	cd[36], cd[37], cd[39] = 32, 2, 9
	copy(cd[64:], "com.apple.lrecon\x00")
	copy(cd[90:], "TEAMID10\x00")
	total := 12 + 8 + len(cd)
	sig := make([]byte, total)
	binary.BigEndian.PutUint32(sig[0:], csSuperBlobMagic)
	binary.BigEndian.PutUint32(sig[4:], uint32(total))
	binary.BigEndian.PutUint32(sig[8:], 1)
	binary.BigEndian.PutUint32(sig[12:], 0)  // CodeDirectory blob type
	binary.BigEndian.PutUint32(sig[16:], 20) // offset inside the superblob
	copy(sig[20:], cd)
	m := lane09RunMap(t, "inspect_signature", writeTemp(t, "sig.bin", sig))
	if m["source"] != "superblob" || m["magic"] != "0xfade0cc0" || m["length"] != float64(total) {
		t.Fatalf("signature header = %v", m)
	}
	blobs := m["blobs"].([]any)
	if len(blobs) != 1 || blobs[0].(map[string]any)["type_name"] != "CodeDirectory" {
		t.Fatalf("blobs = %v", blobs)
	}
	ver := m["verification"].(map[string]any)
	if !strings.Contains(fmt.Sprint(ver["reason"]), "bare signature blob") {
		t.Fatalf("verification = %+v", ver)
	}
}

func TestLane09OpInspectWithObjdump(t *testing.T) {
	bin := buildTarget(t, "linux", "amd64", "lane09obj")
	v, err := runOp("inspect_with_objdump", bin)
	if err != nil {
		t.Fatal(err)
	}
	res := v.(objdumpResult)
	if res.Format != "elf" || res.Output == "" || len(res.Parts) < 3 {
		t.Fatalf("elf objdump = %+v", res)
	}
	names := map[string]bool{}
	for _, p := range res.Parts {
		names[p.Name] = true
	}
	for _, want := range []string{"sections", "symbols", "disassembly"} {
		if !names[want] {
			t.Fatalf("missing part %s in %v", want, names)
		}
	}
	if !strings.Contains(res.Note, "no external tool") {
		t.Fatalf("note = %q", res.Note)
	}
}

func TestLane09OpInstallADBPackage(t *testing.T) {
	apk := writeTemp(t, "app.apk", []byte("PK\x03\x04 fake apk"))
	shim := `while [ "$1" = "-s" ]; do shift 2; done
case "$1" in
 devices) printf 'List of devices attached\nR58M\tdevice product:beyond1lte model:SM_G973F transport_id:1\n';;
 install) printf 'Performing Streamed Install\nSuccess\n';;
esac
`
	rtFakeTool(t, "adb", shim)
	m := lane09RunMap(t, "install_adb_package", apk)
	if m["result"] != "Success" || m["method"] != "streamed install -r -t" || m["apk"] != apk {
		t.Fatalf("install = %v", m)
	}
	// Failure on stdout must be reported, not read as success.
	rtFakeTool(t, "adb", `while [ "$1" = "-s" ]; do shift 2; done
case "$1" in
 devices) printf 'List of devices attached\nR58M\tdevice\n';;
 install) printf 'Failure [INSTALL_FAILED_TEST_ONLY]\n';;
esac
`)
	_, err := runOp("install_adb_package", apk)
	if err == nil || !strings.Contains(err.Error(), "INSTALL_FAILED_TEST_ONLY") {
		t.Fatalf("failure install error = %v", err)
	}
	// Missing APK must fail at os.Stat before any tool call.
	if _, err := runOp("install_adb_package", apk+".missing"); err == nil {
		t.Fatal("missing APK accepted")
	}
}

func TestLane09OpWebOpsThroughFakeCDP(t *testing.T) {
	targets := []webTargetRow{{ID: "T1", Type: "page", Title: "App", URL: "file:///a/index.html", Attached: true, WS: "ws://127.0.0.1:9222/devtools/page/T1"}}

	// list_browser_targets: real target rows and the browser WS endpoint.
	fakeDriver(t, webOut{Targets: targets, Version: map[string]any{"webSocketDebuggerUrl": "ws://127.0.0.1:9222/devtools/browser/B1"}})
	m := lane09RunMap(t, "list_browser_targets", "127.0.0.1:9222")
	if m["count"] != float64(1) || m["browser_ws"] != "ws://127.0.0.1:9222/devtools/browser/B1" {
		t.Fatalf("browser targets = %v", m)
	}
	if byType := m["by_type"].(map[string]any); byType["page"] != float64(1) {
		t.Fatalf("by_type = %v", byType)
	}

	// Target.getTargets step: two rows, one attached, one service worker.
	fakeDriver(t, webOut{Steps: []webStepResult{okStep("Target.getTargets", map[string]any{"targetInfos": []any{
		map[string]any{"targetId": "T1", "type": "page", "title": "App", "url": "file:///a/index.html", "attached": true},
		map[string]any{"targetId": "T2", "type": "service_worker", "title": "sw", "url": "file:///a/sw.js"},
	}})}})
	m = lane09RunMap(t, "list_javascript_runtime_targets", "127.0.0.1:9222")
	if m["count"] != float64(2) {
		t.Fatalf("runtime targets count = %v", m["count"])
	}
	js := m["targets"].([]any)
	if js[0].(map[string]any)["attached"] != true || js[1].(map[string]any)["type"] != "service_worker" {
		t.Fatalf("runtime targets = %v", js)
	}

	// page probe: every fact is read from the Runtime.evaluate value map.
	fakeDriver(t, webOut{Target: &targets[0], Steps: []webStepResult{
		okStep("Runtime.enable", map[string]any{}),
		okStep("Runtime.evaluate", map[string]any{"result": map[string]any{"type": "object", "value": map[string]any{
			"title": "App", "readyState": "complete", "href": "file:///a/index.html",
			"html": float64(4096), "nodes": float64(120), "w": float64(1280), "h": float64(720), "ua": "Mozilla/5.0",
		}}}),
	}})
	m = lane09RunMap(t, "inspect_web_page", "127.0.0.1:9222")
	if m["target"] != "T1" || m["url"] != "file:///a/index.html" || m["title"] != "App" ||
		m["ready_state"] != "complete" || m["nodes"] != float64(120) || m["html_bytes"] != float64(4096) ||
		m["width"] != float64(1280) || m["height"] != float64(720) {
		t.Fatalf("page facts = %v", m)
	}
	// missing readyState -> hard error, not a page full of zeros
	fakeDriver(t, webOut{Target: &targets[0], Steps: []webStepResult{
		okStep("Runtime.enable", map[string]any{}),
		okStep("Runtime.evaluate", map[string]any{"result": map[string]any{"type": "object", "value": map[string]any{"title": "App"}}}),
	}})
	_, err := runOp("inspect_web_page", "127.0.0.1:9222")
	if err == nil || !strings.Contains(err.Error(), "no readyState") {
		t.Fatalf("page missing readyState error = %v", err)
	}

	// event listeners: window+document lists, counts and sorting.
	fakeDriver(t, webOut{Target: &targets[0], Steps: []webStepResult{
		okStep("Runtime.enable", map[string]any{}),
		okStep("Runtime.evaluate", map[string]any{"result": map[string]any{"objectId": "1"}}),
		okStep("Runtime.evaluate", map[string]any{"result": map[string]any{"objectId": "2"}}),
		okStep("DOMDebugger.getEventListeners", map[string]any{"listeners": []any{
			map[string]any{"type": "click", "lineNumber": float64(10), "columnNumber": float64(4)},
		}}),
		okStep("DOMDebugger.getEventListeners", map[string]any{"listeners": []any{
			map[string]any{"type": "click", "useCapture": true, "once": true, "lineNumber": float64(3)},
		}}),
	}})
	m = lane09RunMap(t, "inspect_web_event_listeners", "127.0.0.1:9222")
	if m["by_type"].(map[string]any)["click"] != float64(2) {
		t.Fatalf("by_type = %v", m["by_type"])
	}
	ls := m["listeners"].([]any)
	if len(ls) != 2 || ls[0].(map[string]any)["scope"] != "document" {
		t.Fatalf("listeners (want document first) = %v", ls)
	}
	if ls[0].(map[string]any)["line"] != float64(3) || ls[0].(map[string]any)["once"] != true {
		t.Fatalf("window listener row = %v", ls[0])
	}

	// electron targets: an isolated context plus an Electron UA -> verdict.
	fakeDriver(t, webOut{Steps: []webStepResult{
		okStep("Runtime.enable", map[string]any{}),
		okStep("Runtime.evaluate", map[string]any{"result": map[string]any{"value": "Mozilla/5.0 Chrome/130.0.0.0 Electron/33.2.1 Safari/537.36"}}),
	}, Events: []webEvent{event("Runtime.executionContextCreated", map[string]any{"context": map[string]any{
		"id": float64(7), "name": electronWorldName, "origin": "file://", "auxData": map[string]any{"type": "default", "isDefault": true},
	}})}})
	m = lane09RunMap(t, "list_electron_targets", "127.0.0.1:9222")
	if m["verdict"] != "electron" || m["ua_electron_version"] != "33.2.1" {
		t.Fatalf("electron verdict/version = %v/%v", m["verdict"], m["ua_electron_version"])
	}
	ctxs := m["contexts"].([]any)
	if len(ctxs) != 1 || m["electron_isolated_world"] != true {
		t.Fatalf("contexts/isolated = %v/%v", ctxs, m["electron_isolated_world"])
	}
	if !strings.Contains(fmt.Sprint(m["attribution"]), "runtime") {
		t.Fatalf("attribution = %v", m["attribution"])
	}

	// empty CDP list is a real error, not an empty success.
	fakeDriver(t, webOut{})
	_, err = runOp("list_browser_targets", "127.0.0.1:9222")
	if err == nil || !strings.Contains(err.Error(), "JsonListIsEmpty") {
		t.Fatalf("empty browser targets error = %v", err)
	}
}

func TestLane09OpListADBDirectoryLongRows(t *testing.T) {
	dir := "/sdcard/My Dir"
	shim := `while [ "$1" = "-s" ]; do shift 2; done
case "$1" in
 devices) printf 'List of devices attached\nR58M\tdevice\n';;
 shell) printf 'total 8\ndrwxr-xr-x 2 root root 4096 2026-01-01 10:00 My Dir\n-rw-r--r-- 1 root root 42 2026-01-01 10:01 read me.txt\nnot a long row\n';;
esac
`
	rtFakeTool(t, "adb", shim)
	v, err := runOp("list_adb_directory", dir)
	if err != nil {
		t.Fatal(err)
	}
	list := v.(rtDirListing)
	if list.Path != dir || len(list.Entries) != 2 {
		t.Fatalf("listing = %+v", list)
	}
	// Name may contain spaces; only the first seven fields are positional.
	if list.Entries[0].Name != "My Dir" || !list.Entries[0].IsDir || list.Entries[0].Perm != "drwxr-xr-x" {
		t.Fatalf("dir entry = %+v", list.Entries[0])
	}
	if list.Entries[1].Name != "read me.txt" || list.Entries[1].IsDir || list.Entries[1].Size != "42" {
		t.Fatalf("file entry = %+v", list.Entries[1])
	}
}

func TestLane09OpListCutterSessionsArraysNeverNull(t *testing.T) {
	v, err := runOp("list_cutter_sessions", "")
	if err != nil {
		t.Fatal(err)
	}
	m := v.(map[string]any)
	// The empty case must be [] not null, and the filesystem-only note present.
	for _, k := range []string{"cutter_processes", "projects"} {
		if _, ok := m[k].([]string); !ok {
			t.Fatalf("%s = %T, want a non-nil []string", k, m[k])
		}
	}
	if !strings.Contains(fmt.Sprint(m["rizin"]), "filesystem-only") {
		t.Fatalf("rizin note = %v", m["rizin"])
	}
	if !strings.Contains(fmt.Sprint(m["process_source"]), "kernel process table") {
		t.Fatalf("process_source = %v", m["process_source"])
	}
}

func TestLane09OpListJebUnitsSyntheticDex(t *testing.T) {
	dex := jebdDex(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "classes.dex"), dex, 0o644); err != nil {
		t.Fatal(err)
	}
	v, err := runOp("list_jeb_units", dir)
	if err != nil {
		t.Fatal(err)
	}
	res := v.(jebdUnits)
	if len(res.Errors) != 0 || len(res.Units) != 2 {
		t.Fatalf("units/errors = %d/%v", len(res.Units), res.Errors)
	}
	if res.Units[0].Class != "Lcom/example/Alpha;" ||
		!reflect.DeepEqual(res.Units[0].Methods, []string{"a"}) ||
		!reflect.DeepEqual(res.Units[0].Abstract, []string{"b"}) {
		t.Fatalf("alpha = %+v", res.Units[0])
	}
	if res.Units[1].Class != "Lcom/example/Beta;" || !reflect.DeepEqual(res.Units[1].Methods, []string{"c"}) {
		t.Fatalf("beta = %+v", res.Units[1])
	}
	// A project with no classes*.dex must error, not return an empty success.
	empty := t.TempDir()
	if err := os.WriteFile(filepath.Join(empty, "smali"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := runOp("list_jeb_units", empty); err == nil || !strings.Contains(err.Error(), "no classes") {
		t.Fatalf("no-dex error = %v", err)
	}
}
