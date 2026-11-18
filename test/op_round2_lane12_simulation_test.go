package main

// Tur 2 Lane 12 independent audit simulation tests.
// Verifies real behavior only; production code is not loosened.

import (
	"debug/macho"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// ---------- A: web ops ----------

func TestR2L12InspectWebPage(t *testing.T) {
	fakeDriver(t, webOut{
		Target: &webTargetRow{ID: "T1"},
		Steps: []webStepResult{
			okStep("Runtime.enable", map[string]any{}),
			okStep("Runtime.evaluate", map[string]any{"result": map[string]any{"value": map[string]any{
				"href": "http://127.0.0.1:9222/app", "title": "Demo", "readyState": "complete",
				"nodes": float64(42), "html": float64(1234), "w": float64(800), "h": float64(600), "ua": "UA/1",
			}}}),
		},
	})
	f := fields(t, run(t, "inspect_web_page", "127.0.0.1:9222"))
	if f["ready_state"] != "complete" || f["url"] != "http://127.0.0.1:9222/app" || f["target"] != "T1" {
		t.Fatalf("page = %v", f)
	}
	if f["nodes"] != float64(42) || f["html_bytes"] != float64(1234) || f["width"] != float64(800) || f["height"] != float64(600) {
		t.Fatalf("numeric fields = %v", f)
	}

	// If readyState is absent, it must be refused as a Runtime.enable violation.
	fakeDriver(t, webOut{Steps: []webStepResult{
		okStep("Runtime.enable", map[string]any{}),
		okStep("Runtime.evaluate", map[string]any{"result": map[string]any{"value": map[string]any{"href": "x"}}}),
	}})
	if _, err := runOp("inspect_web_page", "127.0.0.1:9222"); err == nil || !strings.Contains(err.Error(), "no readyState") {
		t.Fatalf("missing readyState: got %v", err)
	}
}

func TestR2L12ListBrowserTargets(t *testing.T) {
	fakeDriver(t, webOut{
		Targets: []webTargetRow{
			{ID: "1", Type: "page", Title: "A"},
			{ID: "2", Type: "worker", Title: "B"},
			{ID: "3", Type: "page", Title: "C"},
		},
		Version: map[string]any{"webSocketDebuggerUrl": "ws://127.0.0.1:9222/devtools/browser/x"},
	})
	f := fields(t, run(t, "list_browser_targets", "127.0.0.1:9222"))
	if f["count"] != float64(3) {
		t.Fatalf("count = %v", f["count"])
	}
	by := f["by_type"].(map[string]any)
	if by["page"] != float64(2) || by["worker"] != float64(1) {
		t.Fatalf("by_type = %v", by)
	}
	if f["browser_ws"] != "ws://127.0.0.1:9222/devtools/browser/x" {
		t.Fatalf("browser_ws = %v", f["browser_ws"])
	}

	fakeDriver(t, webOut{})
	if _, err := runOp("list_browser_targets", "127.0.0.1:9222"); err == nil || !strings.Contains(err.Error(), "JsonListIsEmpty") {
		t.Fatalf("empty target list: got %v", err)
	}
}

func TestR2L12ListElectronTargets(t *testing.T) {
	ctx2 := map[string]any{"id": float64(2), "name": electronWorldName, "origin": "http://x", "auxData": map[string]any{"type": "isolated"}}
	ctx1 := map[string]any{"id": float64(1), "name": "", "origin": "http://x", "auxData": map[string]any{"isDefault": true, "type": "default"}}
	fakeDriver(t, webOut{
		Targets: []webTargetRow{{ID: "T1", Type: "page"}},
		Steps: []webStepResult{
			okStep("Runtime.enable", map[string]any{}),
			okStep("Runtime.evaluate", map[string]any{"result": map[string]any{"value": "Mozilla/5.0 Electron/28.1.0 Chrome/120"}}),
		},
		Events: []webEvent{
			event("Runtime.executionContextCreated", map[string]any{"context": ctx2}),
			event("Runtime.executionContextCreated", map[string]any{"context": ctx1}),
		},
	})
	f := fields(t, run(t, "list_electron_targets", "127.0.0.1:9222"))
	if f["verdict"] != "electron" || f["electron_isolated_world"] != true {
		t.Fatalf("verdict = %v isolated = %v", f["verdict"], f["electron_isolated_world"])
	}
	if f["ua_electron_version"] != "28.1.0" {
		t.Fatalf("ua_electron = %v", f["ua_electron_version"])
	}
	ctxs := f["contexts"].([]any)
	if len(ctxs) != 2 || ctxs[0].(map[string]any)["id"] != float64(1) {
		t.Fatalf("contexts not sorted by id: %v", ctxs)
	}
	attr := f["attribution"].([]any)
	if len(attr) != 2 || attr[0] != "runtime" || attr[1] != "ua" {
		t.Fatalf("attribution = %v", attr)
	}

	// UA Electron but no isolated world -> "possible".
	fakeDriver(t, webOut{Steps: []webStepResult{
		okStep("Runtime.enable", map[string]any{}),
		okStep("Runtime.evaluate", map[string]any{"result": map[string]any{"value": "Electron/9.0.0"}}),
	}})
	f = fields(t, run(t, "list_electron_targets", "127.0.0.1:9222"))
	if f["verdict"] != "possible" || f["electron_isolated_world"] != false {
		t.Fatalf("possible verdict = %v", f)
	}
	if f["contexts"].([]any) == nil {
		t.Fatal("contexts must be a []")
	}
}

func TestR2L12ListJavascriptRuntimeTargets(t *testing.T) {
	fakeDriver(t, webOut{Steps: []webStepResult{okStep("Target.getTargets", map[string]any{
		"targetInfos": []any{
			map[string]any{"targetId": "A", "type": "page", "title": "P", "url": "http://x", "attached": true},
			map[string]any{"targetId": "B", "type": "service_worker", "attached": false},
		},
	})}})
	f := fields(t, run(t, "list_javascript_runtime_targets", "127.0.0.1:9222"))
	if f["count"] != float64(2) {
		t.Fatalf("count = %v", f["count"])
	}
	rows := f["targets"].([]any)
	first := rows[0].(map[string]any)
	if first["id"] != "A" || first["type"] != "page" || first["attached"] != true {
		t.Fatalf("first target = %v", first)
	}
	second := rows[1].(map[string]any)
	if second["attached"] != false || second["id"] != "B" {
		t.Fatalf("second target = %v", second)
	}

	fakeDriver(t, webOut{Steps: []webStepResult{{Method: "Target.getTargets"}}})
	if _, err := runOp("list_javascript_runtime_targets", "127.0.0.1:9222"); err == nil {
		t.Fatal("failed Target.getTargets must be an error")
	}
}

// ---------- B: objdump ----------

func TestR2L12ObjdumpFormat(t *testing.T) {
	cases := []struct {
		name string
		b    []byte
		want string
	}{
		{"elf", []byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0}, "elf"},
		{"pe", []byte("MZ\x90\x00\x03\x00\x00\x00"), "pe"},
		{"archive", []byte("!<arch>\n"), "archive"},
		{"macho", []byte{0xcf, 0xfa, 0xed, 0xfe, 0x0c, 0, 0, 0}, "macho"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := objdumpFormat(writeTemp(t, c.name+".bin", c.b)); got != c.want {
				t.Fatalf("format = %q, want %q", got, c.want)
			}
		})
	}
	if got := objdumpFormat(writeTemp(t, "empty.bin", nil)); got != "" {
		t.Fatalf("unreadable short file = %q, want empty", got)
	}
}

func TestR2L12ObjdumpSymbolsText(t *testing.T) {
	if got := symbolsText(nil, "%016x %c %s\n"); got != "(no symbol table: stripped, or the format stores none here)" {
		t.Fatalf("empty = %q", got)
	}
	got := symbolsText([]objectSymbol{{Value: 0x10, Kind: 'T', Name: "main"}}, "%016x %c %s\n")
	if got != fmt.Sprintf("%016x %c %s\n", 0x10, 'T', "main") {
		t.Fatalf("symbols = %q", got)
	}
}

// arHeader builds one 60-byte BSD ar header.
func r2l12ARHeader(name string, size int) []byte {
	h := make([]byte, 60)
	for i := range h {
		h[i] = ' '
	}
	copy(h[0:], name)
	copy(h[48:], strconv.Itoa(size))
	copy(h[58:], "`\n")
	return h
}

func TestR2L12ObjdumpArchiveMembers(t *testing.T) {
	longName := "very_long_nm" // 12 bytes
	payload := []byte("hello")
	raw := []byte("!<arch>\n")
	raw = append(raw, r2l12ARHeader("#1/12", len(longName)+len(payload))...)
	raw = append(raw, []byte(longName)...)
	raw = append(raw, payload...)
	if len(raw)%2 == 1 {
		raw = append(raw, '\n')
	}
	got, err := archiveMembers(writeTemp(t, "lib.a", raw))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, longName) || !strings.Contains(got, "5 bytes") {
		t.Fatalf("members = %q, want long name and 5 bytes", got)
	}
	if strings.Contains(got, "#1/12") {
		t.Fatalf("raw BSD name leaked: %q", got)
	}
	got, err = archiveMembers(writeTemp(t, "empty.a", []byte("!<arch>\n")))
	if err != nil || got != "(no members)" {
		t.Fatalf("empty archive = %q, %v", got, err)
	}
}

// ---------- C: ADB helpers ----------

func TestR2L12InstallReason(t *testing.T) {
	stderr := "adb: failed to install /tmp/app.apk:\nException occurred while executing 'install':\njava.lang.IllegalArgumentException: bad manifest\n"
	if got := installReason(stderr); got != "java.lang.IllegalArgumentException: bad manifest" {
		t.Fatalf("reason = %q", got)
	}
	if got := installReason("adb: failed to install x.apk:\n"); got != "" {
		t.Fatalf("filtered-only = %q", got)
	}
}

func TestR2L12AdbShellQuote(t *testing.T) {
	if got := adbShellQuote("a'b c"); got != `'a'\''b c'` {
		t.Fatalf("quote = %q", got)
	}
	if got := adbShellQuote("/sdcard/x"); got != `'/sdcard/x'` {
		t.Fatalf("simple quote = %q", got)
	}
}

func TestR2L12AdbPSTable(t *testing.T) {
	// -o table with header: ARGS spans more than one column.
	layout, rows := adbPSTable("PID USER NAME ARGS\n100 shell zygote /system/bin/zygote --socket=z\n200 u0_a1 com.app com.app -x y\n")
	if layout.pid != 0 || layout.name != 2 || len(rows) != 2 {
		t.Fatalf("layout = %+v rows = %+v", layout, rows)
	}
	if rows[0].PID != "100" || rows[0].Name != "zygote" || rows[0].Args != "/system/bin/zygote --socket=z" {
		t.Fatalf("row0 = %+v", rows[0])
	}
	// Headerless legacy 9-column table.
	_, legacy := adbPSTable("u0_a1 321 1 1000 2000 0 0 S com.legacy\n")
	if len(legacy) != 1 || legacy[0].PID != "321" || legacy[0].Name != "com.legacy" {
		t.Fatalf("legacy = %+v", legacy)
	}
	// If the first line is not a table it is skipped; a later valid line is still read.
	_, junk := adbPSTable("not a table\n1 u a b\n")
	if len(junk) != 1 || junk[0].PID != "1" || junk[0].Name != "a" {
		t.Fatalf("junk rows = %+v", junk)
	}
	if _, ok := adbPSHeader([]string{"PID", "NAME"}); !ok {
		t.Fatal("PID+NAME header must be accepted")
	}
	if _, ok := adbPSHeader([]string{"PID", "ARGS"}); ok {
		t.Fatal("header without NAME must be refused")
	}
	if _, ok := adbPSInfer([]string{"123", "proc", "args", "more"}); !ok {
		t.Fatal("numeric-first row must infer")
	}
}

func TestR2L12RtParseDevices(t *testing.T) {
	devs := rtParseDevices("List of devices attached\nR58M\tdevice product:beyond1lte model:SM_G973F transport_id:1\nZZZ\tunauthorized\n")
	if len(devs) != 2 {
		t.Fatalf("devices = %+v", devs)
	}
	if devs[0].Serial != "R58M" || devs[0].State != "device" || devs[0].Model != "SM_G973F" || devs[0].TransportID != "1" {
		t.Fatalf("dev0 = %+v", devs[0])
	}
	if devs[1].State != "unauthorized" {
		t.Fatalf("dev1 = %+v", devs[1])
	}
	if got := rtParseDevices("List of devices attached\n"); got == nil || len(got) != 0 {
		t.Fatalf("empty = %+v", got)
	}
}

func TestR2L12ThinAlign(t *testing.T) {
	f := &macho.File{Sections: []*macho.Section{
		{SectionHeader: macho.SectionHeader{Align: 2}},
		{SectionHeader: macho.SectionHeader{Align: 7}},
		{SectionHeader: macho.SectionHeader{Align: 3}},
	}}
	if got := thinAlign(f); got != 7 {
		t.Fatalf("thinAlign = %d, want 7", got)
	}
	if got := thinAlign(&macho.File{}); got != 0 {
		t.Fatalf("no sections = %d", got)
	}
}

func TestR2L12CsHashFor(t *testing.T) {
	data := []byte("abc")
	if h := csHashFor(1); h == nil {
		t.Fatal("typ1 = nil")
	} else if got := len(h(data)); got != 20 {
		t.Fatalf("typ1 len = %d, want 20", got)
	}
	if h := csHashFor(2); h == nil {
		t.Fatal("typ2 = nil")
	} else if got := len(h(data)); got != 32 {
		t.Fatalf("typ2 len = %d, want 32", got)
	}
	h3, h2 := csHashFor(3), csHashFor(2)
	if h3 == nil || !slices.Equal(h3(data), h2(data)[:20]) {
		t.Fatal("typ3 must be sha256 truncated to 20")
	}
	if h := csHashFor(4); h == nil {
		t.Fatal("typ4 = nil")
	} else if got := len(h(data)); got != 48 {
		t.Fatalf("typ4 len = %d, want 48", got)
	}
	if csHashFor(99) != nil {
		t.Fatal("unknown hash type must be nil")
	}
}

func TestR2L12MetaRequireBookmarkAddress(t *testing.T) {
	if err := metaRequireBookmarkAddress(metaJob{}); err == nil || !strings.Contains(err.Error(), `job needs "address"`) {
		t.Fatalf("empty address = %v", err)
	}
	if err := metaRequireBookmarkAddress(metaJob{Address: "0x1000"}); err != nil {
		t.Fatalf("valid address = %v", err)
	}
}

// ---------- D: ADB ops (real shim) ----------

const r2l12OneDevice = `if [ "$1" = "devices" ]; then printf 'List of devices attached\nR58M\tdevice product:beyond1lte model:SM_G973F transport_id:1\n'; exit 0; fi
`

func TestR2L12ListADBDevicesAndFeatures(t *testing.T) {
	t.Run("devices", func(t *testing.T) {
		rtFakeTool(t, "adb", `printf 'List of devices attached\nR58M\tdevice model:SM_G973F\n'`)
		// list_adb_devices returns the bare []rtDevice array, not an envelope.
		v := run(t, "list_adb_devices", "")
		devs, ok := v.([]rtDevice)
		if !ok || len(devs) != 1 || devs[0].Serial != "R58M" || devs[0].Model != "SM_G973F" {
			t.Fatalf("devices = %+v (%T)", v, v)
		}
	})
	t.Run("features", func(t *testing.T) {
		rtFakeTool(t, "adb", `if [ "$1" = "host-features" ]; then printf 'shell_v2,\r\n,cmd,stat,\n'; exit 0; fi`)
		f := fields(t, run(t, "list_adb_features", ""))
		if f["count"] != float64(3) {
			t.Fatalf("features = %v", f)
		}
		feats := f["features"].([]any)
		if !slices.Equal([]any{"shell_v2", "cmd", "stat"}, feats) {
			t.Fatalf("feature list = %v", feats)
		}
	})
	t.Run("features empty refuses", func(t *testing.T) {
		rtFakeTool(t, "adb", `printf ' \n'`)
		if _, err := runOp("list_adb_features", ""); err == nil || !strings.Contains(err.Error(), "printed nothing") {
			t.Fatalf("empty features = %v", err)
		}
	})
}

func TestR2L12ListADBPackagesDirectoryProcesses(t *testing.T) {
	t.Run("packages last equals", func(t *testing.T) {
		rtFakeTool(t, "adb", r2l12OneDevice+`
if [ "$3" = "shell" ]; then
printf 'package:/data/app/~~abc==/com.example=a==/base.apk=com.example.foo\n'
printf 'junk line\n'
exit 0; fi`)
		f := fields(t, run(t, "list_adb_packages", ""))
		if f["count"] != float64(1) {
			t.Fatalf("packages = %v", f)
		}
		row := f["packages"].([]any)[0].(map[string]any)
		if row["package"] != "com.example.foo" || row["apk"] != "/data/app/~~abc==/com.example=a==/base.apk" {
			t.Fatalf("row = %v", row)
		}
	})
	t.Run("directory", func(t *testing.T) {
		rtFakeTool(t, "adb", r2l12OneDevice+`
if [ "$3" = "shell" ]; then
printf 'total 2\ndrwxr-xr-x 2 shell shell 4096 2024-01-01 12:00 my dir\n-rw-r--r-- 1 shell shell 10 2024-01-01 12:00 file.txt\n'
exit 0; fi`)
		f := fields(t, run(t, "list_adb_directory", "/sdcard/my dir"))
		entries := f["entries"].([]any)
		if len(entries) != 2 {
			t.Fatalf("entries = %v", entries)
		}
		dir := entries[0].(map[string]any)
		if dir["name"] != "my dir" || dir["dir"] != true || dir["size"] != "4096" {
			t.Fatalf("dir = %v", dir)
		}
		file := entries[1].(map[string]any)
		if file["name"] != "file.txt" || file["dir"] != false || file["size"] != "10" {
			t.Fatalf("file = %v", file)
		}
	})
	t.Run("processes", func(t *testing.T) {
		rtFakeTool(t, "adb", r2l12OneDevice+`
if [ "$3" = "shell" ]; then
printf 'PID USER NAME ARGS\n100 shell zygote /system/bin/zygote --socket=z\n'
exit 0; fi`)
		f := fields(t, run(t, "list_adb_processes", ""))
		if f["count"] != float64(1) {
			t.Fatalf("processes = %v", f)
		}
		row := f["rows"].([]any)[0].(map[string]any)
		if row["pid"] != "100" || row["name"] != "zygote" || row["args"] != "/system/bin/zygote --socket=z" {
			t.Fatalf("row = %v", row)
		}
	})
}

func TestR2L12ListADBServices(t *testing.T) {
	rtFakeTool(t, "adb", `if [ "$1" = "devices" ]; then printf 'List of devices attached\nR58M\tdevice\n'; exit 0; fi
if [ "$1" = "shell" ]; then printf 'services:\n  activity\n  package\n\n'; exit 0; fi`)
	f := fields(t, run(t, "list_adb_services", ""))
	if f["count"] != float64(2) {
		t.Fatalf("services = %v", f)
	}
	rows := f["services"].([]any)
	if rows[0].(map[string]any)["name"] != "activity" || rows[1].(map[string]any)["name"] != "package" {
		t.Fatalf("rows = %v", rows)
	}
}

// ---------- E: Frida ops ----------

func TestR2L12ListFridaDevices(t *testing.T) {
	rtFakeTool(t, "adb", `printf 'List of devices attached\nR58M\tdevice model:SM_G973F\nZZZ\tunauthorized\n'`)
	f := fields(t, run(t, "list_frida_devices", ""))
	if f["count"] != float64(3) { // host + 2 adb rows
		t.Fatalf("frida devices = %v", f)
	}
	rows := f["devices"].([]any)
	host := rows[0].(map[string]any)
	if host["id"] != "local" || host["type"] != "local" {
		t.Fatalf("host = %v", host)
	}
	usb := rows[1].(map[string]any)
	if usb["id"] != "R58M" || usb["name"] != "SM_G973F" || usb["type"] != "usb" || usb["os"] != "Android" {
		t.Fatalf("usb = %v", usb)
	}
	note := f["note"].(string)
	if !strings.Contains(note, `ZZZ is "unauthorized"`) {
		t.Fatalf("note = %q", note)
	}

	rtFakeTool(t, "adb", `printf 'List of devices attached\n'`)
	f = fields(t, run(t, "list_frida_devices", ""))
	if f["count"] != float64(1) || !strings.Contains(f["note"].(string), "only the host row is real") {
		t.Fatalf("empty frida devices = %v", f)
	}
}

func TestR2L12ListFridaProcesses(t *testing.T) {
	rtFakeTool(t, "adb", r2l12OneDevice+`
if [ "$3" = "shell" ]; then
printf 'PID USER NAME ARGS\n100 shell zygote /system/bin/zygote\n200 u0_a1 com.app com.app -x\n'
exit 0; fi`)
	f := fields(t, run(t, "list_frida_processes", ""))
	if f["count"] != float64(2) || f["device"] != "R58M" {
		t.Fatalf("frida processes = %v", f)
	}
	rows := f["processes"].([]any)
	if rows[0].(map[string]any)["pid"] != float64(100) || rows[1].(map[string]any)["name"] != "com.app" {
		t.Fatalf("rows = %v", rows)
	}
}

func TestR2L12RtParseAdbPSLegacy(t *testing.T) {
	ps := rt2ParseAdbPS("u0_a1 321 1 1000 2000 0 0 S com.legacy\n")
	if len(ps) != 1 || ps[0].PID != 321 || ps[0].Name != "com.legacy" {
		t.Fatalf("rt2ParseAdbPS = %+v", ps)
	}
	if got := rt2ParseAdbPS("not a table\n"); len(got) != 0 {
		t.Fatalf("junk = %+v", got)
	}
}

func TestR2L12InstrumentFridaRefused(t *testing.T) {
	stdout, _, code := runCLIAll(t, "--op", "instrument_with_frida", "--json")
	if code != 2 {
		t.Fatalf("exit = %d, stdout = %s", code, stdout)
	}
	var e struct {
		Kind  string `json:"kind"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal([]byte(stdout), &e); err != nil {
		t.Fatalf("refusal not JSON: %v (%s)", err, stdout)
	}
	if e.Kind != string(kindOutOfScope) || !strings.Contains(strings.ToLower(e.Error), "out of scope") {
		t.Fatalf("refusal = %+v", e)
	}
}

// ---------- F: various list ops ----------

func TestR2L12ListArchitecturesSkip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "plain.bin")
	if err := os.WriteFile(p, []byte("not a binary"), 0o644); err != nil {
		t.Fatal(err)
	}
	v, err := runOp("list_architectures", p)
	if err != nil {
		t.Fatalf("list_architectures: %v", err)
	}
	if _, ok := v.(*skip); !ok {
		t.Fatalf("non-macho must skip, got %T: %v", v, v)
	}
}

func TestR2L12ListBookmarks(t *testing.T) {
	metaTestState(t)
	f := metaMustRun(t, "list_bookmarks", `{}`)
	if f["total"] != float64(0) || f["count"] != float64(0) || f["exists"] != false {
		t.Fatalf("bookmarks = %v", f)
	}
	if f["bookmarks"].([]any) == nil {
		t.Fatal("bookmarks must be []")
	}
}

func TestR2L12ListCutterSessionsAndDocuments(t *testing.T) {
	f := fields(t, run(t, "list_cutter_sessions", ""))
	if f["cutter_processes"].([]any) == nil || f["projects"].([]any) == nil {
		t.Fatalf("cutter = %v", f)
	}
	if f["rizin"] == nil || !strings.Contains(f["rizin"].(string), "filesystem-only") {
		t.Fatalf("rizin note = %v", f["rizin"])
	}
	// list_documents needs a recorded session with at least one document.
	metaTestState(t)
	doc := filepath.Join(t.TempDir(), "target.bin")
	if err := os.WriteFile(doc, []byte("MZ"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := saveSession(nativeSession{Kind: "lrecon.session/1", Project: "p", Document: doc, Documents: []string{doc}}); err != nil {
		t.Fatal(err)
	}
	d := fields(t, run(t, "list_documents", ""))
	rows := d["documents"].([]any)
	if len(rows) != 1 {
		t.Fatalf("documents = %v", d)
	}
	row := rows[0].(map[string]any)
	if row["selected"] != true || row["exists"] != true {
		t.Fatalf("doc row = %v", row)
	}
	if _, ok := d["session"]; !ok {
		t.Fatalf("session missing from %v", d)
	}
}

// ---------- G: JEB ----------

func TestR2L12JebUnits(t *testing.T) {
	dex := jebdDex(t)
	dir := t.TempDir()
	dexFile := filepath.Join(dir, "classes.dex")
	if err := os.WriteFile(dexFile, dex, 0o644); err != nil {
		t.Fatal(err)
	}
	// .dir order: classes.dex (1) and classes2.dex (2).
	dex2 := filepath.Join(dir, "classes2.dex")
	if err := os.WriteFile(dex2, dex, 0o644); err != nil {
		t.Fatal(err)
	}
	files, err := jebdDexFiles(dir)
	if err != nil || len(files) != 2 || !strings.HasSuffix(files[0], "classes.dex") || !strings.HasSuffix(files[1], "classes2.dex") {
		t.Fatalf("jebdDexFiles = %v, %v", files, err)
	}

	units, errs := jebdUnitsOf(dex)
	if len(errs) != 0 || len(units) != 2 {
		t.Fatalf("units = %+v errors = %v", units, errs)
	}
	if units[0].Class != "Lcom/example/Alpha;" || !slices.Equal(units[0].Methods, []string{"a"}) || !slices.Equal(units[0].Abstract, []string{"b"}) {
		t.Fatalf("alpha = %+v", units[0])
	}
	if units[1].Class != "Lcom/example/Beta;" || !slices.Equal(units[1].Methods, []string{"c"}) {
		t.Fatalf("beta = %+v", units[1])
	}

	// list_jeb_units parses every classes*.dex in the dir; use a single-dex
	// dir so the unit count is unambiguous.
	single := t.TempDir()
	if err := os.WriteFile(filepath.Join(single, "classes.dex"), dex, 0o644); err != nil {
		t.Fatal(err)
	}
	v, err := runOp("list_jeb_units", single)
	if err != nil {
		t.Fatalf("list_jeb_units: %v", err)
	}
	res := v.(jebdUnits)
	if len(res.Units) != 2 || len(res.Errors) != 0 {
		t.Fatalf("res = %+v", res)
	}

	apk := jebdApk(t, dex)
	imgs, err := jebdImages(apk)
	if err != nil || len(imgs) != 1 {
		t.Fatalf("jebdImages = %d, %v", len(imgs), err)
	}
}

// ---------- H: existing lane test helpers ----------

func TestR2L12ExistingHelpers(t *testing.T) {
	// op_lane05_simulation_test.go: writeVInt <-> production nibVInt roundtrip.
	for _, v := range []uint32{0, 1, 127, 128, 300, 0xffff, 0xffffffff} {
		got, n, err := nibVInt(writeVInt(v), 0)
		if err != nil || got != v || n <= 0 {
			t.Fatalf("VInt %d -> %d, n=%d, err=%v", v, got, n, err)
		}
	}

	// op_lane09_regression_test.go: structure of the synthetic ICMP frame.
	frame := lane09IPv4ICMPFrame([]byte{8, 0, 0, 0, 0, 0, 0, 0})
	if len(frame) != 14+20+8 || frame[12] != 0x08 || frame[13] != 0x00 || frame[23] != 1 {
		t.Fatalf("icmp frame = %s", hex.EncodeToString(frame))
	}
	if frame[16] != 0 || frame[17] != 28 {
		t.Fatalf("ip total length = %d", int(frame[16])<<8|int(frame[17]))
	}
}
