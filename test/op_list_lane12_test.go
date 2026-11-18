package main

// Lane A12's items: the two frida host-table listings, the Electron/CDP pair,
// the DEX unit lister, list_strings and the four Ghidra-backed listings.
//
// Nothing here needs a network or an engine: adb is a shell stand-in on PATH,
// the CDP transport is the cdp.go seam, and the DEX fixture is built byte by
// byte so the parser is exercised without a real APK.

import (
	"archive/zip"
	"context"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// lane12Ops is the lane's inventory: name -> route and whether it wants a target.
var lane12Ops = map[string]struct {
	route string
	needs bool
}{
	"list_electron_targets":           {"Y", true},
	"list_frida_devices":              {"Y", false},
	"list_frida_processes":            {"Y", false},
	"list_javascript_runtime_targets": {"Y", true},
	"list_jeb_units":                  {"L", true},
	"list_names":                      {"G", true},
	"list_procedures":                 {"G", true},
	"list_segments":                   {"G", true},
	"list_strings":                    {"L", true},
	"list_unknowns":                   {"G", true},
}

func TestLane12Registered(t *testing.T) {
	for name, want := range lane12Ops {
		o, ok := ops[name]
		if !ok {
			t.Errorf("%s is not registered", name)
			continue
		}
		if o.route != want.route || o.needs != want.needs {
			t.Errorf("%s route/needs = %s/%v, want %s/%v", name, o.route, o.needs, want.route, want.needs)
		}
		if o.desc == "" || o.run == nil {
			t.Errorf("%s has no desc or run", name)
		}
	}
}

// TestLane12MissingTarget: every item that reads a document refuses without one,
// and the refusal classifies as needs_arg rather than as an internal error.
func TestLane12MissingTarget(t *testing.T) {
	for name, want := range lane12Ops {
		if !want.needs {
			continue
		}
		v, err := runOp(name, "")
		if err == nil {
			t.Errorf("%s answered %T without a target, want a refusal", name, v)
			continue
		}
		if got := classify(err.Error()); got != kindNeedsArg {
			t.Errorf("%s without a target: kind %s (%q), want %s", name, got, err, kindNeedsArg)
		}
	}
}

// TestLane12BrokenTarget: a path that is not there is io for the items that open
// a file, and bad_arg for the CDP pair, whose target is a host:port and never a
// path. Neither may answer with a zero result.
func TestLane12BrokenTarget(t *testing.T) {
	want := map[string]errorKind{
		"list_electron_targets":           kindBadArg,
		"list_javascript_runtime_targets": kindBadArg,
		"list_jeb_units":                  kindIO,
		"list_names":                      kindIO,
		"list_procedures":                 kindIO,
		"list_segments":                   kindIO,
		"list_strings":                    kindIO,
		"list_unknowns":                   kindIO,
	}
	for name, k := range want {
		v, err := runOp(name, "/nonexistent-xyz")
		if err == nil {
			t.Errorf("%s answered %T for a path that is not there", name, v)
			continue
		}
		if got := classify(err.Error()); got != k {
			t.Errorf("%s broken target: kind %s (%q), want %s", name, got, err, k)
		}
	}
}

// lane12FakeAdb puts a stand-in named adb alone on PATH: the body is verbatim
// shell, so each test states exactly what the device table advertised.
func lane12FakeAdb(t *testing.T, body string) {
	t.Helper()
	dir := t.TempDir()
	script := "#!/bin/sh\n" + body + "\n"
	if err := os.WriteFile(filepath.Join(dir, "adb"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	// The adb alternative path is a hint string, not a fallback binary, but a
	// stray ANDROID_SERIAL would still change which device answers.
	t.Setenv("ANDROID_SERIAL", "")
}

func TestLane12FridaDevicesEmptyTable(t *testing.T) {
	lane12FakeAdb(t, `printf 'List of devices attached\n\n'`)
	v, err := runOp("list_frida_devices", "")
	if err != nil {
		t.Fatalf("empty device table: %v", err)
	}
	list := v.(rt2FridaDeviceList)
	if list.Count != 1 || len(list.Devices) != 1 {
		t.Fatalf("devices %v, want only the host row", list.Devices)
	}
	if d := list.Devices[0]; d.ID != "local" || d.Type != "local" {
		t.Errorf("host row %+v, want id/type local", d)
	}
	if !strings.Contains(list.Note, "listed no rows") {
		t.Errorf("note %q must say the table was empty", list.Note)
	}
}

func TestLane12FridaDevicesRows(t *testing.T) {
	lane12FakeAdb(t, `printf 'List of devices attached\nR58M\tdevice usb:1-1 product:x model:SM_G960F\nZZZ\toffline\n'`)
	v, err := runOp("list_frida_devices", "/nonexistent-xyz") // needs=false: the target is ignored
	if err != nil {
		t.Fatalf("device table: %v", err)
	}
	list := v.(rt2FridaDeviceList)
	if list.Count != 3 {
		t.Fatalf("count %d (%v), want host + 2 rows", list.Count, list.Devices)
	}
	if got := list.Devices[1]; got.ID != "R58M" || got.Name != "SM_G960F" || got.OS != "Android" {
		t.Errorf("usb row %+v", got)
	}
	if !strings.Contains(list.Note, `ZZZ is "offline"`) {
		t.Errorf("note %q must name the offline row and its state", list.Note)
	}
}

func TestLane12FridaDevicesNoAdb(t *testing.T) {
	t.Setenv("PATH", t.TempDir()) // no adb at all
	v, err := opListFridaDevices("")
	if err != nil {
		t.Fatalf("missing adb must be a skip, got error %v", err)
	}
	sk, ok := v.(*skip)
	if !ok {
		t.Fatalf("got %T, want a *skip: a device list cannot be invented", v)
	}
	if !strings.Contains(sk.Reason, "adb") {
		t.Errorf("skip reason %q must name adb", sk.Reason)
	}
}

// TestLane12FridaProcessesHostNote is the regression test for the dangling
// separator: with an empty device table the note ended in "; " and nothing.
func TestLane12FridaProcessesHostNote(t *testing.T) {
	lane12FakeAdb(t, `printf 'List of devices attached\n\n'`)
	v, err := runOp("list_frida_processes", "")
	if err != nil {
		t.Fatalf("host table: %v", err)
	}
	list := v.(rt2FridaProcessList)
	if list.Device != "local" || list.DeviceType != "local" {
		t.Errorf("device %q/%q, want the host table", list.Device, list.DeviceType)
	}
	const want = `no device in state "device": the host table answers`
	if list.Note != want {
		t.Errorf("note %q, want %q", list.Note, want)
	}
	if list.Count != len(list.Processes) || list.Count == 0 {
		t.Errorf("count %d for %d rows, want the kernel table", list.Count, len(list.Processes))
	}
}

func TestLane12FridaProcessesOfflineRow(t *testing.T) {
	lane12FakeAdb(t, `printf 'List of devices attached\nZZZ\toffline\n'`)
	v, err := runOp("list_frida_processes", "")
	if err != nil {
		t.Fatalf("offline table: %v", err)
	}
	note := v.(rt2FridaProcessList).Note
	if !strings.Contains(note, `no device in state "device"`) || !strings.Contains(note, "ZZZ is offline") {
		t.Errorf("note %q must keep the host sentence and name the row", note)
	}
	if strings.HasSuffix(note, "; ") {
		t.Errorf("note %q ends in a dangling separator", note)
	}
}

func TestLane12FridaProcessesDevice(t *testing.T) {
	lane12FakeAdb(t, `case "$1" in
devices) printf 'List of devices attached\nR58M\tdevice usb:1-1 product:x model:SM_G960F\n' ;;
*) printf '  PID NAME\n    1 init\n  456 adbd\n' ;;
esac`)
	v, err := runOp("list_frida_processes", "")
	if err != nil {
		t.Fatalf("device table: %v", err)
	}
	list := v.(rt2FridaProcessList)
	if list.Device != "R58M" || list.DeviceType != "usb" {
		t.Fatalf("device %q/%q, want R58M/usb", list.Device, list.DeviceType)
	}
	if list.Count != 2 || len(list.Processes) != 2 {
		t.Fatalf("processes %v, want 2 rows", list.Processes)
	}
	if p := list.Processes[0]; p.PID != 1 || p.Name != "init" {
		t.Errorf("first row %+v", p)
	}
	if !strings.Contains(list.Note, "adb shell ps") {
		t.Errorf("note %q must name the command that answered", list.Note)
	}
}

// lane12Dex builds the smallest DEX this reader walks: one class
// Lcom/x/A; with one abstract method a, no code items.
func lane12Dex() []byte {
	b := make([]byte, 0xC0)
	copy(b, "dex\n035\x00")
	binary.LittleEndian.PutUint32(b[0x20:], uint32(len(b))) // file_size
	binary.LittleEndian.PutUint32(b[0x24:], 0x70)           // header_size
	binary.LittleEndian.PutUint32(b[0x28:], 0x12345678)     // endian_tag

	binary.LittleEndian.PutUint32(b[0x38:], 2)    // string_ids_size
	binary.LittleEndian.PutUint32(b[0x3C:], 0x70) // string_ids_off
	binary.LittleEndian.PutUint32(b[0x70:], 0xB0) // "Lcom/x/A;"
	binary.LittleEndian.PutUint32(b[0x74:], 0xBC) // "a"

	binary.LittleEndian.PutUint32(b[0x40:], 1)    // type_ids_size
	binary.LittleEndian.PutUint32(b[0x44:], 0x78) // type_ids_off
	binary.LittleEndian.PutUint32(b[0x78:], 0)    // type 0 -> string 0

	binary.LittleEndian.PutUint32(b[0x58:], 1)    // method_ids_size
	binary.LittleEndian.PutUint32(b[0x5C:], 0x7C) // method_ids_off
	binary.LittleEndian.PutUint32(b[0x80:], 1)    // name_idx -> "a"

	binary.LittleEndian.PutUint32(b[0x60:], 1)          // class_defs_size
	binary.LittleEndian.PutUint32(b[0x64:], 0x84)       // class_defs_off
	binary.LittleEndian.PutUint32(b[0x84:], 0)          // class_idx
	binary.LittleEndian.PutUint32(b[0x88:], 0x1)        // access_flags: public
	binary.LittleEndian.PutUint32(b[0x8C:], 0xFFFFFFFF) // superclass_idx: none
	binary.LittleEndian.PutUint32(b[0x94:], 0xFFFFFFFF) // source_file_idx: none
	binary.LittleEndian.PutUint32(b[0x9C:], 0xA4)       // class_data_off

	b[0xA4], b[0xA5], b[0xA6], b[0xA7] = 0, 0, 1, 0 // static, instance, direct, virtual fields
	b[0xA8], b[0xA9], b[0xAA] = 0, 1, 0             // method_idx_diff, access, code_off (no code)

	// A string_data_item is a ULEB utf16 length then MUTF-8 bytes.
	b[0xB0] = 9
	copy(b[0xB1:], "Lcom/x/A;\x00")
	b[0xBC] = 1
	copy(b[0xBD:], "a\x00")
	return b
}

func TestLane12JebUnitsClass(t *testing.T) {
	p := filepath.Join(t.TempDir(), "classes.dex")
	if err := os.WriteFile(p, lane12Dex(), 0o600); err != nil {
		t.Fatal(err)
	}
	v, err := runOp("list_jeb_units", p)
	if err != nil {
		t.Fatalf("one-class dex: %v", err)
	}
	res := v.(jebdUnits)
	if len(res.Dex) != 1 || !strings.HasSuffix(res.Dex[0], "classes.dex") {
		t.Errorf("dex %v, want the one file", res.Dex)
	}
	if len(res.Units) != 1 {
		t.Fatalf("units %v, want one class", res.Units)
	}
	u := res.Units[0]
	if u.Class != "Lcom/x/A;" {
		t.Errorf("class %q", u.Class)
	}
	if len(u.Methods) != 0 || len(u.Abstract) != 1 || u.Abstract[0] != "a" {
		t.Errorf("methods %v abstract %v, want a listed as abstract", u.Methods, u.Abstract)
	}
	if len(res.Errors) != 0 {
		t.Errorf("errors %v, want none", res.Errors)
	}
}

func TestLane12JebUnitsNoClassDefs(t *testing.T) {
	b := lane12Dex()
	binary.LittleEndian.PutUint32(b[0x60:], 0) // class_defs_size
	binary.LittleEndian.PutUint32(b[0x64:], 0) // class_defs_off
	p := filepath.Join(t.TempDir(), "classes.dex")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	v, err := runOp("list_jeb_units", p)
	if err != nil {
		t.Fatalf("dex without classes: %v", err)
	}
	res := v.(jebdUnits)
	if len(res.Units) != 0 {
		t.Errorf("units %v, want none", res.Units)
	}
	if !strings.Contains(res.Note, "no class_defs") {
		t.Errorf("note %q must explain the empty table", res.Note)
	}
	// The empty table is still an array: a null reads as a missing field.
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"units":[]`) {
		t.Errorf("json %s must carry units as an empty array", raw)
	}
}

func TestLane12JebUnitsNotADex(t *testing.T) {
	p := filepath.Join(t.TempDir(), "notes.bin")
	if err := os.WriteFile(p, []byte("not a dex"), 0o600); err != nil {
		t.Fatal(err)
	}
	v, err := runOp("list_jeb_units", p)
	if err == nil {
		t.Fatalf("answered %T for a file that is not a DEX", v)
	}
	if !strings.Contains(err.Error(), "not a readable DEX image") {
		t.Errorf("error %q must say the file is not a DEX", err)
	}
	if got := classify(err.Error()); got != kindBadArg {
		t.Errorf("kind %s, want %s", got, kindBadArg)
	}
}

func TestLane12StringsPositive(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Skip("no executable path to read")
	}
	v, err := runOp("list_strings", exe)
	if err != nil {
		t.Fatalf("strings of the test binary: %v", err)
	}
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Strings      int              `json:"strings"`
		Shown        int              `json:"shown"`
		Truncated    bool             `json:"truncated"`
		Scanned      uint64           `json:"scanned"`
		ScannedWhole bool             `json:"scanned_whole"`
		Rows         []map[string]any `json:"rows"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if got.Strings == 0 || got.Shown == 0 || len(got.Rows) != got.Shown {
		t.Fatalf("strings %d shown %d rows %d, want a bounded sample", got.Strings, got.Shown, len(got.Rows))
	}
	if got.Truncated != (got.Strings > got.Shown) {
		t.Errorf("truncated %v for %d of %d", got.Truncated, got.Shown, got.Strings)
	}
	if got.Scanned == 0 || !got.ScannedWhole {
		t.Errorf("scanned %d scanned_whole %v, want the whole small file", got.Scanned, got.ScannedWhole)
	}
	for _, k := range []string{"address", "file_offset", "len", "value"} {
		if _, ok := got.Rows[0][k]; !ok {
			t.Errorf("row %v has no %s", got.Rows[0], k)
		}
	}
}

func TestLane12StringsNotABinary(t *testing.T) {
	p := filepath.Join(t.TempDir(), "notes.txt")
	if err := os.WriteFile(p, []byte("plain text"), 0o600); err != nil {
		t.Fatal(err)
	}
	if v, err := runOp("list_strings", p); err == nil {
		t.Fatalf("answered %T for a text file", v)
	} else if got := classify(err.Error()); got != kindBadArg {
		t.Errorf("kind %s (%q), want %s", got, err, kindBadArg)
	}
}

// lane12Driver answers every CDP call with out: cdp.go keeps webTransport as the
// one seam, so the op layer runs without a socket.
func lane12Driver(t *testing.T, out webOut) {
	t.Helper()
	prev := webTransport
	webTransport = func(context.Context, webSpec) (webOut, error) { return out, nil }
	t.Cleanup(func() { webTransport = prev })
}

func TestLane12ElectronIsolatedWorld(t *testing.T) {
	lane12Driver(t, webOut{
		Steps: []webStepResult{
			{Method: "Runtime.enable", Ok: true, Result: map[string]any{}},
			{Method: "Runtime.evaluate", Ok: true, Result: map[string]any{"result": map[string]any{"value": "Mozilla/5.0 Chrome/130.0.0.0 Electron/33.2.1 Safari/537.36"}}},
		},
		Events: []webEvent{
			{Method: "Runtime.executionContextCreated", Params: map[string]any{"context": map[string]any{"id": float64(2), "name": "", "origin": "file://", "auxData": map[string]any{"type": "default", "isDefault": true}}}},
			{Method: "Runtime.executionContextCreated", Params: map[string]any{"context": map[string]any{"id": float64(1), "name": electronWorldName, "origin": "file://", "auxData": map[string]any{"type": "isolated"}}}},
			{Method: "Runtime.executionContextDestroyed", Params: map[string]any{"executionContextId": float64(9)}},
		},
	})
	v, err := runOp("list_electron_targets", "127.0.0.1:9222")
	if err != nil {
		t.Fatalf("electron report: %v", err)
	}
	res := v.(electronReport)
	if res.Verdict != "electron" || !res.Isolated || res.UAelectron != "33.2.1" {
		t.Errorf("verdict %q isolated %v ua %q", res.Verdict, res.Isolated, res.UAelectron)
	}
	if len(res.Contexts) != 2 || res.Contexts[0].ID != 1 || !res.Contexts[1].IsDefault {
		t.Errorf("contexts %+v, want two rows sorted by id", res.Contexts)
	}
	if len(res.Attribution) == 0 || res.Attribution[0] != "runtime" {
		t.Errorf("attribution %v, want the isolated world named", res.Attribution)
	}
}

// TestLane12ElectronEmptyLists: with no contexts the report still carries arrays.
func TestLane12ElectronEmptyLists(t *testing.T) {
	lane12Driver(t, webOut{Steps: []webStepResult{
		{Method: "Runtime.enable", Ok: true, Result: map[string]any{}},
		{Method: "Runtime.evaluate", Ok: true, Result: map[string]any{"result": map[string]any{"value": "Mozilla/5.0 Chrome/130.0.0.0 Safari/537.36"}}},
	}})
	v, err := runOp("list_electron_targets", "127.0.0.1:9222")
	if err != nil {
		t.Fatalf("bare page: %v", err)
	}
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	doc := string(raw)
	for _, want := range []string{`"targets":[]`, `"contexts":[]`, `"attribution":[]`, `"verdict":"not-seen"`} {
		if !strings.Contains(doc, want) {
			t.Errorf("json %s must carry %s", doc, want)
		}
	}
}

// TestLane12ElectronProbeFailure: a rejected Runtime.enable cannot become the
// verdict "not-seen", which would claim Electron is absent after a probe that
// never ran.
func TestLane12ElectronProbeFailure(t *testing.T) {
	lane12Driver(t, webOut{Steps: []webStepResult{
		{Method: "Runtime.enable", Ok: false, Error: &webStepError{Code: -32601, Message: "method not found"}},
	}})
	v, err := runOp("list_electron_targets", "127.0.0.1:9222")
	if err == nil {
		t.Fatalf("answered %T after a rejected probe, want a refusal", v)
	}
	if !strings.Contains(err.Error(), "Runtime.enable") || !strings.Contains(err.Error(), "method not found") {
		t.Errorf("error %q must name the step and its CDP error", err)
	}
	if got := classify(err.Error()); got != kindNoEngine {
		t.Errorf("kind %s (%q), want %s", got, err, kindNoEngine)
	}
}

func TestLane12JSRuntimeTargets(t *testing.T) {
	lane12Driver(t, webOut{Steps: []webStepResult{
		{Method: "Target.getTargets", Ok: true, Result: map[string]any{"targetInfos": []any{
			map[string]any{"targetId": "T1", "type": "page", "title": "App", "url": "file:///a/index.html", "attached": true},
			map[string]any{"targetId": "T2", "type": "service_worker", "title": "sw", "url": "file:///a/sw.js"},
		}}},
	}})
	v, err := runOp("list_javascript_runtime_targets", "127.0.0.1:9222")
	if err != nil {
		t.Fatalf("target list: %v", err)
	}
	res := v.(runtimeTargets)
	if res.Count != 2 || len(res.Targets) != 2 {
		t.Fatalf("targets %+v", res.Targets)
	}
	if got := res.Targets[0]; got.ID != "T1" || got.Type != "page" || !got.Attached || got.URL != "file:///a/index.html" {
		t.Errorf("first target %+v", got)
	}
	if res.Targets[1].Attached {
		t.Errorf("second target %+v, want attached false", res.Targets[1])
	}
}

// TestLane12JSRuntimeNoTargets: a live endpoint with nothing to list is a
// missing process plane, not an lrecon fault.
func TestLane12JSRuntimeNoTargets(t *testing.T) {
	lane12Driver(t, webOut{Steps: []webStepResult{
		{Method: "Target.getTargets", Ok: true, Result: map[string]any{"targetInfos": []any{}}},
	}})
	if v, err := runOp("list_javascript_runtime_targets", "127.0.0.1:9222"); err == nil {
		t.Fatalf("answered %T for an empty endpoint", v)
	} else {
		if !strings.Contains(err.Error(), "no targets") {
			t.Errorf("error %q must say there were no targets", err)
		}
		if got := classify(err.Error()); got != kindNoEngine {
			t.Errorf("kind %s (%q), want %s", got, err, kindNoEngine)
		}
	}
}

// TestLane12JSRuntimeStepFailure: a step that never ran is a refusal, not an
// empty list.
func TestLane12JSRuntimeStepFailure(t *testing.T) {
	lane12Driver(t, webOut{Steps: []webStepResult{
		{Method: "Target.getTargets", Ok: false, Error: &webStepError{Code: -32601, Message: "method not found"}},
	}})
	if v, err := runOp("list_javascript_runtime_targets", "127.0.0.1:9222"); err == nil {
		t.Fatalf("answered %T, want a refusal", v)
	} else if !strings.Contains(err.Error(), "Target.getTargets") {
		t.Errorf("error %q must name the method", err)
	}
}

// lane12DexN is lane12Dex generalised to n classes, each with one abstract
// method named a: the shape a code-sized dex has, built from the header down.
func lane12DexN(n int) []byte {
	strCount := n + 1 // one descriptor per class, plus the method name
	strOff := 0x70
	typOff := strOff + 4*strCount
	metOff := typOff + 4*n
	clsOff := metOff + 8*n
	dataOff := clsOff + 32*n
	strs := make([][]byte, strCount)
	for i := range n {
		strs[i] = []byte("Lcom/x/C" + strconv.Itoa(i) + ";")
	}
	strs[n] = []byte("a")
	dataLen := 0
	for _, s := range strs {
		dataLen += 2 + len(s) // ULEB length byte + bytes + NUL
	}
	classDataOff := dataOff + dataLen
	b := make([]byte, classDataOff+7*n)
	copy(b, "dex\n035\x00")
	binary.LittleEndian.PutUint32(b[0x20:], uint32(len(b)))
	binary.LittleEndian.PutUint32(b[0x24:], 0x70)
	binary.LittleEndian.PutUint32(b[0x28:], 0x12345678)
	binary.LittleEndian.PutUint32(b[0x38:], uint32(strCount))
	binary.LittleEndian.PutUint32(b[0x3C:], uint32(strOff))
	binary.LittleEndian.PutUint32(b[0x40:], uint32(n))
	binary.LittleEndian.PutUint32(b[0x44:], uint32(typOff))
	binary.LittleEndian.PutUint32(b[0x58:], uint32(n))
	binary.LittleEndian.PutUint32(b[0x5C:], uint32(metOff))
	binary.LittleEndian.PutUint32(b[0x60:], uint32(n))
	binary.LittleEndian.PutUint32(b[0x64:], uint32(clsOff))
	pos := dataOff
	for i, s := range strs {
		binary.LittleEndian.PutUint32(b[strOff+4*i:], uint32(pos))
		b[pos] = byte(len(s))
		copy(b[pos+1:], s)
		pos += 2 + len(s)
	}
	for i := range n {
		binary.LittleEndian.PutUint32(b[typOff+4*i:], uint32(i))   // descriptor
		binary.LittleEndian.PutUint16(b[metOff+8*i:], uint16(i))   // class_idx
		binary.LittleEndian.PutUint32(b[metOff+8*i+4:], uint32(n)) // name_idx -> "a"
		at := clsOff + 32*i
		binary.LittleEndian.PutUint32(b[at:], uint32(i))
		binary.LittleEndian.PutUint32(b[at+4:], 1) // public
		binary.LittleEndian.PutUint32(b[at+8:], 0xFFFFFFFF)
		binary.LittleEndian.PutUint32(b[at+20:], 0xFFFFFFFF) // source_file_idx
		binary.LittleEndian.PutUint32(b[at+24:], uint32(classDataOff+7*i))
		cd := classDataOff + 7*i
		b[cd], b[cd+1], b[cd+2], b[cd+3] = 0, 0, 1, 0
		b[cd+4], b[cd+5], b[cd+6] = 0, 1, 0 // abstract: no code item
	}
	return b
}

// BenchmarkLane12JebdUnitsOf guards the class_data walk: the listing answers a
// whole dex, so the per-class cost is the number that matters.
func BenchmarkLane12JebdUnitsOf(b *testing.B) {
	raw := lane12DexN(1000)
	b.ReportAllocs()
	for b.Loop() {
		units, errs := jebdUnitsOf(raw)
		if len(units) != 1000 || len(errs) != 0 {
			b.Fatalf("units %d errs %v", len(units), errs)
		}
	}
}

// lane12Apk writes a zip holding one copy of the lane fixture per entry name,
// in the order given, so the multi-dex order is the archive's order.
func lane12Apk(t *testing.T, names ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "app.apk")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zw := zip.NewWriter(f)
	for _, name := range names {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(lane12Dex()); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

// An APK carries several classes*.dex; every readable one is a separate image
// and must be reported, not just the first.
func TestLane12JebUnitsApkMultipleDex(t *testing.T) {
	v, err := runOp("list_jeb_units", lane12Apk(t, "classes.dex", "classes2.dex"))
	if err != nil {
		t.Fatalf("two-dex apk: %v", err)
	}
	res := v.(jebdUnits)
	if len(res.Dex) != 2 || !strings.HasSuffix(res.Dex[0], "!classes.dex") || !strings.HasSuffix(res.Dex[1], "!classes2.dex") {
		t.Errorf("dex %v, want both archive entries in order", res.Dex)
	}
	if len(res.Units) != 2 {
		t.Fatalf("units %v, want one class per dex", res.Units)
	}
	for _, u := range res.Units {
		if u.Class != "Lcom/x/A;" || len(u.Abstract) != 1 {
			t.Errorf("unit %+v, want the fixture class", u)
		}
	}
	if len(res.Errors) != 0 {
		t.Errorf("errors %v, want none", res.Errors)
	}
}

// A decoded project is a directory; classes.dex and classes2.dex are ordered by
// index, not by readdir order (readdir gave classes2.dex first here).
func TestLane12JebUnitsProjectDir(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "classes2.dex"), lane12Dex(), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "classes.dex"), lane12Dex(), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("not a dex"), 0o600); err != nil {
		t.Fatal(err)
	}
	v, err := runOp("list_jeb_units", dir)
	if err != nil {
		t.Fatalf("project dir: %v", err)
	}
	res := v.(jebdUnits)
	if len(res.Dex) != 2 || !strings.HasSuffix(res.Dex[0], "classes.dex") || !strings.HasSuffix(res.Dex[1], "classes2.dex") {
		t.Errorf("dex %v, want classes.dex then classes2.dex", res.Dex)
	}
	if len(res.Units) != 2 {
		t.Errorf("units %v, want one per dex file", res.Units)
	}
}

// A zip whose .dex entry is not a DEX must not be reported as a readable image.
func TestLane12JebUnitsApkWithJunkDex(t *testing.T) {
	path := filepath.Join(t.TempDir(), "junk.apk")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	w, err := zw.Create("classes.dex")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("not a dex at all, just text")); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	_, err = runOp("list_jeb_units", path)
	if err == nil {
		t.Fatal("junk apk: want a refusal")
	}
	if !strings.Contains(err.Error(), "carries no classes*.dex") {
		t.Errorf("error %q, want the no-classes refusal", err)
	}
	if k := classify(err.Error()); k != kindBadArg {
		t.Errorf("kind %q, want %q", k, kindBadArg)
	}
}

// The four Ghidra listings must refuse, not fall over, when analyzeHeadless is
// not where the environment says it is. LRECON_GHIDRA is authoritative (see
// findGhidra): a bad value is an error, so this proves the absent-engine path
// without touching the installed Ghidra.
func TestLane12GhidraMissingEngine(t *testing.T) {
	t.Setenv("LRECON_GHIDRA", filepath.Join(t.TempDir(), "no-such-analyzeHeadless"))

	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"list_names", "list_procedures", "list_segments", "list_unknowns"} {
		v, err := runOp(name, self)
		if err != nil {
			t.Errorf("%s: unexpected error %v", name, err)
			continue
		}
		s, ok := v.(*skip)
		if !ok {
			t.Errorf("%s: want a *skip refusal, got %T", name, v)
			continue
		}
		if k := classify(s.Reason); k != kindNoEngine {
			t.Errorf("%s: reason %q classifies %q, want %q", name, s.Reason, k, kindNoEngine)
		}
	}
}
