package main

// Tur 5, lane 01: gercek op davranisi, sahte host araci ve sahte artifact ile.
// Uretim kodu gevsetilmez; her test gercek regex/parser/run yolunu calistirir.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// tur5FakeADB, bir op'in gercek `adb` surecini offline calistirmasi icin tek
// yollu bir kabuk betigi yazar. Cikti sahte, cokecek regex ve tablo ayristirici
// uretim kodundandir.
func tur5FakeADB(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "adb"), []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatalf("fake adb yazilamadi: %v", err)
	}
	t.Setenv("PATH", dir)
	return dir
}

func TestTur5L01InspectADBClientRealVersionAndDevices(t *testing.T) {
	tur5FakeADB(t, `case "$*" in
  "version") printf '%s\n' 'Android Debug Bridge version 1.0.41' 'Version 35.0.2-13114751' 'Installed as /sdk/platform-tools/adb' ;;
  "devices -l") printf 'List of devices attached\nemulator-5554 device product:sdk_gphone model:Pixel transport_id:1\n\n' ;;
  *) echo "beklenmeyen adb arg: $*" >&2; exit 2 ;;
esac`)

	v, err := ops["inspect_adb_client"].run("/bin/true")
	if err != nil {
		t.Fatalf("inspect_adb_client: %v", err)
	}
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var got rtADBClient
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got.ClientVersion != "1.0.41" || got.Build != "35.0.2-13114751" || got.Path != "/sdk/platform-tools/adb" {
		t.Fatalf("client = %+v", got)
	}
	if len(got.Devices) != 1 || got.Devices[0].Serial != "emulator-5554" || got.Devices[0].State != "device" ||
		got.Devices[0].Product != "sdk_gphone" || got.Devices[0].Model != "Pixel" || got.Devices[0].TransportID != "1" {
		t.Fatalf("devices = %+v", got.Devices)
	}
}

func TestTur5L01InspectADBClientEmptyDeviceTableIsAnAnswer(t *testing.T) {
	tur5FakeADB(t, `case "$*" in
  "version") printf '%s\n' 'Android Debug Bridge version 1.0.41' 'Version 35.0.2-13114751' 'Installed as /sdk/platform-tools/adb' ;;
  "devices -l") printf 'List of devices attached\n\n' ;;
  *) echo "beklenmeyen adb arg: $*" >&2; exit 2 ;;
esac`)

	v, err := ops["inspect_adb_client"].run("/bin/true")
	if err != nil {
		t.Fatalf("bos cihaz tablosu reddedildi: %v", err)
	}
	b, _ := json.Marshal(v)
	var got struct {
		Devices []rtDevice `json:"devices"`
	}
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got.Devices == nil || len(got.Devices) != 0 {
		t.Fatalf("bos tablo [] degil: %+v", got.Devices)
	}
}

func TestTur5L01ListADBProcessesRealTable(t *testing.T) {
	tur5FakeADB(t, `case "$*" in
  "devices -l") printf 'List of devices attached\nemulator-5554 device\n\n' ;;
  *"-o PID,USER,NAME,ARGS"*) printf 'PID USER NAME ARGS\n100 shell zygote /system/bin/zygote --socket=z\n200 u0_a1 com.app com.app -x y\n' ;;
  *) echo "beklenmeyen adb arg: $*" >&2; exit 2 ;;
esac`)

	v, err := runOp("list_adb_processes", "")
	if err != nil {
		t.Fatalf("list_adb_processes: %v", err)
	}
	b, _ := json.Marshal(v)
	var got rtADBProcesses
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got.Command != "ps -A -o PID,USER,NAME,ARGS" || got.Count != 2 || len(got.Rows) != 2 {
		t.Fatalf("tablo = %+v", got)
	}
	if got.Rows[0].PID != "100" || got.Rows[0].User != "shell" || got.Rows[0].Name != "zygote" ||
		got.Rows[0].Args != "/system/bin/zygote --socket=z" {
		t.Fatalf("satir 0 = %+v", got.Rows[0])
	}
	if got.Rows[1].PID != "200" || got.Rows[1].User != "u0_a1" || got.Rows[1].Name != "com.app" ||
		got.Rows[1].Args != "com.app -x y" {
		t.Fatalf("satir 1 = %+v", got.Rows[1])
	}
}

func TestTur5L01ListADBProcessesFallbackLegacyPS(t *testing.T) {
	tur5FakeADB(t, `case "$*" in
  "devices -l") printf 'List of devices attached\nemulator-5554 device\n\n' ;;
  *"-o PID,USER,NAME,ARGS"*) echo 'ps: -o not supported' >&2; exit 1 ;;
  *" shell ps") printf 'u0_a1 321 1 1000 2000 0 0 S com.legacy\n' ;;
  *) echo "beklenmeyen adb arg: $*" >&2; exit 2 ;;
esac`)

	v, err := runOp("list_adb_processes", "")
	if err != nil {
		t.Fatalf("fallback ps: %v", err)
	}
	b, _ := json.Marshal(v)
	var got rtADBProcesses
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got.Command != "ps" || got.Count != 1 {
		t.Fatalf("fallback tablo = %+v", got)
	}
	if got.Rows[0].PID != "321" || got.Rows[0].User != "u0_a1" || got.Rows[0].Name != "com.legacy" {
		t.Fatalf("legacy satir = %+v", got.Rows[0])
	}
	if len(got.Columns) != 9 || got.Columns[0] != "USER" || got.Columns[8] != "NAME" {
		t.Fatalf("legacy kolonlar = %v", got.Columns)
	}
}

func tur5FuseFile(t *testing.T, tail []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "Framework")
	if err := os.WriteFile(p, append([]byte("MZ"), append([]byte(fuseSentinel), tail...)...), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestTur5L01ElectronFusesWireStates(t *testing.T) {
	// Electron wire: sentinel + version + count + bir fuse basi durum bayti.
	p := tur5FuseFile(t, append([]byte{1, 4}, []byte("10rx")...))

	off, wire, err := fuseWire(p)
	if err != nil || off != 2 || len(wire) < 6 || wire[0] != 1 || wire[1] != 4 {
		t.Fatalf("fuseWire = off %d wire %q err %v", off, wire, err)
	}

	v, err := ops["inspect_electron_fuses"].run(p)
	if err != nil {
		t.Fatalf("inspect_electron_fuses: %v", err)
	}
	b, _ := json.Marshal(v)
	var got struct {
		WireOffset int64 `json:"wire_offset"`
		Version    int   `json:"wire_version"`
		Count      int   `json:"fuse_count"`
		Fuses      []struct {
			Index int    `json:"index"`
			Name  string `json:"name"`
			State string `json:"state"`
		} `json:"fuses"`
	}
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got.WireOffset != 2 || got.Version != 1 || got.Count != 4 || len(got.Fuses) != 4 {
		t.Fatalf("wire = %+v", got)
	}
	want := []struct{ name, state string }{
		{"RunAsNode", "enabled"},
		{"EnableCookieEncryption", "disabled"},
		{"EnableNodeOptionsEnvironmentVariable", "removed"},
		{"EnableNodeCliInspectArguments", "invalid"},
	}
	for i, w := range want {
		if got.Fuses[i].Index != i+1 || got.Fuses[i].Name != w.name || got.Fuses[i].State != w.state {
			t.Fatalf("fuse %d = %+v, want %s %s", i, got.Fuses[i], w.name, w.state)
		}
	}
}

func TestTur5L01ElectronFusesRefusals(t *testing.T) {
	// Sentinel yok: op skip donderir, hata degil.
	plain := filepath.Join(t.TempDir(), "plain")
	if err := os.WriteFile(plain, []byte("MZ not electron"), 0o644); err != nil {
		t.Fatal(err)
	}
	v, err := ops["inspect_electron_fuses"].run(plain)
	if err != nil {
		t.Fatalf("sentinel yoksa hata: %v", err)
	}
	sk, ok := v.(*skip)
	if !ok || !strings.Contains(sk.Reason, "no Electron fuse wire") {
		t.Fatalf("skip = %+v", v)
	}

	// Sentinel var ama versiyon bayti yok: truncate edilmis wire reddedilir.
	_, err = ops["inspect_electron_fuses"].run(tur5FuseFile(t, []byte{1}))
	if err == nil || !strings.Contains(err.Error(), "no fuse version byte") {
		t.Fatalf("truncated wire = %v", err)
	}

	// Count sinir disinda: 33 fuse uydurulamaz.
	_, err = ops["inspect_electron_fuses"].run(tur5FuseFile(t, append([]byte{1, 33}, []byte(strings.Repeat("1", 33))...)))
	if err == nil || !strings.Contains(err.Error(), "count must be 1..32") {
		t.Fatalf("count 33 = %v", err)
	}

	// Count, wire'dan uzun: eksik bayt reddedilir.
	_, err = ops["inspect_electron_fuses"].run(tur5FuseFile(t, []byte{1, 8, '1', '0'}))
	if err == nil || !strings.Contains(err.Error(), "not as long as its count declares") {
		t.Fatalf("short wire = %v", err)
	}
}

// TestTur5L01OpsJSONContractAlignment: bu lane'in 3 op'u için ops.json
// sözleşme satırlarını registerOp ve gerçek run davranışıyla eşleştirir.
// Tablo alanları (route/needs/no_args/with_target/fixture) pinlenir; sensiz
// sözleşmeler (needs_arg, bad_arg) in-process olarak çalıştırılır.
func TestTur5L01OpsJSONContractAlignment(t *testing.T) {
	tbl, err := loadOpTable(opTablePath)
	if err != nil {
		t.Fatalf("load %s: %v", opTablePath, err)
	}
	want := map[string]opTableRow{
		"inspect_adb_client":     {Name: "inspect_adb_client", Route: "Y", Needs: false, Expect: opExpectation{NoArgs: opClassNoEngine, WithTarget: opClassNotApplicable}},
		"list_adb_processes":     {Name: "list_adb_processes", Route: "Y", Needs: false, Expect: opExpectation{NoArgs: opClassNoEngine, WithTarget: opClassNotApplicable}},
		"inspect_electron_fuses": {Name: "inspect_electron_fuses", Route: "L", Needs: true, Expect: opExpectation{NoArgs: opClassNeedsArg, WithTarget: opClassBadArg, Fixture: "macho"}},
	}
	rows := make(map[string]opTableRow, len(tbl.Ops))
	for _, row := range tbl.Ops {
		rows[row.Name] = row
	}
	for name, w := range want {
		row, ok := rows[name]
		if !ok {
			t.Fatalf("ops.json missing %q", name)
		}
		if row.Route != w.Route || row.Needs != w.Needs || row.Expect != w.Expect {
			t.Fatalf("ops.json %q = %+v, want %+v", name, row, w)
		}
		o, ok := ops[name]
		if !ok {
			t.Fatalf("registerOp missing %q", name)
		}
		if o.route != row.Route || o.needs != row.Needs {
			t.Fatalf("%q register route/needs = %q/%v, ops.json = %q/%v", name, o.route, o.needs, row.Route, row.Needs)
		}
	}

	// needs=true + no target -> needs_arg (runOp rejects before the op runs).
	_, err = runOp("inspect_electron_fuses", "")
	if err == nil || !strings.Contains(err.Error(), "needs a target path") {
		t.Fatalf("fuses no target = %v, want needs a target path", err)
	}

	// needs=false -> no target is never a needs_arg refusal (route Y still runs).
	for _, name := range []string{"inspect_adb_client", "list_adb_processes"} {
		_, err := runOp(name, "")
		if err != nil && strings.Contains(err.Error(), "needs a target path") {
			t.Fatalf("%s no target = needs_arg, ops.json says %s", name, opClassNoEngine)
		}
	}

	// with_target=bad_arg on fixture=macho: a Mach-O with no fuse wire yields
	// *skip ("not an Electron binary"); main turns a bare skip into a refusal
	// whose prose class is wrong_kind, which lives as bad_arg.
	macho := filepath.Join(t.TempDir(), "target.bin")
	if err := os.WriteFile(macho, []byte{0xcf, 0xfa, 0xed, 0xfe, 0x0c, 0, 0, 0}, 0o644); err != nil {
		t.Fatal(err)
	}
	v, err := ops["inspect_electron_fuses"].run(macho)
	if err != nil {
		t.Fatal(err)
	}
	sk, ok := v.(*skip)
	if !ok {
		t.Fatalf("macho fixture = %T, want *skip", v)
	}
	class, _ := classifyOpRun(2, "", sk.Reason)
	if class != opClassWrongKind && class != opClassBadArg {
		t.Fatalf("macho fixture class = %q, want %q/%q (bad_arg live)", class, opClassWrongKind, opClassBadArg)
	}
}
