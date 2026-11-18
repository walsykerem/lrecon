package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Every RT2 op is tested twice: once with no tools on PATH (the structured
// skip, which is the answer on this host) and once against a fake tool planted
// on PATH that prints exactly what final.md §y documents. No test attaches a
// device, installs frida, or debugs anything.

const rt2TestFakeAdb = `#!/bin/sh
if [ "$1" = "devices" ]; then
  printf 'List of devices attached\nemulator-5554\tdevice\n'
  exit 0
fi
if [ "$1" = "pull" ]; then
  printf 'data' > "$3"
  exit 0
fi
if [ "$1" = "push" ]; then
  exit 0
fi
if [ "$1" = "exec-out" ]; then
  printf '[   12.345678] /dev/input/event2: EV_ABS       ABS_MT_POSITION_X    0000037f           3\n'
  printf '[   12.345679] /dev/input/event2: EV_SYN       SYN_REPORT           00000000           0\n'
  exit 0
fi
if [ "$1" != "shell" ]; then exit 0; fi
shift
case "$*" in
"dumpsys -l") printf 'Currently running services:\nactivity\nwindow\n' ;;
uiautomator\ dump*) printf 'UI hierchary dumped to: /data/local/tmp/ui-1.xml\n' ;;
cat\ *) printf '<hierarchy><node text="a"/><node text="b"/></hierarchy>\n' ;;
rm\ -f\ *) exit 0 ;;
stat\ -c\ %s\ *) printf '4\n' ;;
pm\ path\ *) printf 'package:/data/app/base.apk\npackage:/data/app/split_config.arm64_v8a.apk\n' ;;
pm\ uninstall*) printf 'Success\n' ;;
logcat*) printf '07-11 14:03:22.123  1234  1300 I ActivityManager: Start proc 1234\nnot a threadtime line\n' ;;
settings\ get\ *) printf '0\n' ;;
cmd\ package\ resolve-activity*) printf 'com.example/.MainActivity\n' ;;
am\ start*) printf 'Starting: Intent { act=android.intent.action.MAIN }\nStatus: ok\nActivity: com.example/.MainActivity\n' ;;
am\ force-stop*) exit 0 ;;
esac
`

// rt2TestFakeAdbUSB is the same adb, with one attachable phone and one offline
// serial, so the frida device and process tables carry both kinds of row. A
// shell call without `-s <serial>` fails the way adb does when two devices are
// attached, so an op that forgets to name the device it picked cannot pass.
const rt2TestFakeAdbUSB = `#!/bin/sh
if [ "$1" = "devices" ]; then
  printf 'List of devices attached\nR58M\tdevice product:beyond1lte model:SM_G973F transport_id:1\nZZZ\toffline\n'
  exit 0
fi
serial=""
if [ "$1" = "-s" ]; then serial="$2"; shift 2; fi
if [ "$1" != "shell" ]; then exit 0; fi
if [ -z "$serial" ]; then echo "adb: more than one device/emulator" >&2; exit 1; fi
shift
case "$*" in
ps\ -A\ -o\ PID,NAME*) printf '  PID NAME\n    1 init\n 1234 com.android.deskclock\n' ;;
esac
`

func rt2TestTools(t *testing.T, scripts map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range scripts {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o755); err != nil {
			t.Fatalf("write fake %s: %v", name, err)
		}
	}
	t.Setenv("PATH", dir)
	return dir
}

func rt2TestAllTools(t *testing.T) {
	t.Helper()
	rt2TestTools(t, map[string]string{"adb": rt2TestFakeAdb})
}

// rt2TestOp runs one op and fails on an error result.
func rt2TestOp(t *testing.T, name, target string) any {
	t.Helper()
	res, err := runOp(name, target)
	if err != nil {
		t.Fatalf("%s: unexpected error: %v", name, err)
	}
	return res
}

// rt2TestSkip asserts the op answered with a structured skip mentioning tool.
func rt2TestSkip(t *testing.T, name, target, mentions string) {
	t.Helper()
	res := rt2TestOp(t, name, target)
	sk, ok := res.(*skip)
	if !ok {
		t.Fatalf("%s: got %T (%v), want a skip", name, res, res)
	}
	if !strings.Contains(sk.Reason, mentions) {
		t.Fatalf("%s: skip %q does not mention %q", name, sk.Reason, mentions)
	}
}

// rt2HasPID reports whether a decoded process table contains pid.
func rt2HasPID(rows []rt2FridaProcess, pid int) bool {
	for _, p := range rows {
		if p.PID == pid {
			return true
		}
	}
	return false
}

func TestRt2OpsRegistered(t *testing.T) {
	// The 25 RT rows this half owns, with the item name exactly as in final.md.
	want := map[string]bool{ // value = needs
		"list_adb_services":          false,
		"list_frida_devices":         false,
		"list_frida_processes":       false,
		"load_frida_script":          false,
		"observe_native_calls":       true,
		"observe_native_ui":          false,
		"pull_adb_file":              true,
		"pull_adb_package":           true,
		"push_adb_file":              true,
		"read_adb_logcat":            false,
		"read_adb_setting":           true,
		"resolve_adb_packages":       true,
		"resume_frida_session":       false,
		"rizin_debug_command":        true,
		"rizin_debug_session_status": true,
		"start_adb_activity":         true,
		"start_adb_app":              true,
		"start_frida_session":        false,
		"start_gdb_session":          true,
		"start_rizin_debug_session":  true,
		"stop_adb_app":               true,
		"trace_native_ui_action":     false,
		"trace_native_values":        false,
		"uninstall_adb_package":      true,
		"unload_frida_script":        false,
	}
	for name, needs := range want {
		o, ok := ops[name]
		if !ok {
			t.Errorf("%s is not registered", name)
			continue
		}
		if o.route != "Y" {
			t.Errorf("%s has route %q, want Y", name, o.route)
		}
		if o.needs != needs {
			t.Errorf("%s has needs=%v, want %v", name, o.needs, needs)
		}
	}
}

func TestRt2NoToolsSkips(t *testing.T) {
	rt2TestTools(t, nil) // empty PATH: no adb, frida or rizin anywhere
	// push_adb_file stats the local file before it looks for adb (a missing
	// local file is io), so the skip case needs a file that really exists.
	local := filepath.Join(t.TempDir(), "x")
	if err := os.WriteFile(local, []byte("x"), 0o600); err != nil {
		t.Fatalf("write temp local file: %v", err)
	}
	cases := []struct{ name, target, mentions string }{
		{"list_adb_services", "", "adb not installed"},
		{"observe_native_ui", "", "adb not installed"},
		{"pull_adb_file", "/data/x:/tmp/x", "adb not installed"},
		{"pull_adb_package", "com.example", "adb not installed"},
		{"push_adb_file", local + ":/data/x", "adb not installed"},
		{"read_adb_logcat", "", "adb not installed"},
		{"read_adb_setting", "system:screen_brightness", "adb not installed"},
		{"resolve_adb_packages", "https://example.com", "adb not installed"},
		{"start_adb_activity", "com.example/.Main", "adb not installed"},
		{"start_adb_app", "com.example", "adb not installed"},
		{"stop_adb_app", "com.example", "adb not installed"},
		{"uninstall_adb_package", "com.example", "adb not installed"},
		{"trace_native_ui_action", "", "adb not installed"},
		{"list_frida_devices", "", "adb not installed"},
	}
	// start_gdb_session is not a skip any more: it refuses before looking for a
	// tool (see TestRt2LiveDebugOutOfScope). The rizin rows are the same refusal
	// (see TestRt2RizinOutOfScope).
	// resume_frida_session, unload_frida_script, load_frida_script,
	// start_frida_session and trace_native_values likewise refuse up front
	// (TestFridaSessionOutOfScope, TestFridaAttachOutOfScope).
	// list_frida_processes is not a skip either: the host table never needs a
	// tool, so without adb it still answers from the kernel (see
	// TestFridaHostProcessTable).
	if len(cases) != 14 {
		t.Fatalf("skip table covers %d ops, want 14", len(cases))
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) { rt2TestSkip(t, c.name, c.target, c.mentions) })
	}
}

func TestRt2NoDeviceSkips(t *testing.T) {
	// adb is installed but nothing is attached: y33-y56 style skip, not an error.
	rt2TestTools(t, map[string]string{
		"adb": "#!/bin/sh\nprintf 'List of devices attached\n'\n",
	})
	for _, name := range []string{"list_adb_services", "read_adb_logcat", "stop_adb_app"} {
		rt2TestSkip(t, name, "com.example", "no device attached")
	}
	// adb lists nothing: both frida items still answer, because the host row is
	// this machine and its process table comes from the kernel.
	devices := rt2TestOp(t, "list_frida_devices", "").(rt2FridaDeviceList)
	if devices.Count != 1 || devices.Devices[0].ID != "local" || devices.Devices[0].Type != "local" {
		t.Fatalf("empty adb table did not leave just the host row: %+v", devices)
	}
	if !strings.Contains(devices.Note, "listed no rows") {
		t.Fatalf("host-only device list does not say why: %q", devices.Note)
	}
	local := rt2TestOp(t, "list_frida_processes", "").(rt2FridaProcessList)
	// Compare the answer with its own rows, not with a second snapshot: the
	// kernel table changes between two calls on a busy host.
	if local.Device != "local" || local.DeviceType != "local" || local.Count == 0 || local.Count != len(local.Processes) {
		t.Fatalf("host process table = %+v, want count matching its non-empty rows", local)
	}
	if !rt2HasPID(local.Processes, os.Getpid()) {
		t.Fatalf("host process table does not contain the test process %d", os.Getpid())
	}
	if !strings.Contains(local.Note, `no device in state "device"`) {
		t.Fatalf("host process table does not say why: %q", local.Note)
	}
}

func TestRt2AdbParsers(t *testing.T) {
	rt2TestAllTools(t)
	t.Chdir(t.TempDir())

	svc := rt2TestOp(t, "list_adb_services", "").(rt2AdbServices)
	if svc.Count != 2 || svc.Services[0].Name != "activity" || svc.Services[1].Name != "window" {
		t.Fatalf("dumpsys -l parsed as %+v", svc)
	}

	lc := rt2TestOp(t, "read_adb_logcat", "").(rt2Logcat)
	if lc.Count != 1 || lc.Unparsed != 1 {
		t.Fatalf("logcat counts: %+v", lc)
	}
	e := lc.Entries[0]
	if e.Time != "07-11 14:03:22.123" || e.PID != 1234 || e.TID != 1300 || e.Level != "I" ||
		e.Tag != "ActivityManager" || e.Msg != "Start proc 1234" {
		t.Fatalf("logcat entry parsed as %+v", e)
	}

	setting := rt2TestOp(t, "read_adb_setting", "system:screen_brightness").(rt2AdbSetting)
	if setting.Namespace != "system" || setting.Key != "screen_brightness" || !setting.Set || *setting.Value != "0" {
		t.Fatalf("settings get parsed as %+v", setting)
	}

	// A "null" answer is unset, not the string "null".
	rt2TestTools(t, map[string]string{"adb": strings.Replace(rt2TestFakeAdb, "printf '0\\n'", "printf 'null\\n'", 1)})
	unset := rt2TestOp(t, "read_adb_setting", "screen_brightness").(rt2AdbSetting)
	if unset.Namespace != "system" || unset.Set || unset.Value != nil {
		t.Fatalf("unset setting parsed as %+v", unset)
	}

	rt2TestAllTools(t)
	for _, tc := range []struct {
		op, target string
		want       any
	}{
		{"resolve_adb_packages", "https://example.com", rt2ResolvedComponent{Component: "com.example/.MainActivity", Package: "com.example", Activity: ".MainActivity"}},
		{"start_adb_activity", "com.example/.MainActivity", rt2AdbStart{Component: "com.example/.MainActivity", Status: "ok", OK: true}},
		{"start_adb_app", "com.example", rt2StartedApp{Package: "com.example", Status: "ok", OK: true}},
		{"uninstall_adb_package", "com.example", rt2UninstalledPackage{Package: "com.example", Scope: "user0", Removed: true}},
	} {
		res := rt2TestOp(t, tc.op, tc.target)
		switch want := tc.want.(type) {
		case rt2ResolvedComponent:
			got := res.(rt2ResolvedIntents)
			if got.Count != 1 || got.Components[0] != want {
				t.Fatalf("%s parsed as %+v", tc.op, got)
			}
		default:
			if !rt2TestEqual(t, res, tc.want) {
				t.Fatalf("%s parsed as %+v, want %+v", tc.op, res, tc.want)
			}
		}
	}

	stop := rt2TestOp(t, "stop_adb_app", "com.example").(rt2StoppedApp)
	if !stop.Stopped || stop.Package != "com.example" {
		t.Fatalf("force-stop parsed as %+v", stop)
	}

	ui := rt2TestOp(t, "observe_native_ui", "").(rt2NativeUI)
	if !ui.Dumped || ui.Nodes != 2 || !strings.HasPrefix(ui.Path, "/data/local/tmp/ui-") {
		t.Fatalf("uiautomator dump parsed as %+v", ui)
	}
	if ui.Cleanup != "" {
		t.Fatalf("cleanup after a successful rm should be empty, got %q", ui.Cleanup)
	}

	trace := rt2TestOp(t, "trace_native_ui_action", "").(rt2UITrace)
	if trace.Count != 2 || trace.Unparsed != 0 || trace.Events[0].Value != 0x37f ||
		trace.Events[0].Code != "ABS_MT_POSITION_X" || trace.Events[0].Device != "/dev/input/event2" {
		t.Fatalf("getevent parsed as %+v", trace)
	}

	pulled := rt2TestOp(t, "pull_adb_file", "/data/x.bin:out.bin").(rt2PulledFile)
	if !pulled.Verified || pulled.RemoteBytes != 4 || pulled.LocalBytes != 4 || len(pulled.SHA256) != 64 {
		t.Fatalf("adb pull parsed as %+v", pulled)
	}

	pkg := rt2TestOp(t, "pull_adb_package", "com.example").(rt2PulledPackage)
	if pkg.Count != 2 || filepath.Base(pkg.Splits[1].Local) != "split_config.arm64_v8a.apk" {
		t.Fatalf("pm path pull parsed as %+v", pkg)
	}

	if err := os.WriteFile("push.bin", []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}
	pushed := rt2TestOp(t, "push_adb_file", "push.bin:/data/local/tmp/push.bin").(rt2PushedFile)
	if !pushed.Verified || pushed.LocalBytes != 4 {
		t.Fatalf("adb push parsed as %+v", pushed)
	}
}

// TestFridaDeviceTable is what frida-ls-devices used to draw, read instead from
// the host and from `adb devices -l`: one local row plus every adb serial, and
// the offline serial is listed but says why it cannot be attached to.
func TestFridaDeviceTable(t *testing.T) {
	rt2TestTools(t, map[string]string{"adb": rt2TestFakeAdbUSB})

	devices := rt2TestOp(t, "list_frida_devices", "").(rt2FridaDeviceList)
	if devices.Count != 3 {
		t.Fatalf("device table has %d rows, want host + 2 serials: %+v", devices.Count, devices)
	}
	host := devices.Devices[0]
	if host.ID != "local" || host.Type != "local" || host.Name == "" || host.OS == "" {
		t.Fatalf("host row = %+v, want a named local device", host)
	}
	if d := devices.Devices[1]; d.ID != "R58M" || d.Type != "usb" || d.Name != "SM_G973F" || d.OS != "Android" {
		t.Fatalf("attachable phone parsed as %+v", d)
	}
	if d := devices.Devices[2]; d.ID != "ZZZ" || d.Type != "usb" || d.Name != "ZZZ" {
		t.Fatalf("offline serial parsed as %+v", d)
	}
	if !strings.Contains(devices.Note, `ZZZ is "offline"`) {
		t.Fatalf("offline serial is not explained: %q", devices.Note)
	}
}

// TestFridaDeviceProcesses reads the phone's process table the way
// Device.EnumerateProcesses did, through `adb shell ps -A -o PID,NAME`.
func TestFridaDeviceProcesses(t *testing.T) {
	rt2TestTools(t, map[string]string{"adb": rt2TestFakeAdbUSB})

	ps := rt2TestOp(t, "list_frida_processes", "").(rt2FridaProcessList)
	if ps.Device != "R58M" || ps.DeviceType != "usb" || ps.Count != 2 {
		t.Fatalf("device process table = %+v, want R58M with 2 rows", ps)
	}
	if got := ps.Processes[1]; got.PID != 1234 || got.Name != "com.android.deskclock" {
		t.Fatalf("ps row parsed as %+v", got)
	}
}

// TestFridaHostProcessTable proves the kernel table is a real answer, not an
// empty fallback: this machine is a frida target too, and it needs no tool.
func TestFridaHostProcessTable(t *testing.T) {
	rt2TestTools(t, nil) // no adb, no frida: the host table still answers

	ps := rt2TestOp(t, "list_frida_processes", "").(rt2FridaProcessList)
	// Count and rows come from one snapshot: comparing Count against a second
	// listProcesses call was flaky by construction (521 vs 519 on a live host).
	if ps.Device != "local" || ps.DeviceType != "local" || ps.Count == 0 || ps.Count != len(ps.Processes) {
		t.Fatalf("host table = %+v, want a non-empty row list matching its count", ps)
	}
	if !rt2HasPID(ps.Processes, os.Getpid()) {
		t.Fatalf("host table does not contain the test process %d", os.Getpid())
	}
	for i, p := range ps.Processes {
		if p.PID <= 0 || p.Name == "" {
			t.Fatalf("row %d is not a process: %+v", i, p)
		}
		if i > 0 && ps.Processes[i-1].PID > p.PID {
			t.Fatalf("rows are not sorted by pid: %d before %d", ps.Processes[i-1].PID, p.PID)
		}
	}
	fresh, err := listProcesses()
	if err != nil {
		t.Fatalf("listProcesses: %v", err)
	}
	alive := make(map[int]bool, len(fresh))
	for _, p := range fresh {
		alive[p.PID] = true
	}
	overlap := 0
	for _, p := range ps.Processes {
		if alive[p.PID] {
			overlap++
		}
	}
	// A fabricated or cached table would name pids the kernel never had. Exact
	// equality is not the contract (churn between two reads is normal), most
	// rows still being alive is.
	if overlap*2 < ps.Count {
		t.Fatalf("only %d of %d reported rows exist in a fresh kernel read: %+v", overlap, ps.Count, ps.Processes)
	}
	if !strings.Contains(ps.Note, "adb is not installed") {
		t.Fatalf("host answer does not say why there is no device: %q", ps.Note)
	}
}

// TestRt2AdbPSLayouts covers both `ps` output shapes in the wild: toybox with
// an -o header, and the legacy fixed-column table with no honoured -o.
func TestRt2AdbPSLayouts(t *testing.T) {
	for _, tc := range []struct {
		name string
		out  string
		want []rt2FridaProcess
	}{
		{
			name: "toybox",
			out:  "  PID NAME\n    1 init\n 1234 com.android.deskclock\n",
			want: []rt2FridaProcess{{PID: 1, Name: "init"}, {PID: 1234, Name: "com.android.deskclock"}},
		},
		{
			name: "legacy",
			out: "USER PID PPID VSZ RSS WCHAN ADDR S NAME\n" +
				"root 1 0 12345 678 0 0 S init\n" +
				"u0_a12 2345 300 1234567 89000 0 0 S com.example/.Main\n",
			want: []rt2FridaProcess{{PID: 1, Name: "init"}, {PID: 2345, Name: "com.example/.Main"}},
		},
		{
			name: "garbage",
			out:  "not a process table\n",
			want: []rt2FridaProcess{},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := rt2ParseAdbPS(tc.out)
			if len(got) != len(tc.want) {
				t.Fatalf("parsed %d rows, want %d: %+v", len(got), len(tc.want), got)
			}
			for i := range tc.want {
				if got[i] != tc.want[i] {
					t.Fatalf("row %d = %+v, want %+v", i, got[i], tc.want[i])
				}
			}
		})
	}
}

// TestRt2LiveDebugOutOfScope pins report B7: lrecon reads static files, so the
// two "start a live debugger" items must refuse without spawning anything. The
// fake lldb/gdb/rizin below leave a marker if they are ever executed, and the
// budget catches a refusal that waits on a tool instead of answering.
func TestRt2LiveDebugOutOfScope(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "spawned")
	for _, tool := range []string{"lldb", "gdb", "rizin"} {
		script := "#!/bin/sh\nprintf '%s' " + strconv.Quote(tool) + " > " + strconv.Quote(marker) + "\nexit 1\n"
		if err := os.WriteFile(filepath.Join(dir, tool), []byte(script), 0o755); err != nil {
			t.Fatalf("write fake %s: %v", tool, err)
		}
	}
	t.Setenv("PATH", dir)

	cases := []struct{ name, wantError string }{
		{"start_gdb_session", "live debug sessions out of scope: lrecon reads static files only"},
		{"start_rizin_debug_session", "out of scope: live debug sessions are not part of lrecon;"},
	}
	for _, c := range cases {
		name, wantError := c.name, c.wantError
		t.Run(name, func(t *testing.T) {
			start := time.Now()
			stdout, stderr, code := runCLIAll(t, "--op", name, "--json", "/bin/ls")
			if elapsed := time.Since(start); elapsed >= time.Second {
				t.Fatalf("%s took %s; a scope refusal must not wait on a debugger", name, elapsed)
			}
			if code != 2 {
				t.Fatalf("%s exited %d, want 2 (refusal); stdout:\n%s\nstderr:\n%s", name, code, stdout, stderr)
			}
			var env struct {
				Op    string `json:"op"`
				Error string `json:"error"`
				Kind  string `json:"kind"`
			}
			if err := json.Unmarshal([]byte(stdout), &env); err != nil {
				t.Fatalf("%s: stdout is not the refusal envelope: %v\n%s", name, err, stdout)
			}
			if env.Op != name || !strings.Contains(env.Error, wantError) || env.Kind != "out_of_scope" {
				t.Fatalf("%s: envelope = %+v, want op=%q error containing %q kind=out_of_scope", name, env, name, wantError)
			}
			if _, err := os.Stat(marker); !os.IsNotExist(err) {
				t.Fatalf("%s launched an external tool (marker %s exists): a refusal must not start a process", name, marker)
			}
		})
	}
}

// TestRt2RizinOutOfScope covers the other rizin rows: the two command-console
// items point at the Ghidra ops with the same job, and the three debugger rows
// point at the lldb batch ops. None of them may spawn rizin.
func TestRt2RizinOutOfScope(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "spawned")
	if err := os.WriteFile(filepath.Join(dir, "rizin"), []byte("#!/bin/sh\nprintf '%s' rizin > "+strconv.Quote(marker)+"\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)

	cases := []struct{ name, target, want string }{
		{"execute_rizin_command", "/bin/ls", "list_procedures (rizin afl)"},
		{"cutter_command", "/bin/ls", "procedure_pseudo_code (rizin pdf)"},
		{"rizin_debug_command", "/bin/ls:dr", "gdb_console"},
		{"rizin_debug_session_status", "/bin/ls", "gdb_session_status"},
		{"close_rizin_debug_session", "/bin/ls", "close_gdb_session"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			stdout, _, code := runCLIAll(t, "--op", c.name, "--json", c.target)
			if code != 2 {
				t.Fatalf("%s exited %d, want 2 (refusal); stdout:\n%s", c.name, code, stdout)
			}
			var env struct {
				Error string `json:"error"`
				Kind  string `json:"kind"`
			}
			if err := json.Unmarshal([]byte(stdout), &env); err != nil {
				t.Fatalf("%s: stdout is not the refusal envelope: %v\n%s", c.name, err, stdout)
			}
			if env.Kind != "out_of_scope" || !strings.Contains(env.Error, c.want) {
				t.Fatalf("%s: envelope = %+v, want kind=out_of_scope naming %q", c.name, env, c.want)
			}
			if _, err := os.Stat(marker); !os.IsNotExist(err) {
				t.Fatalf("%s launched rizin (marker %s exists)", c.name, marker)
			}
		})
	}
}

// rt2TestEqual compares the flat structs asserted above without pulling in a
// reflection helper for one call site.
func rt2TestEqual(t *testing.T, got, want any) bool {
	t.Helper()
	switch w := want.(type) {
	case rt2AdbStart:
		g, ok := got.(rt2AdbStart)
		return ok && g == w
	case rt2StartedApp:
		g, ok := got.(rt2StartedApp)
		return ok && g == w
	case rt2UninstalledPackage:
		g, ok := got.(rt2UninstalledPackage)
		return ok && g == w
	}
	return false
}

// TestRt2ResolveAdbPackagesURL keeps the URI out of the website decline: the op
// is asked which app opens a URL on the device, so the URL is its argument.
func TestRt2ResolveAdbPackagesURL(t *testing.T) {
	rt2TestAllTools(t)
	stdout, stderr, code := runCLIAll(t, "--op", "resolve_adb_packages", "--json", "https://example.com")
	if code != 0 {
		t.Fatalf("exit %d, want 0 (answered)\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	if strings.Contains(stdout, "out of scope") || strings.Contains(stderr, "out of scope") {
		t.Fatalf("the URL was declined before the op ran: %s%s", stdout, stderr)
	}
	// A URL with no op is still declined: the exemption is per op.
	plain, _, code := runCLIAll(t, "--json", "https://example.com")
	if code != 2 || !strings.Contains(plain, "out of scope") {
		t.Fatalf("plain URL target: exit %d stdout %q, want the website decline", code, plain)
	}
}

// TestRt2GeteventHeaderNotUnparsed pins the getevent fix: the device table it
// prints on startup is not an event and must not be counted as a parse failure.
func TestRt2GeteventHeaderNotUnparsed(t *testing.T) {
	rt2TestTools(t, map[string]string{"adb": `#!/bin/sh
if [ "$1" = "devices" ]; then
  printf 'List of devices attached\nemulator-5554\tdevice\n'
  exit 0
fi
if [ "$1" = "exec-out" ]; then
  printf 'add device 1: /dev/input/event2\n  name: "virtio_input"\n  events:\n    KEY (0001): BTN_TOUCH\n'
  printf '[   12.345678] /dev/input/event2: EV_ABS       ABS_MT_POSITION_X    0000037f           3\n'
  printf '[   12.345679] /dev/input/event2: EV_SYN       SYN_REPORT           00000000           0\n'
  exit 0
fi
exit 0
`})
	trace := rt2TestOp(t, "trace_native_ui_action", "").(rt2UITrace)
	if trace.Unparsed != 0 {
		t.Fatalf("device table counted as unparsed: %+v", trace)
	}
	if trace.Count != 2 || trace.Events[0].Value != 0x37f {
		t.Fatalf("events parsed as %+v", trace)
	}
}

// TestRt2PullPermissionDenied keeps adb's refusal but adds the part a reader
// can act on: which paths the shell user can read.
func TestRt2PullPermissionDenied(t *testing.T) {
	rt2TestTools(t, map[string]string{"adb": `#!/bin/sh
if [ "$1" = "devices" ]; then
  printf 'List of devices attached\nemulator-5554\tdevice\n'
  exit 0
fi
if [ "$1" = "pull" ]; then
  echo "adb: error: failed to copy '$2' to '$3': remote open failed: Permission denied" >&2
  exit 1
fi
exit 0
`})
	local := filepath.Join(t.TempDir(), "build.prop")
	rt2TestSkip(t, "pull_adb_file", "/system/build.prop:"+local, "/sdcard")
}

// TestRt2BugreportzFailIsDeviceLimit pins the emulator answer: dumpstatez is
// disabled on the image and bugreportz says FAIL:<why>.
func TestRt2BugreportzFailIsDeviceLimit(t *testing.T) {
	rt2TestTools(t, map[string]string{"adb": `#!/bin/sh
if [ "$1" = "devices" ]; then
  printf 'List of devices attached\nemulator-5554\tdevice\n'
  exit 0
fi
if [ "$1" = "-s" ] && [ "$3" = "shell" ]; then
  # the device prints FAIL on stdout, which is why the op can read it
  echo "FAIL:Failed to connect to dumpstatez service: Connection refused"
  exit 1
fi
exit 0
`})
	rt2TestSkip(t, "collect_adb_bugreport", filepath.Join(t.TempDir(), "bug.zip"), "read_adb_logcat")
}

// TestRt2AMErrorCause pins the am-start fix: the banner line is not the reason.
func TestRt2AMErrorCause(t *testing.T) {
	rt2TestTools(t, map[string]string{"adb": `#!/bin/sh
if [ "$1" = "devices" ]; then
  printf 'List of devices attached\nemulator-5554\tdevice\n'
  exit 0
fi
if [ "$1" = "shell" ] || { [ "$1" = "-s" ] && [ "$3" = "shell" ]; }; then
  echo "Starting: Intent { act=android.intent.action.MAIN cat=[android.intent.category.LAUNCHER] pkg=com.example.nonexistent }"
  echo "Error: Activity not started, unable to resolve Intent { act=android.intent.action.MAIN pkg=com.example.nonexistent }" >&2
  exit 1
fi
exit 0
`})
	_, err := runOp("start_adb_app", "com.example.nonexistent")
	if err == nil {
		t.Fatal("a package that does not exist must not report success")
	}
	if !strings.Contains(err.Error(), "unable to resolve Intent") {
		t.Fatalf("error hides the reason: %v", err)
	}
	if strings.Contains(err.Error(), "Starting: Intent") {
		t.Fatalf("error is the banner: %v", err)
	}
	if got := classify(err.Error()); got != kindBadArg {
		t.Fatalf("classified as %v, want bad_arg", got)
	}
}

// resume_frida_session and unload_frida_script used to shell out to python3 with
// the frida module. Both are live-session moves, so they now refuse with a
// named kind and a mapping; the fake python3 below leaves a marker if anything
// still runs it.
func TestFridaSessionOutOfScope(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "spawned")
	script := "#!/bin/sh\nprintf '%s' \"$0\" >> " + strconv.Quote(marker) + "\nexit 1\n"
	for _, tool := range []string{"python3", "frida"} {
		if err := os.WriteFile(filepath.Join(dir, tool), []byte(script), 0o755); err != nil {
			t.Fatalf("write fake %s: %v", tool, err)
		}
	}
	t.Setenv("PATH", dir)

	cases := []struct{ name, target, says string }{
		{"resume_frida_session", "4321", "out of scope"},
		{"unload_frida_script", "4321:/tmp/s.js", "out of scope"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			stdout, stderr, code := runCLIAll(t, "--op", c.name, "--json", c.target)
			if code != 2 {
				t.Fatalf("%s exited %d, want 2; stdout:\n%s\nstderr:\n%s", c.name, code, stdout, stderr)
			}
			var env struct {
				Op    string `json:"op"`
				Error string `json:"error"`
				Kind  string `json:"kind"`
			}
			if err := json.Unmarshal([]byte(stdout), &env); err != nil {
				t.Fatalf("%s: stdout is not the refusal envelope: %v\n%s", c.name, err, stdout)
			}
			if env.Op != c.name || env.Kind != "out_of_scope" {
				t.Fatalf("%s: envelope = %+v, want op=%q kind=out_of_scope", c.name, env, c.name)
			}
			if !strings.Contains(env.Error, c.says) {
				t.Fatalf("%s: refusal does not say %q: %q", c.name, c.says, env.Error)
			}
			if _, err := os.Stat(marker); !os.IsNotExist(err) {
				t.Fatalf("%s launched an external tool (marker %s exists)", c.name, marker)
			}
		})
	}
}

// observe_native_calls (frida-trace) is a runtime trace, so it refuses and
// names the Ghidra ops that answer the static half of the question.
func TestObserveNativeCallsOutOfScope(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "spawned")
	script := "#!/bin/sh\nprintf '%s' \"$0\" >> " + strconv.Quote(marker) + "\nexit 1\n"
	for _, tool := range []string{"frida-trace", "frida"} {
		if err := os.WriteFile(filepath.Join(dir, tool), []byte(script), 0o755); err != nil {
			t.Fatalf("write fake %s: %v", tool, err)
		}
	}
	t.Setenv("PATH", dir)

	stdout, stderr, code := runCLIAll(t, "--op", "observe_native_calls", "--json", "com.example:open")
	if code != 2 {
		t.Fatalf("exited %d, want 2; stdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	var env struct {
		Op    string `json:"op"`
		Error string `json:"error"`
		Kind  string `json:"kind"`
	}
	if err := json.Unmarshal([]byte(stdout), &env); err != nil {
		t.Fatalf("stdout is not the refusal envelope: %v\n%s", err, stdout)
	}
	if env.Op != "observe_native_calls" || env.Kind != "out_of_scope" {
		t.Fatalf("envelope = %+v, want op=observe_native_calls kind=out_of_scope", env)
	}
	for _, says := range []string{"xrefs", "get_call_graph", "procedure_pseudo_code"} {
		if !strings.Contains(env.Error, says) {
			t.Fatalf("refusal does not name %q: %q", says, env.Error)
		}
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("a runtime tracer was launched (marker %s exists)", marker)
	}
}

// A dump that wrote the file and a read that failed leaves the hierarchy on the
// device. The op errors (correctly: nothing was captured), but the file must be
// removed on the way out — the fake below leaves a marker only if rm runs.
func TestObserveNativeUICatFailureRemovesDump(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "rm-called")
	// The marker must not exist before the run: rtFixture would create it and
	// make the stat below pass whether rm ran or not.
	t.Setenv("FAKE_RM_MARKER", marker)
	rtFakeTool(t, "adb", `case "$1" in
  shell) shift; cmd="$*" ;;
  *) `+rtOneDevice+`; exit 0 ;;
esac
case "$cmd" in
  uiautomator*) echo "UI hierchary dumped to: /data/local/tmp/ui-1.xml" ;;
  cat*) echo "cat: /data/local/tmp/ui-1.xml: No such file or directory" >&2; exit 1 ;;
  rm*) : > "$FAKE_RM_MARKER" ;;
  *) echo "unexpected device command: $cmd" >&2; exit 2 ;;
esac`)
	if _, err := runOp("observe_native_ui", ""); err == nil {
		t.Fatal("a failed cat must surface as an error, not an empty hierarchy")
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("the dumped file was left on the device: rm was not attempted (%v)", err)
	}
}

// rt2AdbReady takes the command it is about to run so the skip can name it.
// observe_native_ui called it with no argument, so the skip said only "no
// device attached" — the caller had to guess which adb command to run once a
// device existed, which is the whole reason the parameter exists.
func TestObserveNativeUINoDeviceSkipNamesCommand(t *testing.T) {
	rt2TestTools(t, map[string]string{
		"adb": "#!/bin/sh\nprintf 'List of devices attached\n'\n",
	})
	res, err := runOp("observe_native_ui", "")
	if err != nil {
		t.Fatal(err)
	}
	sk, ok := res.(*skip)
	if !ok {
		t.Fatalf("want a skip when nothing is attached, got %T", res)
	}
	if !strings.Contains(sk.Reason, "adb shell uiautomator dump --windows") {
		t.Fatalf("skip must name the command it could not run, got %q", sk.Reason)
	}
}

// rt2AdbReady must not refuse a deliberate serial: adb reads ANDROID_SERIAL
// itself, so the gate only has to stop a real ambiguity, and its refusal must
// name the escape hatch instead of leaving the caller to read adb's own error.
func TestRT2AdbReadyHonoursAndroidSerial(t *testing.T) {
	rt2TestTools(t, map[string]string{
		"adb": "#!/bin/sh\nprintf 'List of devices attached\nR58M device\nEMU1 device\n'\n",
	})
	t.Setenv("ANDROID_SERIAL", "EMU1")
	if sk, err := rt2AdbReady("dumpsys", "activity"); sk != nil || err != nil {
		t.Fatalf("skip=%v err=%v", sk, err)
	}
	t.Setenv("ANDROID_SERIAL", "GONE")
	if _, err := rt2AdbReady(); err == nil || !strings.Contains(err.Error(), "is not attached") {
		t.Fatalf("want a not-attached error, got %v", err)
	}
	t.Setenv("ANDROID_SERIAL", "")
	if _, err := rt2AdbReady(); err == nil || !strings.Contains(err.Error(), "ANDROID_SERIAL") {
		t.Fatalf("want a refusal naming ANDROID_SERIAL, got %v", err)
	}
}

// TestRt2RefusalKinds pins the Android/debug refusal answers that need no
// device: a malformed pair is bad_arg, a half-written selector is needs_arg,
// a missing local file is io, and the out-of-scope ops say so for any target.
func TestRt2RefusalKinds(t *testing.T) {
	a21WantKind(t, "pull_adb_file", "", kindNeedsArg)
	a21WantKind(t, "pull_adb_file", "nocolon", kindBadArg)
	a21WantKind(t, "push_adb_file", "", kindNeedsArg)
	a21WantKind(t, "push_adb_file", "nocolon", kindBadArg)
	a21WantKind(t, "push_adb_file", "missing-local:/data/local/tmp/x", kindIO)
	a21WantKind(t, "pull_adb_package", "", kindNeedsArg)
	a21WantKind(t, "read_adb_setting", "", kindNeedsArg)
	a21WantKind(t, "read_adb_setting", "bogus:key", kindBadArg)
	a21WantKind(t, "read_adb_setting", "system:", kindNeedsArg)
	a21WantKind(t, "resolve_adb_packages", "", kindNeedsArg)
	a21WantKind(t, "resolve_adb_packages", " ", kindNeedsArg)
	a21WantKind(t, "resolve_adb_packages", ",", kindNeedsArg)
	a21WantKind(t, "__no_such_op__", "/bin/ls", kindBadArg)
}
