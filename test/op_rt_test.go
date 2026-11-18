package main

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// rtFakeTool puts a /bin/sh shim named tool on PATH (with /bin kept for cat and
// printf) and nowhere else. The shim is the "tool is installed" half; the
// missing-tool half is rtNoTools.
func rtFakeTool(t *testing.T, name, body string) {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+":/bin:/usr/bin")
}

func rtNoTools(t *testing.T) {
	t.Helper()
	t.Setenv("PATH", t.TempDir()+":/bin")
}

// rtTestPNG is a 24-byte PNG prefix: signature plus IHDR with the given size.
// The CRC is not checked by rtPNGInfo, so zeros are enough.
func rtTestPNG(t *testing.T, w, h uint32) []byte {
	t.Helper()
	b := []byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 13, 'I', 'H', 'D', 'R'}
	b = binary.BigEndian.AppendUint32(b, w)
	b = binary.BigEndian.AppendUint32(b, h)
	return append(b, 8, 6, 0, 0, 0, 0, 0, 0, 0)
}

func rtFixture(t *testing.T, env, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), env)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv(env, p)
	return p
}

// rtOneDevice is the header plus one ready device, for shims that answer every
// non-shell call with the device table.
const rtOneDevice = `printf 'List of devices attached\nR58M\tdevice product:beyond1lte model:SM_G973F transport_id:1\n'`

// rtTwoDevices is the ambiguity the gate must not treat as a guess when
// ANDROID_SERIAL names one of them.
const rtTwoDevices = `printf 'List of devices attached\nR58M\tdevice product:beyond1lte\nEMU1\tdevice product:sdk_gphone\n'`

func TestAdbSerialHonoursAndroidSerial(t *testing.T) {
	rtFakeTool(t, "adb", rtTwoDevices)
	t.Setenv("ANDROID_SERIAL", "EMU1")
	serial, sk, err := rtAdbSerial(context.Background(), "adb")
	if sk != nil || err != nil {
		t.Fatalf("skip=%v err=%v", sk, err)
	}
	if serial != "EMU1" {
		t.Fatalf("serial = %q, want EMU1: adb itself reads ANDROID_SERIAL", serial)
	}
}

func TestAdbSerialNamesTheEscapeHatch(t *testing.T) {
	rtFakeTool(t, "adb", rtTwoDevices)
	t.Setenv("ANDROID_SERIAL", "")
	_, _, err := rtAdbSerial(context.Background(), "adb")
	if err == nil || !strings.Contains(err.Error(), "ANDROID_SERIAL") {
		t.Fatalf("want an error naming ANDROID_SERIAL, got %v", err)
	}
	// A serial that is not attached must be reported as such, not silently
	// replaced by the first ready device.
	t.Setenv("ANDROID_SERIAL", "GONE")
	if _, _, err := rtAdbSerial(context.Background(), "adb"); err == nil || !strings.Contains(err.Error(), "is not attached") {
		t.Fatalf("want a not-attached error, got %v", err)
	}
}

func rtSkipOf(t *testing.T, v any) *skip {
	t.Helper()
	s, ok := v.(*skip)
	if !ok {
		t.Fatalf("want *skip, got %T %v", v, v)
	}
	return s
}

func TestRtOpsRegistered(t *testing.T) {
	want := map[string]string{
		"capture_adb_screen": "Y", "capture_native_ui_scenario": "Y",
		"capture_process_scenario": "Y", "close_frida_session": "Y",
		"close_gdb_session": "Y", "close_rizin_debug_session": "Y",
		"collect_adb_bugreport": "Y", "compare_process_captures": "L",
		"decode_signal_recording": "L", "frida_session_status": "Y",
		"gdb_console": "Y", "gdb_session_status": "Y",
		"inspect_adb_client": "Y", "inspect_adb_device": "Y",
		"inspect_adb_display": "Y", "inspect_adb_package": "Y",
		"inspect_adb_window": "Y", "inspect_apple_ips": "L",
		"inspect_signal_decoders": "L", "install_adb_package": "Y",
		"instrument_with_frida": "Y", "list_adb_devices": "Y",
		"list_adb_directory": "Y", "list_adb_features": "Y",
		"list_adb_packages": "Y", "list_adb_processes": "Y",
	}
	for name, route := range want {
		o, ok := ops[name]
		if !ok {
			t.Fatalf("%s is not registered", name)
		}
		if o.route != route {
			t.Errorf("%s route = %s, want %s", name, o.route, route)
		}
	}
	if _, err := runOp("install_adb_package", ""); err == nil {
		t.Error("install_adb_package accepted an empty target")
	}
}

func TestCaptureADBScreen(t *testing.T) {
	png := rtTestPNG(t, 640, 1280)
	rtFixture(t, "FAKE_PNG", string(png))
	rtFakeTool(t, "adb", `if [ "$3" = "exec-out" ]; then cat "$FAKE_PNG"; exit 0; fi
`+rtOneDevice)
	out := filepath.Join(t.TempDir(), "shot.png")
	v, err := runOp("capture_adb_screen", out)
	if err != nil {
		t.Fatal(err)
	}
	got := v.(rtScreenshot)
	sum := sha256.Sum256(png)
	if got.Width != 640 || got.Height != 1280 || got.Bytes != len(png) {
		t.Fatalf("got %+v, want 640x1280/%d bytes", got, len(png))
	}
	if got.SHA256 != hex.EncodeToString(sum[:]) {
		t.Errorf("sha = %s", got.SHA256)
	}
	written, err := os.ReadFile(out)
	if err != nil || string(written) != string(png) {
		t.Fatalf("png not written: %v (%d bytes)", err, len(written))
	}
}

func TestCaptureADBScreenRejectsNonPNG(t *testing.T) {
	rtFixture(t, "FAKE_PNG", "not a png at all, no signature")
	rtFakeTool(t, "adb", `if [ "$3" = "exec-out" ]; then cat "$FAKE_PNG"; exit 0; fi
`+rtOneDevice)
	if _, err := runOp("capture_adb_screen", ""); err == nil || !strings.Contains(err.Error(), "not a PNG") {
		t.Fatalf("want a not-a-PNG error, got %v", err)
	}
}

func TestCaptureNativeUIScenario(t *testing.T) {
	old := rtUIDelay
	rtUIDelay = time.Millisecond
	t.Cleanup(func() { rtUIDelay = old })

	rtFixture(t, "FAKE_PNG", string(rtTestPNG(t, 1080, 2400)))
	xml := `<hierarchy rotation="0"><node text="A"/><node text="B"/></hierarchy>`
	rtFixture(t, "FAKE_UI", xml)
	steps := filepath.Join(t.TempDir(), "steps.txt")
	if err := os.WriteFile(steps, []byte("# open settings\ntap 540 1200\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rtFakeTool(t, "adb", `case "$3" in
  exec-out) cat "$FAKE_PNG"; exit 0 ;;
  shell) shift 3; cmd="$*" ;;
  *) `+rtOneDevice+`; exit 0 ;;
esac
case "$cmd" in
  input*) echo done ;;
  uiautomator*) echo "UI hierchary dumped to: /data/local/tmp/ui-1.xml" ;;
  cat*) cat "$FAKE_UI" ;;
  rm*) : ;;
  *) echo "unexpected device command: $cmd" >&2; exit 2 ;;
esac`)
	v, err := runOp("capture_native_ui_scenario", steps)
	if err != nil {
		t.Fatal(err)
	}
	got := v.(rtUIScenario)
	if len(got.Steps) != 1 || got.Steps[0] != "tap 540 1200" {
		t.Errorf("steps = %v", got.Steps)
	}
	if got.Screenshot.Width != 1080 || got.Screenshot.Height != 2400 {
		t.Errorf("screenshot = %+v", got.Screenshot)
	}
	if got.UI == nil {
		t.Fatalf("ui is nil: %s", got.Note)
	}
	sum := sha256.Sum256([]byte(xml))
	if got.UI.SHA256 != hex.EncodeToString(sum[:]) || got.UI.Nodes != 2 || got.UI.Bytes != len(xml) {
		t.Errorf("ui = %+v", *got.UI)
	}
	if got.Note != "idle after 2 dumps" {
		t.Errorf("note = %q", got.Note)
	}
}

func TestCaptureNativeUIScenarioNeverIdle(t *testing.T) {
	old := rtUIDelay
	rtUIDelay = time.Millisecond
	t.Cleanup(func() { rtUIDelay = old })

	rtFixture(t, "FAKE_PNG", string(rtTestPNG(t, 10, 10)))
	rtFakeTool(t, "adb", `case "$3" in
  exec-out) cat "$FAKE_PNG"; exit 0 ;;
  shell) shift 3; cmd="$*" ;;
  *) `+rtOneDevice+`; exit 0 ;;
esac
case "$cmd" in
  uiautomator*) echo dumped ;;
  cat*) echo $$ ;;
  rm*) : ;;
  *) echo i ;;
esac`)
	v, err := runOp("capture_native_ui_scenario", "")
	if err != nil {
		t.Fatal(err)
	}
	got := v.(rtUIScenario)
	if got.UI != nil {
		t.Fatalf("ui should be nil when every dump differs: %+v", *got.UI)
	}
	if !strings.Contains(got.Note, "ui:null") {
		t.Errorf("note = %q", got.Note)
	}
}

func TestCaptureProcessScenario(t *testing.T) {
	rtFakeTool(t, "sample", `f=""
while [ $# -gt 0 ]; do
  case "$1" in -file) shift; f="$1" ;; esac
  shift
done
cat > "$f" <<'EOF'
Analysis of sampling process 4242 (sample) every 1 millisecond
Process:         /Applications/Foo.app/Contents/MacOS/Foo [4242]
Call graph:
    1000 Thread_0x1f0d   DispatchQueue_1: com.apple.main-thread  (serial)
    + 1000 start  (in dyld) + 7184  [0x1f0d1234]
      900 main  (in Foo) + 123  [0x1f0d5678]
    200 Thread_0x2a0b
      200 worker  (in libsystem_pthread.dylib) + 44  [0x7fff1234]
EOF`)
	v, err := runOp("capture_process_scenario", strconv.Itoa(os.Getpid()))
	if err != nil {
		t.Fatal(err)
	}
	got := v.(rtProcessCapture)
	if got.PID != os.Getpid() || got.Path != "/Applications/Foo.app/Contents/MacOS/Foo" {
		t.Errorf("pid/path = %d %q", got.PID, got.Path)
	}
	if len(got.Threads) != 2 {
		t.Fatalf("threads = %+v", got.Threads)
	}
	if id := got.Threads[0].ID; id != "0x1f0d" {
		t.Errorf("thread id = %q", id)
	}
	if len(got.Threads[0].Frames) != 2 {
		t.Fatalf("frames = %+v", got.Threads[0].Frames)
	}
	f := got.Threads[0].Frames[1]
	if f.Sym != "main" || f.Lib != "Foo" || f.Addr != "0x1f0d5678" || f.Count != 900 {
		t.Errorf("frame = %+v", f)
	}
}

// The frida attach/instrument ops used to drive the frida CLI. Attaching to a
// live process is instrumentation, not inspection, so they refuse with a named
// kind and a mapping; the fake frida below leaves a marker if anything still
// runs it.
func TestFridaAttachOutOfScope(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "spawned")
	script := "#!/bin/sh\nprintf '%s' \"$0\" >> " + strconv.Quote(marker) + "\nexit 1\n"
	for _, tool := range []string{"frida", "python3"} {
		if err := os.WriteFile(filepath.Join(dir, tool), []byte(script), 0o755); err != nil {
			t.Fatalf("write fake %s: %v", tool, err)
		}
	}
	t.Setenv("PATH", dir)

	cases := []struct{ name, target string }{
		{"start_frida_session", "com.example.app"},
		{"frida_session_status", "4321"},
		{"close_frida_session", "4321"},
		{"load_frida_script", "com.example.app:/tmp/hook.js"},
		{"instrument_with_frida", "com.example.app::/tmp/hook.js"},
		{"trace_native_values", "com.example.app:/tmp/hook.js"},
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
			if !strings.Contains(env.Error, "out of scope") {
				t.Fatalf("%s: refusal does not say what it is: %q", c.name, env.Error)
			}
			if _, err := os.Stat(marker); !os.IsNotExist(err) {
				t.Fatalf("%s launched an external tool (marker %s exists)", c.name, marker)
			}
		})
	}
}

func TestInspectADBClient(t *testing.T) {
	rtFakeTool(t, "adb", `if [ "$1" = "version" ]; then
  printf 'Android Debug Bridge version 1.0.41\nVersion 35.0.2-13114751\nInstalled as /opt/android/platform-tools/adb\n'
  exit 0
fi
`+rtOneDevice)
	v, err := runOp("inspect_adb_client", "")
	if err != nil {
		t.Fatal(err)
	}
	got := v.(rtADBClient)
	if got.ClientVersion != "1.0.41" || got.Build != "35.0.2-13114751" || got.Path != "/opt/android/platform-tools/adb" {
		t.Errorf("client = %+v", got)
	}
	if len(got.Devices) != 1 || got.Devices[0].Serial != "R58M" || got.Devices[0].Model != "SM_G973F" {
		t.Errorf("devices = %+v", got.Devices)
	}
}

func TestInspectADBDevice(t *testing.T) {
	rtFakeTool(t, "adb", `if [ "$3" = "shell" ]; then
  printf 'Pixel 7\n34\ngoogle/panther/panther:14/UQ1A.240105.004/1234567:user/release-keys\n0\n'
  exit 0
fi
`+rtOneDevice)
	v, err := runOp("inspect_adb_device", "")
	if err != nil {
		t.Fatal(err)
	}
	got := v.(rtADBDeviceProps)
	if got.Serial != "R58M" || got.Model != "Pixel 7" || got.SDK != "34" || got.Debuggable != "0" {
		t.Errorf("props = %+v", got)
	}
	if !strings.Contains(got.Fingerprint, "panther:14") {
		t.Errorf("fingerprint = %q", got.Fingerprint)
	}
}

func TestInspectADBDisplay(t *testing.T) {
	rtFakeTool(t, "adb", `if [ "$3" = "shell" ]; then
  printf 'Physical size: 1080x2400\nOverride size: 1080x2160\nPhysical density: 440\nOverride density: 420\n'
  exit 0
fi
`+rtOneDevice)
	v, err := runOp("inspect_adb_display", "")
	if err != nil {
		t.Fatal(err)
	}
	got := v.(rtADBDisplay)
	if got.PhysicalSize != "1080x2400" || got.OverrideSize != "1080x2160" ||
		got.PhysicalDensity != "440" || got.OverrideDensity != "420" {
		t.Errorf("display = %+v", got)
	}
}

func TestInspectADBWindow(t *testing.T) {
	rtFakeTool(t, "adb", `if [ "$3" = "shell" ]; then
  printf '  mCurrentFocus=Window{8d4f u0 com.example/com.example.MainActivity}\n  mFocusedApp=ActivityRecord{7c3 u0 com.example/.MainActivity t42}\n  Window{8d4f u0 com.example/com.example.MainActivity}\n  Window{1a2b u0 StatusBar}\n'
  exit 0
fi
`+rtOneDevice)
	v, err := runOp("inspect_adb_window", "")
	if err != nil {
		t.Fatal(err)
	}
	got := v.(rtADBWindow)
	if !strings.Contains(got.CurrentFocus, "MainActivity") || !strings.Contains(got.FocusedApp, "t42") {
		t.Errorf("focus = %+v", got)
	}
	if got.Windows != 2 {
		t.Errorf("windows = %d", got.Windows)
	}
}

func TestInspectADBPackage(t *testing.T) {
	rtFakeTool(t, "adb", `if [ "$3" = "shell" ]; then
  case "$*" in
    *"com.nope"*) printf 'Unable to find package: com.nope\n'; exit 0 ;;
  esac
  printf 'Packages:\n  Package [com.example.app] (abc):\n    versionCode=42 minSdk=21 targetSdk=34\n    versionName=1.2.3\n    requested permissions:\n      android.permission.CAMERA\n      android.permission.INTERNET\n    install permissions:\n      android.permission.INTERNET: granted=true\n'
  exit 0
fi
`+rtOneDevice)
	v, err := runOp("inspect_adb_package", "com.example.app")
	if err != nil {
		t.Fatal(err)
	}
	got := v.(rtADBPackage)
	if got.State != "installed" || got.VersionName != "1.2.3" || got.VersionCode != "42" {
		t.Errorf("pkg = %+v", got)
	}
	if len(got.Permissions) != 2 || got.Permissions[0] != "android.permission.CAMERA" {
		t.Errorf("permissions = %v", got.Permissions)
	}
	v, err = runOp("inspect_adb_package", "com.nope")
	if err != nil {
		t.Fatal(err)
	}
	if got := v.(rtADBPackage); got.State != "not-installed" {
		t.Errorf("missing pkg = %+v", got)
	}
}

func TestInstallADBPackage(t *testing.T) {
	apk := filepath.Join(t.TempDir(), "app.apk")
	if err := os.WriteFile(apk, []byte("PK"), 0o644); err != nil {
		t.Fatal(err)
	}
	rtFakeTool(t, "adb", `if [ "$3" = "install" ]; then
  printf 'Performing Streamed Install\nSuccess\n'
  exit 0
fi
`+rtOneDevice)
	v, err := runOp("install_adb_package", apk)
	if err != nil {
		t.Fatal(err)
	}
	if got := v.(rtADBInstall); got.Result != "Success" {
		t.Errorf("install = %+v", got)
	}
}

func TestInstallADBPackageFailure(t *testing.T) {
	apk := filepath.Join(t.TempDir(), "app.apk")
	if err := os.WriteFile(apk, []byte("PK"), 0o644); err != nil {
		t.Fatal(err)
	}
	rtFakeTool(t, "adb", `if [ "$3" = "install" ]; then
  printf 'Performing Streamed Install\nadb: failed to install: Failure [INSTALL_FAILED_ALREADY_EXISTS]\n'
  exit 0
fi
`+rtOneDevice)
	if _, err := runOp("install_adb_package", apk); err == nil || !strings.Contains(err.Error(), "INSTALL_FAILED_ALREADY_EXISTS") {
		t.Fatalf("want the adb failure text, got %v", err)
	}
}

func TestListADBDirectory(t *testing.T) {
	rtFakeTool(t, "adb", `if [ "$3" = "shell" ]; then
  printf 'total 12\ndrwxr-xr-x  2 root root 4096 2024-01-01 12:00 dir with space\n-rw-r--r--  1 root root  123 2024-01-01 12:00 file.txt\nlrwxrwxrwx  1 root root    4 2024-01-01 12:00 link -> file.txt\n'
  exit 0
fi
`+rtOneDevice)
	v, err := runOp("list_adb_directory", "/sdcard")
	if err != nil {
		t.Fatal(err)
	}
	got := v.(rtDirListing)
	if got.Path != "/sdcard" || len(got.Entries) != 3 {
		t.Fatalf("listing = %+v", got)
	}
	if !got.Entries[0].IsDir || got.Entries[0].Name != "dir with space" || got.Entries[0].Perm != "drwxr-xr-x" {
		t.Errorf("dir entry = %+v", got.Entries[0])
	}
	if got.Entries[2].Name != "link -> file.txt" {
		t.Errorf("symlink = %+v", got.Entries[2])
	}
}

func TestListADBFeatures(t *testing.T) {
	rtFakeTool(t, "adb", `if [ "$1" = "host-features" ]; then printf 'cmd,shell_v2,abb_exec\n'; exit 0; fi
`+rtOneDevice)
	v, err := runOp("list_adb_features", "")
	if err != nil {
		t.Fatal(err)
	}
	got := v.(rtADBFeatures)
	if got.Count != 3 || got.Features[1] != "shell_v2" {
		t.Errorf("features = %+v", got)
	}
}

func TestListADBPackages(t *testing.T) {
	rtFakeTool(t, "adb", `if [ "$3" = "shell" ]; then
  printf 'package:/system/app/A/A.apk=com.a\npackage:/data/app/~~gCzVouwI19tods42WSlecg==/com.b-x1==/base.apk=com.b\n'
  exit 0
fi
`+rtOneDevice)
	v, err := runOp("list_adb_packages", "")
	if err != nil {
		t.Fatal(err)
	}
	got := v.(rtADBPackages)
	if got.Count != 2 {
		t.Fatalf("packages = %+v", got)
	}
	// The path holds two '=' from the base64 id; the name follows the last one.
	if got.Packages[1].Package != "com.b" || got.Packages[1].APK != "/data/app/~~gCzVouwI19tods42WSlecg==/com.b-x1==/base.apk" {
		t.Errorf("packages = %+v", got)
	}
}

func TestListADBProcesses(t *testing.T) {
	rtFakeTool(t, "adb", `if [ "$3" = "shell" ]; then
  printf 'PID USER NAME ARGS\n1 root init\n200 u0_a2 sh sh -c sleep\n'
  exit 0
fi
`+rtOneDevice)
	v, err := runOp("list_adb_processes", "")
	if err != nil {
		t.Fatal(err)
	}
	got := v.(rtADBProcesses)
	if got.Count != 2 || got.Command != "ps -A -o PID,USER,NAME,ARGS" {
		t.Fatalf("ps = %+v", got)
	}
	if got.Rows[1].Args != "sh -c sleep" || got.Rows[1].User != "u0_a2" {
		t.Errorf("row = %+v", got.Rows[1])
	}
}

// TestListADBProcessesFallback is the legacy table a toolbox without `-A`
// prints: `USER PID PPID VSZ RSS WCHAN ADDR S NAME`. Reading column 0 as the
// pid would answer pid=root, user=1 — a table that parses but is wrong, which
// is exactly what an exit code cannot catch, so the values are asserted.
func TestListADBProcessesFallback(t *testing.T) {
	rtFakeTool(t, "adb", `if [ "$3" = "shell" ]; then
  case "$*" in
    *"-A"*) echo "ps: unknown option -A" >&2; exit 1 ;;
  esac
  printf 'USER PID PPID VSZ RSS WCHAN ADDR S NAME\nroot 1 0 12345 678 0 0 S init\nu0_a12 2345 300 1234567 89000 0 0 S com.example/.Main\n'
  exit 0
fi
`+rtOneDevice)
	v, err := runOp("list_adb_processes", "")
	if err != nil {
		t.Fatal(err)
	}
	got := v.(rtADBProcesses)
	if got.Command != "ps" || got.Count != 2 {
		t.Fatalf("fallback = %+v", got)
	}
	if len(got.Columns) != 9 || got.Columns[0] != "USER" || got.Columns[1] != "PID" || got.Columns[8] != "NAME" {
		t.Errorf("columns = %v, want the legacy layout named", got.Columns)
	}
	r := got.Rows[1]
	if r.PID != "2345" || r.User != "u0_a12" || r.Name != "com.example/.Main" || r.Args != "" {
		t.Errorf("legacy row = %+v, want pid 2345 of u0_a12", r)
	}
	if got.Rows[0].PID != "1" || got.Rows[0].Name != "init" {
		t.Errorf("legacy row 0 = %+v", got.Rows[0])
	}
}

func TestListADBDevices(t *testing.T) {
	rtFakeTool(t, "adb", `printf 'List of devices attached\nAAA\tdevice product:panther model:Pixel_7 transport_id:1\nBBB\tunauthorized transport_id:2\n'`)
	v, err := runOp("list_adb_devices", "")
	if err != nil {
		t.Fatal(err)
	}
	got := v.([]rtDevice)
	if len(got) != 2 || got[0].Model != "Pixel_7" || got[1].State != "unauthorized" {
		t.Errorf("devices = %+v", got)
	}
}

func TestCollectADBBugreport(t *testing.T) {
	local := filepath.Join(t.TempDir(), "br.zip")
	rtFakeTool(t, "adb", `case "$3" in
  shell) printf 'OK:/data/local/tmp/bugreport-abc.zip\n'; exit 0 ;;
  pull) printf 'zipdata' > "$5"; echo "1 file pulled"; exit 0 ;;
esac
`+rtOneDevice)
	v, err := runOp("collect_adb_bugreport", local)
	if err != nil {
		t.Fatal(err)
	}
	got := v.(rtADBBugreport)
	if got.Remote != "/data/local/tmp/bugreport-abc.zip" || got.Local != local || got.Bytes != 7 {
		t.Fatalf("bugreport = %+v", got)
	}
	sum := sha256.Sum256([]byte("zipdata"))
	if got.SHA256 != hex.EncodeToString(sum[:]) {
		t.Errorf("sha = %s", got.SHA256)
	}
}

func TestCompareProcessCaptures(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.json")
	b := filepath.Join(dir, "b.json")
	if err := os.WriteFile(a, []byte(`{"main":[1,2],"worker":[0]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(b, []byte(`{"main":[1,3],"extra":[5]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	v, err := runOp("compare_process_captures", a+","+b)
	if err != nil {
		t.Fatal(err)
	}
	got := v.(rtCaptureDiff)
	if len(got.OnlyInFirst) != 1 || got.OnlyInFirst[0] != "worker" {
		t.Errorf("only first = %v", got.OnlyInFirst)
	}
	if len(got.OnlyInSecond) != 1 || got.OnlyInSecond[0] != "extra" {
		t.Errorf("only second = %v", got.OnlyInSecond)
	}
	if len(got.Changed) != 1 || got.Changed[0].Symbol != "main" ||
		strings.Join(got.Changed[0].First, ",") != "1,2" || strings.Join(got.Changed[0].Second, ",") != "1,3" {
		t.Errorf("changed = %+v", got.Changed)
	}
}

func TestDecodeSignalRecording(t *testing.T) {
	dir := t.TempDir()
	meta := filepath.Join(dir, "rec.sigmf-meta")
	body, err := json.Marshal(map[string]any{
		"global": map[string]any{
			"core:datatype":    "cf32_le",
			"core:sample_rate": 1e6,
			"core:dataset":     "rec.sigmf-data",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(meta, body, 0o644); err != nil {
		t.Fatal(err)
	}
	const n, bin = 4096, 64
	buf := make([]byte, 0, n*8)
	for i := range n {
		ph := 2 * math.Pi * float64(bin) * float64(i) / float64(n)
		buf = binary.LittleEndian.AppendUint32(buf, math.Float32bits(float32(math.Cos(ph))))
		buf = binary.LittleEndian.AppendUint32(buf, math.Float32bits(float32(math.Sin(ph))))
	}
	if err := os.WriteFile(filepath.Join(dir, "rec.sigmf-data"), buf, 0o644); err != nil {
		t.Fatal(err)
	}
	v, err := runOp("decode_signal_recording", meta)
	if err != nil {
		t.Fatal(err)
	}
	got := v.(rtSignal)
	if got.SampleRate != 1e6 || got.Datatype != "cf32_le" || got.Samples != n {
		t.Fatalf("signal = %+v", got)
	}
	if got.DurationS != float64(n)/1e6 || got.DFTBins != n || !got.HasPeak {
		t.Errorf("duration/bins = %+v", got)
	}
	want := float64(bin) * 1e6 / n
	if math.Abs(got.PeakHz-want) > 1 {
		t.Errorf("peak = %v, want %v", got.PeakHz, want)
	}
}

func TestDecodeSignalRecordingNegativeFrequency(t *testing.T) {
	dir := t.TempDir()
	meta := filepath.Join(dir, "neg.sigmf-meta")
	body, err := json.Marshal(map[string]any{
		"global": map[string]any{
			"core:datatype":    "cf32_le",
			"core:sample_rate": 1e6,
			"core:dataset":     "neg.sigmf-data",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(meta, body, 0o644); err != nil {
		t.Fatal(err)
	}
	// The same tone as TestDecodeSignalRecording, mirrored below DC:
	// exp(-j2*pi*bin*i/n) peaks at bin n-bin, which is a negative frequency.
	const n, bin = 4096, 64
	buf := make([]byte, 0, n*8)
	for i := range n {
		ph := -2 * math.Pi * float64(bin) * float64(i) / float64(n)
		buf = binary.LittleEndian.AppendUint32(buf, math.Float32bits(float32(math.Cos(ph))))
		buf = binary.LittleEndian.AppendUint32(buf, math.Float32bits(float32(math.Sin(ph))))
	}
	if err := os.WriteFile(filepath.Join(dir, "neg.sigmf-data"), buf, 0o644); err != nil {
		t.Fatal(err)
	}
	v, err := runOp("decode_signal_recording", meta)
	if err != nil {
		t.Fatal(err)
	}
	got := v.(rtSignal)
	if !got.HasPeak {
		t.Fatalf("no peak measured: %+v", got)
	}
	want := -float64(bin) * 1e6 / n
	if math.Abs(got.PeakHz-want) > 1 {
		t.Errorf("peak = %v Hz, want %v Hz: bins past n/2 are negative frequencies", got.PeakHz, want)
	}
}

func TestDecodeSignalRecordingIntegerFormat(t *testing.T) {
	dir := t.TempDir()
	meta := filepath.Join(dir, "iq.sigmf-meta")
	body, err := json.Marshal(map[string]any{
		"global": map[string]any{"core:datatype": "ci16_le", "core:sample_rate": 48000},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(meta, body, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "iq.sigmf-data"), make([]byte, 16), 0o644); err != nil {
		t.Fatal(err)
	}
	v, err := runOp("decode_signal_recording", meta)
	if err != nil {
		t.Fatal(err)
	}
	got := v.(rtSignal)
	if got.Samples != 4 || got.HasPeak || !strings.Contains(got.Note, "complex float") {
		t.Errorf("integer signal = %+v", got)
	}
}

func TestInspectAppleIPS(t *testing.T) {
	p := filepath.Join(t.TempDir(), "Foo.ips")
	body := `{"app_name":"Foo","bug_type":"309","os_version":"iPhone OS 17.4 (21E219)","timestamp":"2024-03-01 10:00:00.00 +0000","name":"Foo-2024-03-01","app_version":"1.0"}
{"uptime":123}
`
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	v, err := runOp("inspect_apple_ips", p)
	if err != nil {
		t.Fatal(err)
	}
	got := v.(rtAppleIPS)
	if got.BugType != "309" || got.AppVersion != "1.0" || !strings.Contains(got.OSVersion, "17.4") ||
		got.Timestamp == "" || got.Name != "Foo-2024-03-01" || !got.BodyParsed {
		t.Errorf("ips = %+v", got)
	}
}

func TestInspectAppleIPSRejectsOtherJSON(t *testing.T) {
	p := filepath.Join(t.TempDir(), "x.ips")
	if err := os.WriteFile(p, []byte(`{"hello":1}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := runOp("inspect_apple_ips", p); err == nil || !strings.Contains(err.Error(), "bug_type") {
		t.Fatalf("want a bug_type error, got %v", err)
	}
}

func TestInspectSignalDecoders(t *testing.T) {
	dir := t.TempDir()
	table := `[{"name":"adsb","family":"aviation","modulation":"ppm","symbol_rate":2000000,"channel":"1090MHz"},
{"name":"ais","family":"marine","modulation":"gmsk","symbol_rate":9600,"channel":"161.975MHz"}]`
	if err := os.WriteFile(filepath.Join(dir, "decoders.json"), []byte(table), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)

	v, err := runOp("inspect_signal_decoders", "AVIATION")
	if err != nil {
		t.Fatal(err)
	}
	got := v.(rtDecoderHits)
	if len(got.Matches) != 1 || got.Matches[0].Name != "adsb" {
		t.Fatalf("by family = %+v", got)
	}
	v, err = runOp("inspect_signal_decoders", "9600")
	if err != nil {
		t.Fatal(err)
	}
	if got := v.(rtDecoderHits); len(got.Matches) != 1 || got.Matches[0].Name != "ais" {
		t.Errorf("by symbol rate = %+v", got)
	}
}

func TestInspectSignalDecodersEmbeddedTable(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("LRECON_DECODERS", "")
	v, err := runOp("inspect_signal_decoders", "433")
	if err != nil {
		t.Fatalf("embedded table: %v", err)
	}
	got := v.(rtDecoderHits)
	if got.Table != "embedded" || len(got.Matches) == 0 || got.Matches[0].Name != "ook-433" {
		t.Fatalf("embedded table = %+v", got)
	}
}

func TestInspectSignalDecodersMissingTable(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("LRECON_DECODERS", filepath.Join(t.TempDir(), "absent.json"))
	if _, err := runOp("inspect_signal_decoders", "adsb"); err == nil || !strings.Contains(err.Error(), "decoders.json") {
		t.Fatalf("want a missing-table error, got %v", err)
	}
}

// TestRtMissingTools is the absent-tool half: each op must skip and name the
// tool plus an alternative instead of returning an empty result.
func TestRtMissingTools(t *testing.T) {
	script := filepath.Join(t.TempDir(), "s.js")
	if err := os.WriteFile(script, []byte("// noop"), 0o644); err != nil {
		t.Fatal(err)
	}
	pid := strconv.Itoa(os.Getpid())
	cases := []struct{ op, target, tool string }{
		{"capture_adb_screen", "", "adb"},
		{"capture_native_ui_scenario", "", "adb"},
		{"list_adb_devices", "", "adb"},
		{"list_adb_features", "", "adb"},
		{"inspect_adb_client", "", "adb"},
		{"inspect_adb_device", "", "adb"},
		{"inspect_adb_display", "", "adb"},
		{"inspect_adb_window", "", "adb"},
		{"inspect_adb_package", "com.example", "adb"},
		{"list_adb_directory", "/sdcard", "adb"},
		{"list_adb_packages", "", "adb"},
		{"list_adb_processes", "", "adb"},
		{"collect_adb_bugreport", filepath.Join(t.TempDir(), "bug.zip"), "adb"},
		{"capture_process_scenario", pid, "sample"},
		{"gdb_console", "/bin/ls", "lldb"},
		{"gdb_session_status", "/bin/ls", "lldb"},
		{"close_gdb_session", "/bin/ls", "lldb"},
	}
	for _, c := range cases {
		t.Run(c.op, func(t *testing.T) {
			rtNoTools(t)
			v, err := runOp(c.op, c.target)
			if err != nil {
				t.Fatalf("%s: %v", c.op, err)
			}
			s := rtSkipOf(t, v)
			if !strings.Contains(s.Reason, c.tool) {
				t.Errorf("reason %q does not name %s", s.Reason, c.tool)
			}
			if !strings.Contains(s.Reason, "alternative") {
				t.Errorf("reason %q names no alternative", s.Reason)
			}
		})
	}
}

func TestRtNoDeviceAttached(t *testing.T) {
	rtFakeTool(t, "adb", `printf 'List of devices attached\n'`)
	v, err := runOp("list_adb_directory", "/sdcard")
	if err != nil {
		t.Fatal(err)
	}
	s := rtSkipOf(t, v)
	if !strings.Contains(s.Reason, "no device attached") || !strings.Contains(s.Reason, "adb") {
		t.Errorf("reason = %q", s.Reason)
	}
}

func TestRtMultipleDevices(t *testing.T) {
	rtFakeTool(t, "adb", `printf 'List of devices attached\nAAA\tdevice\nBBB\tdevice\n'`)
	if _, err := runOp("list_adb_directory", "/sdcard"); err == nil || !strings.Contains(err.Error(), "AAA") {
		t.Fatalf("want a multi-device refusal naming both, got %v", err)
	}
}

func TestRtToolFailureCarriesStderr(t *testing.T) {
	rtFakeTool(t, "adb", `if [ "$1" = "host-features" ]; then echo "error: server not running" >&2; exit 1; fi
`+rtOneDevice)
	_, err := runOp("list_adb_features", "")
	if err == nil || !strings.Contains(err.Error(), "server not running") {
		t.Fatalf("want stderr's first line, got %v", err)
	}
}

// gdb does not exist on macOS; lldb does, and the three file-level gdb op
// names run on it. Each answer says `engine: lldb` instead of pretending gdb
// ran, and a host without lldb gets a skip naming lldb.
func TestGdbConsoleLLDB(t *testing.T) {
	rtFakeTool(t, "lldb", `echo "(lldb) target list"
echo "* target #0: /bin/ls ( arch=arm64e-apple-macosx11.0.0, platform=host )"
cat > /dev/null`)
	v, err := runOp("gdb_console", "/bin/ls")
	if err != nil {
		t.Fatal(err)
	}
	got := v.(rtGdbConsole)
	if got.Engine != "lldb" {
		t.Errorf("engine = %q, want lldb", got.Engine)
	}
	if len(got.Output) != 2 || !strings.Contains(got.Output[1], "target #0") {
		t.Errorf("output = %v", got.Output)
	}
}

func TestGdbSessionStatusLLDBNoInferior(t *testing.T) {
	rtFakeTool(t, "lldb", `echo "(lldb) thread list"
echo "error: Command requires a current process." >&2
exit 1`)
	v, err := runOp("gdb_session_status", "/bin/ls")
	if err != nil {
		t.Fatal(err)
	}
	got := v.(rtGdbStatus)
	if got.Engine != "lldb" || got.Stopped != "no-inferior" || len(got.Threads) != 0 {
		t.Errorf("status = %+v", got)
	}
	if !strings.Contains(got.Note, "requires a current process") {
		t.Errorf("note does not carry lldb's sentence: %q", got.Note)
	}
}

func TestCloseGdbSessionLLDB(t *testing.T) {
	rtFakeTool(t, "lldb", `echo "error: Command requires a current process." >&2
exit 1`)
	v, err := runOp("close_gdb_session", "/bin/ls")
	if err != nil {
		t.Fatal(err)
	}
	got := v.(rtGdbClosed)
	if got.Engine != "lldb" || got.Exited {
		t.Errorf("closed = %+v", got)
	}
	if !strings.Contains(got.Note, "batch dialog") {
		t.Errorf("note does not explain the missing session: %q", got.Note)
	}
}

// The dump path is derived from the steps, so a file an earlier run left behind
// sits exactly where this run reads. A dump that writes nothing (uiautomator
// fails, exits 0) must then fail the op; before the pre-dump rm it was cat'ed
// and hashed, and a stale hierarchy was reported as this run's capture.
func TestCaptureNativeUIScenarioIgnoresLeftoverDump(t *testing.T) {
	old := rtUIDelay
	rtUIDelay = time.Millisecond
	t.Cleanup(func() { rtUIDelay = old })

	rtFixture(t, "FAKE_PNG", string(rtTestPNG(t, 10, 10)))
	stale := rtFixture(t, "FAKE_UI", `<hierarchy><node text="from an earlier run"/></hierarchy>`)
	rtFakeTool(t, "adb", `case "$3" in
  exec-out) cat "$FAKE_PNG"; exit 0 ;;
  shell) shift 3; cmd="$*" ;;
  *) `+rtOneDevice+`; exit 0 ;;
esac
case "$cmd" in
  input*) echo done ;;
  uiautomator*) echo "ERROR: could not get idle state." ;;
  cat*) cat "$FAKE_UI" 2>/dev/null || { echo "cat: No such file or directory" >&2; exit 1; } ;;
  rm*) rm -f "$FAKE_UI" ;;
  *) echo "unexpected device command: $cmd" >&2; exit 2 ;;
esac`)
	steps := filepath.Join(t.TempDir(), "steps.txt")
	if err := os.WriteFile(steps, []byte("tap 1 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	v, err := runOp("capture_native_ui_scenario", steps)
	if err == nil {
		t.Fatalf("a leftover dump was reported as this run's hierarchy: %+v", v)
	}
	if _, statErr := os.Stat(stale); statErr == nil {
		t.Fatal("the leftover device file was not removed before the dump")
	}
}

// A failed rm is a device-side leak to report, not a reason to throw the
// capture away (observe_native_ui keeps the same fact in Cleanup).
func TestCaptureNativeUIScenarioCleanupFailureIsNoted(t *testing.T) {
	old := rtUIDelay
	rtUIDelay = time.Millisecond
	t.Cleanup(func() { rtUIDelay = old })

	rtFixture(t, "FAKE_PNG", string(rtTestPNG(t, 10, 10)))
	rtFixture(t, "FAKE_UI", `<hierarchy rotation="0"><node text="A"/></hierarchy>`)
	rtFakeTool(t, "adb", `case "$3" in
  exec-out) cat "$FAKE_PNG"; exit 0 ;;
  shell) shift 3; cmd="$*" ;;
  *) `+rtOneDevice+`; exit 0 ;;
esac
case "$cmd" in
  input*) echo done ;;
  uiautomator*) echo dumped ;;
  cat*) cat "$FAKE_UI" ;;
  rm*) echo "rm: /data/local/tmp: Read-only file system" >&2; exit 1 ;;
  *) echo "unexpected device command: $cmd" >&2; exit 2 ;;
esac`)
	v, err := runOp("capture_native_ui_scenario", "")
	if err != nil {
		t.Fatalf("a cleanup failure must not discard the capture: %v", err)
	}
	got := v.(rtUIScenario)
	if got.UI == nil {
		t.Fatalf("ui should still be captured: %s", got.Note)
	}
	if !strings.Contains(got.Cleanup, "Read-only file system") {
		t.Errorf("cleanup = %q", got.Cleanup)
	}
}

// A pid that is gone has no alternative tool. Naming the linux perf fallback
// sent a darwin caller to a command that cannot sample anything (measured:
// "no live process with pid 999999: no alternative on linux (perf script ...)").
func TestCaptureProcessScenarioDeadPidHasNoAlternative(t *testing.T) {
	v, err := runOp("capture_process_scenario", "999999")
	if err != nil {
		t.Fatalf("a dead pid is a skip, not an error: %v", err)
	}
	sk := rtSkipOf(t, v)
	if !strings.Contains(sk.Reason, "nothing to sample") {
		t.Errorf("skip = %q", sk.Reason)
	}
	if strings.Contains(sk.Reason, "perf script") {
		t.Errorf("skip names a tool that cannot sample a dead process: %q", sk.Reason)
	}
}
