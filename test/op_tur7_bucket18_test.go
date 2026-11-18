package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// bucket18AdbStub is one adb that behaves like the real client: `devices -l`
// prints the table ADB_TABLE names (empty means "present, nothing attached"),
// `host-features` answers from the host, and a device command prints what a
// device would print. Every invocation is appended to ADB_MARKER so a test can
// tell "the tool was asked" from "the decision happened before asking it".
const bucket18AdbStub = `#!/bin/sh
printf '%s\n' "$*" >> "$ADB_MARKER"
case "$1" in
  devices)
    printf 'List of devices attached\n'
    if [ -n "$ADB_TABLE" ]; then printf '%s\n' "$ADB_TABLE"; fi
    ;;
  host-features) printf 'cmd,shell_v2,abb_exec\n' ;;
  -s)
    case "$3" in
      shell)
        case "$4 $5" in
          "ls -la") printf 'total 0\ndrwxr-xr-x 2 root root 4096 2024-01-01 12:00 dir\n-rw-r--r-- 1 root root 7 2024-01-01 12:00 f.txt\n' ;;
          "cmd package") printf 'package:/system/app/A.apk=com.a\n' ;;
          "ps -A") printf 'PID USER NAME ARGS\n1 root init\n' ;;
          *) printf 'unknown device command: %s\n' "$*" >&2; exit 1 ;;
        esac
        ;;
      install) printf 'Performing Streamed Install\nSuccess\n' ;;
    esac
    ;;
esac
`

// TestTur7Bucket18AdbPrecedence pins the precedence itself rather than one
// outcome per test (TestRtMissingTools pins absent, TestRtNoDeviceAttached one
// device-less op): the same six ops are run with adb absent, present but
// device-less, and present with one ready device. The documented order is
// LookPath -> device table -> device shell, so (1) absent must never surface a
// device problem, (2) device-less must never surface "not installed" nor touch
// a device command, and (3) only the ready-device state may answer with data,
// and that data must be non-empty. instrument_with_frida refuses before the
// gate at all, so its refusal must be byte-identical in all three states.
func TestTur7Bucket18AdbPrecedence(t *testing.T) {
	apk := filepath.Join(t.TempDir(), "app.apk")
	if err := os.WriteFile(apk, []byte("PK\x03\x04"), 0o644); err != nil {
		t.Fatal(err)
	}
	stubDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(stubDir, "adb"), []byte(bucket18AdbStub), 0o755); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(t.TempDir(), "adb-calls")
	t.Setenv("ADB_MARKER", marker)

	states := []struct{ name, path, table string }{
		{"absent", t.TempDir(), ""},
		{"nodevice", stubDir + ":/bin:/usr/bin", ""},
		{"device", stubDir + ":/bin:/usr/bin", "R58M\tdevice product:beyond1lte model:SM_G973F transport_id:1"},
	}
	ops := []struct{ op, target string }{
		{"list_adb_devices", ""},
		{"list_adb_features", ""},
		{"list_adb_directory", "/sdcard"},
		{"list_adb_packages", ""},
		{"list_adb_processes", ""},
		{"install_adb_package", apk},
	}

	for _, state := range states {
		t.Run(state.name, func(t *testing.T) {
			t.Setenv("PATH", state.path)
			t.Setenv("ADB_TABLE", state.table)
			if err := os.Remove(marker); err != nil && !os.IsNotExist(err) {
				t.Fatal(err)
			}

			for _, o := range ops {
				v, err := runOp(o.op, o.target)
				if err != nil {
					t.Fatalf("%s: err = %v; no state may fail instead of answering", o.op, err)
				}
				switch state.name {
				case "absent":
					s := rtSkipOf(t, v)
					if !strings.Contains(s.Reason, "adb not installed") || !strings.Contains(s.Reason, "alternative") {
						t.Errorf("%s: absent reason = %q, want 'adb not installed' plus the alternative", o.op, s.Reason)
					}
					if strings.Contains(s.Reason, "no device") {
						t.Errorf("%s: absent adb reported a device problem (%q); LookPath must decide first", o.op, s.Reason)
					}
				case "nodevice":
					switch o.op {
					case "list_adb_devices":
						devs, ok := v.([]rtDevice)
						if !ok || devs == nil || len(devs) != 0 {
							t.Errorf("list_adb_devices: present-but-device-less = %#v, want an empty, non-nil table: the device table needs no device", v)
						}
					case "list_adb_features":
						feats, ok := v.(rtADBFeatures)
						if !ok || feats.Count != 3 {
							t.Errorf("list_adb_features: present-but-device-less = %#v, want the host feature list (host-features is not a device command)", v)
						}
					default:
						s := rtSkipOf(t, v)
						if !strings.Contains(s.Reason, "no device attached") {
							t.Errorf("%s: device-less reason = %q, want 'no device attached'", o.op, s.Reason)
						}
						if strings.Contains(s.Reason, "not installed") {
							t.Errorf("%s: device-less adb was reported as not installed (%q)", o.op, s.Reason)
						}
					}
				case "device":
					if s, ok := v.(*skip); ok {
						t.Fatalf("%s: ready device still skipped: %s", o.op, s.Reason)
					}
					switch o.op {
					case "list_adb_devices":
						devs, ok := v.([]rtDevice)
						if !ok || len(devs) != 1 || devs[0].Serial != "R58M" || devs[0].State != "device" ||
							devs[0].Model != "SM_G973F" || devs[0].TransportID != "1" {
							t.Errorf("list_adb_devices: ready table = %#v", v)
						}
					case "list_adb_features":
						feats, ok := v.(rtADBFeatures)
						if !ok || feats.Count != 3 || feats.Features[1] != "shell_v2" {
							t.Errorf("list_adb_features: ready = %#v", v)
						}
					case "list_adb_directory":
						dir, ok := v.(rtDirListing)
						if !ok || dir.Path != "/sdcard" || len(dir.Entries) != 2 ||
							!dir.Entries[0].IsDir || dir.Entries[1].Name != "f.txt" {
							t.Errorf("list_adb_directory: ready = %#v", v)
						}
					case "list_adb_packages":
						pkgs, ok := v.(rtADBPackages)
						if !ok || pkgs.Count != 1 || pkgs.Packages[0].Package != "com.a" ||
							pkgs.Packages[0].APK != "/system/app/A.apk" {
							t.Errorf("list_adb_packages: ready = %#v", v)
						}
					case "list_adb_processes":
						ps, ok := v.(rtADBProcesses)
						if !ok || ps.Count != 1 || ps.Rows[0].PID != "1" || ps.Rows[0].Name != "init" ||
							len(ps.Columns) == 0 || ps.Columns[0] != "PID" {
							t.Errorf("list_adb_processes: ready = %#v", v)
						}
					case "install_adb_package":
						inst, ok := v.(rtADBInstall)
						if !ok || inst.APK != apk || inst.Result != "Success" || !strings.Contains(inst.Method, "streamed") {
							t.Errorf("install_adb_package: ready = %#v", v)
						}
					}
				}
			}

			calls, err := os.ReadFile(marker)
			if err != nil && !os.IsNotExist(err) {
				t.Fatal(err)
			}
			lines := rtLines(string(calls))
			switch state.name {
			case "absent":
				// The stub lives in stubDir, not on PATH: a fallback search would
				// show up here, and so would a lucky "adb" from another dir.
				if len(lines) != 0 {
					t.Errorf("adb absent from PATH, yet %d call(s) reached the stub: %q", len(lines), lines)
				}
			case "nodevice":
				if len(lines) == 0 {
					t.Fatal("device-less adb was never asked for its device table")
				}
				for _, l := range lines {
					if strings.HasPrefix(l, "-s ") {
						t.Errorf("device-less adb got the device command %q; the readiness gate must refuse before it", l)
					}
				}
				if !bucket18HasLine(lines, "devices -l") || !bucket18HasLine(lines, "host-features") {
					t.Errorf("device-less calls = %q, want the device table and host-features", lines)
				}
			case "device":
				for _, want := range []string{
					"devices -l",
					"shell ls -la '/sdcard'",
					"shell cmd package list packages -f",
					"shell ps -A -o PID,USER,NAME,ARGS",
					"install -r -t " + apk,
				} {
					if !bucket18HasLine(lines, want) {
						t.Errorf("ready state never issued %q; calls = %q", want, lines)
					}
				}
			}
		})
	}

	// instrument_with_frida refuses because the work is live instrumentation,
	// not because adb is missing: the refusal must not move between the three
	// tool states, and the stub must never be spawned for it.
	var refusal string
	for _, state := range states {
		t.Run("frida/"+state.name, func(t *testing.T) {
			t.Setenv("PATH", state.path)
			t.Setenv("ADB_TABLE", state.table)
			if err := os.Remove(marker); err != nil && !os.IsNotExist(err) {
				t.Fatal(err)
			}
			stdout, stderr, code := runCLIAll(t, "--op", "instrument_with_frida", "--json", "com.example.app::/tmp/hook.js")
			if code != 2 {
				t.Fatalf("instrument_with_frida exited %d, want 2; stdout:\n%s\nstderr:\n%s", code, stdout, stderr)
			}
			var env struct {
				Error string `json:"error"`
				Kind  string `json:"kind"`
			}
			if err := json.Unmarshal([]byte(stdout), &env); err != nil {
				t.Fatalf("stdout is not the refusal envelope: %v\n%s", err, stdout)
			}
			if env.Kind != string(kindOutOfScope) || !strings.Contains(env.Error, "out of scope") {
				t.Fatalf("refusal = %+v, want kind out_of_scope", env)
			}
			if refusal == "" {
				refusal = env.Error
			} else if env.Error != refusal {
				t.Errorf("refusal text moved with the adb state: %q vs %q", env.Error, refusal)
			}
			if calls, err := os.ReadFile(marker); err == nil && len(calls) != 0 {
				t.Errorf("instrument_with_frida spawned adb: %q", string(calls))
			}
		})
	}
}

func bucket18HasLine(lines []string, want string) bool {
	for _, l := range lines {
		if strings.Contains(l, want) {
			return true
		}
	}
	return false
}
