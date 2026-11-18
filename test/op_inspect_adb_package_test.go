package main

import (
	"os"
	"path/filepath"
	"testing"
)

// a07FakeADBWithDump points a fake adb at a canned `dumpsys package` body: the
// device call is answered locally so the dump parse is what gets exercised.
func a07FakeADBWithDump(t *testing.T, dump string) {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "dump.txt")
	if err := os.WriteFile(p, []byte(dump), 0o600); err != nil {
		t.Fatalf("write dump: %v", err)
	}
	a07FakeTool(t, dir, "adb", `if [ "$1" = "devices" ]; then printf 'List of devices attached\nFAKE123\tdevice\n\n'; exit 0; fi
/bin/cat "$A07_DUMP"`)
	t.Setenv("PATH", dir)
	t.Setenv("A07_DUMP", p)
}

// `dumpsys package <unknown>` exits 0 and prints the whole package database, so
// the version lines of the FIRST package in the dump must never be reported as
// the requested package's version.
func TestInspectADBPackageReadsOnlyItsOwnSection(t *testing.T) {
	a07FakeADBWithDump(t, `Packages:
  Package [com.other.pkg] (111):
    versionCode=9 minSdk=21
    versionName=9.9
  Package [com.example.app] (222):
    requested permissions:
      android.permission.INTERNET
      android.permission.CAMERA
    install permissions:
    versionCode=7 minSdk=21
    versionName=1.2.3
`)

	m := reaMobileMap(t, reaMobileRun(t, "inspect_adb_package", "com.example.app"))
	if m["version_name"] != "1.2.3" || m["version_code"] != "7" {
		t.Fatalf("version = %v/%v, want 1.2.3/7 (other package is 9.9/9)", m["version_name"], m["version_code"])
	}
	perms, _ := m["permissions"].([]any)
	if len(perms) != 2 || perms[0] != "android.permission.INTERNET" || perms[1] != "android.permission.CAMERA" {
		t.Fatalf("permissions = %v", m["permissions"])
	}
}

// A name the dump does not carry is a bad argument, never a fabricated install.
func TestInspectADBPackageUnknownNameIsBadArg(t *testing.T) {
	a07FakeADBWithDump(t, "Package [com.other.pkg] (111):\n  versionCode=9\n  versionName=9.9\n")

	_, err := ops["inspect_adb_package"].run("com.example.app")
	if err == nil {
		t.Fatal("a missing Package section must refuse, not borrow another package's version")
	}
	if got := classify(err.Error()); got != kindBadArg {
		t.Fatalf("kind = %s, want %s: %v", got, kindBadArg, err)
	}
}

func TestInspectADBPackageSentinelIsNotInstalled(t *testing.T) {
	a07FakeADBWithDump(t, "Unable to find package: com.nope\n")

	m := reaMobileMap(t, reaMobileRun(t, "inspect_adb_package", "com.nope"))
	if m["state"] != "not-installed" {
		t.Fatalf("state = %v, want not-installed", m["state"])
	}
	if _, ok := m["version_name"]; ok {
		t.Fatalf("a not-installed package carries no version: %v", m)
	}
}
