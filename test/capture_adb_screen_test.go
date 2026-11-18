package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// adb is not on PATH on a machine where Android Studio installed the SDK, and
// every adb op spawns it by name. The SDK roots are where the tools themselves
// look, so they must be searched before the op skips as "adb not installed".
func TestFindADBInSDK(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home) // no default install to fall through to
	t.Setenv("ANDROID_HOME", filepath.Join(home, "missing"))

	sdk := t.TempDir()
	bin := filepath.Join(sdk, "platform-tools", "adb")
	if err := os.MkdirAll(filepath.Dir(bin), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ANDROID_SDK_ROOT", sdk)
	if got, ok := findADBInSDK(); !ok || got != bin {
		t.Fatalf("findADBInSDK() = %q, %v; want %q", got, ok, bin)
	}
}

// findADBInSDK finds the binary; this pins the step after it, the PATH prepend
// that makes every later exec.LookPath("adb") see the SDK copy. Without it the
// discovery is dead code and every adb op still skips "adb not installed".
func TestInstallADBOnPathReachesLookPath(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("ANDROID_SDK_ROOT", filepath.Join(home, "missing"))

	// The dev machine's own PATH may already carry platform-tools; replace it
	// so the prepend is the only thing that can make adb findable.
	empty := t.TempDir()
	t.Setenv("PATH", empty)
	if p, err := exec.LookPath("adb"); err == nil {
		t.Fatalf("test setup: adb still resolves to %q with PATH=%q", p, empty)
	}

	sdk := t.TempDir()
	bin := filepath.Join(sdk, "platform-tools", "adb")
	if err := os.MkdirAll(filepath.Dir(bin), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ANDROID_HOME", sdk)

	installADBOnPath()

	got, err := exec.LookPath("adb")
	if err != nil {
		t.Fatalf("after installADBOnPath adb must be findable: %v (PATH=%q)", err, os.Getenv("PATH"))
	}
	if got != bin {
		t.Fatalf("LookPath(adb) = %q; want the SDK copy %q", got, bin)
	}
	// A second call must not stack duplicates onto PATH.
	installADBOnPath()
	if q := os.Getenv("PATH"); q != filepath.Dir(bin)+string(os.PathListSeparator)+empty {
		t.Fatalf("PATH was prepended twice: %q", q)
	}
}

// An in-process caller with no -o must not make its output tree in the working
// directory: that is what left lrecon-* directories beside whatever tree lrecon
// was started from.
func TestAdbPullDestOutsideCwd(t *testing.T) {
	old := opOutput
	opOutput = ""
	t.Cleanup(func() { opOutput = old })

	dir, err := adbPullDest("com.example")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	if !strings.HasPrefix(dir, os.TempDir()) {
		t.Fatalf("pull destination %q is not under the system temp dir %q", dir, os.TempDir())
	}
	if wd, err := os.Getwd(); err == nil {
		if rel, err := filepath.Rel(wd, dir); err == nil && !strings.HasPrefix(rel, "..") {
			t.Fatalf("pull destination %q lands inside the working directory %q", dir, wd)
		}
	}
}

// A sweep that hands every op the same target can hand bugreport the device
// serial; adb pull would then write a zip named after the serial into the
// working directory. The serial is a selector, not a destination.
func TestCollectADBBugreportRefusesSerialAsDest(t *testing.T) {
	_, err := collectADBBugreport("emulator-5554")
	if err == nil || !strings.Contains(err.Error(), "ending in .zip") {
		t.Fatalf("a serial-shaped destination must be refused with the .zip rule, got %v", err)
	}
}

// The destination of capture_adb_screen is also its positional target, so a
// sweep that hands every op the same fixture can hand it a Mach-O. On
// 2026-11-02 that is exactly what happened: a screenshot replaced
// macho_thin_arm64, and 24 route-G ops then answered "unknown: no decompiler
// kind here" — a fixture loss that read like a Ghidra fault. This pins the
// refusal so the same overwrite cannot come back unnoticed.
func TestPngOnlyOverwrite(t *testing.T) {
	dir := t.TempDir()

	if err := pngOnlyOverwrite(filepath.Join(dir, "new.png")); err != nil {
		t.Fatalf("a path that does not exist yet must be allowed: %v", err)
	}

	png := filepath.Join(dir, "shot.png")
	if err := os.WriteFile(png, []byte("\x89PNG\r\n\x1a\nrest"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := pngOnlyOverwrite(png); err != nil {
		t.Fatalf("overwriting a previous screenshot must stay allowed: %v", err)
	}

	bin := filepath.Join(dir, "fixture")
	if err := os.WriteFile(bin, []byte("\xcf\xfa\xed\xfe not a png"), 0o755); err != nil {
		t.Fatal(err)
	}
	err := pngOnlyOverwrite(bin)
	if err == nil {
		t.Fatal("a non-PNG destination must be refused, not overwritten")
	}
	// Only the cause is asserted: the helper is shared with
	// capture_web_screenshot, whose way out is host:port=<path> rather than -o,
	// so each op adds its own hint on top of this error (capture_adb_screen:
	// "pass -o with a new path").
	if !strings.Contains(err.Error(), "not a PNG") {
		t.Fatalf("refusal must name the cause, got %q", err)
	}
	if b, _ := os.ReadFile(bin); string(b) != "\xcf\xfa\xed\xfe not a png" {
		t.Fatalf("refused destination changed anyway: %q", b)
	}

	if err := pngOnlyOverwrite(dir); err == nil {
		t.Fatal("a directory destination must be refused")
	}
}
