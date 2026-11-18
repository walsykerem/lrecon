package main

import (
	"testing"
)

// A device whose wm prints nothing usable is a device problem, not an lrecon
// fault: the envelope has to say no_engine, not internal.
func TestInspectADBDisplayUnusableWmIsNoEngine(t *testing.T) {
	dir := t.TempDir()
	a07FakeTool(t, dir, "adb", `if [ "$1" = "devices" ]; then printf 'List of devices attached\nFAKE123\tdevice\n\n'; exit 0; fi
echo "junk shell output"`)
	t.Setenv("PATH", dir)

	_, err := ops["inspect_adb_display"].run("")
	if err == nil {
		t.Fatal("a junk `wm size; wm density` must refuse, not report a display")
	}
	if got := classify(err.Error()); got != kindNoEngine {
		t.Fatalf("kind = %s, want %s: %v", got, kindNoEngine, err)
	}
}

// The positive path stays a parse of the device's own lines, not a guess.
func TestInspectADBDisplayParsesWmLines(t *testing.T) {
	dir := t.TempDir()
	a07FakeTool(t, dir, "adb", `if [ "$1" = "devices" ]; then printf 'List of devices attached\nFAKE123\tdevice\n\n'; exit 0; fi
printf 'Physical size: 1080x2400\nPhysical density: 420\nOverride size: 720x1600\n'`)
	t.Setenv("PATH", dir)

	m := reaMobileMap(t, reaMobileRun(t, "inspect_adb_display", ""))
	if m["physical_size"] != "1080x2400" || m["physical_density"] != "420" || m["override_size"] != "720x1600" {
		t.Fatalf("display = %v", m)
	}
}
