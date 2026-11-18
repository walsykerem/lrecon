package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTmp(t *testing.T, name string, body []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, body, 0o644); err != nil {
		t.Fatalf("write %s: %v", p, err)
	}
	return p
}

func evasionFamily(t *testing.T, path, family string) evasionFamilyResult {
	t.Helper()
	got, err := runCheckRuntimeEvasion(path)
	if err != nil {
		t.Fatalf("check_runtime_evasion: %v", err)
	}
	for _, f := range got.(map[string]any)["families"].([]evasionFamilyResult) {
		if f.Family == family {
			return f
		}
	}
	t.Fatalf("family %q not in output", family)
	return evasionFamilyResult{}
}

func TestEvasionPackHasSixFamilies(t *testing.T) {
	want := []string{"anti-timing", "debugger-detect", "remote-debug-attach", "sandbox-detect", "synthetic-trace", "vm-detect"}
	got := evasionFamilies()
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("families = %v, want %v", got, want)
	}
}

func TestEvasionDebuggerDetectHit(t *testing.T) {
	body := []byte("\x7fELF padded text ... IsDebuggerPresent ... PT_DENY_ATTACH ...")
	p := writeTmp(t, "dbg", body)
	f := evasionFamily(t, p, "debugger-detect")
	ids := map[string]bool{}
	for _, h := range f.Hits {
		ids[h.ID] = true
	}
	if !ids["isdebuggerpresent"] || !ids["pt-deny-attach"] {
		t.Fatalf("debugger-detect hits = %+v, want IsDebuggerPresent and PT_DENY_ATTACH", f.Hits)
	}
	if f.Confidence != "static-indicator" {
		t.Fatalf("confidence = %q, want static-indicator", f.Confidence)
	}
	for _, h := range f.Hits {
		if h.Offset <= 0 {
			t.Fatalf("hit offset = %d, want the literal's position", h.Offset)
		}
	}
}

func TestEvasionVMFamilyHit(t *testing.T) {
	p := writeTmp(t, "vm", []byte("payload VBoxService.exe and vmware.log"))
	f := evasionFamily(t, p, "vm-detect")
	if len(f.Hits) < 2 {
		t.Fatalf("vm-detect hits = %+v, want VBox and vmware.log", f.Hits)
	}
}

func TestEvasionNegativeControl(t *testing.T) {
	p := writeTmp(t, "clean", []byte("ordinary application text with no analysis markers at all"))
	got, err := runCheckRuntimeEvasion(p)
	if err != nil {
		t.Fatalf("check_runtime_evasion: %v", err)
	}
	res := got.(map[string]any)
	if n := res["indicators"].(int); n != 0 {
		t.Fatalf("clean file reports %d indicators", n)
	}
	for _, f := range res["families"].([]evasionFamilyResult) {
		if len(f.Hits) != 0 {
			t.Fatalf("clean file hits family %s: %+v", f.Family, f.Hits)
		}
	}
}

// The answer must never claim the target was defeated or bypassed: a static
// marker is not a runtime outcome.
func TestEvasionNeverClaimsBypass(t *testing.T) {
	p := writeTmp(t, "dbg", []byte("IsDebuggerPresent PT_DENY_ATTACH VBox frida rdtsc jdwp"))
	got, err := runCheckRuntimeEvasion(p)
	if err != nil {
		t.Fatalf("check_runtime_evasion: %v", err)
	}
	text := strings.ToLower(toString(got))
	for _, bad := range []string{"bypassed", "defeated"} {
		if strings.Contains(text, bad) {
			t.Fatalf("output contains %q: %s", bad, text)
		}
	}
}

// toString renders any answer through its JSON form for substring asserts.
func toString(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(b)
}
