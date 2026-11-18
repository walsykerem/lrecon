package main

// TUR3 lane26: skill-interaction checks for this lane's ops and helpers.
// The 9 ops here must stay registered with the route skill/op-index.md names,
// and the pure parsers must keep the edge-case behaviour the skill relies on.

import (
	"encoding/json"
	"strings"
	"testing"
)

// Skill route table (references/op-index.md, 127 L / 69 Y / 39 G): every lane26
// op must be registered under its documented route.
func TestR3L26OpsRegisteredRoutes(t *testing.T) {
	want := map[string]string{
		"build_call_path":                  "G",
		"current_procedure":                "L",
		"get_evidence_bundle":              "L",
		"inspect_devicetree":               "L",
		"inspect_pe_imports":               "L",
		"list_frida_processes":             "Y",
		"procedure_info":                   "G",
		"search_strings":                   "L",
		"verify_managed_native_boundaries": "L",
	}
	for name, route := range want {
		o, ok := ops[name]
		if !ok {
			t.Fatalf("op %q not registered", name)
		}
		if o.route != route {
			t.Fatalf("op %q route = %q, want %q", name, o.route, route)
		}
		if o.run == nil || o.desc == "" {
			t.Fatalf("op %q missing run/desc", name)
		}
	}
}

// klib is a post reader: host kind stays, version is read from the manifest.
func TestR3L26KlibMajor(t *testing.T) {
	for _, c := range []struct {
		v    string
		want int
		ok   bool
	}{
		{"2.1", 2, true}, {"1", 1, true}, {" 3.0 ", 3, true},
		{"bad", 0, false}, {"", 0, false}, {"-1.0", -1, false},
	} {
		got, ok := klibMajor(c.v)
		if got != c.want || ok != c.ok {
			t.Fatalf("klibMajor(%q) = %d,%v want %d,%v", c.v, got, ok, c.want, c.ok)
		}
	}
}

func TestR3L26KlibQnNames(t *testing.T) {
	strs := []string{"com", "acme", "Widget"}
	// entry 0: short "com" parent -1; entry 1: "acme" parent 0; entry 2: "Widget" parent 1
	qns := [][2]int32{{-1, 0}, {0, 1}, {1, 2}}
	got := qnNames(qns, strs)
	if len(got) != 3 || got[2] != "com.acme.Widget" {
		t.Fatalf("qnNames = %v", got)
	}
	if g := qnNames([][2]int32{{-1, 0}, {1, 1}}, strs); len(g) == 0 {
		t.Fatal("cycle-guard qnNames returned nothing")
	}
}

// P/Invoke boundary matching: decoration and .dll suffix are not identity.
func TestR3L26NativeBoundaryHelpers(t *testing.T) {
	if !sameModule("kernel32", "KERNEL32.DLL") {
		t.Fatal("sameModule dropped a .dll suffix")
	}
	if !sameImport("_MessageBoxA@16", "MessageBoxA") {
		t.Fatal("sameImport dropped Win32 decoration")
	}
	if sameImport("MessageBoxA", "MessageBoxW") {
		t.Fatal("sameImport conflated A/W variants")
	}
	if got := pinvokeCallConv(0); got != "winapi" {
		t.Fatalf("pinvokeCallConv(0) = %q, want winapi", got)
	}
	if got := pinvokeCallConv((1 << 8) | 1); got != "cdecl" {
		t.Fatalf("pinvokeCallConv(cdecl) = %q", got)
	}
	if got := joinNote("", "x"); got != "x" || joinNote("a", "b") != "a; b" {
		t.Fatalf("joinNote = %q / %q", got, joinNote("a", "b"))
	}
}

// inspect_adb_display runs one `wm size; wm density` shell call. An override
// line is optional: when the device has none, the field stays absent in JSON
// (omitempty) rather than becoming an empty string. This drives the real op
// through an adb shim that answers with only the two physical lines.
func TestR3L26ADBDisplayOverrideAbsent(t *testing.T) {
	rtFakeTool(t, "adb", `if [ "$3" = "shell" ]; then
  printf 'Physical size: 1080x2400\nPhysical density: 440\n'
  exit 0
fi
`+rtOneDevice)
	v, err := runOp("inspect_adb_display", "")
	if err != nil {
		t.Fatal(err)
	}
	got, ok := v.(rtADBDisplay)
	if !ok {
		t.Fatalf("result type = %T, want rtADBDisplay", v)
	}
	if got.PhysicalSize != "1080x2400" || got.PhysicalDensity != "440" {
		t.Fatalf("display = %+v", got)
	}
	if got.OverrideSize != "" || got.OverrideDensity != "" {
		t.Fatalf("override fields must stay empty when no override line: %+v", got)
	}
	b, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	j := string(b)
	if strings.Contains(j, "override_size") || strings.Contains(j, "override_density") {
		t.Fatalf("absent override must be omitted from JSON, got %s", j)
	}
	if !strings.Contains(j, `"physical_size":"1080x2400"`) || !strings.Contains(j, `"physical_density":"440"`) {
		t.Fatalf("physical lines lost in JSON, got %s", j)
	}
}

// No physical size/density line means the op refuses instead of guessing: the
// error names the first shell line so the caller sees what the device returned.
func TestR3L26ADBDisplayMissingPhysicalRefuses(t *testing.T) {
	rtFakeTool(t, "adb", `if [ "$3" = "shell" ]; then
  printf 'Physical size: 1080x2400\nOverride size: 1080x2160\n'
  exit 0
fi
`+rtOneDevice)
	_, err := runOp("inspect_adb_display", "")
	if err == nil {
		t.Fatal("missing physical density must be an error, not an empty display")
	}
	if !strings.Contains(err.Error(), "wm size and wm density are not available") {
		t.Fatalf("error = %q, want the unavailable-size/density message", err)
	}
	if !strings.Contains(err.Error(), "Physical size: 1080x2400") {
		t.Fatalf("error = %q, want first shell line quoted", err)
	}
}

// A small bundle stays inline; get_evidence_bundle is read-only and never
// spills below the cap (skill contract: no write beside the target).
func TestR3L26CapEvidenceBundleInline(t *testing.T) {
	out := map[string]any{"verified": true, "bundle_sha256": "abc"}
	got, err := capEvidenceBundle(out)
	if err != nil {
		t.Fatal(err)
	}
	m, ok := got.(map[string]any)
	if !ok || m["verified"] != true {
		t.Fatalf("capEvidenceBundle = %+v", got)
	}
	if _, spilled := m["written_to"]; spilled {
		t.Fatal("small bundle was spilled")
	}
}
