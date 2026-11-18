package main

// TUR3 lane28: the nine ops shipped by this lane are driven against real
// artifacts (the bundled APK/PE fixtures and a real Mach-O), never against a
// stub. The two readers (v8cache, lsdamacho) are already covered by their own
// test files; here the CLI/registry surface is what matters.

import (
	"os"
	"strings"
	"testing"
)

var lane28Ops = map[string]struct {
	route string
	needs bool
}{
	"capture_adb_screen":        {"Y", false},
	"decode_android_resources":  {"L", true},
	"get_objc_classes":          {"L", true},
	"inspect_electron_page":     {"Y", true},
	"inspect_pe_resources":      {"L", true},
	"list_jeb_units":            {"L", true},
	"procedure_references":      {"G", true},
	"set_addresses_names":       {"G", true},
	"verify_unknown_resolution": {"L", true},
}

func TestR3L28OpsRegistered(t *testing.T) {
	if len(lane28Ops) != 9 {
		t.Fatalf("lane inventory = %d, want 9", len(lane28Ops))
	}
	for name, want := range lane28Ops {
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

func TestR3L28DecodeAndroidResourcesRealApk(t *testing.T) {
	m := opStatic(t, "decode_android_resources", "testdata/fixtures/apk/resources.apk")
	pkgs, ok := m["packages"].([]any)
	if !ok || len(pkgs) != 1 {
		t.Fatalf("packages = %v, want one real package", m["packages"])
	}
	pkg := pkgs[0].(map[string]any)
	if got := opStaticNum(t, pkg, "id"); got != 0x7f {
		t.Fatalf("package id = %#x, want 0x7f", got)
	}
	if got := opStaticStr(t, pkg, "name"); got != "com.example.fix" {
		t.Fatalf("package name = %q, want com.example.fix", got)
	}
	names, _ := pkg["names"].([]any)
	if len(names) == 0 {
		t.Fatalf("names = %v, want a real resource name", pkg["names"])
	}
}

func TestR3L28ListJebUnitsRealApk(t *testing.T) {
	m := opStatic(t, "list_jeb_units", "testdata/fixtures/apk/resources.apk")
	units, ok := m["units"].([]any)
	if !ok || len(units) < 2 {
		t.Fatalf("units = %v, want real DEX classes", m["units"])
	}
	want := map[string]bool{"Lcom/example/fix/Main;": false, "Lcom/example/fix/Helper;": false}
	for _, u := range units {
		cls := opStaticStr(t, u.(map[string]any), "class")
		if _, ok := want[cls]; ok {
			want[cls] = true
		}
	}
	for cls, seen := range want {
		if !seen {
			t.Fatalf("class %s missing from real DEX units", cls)
		}
	}
}

func TestR3L28InspectPEResourcesRealPE(t *testing.T) {
	m := opStatic(t, "inspect_pe_resources", "testdata/fixtures/pe.exe")
	for _, k := range []string{"present", "section", "base_rva", "directory_bytes", "leaves", "types"} {
		if _, ok := m[k]; !ok {
			t.Fatalf("result missing %q: %v", k, m)
		}
	}
	if _, ok := m["present"].(bool); !ok {
		t.Fatalf("present = %v (%T), want bool", m["present"], m["present"])
	}
}

// A real Mach-O has no ObjC class list: the lane reader returns a skip refusal
// instead of inventing a class (the CLI maps that skip to bad_arg on stdout).
func TestR3L28ObjcClassesRealMachORefusal(t *testing.T) {
	v, err := runOp("get_objc_classes", "testdata/fixtures/macho")
	if err != nil {
		t.Fatal(err)
	}
	sk, ok := v.(*skip)
	if !ok {
		t.Fatalf("result = %T, want a skip refusal", v)
	}
	if !strings.Contains(sk.Reason, "no Objective-C class list") {
		t.Fatalf("skip reason = %q, want a no-class-list refusal", sk.Reason)
	}
}

// The two argument-taking G ops and the job-taking L op refuse an incomplete
// call on a real target; they never answer with an empty result.
func TestR3L28NeedsArgOnRealTarget(t *testing.T) {
	cases := map[string]string{
		"procedure_references":      "LRECON_AT",
		"set_addresses_names":       "labels",
		"verify_unknown_resolution": "address",
	}
	target := "testdata/fixtures/macho"
	for name, hint := range cases {
		v, err := runOp(name, target)
		if err == nil {
			t.Errorf("%s answered %T on a real target with no job/address", name, v)
			continue
		}
		if !strings.Contains(err.Error(), hint) {
			t.Errorf("%s err = %q, want hint %q", name, err, hint)
		}
	}
}

// pngOnlyOverwrite is the guard that stopped this lane's capture op from
// erasing a binary used as a sweep target. A new path is fine; a real Mach-O
// already at that path is not.
func TestR3L28PngOnlyOverwriteRealMachO(t *testing.T) {
	p := t.TempDir() + "/dest.png"
	if err := pngOnlyOverwrite(p); err != nil {
		t.Fatalf("a new path was refused: %v", err)
	}
	raw, err := os.ReadFile("testdata/fixtures/macho")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := pngOnlyOverwrite(p); err == nil || !strings.Contains(err.Error(), "is not a PNG") {
		t.Fatalf("pngOnlyOverwrite(real Mach-O) = %v, want a not-a-PNG refusal", err)
	}
}

// The V8 magic lives at bytes 2-3, not at the file prefix. A real cache built
// in the documented layout must be claimed; a leading C0 DE fingerprint must
// not (the existing v8cache_test.go pins the full capability set).
func TestR3L28V8CacheMagicOffset(t *testing.T) {
	if v8cacheMatch([]byte{0xde, 0xc0, 0, 0}, 64) {
		t.Fatal("a C0 DE file prefix was mistaken for the V8 magic")
	}
	if !v8cacheMatch([]byte{0x34, 0x12, v8cacheMagic0, v8cacheMagic1}, 64) {
		t.Fatal("the real magic at bytes 2-3 was not matched")
	}
}
