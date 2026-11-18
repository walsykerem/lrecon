package main

import (
	"fmt"
	"reflect"
	"testing"
)

func TestRoleOf(t *testing.T) {
	cases := []struct{ in, want string }{
		{"libcrypto.dylib", "crypto"},
		{"libssl.3.dylib", "crypto"},
		{"/usr/lib/libsqlite3.dylib", "storage"},
		{"github.com/mattn/go-sqlite3", "storage"},
		{"napi_create_string", "node-addon"},
		{"ptrace", "debugger"},
		{"task_for_pid", "debugger"},
		{"socket", "network"},
		{"connect", "network"},
		{"SecTrustEvaluate", "codesign"},
		{"Security", "codesign"},
		{"frida-agent.dylib", "instrumentation"},
		{"mach_inject", "instrumentation"},
		{"libcurl.4.dylib", "http"},
		{"libz.so.1", "compression"},
		{"libavcodec", "media"},
		{"libcups.2.dylib", "printing"},
		{"Carbon", "ui"},
		{"AppKit", "ui"},
		{"libSystem.B.dylib", ""},
		{"", ""},
	}
	for _, c := range cases {
		if got := RoleOf(c.in); got != c.want {
			t.Errorf("RoleOf(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestAddUpdaterCaps(t *testing.T) {
	d := Digest{
		Deps:    []Dep{{Path: "electron-updater", Version: "6.1.0"}},
		Dylibs:  []string{"Squirrel.framework/Squirrel"},
		Imports: []string{"autoUpdater", "socket"},
		Notes:   []string{"Sparkle 2.6 embedded"},
	}
	AddUpdaterCaps(&d)
	AddUpdaterCaps(&d) // idempotent
	want := []string{
		"updater:Sparkle",
		"updater:Squirrel",
		"updater:autoUpdater",
		"updater:electron-updater",
	}
	if !reflect.DeepEqual(d.Capabilities, want) {
		t.Fatalf("capabilities = %v, want %v", d.Capabilities, want)
	}
}

// TestUpdaterCapsFromModulePaths: declared dependency names count even when no
// node_modules tree is vendored, and tuf matches as a module path segment, not
// as a substring of a basename ("future" and "tufa" stay out).
func TestUpdaterCapsFromModulePaths(t *testing.T) {
	cases := []struct {
		name  string
		names []string
		want  []string
	}{
		{"declared", []string{"electron-updater", "go-tuf", "Squirrel.Windows"},
			[]string{"updater:Squirrel", "updater:electron-updater", "updater:tuf"}},
		{"tuf-segment", []string{"github.com/sigstore/sigstore/pkg/tuf"},
			[]string{"updater:tuf"}},
		{"tuf-versioned", []string{"github.com/theupdateframework/go-tuf/v2"},
			[]string{"updater:tuf"}},
		{"no-false-positive", []string{"future", "tufa", "refactoring"}, nil},
		{"trailing-slash", []string{"github.com/x/tuf/"}, []string{"updater:tuf"}},
		{"segment-prefix-only", []string{"tufa/tufb"}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var d Digest
			AddUpdaterCapsFrom(&d, c.names)
			if !reflect.DeepEqual(d.Capabilities, c.want) {
				t.Fatalf("capabilities = %v, want %v", d.Capabilities, c.want)
			}
		})
	}
}

// TestAsarDeclaredUpdaterDeps: a package.json dependency declared inside the
// asar is a capability even when the module itself is not packed.
func TestAsarDeclaredUpdaterDeps(t *testing.T) {
	cases := []struct {
		name string
		pkg  string
		want []string
	}{
		{"dependencies", `{"name":"app","version":"1.0.0","main":"main.js",` +
			`"dependencies":{"electron-updater":"6.1.0","github.com/sigstore/sigstore/pkg/tuf":"v1"}}`,
			[]string{"updater:electron-updater", "updater:tuf"}},
		{"devDependencies", `{"name":"app","version":"1.0.0","main":"main.js",` +
			`"devDependencies":{"electron":"33.0.0","Squirrel.Windows":"2.0.0"}}`,
			[]string{"updater:Squirrel"}},
		{"none", `{"name":"app","version":"1.0.0","main":"main.js"}`, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := probeAsar(t, map[string][]byte{
				"package.json": []byte(c.pkg),
				"main.js":      []byte("app.whenReady()\n"),
			})
			for _, want := range c.want {
				if !containsStr(d.Capabilities, want) {
					t.Fatalf("capabilities = %v, want %q", d.Capabilities, want)
				}
			}
			if c.want == nil && len(d.Capabilities) > 0 {
				t.Fatalf("capabilities = %v, want none for a plain package.json", d.Capabilities)
			}
		})
	}
}

func TestDiffDigests(t *testing.T) {
	old := Digest{
		Kind:         "macho",
		Toolchain:    "go1.22",
		Deps:         []Dep{{Path: "foo", Version: "v1.0.0"}, {Path: "gone", Version: "v0.1.0"}},
		Capabilities: []string{"updater:Squirrel", "asar"},
		AsarFiles:    12,
	}
	new := Digest{
		Kind:         "elf",
		Toolchain:    "go1.23",
		Deps:         []Dep{{Path: "foo", Version: "v2.0.0"}, {Path: "added", Version: "v3.1.0"}},
		Capabilities: []string{"asar", "updater:Sparkle"},
		AsarFiles:    14,
	}
	want := []string{
		"kind macho -> elf",
		"+dep added v3.1.0",
		"~dep foo v1.0.0 -> v2.0.0",
		"-dep gone v0.1.0",
		"toolchain go1.22 -> go1.23",
		"+capability updater:Sparkle",
		"-capability updater:Squirrel",
		"files 12 -> 14",
	}
	if got := DiffDigests(old, new); !reflect.DeepEqual(got, want) {
		t.Fatalf("DiffDigests =\n%v\nwant\n%v", got, want)
	}
	if got := DiffDigests(old, old); len(got) != 0 {
		t.Fatalf("self diff = %v, want empty", got)
	}
}

// Go main module, mobile manifest and rust crate deltas moved between two
// builds; the diff has to name them instead of "no differences".
func TestDiffDigestsNonBinaryFields(t *testing.T) {
	cases := []struct {
		name string
		a, b Digest
		want string
	}{
		{"mod", Digest{Mod: "example.com/a v1.0.0"}, Digest{Mod: "example.com/a v1.1.0"},
			"mod example.com/a v1.0.0 -> example.com/a v1.1.0"},
		{"permission", Digest{MobilePerms: []string{"INTERNET"}},
			Digest{MobilePerms: []string{"INTERNET", "CAMERA"}}, "+mobile_permission CAMERA"},
		{"crate", Digest{RustCrates: []string{"serde 1.0.1"}},
			Digest{RustCrates: []string{"serde 1.0.1", "tokio 1.38.0"}}, "+rust_crate tokio 1.38.0"},
	}
	for _, c := range cases {
		if got := DiffDigests(c.a, c.b); len(got) != 1 || got[0] != c.want {
			t.Errorf("%s: DiffDigests = %v, want [%s]", c.name, got, c.want)
		}
	}
	same := Digest{
		Mod: "example.com/a v1.0.0", MobilePkg: "com.example", MobileSDK: "34",
		MobilePerms: []string{"CAMERA", "INTERNET"},
		RustCrates:  []string{"serde 1.0.1", "tokio 1.38.0"},
		ElectronIPC: []string{"a", "b"}, SourceMaps: []string{"dist/app.js.map"}, UnpackedNode: 2,
	}
	if got := DiffDigests(same, same); len(got) != 0 {
		t.Fatalf("equal digests diffed non-empty: %v", got)
	}
}

// A version bump moves minos/uuid/electron/exports/slices; before this the diff
// said "no differences" for two different binaries.
func TestDiffDigestsVersionFields(t *testing.T) {
	old := Digest{
		Format: "fat", Slices: 2, MinOS: "11.0", UUID: "aaaa",
		ElectronVer: "44.1.1", AsarMain: "index.js", AsarVersion: "1.0.0",
		FlutterHash: "old", Exports: 10,
		SliceInfo: []string{"arm64 minos 11.0"}, Dylibs: []string{"/usr/lib/libA.dylib"},
		Imports: []string{"sqlite3_open"}, Rpaths: []string{"@executable_path/../Frameworks"},
		Hardening: []string{"codesign", "pie"},
	}
	new := Digest{
		Format: "fat", Slices: 3, MinOS: "12.0", UUID: "bbbb",
		ElectronVer: "45.0.0", AsarMain: "main.js", AsarVersion: "1.1.0",
		FlutterHash: "new", Exports: 12,
		SliceInfo: []string{"arm64 minos 12.0"}, Dylibs: []string{"/usr/lib/libB.dylib"},
		Imports: []string{"sqlite3_close"}, Rpaths: []string{"@loader_path"},
		Hardening: []string{"codesign", "nx"},
	}
	want := []string{
		"minos 11.0 -> 12.0",
		"uuid aaaa -> bbbb",
		"electron 44.1.1 -> 45.0.0",
		"asar_main index.js -> main.js",
		"asar_version 1.0.0 -> 1.1.0",
		"flutter_hash old -> new",
		"slices 2 -> 3",
		"exports 10 -> 12",
		"+slice arm64 minos 12.0",
		"-slice arm64 minos 11.0",
		"+dylib /usr/lib/libB.dylib",
		"-dylib /usr/lib/libA.dylib",
		"+import sqlite3_close",
		"-import sqlite3_open",
		"+rpath @loader_path",
		"-rpath @executable_path/../Frameworks",
		"+hardening nx",
		"-hardening pie",
	}
	if got := DiffDigests(old, new); !reflect.DeepEqual(got, want) {
		t.Fatalf("DiffDigests =\n%v\nwant\n%v", got, want)
	}
}

// BenchmarkAddUpdaterCapsFrom measures the per-name scan every reader runs over
// deps, dylibs, imports and notes. The haystack is a realistic list: mostly
// module paths with no updater in them.
func BenchmarkAddUpdaterCapsFrom(b *testing.B) {
	names := make([]string, 0, 515)
	for i := range 512 {
		names = append(names, fmt.Sprintf("github.com/example/module%03d/pkg/v%d", i%97, i%3+1))
	}
	names = append(names, "github.com/theupdateframework/go-tuf/v2", "electron-updater", "Sparkle")
	b.ReportAllocs()
	b.ResetTimer()
	var d Digest
	for b.Loop() {
		d.Capabilities = d.Capabilities[:0]
		AddUpdaterCapsFrom(&d, names)
	}
}
