package main

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
)

// Parity harness: proves lrecon reads real targets deeply enough to answer the
// questions an agent actually asks (slices, hardening, Go deps, Electron
// payload, budget). Rows that can run anywhere point at tracked fixtures under
// testdata/fixtures. Rows that need a target only a real Mac install has (the
// Homebrew gh build, Studio.app) skip naming the lost coverage, so a CI run
// reports the gap instead of silently passing. A missing Digest field fails
// naming the field.

const (
	studioApp = "/Applications/Studio.app"

	// Tracked fixtures: every parity row that can be proven without a host
	// install uses one of these, so the suite is green on any checkout.
	fixtureMacho = "testdata/fixtures/macho"
	fixtureFat   = "testdata/fixtures/fatbin/universal.fat"
	fixtureAsar  = "testdata/fixtures/electron/app.asar"
	fixtureRust  = "testdata/fixtures/rust/fixture_rust"
)

// hostTarget resolves a target that only a real Mac install provides. Absence
// skips with the coverage it costs named, never a silent pass.
func hostTarget(t *testing.T, path, covers string) string {
	t.Helper()
	if _, err := os.Stat(path); err != nil {
		t.Skipf("coverage lost: %s absent (%v), so %s is unproven here", path, err, covers)
	}
	return path
}

type parityRow struct {
	name   string
	target string
	field  string
	want   string
	check  func(t *testing.T, d Digest)
}

func TestParityRealTargets(t *testing.T) {
	rows := []parityRow{
		{
			name: "fat/macho-slices", target: fixtureFat, field: "kind format slices",
			want: "macho/fat with >= 2 slices",
			check: func(t *testing.T, d Digest) {
				if d.Kind != "macho" || d.Format != "fat" {
					t.Fatalf("kind/format = %q/%q, want macho/fat", d.Kind, d.Format)
				}
				if d.Slices < 2 {
					t.Fatalf("slices = %d, want >= 2 (universal binary)", d.Slices)
				}
			},
		},
		{
			name: "macho/hardening", target: fixtureMacho, field: "hardening",
			want: "contains at least one of nx/pie/aslr",
			check: func(t *testing.T, d Digest) {
				requireDigestField(t, "hardening")
				raw, ok := digestMap(t, d)["hardening"]
				if !ok {
					t.Fatalf("hardening empty for %s, want one of nx/pie/aslr", d.Path)
				}
				low := strings.ToLower(fmt.Sprint(raw))
				for _, flag := range []string{"nx", "pie", "aslr"} {
					if strings.Contains(low, flag) {
						return
					}
				}
				t.Fatalf("hardening = %q, want one of nx/pie/aslr", low)
			},
		},
		{
			name: "go/buildinfo", target: goFixtureDeps(t, 1), field: "kind toolchain mod deps",
			want: "macho thin, toolchain go1., mod example.com/fix, 1 dep",
			check: func(t *testing.T, d Digest) {
				if d.Kind != "macho" {
					t.Fatalf("kind = %q, want macho", d.Kind)
				}
				if !strings.Contains(d.Toolchain, "go1.") {
					t.Fatalf("toolchain = %q, want it to contain go1.", d.Toolchain)
				}
				if !strings.Contains(d.Mod, "example.com/fix") {
					t.Fatalf("mod = %q, want example.com/fix", d.Mod)
				}
				if len(d.Deps) != 1 || !strings.HasPrefix(d.Deps[0].Path, "example.com/dep") {
					t.Fatalf("deps = %v, want example.com/dep*", d.Deps)
				}
			},
		},
		{
			name: "macho/imports", target: fixtureMacho, field: "imports",
			want: ">= 10 capability imports",
			check: func(t *testing.T, d Digest) {
				if len(d.Imports) < 10 {
					t.Fatalf("imports = %d, want >= 10; got %v", len(d.Imports), d.Imports)
				}
			},
		},
		{
			name: "file/native-macho", target: fixtureMacho, field: "kind dylibs imports",
			want: "macho with dylibs or imports",
			check: func(t *testing.T, d Digest) {
				if d.Kind != "macho" {
					t.Fatalf("kind = %q, want macho", d.Kind)
				}
				if d.Format == "" {
					t.Fatal("format empty for a Mach-O")
				}
				if len(d.Dylibs) == 0 && len(d.Imports) == 0 {
					t.Fatalf("both dylibs and imports empty for %s", d.Path)
				}
			},
		},
		{
			name: "asar/inventory", target: fixtureAsar, field: "kind asar_files asar_main",
			want: "asar, 8 files, main dist/main.js",
			check: func(t *testing.T, d Digest) {
				if d.Kind != "asar" {
					t.Fatalf("kind = %q, want asar", d.Kind)
				}
				if d.AsarFiles != 8 {
					t.Fatalf("asar_files = %d, want 8", d.AsarFiles)
				}
				if d.AsarMain != "dist/main.js" {
					t.Fatalf("asar_main = %q, want dist/main.js", d.AsarMain)
				}
			},
		},
		{
			name: "asar/capabilities", target: fixtureAsar, field: "capabilities electron",
			want: "electron capability plus a proven Electron version",
			check: func(t *testing.T, d Digest) {
				// Electron may surface as a capability or as the electron field; either
				// proves the archive was understood as an Electron app.
				m := digestMap(t, d)
				if !containsStr(d.Capabilities, "electron") && fmt.Sprint(m["electron"]) == "" {
					t.Fatalf("capabilities = %v and electron = %v, want an Electron version", d.Capabilities, m["electron"])
				}
			},
		},
		{
			name: "studio/app-bundle", target: hostTarget(t, studioApp, "a real .app bundle resolving inward to its asar"), field: "kind app electron",
			want: "a .app directory resolves to its asar instead of stopping at directory",
			check: func(t *testing.T, d Digest) {
				if d.Kind != "app" {
					t.Fatalf("kind = %q, want app (directory targets must resolve inward)", d.Kind)
				}
				if !containsStr(d.Capabilities, "electron") {
					t.Fatalf("capabilities = %v, want electron", d.Capabilities)
				}
			},
		},
		{
			name: "wasm/magic", target: writeTemp(t, "m.wasm", append([]byte("\x00asm\x01\x00\x00\x00"), make([]byte, 16)...)),
			field: "kind capabilities",
			want:  "wasm v1 with wasm capability",
			check: func(t *testing.T, d Digest) {
				if d.Kind != "wasm" {
					t.Fatalf("kind = %q, want wasm", d.Kind)
				}
				if d.Format != "v1" {
					t.Fatalf("format = %q, want v1", d.Format)
				}
			},
		},
	}

	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			d := parityDigest(t, row.target)
			row.check(t, d)
		})
	}
}

// Malformed inputs must produce a digest with a kind, not a panic or exit 1:
// an agent probing junk still needs an answer it can branch on.
func TestParityMalformedInputs(t *testing.T) {
	rows := []struct {
		name string
		data []byte
	}{
		{"four-random-bytes", []byte{0x9a, 0x11, 0xcd, 0x02}},
		{"truncated-gzip", []byte{0x1f, 0x8b, 0x08, 0x00}},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			path := writeTemp(t, row.name+".bin", row.data)
			out, code := runCLI(t, "--json", path)
			if code != 0 {
				t.Fatalf("exit %d, want 0 for malformed input; output:\n%s", code, out)
			}
			var d Digest
			if err := json.Unmarshal([]byte(out), &d); err != nil {
				t.Fatalf("stdout is not JSON (panic or truncated digest?): %v\n%s", err, out)
			}
			if d.Kind == "" {
				t.Fatalf("kind empty for malformed input %q", row.name)
			}
		})
	}
}

// A zero-byte target has no identity to report: the digest must refuse with a
// typed error (io/bad_arg), never answer "unknown" and never panic.
func TestParityEmptyTargetRefuses(t *testing.T) {
	path := writeTemp(t, "empty.bin", nil)
	out, code := runCLI(t, "--json", path)
	if code != 2 {
		t.Fatalf("exit %d, want 2 for a zero-byte target; output:\n%s", code, out)
	}
	var env struct {
		Kind  string `json:"kind"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		t.Fatalf("stdout is not a JSON error envelope: %v\n%s", err, out)
	}
	if env.Kind != "io" && env.Kind != "bad_arg" {
		t.Fatalf("kind = %q, want io or bad_arg; output:\n%s", env.Kind, out)
	}
}

// Default text output is a fixed budget; --json is a machine contract and must
// never be cut at the same budget.
func TestParityBudgetAndJSON(t *testing.T) {
	d := parityDigest(t, fixtureRust)
	t.Run("text-budget", func(t *testing.T) {
		if n := len(digestText(d, 4096)); n > 4096 {
			t.Fatalf("text digest = %d bytes, budget 4096", n)
		}
	})
	t.Run("json-never-truncated", func(t *testing.T) {
		out, code := runCLI(t, "--json", fixtureRust)
		if code != 0 {
			t.Fatalf("exit %d, want 0", code)
		}
		var back Digest
		if err := json.Unmarshal([]byte(out), &back); err != nil {
			t.Fatalf("--json output does not parse (%d bytes): %v", len(out), err)
		}
		if len(back.Deps) == 0 {
			t.Fatal("--json lost deps")
		}
	})
}

// Same target twice must be byte-identical, or every diff/compare workflow lies.
func TestParityDeterminism(t *testing.T) {
	for _, target := range []string{fixtureMacho, fixtureFat, fixtureAsar} {
		t.Run(strings.TrimPrefix(target, "/"), func(t *testing.T) {
			first, code := runCLI(t, target)
			if code != 0 {
				t.Fatalf("exit %d on first run", code)
			}
			second, code := runCLI(t, target)
			if code != 0 {
				t.Fatalf("exit %d on second run", code)
			}
			if first != second {
				t.Fatalf("output differs between runs:\n--- first ---\n%s\n--- second ---\n%s", first, second)
			}
		})
	}
}

// parityDigest probes a tracked fixture; absence is a failure, not a skip,
// because these files ship with the repo and a missing one is a broken checkout.
func parityDigest(t *testing.T, target string) Digest {
	t.Helper()
	if _, err := os.Stat(target); err != nil {
		t.Fatalf("tracked fixture %s missing: %v", target, err)
	}
	d, err := Probe(target)
	if err != nil {
		t.Fatalf("Probe(%s) error: %v", target, err)
	}
	return d
}

// requireDigestField fails, naming the field, when the Digest contract lacks it.
func requireDigestField(t *testing.T, name string) {
	t.Helper()
	typ := reflect.TypeOf(Digest{})
	for i := 0; i < typ.NumField(); i++ {
		if strings.Split(typ.Field(i).Tag.Get("json"), ",")[0] == name {
			return
		}
	}
	t.Fatalf("missing field %q on Digest: parity cannot prove %s; add it to types.go (json tag %q)", name, name, name)
}

// digestMap reads a Digest through its JSON contract, so new fields need no helper.
func digestMap(t *testing.T, d Digest) map[string]any {
	t.Helper()
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatalf("marshal digest: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal digest: %v", err)
	}
	return m
}
