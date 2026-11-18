package main

// Tests for the five inspect_* runtime items. Each one goes through runOp, the
// same path the CLI uses, and is decoded from JSON so a result that does not
// marshal fails here instead of at the printer.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func reaRun(t *testing.T, name, path string) map[string]any {
	t.Helper()
	res, err := runOp(name, path)
	if err != nil {
		t.Fatalf("%s(%s): %v", name, path, err)
	}
	b, err := json.Marshal(res)
	if err != nil {
		t.Fatalf("%s(%s): result does not marshal: %v", name, path, err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("%s(%s): result is not a JSON object: %v (%s)", name, path, err, b)
	}
	return m
}

func reaString(t *testing.T, m map[string]any, key string) string {
	t.Helper()
	s, ok := m[key].(string)
	if !ok {
		t.Fatalf("field %q is %T, want string (%v)", key, m[key], m)
	}
	return s
}

func reaList(t *testing.T, m map[string]any, key string) []string {
	t.Helper()
	raw, ok := m[key].([]any)
	if !ok {
		t.Fatalf("field %q is %T, want array (%v)", key, m[key], m)
	}
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		s, ok := v.(string)
		if !ok {
			t.Fatalf("field %q holds %T, want string", key, v)
		}
		out = append(out, s)
	}
	return out
}

// reaRuntimeSkip returns the refusal reason, or "" when the op answered.
func reaRuntimeSkip(t *testing.T, m map[string]any) string {
	t.Helper()
	s, _ := m["skipped"].(string)
	return s
}

func TestReaRuntime(t *testing.T) {
	goBin := buildTarget(t, "linux", "amd64", "go-target")

	t.Run("inspect_go_binary", func(t *testing.T) {
		m := reaRun(t, "inspect_go_binary", goBin)
		if got := reaString(t, m, "kind"); got != "elf" {
			t.Fatalf("kind = %q, want elf", got)
		}
		if got := reaString(t, m, "toolchain"); !strings.HasPrefix(got, "go") {
			t.Fatalf("toolchain = %q, want a go producer string", got)
		}
		if got := reaString(t, m, "names"); !strings.HasPrefix(got, "pclntab:") {
			t.Fatalf("names = %q, want a pclntab count", got)
		}
	})

	t.Run("inspect_rust_binary", func(t *testing.T) {
		// native_test.go's C build gives a real non-Go Mach-O; the markers are
		// appended the way detect_test.go builds its Rust fixture.
		base, err := os.ReadFile(buildCTarget(t))
		if err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(t.TempDir(), "rusty")
		markers := "rustc version 1.75.0\x00" +
			`C:\Users\u\.cargo\registry\src\index.crates.io-1ecc6299db9ec823\memchr-2.8.3\src\lib.rs` + "\x00"
		if err := os.WriteFile(p, append(base, []byte(markers)...), 0o644); err != nil {
			t.Fatal(err)
		}
		m := reaRun(t, "inspect_rust_binary", p)
		if got := reaString(t, m, "toolchain"); !strings.HasPrefix(got, "rustc") {
			t.Fatalf("toolchain = %q, want a rustc producer string", got)
		}
		if crates := reaList(t, m, "crates"); len(crates) != 1 || crates[0] != "memchr-2.8.3" {
			t.Fatalf("crates = %v, want [memchr-2.8.3]", crates)
		}
	})

	t.Run("inspect_python_pyc", func(t *testing.T) {
		body := mCode(311, "outer", "mod.outer", "src/mod.py")
		p := writeTemp(t, "target.pyc", pycBlob(3495, 0, body))
		m := reaRun(t, "inspect_python_pyc", p)
		if got := reaString(t, m, "toolchain"); got != "cpython 3.11" {
			t.Fatalf("toolchain = %q, want cpython 3.11", got)
		}
		names := strings.Join(reaList(t, m, "qualnames"), ",")
		if !strings.Contains(names, "mod.outer") {
			t.Fatalf("qualnames = %q, want mod.outer", names)
		}
		// A text file is not a pyc: the refusal must name the kind it saw.
		txt := writeTemp(t, "notes.txt", []byte("just text\n"))
		if skip := reaRuntimeSkip(t, reaRun(t, "inspect_python_pyc", txt)); !strings.Contains(skip, "not a CPython .pyc") {
			t.Fatalf("skip = %q, want a not-a-pyc refusal", skip)
		}
	})

	t.Run("inspect_managed_artifact", func(t *testing.T) {
		m := reaRun(t, "inspect_managed_artifact", buildTablesPE(t, managedTablesFixture(t)))
		if got := reaString(t, m, "kind"); got != "pe-dotnet" {
			t.Fatalf("kind = %q, want pe-dotnet", got)
		}
		if got := reaString(t, m, "runtime"); got != "v4.0.30319" {
			t.Fatalf("runtime = %q, want v4.0.30319", got)
		}
		for key, want := range map[string]float64{"types": 2, "methods": 3, "assembly_refs": 2} {
			if got, _ := m[key].(float64); got != want {
				t.Fatalf("%s = %v, want %v", key, m[key], want)
			}
		}
	})

	t.Run("inspect_il2cpp_metadata", func(t *testing.T) {
		// A metadata file too short to hold a header is refused with the
		// reason: there is a reader now, and it cannot read this one.
		p := writeTemp(t, "global-metadata.dat", []byte("\xaf\x1b\xba\xfa\x1f\x00\x00\x00"))
		if _, err := runOp("inspect_il2cpp_metadata", p); err == nil || !strings.Contains(err.Error(), "shorter than the 168-byte header") {
			t.Fatalf("err = %v, want the short-header refusal", err)
		}
		// An image that references the file is the side lrecon does answer.
		b, err := os.ReadFile(goBin)
		if err != nil {
			t.Fatal(err)
		}
		img := filepath.Join(t.TempDir(), "unity-player")
		if err := os.WriteFile(img, append(b, []byte("global-metadata.dat\x00Unity 2021.3.5f1\x00")...), 0o644); err != nil {
			t.Fatal(err)
		}
		m := reaRun(t, "inspect_il2cpp_metadata", img)
		if !containsStr(reaList(t, m, "capabilities"), "il2cpp") {
			t.Fatalf("capabilities = %v, want il2cpp", m["capabilities"])
		}
	})
}
