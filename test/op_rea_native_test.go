package main

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// reaObject re-marshals an op result and returns it as a generic object, so the
// test proves the answer is JSON and reads the keys a consumer would see.
func reaObject(t *testing.T, v any) map[string]any {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("result is not marshalable: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("result is not a JSON object: %v (%s)", err, b)
	}
	return m
}

// reaSkip asserts the refusal shape and returns the reason text.
func reaSkip(t *testing.T, v any) string {
	t.Helper()
	s, ok := v.(*skip)
	if !ok {
		t.Fatalf("want *skip refusal, got %T", v)
	}
	if s.Reason == "" {
		t.Fatal("skip reason is empty")
	}
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("skip is not marshalable: %v", err)
	}
	if !strings.Contains(string(b), `"skipped"`) {
		t.Fatalf("skip JSON lacks the skipped key: %s", b)
	}
	return s.Reason
}

func TestReaNativeOps(t *testing.T) {
	machoPath := buildTarget(t, "darwin", "arm64", "rea-macho")
	elfPath := buildTarget(t, "linux", "amd64", "rea-elf")
	pePath := buildTarget(t, "windows", "amd64", "rea-pe.exe")

	t.Run("inspect_macho", func(t *testing.T) {
		v, err := runOp("inspect_macho", machoPath)
		if err != nil {
			t.Fatalf("inspect_macho: %v", err)
		}
		m := reaObject(t, v)
		if m["kind"] != "macho" || m["format"] != "thin" {
			t.Fatalf("kind/format = %v/%v, want macho/thin", m["kind"], m["format"])
		}
		if m["slices"] != float64(1) {
			t.Fatalf("slices = %v, want 1", m["slices"])
		}
		sections, ok := m["sections"].([]any)
		if !ok || len(sections) == 0 {
			t.Fatalf("sections = %v, want at least one mapped section", m["sections"])
		}
		if m["symbols"] != symPresent {
			t.Fatalf("symbols = %v, want %q", m["symbols"], symPresent)
		}

		v, err = runOp("inspect_macho", elfPath)
		if err != nil {
			t.Fatalf("inspect_macho on ELF: %v", err)
		}
		if reason := reaSkip(t, v); !strings.Contains(reason, "not Mach-O") {
			t.Fatalf("skip reason = %q, want not Mach-O", reason)
		}

		// The tracked fat fixture is a real universal Mach-O, so the fat path is
		// proven here without borrowing a host binary.
		if b, err := os.ReadFile(fixtureFat); err == nil && len(b) >= 4 && binary.BigEndian.Uint32(b) == 0xcafebabe {
			v, err := runOp("inspect_macho", fixtureFat)
			if err != nil {
				t.Fatalf("inspect_macho fat: %v", err)
			}
			fat := reaObject(t, v)
			if fat["format"] != "fat" {
				t.Fatalf("fat format = %v, want fat", fat["format"])
			}
			if slices, ok := fat["slices"].(float64); !ok || slices < 2 {
				t.Fatalf("fat slices = %v, want at least 2", fat["slices"])
			}
			if secs, ok := fat["sections"].([]any); !ok || len(secs) == 0 {
				t.Fatalf("fat sections = %v, want sections", fat["sections"])
			}
		}
	})

	t.Run("inspect_pe_imports", func(t *testing.T) {
		v, err := runOp("inspect_pe_imports", pePath)
		if err != nil {
			t.Fatalf("inspect_pe_imports: %v", err)
		}
		m := reaObject(t, v)
		dlls, ok := m["dlls"].([]any)
		if !ok || len(dlls) == 0 {
			t.Fatalf("dlls = %v, want imported DLLs", m["dlls"])
		}
		imports, ok := m["imports"].([]any)
		if !ok || len(imports) == 0 {
			t.Fatalf("imports = %v, want imported symbols", m["imports"])
		}
		total, ok := m["total"].(float64)
		if !ok || int(total) < len(imports) {
			t.Fatalf("total = %v, shown = %d", m["total"], len(imports))
		}

		v, err = runOp("inspect_pe_imports", elfPath)
		if err != nil {
			t.Fatalf("inspect_pe_imports on ELF: %v", err)
		}
		if reason := reaSkip(t, v); !strings.Contains(reason, "not PE") {
			t.Fatalf("skip reason = %q, want not PE", reason)
		}
	})

	t.Run("inspect_native_exports", func(t *testing.T) {
		v, err := runOp("inspect_native_exports", elfPath)
		if err != nil {
			t.Fatalf("inspect_native_exports: %v", err)
		}
		m := reaObject(t, v)
		if m["kind"] != "elf" {
			t.Fatalf("kind = %v, want elf", m["kind"])
		}
		if m["symbols"] != symPresent {
			t.Fatalf("symbols = %v, want %q", m["symbols"], symPresent)
		}
		if _, ok := m["exports"].(float64); !ok {
			t.Fatalf("exports = %v, want a count", m["exports"])
		}

		v, err = runOp("inspect_native_exports", machoPath)
		if err != nil {
			t.Fatalf("inspect_native_exports on Mach-O: %v", err)
		}
		if reason := reaSkip(t, v); !strings.Contains(reason, "covered by inspect_macho") {
			t.Fatalf("skip reason = %q, want covered by inspect_macho", reason)
		}
	})

	t.Run("inspect_native_load_image", func(t *testing.T) {
		v, err := runOp("inspect_native_load_image", pePath)
		if err != nil {
			t.Fatalf("inspect_native_load_image: %v", err)
		}
		reason := reaSkip(t, v)
		if !strings.Contains(reason, "never maps a loaded image") {
			t.Fatalf("skip reason = %q, want never maps a loaded image", reason)
		}
		if !strings.Contains(reason, pePath) {
			t.Fatalf("skip reason = %q, want it to name %s", reason, pePath)
		}
	})

	t.Run("list_architectures", func(t *testing.T) {
		v, err := runOp("list_architectures", machoPath)
		if err != nil {
			t.Fatalf("list_architectures: %v", err)
		}
		m := reaObject(t, v)
		if m["format"] != "thin" || m["slices"] != float64(1) {
			t.Fatalf("format/slices = %v/%v, want thin/1", m["format"], m["slices"])
		}
		arches, ok := m["architectures"].([]any)
		if !ok || len(arches) != 1 {
			t.Fatalf("architectures = %v, want one row", m["architectures"])
		}
		row, ok := arches[0].(map[string]any)
		if !ok || row["arch"] != "arm64" {
			t.Fatalf("arch row = %v, want arm64", arches[0])
		}
		if row["offset"] != float64(0) {
			t.Fatalf("offset = %v, want 0 for a thin image", row["offset"])
		}
		if size, ok := row["size"].(float64); !ok || size <= 0 {
			t.Fatalf("size = %v, want positive bytes", row["size"])
		}
		// A thin row has no slice header to carry alignment, but the field is
		// part of the answer for both thin and universal images, so it must be
		// there as a measured number rather than absent.
		if align, ok := row["align"].(float64); !ok || align < 0 {
			t.Fatalf("align = %v, want a measured number for a thin image", row["align"])
		}

		v, err = runOp("list_architectures", pePath)
		if err != nil {
			t.Fatalf("list_architectures on PE: %v", err)
		}
		if reason := reaSkip(t, v); !strings.Contains(reason, "not Mach-O") {
			t.Fatalf("skip reason = %q, want not Mach-O", reason)
		}
	})
}

// a21WantKind asserts that one op answers one target with the given kind: the
// contract the CLI proves, held directly so a regression names the op.
func a21WantKind(t *testing.T, name, path string, want errorKind) {
	t.Helper()
	got, err := runOp(name, path)
	if err == nil {
		t.Errorf("%s(%q) = %#v, want a %s error", name, path, got, want)
		return
	}
	if kind := classify(err.Error()); kind != want {
		t.Errorf("%s(%q) kind = %s (%v), want %s", name, path, kind, err, want)
	}
}

// a21Zip writes a zip fixture under the test's own temp dir.
func a21Zip(t *testing.T, name string, files map[string]string) string {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for entry, body := range files {
		w, err := zw.Create(entry)
		if err != nil {
			t.Fatalf("zip entry %q: %v", entry, err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatalf("zip write %q: %v", entry, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return writeTemp(t, name, buf.Bytes())
}

// TestReaNativeRefusalKinds pins the three answers every Ghidra-backed op owes
// before an engine is found: no target is needs_arg, a target not on disk is
// io, and a target with no native code is a no_engine skip. The cache stays
// empty, so the refusal never starts Ghidra.
func TestReaNativeRefusalKinds(t *testing.T) {
	names := []string{
		"procedure_assembly", "procedure_callees", "procedure_callers",
		"procedure_info", "procedure_pseudo_code", "procedure_references",
		"read_function_instructions", "resolve_containing_procedure",
		"resolve_native_call_targets", "search_procedures",
	}
	cache := t.TempDir()
	t.Setenv("LRECON_GHIDRA_CACHE", cache)
	t.Setenv("LRECON_AT", "0x1000")
	t.Setenv("LRECON_NAME", "main")
	t.Setenv("LRECON_PATTERN", "main")
	text := writeTemp(t, "note.txt", []byte("no native code here\n"))
	for _, name := range names {
		a21WantKind(t, name, "", kindNeedsArg)
		a21WantKind(t, name, "/nonexistent-xyz", kindIO)
		got, err := runOp(name, text)
		if err != nil {
			t.Errorf("%s on a text file = %v, want a no_engine skip", name, err)
			continue
		}
		if reason := reaSkip(t, got); classify(reason) != kindNoEngine || !strings.Contains(reason, "no decompiler") {
			t.Errorf("%s text skip = %q, want a no decompiler no_engine refusal", name, reason)
		}
	}
	if ents, err := os.ReadDir(cache); err != nil || len(ents) != 0 {
		t.Errorf("Ghidra cache = %v, %v; want no engine work at all", ents, err)
	}
}
