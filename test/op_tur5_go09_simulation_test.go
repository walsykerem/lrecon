package main

// Tur 5 Go09 simulation: pure decoding/routing helpers whose real behavior is
// not covered by the existing suite. No production code is changed.

import (
	"encoding/binary"
	"encoding/json"
	"testing"
)

// A resources.arsc type chunk is consumed by arscTypeEntries with three
// different offset-table layouts. Build each layout as an actual chunk and
// verify the resolved, type-prefixed names and the entry count.
func TestTur5Go09ArscOffsetLayouts(t *testing.T) {
	keys := []string{"alpha", "beta"}
	types := []string{"string"}
	const hs = 20

	t.Run("legacy-u32", func(t *testing.T) {
		c := make([]byte, 44)
		c[8], c[9] = 1, 0
		binary.LittleEndian.PutUint32(c[12:], 2)
		binary.LittleEndian.PutUint32(c[16:], 28)
		binary.LittleEndian.PutUint32(c[20:], 0)
		binary.LittleEndian.PutUint32(c[24:], 8)
		binary.LittleEndian.PutUint32(c[32:], 0) // entry 0 key index
		binary.LittleEndian.PutUint32(c[40:], 1) // entry 1 key index
		n, names, err := arscTypeEntries(c, hs, types, keys)
		if err != nil || n != 2 || len(names) != 2 || names[0] != "string/alpha" || names[1] != "string/beta" {
			t.Fatalf("legacy = %d %v %v", n, names, err)
		}
	})

	t.Run("sparse-index-offset", func(t *testing.T) {
		c := make([]byte, 44)
		c[8], c[9] = 1, 0x01
		binary.LittleEndian.PutUint32(c[12:], 2)
		binary.LittleEndian.PutUint32(c[16:], 28)
		binary.LittleEndian.PutUint16(c[20:], 5) // pair 0: index 5
		binary.LittleEndian.PutUint16(c[22:], 0) //         offset/4 = 0
		binary.LittleEndian.PutUint16(c[24:], 7) // pair 1: index 7
		binary.LittleEndian.PutUint16(c[26:], 2) //         offset/4 = 2 -> rel 8
		binary.LittleEndian.PutUint32(c[32:], 0)
		binary.LittleEndian.PutUint32(c[40:], 1)
		n, names, err := arscTypeEntries(c, hs, types, keys)
		if err != nil || n != 2 || len(names) != 2 || names[0] != "string/alpha" || names[1] != "string/beta" {
			t.Fatalf("sparse = %d %v %v", n, names, err)
		}
	})

	t.Run("offset16", func(t *testing.T) {
		c := make([]byte, 40)
		c[8], c[9] = 1, 0x02
		binary.LittleEndian.PutUint32(c[12:], 2)
		binary.LittleEndian.PutUint32(c[16:], 24)
		binary.LittleEndian.PutUint16(c[20:], 0)
		binary.LittleEndian.PutUint16(c[22:], 2)
		binary.LittleEndian.PutUint32(c[28:], 0)
		binary.LittleEndian.PutUint32(c[36:], 1)
		n, names, err := arscTypeEntries(c, hs, types, keys)
		if err != nil || n != 2 || len(names) != 2 || names[0] != "string/alpha" || names[1] != "string/beta" {
			t.Fatalf("offset16 = %d %v %v", n, names, err)
		}
	})

	t.Run("compact-key-in-u16", func(t *testing.T) {
		c := make([]byte, 36)
		c[8], c[9] = 1, 0
		binary.LittleEndian.PutUint32(c[12:], 1)
		binary.LittleEndian.PutUint32(c[16:], 28)
		binary.LittleEndian.PutUint32(c[20:], 0)
		binary.LittleEndian.PutUint16(c[28:], 1)    // compact: key index in size slot
		binary.LittleEndian.PutUint16(c[30:], 0x08) // compact flag
		n, names, err := arscTypeEntries(c, hs, types, keys)
		if err != nil || n != 1 || len(names) != 1 || names[0] != "string/beta" {
			t.Fatalf("compact = %d %v %v", n, names, err)
		}
	})

	t.Run("declares-past-buffer", func(t *testing.T) {
		c := make([]byte, 24)
		c[8], c[9] = 1, 0
		binary.LittleEndian.PutUint32(c[12:], 100)
		binary.LittleEndian.PutUint32(c[16:], 24)
		if _, _, err := arscTypeEntries(c, hs, types, keys); err == nil {
			t.Fatal("offset table past the chunk must be refused")
		}
	})
}

// utf16Name decodes a fixed-width UTF-16LE package name up to its NUL. A name
// that fills the whole field without a terminator must still decode fully.
func TestTur5Go09Utf16Name(t *testing.T) {
	b := make([]byte, 256)
	for i, r := range "com.example.App" {
		binary.LittleEndian.PutUint16(b[i*2:], uint16(r))
	}
	if got := utf16Name(b); got != "com.example.App" {
		t.Fatalf("utf16Name = %q", got)
	}
	binary.LittleEndian.PutUint16(b[2:], 0) // terminate after "c"
	if got := utf16Name(b); got != "c" {
		t.Fatalf("early NUL = %q", got)
	}
}

// find_changed_behavior keeps only mapped digest paths; the classification is
// a fixed name lookup, not an inference from values.
func TestTur5Go09BehaviorKindRouting(t *testing.T) {
	cases := map[string]string{
		"kind":               "executable-format",
		"minos":              "os-floor",
		"deps.foo":           "dependency",
		"capabilities":       "capability",
		"mobile_permissions": "permission",
		"plist_keys":         "declared-key",
		"asar_main":          "application-identity",
		"hardening":          "hardening",
		"symbols":            "code-surface",
		"constants":          "crypto-constant",
		"ipc":                "runtime-surface",
		"unknown_field":      "other",
	}
	for path, want := range cases {
		if got := metaBehaviorKind(path); got != want {
			t.Errorf("metaBehaviorKind(%q) = %q, want %q", path, got, want)
		}
	}
}

// Crash JSON arrives with numbers in three shapes; int and int64 parsers must
// agree on decimal but differ on base-0 string prefixes.
func TestTur5Go09CrashNumberForms(t *testing.T) {
	if n, ok := netcInt(json.Number("42")); !ok || n != 42 {
		t.Fatalf("netcInt(json.Number) = %d %v", n, ok)
	}
	if n, ok := netcInt(float64(7)); !ok || n != 7 {
		t.Fatalf("netcInt(float64) = %d %v", n, ok)
	}
	if n, ok := netcInt("0x10"); ok || n != 0 {
		t.Fatalf("netcInt(\"0x10\") = %d %v, want refusal", n, ok)
	}
	if n, ok := netcInt64("0x10"); !ok || n != 16 {
		t.Fatalf("netcInt64(\"0x10\") = %d %v, want 16", n, ok)
	}
	if got := lastPathPart("/usr/lib/libX.dylib"); got != "libX.dylib" {
		t.Fatalf("lastPathPart = %q", got)
	}
}
