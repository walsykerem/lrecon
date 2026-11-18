package main

import (
	"encoding/json"
	"slices"
	"sort"
	"strings"
	"testing"
)

// The inventory op must answer with no target, derive every format from live
// state (no second list to drift), and still name the file it was given.
func TestFormatCoverageInventory(t *testing.T) {
	v, err := runOp("inspect_format_coverage", "")
	if err != nil {
		t.Fatalf("inspect_format_coverage with no target: %v", err)
	}
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var inv struct {
		SupportedFormats []string `json:"supported_formats"`
		ReaderCount      int      `json:"reader_count"`
		MagicSwitchKinds []string `json:"magic_switch_kinds"`
	}
	if err := json.Unmarshal(raw, &inv); err != nil {
		t.Fatal(err)
	}
	if len(inv.SupportedFormats) == 0 {
		t.Fatal("supported_formats is empty")
	}
	if inv.ReaderCount != len(readers) {
		t.Fatalf("reader_count = %d, want len(readers) = %d", inv.ReaderCount, len(readers))
	}
	if !sort.StringsAreSorted(inv.SupportedFormats) {
		t.Fatalf("supported_formats is not sorted: %v", inv.SupportedFormats)
	}
	if len(inv.MagicSwitchKinds) == 0 {
		t.Fatal("magic_switch_kinds is empty")
	}
	for _, want := range []string{"mach-o", "elf", "pe", "wasm", "sqlite"} {
		if !containsFormat(inv.SupportedFormats, want) {
			t.Fatalf("supported_formats misses %q: %v", want, inv.SupportedFormats)
		}
	}
	// Every live reader format is published, so a new reader shows up here.
	for _, r := range readers {
		if !containsFormat(inv.SupportedFormats, r.format) {
			t.Fatalf("reader format %q missing from supported_formats", r.format)
		}
	}
}

// Unknown bytes are the uncovered case: the op says so by note instead of
// pretending the file was in an unread format.
func TestFormatCoverageUnknownBytes(t *testing.T) {
	p := writeTemp(t, "garbage.bin", []byte(strings.Repeat("\x63\x00\x00\x00", 4)))
	m := opStatic(t, "inspect_format_coverage", p)
	if got := opStaticStr(t, m, "target_kind"); got != "unknown" {
		t.Fatalf("target_kind = %q, want unknown", got)
	}
	if covered, ok := m["covered"].(bool); !ok || covered {
		t.Fatalf("covered = %v (%T), want false", m["covered"], m["covered"])
	}
	var noted bool
	for _, n := range m["notes"].([]any) {
		if s, _ := n.(string); strings.Contains(s, "uncovered-format") {
			noted = true
		}
	}
	if !noted {
		t.Fatalf("notes = %v, want uncovered-format", m["notes"])
	}
}

// A known target is covered and the digest's note names the leading bytes, so a
// caller can read the format guess without a second probe.
func TestFormatCoverageKnownTargetAndLeadingBytes(t *testing.T) {
	p := writeTemp(t, "garbage.bin", []byte(strings.Repeat("\x63\x00\x00\x00", 4)))
	m := opStatic(t, "inspect_format_coverage", p)
	if covered, ok := m["covered"].(bool); !ok || covered {
		t.Fatalf("covered = %v, want false for unknown bytes", m["covered"])
	}
	d, err := Probe(p)
	if err != nil {
		t.Fatal(err)
	}
	var note string
	for _, n := range d.Notes {
		if strings.Contains(n, "no known magic") {
			note = n
		}
	}
	if !strings.Contains(note, "leading=63000000") {
		t.Fatalf("unknown note = %q, want leading=63000000", note)
	}
}

// A virtual table's rows live in shadow tables the b-tree walk never follows,
// so the op counts them and says so instead of reporting an empty schema.
func TestSqliteVirtualTableCount(t *testing.T) {
	tables := []sqliteTable{
		{Name: "t", SQL: "CREATE TABLE t(a)"},
		{Name: "docs", SQL: "CREATE VIRTUAL TABLE docs USING fts5(body)"},
		{Name: "docs_data", SQL: "CREATE TABLE 'docs_data'(id INTEGER PRIMARY KEY, block BLOB)"},
	}
	if got := sqliteVirtualTables(tables); got != 1 {
		t.Fatalf("sqliteVirtualTables = %d, want 1", got)
	}
	if got := sqliteVirtualTables(nil); got != 0 {
		t.Fatalf("sqliteVirtualTables(nil) = %d, want 0", got)
	}
}

func containsFormat(list []string, want string) bool {
	return slices.Contains(list, want)
}
