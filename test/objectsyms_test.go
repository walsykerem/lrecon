package main

import (
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestObjectSymbolLine(t *testing.T) {
	s := objectSymbol{Value: 0x10, Kind: 'T', Name: "_main"}
	if got, want := s.line(), "0000000000000010 T _main"; got != want {
		t.Fatalf("line() = %q, want %q", got, want)
	}
}

// TestElfSymbolKind pins the nm letter for each section/type combination the
// reader can produce, including the two "cannot say" paths (unknown section
// index and undefined symbol).
func TestElfSymbolKind(t *testing.T) {
	text := &elf.Section{SectionHeader: elf.SectionHeader{Name: ".text", Flags: elf.SHF_ALLOC | elf.SHF_EXECINSTR}}
	data := &elf.Section{SectionHeader: elf.SectionHeader{Name: ".data", Flags: elf.SHF_ALLOC | elf.SHF_WRITE}}
	bss := &elf.Section{SectionHeader: elf.SectionHeader{Name: ".bss", Type: elf.SHT_NOBITS, Flags: elf.SHF_ALLOC | elf.SHF_WRITE}}
	rodata := &elf.Section{SectionHeader: elf.SectionHeader{Name: ".rodata", Flags: elf.SHF_ALLOC}}
	f := &elf.File{}
	f.Sections = []*elf.Section{nil, text, data, bss, rodata}

	cases := []struct {
		name string
		sym  elf.Symbol
		want byte
	}{
		{"undefined", elf.Symbol{Section: elf.SHN_UNDEF}, 'U'},
		{"func binds before section lookup", elf.Symbol{Section: 2, Info: byte(elf.STB_GLOBAL)<<4 | byte(elf.STT_FUNC)}, 'T'},
		{"text", elf.Symbol{Section: 1}, 'T'},
		{"data", elf.Symbol{Section: 2}, 'D'},
		{"bss", elf.Symbol{Section: 3}, 'B'},
		{"rodata", elf.Symbol{Section: 4}, 'R'},
		{"section index past table", elf.Symbol{Section: elf.SectionIndex(len(f.Sections))}, '?'},
	}
	for _, tc := range cases {
		if got := elfSymbolKind(f, tc.sym); got != tc.want {
			t.Errorf("%s: elfSymbolKind = %c, want %c", tc.name, got, tc.want)
		}
	}
}

func TestMachoSymbolKind(t *testing.T) {
	f := &macho.File{}
	f.Sections = []*macho.Section{
		{SectionHeader: macho.SectionHeader{Name: "__text", Seg: "__TEXT"}},
		{SectionHeader: macho.SectionHeader{Name: "__const", Seg: "__TEXT"}},
		{SectionHeader: macho.SectionHeader{Name: "__data", Seg: "__DATA"}},
		{SectionHeader: macho.SectionHeader{Name: "__bss", Seg: "__DATA", Flags: 0x1}},
	}

	cases := []struct {
		name string
		sym  macho.Symbol
		want byte
	}{
		{"undefined", macho.Symbol{Sect: 1, Type: 0x0}, 'U'},
		{"no section", macho.Symbol{Sect: 0, Type: 0xf}, '?'},
		{"section past table", macho.Symbol{Sect: uint8(len(f.Sections) + 1), Type: 0xf}, '?'},
		{"text", macho.Symbol{Sect: 1, Type: 0xf}, 'T'},
		{"text const", macho.Symbol{Sect: 2, Type: 0xf}, 'R'},
		{"data", macho.Symbol{Sect: 3, Type: 0xf}, 'D'},
		{"bss", macho.Symbol{Sect: 4, Type: 0xf}, 'B'},
	}
	for _, tc := range cases {
		if got := machoSymbolKind(f, tc.sym); got != tc.want {
			t.Errorf("%s: machoSymbolKind = %c, want %c", tc.name, got, tc.want)
		}
	}
}

func TestPESymbolTable(t *testing.T) {
	f := &pe.File{}
	f.Sections = []*pe.Section{
		{SectionHeader: pe.SectionHeader{Name: ".text", Characteristics: 0x60000020}},
		{SectionHeader: pe.SectionHeader{Name: ".data", Characteristics: 0x40000040}},
	}
	f.Symbols = []*pe.Symbol{
		{Name: "_data", Value: 0x3000, SectionNumber: 2},
		{Name: "_text", Value: 0x1000, SectionNumber: 1},
		{Name: "_undef", Value: 0, SectionNumber: 0},
		{Name: "_past", Value: 0x4000, SectionNumber: 9},
		{Name: "", Value: 0x2000, SectionNumber: 1},
	}

	got := peSymbolTable(f)
	want := []objectSymbol{
		{Value: 0, Kind: 'U', Name: "_undef"},
		{Value: 0x1000, Kind: 'T', Name: "_text"},
		{Value: 0x3000, Kind: 'D', Name: "_data"},
		{Value: 0x4000, Kind: 'D', Name: "_past"},
	}
	if len(got) != len(want) {
		t.Fatalf("peSymbolTable length = %d, want %d (%v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("peSymbolTable[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}
}

// TestObjectSymbolTableDispatch runs the real container detection on tracked
// fixtures and checks the normalised output is sorted and only uses letters
// objectSymbol documents. It reads fixtures rather than the test binary: a
// cached test binary is stripped of .symtab on some builders, and a host
// binary would make this a platform test instead of a dispatch test.
func TestObjectSymbolTableDispatch(t *testing.T) {
	for _, target := range []string{
		"testdata/fixtures/cxx/vtables.o", // ELF
		fixtureMacho,                      // Mach-O
	} {
		syms, err := objectSymbolTable(target)
		if err != nil {
			t.Fatalf("objectSymbolTable(%s): %v", target, err)
		}
		if len(syms) == 0 {
			t.Fatalf("objectSymbolTable(%s) returned no symbols", target)
		}
		if !sort.SliceIsSorted(syms, func(i, j int) bool { return syms[i].Value < syms[j].Value }) {
			t.Fatalf("%s: symbol table is not sorted by value", target)
		}
		for _, s := range syms {
			if !strings.ContainsRune("TDBRU?", rune(s.Kind)) {
				t.Fatalf("%s: %s has unexpected kind %q", target, s.Name, s.Kind)
			}
		}
	}

	dir := t.TempDir()
	// An empty file cannot even be sniffed (objdumpFormat returns ""), which is
	// the one path that produces objectSymbolTable's own refusal rather than a
	// parser error.
	stub := filepath.Join(dir, "stub.bin")
	if err := os.WriteFile(stub, nil, 0o600); err != nil {
		t.Fatalf("write stub: %v", err)
	}
	if _, err := objectSymbolTable(stub); err == nil || !strings.Contains(err.Error(), "not an object file lrecon can read") {
		t.Fatalf("objectSymbolTable(stub) error = %v, want the not-an-object-file refusal", err)
	}
	// Junk with a full magic-byte window sniffs as macho and fails in the
	// parser, which is still a refusal: it must not return symbols.
	junk := filepath.Join(dir, "junk.bin")
	if err := os.WriteFile(junk, []byte("not an object file"), 0o600); err != nil {
		t.Fatalf("write junk: %v", err)
	}
	if syms, err := objectSymbolTable(junk); err == nil || len(syms) != 0 {
		t.Fatalf("objectSymbolTable(junk) = %v, %v; want an error and no symbols", syms, err)
	}
}

// TestObjectSymbolTableTruncatedReadsAsIO: a cut object file must fail as a
// read failure, not as an internal error. The parser error text is what
// errors.go classifies, so it has to say the file could not be read.
func TestObjectSymbolTableTruncatedReadsAsIO(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		name string
		head []byte
	}{
		{"elf", []byte("\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00")},
		{"macho", []byte{0xcf, 0xfa, 0xed, 0xfe, 0x0c, 0x00, 0x00, 0x01}},
		{"pe", []byte("MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00")},
	}
	for _, c := range cases {
		path := filepath.Join(dir, c.name)
		if err := os.WriteFile(path, c.head, 0o600); err != nil {
			t.Fatalf("write %s fixture: %v", c.name, err)
		}
		syms, err := objectSymbolTable(path)
		if err == nil || len(syms) != 0 {
			t.Fatalf("objectSymbolTable(%s) = %v, %v; want an error and no symbols", c.name, syms, err)
		}
		if !strings.Contains(err.Error(), "cannot read") {
			t.Fatalf("objectSymbolTable(%s) error = %q, want it to name a read failure so the CLI answers io, not internal", c.name, err)
		}
	}
}
