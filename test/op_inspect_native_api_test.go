package main

import (
	"encoding/binary"
	"fmt"
	"testing"
)

// TestInspectNativeAPIMarksCutListing: the import table is capped at 100 rows,
// so a binary with more imports than that must say the listing is cut. The
// counts stay honest (imports = whole table, shown = the rows on hand) and the
// gap is marked, because a gap is not a result.
func TestInspectNativeAPIMarksCutListing(t *testing.T) {
	cases := []struct {
		name  string
		path  string
		total int
	}{
		{"elf", nativeAPIDynELF(t, 150), 150},
		{"macho", nativeAPIDynMachO(t, 120), 120},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := nativeAPIAnswer(t, tc.path)
			if m["truncated"] != true {
				t.Fatalf("a cut listing must be marked: %v", m)
			}
			if m["imports"] != tc.total || m["shown"] != 100 {
				t.Fatalf("imports = %v, shown = %v, want %d and 100", m["imports"], m["shown"], tc.total)
			}
		})
	}
}

// TestInspectNativeAPIWholeListingHasNoMarker: a table that fits under the cap
// is the whole table, so the answer must not claim a gap.
func TestInspectNativeAPIWholeListingHasNoMarker(t *testing.T) {
	cases := []struct {
		name string
		path string
	}{
		{"elf", nativeAPIDynELF(t, 5)},
		{"macho", nativeAPIDynMachO(t, 5)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := nativeAPIAnswer(t, tc.path)
			if _, marked := m["truncated"]; marked {
				t.Fatalf("a whole listing must carry no gap marker: %v", m)
			}
			if m["imports"] != 5 || m["shown"] != 5 {
				t.Fatalf("imports = %v, shown = %v, want 5 and 5", m["imports"], m["shown"])
			}
		})
	}
}

// nativeAPIAnswer runs the op and returns its answer map.
func nativeAPIAnswer(t *testing.T, path string) map[string]any {
	t.Helper()
	res, err := runOp("inspect_native_api", path)
	if err != nil {
		t.Fatalf("inspect_native_api: %v", err)
	}
	m, ok := res.(map[string]any)
	if !ok {
		t.Fatalf("answer = %T, want a map", res)
	}
	return m
}

// nativeAPIDynELF writes an ELF64 with n undefined dynamic symbols and returns
// its path. The import table is all the op reads, so a header plus .dynstr and
// .dynsym is enough; no fixture has to ship with the tests.
func nativeAPIDynELF(t *testing.T, n int) string {
	t.Helper()
	le := binary.LittleEndian

	// .dynstr: one NUL-terminated name per imported symbol.
	strtab := []byte{0}
	offsets := make([]uint32, n)
	for i := range offsets {
		offsets[i] = uint32(len(strtab))
		strtab = append(strtab, fmt.Sprintf("sym_%03d", i)...)
		strtab = append(strtab, 0)
	}

	// .dynsym: the null entry the reader skips, then n undefined symbols.
	symtab := make([]byte, 24)
	for _, off := range offsets {
		e := make([]byte, 24)
		le.PutUint32(e[0:], off)
		e[4] = 0x12 // STB_GLOBAL | STT_FUNC
		le.PutUint16(e[6:], 0)
		symtab = append(symtab, e...)
	}

	// .shstrtab: the section names.
	shstr := []byte{0}
	addName := func(s string) uint32 {
		off := uint32(len(shstr))
		shstr = append(shstr, s...)
		shstr = append(shstr, 0)
		return off
	}
	nDynstr := addName(".dynstr")
	nDynsym := addName(".dynsym")
	nShstr := addName(".shstrtab")

	const (
		ehsize    = 64
		shentsize = 64
	)
	dynstrOff := ehsize
	dynsymOff := dynstrOff + len(strtab)
	shstrOff := dynsymOff + len(symtab)
	shoff := (shstrOff + len(shstr) + 7) &^ 7

	b := make([]byte, shoff+4*shentsize)
	copy(b, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0})
	le.PutUint16(b[16:], 3)  // ET_DYN
	le.PutUint16(b[18:], 62) // EM_X86_64
	le.PutUint32(b[20:], 1)  // EV_CURRENT
	le.PutUint64(b[40:], uint64(shoff))
	le.PutUint16(b[52:], ehsize)
	le.PutUint16(b[58:], shentsize)
	le.PutUint16(b[60:], 4) // section headers
	le.PutUint16(b[62:], 3) // .shstrtab

	copy(b[dynstrOff:], strtab)
	copy(b[dynsymOff:], symtab)
	copy(b[shstrOff:], shstr)

	sh := func(i int) []byte { return b[shoff+i*shentsize : shoff+(i+1)*shentsize] }
	s1 := sh(1)
	le.PutUint32(s1[0:], nDynstr)
	le.PutUint32(s1[4:], 3) // SHT_STRTAB
	le.PutUint64(s1[24:], uint64(dynstrOff))
	le.PutUint64(s1[32:], uint64(len(strtab)))
	le.PutUint64(s1[48:], 1)

	s2 := sh(2)
	le.PutUint32(s2[0:], nDynsym)
	le.PutUint32(s2[4:], 11) // SHT_DYNSYM
	le.PutUint64(s2[24:], uint64(dynsymOff))
	le.PutUint64(s2[32:], uint64(len(symtab)))
	le.PutUint32(s2[40:], 1) // .dynstr
	le.PutUint64(s2[48:], 8)
	le.PutUint64(s2[56:], 24)

	s3 := sh(3)
	le.PutUint32(s3[0:], nShstr)
	le.PutUint32(s3[4:], 3) // SHT_STRTAB
	le.PutUint64(s3[24:], uint64(shstrOff))
	le.PutUint64(s3[32:], uint64(len(shstr)))
	le.PutUint64(s3[48:], 1)

	return writeTemp(t, "imports.elf", b)
}

// nativeAPIDynMachO writes a Mach-O 64 with n undefined symbols and returns its
// path. LC_SYMTAB plus LC_DYSYMTAB is the import table dyld reads, so this is
// the format the shipped measurements came from.
func nativeAPIDynMachO(t *testing.T, n int) string {
	t.Helper()
	le := binary.LittleEndian

	// string table: one NUL-terminated name per imported symbol.
	strtab := []byte{0}
	offsets := make([]uint32, n)
	for i := range offsets {
		offsets[i] = uint32(len(strtab))
		strtab = append(strtab, fmt.Sprintf("_sym_%03d", i)...)
		strtab = append(strtab, 0)
	}

	// symbol table: the null symbol, then n undefined ones.
	syms := make([]byte, 16)
	for _, off := range offsets {
		e := make([]byte, 16)
		le.PutUint32(e[0:], off)
		e[4] = 0x01 // N_EXT | N_UNDF
		syms = append(syms, e...)
	}

	const (
		hdrSize     = 32
		symtabCmd   = 24
		dysymtabCmd = 80
	)
	symoff := hdrSize + symtabCmd + dysymtabCmd
	stroff := symoff + len(syms)

	b := make([]byte, stroff+len(strtab))
	le.PutUint32(b[0:], 0xfeedfacf) // MH_MAGIC_64
	le.PutUint32(b[4:], 0x01000007) // x86_64
	le.PutUint32(b[8:], 3)          // SUBTYPE_X86_64_ALL
	le.PutUint32(b[12:], 2)         // MH_EXECUTE
	le.PutUint32(b[16:], 2)         // ncmds
	le.PutUint32(b[20:], symtabCmd+dysymtabCmd)

	// LC_SYMTAB
	le.PutUint32(b[32:], 0x2)
	le.PutUint32(b[36:], symtabCmd)
	le.PutUint32(b[40:], uint32(symoff))
	le.PutUint32(b[44:], uint32(n+1))
	le.PutUint32(b[48:], uint32(stroff))
	le.PutUint32(b[52:], uint32(len(strtab)))

	// LC_DYSYMTAB: symbols 1..n are the undefined ones.
	d := b[56:]
	le.PutUint32(d[0:], 0xb)
	le.PutUint32(d[4:], dysymtabCmd)
	le.PutUint32(d[24:], 1)         // iundefsym
	le.PutUint32(d[28:], uint32(n)) // nundefsym

	copy(b[symoff:], syms)
	copy(b[stroff:], strtab)
	return writeTemp(t, "imports.macho", b)
}
