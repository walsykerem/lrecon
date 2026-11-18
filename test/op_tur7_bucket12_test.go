package main

// Tur 7 bucket 12: address arithmetic, proven against an independent read of
// the target's own Mach-O load commands.
//
// Every expected number here is derived by parsing the file's bytes in this
// test (mach_header_64, LC_SEGMENT_64 section tables, LC_SYMTAB nlist_64).
// Nothing is taken from nativeSections/nativeFunctions, so an off-by-one in
// lrecon's mapping, or a constant answer, cannot satisfy these assertions.

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

type tur7b12Section struct {
	name string
	addr uint64
	size uint64
	off  uint64
}

type tur7b12Segment struct {
	name     string
	addr     uint64
	filesize uint64
}

type tur7b12MachO struct {
	sections []tur7b12Section
	segments []tur7b12Segment
	starts   []uint64            // sorted, deduplicated function starts from LC_SYMTAB
	names    map[uint64][]string // start -> symbol names (leading "_" kept)
}

func tur7b12Hex(v uint64) string { return fmt.Sprintf("0x%x", v) }

// independentMachO parses only what the load commands say. It fails, not
// skips, when the target is not the thin little-endian 64-bit image this
// parser understands: the point of the test is the bytes, not a fallback.
func independentMachO(t *testing.T, path string) tur7b12MachO {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read target %s: %v", path, err)
	}
	le := binary.LittleEndian
	if len(b) < 32 {
		t.Fatalf("%s: %d bytes, shorter than a mach_header_64", path, len(b))
	}
	if magic := le.Uint32(b[0:]); magic != 0xfeedfacf {
		t.Fatalf("%s: magic %#x is not MH_MAGIC_64 (thin little-endian); this test parses the load commands itself", path, magic)
	}
	ncmds := le.Uint32(b[16:])
	sizeofcmds := le.Uint32(b[20:])
	if 32+uint64(sizeofcmds) > uint64(len(b)) {
		t.Fatalf("%s: sizeofcmds %d overruns the %d-byte file", path, sizeofcmds, len(b))
	}

	var out tur7b12MachO
	out.names = map[uint64][]string{}
	var symoff, nsyms, stroff uint32
	var haveSymtab bool

	off := uint64(32)
	for i := uint32(0); i < ncmds; i++ {
		if off+8 > uint64(len(b)) {
			t.Fatalf("%s: load command %d starts past EOF at %#x", path, i, off)
		}
		cmd := le.Uint32(b[off:])
		cmdsize := le.Uint32(b[off+4:])
		if cmdsize < 8 || off+uint64(cmdsize) > uint64(len(b)) {
			t.Fatalf("%s: load command %d has cmdsize %d at %#x", path, i, cmdsize, off)
		}
		switch cmd {
		case 0x19: // LC_SEGMENT_64
			if cmdsize < 72 {
				t.Fatalf("%s: LC_SEGMENT_64 at %#x is %d bytes", path, off, cmdsize)
			}
			name := tur7b12CString(b[off+8 : off+24])
			vmaddr := le.Uint64(b[off+24:])
			fileoff := le.Uint64(b[off+40:])
			filesize := le.Uint64(b[off+48:])
			nsects := le.Uint32(b[off+64:])
			if fileoff != 0 || filesize != 0 {
				out.segments = append(out.segments, tur7b12Segment{name: name, addr: vmaddr, filesize: filesize})
			}
			for s := uint32(0); s < nsects; s++ {
				so := off + 72 + uint64(s)*80
				if so+80 > uint64(len(b)) {
					t.Fatalf("%s: section %d of %s starts past EOF", path, s, name)
				}
				sec := tur7b12Section{
					name: tur7b12CString(b[so : so+16]),
					addr: le.Uint64(b[so+32:]),
					size: le.Uint64(b[so+40:]),
					off:  uint64(le.Uint32(b[so+48:])),
				}
				if sec.size == 0 || sec.off == 0 {
					continue // not file-backed: nativeSections drops these too
				}
				// __DWARF ships vmsize 0 with real section addresses, so the
				// section table, not the segment extent, is authoritative here.
				out.sections = append(out.sections, sec)
			}
		case 0x2: // LC_SYMTAB
			symoff = le.Uint32(b[off+8:])
			nsyms = le.Uint32(b[off+12:])
			stroff = le.Uint32(b[off+16:])
			haveSymtab = true
		}
		off += uint64(cmdsize)
	}
	if !haveSymtab || nsyms == 0 {
		t.Fatalf("%s: no LC_SYMTAB, so there is no second source for function starts", path)
	}
	if uint64(symoff)+uint64(nsyms)*16 > uint64(len(b)) || uint64(stroff) > uint64(len(b)) {
		t.Fatalf("%s: LC_SYMTAB (symoff=%d nsyms=%d stroff=%d) overruns the file", path, symoff, nsyms, stroff)
	}
	for i := uint32(0); i < nsyms; i++ {
		no := uint64(symoff) + uint64(i)*16
		strx := le.Uint32(b[no:])
		typ := b[no+4]
		sect := b[no+5]
		val := le.Uint64(b[no+8:])
		if typ&0x0e != 0x0e || sect == 0 || val == 0 { // only defined N_SECT symbols
			continue
		}
		if sec := tur7b12SectionAt(out.sections, val); sec == nil || sec.name != "__text" {
			continue
		}
		start := uint64(stroff) + uint64(strx)
		if start >= uint64(len(b)) {
			continue
		}
		out.names[val] = append(out.names[val], tur7b12CString(b[start:]))
	}
	for v := range out.names {
		out.starts = append(out.starts, v)
	}
	sort.Slice(out.starts, func(i, j int) bool { return out.starts[i] < out.starts[j] })
	if len(out.starts) < 8 {
		t.Fatalf("%s: only %d text symbols in LC_SYMTAB", path, len(out.starts))
	}
	return out
}

func tur7b12CString(b []byte) string {
	if i := strings.IndexByte(string(b), 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

func tur7b12SectionAt(secs []tur7b12Section, addr uint64) *tur7b12Section {
	for i := range secs {
		if addr >= secs[i].addr && addr < secs[i].addr+secs[i].size {
			return &secs[i]
		}
	}
	return nil
}

// expectedWhere mirrors the tool's own order (sections, then segments) using
// only the numbers this test parsed, and reports the name an answer must use.
func (m tur7b12MachO) expectedWhere(addr uint64) (mapping, name string, base uint64) {
	if s := tur7b12SectionAt(m.sections, addr); s != nil {
		seg := "__TEXT"
		for _, g := range m.segments {
			if addr >= g.addr && addr < g.addr+g.filesize {
				seg = g.name
				break
			}
		}
		return "section", seg + "," + s.name, s.addr
	}
	for _, g := range m.segments {
		if addr >= g.addr && addr < g.addr+g.filesize {
			return "segment", g.name, g.addr
		}
	}
	return "", "", 0
}

func tur7b12Norm(name string) string { return strings.TrimPrefix(name, "_") }

func tur7b12MustOp(t *testing.T, name, target string) map[string]any {
	t.Helper()
	res, err := runOp(name, target)
	if err != nil {
		t.Fatalf("%s(%s): %v", name, target, err)
	}
	m, ok := res.(map[string]any)
	if !ok {
		t.Fatalf("%s: result is %T, not an object", name, res)
	}
	return m
}

func TestTur7Bucket12AddressArithmetic(t *testing.T) {
	target, err := filepath.Abs(filepath.Join("..", "env", "old-lrecon-binary-0.1.5"))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("LRECON_STATE", t.TempDir())
	t.Setenv("LRECON_SESSION", "")

	macho := independentMachO(t, target)

	var text, rodata *tur7b12Section
	var textSeg *tur7b12Segment
	for i := range macho.sections {
		s := &macho.sections[i]
		if s.name == "__text" && text == nil {
			text = s
		}
		if s.name == "__rodata" && rodata == nil {
			rodata = s
		}
	}
	for i := range macho.segments {
		if macho.segments[i].name == "__TEXT" {
			textSeg = &macho.segments[i]
		}
	}
	if text == nil || rodata == nil || textSeg == nil {
		t.Fatalf("%s: load commands lack __TEXT,__text / __TEXT,__rodata / __TEXT", target)
	}
	if text.off+text.size > uint64(1)<<40 {
		t.Fatalf("implausible __text offset/size %#x/%#x", text.off, text.size)
	}

	// A mid-table function start whose name is unambiguous, so "procedure"
	// has exactly one correct answer from the symbol table.
	idx := -1
	for i := len(macho.starts) / 2; i < len(macho.starts)-3; i++ {
		if len(macho.names[macho.starts[i]]) == 1 && macho.starts[i+1]-macho.starts[i] > 4 {
			idx = i
			break
		}
	}
	if idx < 0 {
		t.Fatalf("%s: no unique mid-table text symbol with room for a successor", target)
	}
	f0 := macho.starts[idx]
	f1 := macho.starts[idx+1]
	f2 := macho.starts[idx+2]
	at := f0 + 1
	wantProc := tur7b12Norm(macho.names[f0][0])

	t.Run("goto_lands_on_the_parsed_section", func(t *testing.T) {
		t.Setenv("LRECON_AT", tur7b12Hex(at))
		m := tur7b12MustOp(t, "goto_address", target)
		if got := m["document"]; got != target {
			t.Fatalf("document = %v, want %s", got, target)
		}
		if got := m["project"]; got != filepath.Base(filepath.Dir(target)) {
			t.Fatalf("project = %v, want %s", got, filepath.Base(filepath.Dir(target)))
		}
		if got := m["address"]; got != tur7b12Hex(at) {
			t.Fatalf("address = %v, want %s (echo must be the request, not a rounded value)", got, tur7b12Hex(at))
		}
		mapping, name, base := macho.expectedWhere(at)
		if got := m["mapping"]; got != mapping {
			t.Fatalf("mapping = %v, want %s from the load commands", got, mapping)
		}
		if got := m["section"]; got != name {
			t.Fatalf("section = %v, want %s at %s", got, name, tur7b12Hex(at))
		}
		if got := m["section_address"]; got != tur7b12Hex(base) {
			t.Fatalf("section_address = %v, want %s (__text starts there per LC_SEGMENT_64)", got, tur7b12Hex(base))
		}
		if got := m["procedure"]; got != wantProc {
			t.Fatalf("procedure = %v, want %q from LC_SYMTAB n_value %s", got, wantProc, tur7b12Hex(f0))
		}
		sessionPath, _ := m["session"].(string)
		if st, err := os.Stat(sessionPath); sessionPath == "" || err != nil || st.Size() == 0 {
			t.Fatalf("session = %q (stat err %v): goto_address must persist the cursor", sessionPath, err)
		}
	})

	t.Run("section_bounds_are_half_open", func(t *testing.T) {
		end := text.addr + text.size
		t.Setenv("LRECON_AT", tur7b12Hex(end-1))
		last := tur7b12MustOp(t, "goto_address", target)
		if last["section"] != "__TEXT,__text" || last["mapping"] != "section" ||
			last["section_address"] != tur7b12Hex(text.addr) {
			t.Fatalf("goto(last byte %s) = section %v mapping %v base %v, want __TEXT,__text/section/%s",
				tur7b12Hex(end-1), last["section"], last["mapping"], last["section_address"], tur7b12Hex(text.addr))
		}

		// First address the section does not own: the load commands place the
		// next stop past it, so only a <= comparison would still say __text.
		mapping, name, base := macho.expectedWhere(end)
		if mapping == "section" && name == "__TEXT,__text" {
			t.Fatalf("fixture assumption broken: %s is still __text by the headers", tur7b12Hex(end))
		}
		t.Setenv("LRECON_AT", tur7b12Hex(end))
		next := tur7b12MustOp(t, "goto_address", target)
		if next["section"] != name || next["mapping"] != mapping || next["section_address"] != tur7b12Hex(base) {
			t.Fatalf("goto(%s) = section %v mapping %v base %v, want %s/%s/%s",
				tur7b12Hex(end), next["section"], next["mapping"], next["section_address"], name, mapping, tur7b12Hex(base))
		}
	})

	t.Run("a_different_section_reports_its_own_base", func(t *testing.T) {
		probe := rodata.addr + 0x10
		want := "__TEXT,__rodata"
		if got := macho.expectedWhereName(probe); got != want {
			t.Fatalf("fixture assumption broken: headers put %s in %s, want %s", tur7b12Hex(probe), got, want)
		}
		t.Setenv("LRECON_AT", tur7b12Hex(probe))
		m := tur7b12MustOp(t, "goto_address", target)
		if m["section"] != want || m["section_address"] != tur7b12Hex(rodata.addr) || m["mapping"] != "section" {
			t.Fatalf("goto(%s) = %v/%v/%v, want %s/section/%s", tur7b12Hex(probe),
				m["section"], m["mapping"], m["section_address"], want, tur7b12Hex(rodata.addr))
		}
	})

	t.Run("next_and_prev_walk_the_symbol_table", func(t *testing.T) {
		t.Setenv("LRECON_AT", tur7b12Hex(at))
		g := tur7b12MustOp(t, "goto_address", target)
		if g["procedure"] != wantProc {
			t.Fatalf("goto procedure = %v, want %q", g["procedure"], wantProc)
		}

		step := func(op string, from, wantTo uint64) map[string]any {
			m := tur7b12MustOp(t, op, target)
			if m["found"] != true {
				t.Fatalf("%s from %s: found=%v, want a step", op, tur7b12Hex(from), m["found"])
			}
			if m["from"] != tur7b12Hex(from) {
				t.Fatalf("%s: from = %v, want the live cursor %s", op, m["from"], tur7b12Hex(from))
			}
			if m["to"] != tur7b12Hex(wantTo) {
				t.Fatalf("%s from %s: to = %v, want %s (next n_value in LC_SYMTAB)",
					op, tur7b12Hex(from), m["to"], tur7b12Hex(wantTo))
			}
			return m
		}
		n1 := step("next_address", at, f1)
		if n1["procedure"] != tur7b12Norm(macho.names[f1][0]) {
			t.Fatalf("next_address procedure = %v, want %q", n1["procedure"], tur7b12Norm(macho.names[f1][0]))
		}
		n2 := step("next_address", f1, f2)
		if end, ok := n2["end"].(string); !ok || end == "" || end == tur7b12Hex(f2) {
			t.Fatalf("next_address end = %v, want a range end past its start", n2["end"])
		}
		step("prev_address", f2, f1)
		step("prev_address", f1, f0)
	})

	t.Run("file_offset_equals_the_load_command_mapping", func(t *testing.T) {
		for _, addr := range []uint64{at, f1, f2} {
			wantOff := text.off + (addr - text.addr) // section fileoff + delta
			if got := macho.fileOffsetOf(t, addr); got != wantOff {
				t.Fatalf("independent mapping of %s = %d, want %d", tur7b12Hex(addr), got, wantOff)
			}
			t.Setenv("LRECON_AT", tur7b12Hex(addr))
			t.Setenv("LRECON_LEN", "32")
			m := tur7b12MustOp(t, "read_bytes", target)
			if m["file_offset"] != wantOff {
				t.Fatalf("read_bytes(%s) file_offset = %v, want %d (section __text fileoff %d + %#x)",
					tur7b12Hex(addr), m["file_offset"], wantOff, text.off, addr-text.addr)
			}
			if m["mapping"] != "section" || m["section"] != "__TEXT,__text" {
				t.Fatalf("read_bytes(%s) = %v/%v, want section/__TEXT,__text", tur7b12Hex(addr), m["mapping"], m["section"])
			}
			if m["length"] != 32 || m["truncated"] != false {
				t.Fatalf("read_bytes(%s) length = %v truncated = %v, want 32/false", tur7b12Hex(addr), m["length"], m["truncated"])
			}
			raw, err := os.ReadFile(target)
			if err != nil {
				t.Fatal(err)
			}
			want := raw[wantOff : wantOff+8]
			line := fmt.Sprintf("%02x %02x %02x %02x %02x %02x %02x %02x",
				want[0], want[1], want[2], want[3], want[4], want[5], want[6], want[7])
			if hex, _ := m["hex"].(string); !strings.Contains(hex, line) {
				t.Fatalf("read_bytes(%s) hex lacks %q: %q", tur7b12Hex(addr), line, hex)
			}
		}
	})

	t.Run("address_outside_every_mapping_is_refused", func(t *testing.T) {
		beyond := uint64(0)
		for _, s := range macho.sections {
			if end := s.addr + s.size; end > beyond {
				beyond = end
			}
		}
		for _, g := range macho.segments {
			if end := g.addr + g.filesize; end > beyond {
				beyond = end
			}
		}
		t.Setenv("LRECON_AT", tur7b12Hex(beyond))
		_, err := runOp("goto_address", target)
		if err == nil || !strings.Contains(err.Error(), "is not inside any file-backed section or segment") {
			t.Fatalf("goto_address(%s) = %v, want the out-of-mapping refusal", tur7b12Hex(beyond), err)
		}
	})
}

func (m tur7b12MachO) expectedWhereName(addr uint64) string {
	_, name, _ := m.expectedWhere(addr)
	return name
}

func (m tur7b12MachO) fileOffsetOf(t *testing.T, addr uint64) uint64 {
	t.Helper()
	if s := tur7b12SectionAt(m.sections, addr); s != nil {
		return s.off + (addr - s.addr)
	}
	t.Fatalf("%s is not in any file-backed section", tur7b12Hex(addr))
	return 0
}
