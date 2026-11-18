package main

import (
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Budgets for the three parts. The whole point of this op is a cheap,
// external-tool-free first look, so every part is a short digest, not a dump.
const (
	objdumpCap    = 64 << 10
	objdumpSymCap = 128 << 10
)

// objdumpPart is one section of the answer. Name is the user-facing label and
// stays stable across formats so callers can index by it.
type objdumpPart struct {
	Name      string `json:"name"`
	Args      string `json:"args"`
	Output    string `json:"output"`
	Truncated bool   `json:"truncated,omitempty"`
}

type objdumpResult struct {
	Tool      string        `json:"tool"`
	Args      []string      `json:"args,omitempty"`
	Output    string        `json:"output,omitempty"`
	Truncated bool          `json:"truncated,omitempty"`
	Format    string        `json:"format"`
	Parts     []objdumpPart `json:"parts"`
	Note      string        `json:"note,omitempty"`
}

func init() {
	registerOp(op{
		name:  "inspect_with_objdump",
		route: "L",
		needs: true,
		desc:  "read the section table and symbol table of an ELF, PE, Mach-O or archive file with the Go standard library (no objdump, nm, otool or llvm-objdump on the host)",
		run:   opInspectWithObjdump,
	})
}

// objdumpFormat sniffs the container from magic bytes so a target with the
// wrong extension still parses.
func objdumpFormat(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	var h [8]byte
	if _, err := f.Read(h[:]); err != nil {
		return ""
	}
	switch {
	case h[0] == 0x7f && h[1] == 'E' && h[2] == 'L' && h[3] == 'F':
		return "elf"
	case (h[0] == 'M' && h[1] == 'Z') || (h[0] == 'P' && h[1] == 'E' && h[2] == 0 && h[3] == 0):
		return "pe"
	case h[0] == '!' && h[1] == '<' && h[2] == 'a' && h[3] == 'r' && h[4] == 'c' && h[5] == 'h':
		return "archive"
	}
	return "macho"
}

func opInspectWithObjdump(path string) (any, error) {
	format := objdumpFormat(path)
	if format == "" {
		return nil, fmt.Errorf("%s: cannot read file header", path)
	}
	res := objdumpResult{Format: format, Tool: "go:debug/" + format}
	switch format {
	case "elf":
		f, err := elf.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		res.Parts = []objdumpPart{
			newPart("sections", "debug/elf.Sections", elfSectionsText(f), objdumpCap),
			newPart("symbols", "debug/elf.Symbols", elfSymbolsText(f), objdumpSymCap),
			disasmNote(),
		}
		res.Output = res.Parts[0].Output
	case "pe":
		f, err := pe.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		res.Parts = []objdumpPart{
			newPart("sections", "debug/pe.Sections", peSectionsText(f), objdumpCap),
			newPart("symbols", "debug/pe.Symbols", peSymbolsText(f), objdumpSymCap),
			disasmNote(),
		}
		res.Output = res.Parts[0].Output
	case "archive":
		out, err := archiveMembers(path)
		if err != nil {
			return nil, err
		}
		res.Parts = []objdumpPart{
			newPart("members", "ar header scan", out, objdumpCap),
			disasmNote(),
		}
		res.Output = res.Parts[0].Output
	default:
		f, err := macho.Open(path)
		fat := false
		if err != nil {
			ff, ferr := macho.OpenFat(path)
			if ferr != nil {
				return nil, fmt.Errorf("%s: neither a Mach-O file (%v) nor a fat Mach-O archive (%v)", path, err, ferr)
			}
			defer ff.Close()
			if len(ff.Arches) == 0 {
				return nil, fmt.Errorf("%s: fat Mach-O archive carries no architecture", path)
			}
			f = ff.Arches[0].File
			fat = true
		} else {
			defer f.Close()
		}
		res.Parts = []objdumpPart{
			newPart("header", "debug/macho.FileHeader", machoHeaderText(f, fat), objdumpCap),
			newPart("sections", "debug/macho.Sections", machoSectionsText(f), objdumpCap),
			newPart("dylibs", "debug/macho.Load(LC_LOAD_DYLIB)", machoDylibsText(f), objdumpCap),
			newPart("symbols", "debug/macho.Symtab", machoSymbolsText(f), objdumpSymCap),
			disasmNote(),
		}
		res.Output = strings.Join([]string{res.Parts[0].Output, res.Parts[2].Output}, "\n")
	}
	res.Note = "pure Go, no external tool; instructions are not listed here — the analyzeHeadless ops decompile and disassemble"
	return res, nil
}

func newPart(name, args, out string, limit int) objdumpPart {
	text, cut := cutUTF8(out, limit)
	return objdumpPart{Name: name, Args: args, Output: text, Truncated: cut}
}

func disasmNote() objdumpPart {
	return objdumpPart{
		Name:   "disassembly",
		Args:   "analyzeHeadless",
		Output: "not produced by this op: instructions need a decompiler, use a Ghidra-backed op",
	}
}

func elfSectionsText(f *elf.File) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%3s %-20s %-10s %-8s %016s %08s %08s %s\n", "Idx", "Name", "Type", "Flags", "Addr", "Off", "Size", "Align")
	for i, s := range f.Sections {
		fmt.Fprintf(&b, "%3d %-20s %-10v %-8s %016x %08x %08x %#x\n",
			i, s.Name, s.Type, elfFlagText(s.Flags), s.Addr, s.Offset, s.Size, s.Addralign)
	}
	return b.String()
}

func elfFlagText(fl elf.SectionFlag) string {
	var out []string
	if fl&elf.SHF_ALLOC != 0 {
		out = append(out, "A")
	}
	if fl&elf.SHF_WRITE != 0 {
		out = append(out, "W")
	}
	if fl&elf.SHF_EXECINSTR != 0 {
		out = append(out, "X")
	}
	if fl&elf.SHF_TLS != 0 {
		out = append(out, "T")
	}
	if len(out) == 0 {
		return "-"
	}
	return strings.Join(out, "")
}

func elfSymbolsText(f *elf.File) string {
	return symbolsText(elfSymbolTable(f), "%016x %c %s\n")
}

func peSectionsText(f *pe.File) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%-8s %08s %08s %08s %08s %s\n", "Name", "VSize", "VAddr", "RawSize", "RawPtr", "Flags")
	for _, s := range f.Sections {
		fmt.Fprintf(&b, "%-8s %08x %08x %08x %08x %08x\n",
			s.Name, s.VirtualSize, s.VirtualAddress, s.Size, s.Offset, s.Characteristics)
	}
	return b.String()
}

func peSymbolsText(f *pe.File) string {
	return symbolsText(peSymbolTable(f), "%016x %c %s\n")
}

func symbolsText(syms []objectSymbol, format string) string {
	var b strings.Builder
	for _, s := range syms {
		fmt.Fprintf(&b, format, s.Value, s.Kind, s.Name)
	}
	if b.Len() == 0 {
		return "(no symbol table: stripped, or the format stores none here)"
	}
	return b.String()
}

func machoHeaderText(f *macho.File, fat bool) string {
	var b strings.Builder
	note := ""
	if fat {
		note = " (first slice of a fat/universal file)"
	}
	fmt.Fprintf(&b, "Mach header%s\n", note)
	fmt.Fprintf(&b, "%12s %10s %10s %10s\n", "magic", "cputype", "filetype", "ncmds")
	fmt.Fprintf(&b, "%#12x %10d %10v %10d\n", f.Magic, f.Cpu, f.Type, f.Ncmd)
	fmt.Fprintf(&b, "%10s=%d %12s=%#x\n", "sizeofcmds", f.Cmdsz, "flags", f.Flags)
	return b.String()
}

func machoSectionsText(f *macho.File) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%-20s %-8s %016s %016s %08s %s\n", "Sect", "Seg", "Addr", "Size", "Off", "Flags")
	for _, s := range f.Sections {
		fmt.Fprintf(&b, "%-20s %-8s %016x %016x %08x %08x\n", s.Name, s.Seg, s.Addr, s.Size, s.Offset, s.Flags)
	}
	return b.String()
}

func machoDylibsText(f *macho.File) string {
	var b strings.Builder
	for _, l := range f.Loads {
		if d, ok := l.(*macho.Dylib); ok {
			fmt.Fprintf(&b, "%s (compat %d, current %d)\n", d.Name, d.CompatVersion, d.CurrentVersion)
		}
	}
	if b.Len() == 0 {
		return "(statically linked: no LC_LOAD_DYLIB)"
	}
	return b.String()
}

func machoSymbolsText(f *macho.File) string {
	return symbolsText(machoFileSymbolTable(f), "%016x %c %s\n")
}

// archiveMembers lists the members of a Unix ar archive (the Objective-C
// static-library shape) without linking anything.
func archiveMembers(path string) (string, error) {
	raw, err := opRead(path, opMaxFile)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	off := 8 // "!<arch>\n"
	for off+60 <= len(raw) {
		hdr := raw[off : off+60]
		if string(hdr[58:60]) != "`\n" {
			break
		}
		name := strings.TrimSpace(string(hdr[0:16]))
		name = strings.TrimSuffix(name, "/")
		size, err := strconv.ParseInt(strings.TrimSpace(string(hdr[48:58])), 10, 64)
		if err != nil {
			break
		}
		// BSD ar (what ld and Xcode write) stores a long name as "#1/<n>": the
		// name itself is the first n bytes of the member data and the header
		// size counts it in. Reporting "#1/20" as the member name is not a name.
		shown := size
		if strings.HasPrefix(name, "#1/") {
			n, err := strconv.ParseInt(name[3:], 10, 64)
			if err != nil || n <= 0 || n > size {
				break
			}
			if off+60+int(n) > len(raw) {
				break
			}
			name = strings.TrimRight(string(raw[off+60:off+60+int(n)]), "\x00")
			shown = size - n
		}
		if name != "" && name != "/" && name != "//" {
			fmt.Fprintf(&b, "%-40s %d bytes\n", name, shown)
		}
		off += 60 + int(size)
		if off%2 == 1 {
			off++
		}
	}
	if b.Len() == 0 {
		return "(no members)", nil
	}
	return b.String(), nil
}
