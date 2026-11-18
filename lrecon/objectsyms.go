package main

import (
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"fmt"
	"sort"
)

// objectSymbol is one symbol table entry, normalised across the three object
// formats lrecon reads. It exists so that nothing in the tree has to shell out
// to nm: the standard library parses all three tables and the mapping to an
// nm-style letter is the only thing nm added.
type objectSymbol struct {
	Value uint64
	Kind  byte // nm letter: T text, D data, B bss, R readonly, U undefined
	Name  string
}

func (s objectSymbol) line() string {
	return fmt.Sprintf("%016x %c %s", s.Value, s.Kind, s.Name)
}

// objectSymbolTable reads the symbol table of path, detecting the container
// from its magic bytes so a misnamed target still works.
func objectSymbolTable(path string) ([]objectSymbol, error) {
	switch objdumpFormat(path) {
	case "elf":
		f, err := elf.Open(path)
		if err != nil {
			return nil, fmt.Errorf("%s: cannot read elf symbols: %w", path, err)
		}
		defer f.Close()
		return elfSymbolTable(f), nil
	case "macho":
		f, err := macho.Open(path)
		if err != nil {
			// A fat binary has several slices: the first one is the host slice on
			// every target we run on, and the symbol table of a fat file is not
			// reachable through debug/macho at all.
			ff, ferr := macho.OpenFat(path)
			if ferr != nil {
				return nil, fmt.Errorf("%s: cannot read macho symbols: %v (fat fallback: %v)", path, err, ferr)
			}
			defer ff.Close()
			if len(ff.Arches) == 0 {
				return nil, fmt.Errorf("%s: cannot read macho symbols: fat image holds no slices", path)
			}
			return machoFileSymbolTable(ff.Arches[0].File), nil
		}
		defer f.Close()
		return machoFileSymbolTable(f), nil
	case "pe":
		f, err := pe.Open(path)
		if err != nil {
			return nil, fmt.Errorf("%s: cannot read pe symbols: %w", path, err)
		}
		defer f.Close()
		return peSymbolTable(f), nil
	}
	return nil, fmt.Errorf("%s: not an object file lrecon can read", path)
}

func elfSymbolTable(f *elf.File) []objectSymbol {
	syms, err := f.Symbols()
	if err != nil {
		return nil
	}
	out := make([]objectSymbol, 0, len(syms))
	for _, s := range syms {
		if s.Name == "" {
			continue
		}
		out = append(out, objectSymbol{Value: s.Value, Kind: elfSymbolKind(f, s), Name: s.Name})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Value < out[j].Value })
	return out
}

func elfSymbolKind(f *elf.File, s elf.Symbol) byte {
	if s.Section == elf.SHN_UNDEF {
		return 'U'
	}
	if elf.ST_TYPE(s.Info) == elf.STT_FUNC {
		return 'T'
	}
	var sec *elf.Section
	if int(s.Section) < len(f.Sections) {
		sec = f.Sections[s.Section]
	}
	if sec == nil {
		return '?'
	}
	w := sec.Flags&elf.SHF_WRITE != 0
	switch {
	case sec.Type == elf.SHT_NOBITS && w:
		return 'B'
	case sec.Flags&elf.SHF_EXECINSTR != 0:
		return 'T'
	case w:
		return 'D'
	default:
		return 'R'
	}
}

func machoFileSymbolTable(f *macho.File) []objectSymbol {
	if f.Symtab == nil {
		return nil
	}
	out := make([]objectSymbol, 0, len(f.Symtab.Syms))
	for _, s := range f.Symtab.Syms {
		if s.Name == "" {
			continue
		}
		out = append(out, objectSymbol{Value: s.Value, Kind: machoSymbolKind(f, s), Name: s.Name})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Value < out[j].Value })
	return out
}

func machoSymbolKind(f *macho.File, s macho.Symbol) byte {
	if s.Type&0x0e == 0 { // N_UNDF
		return 'U'
	}
	if int(s.Sect) == 0 || int(s.Sect) > len(f.Sections) {
		return '?'
	}
	sec := f.Sections[s.Sect-1]
	switch {
	case sec.Name == "__bss" || sec.Flags&0xff == 0x1:
		return 'B'
	case sec.Seg == "__TEXT" && sec.Name == "__text":
		return 'T'
	case sec.Seg == "__TEXT":
		return 'R'
	default:
		return 'D'
	}
}

func peSymbolTable(f *pe.File) []objectSymbol {
	out := make([]objectSymbol, 0, len(f.Symbols))
	for _, s := range f.Symbols {
		if s.Name == "" {
			continue
		}
		kind := byte('D')
		if s.SectionNumber <= 0 {
			kind = 'U'
		} else if int(s.SectionNumber) <= len(f.Sections) {
			sec := f.Sections[s.SectionNumber-1]
			if sec.Characteristics&0x20000000 != 0 { // IMAGE_SCN_MEM_EXECUTE
				kind = 'T'
			}
		}
		out = append(out, objectSymbol{Value: uint64(s.Value), Kind: kind, Name: s.Name})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Value < out[j].Value })
	return out
}
