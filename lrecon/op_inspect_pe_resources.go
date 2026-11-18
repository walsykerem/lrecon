package main

import "slices"

import "fmt"

// A .rsrc section is an IMAGE_RESOURCE_DIRECTORY (16-byte header plus 8-byte
// entries) three levels deep: type, name, language. Only the leaf level points
// at an IMAGE_RESOURCE_DATA_ENTRY, which holds the real data RVA and size.

const (
	peResMaxEntries = 1 << 14
	peResMaxLeaves  = 1 << 16
	peResMaxName    = 512
)

var peResKindNames = map[uint32]string{
	1: "CURSOR", 2: "BITMAP", 3: "ICON", 4: "MENU", 5: "DIALOG", 6: "STRING",
	7: "FONTDIR", 8: "FONT", 9: "ACCELERATOR", 10: "RCDATA", 11: "MESSAGETABLE",
	12: "GROUP_CURSOR", 14: "GROUP_ICON", 16: "VERSION", 17: "DLGINCLUDE",
	19: "PLUGPLAY", 20: "VXD", 21: "ANICURSOR", 22: "ANIICON", 23: "HTML", 24: "MANIFEST",
}

type peResLanguage struct {
	Language   uint32 `json:"language"`
	Name       string `json:"name,omitempty"`
	DataRVA    uint32 `json:"data_rva"`
	FileOffset uint64 `json:"file_offset"`
	Size       uint32 `json:"size"`
	CodePage   uint32 `json:"codepage"`
}

type peResNameEntry struct {
	ID        uint32          `json:"id"`
	Name      string          `json:"name,omitempty"`
	Languages []peResLanguage `json:"languages"`
}

type peResTypeEntry struct {
	ID      uint32           `json:"id"`
	Name    string           `json:"name,omitempty"`
	Kind    string           `json:"kind"`
	Entries []peResNameEntry `json:"entries"`
}

type peResTree struct {
	section string
	types   []peResTypeEntry
	leaves  int
	chain   []uint32 // ancestor rels; the tree is three levels deep, so this stays tiny
}

func init() {
	registerOp(op{
		name:  "inspect_pe_resources",
		route: "L",
		needs: true,
		desc:  "PE .rsrc tree: every type/name/language leaf with its IMAGE_RESOURCE_DATA_ENTRY RVA, file offset, size and codepage",
		run: func(path string) (any, error) {
			b, err := opRead(path, opMaxFile)
			if err != nil {
				return nil, err
			}
			p, err := openPEBytes(b)
			if err != nil {
				return nil, fmt.Errorf("%s: %v", path, err)
			}
			base, size, err := p.dir(peDirResource)
			if err != nil {
				return nil, fmt.Errorf("%s: %v", path, err)
			}
			if base == 0 || size == 0 {
				return struct {
					Present bool             `json:"present"`
					Section string           `json:"section"`
					BaseRVA uint32           `json:"base_rva"`
					Bytes   uint32           `json:"directory_bytes"`
					Leaves  int              `json:"leaves"`
					Types   []peResTypeEntry `json:"types"`
				}{false, "", 0, 0, 0, []peResTypeEntry{}}, nil
			}
			tr := &peResTree{section: p.sectionName(base), chain: make([]uint32, 0, 4)}
			if err := peResWalk(p, tr, base, 0, 0, nil, nil); err != nil {
				return nil, fmt.Errorf("%s resources: %v", path, err)
			}
			if tr.leaves == 0 {
				return nil, fmt.Errorf("%s resource directory holds no data entries", path)
			}
			return struct {
				Present bool             `json:"present"`
				Section string           `json:"section"`
				BaseRVA uint32           `json:"base_rva"`
				Bytes   uint32           `json:"directory_bytes"`
				Leaves  int              `json:"leaves"`
				Types   []peResTypeEntry `json:"types"`
			}{true, tr.section, base, size, tr.leaves, tr.types}, nil
		},
	})
}

// peResWalk descends one directory. typ/name are the ancestors already decoded;
// at depth 2 they point at the type and name entries being filled.
func peResWalk(p *peFile, tr *peResTree, base, rel uint32, depth int, typ *peResTypeEntry, name *peResNameEntry) error {
	if depth > 3 {
		return fmt.Errorf("directory at RVA %#x is nested deeper than three levels", base+rel)
	}
	if slices.Contains(tr.chain, rel) {
		return fmt.Errorf("resource directory at RVA %#x loops back on itself", base+rel)
	}
	tr.chain = append(tr.chain, rel)
	defer func() { tr.chain = tr.chain[:len(tr.chain)-1] }()

	hdr, err := p.at(base+rel, 16)
	if err != nil {
		return fmt.Errorf("directory at RVA %#x: %v", base+rel, err)
	}
	nNamed, nID := int(u16le(hdr, 12)), int(u16le(hdr, 14))
	total := nNamed + nID
	if total == 0 {
		return fmt.Errorf("directory at RVA %#x declares no entries", base+rel)
	}
	if total > peResMaxEntries {
		return fmt.Errorf("directory at RVA %#x declares %d entries", base+rel, total)
	}
	blob, err := p.at(base+rel, uint32(16+total*8))
	if err != nil {
		return fmt.Errorf("directory at RVA %#x: %v", base+rel, err)
	}
	for i := range total {
		id, off := u32le(blob, 16+i*8), u32le(blob, 20+i*8)
		label, nameID := "", id
		if id&0x80000000 != 0 {
			label, err = peResString(p, base, id&0x7FFFFFFF)
			if err != nil {
				return err
			}
			nameID = 0
		}
		if off&0x80000000 == 0 {
			if depth != 2 {
				return fmt.Errorf("directory at RVA %#x level %d points at data entry at RVA %#x instead of a directory", base+rel, depth, base+off)
			}
			ent, err := p.at(base+off, 16)
			if err != nil {
				return fmt.Errorf("data entry at RVA %#x: %v", base+off, err)
			}
			dataRVA, bytes, codePage := u32le(ent, 0), u32le(ent, 4), u32le(ent, 8)
			fileOff, err := p.fileOffset(dataRVA, bytes)
			if err != nil {
				return fmt.Errorf("data entry at RVA %#x: %v", base+off, err)
			}
			tr.leaves++
			if tr.leaves > peResMaxLeaves {
				return fmt.Errorf("resource tree holds more than %d data entries", peResMaxLeaves)
			}
			name.Languages = append(name.Languages, peResLanguage{
				Language: nameID, Name: label, DataRVA: dataRVA,
				FileOffset: fileOff, Size: bytes, CodePage: codePage,
			})
			continue
		}
		child := off & 0x7FFFFFFF
		switch depth {
		case 0:
			tr.types = append(tr.types, peResTypeEntry{ID: nameID, Name: label, Kind: peResKind(nameID)})
			if err := peResWalk(p, tr, base, child, 1, &tr.types[len(tr.types)-1], nil); err != nil {
				return err
			}
		case 1:
			typ.Entries = append(typ.Entries, peResNameEntry{ID: nameID, Name: label})
			if err := peResWalk(p, tr, base, child, 2, typ, &typ.Entries[len(typ.Entries)-1]); err != nil {
				return err
			}
		case 2:
			return fmt.Errorf("directory at RVA %#x nests a fourth level under language %d", base+rel, nameID)
		}
	}
	return nil
}

func peResKind(id uint32) string {
	if n, ok := peResKindNames[id]; ok {
		return n
	}
	return ""
}

// peResString reads a directory name: u16 character count then UTF-16LE units.
func peResString(p *peFile, base, rel uint32) (string, error) {
	hdr, err := p.at(base+rel, 2)
	if err != nil {
		return "", fmt.Errorf("resource name at RVA %#x: %v", base+rel, err)
	}
	n := int(u16le(hdr, 0))
	if n > peResMaxName {
		return "", fmt.Errorf("resource name at RVA %#x declares %d characters", base+rel, n)
	}
	b, err := p.at(base+rel, uint32(2+n*2))
	if err != nil {
		return "", fmt.Errorf("resource name at RVA %#x: %v", base+rel, err)
	}
	rs := make([]rune, n)
	for i := range rs {
		rs[i] = rune(u16le(b, 2+i*2))
	}
	return string(rs), nil
}
