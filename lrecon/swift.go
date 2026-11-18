package main

import (
	"bytes"
	"debug/elf"
	"debug/macho"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"strings"
)

// Swift metadata carries no magic of its own: it is recognized by section name
// only, after the Mach-O or ELF reader has claimed the file. Every layout below
// is the one verified in notes-r.md R10 (swiftc 6.2.4, arm64). A section this
// reader cannot verify is refused by name, never guessed.
const (
	swiftVersionUnverified = "swift-version-unverified"
	swiftSizeMisaligned    = "swift-section-size-misaligned"
	swiftOffsetOutOfRange  = "swift-relative-offset-out-of-range"
	swiftTyperefSkipped    = "swift-typeref-walk-skipped"
	swiftSectionUnreadable = "swift-section-unreadable"
	swiftSliceUnreadable   = "swift-slice-unreadable"
)

// swiftSections maps both spellings to one canonical name. Mach-O uses the
// 16-byte sectname (`__swift5_*`), ELF the literal asm name without a dot
// (`swift5_*`); a leading dot is trimmed before the lookup.
var swiftSections = map[string]string{
	"__swift5_types":   "types",
	"__swift5_types2":  "types2",
	"__swift5_protos":  "protos",
	"__swift5_proto":   "proto",
	"__swift5_fieldmd": "fieldmd",
	"__swift5_reflstr": "reflstr",
	"__swift5_typeref": "typeref",
	"__swift5_assocty": "assocty",
	"__swift5_builtin": "builtin",
	"__swift5_capture": "capture",
	"__swift5_mpenum":  "mpenum",
	"__swift5_entry":   "entry",

	"swift5_type_metadata":         "types",
	"swift5_type_metadata_2":       "types2",
	"swift5_protocols":             "protos",
	"swift5_protocol_conformances": "proto",
	"swift5_fieldmd":               "fieldmd",
	"swift5_reflstr":               "reflstr",
	"swift5_typeref":               "typeref",
	"swift5_assocty":               "assocty",
	"swift5_builtin":               "builtin",
	"swift5_capture":               "capture",
	"swift5_mpenum":                "mpenum",
	"swift5_entry":                 "entry",
}

// swiftEntrySize is the fixed record length for sections whose whole body is a
// flat array; 0 means variable-length, where only the byte size is a fact.
// fieldmd is variable (16-byte header + NumFields*FieldRecordSize records), so
// it is sized, never counted.
var swiftEntrySize = map[string]int{
	"types": 4, "types2": 4, "protos": 4, "proto": 4,
}

// swiftMask clears the tag bits carried in the low bits of a relative offset.
var swiftMask = map[string]uint32{"types": 3, "types2": 3, "protos": 1, "proto": 1}

type swiftSeg struct {
	addr, size uint64
}

type swiftSec struct {
	name string
	addr uint64
	data []byte
}

// swiftImage is one Mach-O slice or ELF image: its metadata sections plus the
// loaded segments that map a target VA to a file range.
type swiftImage struct {
	arch       string
	slice      int
	sections   []swiftSec
	unreadable []string
	segs       []swiftSeg
	version    []byte // raw ___swift_reflection_version bytes, nil when absent
}

func init() {
	register(reader{
		format: "swift",
		post:   true,
		reasons: []string{
			swiftVersionUnverified, swiftSizeMisaligned,
			swiftOffsetOutOfRange, swiftTyperefSkipped, swiftSectionUnreadable,
			swiftSliceUnreadable,
		},
		match: func(head []byte, size int64) bool {
			return fatMachOOK(head, size) || isMachO(head) || bytes.HasPrefix(head, []byte("\x7fELF"))
		},
		inspect: inspectSwift,
	})
}

func inspectSwift(path string, d *Digest) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	switch d.Kind {
	case "macho":
		imgs, bad := machoSwiftImages(f)
		reportSwift(imgs, bad, d)
	case "elf":
		if ef, err := elf.NewFile(f); err == nil {
			reportSwift([]swiftImage{elfSwift(ef)}, 0, d)
		}
	}
}

// machoSwiftImages reads a thin image or every slice of a fat one. One slice
// that does not parse must not hide the others, so a fat file that
// macho.NewFatFile refuses outright (it aborts on the first bad slice) is
// retried through its arch table, counting the unreadable slices.
func machoSwiftImages(r io.ReaderAt) (imgs []swiftImage, bad int) {
	if ff, err := macho.NewFatFile(r); err == nil {
		defer ff.Close()
		for i, a := range ff.Arches {
			img := machoSwift(a.File)
			img.slice = i
			imgs = append(imgs, img)
		}
		return imgs, 0
	}
	if f, err := macho.NewFile(r); err == nil {
		return []swiftImage{machoSwift(f)}, 0
	}
	shards, err := swiftFatSlices(r)
	if err != nil {
		return nil, 0
	}
	for i, shard := range shards {
		f, err := macho.NewFile(shard)
		if err != nil {
			bad++
			continue
		}
		img := machoSwift(f)
		img.slice = i
		imgs = append(imgs, img)
	}
	return imgs, bad
}

// swiftFatSlices reads only the fat arch table, using the stdlib header types,
// to hand each slice to debug/macho on its own.
func swiftFatSlices(r io.ReaderAt) ([]io.ReaderAt, error) {
	sr := io.NewSectionReader(r, 0, 1<<63-1)
	var hdr struct{ Magic, Narch uint32 }
	if err := binary.Read(sr, binary.BigEndian, &hdr); err != nil {
		return nil, err
	}
	if hdr.Magic != macho.MagicFat || hdr.Narch < 1 || hdr.Narch > 64 {
		return nil, macho.ErrNotFat
	}
	shards := make([]io.ReaderAt, 0, hdr.Narch)
	for i := uint32(0); i < hdr.Narch; i++ {
		var a macho.FatArchHeader
		if err := binary.Read(sr, binary.BigEndian, &a); err != nil {
			return nil, err
		}
		shards = append(shards, io.NewSectionReader(r, int64(a.Offset), int64(a.Size)))
	}
	return shards, nil
}

func machoSwift(f *macho.File) swiftImage {
	img := swiftImage{arch: machoArch(f.Cpu)}
	for _, l := range f.Loads {
		if seg, ok := l.(*macho.Segment); ok {
			img.segs = append(img.segs, swiftSeg{seg.Addr, seg.Filesz})
		}
	}
	// Swift metadata lives in __TEXT only; a same-named section elsewhere is not
	// the section the runtime reads.
	for _, s := range f.Sections {
		name, ok := swiftSectionName(s.Name)
		if !ok || s.Seg != "__TEXT" {
			continue
		}
		if b, err := s.Data(); err == nil {
			img.sections = append(img.sections, swiftSec{name, s.Addr, b})
		} else {
			img.unreadable = append(img.unreadable, name)
		}
	}
	if f.Symtab != nil {
		for _, sym := range f.Symtab.Syms {
			if sym.Name == "___swift_reflection_version" || sym.Name == "__swift_reflection_version" {
				img.version = machoAt(f, sym.Value)
				break
			}
		}
	}
	return img
}

func elfSwift(f *elf.File) swiftImage {
	img := swiftImage{arch: elfArch(f.Machine)}
	for _, p := range f.Progs {
		if p.Type == elf.PT_LOAD {
			img.segs = append(img.segs, swiftSeg{p.Vaddr, p.Filesz})
		}
	}
	for _, s := range f.Sections {
		name, ok := swiftSectionName(s.Name)
		if !ok {
			continue
		}
		if b, err := s.Data(); err == nil {
			img.sections = append(img.sections, swiftSec{name, s.Addr, b})
		} else {
			img.unreadable = append(img.unreadable, name)
		}
	}
	syms, err := f.Symbols()
	if err != nil {
		syms, _ = f.DynamicSymbols()
	}
	for _, sym := range syms {
		if sym.Name == "__swift_reflection_version" {
			img.version = elfAt(f, sym.Value)
			break
		}
	}
	return img
}

// machoAt returns the 2 bytes at VA, reading only the containing section.
func machoAt(f *macho.File, va uint64) []byte {
	for _, s := range f.Sections {
		if va < s.Addr || va+2 > s.Addr+s.Size {
			continue
		}
		b, err := s.Data()
		if err != nil || va-s.Addr+2 > uint64(len(b)) {
			return nil
		}
		return b[va-s.Addr : va-s.Addr+2]
	}
	return nil
}

func elfAt(f *elf.File, va uint64) []byte {
	for _, s := range f.Sections {
		if va < s.Addr || va+2 > s.Addr+s.Size {
			continue
		}
		b, err := s.Data()
		if err != nil || va-s.Addr+2 > uint64(len(b)) {
			return nil
		}
		return b[va-s.Addr : va-s.Addr+2]
	}
	return nil
}

// reportSwift emits one capability line per section, summed over the slices of
// a fat file, then refuses what it could not lay out. Missing Swift sections are
// not an error: nothing is claimed and the Mach-O/ELF digest stays unchanged.
func reportSwift(imgs []swiftImage, bad int, d *Digest) {
	have := false
	archs := make([]string, 0, len(imgs))
	var names []string
	for i, img := range imgs {
		arch := img.arch
		if arch == "" {
			arch = fmt.Sprintf("slice%d", i)
		}
		archs = append(archs, arch)
		for _, name := range img.unreadable {
			d.skip(swiftSectionUnreadable, fmt.Sprintf("%s:%s section body could not be read", arch, name))
		}
		have = have || len(img.sections) > 0 || len(img.unreadable) > 0
		for _, sec := range img.sections {
			names = append(names, sec.name)
		}
	}
	if bad > 0 && have {
		d.skip(swiftSliceUnreadable, fmt.Sprintf("%d of %d slices did not parse", bad, bad+len(imgs)))
		for range bad {
			d.unparsed()
		}
	}
	if !have {
		return
	}
	if len(imgs) > 1 {
		d.Notes = append(d.Notes, fmt.Sprintf("swift: %d slices (%s)", len(imgs), strings.Join(archs, ", ")))
	}

	var caps []string
	ver, vok := uint16(0), false
	for _, img := range imgs {
		if v, ok := swiftReflectionVersion(img.version); ok {
			ver, vok = v, true
			break
		}
	}
	if vok && ver == 3 {
		caps = append(caps, "swift:reflection_version=3")
	} else if vok {
		d.skip(swiftVersionUnverified, fmt.Sprintf("reflection_version=%d, only layout 3 is verified", ver))
	} else {
		d.skip(swiftVersionUnverified, fmt.Sprintf(
			"no __swift_reflection_version symbol; swift sections present: %s", strings.Join(names, ",")))
	}

	total := map[string]int{}
	byArch := map[string][]swiftSliceCount{}
	order := make([]string, 0, len(names))
	typeref := 0
	for i, img := range imgs {
		arch := img.arch
		if arch == "" {
			arch = fmt.Sprintf("slice%d", i)
		}
		imgVer, imgVok := swiftReflectionVersion(img.version)
		for _, s := range img.sections {
			d.scannedAt(int64(s.addr), int64(len(s.data)))
			if size := swiftEntrySize[s.name]; size > 0 {
				n, aligned := swiftEntryCount(s.data, size)
				if !aligned {
					d.skip(swiftSizeMisaligned, fmt.Sprintf("%s:%s %d B is not a multiple of %d", arch, s.name, len(s.data), size))
					continue
				}
				if _, seen := total[s.name]; !seen {
					order = append(order, s.name)
				}
				total[s.name] += n
				byArch[s.name] = append(byArch[s.name], swiftSliceCount{arch, n})
				d.parsed()
				if imgVok && imgVer == 3 {
					if mask, ok := swiftMask[s.name]; ok {
						if badTargets := swiftBadTargets(s, mask, img.segs); badTargets > 0 {
							d.skip(swiftOffsetOutOfRange, fmt.Sprintf("%s:%s: %d relative targets outside loaded segments", arch, s.name, badTargets))
						}
					}
				}
				continue
			}
			if _, seen := total[s.name]; !seen {
				order = append(order, s.name)
			}
			total[s.name] += len(s.data)
			d.parsed()
			if s.name == "typeref" {
				typeref += len(s.data)
			}
		}
	}
	for _, name := range order {
		if _, fixed := swiftEntrySize[name]; fixed {
			caps = append(caps, fmt.Sprintf("swift:%s=%d", name, total[name]))
			if p := byArch[name]; swiftDiffering(p) {
				list := make([]string, len(p))
				for i, c := range p {
					list[i] = fmt.Sprintf("%s=%d", c.arch, c.n)
				}
				d.Notes = append(d.Notes, fmt.Sprintf("swift %s by slice: %s", name, strings.Join(list, ", ")))
			}
			continue
		}
		caps = append(caps, fmt.Sprintf("swift:%s=%db", name, total[name]))
	}
	if typeref > 0 {
		// Typeref bodies have no length table, so the walk is refused by name.
		d.skip(swiftTyperefSkipped, fmt.Sprintf("typeref %d B variable-length, not walked", typeref))
	}
	d.Capabilities = append(d.Capabilities, uniqued(caps)...)
}

// swiftSliceCount is one slice's count for one section, kept with its arch so a
// disagreement can name both.
type swiftSliceCount struct {
	arch string
	n    int
}

// swiftDiffering reports whether the per-slice counts disagree; equal counts
// need no breakdown even though the arch labels differ.
func swiftDiffering(parts []swiftSliceCount) bool {
	if len(parts) < 2 {
		return false
	}
	for _, p := range parts[1:] {
		if p.n != parts[0].n {
			return true
		}
	}
	return false
}

// swiftSectionName canonicalizes a Mach-O or ELF section name.
func swiftSectionName(raw string) (string, bool) {
	name, ok := swiftSections[strings.TrimPrefix(raw, ".")]
	return name, ok
}

// swiftTargets decodes 4-byte relative offsets: target = field's own VA +
// int32(raw &^ mask). A raw zero is null, not a pointer to the field.
func swiftTargets(data []byte, base uint64, mask uint32) (targets []uint64, nulls int, ok bool) {
	if len(data)%4 != 0 {
		return nil, 0, false
	}
	for i := 0; i+4 <= len(data); i += 4 {
		raw := binary.LittleEndian.Uint32(data[i:])
		if raw == 0 {
			nulls++
			continue
		}
		targets = append(targets, base+uint64(i)+uint64(int64(int32(raw&^mask))))
	}
	return targets, nulls, true
}

// swiftReflectionVersion reads the Int16 reflection layout version.
func swiftReflectionVersion(b []byte) (uint16, bool) {
	if len(b) < 2 {
		return 0, false
	}
	return binary.LittleEndian.Uint16(b), true
}

// swiftEntryCount counts fixed-size records, refusing a body cut mid-record.
func swiftEntryCount(data []byte, size int) (int, bool) {
	if size <= 0 {
		return 0, true
	}
	if len(data)%size != 0 {
		return 0, false
	}
	return len(data) / size, true
}

func swiftBadTargets(s swiftSec, mask uint32, segs []swiftSeg) int {
	targets, _, ok := swiftTargets(s.data, s.addr, mask)
	if !ok {
		return 0
	}
	bad := 0
	for _, t := range targets {
		if !vaInSegments(segs, t) {
			bad++
		}
	}
	return bad
}

func vaInSegments(segs []swiftSeg, va uint64) bool {
	for _, s := range segs {
		if va >= s.addr && va+4 <= s.addr+s.size {
			return true
		}
	}
	return false
}
