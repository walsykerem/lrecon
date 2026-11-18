package main

// Producer reader: the compiler that wrote a native file, taken only from a
// producer string the file itself records (.comment, DW_AT_producer, Mach-O
// LC_BUILD_VERSION, PE linker version, CodeView strings).
//
// Candidate discipline: a token that merely looks like a producer is never a
// candidate. Entropy, section names, panic-marker strings (start.zig,
// lib/std/, builtin.default_panic), exception tables and mangled symbols
// (DW.ref.*, .gcc_except_table, .eh_frame, legacy _Z) carry no weight here:
// they are shapes, and a shape cannot name a version. Rust and Swift embed
// clang paths and clang- versions inside their own producers, so their family
// is decided before clang/gcc is considered.

import (
	"bytes"
	"debug/dwarf"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"io"
	"regexp"
	"strings"
)

const (
	producerMaxCUs                 = 8 // compile units asked for a DW_AT_producer
	producerMaxBlob                = 64 << 10
	producerMaxRuns                = 64
	producerMaxClaim               = 2
	lcSourceVersion  macho.LoadCmd = 0x2a
	toolClang        uint32        = 1
	toolSwift        uint32        = 2
	toolLD           uint32        = 3
)

func init() {
	reasonRegistry["producer"] = reasonSet("producer-not-recorded")
	register(reader{
		format:  "producer",
		reasons: []string{"producer-not-recorded"},
		post:    true,
		inspect: inspectProducer,
	})
}

// producerHit is one recorded producer string and where it came from.
type producerHit struct {
	text   string
	mech   string // elf:.comment, dwarf:DW_AT_producer, macho:LC_BUILD_VERSION, ...
	off    int64
	family string // set when the mechanism already named the family
	value  string // set when the mechanism already normalized the value
}

func inspectProducer(path string, d *Digest) {
	switch d.Kind {
	case "elf", "macho", "pe":
	default:
		return
	}
	// Rust, Swift and Go name themselves first; a producer string must not
	// overwrite a toolchain that was read from a dedicated record.
	if d.Toolchain != "" {
		return
	}
	if hasSkipPrefix(d, "buildinfo-") {
		return
	}

	var hits []producerHit
	var sourceVersion string
	var rich, evidence bool
	switch d.Kind {
	case "elf":
		hits, evidence = elfProducerHits(path)
	case "macho":
		hits, sourceVersion, evidence = machoProducerHits(path)
	case "pe":
		hits, rich, evidence = peProducerHits(path)
	}
	hits = dedupeHits(hits)

	best, mechs, off := pickProducer(hits)
	if best == "" {
		detail := "no producer record in sections, load commands or DWARF"
		if evidence {
			detail = "producer record present but no gcc/clang/rustc/swift/zig/msvc version"
		}
		if rich {
			detail += "; PE Rich header present but build ids unmapped"
		}
		d.skip("producer-not-recorded", detail)
		return
	}

	d.Toolchain = best
	for i, m := range mechs {
		if i >= producerMaxClaim {
			break
		}
		d.claim(best, "producer:"+m, off[i])
	}
	note := fmt.Sprintf("producer: %s from %s", best, strings.Join(mechs, ", "))
	if sourceVersion != "" {
		note += "; LC_SOURCE_VERSION " + sourceVersion
	}
	deepNote(d, note)
}

func hasSkipPrefix(d *Digest, prefix string) bool {
	for _, s := range d.Skipped {
		if strings.HasPrefix(s.Reason, prefix) {
			return true
		}
	}
	return false
}

func dedupeHits(hits []producerHit) []producerHit {
	seen := map[string]bool{}
	out := hits[:0]
	for _, h := range hits {
		key := h.mech + "\x00" + h.text
		if seen[key] || strings.TrimSpace(h.text) == "" {
			continue
		}
		seen[key] = true
		out = append(out, h)
	}
	return out
}

// pickProducer chooses one normalized toolchain: compiler evidence outranks a
// linker version, then frequency, then first seen.
func pickProducer(hits []producerHit) (string, []string, []int64) {
	type vote struct {
		value  string
		family string
		weight int
		count  int
		order  int
		mechs  []string
		offs   []int64
	}
	votes := map[string]*vote{}
	var order []string
	for i, h := range hits {
		value, family, ok := h.value, h.family, h.value != ""
		if !ok {
			value, family, ok = classifyProducer(h.text)
		}
		if !ok {
			continue
		}
		v := votes[value]
		if v == nil {
			v = &vote{value: value, family: family, weight: producerWeight(family), order: i}
			votes[value] = v
			order = append(order, value)
		}
		v.count++
		v.mechs = append(v.mechs, h.mech)
		v.offs = append(v.offs, h.off)
	}
	if len(order) == 0 {
		return "", nil, nil
	}
	best := votes[order[0]]
	for _, key := range order[1:] {
		v := votes[key]
		if v.weight > best.weight || (v.weight == best.weight && v.count > best.count) {
			best = v
		}
	}
	// One claim per mechanism keeps offset and source paired.
	var mechs []string
	var offs []int64
	seen := map[string]bool{}
	for i, m := range best.mechs {
		if seen[m] {
			continue
		}
		seen[m] = true
		mechs = append(mechs, m)
		offs = append(offs, best.offs[i])
	}
	return best.value, mechs, offs
}

func producerWeight(family string) int {
	if family == "linker" {
		return 1
	}
	return 3
}

var (
	reRustc     = regexp.MustCompile(`(?i)\brustc(?: version)? (\d+\.\d+\.\d+)`)
	reSwift     = regexp.MustCompile(`(?i)\b(?:apple )?swift(?: version)? (\d+\.\d+(?:\.\d+)?)`)
	reZig       = regexp.MustCompile(`(?i)\bzig(?: version)? (\d+\.\d+\.\d+)`)
	reZigBare   = regexp.MustCompile(`(?i)\bziglang\b`)
	reMSVC      = regexp.MustCompile(`(?i)Microsoft \(R\) (?:C/C\+\+ )?(?:Optimizing )?Compiler Version (\d+\.\d+\.\d+)`)
	reClang     = regexp.MustCompile(`(?i)\bclang(?: version |[- ])(\d+\.\d+\.\d+)`)
	reGCCParen  = regexp.MustCompile(`(?i)\bGCC:\s*\([^)]*\)\s*(\d+[\w.~+-]*)`)
	reGNUDirect = regexp.MustCompile(`(?i)^GNU (?:C|C\+\+|Objective-C|Fortran|D)\w*\s+(\d+\.\d+\.\d+)`)
)

// classifyProducer normalizes one recorded producer string. Order matters:
// Rust's producer starts with "clang LLVM (rustc version ...)" and Swift's
// embeds "clang-...", so both are recognized before clang.
func classifyProducer(s string) (value, family string, ok bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", "", false
	}
	if m := reRustc.FindStringSubmatch(s); m != nil {
		return "rustc " + m[1], "rustc", true
	}
	if m := reSwift.FindStringSubmatch(s); m != nil {
		return "swift " + m[1], "swift", true
	}
	if m := reZig.FindStringSubmatch(s); m != nil {
		return "zig " + m[1], "zig", true
	}
	if reZigBare.MatchString(s) {
		return "zig (version not recorded)", "zig", true
	}
	if m := reMSVC.FindStringSubmatch(s); m != nil {
		return "msvc " + m[1], "msvc", true
	}
	if m := reClang.FindStringSubmatch(s); m != nil {
		return "clang " + m[1], "clang", true
	}
	if m := reGCCParen.FindStringSubmatch(s); m != nil {
		return "gcc " + m[1], "gcc", true
	}
	if m := reGNUDirect.FindStringSubmatch(s); m != nil {
		return "gcc " + m[1], "gcc", true
	}
	return "", "", false
}

// trimVersion drops trailing ".0" pairs a linker version often carries.
func trimVersion(v string) string {
	for strings.HasSuffix(v, ".0") {
		v = strings.TrimSuffix(v, ".0")
	}
	return v
}

// --- ELF ---

func elfProducerHits(path string) (hits []producerHit, evidence bool) {
	f, err := elf.Open(path)
	if err != nil {
		return nil, false
	}
	defer f.Close()
	if s := f.Section(".comment"); s != nil {
		b := sectionBytes(s, producerMaxBlob)
		if len(b) > 0 {
			evidence = true
			hits = append(hits, textHits(b, "elf:.comment", int64(s.Offset))...)
		}
	}
	if dw, err := f.DWARF(); err == nil {
		evidence = true
		dwBase := int64(-1)
		if s := f.Section(".debug_info"); s != nil {
			dwBase = int64(s.Offset)
		}
		hits = append(hits, dwarfHits(dw, "dwarf:DW_AT_producer", dwBase)...)
	}
	return hits, evidence
}

func sectionBytes(s *elf.Section, max int64) []byte {
	b, _ := io.ReadAll(io.LimitReader(s.Open(), max))
	return b
}

// textHits reads NUL- or newline-separated producer strings.
func textHits(b []byte, mech string, base int64) []producerHit {
	var hits []producerHit
	start := 0
	for i := 0; i <= len(b); i++ {
		if i < len(b) && b[i] != 0 && b[i] != '\n' {
			continue
		}
		text := strings.TrimSpace(string(b[start:i]))
		if text != "" {
			hits = append(hits, producerHit{text: text, mech: mech, off: base + int64(start)})
		}
		start = i + 1
	}
	return hits
}

// --- Mach-O ---

func machoProducerHits(path string) (hits []producerHit, sourceVersion string, evidence bool) {
	if ff, err := macho.OpenFat(path); err == nil {
		defer ff.Close()
		for _, arch := range ff.Arches {
			h, sv, e := machoFileHits(arch.File, int64(arch.Offset))
			hits = append(hits, h...)
			evidence = evidence || e
			if sourceVersion == "" {
				sourceVersion = sv
			}
		}
		return hits, sourceVersion, evidence
	}
	f, err := macho.Open(path)
	if err != nil {
		return nil, "", false
	}
	defer f.Close()
	return machoFileHits(f, 0)
}

// machoFileHits reads the load commands. base is the file offset of the Mach-O
// header itself (non-zero for a slice of a fat file); every hit carries the
// file offset of the field it was read from, not an offset inside the command.
func machoFileHits(f *macho.File, base int64) (hits []producerHit, sourceVersion string, evidence bool) {
	hdr := int64(28)
	if f.Magic == macho.Magic64 {
		hdr = 32
	}
	cmdAt := base + hdr
	for _, l := range f.Loads {
		raw := l.Raw()
		if len(raw) < 8 {
			continue
		}
		cmdOff := cmdAt
		cmdAt += int64(binary.LittleEndian.Uint32(raw[4:]))
		switch macho.LoadCmd(binary.LittleEndian.Uint32(raw)) {
		case lcBuildVersion:
			evidence = true
			if len(raw) < 24 {
				continue
			}
			n := int(binary.LittleEndian.Uint32(raw[20:]))
			for i := range n {
				off := 24 + i*8
				if off+8 > len(raw) {
					break
				}
				tool := binary.LittleEndian.Uint32(raw[off:])
				ver := trimVersion(packedVersion(binary.LittleEndian.Uint32(raw[off+4:])))
				h := producerHit{mech: "macho:LC_BUILD_VERSION", off: cmdOff + int64(off)}
				switch tool {
				case toolClang:
					h.family, h.value, h.text = "clang", "clang "+ver, "clang "+ver
				case toolSwift:
					h.family, h.value, h.text = "swift", "swift "+ver, "swift "+ver
				case toolLD:
					h.family, h.value, h.text = "linker", "ld "+ver, "ld "+ver
				default:
					continue
				}
				hits = append(hits, h)
			}
		case lcSourceVersion:
			if len(raw) >= 16 {
				sourceVersion = sourceVersionString(binary.LittleEndian.Uint64(raw[8:]))
			}
		}
	}
	if s := f.Section("__comment"); s != nil {
		b, _ := io.ReadAll(io.LimitReader(s.Open(), producerMaxBlob))
		if len(b) > 0 {
			evidence = true
			hits = append(hits, textHits(b, "macho:__comment", int64(s.Offset))...)
		}
	}
	if dw, err := f.DWARF(); err == nil {
		evidence = true
		dwBase := int64(-1)
		if s := f.Section("__debug_info"); s != nil {
			dwBase = base + int64(s.Offset)
		}
		hits = append(hits, dwarfHits(dw, "dwarf:DW_AT_producer", dwBase)...)
	}
	return hits, sourceVersion, evidence
}

// packedVersion decodes the xxxx.yy.zz layout Mach-O uses for tool versions.
func packedVersion(v uint32) string {
	return fmt.Sprintf("%d.%d.%d", v>>16, (v>>8)&0xff, v&0xff)
}

// sourceVersionString decodes the a.b.c.d.e layout of LC_SOURCE_VERSION.
func sourceVersionString(v uint64) string {
	return fmt.Sprintf("%d.%d.%d", v>>40, (v>>30)&0x3ff, (v>>20)&0x3ff)
}

// --- PE ---

func peProducerHits(path string) (hits []producerHit, rich, evidence bool) {
	f, err := pe.Open(path)
	if err != nil {
		return nil, false, false
	}
	defer f.Close()
	// The linker version field sits in the optional header: PE signature (4) +
	// COFF header (20) past e_lfanew, then MajorLinkerVersion at offset 2.
	linkerOff := int64(0)
	if hdr := head(path, 0x40); len(hdr) >= 0x40 {
		if e := int64(binary.LittleEndian.Uint32(hdr[0x3c:])); e > 0 && e < 1<<20 {
			linkerOff = e + 24 + 2
		}
	}
	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader64:
		hits = append(hits, linkerHit(oh.MajorLinkerVersion, oh.MinorLinkerVersion, linkerOff))
		evidence = true
	case *pe.OptionalHeader32:
		hits = append(hits, linkerHit(oh.MajorLinkerVersion, oh.MinorLinkerVersion, linkerOff))
		evidence = true
	}
	for _, s := range f.Sections {
		name := strings.ToLower(s.Name)
		if !strings.HasPrefix(name, ".debug$") {
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(s.Open(), producerMaxBlob))
		if len(b) > 0 {
			evidence = true
			hits = append(hits, printableHits(b, "pe:"+name, int64(s.Offset))...)
		}
	}
	if dw, err := f.DWARF(); err == nil {
		evidence = true
		dwBase := int64(-1)
		for _, s := range f.Sections {
			if strings.EqualFold(s.Name, ".debug_info") {
				dwBase = int64(s.Offset)
			}
		}
		hits = append(hits, dwarfHits(dw, "dwarf:DW_AT_producer", dwBase)...)
	}
	rich = bytes.Contains(head(path, 4096), []byte("Rich"))
	return hits, rich, evidence
}

func linkerHit(major, minor uint8, off int64) producerHit {
	v := fmt.Sprintf("%d.%d", major, minor)
	return producerHit{
		text:   "linker " + v,
		off:    off,
		mech:   "pe:LinkerVersion",
		family: "linker",
		value:  "linker " + v,
	}
}

// printableHits pulls ASCII runs out of a binary blob (CodeView .debug$S) and
// keeps only the ones that classify as a producer.
func printableHits(b []byte, mech string, base int64) []producerHit {
	var hits []producerHit
	for i := 0; i < len(b) && len(hits) < producerMaxRuns; {
		if b[i] < 0x20 || b[i] > 0x7e {
			i++
			continue
		}
		start := i
		for i < len(b) && b[i] >= 0x20 && b[i] <= 0x7e {
			i++
		}
		if i-start < 8 {
			continue
		}
		text := strings.TrimSpace(string(b[start:i]))
		if _, _, ok := classifyProducer(text); ok {
			hits = append(hits, producerHit{text: text, mech: mech, off: base + int64(start)})
		}
	}
	return hits
}

// --- DWARF ---

// dwarfHits asks at most producerMaxCUs compile units for their producer. It
// never guesses from other attributes. base is the file offset of the
// .debug_info section, so a unit offset becomes a file offset; -1 keeps the
// section-relative offset when the section is compressed or unnamed.
func dwarfHits(dw *dwarf.Data, mech string, base int64) []producerHit {
	r := dw.Reader()
	var hits []producerHit
	cus := 0
	for cus < producerMaxCUs {
		e, err := r.Next()
		if err != nil || e == nil {
			break
		}
		if e.Tag != dwarf.TagCompileUnit {
			continue
		}
		cus++
		if v, ok := e.Val(dwarf.AttrProducer).(string); ok && strings.TrimSpace(v) != "" {
			off := int64(e.Offset)
			if base >= 0 {
				off += base
			}
			hits = append(hits, producerHit{text: v, mech: mech, off: off})
		}
		r.SkipChildren()
	}
	return hits
}
