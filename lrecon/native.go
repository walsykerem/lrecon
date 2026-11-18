package main

import (
	"bytes"
	"compress/zlib"
	"debug/buildinfo"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
)

// Budgets: the digest is for agents, so every list is short and every read is bounded.
const (
	maxDylibs  = 40
	maxDeps    = 60
	maxDeep    = 200
	maxSection = 8 << 10 // rustc metadata sections are tiny
	maxSniff   = 2 << 20 // bounded Mach-O fallback window for rust markers
)

func inspectNative(path string, d *Digest) {
	var err error
	switch d.Kind {
	case "macho":
		err = machoDigest(path, d)
		deepNote(d, "read load commands, segment table and symbol table to recover linked dylibs, exported symbols, code signature and stripped symbol names")
	case "elf":
		err = elfDigest(path, d)
		deepNote(d, "read program headers, section table and dynamic section to recover library dependencies, build id, module version and stripped symbol names")
	case "pe":
		err = peDigest(path, d)
		deepNote(d, "read section, import and resource tables to recover imports, module version, resources, debug directory and embedded certificate table")
	}
	if err != nil {
		d.Notes = append(d.Notes, "native: "+err.Error())
		// A failed parse must not read as a clean negative: say nothing was read.
		if len(d.Constants) == 0 {
			d.Constants = consts{constNotScanned}
		}
		if d.Names == "" {
			d.Names = nameNotRecovered
		}
		if d.JIT == "" {
			d.JIT = constNotDetected
		}
	} else if gap := d.FileSize - d.readEnd(); gap > 0 {
		// The parse walked the file to its end, so every byte is accounted for.
		// shortcut: section padding has no reader and counts as covered once the
		// format parse completes; upgrade when readers record per-section spans.
		d.scanned(gap)
	}
	if d.Kind == "macho" || d.Kind == "elf" {
		d.Skeleton = resolveSkeleton(path, d)
	}
	if !goDigest(path, d) && (d.Kind == "elf" || d.Kind == "macho") {
		rustDigest(path, d)
	}
}

// --- Mach-O ---

// Load commands debug/macho does not decode itself.
const (
	lcUUID               macho.LoadCmd = 0x1b
	lcCodeSignature      macho.LoadCmd = 0x1d
	lcVersionMinMacOSX   macho.LoadCmd = 0x24
	lcVersionMinIPhoneOS macho.LoadCmd = 0x25
	lcBuildVersion       macho.LoadCmd = 0x32
	lcDyldInfo           macho.LoadCmd = 0x22
	lcDyldInfoOnly       macho.LoadCmd = 0x80000022
	lcDyldExportsTrie    macho.LoadCmd = 0x80000033
	lcFunctionStarts     macho.LoadCmd = 0x26
	lcChainedFixups      macho.LoadCmd = 0x80000034
)

// symbol table states a digest reports: a zero export count means nothing
// without knowing whether a table was there to count from.
const (
	symPresent  = "present"
	symStripped = "stripped"
)

// machoInfo is one slice: a fat binary gets one line per arch in SliceInfo.
type machoInfo struct {
	arch    string
	minos   string
	uuid    string
	exports int
	symbols string
	rpaths  []string
	hard    []string
	libs    []string
	syms    []string
}

func machoDigest(path string, d *Digest) error {
	var files []*macho.File
	var bases []int64 // load-command file offsets are relative to the fat slice
	host := 0         // index of the slice this machine would load
	if d.Format == "fat" {
		// macho.Open fails on universal binaries ("invalid magic number in record").
		f, err := macho.OpenFat(path)
		if err != nil {
			return err
		}
		defer f.Close()
		d.Slices = len(f.Arches)
		host = machoHostSlice(f.Arches)
		for _, a := range f.Arches {
			files, bases = append(files, a.File), append(bases, int64(a.Offset))
			// Each slice is read through its own base; the span says which bytes
			// that architecture's facts came from.
			if a.Size > 0 {
				d.witness(Witness{Axis: "slice", Class: "slice", Value: machoArch(a.Cpu), Start: int64(a.Offset), End: int64(a.Offset) + int64(a.Size)})
			}
		}
	} else {
		f, err := macho.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		files, bases = append(files, f), append(bases, 0)
	}
	var libs, syms, hard, rpaths []string
	var hits []constHit
	var jit []string
	scanned, partial, locals := 0, 0, 0
	sliceExports := 0
	sliceSymbols := false
	for i, f := range files {
		m := machoScan(f, path, bases[i])
		// The entry point is the one the host would load, not slice 0's.
		if d.Entrypoint == nil && i == host {
			if entry, ok := machoEntry(f); ok {
				d.Entrypoint = &entry
			}
		}
		libs, syms = append(libs, m.libs...), append(syms, m.syms...)
		hard, rpaths = append(hard, m.hard...), append(rpaths, m.rpaths...)
		h, sc, pa := machoConstants(path, f, bases[i])
		hits, scanned, partial = append(hits, h...), scanned+sc, partial+pa
		jit = append(jit, machoJIT(f)...)
		locals += machoLocalNames(f)
		sliceExports += m.exports
		sliceSymbols = sliceSymbols || m.symbols == symPresent
		if d.Format == "fat" {
			d.SliceInfo = append(d.SliceInfo, m.line())
		} else {
			d.MinOS, d.UUID, d.Exports, d.Symbols = m.minos, m.uuid, m.exports, m.symbols
		}
	}
	if d.Format == "fat" {
		// The top-level answer must not read as "nothing exported" when every
		// slice exports something: sum the slices, and keep the symbol-table
		// state present if any slice still has one.
		d.Exports = sliceExports
		d.Symbols = symStripped
		if sliceSymbols {
			d.Symbols = symPresent
		}
	}
	d.Hardening = append(d.Hardening, uniqued(hard)...)
	// Imported symbols are where canary/fortify show up on Mach-O too; ELF had
	// this call but Mach-O did not, so a hardened binary answered "nx,pie" only.
	d.Hardening = uniqued(append(d.Hardening, chkHardening(syms)...))
	d.Dylibs = capped(d, "dylibs", uniqued(libs), maxDylibs)
	d.Imports = uniqued(syms)
	// Unconditional: a nil slice marshals to null, but the contract types this
	// field as an array. A binary with no LC_RPATH must answer [], not null.
	d.Rpaths = capped(d, "rpaths", uniqued(rpaths), maxDylibs)
	setConstants(d, hits, scanned, partial)
	d.JIT = jitValue(d, jit)
	d.Names = namesValue(locals)
	return nil
}

// machoScan reads minors from raw load commands; only the typed ones matter for libs.
func machoScan(f *macho.File, path string, base int64) machoInfo {
	m := machoInfo{arch: machoArch(f.Cpu)}
	bo := f.ByteOrder
	dwarf := false
	for _, l := range f.Loads {
		raw := l.Raw()
		if len(raw) < 8 {
			continue
		}
		switch macho.LoadCmd(bo.Uint32(raw[0:4])) {
		case macho.LoadCmdRpath:
			if r, ok := l.(*macho.Rpath); ok {
				m.rpaths = append(m.rpaths, r.Path)
			}
		case lcUUID:
			if len(raw) >= 24 {
				m.uuid = fmt.Sprintf("%X", raw[8:24])
			}
		case lcCodeSignature:
			m.hard = append(m.hard, "codesign")
		case lcBuildVersion:
			if len(raw) >= 16 {
				m.minos = platformName(bo.Uint32(raw[8:12])) + " " + verString(bo.Uint32(raw[12:16]))
			}
		case lcVersionMinMacOSX:
			if m.minos == "" && len(raw) >= 12 {
				m.minos = "macOS " + verString(bo.Uint32(raw[8:12]))
			}
		case lcVersionMinIPhoneOS:
			if m.minos == "" && len(raw) >= 12 {
				m.minos = "iOS " + verString(bo.Uint32(raw[8:12]))
			}
		}
		if seg, ok := l.(*macho.Segment); ok && seg.Name == "__DWARF" {
			dwarf = true
		}
	}
	if dwarf {
		m.hard = append(m.hard, "debug-info:dwarf")
	}
	if f.Flags&macho.FlagPIE != 0 {
		m.hard = append(m.hard, "pie")
		// ASLR: a PIE image with dyld fixup info is rebased at load; chained
		// fixups or a non-empty rebase region both prove the slide is
		// applied, so the binary is randomized even when it has no __TEXT
		// slide assumption of its own.
		if machoHasRebase(f) {
			m.hard = append(m.hard, "aslr")
		}
		if f.Flags&macho.FlagAllowStackExecution == 0 {
			m.hard = append(m.hard, "nx")
		}
	} else if f.Flags&macho.FlagAllowStackExecution == 0 {
		m.hard = append(m.hard, "nx")
	}
	// The export trie is what dyld binds against and it survives strip -x, while
	// the symbol table can undercount, so the trie answers when it has data.
	m.exports, m.symbols = machoExports(path, base, f)
	m.libs, m.syms = machoParts(f)
	return m
}

// machoHasRebase reports ASLR evidence in the load commands: LC_DYLD_CHAINED_FIXUPS
// (chained fixups) or a LC_DYLD_INFO/LC_DYLD_INFO_ONLY with a non-zero rebase
// region. Both are byte-level proof the loader applies a slide; an absent or
// zero-byte region is no proof, so it stays silent instead of implying aslr.
func machoHasRebase(f *macho.File) bool {
	for _, l := range f.Loads {
		// debug/macho keeps unknown loads as LoadBytes with no typed name for
		// the chained-fixups / dyld-info commands, so test the header magic.
		if b, ok := l.(macho.LoadBytes); ok && len(b) >= 8 {
			cmd := binary.LittleEndian.Uint32(b)
			switch cmd {
			case 0x80000034: // LC_DYLD_CHAINED_FIXUPS
				return true
			case 0x22, 0x80000022: // LC_DYLD_INFO / LC_DYLD_INFO_ONLY
				// struct dyld_info_command: cmd, cmdsize, rebase_off, rebase_size, ...
				if len(b) >= 16 && binary.LittleEndian.Uint32(b[12:]) > 0 {
					return true
				}
			}
		}
	}
	return false
}

// symbolsState names whether a symbol table existed at all, so a zero export
// count stays distinguishable from a table that was stripped away.
func symbolsState(table bool) string {
	if table {
		return symPresent
	}
	return symStripped
}

func machoExports(path string, base int64, f *macho.File) (int, string) {
	n, defined := 0, false
	if f.Symtab != nil {
		for _, s := range f.Symtab.Syms {
			if s.Type&0x0e == 0 { // neither N_SECT nor N_ABS: an import
				continue
			}
			defined = true
			if s.Type&0x01 != 0 { // N_EXT
				n++
			}
		}
	}
	// A stripped Go binary keeps a symtab holding only imports, so defined
	// entries existing is the honest test for whether a name can resolve.
	symbols := symbolsState(defined)
	if trie, ok := dyldExportCount(path, base, f); ok {
		return trie, symbols
	}
	return n, symbols
}

// dyldExportCount walks the export trie behind LC_DYLD_EXPORTS_TRIE or the
// export region of LC_DYLD_INFO[_ONLY], which debug/macho does not expose.
// base is the fat-slice offset the load-command file offsets are relative to.
func dyldExportCount(path string, base int64, f *macho.File) (int, bool) {
	bo := f.ByteOrder
	var off, size int64
	for _, l := range f.Loads {
		raw := l.Raw()
		var o, s int64
		switch macho.LoadCmd(bo.Uint32(raw[0:4])) {
		case lcDyldExportsTrie:
			if len(raw) < 16 {
				continue
			}
			o, s = int64(bo.Uint32(raw[8:12])), int64(bo.Uint32(raw[12:16]))
		case lcDyldInfo, lcDyldInfoOnly:
			if len(raw) < 48 {
				continue
			}
			o, s = int64(bo.Uint32(raw[40:44])), int64(bo.Uint32(raw[44:48]))
		default:
			continue
		}
		if s > 0 {
			off, size = o, s
			break
		}
	}
	if size <= 0 || off <= 0 || size > 16<<20 { // corrupt sizes must not allocate
		return 0, false
	}
	fh, err := os.Open(path)
	if err != nil {
		return 0, false
	}
	defer fh.Close()
	b := make([]byte, size)
	n, _ := fh.ReadAt(b, base+off)
	if int64(n) != size {
		return 0, false
	}
	return trieTerminals(b), true
}

// trieTerminals counts terminal nodes: terminal ULEB128 size (0 means the node
// is not terminal), that many bytes of terminal data, then a child count and
// (edge string, child offset) per child.
func trieTerminals(b []byte) int {
	seen := make(map[int]bool)
	count := 0
	var walk func(off int)
	walk = func(off int) {
		if off < 0 || off >= len(b) || seen[off] {
			return
		}
		seen[off] = true
		term, width := uleb128(b[off:])
		if width == 0 {
			return
		}
		off += width
		if term != 0 {
			count++
			off += int(term)
		}
		if off >= len(b) {
			return
		}
		children := int(b[off])
		off++
		for range children {
			for off < len(b) && b[off] != 0 {
				off++
			}
			if off >= len(b) { // a corrupt trie must not slice past the end
				return
			}
			off++ // NUL after the edge string
			child, width := uleb128(b[off:])
			if width == 0 {
				return
			}
			off += width
			walk(int(child))
		}
	}
	walk(0)
	return count
}

func uleb128(b []byte) (uint64, int) {
	var v uint64
	for i := 0; i < len(b) && i < 10; i++ {
		v |= uint64(b[i]&0x7f) << (7 * uint(i))
		if b[i]&0x80 == 0 {
			return v, i + 1
		}
	}
	return 0, 0
}

func (m machoInfo) line() string {
	parts := []string{m.arch}
	if m.minos != "" {
		parts = append(parts, "minos "+m.minos)
	}
	if m.uuid != "" {
		parts = append(parts, "uuid "+m.uuid)
	}
	parts = append(parts, "exports "+fmt.Sprint(m.exports))
	if m.symbols != symPresent {
		parts = append(parts, "symbols "+m.symbols)
	}
	return strings.Join(append(parts, m.hard...), " ")
}

// machoHostSlice picks the slice this machine would load: on arm64 an
// x86_64-first universal binary would otherwise report the wrong entry.
// Falls back to slice 0 when no slice matches the host.
func machoHostSlice(arches []macho.FatArch) int {
	for i, a := range arches {
		if arch := machoArch(a.Cpu); arch == runtime.GOARCH || (runtime.GOARCH == "amd64" && arch == "x86-64") {
			return i
		}
	}
	return 0
}

// machoEntry reads the entry point on disk: LC_MAIN's entryoff (an offset from
// the __TEXT vmaddr) or, for old binaries, the pc/rip/eip in LC_UNIXTHREAD.
func machoEntry(f *macho.File) (uint64, bool) {
	var textVM uint64
	var entryOff, unix uint64
	haveMain, haveUnix := false, false
	for _, load := range f.Loads {
		raw := load.Raw()
		if len(raw) < 8 {
			continue
		}
		switch f.ByteOrder.Uint32(raw) {
		case 0x1: // LC_SEGMENT
			if len(raw) >= 56 && strings.TrimRight(string(raw[8:24]), "\x00") == "__TEXT" {
				textVM = uint64(f.ByteOrder.Uint32(raw[24:]))
			}
		case 0x19: // LC_SEGMENT_64
			if len(raw) >= 72 && strings.TrimRight(string(raw[8:24]), "\x00") == "__TEXT" {
				textVM = f.ByteOrder.Uint64(raw[24:])
			}
		case 0x80000028: // LC_MAIN
			if len(raw) >= 16 {
				entryOff, haveMain = f.ByteOrder.Uint64(raw[8:]), true
			}
		case 0x5: // LC_UNIXTHREAD
			unix, haveUnix = machoThreadEntry(f, raw)
		}
	}
	if haveMain {
		return textVM + entryOff, true
	}
	return unix, haveUnix
}

// machoThreadEntry pulls the program counter out of thread_state. Enough for
// x86-64/arm64/i386, the only Mach-O CPUs whose old binaries predate LC_MAIN.
func machoThreadEntry(f *macho.File, raw []byte) (uint64, bool) {
	if len(raw) < 16 {
		return 0, false
	}
	flavor, state := f.ByteOrder.Uint32(raw[8:]), raw[16:]
	idx, size := 0, 8
	switch f.Cpu {
	case macho.CpuAmd64:
		if flavor != 4 { // x86_THREAD_STATE64
			return 0, false
		}
		idx = 16 // rip
	case macho.CpuArm64:
		if flavor != 6 { // ARM_THREAD_STATE64
			return 0, false
		}
		idx = 32 // pc
	case macho.Cpu386:
		if flavor != 1 { // x86_THREAD_STATE32
			return 0, false
		}
		idx, size = 10, 4 // eip
	default:
		return 0, false
	}
	off := idx * size
	if len(state) < off+size {
		return 0, false
	}
	if size == 8 {
		return f.ByteOrder.Uint64(state[off:]), true
	}
	return uint64(f.ByteOrder.Uint32(state[off:])), true
}

func peEntry(f *pe.File) (uint64, bool) {
	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader64:
		if oh.AddressOfEntryPoint == 0 {
			return 0, false
		}
		return oh.ImageBase + uint64(oh.AddressOfEntryPoint), true
	case *pe.OptionalHeader32:
		if oh.AddressOfEntryPoint == 0 {
			return 0, false
		}
		return uint64(oh.ImageBase) + uint64(oh.AddressOfEntryPoint), true
	}
	return 0, false
}

func machoArch(c macho.Cpu) string {
	switch c {
	case macho.CpuAmd64:
		return "x86-64"
	case macho.CpuArm64:
		return "arm64"
	case macho.Cpu386:
		return "386"
	case macho.CpuArm:
		return "arm"
	}
	return fmt.Sprintf("cpu-%#x", uint32(c))
}

func platformName(p uint32) string {
	switch p {
	case 1:
		return "macOS"
	case 2:
		return "iOS"
	case 3:
		return "tvOS"
	case 4:
		return "watchOS"
	case 5:
		return "bridgeOS"
	case 6:
		return "macCatalyst"
	case 7:
		return "iOSSim"
	case 8:
		return "tvOSSim"
	case 9:
		return "watchOSSim"
	case 10:
		return "DriverKit"
	case 11:
		return "visionOS"
	case 12:
		return "visionOSSim"
	}
	return fmt.Sprintf("platform%d", p)
}

// Mach-O packs xxxx.yy.zz as major<<16 | minor<<8 | patch.
func verString(v uint32) string {
	if p := v & 0xff; p != 0 {
		return fmt.Sprintf("%d.%d.%d", v>>16, (v>>8)&0xff, p)
	}
	return fmt.Sprintf("%d.%d", v>>16, (v>>8)&0xff)
}

// machoParts returns dylib base names and every undefined symbol. The digest's
// imports field is the import list itself (nm -u), not a capability hint
// subset; filtering it here made /bin/ls answer one row out of ninety.
// Both Imported* methods return ([]string, error) in go1.26 and fail on stripped files.
func machoParts(f *macho.File) (libs, syms []string) {
	if f == nil {
		return nil, nil
	}
	if l, err := f.ImportedLibraries(); err == nil {
		for _, s := range l {
			libs = append(libs, base(s))
		}
	}
	if s, err := f.ImportedSymbols(); err == nil {
		syms = append(syms, s...)
	}
	return libs, syms
}

// --- ELF / PE ---

func elfDigest(path string, d *Digest) error {
	f, err := elf.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	d.Format = elfArch(f.Machine)
	if f.Entry != 0 {
		entry := f.Entry
		d.Entrypoint = &entry
	}
	if libs, err := f.ImportedLibraries(); err == nil {
		d.Dylibs = capped(d, "dylibs", uniqued(basenames(libs)), maxDylibs)
	}
	if so, err := f.DynString(elf.DT_SONAME); err == nil && len(so) > 0 {
		d.Soname = so[0]
	}
	d.BuildID = elfBuildID(d, f)
	d.Exports, d.Symbols = elfExports(f)

	var hard []string
	interp := false
	for _, p := range f.Progs {
		switch p.Type {
		case elf.PT_GNU_STACK:
			if p.Flags&elf.PF_X == 0 {
				hard = append(hard, "nx")
			}
		case elf.PT_GNU_RELRO:
			hard = append(hard, relroToken(f))
		case elf.PT_INTERP:
			interp = true
		}
	}
	if f.Type == elf.ET_DYN && interp {
		hard = append(hard, "pie")
	}
	// ImportedSymbols reads .dynsym, so these survive stripping of a dynamic binary.
	if f.Section(".debug_info") != nil {
		hard = append(hard, "debug-info:dwarf")
	}
	if syms, err := f.ImportedSymbols(); err == nil {
		names := make([]string, len(syms))
		for i, s := range syms {
			names[i] = s.Name
		}
		hard = append(hard, chkHardening(names)...)
		// imports is the undefined-symbol list, the same set nm -u prints.
		d.Imports = uniqued(names)
	}
	d.Hardening = append(d.Hardening, hard...)
	hits, scanned, partial := elfConstants(f)
	setConstants(d, hits, scanned, partial)
	d.JIT = jitValue(d, elfJIT(f))
	d.Names = namesValue(elfLocalNames(f))
	return nil
}

// elfExports counts defined global/weak symbols: .dynsym survives strip -s on a
// dynamic binary, .symtab only when the build kept it.
func elfExports(f *elf.File) (int, string) {
	syms, err := f.DynamicSymbols()
	if err != nil || len(syms) == 0 {
		if all, aerr := f.Symbols(); aerr == nil {
			syms = all
		}
	}
	n := 0
	for _, s := range syms {
		if s.Section == elf.SHN_UNDEF {
			continue
		}
		if b := elf.ST_BIND(s.Info); b == elf.STB_GLOBAL || b == elf.STB_WEAK {
			n++
		}
	}
	if len(syms) == 0 {
		return 0, symStripped
	}
	return n, symPresent
}

// relroToken splits partial from full RELRO: only full RELRO binds every
// relocation at load time, so .got.plt is read-only once the program runs.
func relroToken(f *elf.File) string {
	if v, err := f.DynValue(elf.DT_BIND_NOW); err == nil && len(v) > 0 {
		return "relro-full"
	}
	if v, err := f.DynValue(elf.DT_FLAGS); err == nil {
		for _, fl := range v {
			if elf.DynFlag(fl)&elf.DF_BIND_NOW != 0 {
				return "relro-full"
			}
		}
	}
	if v, err := f.DynValue(elf.DT_FLAGS_1); err == nil {
		for _, fl := range v {
			if elf.DynFlag1(fl)&elf.DF_1_NOW != 0 {
				return "relro-full"
			}
		}
	}
	return "relro-partial"
}

// chkHardening flags stack-protector (-fstack-protector) and FORTIFY_SOURCE from
// dynamic symbol names; import names are the only post-link evidence for either,
// and they survive stripping because they live in .dynsym.
// shortcut: name heuristics only — no GOT/relocation confirmation.
func chkHardening(syms []string) []string {
	canary, fortify := false, false
	for _, s := range syms {
		if strings.Contains(s, "__stack_chk_fail") {
			canary = true
		} else if strings.Contains(s, "_chk") {
			fortify = true
		}
	}
	var out []string
	if canary {
		out = append(out, "canary")
	}
	if fortify {
		out = append(out, "fortify")
	}
	return out
}

// elfBuildID reads the GNU note; absent on stripped or non-GNU-linked objects.
func elfBuildID(d *Digest, f *elf.File) string {
	s := f.Section(".note.gnu.build-id")
	if s == nil {
		return ""
	}
	b := sectionHead(s)
	bo := f.ByteOrder
	if len(b) >= 12 {
		namesz, descsz := int(bo.Uint32(b[0:4])), int(bo.Uint32(b[4:8]))
		desc := 12 + (namesz+3)&^3
		if namesz < 4 || desc+descsz > len(b) || string(b[12:12+namesz-1]) != "GNU" {
			return ""
		}
		id := fmt.Sprintf("%x", b[desc:desc+descsz])
		// The digest of this note is only as good as the section bytes behind it.
		if s.FileSize > 0 {
			d.witness(Witness{Axis: "build_id", Class: "note", Value: id, Start: int64(s.Offset), End: int64(s.Offset) + int64(s.FileSize)})
		}
		return id
	}
	return ""
}

func peDigest(path string, d *Digest) error {
	f, err := pe.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	d.Format = peArch(f.Machine)
	if entry, ok := peEntry(f); ok {
		d.Entrypoint = &entry
	}
	d.Exports, d.Symbols = peExports(path, f)
	// ImportedSymbols is "sym:DLL"; that is where the DLL list comes from too.
	var libs, syms []string
	canary := false
	if all, err := f.ImportedSymbols(); err == nil {
		for _, s := range all {
			name, lib, _ := strings.Cut(s, ":")
			if lib != "" {
				libs = append(libs, lib)
			}
			if strings.Contains(name, "__security_check_cookie") {
				canary = true
			}
			syms = append(syms, s)
		}
	}
	if len(libs) == 0 {
		if l, err := f.ImportedLibraries(); err == nil {
			libs = basenames(l)
		}
	}
	d.Dylibs = capped(d, "dylibs", uniqued(libs), maxDylibs)
	d.Imports = uniqued(syms)

	var hard []string
	if f.Characteristics&pe.IMAGE_FILE_DLL != 0 {
		hard = append(hard, "dll")
	}
	if sub, chars := peOptional(f); sub != 0 {
		d.Subsystem = peSubsystem(sub)
		if chars&pe.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE != 0 {
			hard = append(hard, "aslr")
		}
		if chars&pe.IMAGE_DLLCHARACTERISTICS_NX_COMPAT != 0 {
			hard = append(hard, "nx")
		}
		if chars&pe.IMAGE_DLLCHARACTERISTICS_GUARD_CF != 0 {
			hard = append(hard, "cfg")
		}
	}
	// MSVC /GS only leaves this import behind; the check itself is inlined.
	if canary {
		hard = append(hard, "canary")
	}
	if pdb := pePDB(path, f); pdb != "" {
		d.PDB = pdb
		hard = append(hard, "debug-info:pdb")
	}
	d.Hardening = append(d.Hardening, hard...)
	hits, scanned, partial := peConstants(path, f)
	setConstants(d, hits, scanned, partial)
	d.JIT = jitValue(d, peJIT(f))
	d.Names = namesValue(peLocalNames(f))
	return nil
}

func peOptional(f *pe.File) (subsystem uint16, dllChars uint16) {
	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		return oh.Subsystem, oh.DllCharacteristics
	case *pe.OptionalHeader64:
		return oh.Subsystem, oh.DllCharacteristics
	}
	return 0, 0
}

func peSubsystem(s uint16) string {
	switch s {
	case 1:
		return "native"
	case 2:
		return "gui"
	case 3:
		return "console"
	case 7:
		return "posix"
	case 9:
		return "wince"
	case 10:
		return "efi"
	case 14:
		return "xbox"
	}
	return fmt.Sprint("subsystem", s)
}

// peExports reads the export directory: a release image usually has no COFF
// symbol table, so only the directory says what the module exports. The symbol
// state still follows the COFF table, which is what --deep resolves names from.
func peExports(path string, f *pe.File) (int, string) {
	symbols := symbolsState(len(f.Symbols) > 0)
	var rva, size uint32
	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		dd := oh.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_EXPORT]
		rva, size = dd.VirtualAddress, dd.Size
	case *pe.OptionalHeader64:
		dd := oh.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_EXPORT]
		rva, size = dd.VirtualAddress, dd.Size
	}
	if rva == 0 || size == 0 {
		return 0, symbols
	}
	off, ok := peOffset(f, rva)
	if !ok {
		return 0, ""
	}
	fh, err := os.Open(path)
	if err != nil {
		return 0, ""
	}
	defer fh.Close()
	buf := make([]byte, 24) // IMAGE_EXPORT_DIRECTORY through NumberOfFunctions
	if n, _ := fh.ReadAt(buf, off); n < len(buf) {
		return 0, ""
	}
	return int(binary.LittleEndian.Uint32(buf[20:])), symbols
}

// pePDB follows the debug directory to the CodeView record and returns its PDB path.
func pePDB(path string, f *pe.File) string {
	var rva, size uint32
	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		dd := oh.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_DEBUG]
		rva, size = dd.VirtualAddress, dd.Size
	case *pe.OptionalHeader64:
		dd := oh.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_DEBUG]
		rva, size = dd.VirtualAddress, dd.Size
	}
	off, ok := peOffset(f, rva)
	if rva == 0 || size == 0 || !ok {
		return ""
	}
	fh, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer fh.Close()
	buf := make([]byte, min(size, 28*8))
	n, _ := fh.ReadAt(buf, int64(off))
	for i := 0; i+28 <= n; i += 28 { // IMAGE_DEBUG_DIRECTORY
		if binary.LittleEndian.Uint32(buf[i+12:]) != 2 { // IMAGE_DEBUG_TYPE_CODEVIEW
			continue
		}
		data := min(binary.LittleEndian.Uint32(buf[i+16:]), maxSection)
		ptr := binary.LittleEndian.Uint32(buf[i+24:])
		rec := make([]byte, data)
		m, _ := fh.ReadAt(rec, int64(ptr))
		rec = rec[:m]
		if !bytes.HasPrefix(rec, []byte("RSDS")) || len(rec) < 25 {
			return ""
		}
		pdb, _, _ := bytes.Cut(rec[24:], []byte{0})
		return string(pdb)
	}
	return ""
}

// peOffset maps an RVA into a raw file offset through the section table.
func peOffset(f *pe.File, rva uint32) (int64, bool) {
	for _, s := range f.Sections {
		if rva >= s.VirtualAddress && rva < s.VirtualAddress+s.Size {
			return int64(s.Offset) + int64(rva-s.VirtualAddress), true
		}
	}
	return 0, false
}

func elfArch(m elf.Machine) string {
	switch m {
	case elf.EM_X86_64:
		return "x86-64"
	case elf.EM_AARCH64:
		return "arm64"
	case elf.EM_386:
		return "386"
	case elf.EM_ARM:
		return "arm"
	case elf.EM_RISCV:
		return "riscv"
	}
	return strings.ToLower(strings.TrimPrefix(m.String(), "EM_"))
}

func peArch(m uint16) string {
	switch m {
	case pe.IMAGE_FILE_MACHINE_AMD64:
		return "x86-64"
	case pe.IMAGE_FILE_MACHINE_ARM64:
		return "arm64"
	case pe.IMAGE_FILE_MACHINE_I386:
		return "386"
	}
	return fmt.Sprintf("pe-%#x", m)
}

// --- Go build info (works for ELF, Mach-O and PE) ---

func goDigest(path string, d *Digest) bool {
	bi, err := buildinfo.ReadFile(path)
	if err != nil {
		return goBuildinfoFallback(path, d)
	}
	settings := make(map[string]string, len(bi.Settings))
	for _, s := range bi.Settings {
		settings[s.Key] = s.Value
	}
	parts := []string{bi.GoVersion}
	if osName, arch := settings["GOOS"], settings["GOARCH"]; osName != "" && arch != "" {
		parts = append(parts, osName+"/"+arch)
	}
	if settings["-trimpath"] != "" {
		parts = append(parts, "trimpath")
	}
	if rev := settings["vcs.revision"]; rev != "" {
		if len(rev) > 12 {
			rev = rev[:12]
		}
		if settings["vcs.modified"] == "true" {
			rev += "+dirty"
		}
		parts = append(parts, "rev:"+rev)
	}
	d.Toolchain = strings.Join(parts, " ")

	if bi.Main.Path != "" {
		d.Mod = bi.Main.Path
		if v := bi.Main.Version; v != "" && v != "(devel)" {
			d.Mod += " " + v
		}
	}

	seen := make(map[string]bool, len(bi.Deps))
	deps := make([]Dep, 0, len(bi.Deps))
	for _, dep := range bi.Deps {
		if dep == nil || dep.Path == "" || strings.HasPrefix(dep.Path, "internal/") {
			continue
		}
		key := dep.Path + "@" + dep.Version
		if seen[key] {
			continue
		}
		seen[key] = true
		deps = append(deps, Dep{Path: dep.Path, Version: dep.Version})
	}
	if len(deps) > maxDeps {
		d.Notes = append(d.Notes, fmt.Sprintf("deps truncated to %d of %d", maxDeps, len(deps)))
		deps = deps[:maxDeps]
	}
	d.Deps = deps
	deepNote(d, "embedded build-info block holds module graph and build flags; function-name table maps code addresses back to Go source positions")
	return true
}

// Go build-info blob header (R7 in notes-r.md): the magic is 14 bytes, then
// ptrSize, flags, and a fixed 32-byte header. Only the header is read here: the
// module body is either a second inline varint string or, before Go 1.18, a pair
// of virtual addresses this reader cannot resolve without a section map.
var goBuildInfoMagic = []byte("\xff Go buildinf:")

// goBuildIDMarker is the build id note text. It survives in Go builds that carry
// no build-info blob at all, which is what separates "Go without build info" from
// "not a Go binary".
var goBuildIDMarker = []byte("\xff Go build ID:")

const (
	goBuildInfoHeaderSize = 32
	goInfoEndianBig       = 0x1 // flags bit0: pointer form stores uintptr big-endian
	goInfoVersionInline   = 0x2 // flags bit1: version and module body follow the header as varint strings

	// shortcut: the scan stops at 32 MB, so a blob past that window reads as
	// absent; upgrade to a section-addressed read if a real target shows that.
	maxGoInfoScan = 32 << 20
)

// goBuildinfoFallback answers for the builds debug/buildinfo refuses instead of
// leaving the digest empty: a Go 1.18-1.20 plugin/-linkshared build has pclntab
// and a build id but no blob, and a blob the stdlib rejects still proves what its
// header says. The module graph is never guessed: it stays unknown.
func goBuildinfoFallback(path string, d *Digest) bool {
	b := head(path, maxGoInfoScan)
	// Every branch below needs the build id note: without it the name is not
	// proof of a Go build, and claiming a foreign binary would hide its findings.
	if !bytes.Contains(b, goBuildIDMarker) {
		return false
	}
	i := bytes.Index(b, goBuildInfoMagic)
	if i < 0 {
		d.skip("buildinfo-absent", "Go build without a build-info blob (plugin/-linkshared from Go 1.18-1.20); module graph and toolchain are not in the file")
		return true
	}
	hdr := parseGoBuildinfoHeader(b[i+len(goBuildInfoMagic):])
	switch {
	case hdr.cut:
		d.skip("buildinfo-header-truncated", fmt.Sprintf("build-info magic at 0x%x ends within the %d-byte scan window", i, len(b)))
		return true
	case !hdr.ok:
		d.skip("buildinfo-absent", fmt.Sprintf("bytes at 0x%x hold the magic but not a well-formed header (ptrSize %d, flags %#x)", i, hdr.ptrSize, hdr.flags))
		return true
	}

	d.Toolchain = hdr.version
	if d.Toolchain == "" {
		d.Toolchain = "unknown" // pointer form: the string lives at a VA, not in the header
	}
	d.Capabilities = append(d.Capabilities,
		"go:buildinfo=header-only",
		fmt.Sprintf("go:ptr_size=%d", hdr.ptrSize),
		"go:endian="+hdr.endian,
		fmt.Sprintf("go:buildinfo_flags=%#02x", hdr.flags),
	)
	if hdr.version != "" {
		d.Capabilities = append(d.Capabilities, "go:version="+hdr.version)
	}
	d.Mod = "unknown"
	deepNote(d, "read the build-info header in place; the module graph needs the linker's blob, so map the pointer-form string addresses through the loaded segments before claiming a dependency list")
	return true
}

// goBuildinfoHeader is what the blob's own 32-byte header proves. version is
// empty for the pointer form, whose strings are addressed rather than inline.
type goBuildinfoHeader struct {
	ptrSize int
	flags   byte
	version string
	endian  string
	cut     bool // the header ended early: a truncation, not a foreign blob
	ok      bool
}

func parseGoBuildinfoHeader(h []byte) goBuildinfoHeader {
	if len(h) < 2 {
		return goBuildinfoHeader{cut: true}
	}
	out := goBuildinfoHeader{ptrSize: int(h[0]), flags: h[1], endian: "unknown"}
	// Everything after the magic: ptrSize, flags, then pointer slots or padding.
	tail := goBuildInfoHeaderSize - len(goBuildInfoMagic)
	if len(h) < tail {
		out.cut = true
		return out
	}
	if out.ptrSize != 4 && out.ptrSize != 8 || out.flags&^0x03 != 0 {
		return out
	}
	if out.flags&goInfoVersionInline == 0 {
		out.endian = "little" // pointer form: flags bit0 selects the uintptr order
		if out.flags&goInfoEndianBig != 0 {
			out.endian = "big"
		}
		out.ok = true
		return out
	}
	n, k := binary.Uvarint(h[tail:])
	if k <= 0 || n == 0 || n > uint64(len(h)-tail-k) {
		out.cut = true
		return out
	}
	version := string(h[tail+k : tail+k+int(n)])
	if !strings.HasPrefix(version, "go") {
		return out // magic in a foreign blob
	}
	out.version, out.ok = version, true
	return out
}

// --- Rust: detection plus the crate list recovered from embedded registry paths ---

// maxRustCrates bounds the reported dependency list. maxRustCrateScan bounds the
// byte window searched for registry paths, which sit in read-only data.
const (
	maxRustCrates    = 64
	maxRustCrateScan = 32 << 20
	// rustModUnknown keeps `mod` non-empty when no symbol table names the user
	// crate. It is a refusal, not a guessed module name.
	rustModUnknown = "crate name not in metadata"
)

func rustDigest(path string, d *Digest) {
	var ver string
	var found bool
	switch d.Kind {
	case "elf":
		ver, found = rustELF(path)
	case "macho":
		ver, found = rustMachO(path)
	case "pe":
		ver, found = rustPanicScan(path)
	}
	if !found {
		return
	}
	if ver != "" {
		d.Toolchain = "rustc " + ver
	} else {
		d.Toolchain = "rustc (version not in metadata)"
	}
	// The module is the user crate that owns `main`; rustsym fills it when the
	// symbol table names that function. Without a table the honest answer is
	// still non-empty, so a reader sees "not in metadata" rather than guessing.
	d.Mod = rustModUnknown
	refs := rustCrateRefs(path)
	deps := rustDepListFromRefs(refs)
	if len(deps) > maxDeps {
		d.Notes = append(d.Notes, fmt.Sprintf("deps truncated to %d of %d", maxDeps, len(deps)))
		deps = deps[:maxDeps]
	}
	if len(deps) > 0 { // no path evidence stays null: "not in metadata", not "no deps"
		d.Deps = deps
	}
	crates := rustCrateListFromRefs(refs)
	if len(crates) == 0 {
		deepNote(d, "Rust build whose crate list is stripped or unavailable; source lockfile holds exact dependency graph")
		return
	}
	d.RustCrates = capped(d, "crates", crates, maxRustCrates)
	deepNote(d, "crate registry source paths embedded in binary list every crate and version; source lockfile holds exact dependency graph")
}

// rustCrateRef is one "<crate>-<version>" directory recovered from a cargo
// source path. The name keeps embedded '-'s; only the last dash before a digit
// separates the version.
type rustCrateRef struct {
	name, version string
}

// rustCrateRefs finds cargo source paths in both layouts: the registry cache
// (registry/src/<registry>/<crate>-<version>/src/...) and a vendored/deps tree
// (deps/<crate>-<version>/src/...). The crate directory is the first component
// after the layout prefix, except in the registry layout where the registry
// directory itself comes first.
func rustCrateRefs(path string) []rustCrateRef {
	b := head(path, maxRustCrateScan)
	var out []rustCrateRef
	seen := map[string]bool{}
	layouts := []struct {
		sep  string
		skip int
	}{
		{"registry/src/", 1},
		{`registry\src\`, 1},
		{"deps/", 0},
		{`deps\`, 0},
	}
	for _, layout := range layouts {
		sl := layout.sep[len(layout.sep)-1]
		for i := 0; ; {
			j := bytes.Index(b[i:], []byte(layout.sep))
			if j < 0 {
				break
			}
			p := i + j + len(layout.sep)
			for n := 0; n < layout.skip; n++ {
				k := bytes.IndexByte(b[p:], sl)
				if k < 0 {
					p = -1
					break
				}
				p += k + 1
			}
			if p < 0 {
				break
			}
			e := bytes.IndexByte(b[p:], sl)
			if e < 0 {
				break
			}
			dir := string(b[p : p+e])
			if name, version, ok := rustSplitCrate(dir); ok {
				key := name + "-" + version
				if !seen[key] {
					seen[key] = true
					out = append(out, rustCrateRef{name: name, version: version})
				}
			}
			i = p + e + 1
		}
	}
	slices.SortFunc(out, func(a, b rustCrateRef) int {
		if c := strings.Compare(a.name, b.name); c != 0 {
			return c
		}
		return strings.Compare(a.version, b.version)
	})
	return out
}

func rustDepListFromRefs(refs []rustCrateRef) []Dep {
	deps := make([]Dep, 0, len(refs))
	for _, ref := range refs {
		deps = append(deps, Dep{Path: ref.name, Version: ref.version})
	}
	return deps
}

// rustCrateList returns "<crate>-<version>" for every cargo source path
// embedded in the binary, as in
// .cargo/registry/src/index.crates.io-<hash>/<crate>-<version>/src/lib.rs or
// /rust/deps/<crate>-<version>/src/lib.rs. Both separators are handled.
func rustCrateList(path string) []string {
	return rustCrateListFromRefs(rustCrateRefs(path))
}

func rustCrateListFromRefs(refs []rustCrateRef) []string {
	out := make([]string, 0, len(refs))
	for _, ref := range refs {
		out = append(out, ref.name+"-"+ref.version)
	}
	return out
}

// rustSplitCrate splits "<crate>-<version>" at the last '-' before a digit;
// crate names contain '-', versions start with a digit.
func rustSplitCrate(dir string) (string, string, bool) {
	for i := len(dir) - 2; i > 0; i-- {
		if dir[i] == '-' && dir[i+1] >= '0' && dir[i+1] <= '9' {
			return dir[:i], dir[i+1:], true
		}
	}
	return "", "", false
}

// rustPanicScan is the fallback for formats without a rustc section and for PE:
// the panic handler string (or a producer string) is the in-process marker.
func rustPanicScan(path string) (string, bool) {
	b := head(path, maxSniff)
	if !bytes.Contains(b, []byte("rust_panic")) && !bytes.Contains(b, []byte("rustc version ")) {
		return "", false
	}
	return rustVersion(b), true
}

func rustELF(path string) (string, bool) {
	f, err := elf.Open(path)
	if err != nil {
		return "", false
	}
	defer f.Close()
	var ver string
	found := false
	if s := f.Section(".comment"); s != nil {
		ver = rustVersion(sectionHead(s))
	}
	if s := f.Section(".rustc"); s != nil {
		found = true
		if ver == "" {
			ver = rustVersion(sectionHead(s))
		}
	}
	if s := f.Section(".dep-v0"); s != nil {
		found = true
		if ver == "" {
			ver = rustVersion(zlibHead(s))
		}
	}
	return ver, found || ver != ""
}

func rustMachO(path string) (string, bool) {
	var files []*macho.File
	if ff, err := macho.OpenFat(path); err == nil {
		defer ff.Close()
		for _, a := range ff.Arches {
			files = append(files, a.File)
		}
	} else if f, err := macho.Open(path); err == nil {
		defer f.Close()
		files = append(files, f)
	} else {
		return "", false
	}
	for _, f := range files {
		for _, s := range f.Sections {
			if strings.Contains(strings.ToLower(s.Name+s.Seg), "rustc") {
				return "", true
			}
		}
	}
	// No rustc section: one bounded window for the panic handler / version string.
	return rustPanicScan(path)
}

var rustMarkers = [][]byte{
	[]byte("rustc version "),
	[]byte(`"rustc_semver":"`),
	[]byte(`"rustc_version":"`),
}

func rustVersion(b []byte) string {
	for _, m := range rustMarkers {
		_, after, ok := bytes.Cut(b, m)
		if !ok {
			continue
		}
		s := after
		end := len(s)
		for j := range s {
			switch s[j] {
			case 0, ' ', '\n', '(', '"', ',':
				end = j
			}
			if end == j {
				break
			}
		}
		v := strings.TrimSpace(string(s[:end]))
		if v != "" && v[0] >= '0' && v[0] <= '9' {
			return v
		}
	}
	return ""
}

// elf.Section.Open returns an io.ReadSeeker (no Close); LimitReader bounds it.
func sectionHead(s *elf.Section) []byte {
	b, _ := io.ReadAll(io.LimitReader(s.Open(), maxSection))
	return b
}

// zlibHead decompresses at most maxSection bytes; .dep-v0 is zlib-compressed.
func zlibHead(s *elf.Section) []byte {
	zr, err := zlib.NewReader(s.Open())
	if err != nil {
		return nil
	}
	defer zr.Close()
	b, _ := io.ReadAll(io.LimitReader(zr, maxSection))
	return b
}

func head(path string, max int64) []byte {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	b, _ := io.ReadAll(io.LimitReader(f, max))
	return b
}

// --- list helpers ---

func uniqued(in []string) []string {
	seen := make(map[string]bool, len(in))
	// Non-nil from the start: every caller puts this straight into a JSON
	// array field, and nil marshals to null while the contract says array.
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

func basenames(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = base(s)
	}
	return out
}

func capped(d *Digest, what string, list []string, max int) []string {
	if len(list) <= max {
		return list
	}
	d.Notes = append(d.Notes, fmt.Sprintf("%s truncated to %d of %d", what, max, len(list)))
	return list[:max]
}

// --- deep scan: the symbol table is read here, machine code is left to the
// engine that already owns it (the Go toolchain for Go binaries, Ghidra for
// everything else) ---

// isGoBinary is the honest test for "may have pclntab names": a Go binary
// carries buildinfo. Scanning for the section magic lied — Homebrew's gh has
// the section name but no resolvable functions, so the name test must be the
// toolchain itself.
func isGoBinary(path string) bool {
	bi, err := buildinfo.ReadFile(path)
	return err == nil && bi != nil
}

// objdumpViaPclntab disassembles one function by name through the Go toolchain,
// which resolves names from pclntab even when the symbol table was stripped.
func objdumpViaPclntab(path, symbol string) (string, error) {
	ctx, cancel := rtCtx()
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "tool", "objdump", "-s", symbol, path)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("%w: %s", err, strings.TrimSpace(stderr.String()))
	}
	if strings.TrimSpace(string(out)) == "" {
		return "", fmt.Errorf("go tool objdump -s %s matched nothing", symbol)
	}
	return capLines(string(out)), nil
}

// DeepScan answers one symbol without a host disassembler. The symbol table is
// read in-process (objectsyms.go), so a stripped file, a misspelt name and a
// data symbol stay three different answers. A Go binary is then disassembled by
// the toolchain, which also survives -s -w; anything else hands the symbol to
// the Ghidra op that owns native code, because a second x86/ARM decoder living
// in this binary would be a new liability, not a dependency reduction.
func DeepScan(path, symbol string) (string, error) {
	if symbol == "" {
		return "", fmt.Errorf("--deep needs a symbol name")
	}
	syms, err := objectSymbolTable(path)
	if err != nil {
		return "", fmt.Errorf("--deep cannot read the symbol table of %s: %w", path, err)
	}
	if len(syms) == 0 {
		if out, ok := deepPclntabFallback(path, symbol); ok {
			return out, nil
		}
		return "", fmt.Errorf("stripped: %s has no symbol table, so --deep cannot resolve %q; set LRECON_AT to an address and run --op procedure_assembly instead", path, symbol)
	}
	hit, ok := findObjectSymbol(syms, symbol)
	if !ok {
		if out, ok := deepPclntabFallback(path, symbol); ok {
			return out, nil
		}
		return "", fmt.Errorf("no symbol table entry %q in %s (%d symbols; check the spelling)", symbol, path, len(syms))
	}
	if hit.Kind != 'T' {
		// A data or undefined symbol has no body to disassemble; the table line is
		// the whole truthful answer.
		return hit.line() + "\n", nil
	}
	// objdump also needs the symbol table (measured: `-s -w` gives "no symbol
	// section" on ELF and "no runtime.pclntab symbol found" on PE), so the gate
	// above is what makes a Go binary's names resolvable at all.
	if isGoBinary(path) {
		out, err := objdumpViaPclntab(path, symbol)
		if err == nil && strings.TrimSpace(out) != "" {
			return strings.TrimRight(out, "\n") + "\n" + deepToolchainHandoff(path, hit), nil
		}
		if err != nil {
			// The engine could not run: say so instead of pretending the
			// in-process answer is the whole one. A caller under a bare PATH
			// (`env -i PATH=/usr/bin:/bin`) has no `go` tool at all.
			return fmt.Sprintf("go tool objdump did not run: %v\n%s", err, deepRedirect(path, hit)), nil
		}
	}
	return deepRedirect(path, hit), nil
}

// findObjectSymbol matches the bare name and the Mach-O spelling: a C symbol
// carries a leading '_', so `--deep bump` and `--deep _bump` must agree. Both
// sides lose the underscore, otherwise the spelling of the query decides.
func findObjectSymbol(syms []objectSymbol, symbol string) (objectSymbol, bool) {
	bare := strings.TrimPrefix(symbol, "_")
	for _, s := range syms {
		if s.Name == symbol || strings.TrimPrefix(s.Name, "_") == bare {
			return s, true
		}
	}
	return objectSymbol{}, false
}

// deepPclntabFallback resolves a symbol from pclntab when the symbol table
// cannot (stripped or entry absent): names survive -s -w. The function body
// is emitted as a hex dump at its file offset plus the Ghidra handoff, since
// no in-process decoder exists. Never a fake body, never an empty answer.
func deepPclntabFallback(path, symbol string) (string, bool) {
	if !isGoBinary(path) {
		return "", false
	}
	fns, err := goFunctions(path)
	if err != nil || len(fns) == 0 {
		return "", false
	}
	bare := strings.TrimPrefix(symbol, "_")
	if bare == "main" {
		bare = "main.main"
	}
	var hit *nativeFunc
	for i := range fns {
		if fns[i].Name == bare || fns[i].Name == symbol {
			hit = &fns[i]
			break
		}
	}
	if hit == nil || hit.End <= hit.Start {
		return "", false
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "%s %s-%s\n", hit.Name, nativeHexAddr(hit.Start), nativeHexAddr(hit.End))
	if off, sec, _ := mapAddress(path, hit.Start); sec != nil {
		n := min(hit.End-hit.Start, 4096)
		if b, err := nativeReadAt(path, off, n); err == nil && len(b) > 0 {
			sb.WriteString(nativeHexDump(b))
		}
	}
	fmt.Fprintf(&sb, "deep: resolved from pclntab (stripped: no symbol table); disassembly is one Ghidra op away:\n  LRECON_AT=%s lrecon --op procedure_assembly %s\n", nativeHexAddr(hit.Start), path)
	return sb.String(), true
}

// deepRedirect is the honest answer for a symbol this binary cannot decode: the
// table line says what the symbol is, and the retained Ghidra op prints the
// instructions. Never a fake body, never a silent empty answer.
func deepRedirect(path string, s objectSymbol) string {
	return fmt.Sprintf("%s\ndeep: %s carries no machine-code decoder; the symbol table is read in-process, so disassembly is one Ghidra op away:\n  LRECON_NAME=%s lrecon --op procedure_assembly %s\n",
		s.line(), filepath.Base(path), strings.TrimPrefix(s.Name, "_"), path)
}

// deepToolchainHandoff follows the Go toolchain's disassembly with the same
// addressable next step. The Go toolchain did decode these bytes, so this hint
// never repeats the "no decoder" claim the non-Go branch makes.
func deepToolchainHandoff(path string, s objectSymbol) string {
	return fmt.Sprintf("deep: disassembled by the Go toolchain from pclntab; the same function is one Ghidra op away:\n  LRECON_NAME=%s lrecon --op procedure_assembly %s\n",
		strings.TrimPrefix(s.Name, "_"), path)
}

// capLines keeps the first maxDeep lines and says how much was dropped.
func capLines(out string) string {
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) > maxDeep {
		lines = append(lines[:maxDeep], fmt.Sprintf("... truncated to %d of %d lines", maxDeep, len(lines)))
	}
	return strings.Join(lines, "\n") + "\n"
}
