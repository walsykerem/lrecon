package main

import (
	"debug/elf"
	"debug/gosym"
	"debug/macho"
	"encoding/binary"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"
)

// A skeleton interval is a byte range the linker itself called code. It is not
// a "function": ICF, thunks and cold splits make that identity unprovable from
// the file, so the vocabulary stays at interval and pointer_edge.
type interval struct {
	start, end uint64
}

// Skeleton is the one merged table: which linker source claimed which bytes of
// the executable sections. Ratio is nil when nothing was readable, so an
// unknown answer never prints as 0% or 100%.
type Skeleton struct {
	Sources []string `json:"sources,omitempty"`
	// Named counts functions whose name the pclntab gave; it feeds Digest.Names
	// and stays out of the JSON to keep the contract unchanged.
	Named      int      `json:"-"`
	Arch       string   `json:"arch,omitempty"`
	Intervals  int      `json:"intervals"`
	TextBytes  uint64   `json:"text_bytes"`
	Attributed uint64   `json:"attributed_bytes"`
	Ratio      *float64 `json:"attributed_ratio,omitempty"`
	Residual   uint64   `json:"residual_bytes"`
	Status     string   `json:"status"`
	Note       string   `json:"note,omitempty"`
	// ChainedFixups records LC_DYLD_CHAINED_FIXUPS presence only; its payload is
	// not parsed, so pointer edges are not claimed here.
	ChainedFixups bool `json:"chained_fixups,omitempty"`
}

const (
	skelOK      = "ok"
	skelPartial = "partial"
	skelUnknown = "empty" // no attribution: the digest contract allows only ok/partial/empty
)

// maxIntervals is the one cap every linker table may fill: a 16 MB payload can
// claim tens of millions of records, and the file owner must not be able to
// spend the analyser's memory that way.
const maxIntervals = 1 << 20

var errIntervalsCapped = fmt.Errorf("func-starts-capped at %d intervals", maxIntervals)

func resolveSkeleton(path string, d *Digest) *Skeleton {
	var s *Skeleton
	switch d.Kind {
	case "macho":
		s = machoSkeleton(path, d.Format == "fat")
	case "elf":
		s = elfSkeleton(path)
	default:
		return nil
	}
	if s != nil && s.Named > 0 {
		d.Names = fmt.Sprintf("pclntab:%d", s.Named)
	}
	return s
}

func (s *Skeleton) line() string {
	if s.Status == skelUnknown || s.Ratio == nil {
		reason := s.Note
		if reason == "" {
			reason = "no unwind table or symbol source in file"
		}
		return "skeleton: unknown (" + reason + ")"
	}
	line := fmt.Sprintf("skeleton: %d intervals, %d/%d text bytes attributed (%.1f%%), sources %s",
		s.Intervals, s.Attributed, s.TextBytes, *s.Ratio*100, strings.Join(s.Sources, "+"))
	if s.Note != "" {
		line += "; " + s.Note
	}
	return line
}

// finish clamps the claims into the executable ranges, counts overlaps once and
// leaves the ratio nil when no source produced anything.
func (s *Skeleton) finish(iv, text []interval, skipped []string) *Skeleton {
	for _, t := range text {
		s.TextBytes += t.end - t.start
	}
	kept, sum := clampUnion(iv, text)
	s.Intervals = len(kept)
	if len(kept) == 0 || s.TextBytes == 0 {
		s.Status = skelUnknown
		s.Residual = s.TextBytes
		if s.TextBytes == 0 {
			s.Note = "no executable section in file"
		} else if len(skipped) > 0 {
			s.Note = strings.Join(skipped, "; ")
		}
		return s
	}
	r := float64(sum) / float64(s.TextBytes)
	s.Ratio = &r
	s.Attributed = sum
	s.Residual = s.TextBytes - sum
	if len(skipped) > 0 {
		s.Status = skelPartial
		s.Note = strings.Join(skipped, "; ")
	} else {
		s.Status = skelOK
	}
	return s
}

// clampUnion intersects every claim with the executable ranges and merges what
// is left, so an overlapping CIE and start-table claim is counted once. The
// executable ranges are merged once, then every claim is a binary search, so a
// multi-section ELF cannot turn this into |intervals| x |sections|.
func clampUnion(iv, text []interval) ([]interval, uint64) {
	var textMerged []interval
	for _, t := range text {
		if n := len(textMerged); n > 0 && t.start <= textMerged[n-1].end {
			if t.end > textMerged[n-1].end {
				textMerged[n-1].end = t.end
			}
			continue
		}
		textMerged = append(textMerged, t)
	}
	var kept []interval
	for _, in := range iv {
		i := sort.Search(len(textMerged), func(i int) bool { return textMerged[i].end > in.start })
		for ; i < len(textMerged) && textMerged[i].start < in.end; i++ {
			t := textMerged[i]
			lo, hi := in.start, in.end
			if lo < t.start {
				lo = t.start
			}
			if hi > t.end {
				hi = t.end
			}
			if lo < hi {
				kept = append(kept, interval{lo, hi})
			}
		}
	}
	sort.Slice(kept, func(i, j int) bool { return kept[i].start < kept[j].start })
	var out []interval
	for _, k := range kept {
		// Only true overlaps merge; touching intervals stay separate so the
		// count keeps the linker's own split.
		if n := len(out); n > 0 && k.start < out[n-1].end {
			if k.end > out[n-1].end {
				out[n-1].end = k.end
			}
			continue
		}
		out = append(out, k)
	}
	var sum uint64
	for _, k := range out {
		sum += k.end - k.start
	}
	return out, sum
}

// --- ELF: .eh_frame CIE/FDE records ---

func elfSkeleton(path string) *Skeleton {
	s := &Skeleton{Status: skelUnknown}
	f, err := elf.Open(path)
	if err != nil {
		s.Note = err.Error()
		return s
	}
	defer f.Close()
	s.Arch = elfArch(f.Machine)
	var fileSize int64
	if st, serr := os.Stat(path); serr == nil {
		fileSize = st.Size()
	}
	text := elfTextRanges(f, fileSize)
	var skipped []string
	var hdrAddr uint64
	if h := f.Section(".eh_frame_hdr"); h != nil {
		hdrAddr = h.Addr
	}

	// A Go binary names its own code; pclntab wins over any unwind table.
	if isGoBinary(path) {
		if pcln, start, ok := elfPclntab(f, fileSize); ok {
			if iv, named := goIntervals(pcln, start); len(iv) > 0 {
				s.Sources, s.Named = []string{"pclntab"}, named
				return s.finish(iv, text, nil)
			}
			skipped = append(skipped, "pclntab: empty symbol table")
		} else {
			skipped = append(skipped, "pclntab: section not found")
		}
	}

	iv, bad, err := elfFrames(f, hdrAddr)
	switch {
	case err != nil:
		skipped = append(skipped, "eh_frame: "+err.Error())
	case bad > 0:
		skipped = append(skipped, fmt.Sprintf("eh_frame: %d records skipped (unsupported encoding)", bad))
	}
	if len(iv) == 0 && len(skipped) == 0 {
		skipped = append(skipped, "no .eh_frame section")
	}
	if len(iv) > 0 {
		s.Sources = []string{"eh_frame"}
	}
	return s.finish(iv, text, skipped)
}

func elfTextRanges(f *elf.File, fileSize int64) []interval {
	var out []interval
	for _, s := range f.Sections {
		if s.Flags&elf.SHF_EXECINSTR == 0 || s.Size == 0 {
			continue
		}
		size := s.Size
		if fileSize > 0 {
			if s.Offset >= uint64(fileSize) {
				size = 0
			} else if avail := uint64(fileSize) - s.Offset; size > avail {
				size = avail
			}
		}
		if size == 0 {
			continue
		}
		out = append(out, interval{s.Addr, s.Addr + size})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].start < out[j].start })
	return out
}

func elfPclntab(f *elf.File, fileSize int64) ([]byte, uint64, bool) {
	for _, name := range []string{".gopclntab", ".data.rel.ro.gopclntab"} {
		sec := f.Section(name)
		if sec == nil {
			continue
		}
		b, err := sec.Data()
		if err != nil || len(b) == 0 {
			continue
		}
		start := uint64(0)
		if t := f.Section(".text"); t != nil {
			start = t.Addr
		} else if r := elfTextRanges(f, fileSize); len(r) > 0 {
			start = r[0].start
		}
		if start == 0 {
			continue
		}
		return b, start, true
	}
	return nil, 0, false
}

// elfFrames walks .eh_frame: CIEs carry the pointer encoding, FDEs carry
// (start, range). Any encoding outside absptr/udata4/sdata4 is counted, never
// guessed, so a half-read table is reported as partial.
func elfFrames(f *elf.File, hdrAddr uint64) ([]interval, int, error) {
	sec := f.Section(".eh_frame")
	if sec == nil {
		return nil, 0, nil
	}
	data, err := sec.Data()
	if err != nil {
		return nil, 0, err
	}
	bo, word := f.ByteOrder, 8
	if f.Class == elf.ELFCLASS32 {
		word = 4
	}

	// First pass: CIE offset -> FDE pointer encoding. CIE records can follow
	// FDEs in the section only for other FDEs, so collecting them up front is
	// what keeps the second pass order-free.
	cies := make(map[uint64]byte)
	bad := 0
	for off := 0; off+4 <= len(data); {
		length := bo.Uint32(data[off:])
		if length == 0 || length == 0xffffffff {
			break
		}
		end := off + 4 + int(length)
		if end > len(data) || end < off+8 {
			bad++
			break
		}
		if bo.Uint32(data[off+4:]) == 0 {
			if enc, ok := cieEnc(data[off+8:end], bo, word); ok {
				cies[uint64(off)] = enc
			} else {
				bad++
			}
		}
		off = end
	}

	var out []interval
	for off := 0; off+4 <= len(data); {
		length := bo.Uint32(data[off:])
		if length == 0 || length == 0xffffffff {
			break
		}
		end := off + 4 + int(length)
		if end > len(data) || end < off+8 {
			break
		}
		if cieID := bo.Uint32(data[off+4:]); cieID != 0 {
			iv, ok := fdeAt(data[off:end], off, sec.Addr, hdrAddr, cies, bo, word)
			if ok {
				out = append(out, iv)
				if len(out) >= maxIntervals {
					return out, bad, errIntervalsCapped
				}
			} else {
				bad++
			}
		}
		off = end
	}
	return out, bad, nil
}

// fdeAt reads one FDE body. off is the record's offset in the section, so a
// pcrel start resolves against its own file address.
func fdeAt(rec []byte, off int, secAddr, hdrAddr uint64, cies map[uint64]byte, bo binary.ByteOrder, word int) (interval, bool) {
	cieID := bo.Uint32(rec[4:])
	cieOff := uint64(off+4) - uint64(cieID)
	enc, ok := cies[cieOff]
	if !ok || len(rec) < 9 {
		return interval{}, false
	}
	if enc&0x70 == 0x30 && hdrAddr == 0 {
		return interval{}, false // datarel needs the eh_frame_hdr base; do not guess
	}
	// FDE body starts with initial_location, then address_range; the
	// augmentation length only follows those and is not needed here.
	start, n, ok := ehValue(enc, rec[8:], secAddr+uint64(off)+8, hdrAddr, bo, word)
	if !ok {
		return interval{}, false
	}
	p := 8 + n
	size, _, ok := ehValue(enc&0x0f, rec[p:], 0, 0, bo, word)
	if !ok || size == 0 {
		return interval{}, false
	}
	return interval{start, start + size}, true
}

// cieEnc returns the FDE pointer encoding from a CIE body (past the id field).
func cieEnc(b []byte, bo binary.ByteOrder, word int) (byte, bool) {
	if len(b) < 4 || b[0] != 1 { // DWARF2/3 only; version 4 changes the layout
		return 0, false
	}
	z := strings.IndexByte(string(b[1:]), 0)
	if z < 0 {
		return 0, false
	}
	aug := string(b[1 : 1+z])
	p := 2 + z
	if _, w := uleb128(b[p:]); w == 0 {
		return 0, false
	} else {
		p += w
	}
	if _, w := sleb128(b[p:]); w == 0 {
		return 0, false
	} else {
		p += w
	}
	if _, w := uleb128(b[p:]); w == 0 {
		return 0, false
	} else {
		p += w
	}
	if !strings.HasPrefix(aug, "z") {
		return 0x00, true
	}
	alen, w := uleb128(b[p:])
	if w == 0 {
		return 0, false
	}
	p += w
	end := p + int(alen)
	if end > len(b) {
		return 0, false
	}
	for _, c := range aug[1:] {
		switch c {
		case 'R':
			if p < end {
				return b[p], true
			}
			return 0, false
		case 'P':
			if p >= end {
				return 0, false
			}
			enc := b[p]
			_, n, ok := ehValue(enc, b[p+1:end], 0, 0, bo, word)
			if !ok {
				return 0, false
			}
			p += 1 + n
		case 'L':
			p++
		}
		if p > end {
			return 0, false
		}
	}
	return 0x00, true
}

// ehValue decodes DW_EH_PE_absptr, udata4 and sdata4 with an absolute,
// pcrel or datarel application. Everything else is rejected on purpose.
func ehValue(enc byte, b []byte, fieldAddr, datarel uint64, bo binary.ByteOrder, word int) (uint64, int, bool) {
	format, app := enc&0x0f, enc&0x70
	var raw int64
	var n int
	switch format {
	case 0x00:
		n = word
		if len(b) < n {
			return 0, 0, false
		}
		if word == 8 {
			raw = int64(bo.Uint64(b))
		} else {
			raw = int64(bo.Uint32(b))
		}
	case 0x03:
		n = 4
		if len(b) < n {
			return 0, 0, false
		}
		raw = int64(bo.Uint32(b))
	case 0x0b:
		n = 4
		if len(b) < n {
			return 0, 0, false
		}
		raw = int64(int32(bo.Uint32(b)))
	default:
		return 0, 0, false
	}
	switch app {
	case 0x00:
	case 0x10:
		raw += int64(fieldAddr)
	case 0x30:
		raw += int64(datarel)
	default:
		return 0, 0, false
	}
	return uint64(raw), n, true
}

func sleb128(b []byte) (int64, int) {
	var v int64
	var shift uint
	for i := 0; i < len(b) && i < 10; i++ {
		c := b[i]
		v |= int64(c&0x7f) << shift
		shift += 7
		if c&0x80 == 0 {
			if shift < 64 && c&0x40 != 0 {
				v |= -1 << shift
			}
			return v, i + 1
		}
	}
	return 0, 0
}

// --- Mach-O: LC_FUNCTION_STARTS ---

func machoSkeleton(path string, fat bool) *Skeleton {
	s := &Skeleton{Status: skelUnknown}
	var f *macho.File
	var base int64
	if fat {
		pf, err := macho.OpenFat(path)
		if err != nil {
			s.Note = err.Error()
			return s
		}
		defer pf.Close()
		if len(pf.Arches) == 0 {
			s.Note = "fat file declares no slices"
			return s
		}
		// The digest describes the slice this machine would load, not slice 0:
		// on arm64 an x86_64-first universal binary would otherwise report the
		// wrong arch, text size and symbol source.
		idx := 0
		for i, a := range pf.Arches {
			if machoArch(a.File.Cpu) == runtime.GOARCH || (runtime.GOARCH == "amd64" && machoArch(a.File.Cpu) == "x86-64") {
				idx = i
				break
			}
		}
		f, base = pf.Arches[idx].File, int64(pf.Arches[idx].Offset)
	} else {
		pf, err := macho.Open(path)
		if err != nil {
			s.Note = err.Error()
			return s
		}
		defer pf.Close()
		f = pf
	}
	s.Arch = machoArch(f.Cpu)
	var fileSize int64
	if st, serr := os.Stat(path); serr == nil {
		fileSize = st.Size()
	}
	text := machoText(f, fileSize, base)
	var skipped []string
	if fat {
		skipped = append(skipped, fmt.Sprintf("fat: slice %s only", machoArch(f.Cpu)))
	}
	for _, l := range f.Loads {
		raw := l.Raw()
		if len(raw) >= 4 && f.ByteOrder.Uint32(raw) == uint32(lcChainedFixups) {
			s.ChainedFixups = true
		}
	}

	if isGoBinary(path) {
		if pcln, start, ok := machoPclntab(f); ok {
			if iv, named := goIntervals(pcln, start); len(iv) > 0 {
				s.Sources, s.Named = []string{"pclntab"}, named
				return s.finish(iv, text, nil)
			}
			skipped = append(skipped, "pclntab: empty symbol table")
		} else {
			skipped = append(skipped, "pclntab: section not found")
		}
	}

	iv, found, err := functionStarts(path, base, f)
	switch {
	case err != nil:
		skipped = append(skipped, "LC_FUNCTION_STARTS: "+err.Error())
	case !found:
		skipped = append(skipped, "no LC_FUNCTION_STARTS")
	case len(iv) == 0:
		skipped = append(skipped, "LC_FUNCTION_STARTS: empty chain")
	}
	if len(iv) > 0 {
		s.Sources = []string{"func_starts"}
	}
	return s.finish(iv, text, skipped)
}

// machoText reports __text clipped to the bytes the file actually holds: a
// section header may claim gigabytes that are not on disk, and an unclipped
// size makes text_bytes (and the attributed ratio) describe a file that is not
// there. Offset is relative to the slice base in a fat file.
func machoText(f *macho.File, fileSize, base int64) []interval {
	sec := f.Section("__text")
	if sec == nil || sec.Size == 0 {
		return nil
	}
	size := uint64(sec.Size)
	if fileSize > 0 {
		avail := fileSize - base - int64(sec.Offset)
		if avail <= 0 {
			size = 0
		} else if size > uint64(avail) {
			size = uint64(avail)
		}
	}
	if size == 0 {
		return nil
	}
	return []interval{{sec.Addr, sec.Addr + size}}
}

func machoPclntab(f *macho.File) ([]byte, uint64, bool) {
	sec := f.Section("__gopclntab")
	text := f.Section("__text")
	if sec == nil || text == nil {
		return nil, 0, false
	}
	b, err := sec.Data()
	if err != nil || len(b) == 0 {
		return nil, 0, false
	}
	return b, text.Addr, true
}

// functionStarts walks the ULEB128 delta chain from the __TEXT vmaddr: each
// delta moves from the previous end, a zero ends the chain. Only the starts are
// stored, so each interval ends where the next one starts.
func functionStarts(path string, base int64, f *macho.File) ([]interval, bool, error) {
	bo := f.ByteOrder
	var off, size int64
	for _, l := range f.Loads {
		raw := l.Raw()
		if len(raw) < 16 || macho.LoadCmd(bo.Uint32(raw)) != lcFunctionStarts {
			continue
		}
		off, size = int64(bo.Uint32(raw[8:])), int64(bo.Uint32(raw[12:]))
		break
	}
	if size <= 0 {
		return nil, false, nil
	}
	if size > 16<<20 {
		return nil, true, fmt.Errorf("payload %d bytes refused", size)
	}
	fh, err := os.Open(path)
	if err != nil {
		return nil, true, err
	}
	defer fh.Close()
	b := make([]byte, size)
	if n, _ := fh.ReadAt(b, base+off); int64(n) != size {
		return nil, true, fmt.Errorf("payload truncated")
	}
	seg := f.Segment("__TEXT")
	if seg == nil {
		return nil, true, fmt.Errorf("no __TEXT segment")
	}
	var fileSize int64
	if st, serr := fh.Stat(); serr == nil {
		fileSize = st.Size()
	}
	text := machoText(f, fileSize, base)
	if len(text) == 0 {
		return nil, true, fmt.Errorf("no __TEXT,__text section")
	}
	addr := seg.Addr
	var starts []uint64
	capped := false
	for i := 0; i < len(b); {
		delta, w := uleb128(b[i:])
		if w == 0 {
			return nil, true, fmt.Errorf("bad ULEB128 at byte %d", i)
		}
		i += w
		if delta == 0 {
			break
		}
		addr += delta
		starts = append(starts, addr)
		if len(starts) >= maxIntervals {
			capped = true
			break
		}
	}
	var out []interval
	for i, st := range starts {
		end := text[0].end
		if i+1 < len(starts) {
			end = starts[i+1]
		}
		if st < text[0].start || st >= text[0].end {
			continue
		}
		if end > text[0].end {
			end = text[0].end
		}
		if st < end {
			out = append(out, interval{st, end})
		}
	}
	if capped {
		return out, true, errIntervalsCapped
	}
	return out, true, nil
}

// --- Go symbol table ---

// goIntervals also counts the funcs the table named: pclntab is a symbol table,
// so the names are there to be counted instead of thrown away.
func goIntervals(pcln []byte, textStart uint64) ([]interval, int) {
	tab, err := gosym.NewTable(nil, gosym.NewLineTable(pcln, textStart))
	if err != nil {
		return nil, 0
	}
	var out []interval
	named := 0
	for i := range tab.Funcs {
		fn := &tab.Funcs[i]
		if fn.End > fn.Entry {
			out = append(out, interval{fn.Entry, fn.End})
			if fn.Name != "" {
				named++
			}
		}
	}
	return out, named
}
