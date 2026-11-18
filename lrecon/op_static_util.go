package main

// Shared helpers for the STATIC ops. Only code used by two or more op files
// lives here; a helper used once stays next to its op.

import (
	"archive/zip"
	"bytes"
	"debug/elf"
	"debug/macho"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"os"
	"sort"
	"strings"
)

// opMaxFile bounds the whole-file reads the static ops do. A target past it is
// refused instead of silently cut, so no answer is built on a partial read.
const opMaxFile = 256 << 20

func opRead(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if st.IsDir() {
		return nil, fmt.Errorf("%s is a directory", path)
	}
	if st.Size() > max {
		return nil, fmt.Errorf("%s is %d bytes, over the %d-byte cap", path, st.Size(), max)
	}
	b, err := readExactly(f, st.Size())
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return b, nil
}

// readExactly reads exactly n bytes from r. A reader that stops early is an
// error, never a shorter slice: a parser handed the zero padding of an
// under-filled buffer answers from bytes the file does not have.
func readExactly(r io.Reader, n int64) ([]byte, error) {
	b := make([]byte, n)
	got, err := io.ReadFull(r, b)
	if err != nil {
		return nil, fmt.Errorf("short read: got %d of %d bytes", got, n)
	}
	return b, nil
}

func u16le(b []byte, o int) uint16 { return binary.LittleEndian.Uint16(b[o:]) }
func u32le(b []byte, o int) uint32 { return binary.LittleEndian.Uint32(b[o:]) }
func u64le(b []byte, o int) uint64 { return binary.LittleEndian.Uint64(b[o:]) }
func u16be(b []byte, o int) uint16 { return binary.BigEndian.Uint16(b[o:]) }
func u32be(b []byte, o int) uint32 { return binary.BigEndian.Uint32(b[o:]) }
func u64be(b []byte, o int) uint64 { return binary.BigEndian.Uint64(b[o:]) }

// cstr reads one NUL-terminated printable ASCII string.
func cstr(b []byte, off int) (string, bool) {
	if off < 0 || off >= len(b) {
		return "", false
	}
	end := bytes.IndexByte(b[off:], 0)
	if end <= 0 || end > 200 {
		return "", false
	}
	s := b[off : off+end]
	for _, c := range s {
		if c < 0x20 || c > 0x7e {
			return "", false
		}
	}
	return string(s), true
}

func printableASCII(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	for _, c := range b {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}

// blockEntropy is the Shannon entropy in bits/byte of each block, last block
// short. A zero-length input yields no blocks.
func blockEntropy(b []byte, block int) []float64 {
	if block <= 0 {
		return nil
	}
	out := make([]float64, 0, (len(b)+block-1)/block)
	for off := 0; off < len(b); off += block {
		end := min(off+block, len(b))
		var freq [256]int
		for _, c := range b[off:end] {
			freq[c]++
		}
		n := float64(end - off)
		h := 0.0
		for _, c := range freq {
			if c == 0 {
				continue
			}
			p := float64(c) / n
			h -= p * math.Log2(p)
		}
		out = append(out, math.Round(h*1000)/1000)
	}
	return out
}

// opPair splits a two-target argument: "<left>,<right>".
func opPair(path string) (string, string, error) {
	i := strings.IndexByte(path, ',')
	if i <= 0 || i == len(path)-1 {
		return "", "", fmt.Errorf("this op takes two targets: <left>,<right> (got %q)", path)
	}
	return path[:i], path[i+1:], nil
}

func uniqSorted(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// swiftImagesOf loads the Swift sections of a Mach-O (thin or fat) or ELF
// target, reusing the section walk the digest already owns.
func swiftImagesOf(path string) ([]swiftImage, int, error) {
	h := head(path, 8)
	switch {
	case isMachO(h) || isFatMachO(h):
		f, err := os.Open(path)
		if err != nil {
			return nil, 0, err
		}
		defer f.Close()
		imgs, bad := machoSwiftImages(f)
		if len(imgs) == 0 && bad == 0 {
			return nil, 0, fmt.Errorf("%s: Mach-O magic but no readable slice", path)
		}
		return imgs, bad, nil
	case bytes.HasPrefix(h, []byte("\x7fELF")):
		f, err := elf.Open(path)
		if err != nil {
			return nil, 0, err
		}
		defer f.Close()
		return []swiftImage{elfSwift(f)}, 0, nil
	}
	return nil, 0, formatRefusal(path, "is neither Mach-O nor ELF")
}

// swiftSectionCount counts the records of one canonical Swift section. A
// variable-length section (typeref, reflstr, fieldmd) has no record size, so its
// byte length is returned instead.
func swiftSectionCount(s swiftSec) (count, size int, ok bool) {
	size = swiftEntrySize[s.name]
	if size == 0 {
		return 0, len(s.data), true
	}
	n, aligned := swiftEntryCount(s.data, size)
	if !aligned {
		return 0, size, false
	}
	return n, size, true
}

// --- PE ---

// peDir is one data directory: an RVA and a byte size.
type peDir struct{ rva, size uint32 }

// --- ECMA-335 table stream ---

// cliView is the metadata table stream decoded into row-addressed slices. The
// digest reader keeps only the groups it prints; the member and interop ops
// need arbitrary rows, so they share this reader.
type cliView struct {
	md   cliMetadata
	rows [0x2D]int
	size [0x2D]int
	off  [0x2D]int
	data []byte
	hs   uint8
}

// opLoadJob is metaLoadJob plus the one thing an op must not swallow: a job
// document that parses as JSON but has the wrong shape for its fields (for
// example "deep": "yes") is the caller's input error, not an internal fault.
// metaLoadJob reports it as a raw encoding/json error, which the error
// classifier cannot place, so the kind would come out as "internal".
func opLoadJob(path string) (metaJob, error) {
	job, err := metaLoadJob(path)
	if err != nil {
		return job, fmt.Errorf("%s is not a job document: %w", path, err)
	}
	return job, nil
}

func openCLIView(path string) (*cliView, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	img, ok := openPEImage(f)
	if !ok {
		return nil, fmt.Errorf("not a PE image")
	}
	if img.cliRVA == 0 || img.cliSize == 0 {
		return nil, fmt.Errorf("%s carries no CLI header, so there is no managed metadata to read", path)
	}
	blob, ok := img.at(img.cliRVA, img.cliSize)
	if !ok {
		return nil, fmt.Errorf("CLI header at RVA %#x is outside every section", img.cliRVA)
	}
	if len(blob) < 16 {
		return nil, fmt.Errorf("CLI header is not 16 bytes long")
	}
	metaRVA := u32le(blob, 8)
	metaSize := u32le(blob, 12)
	meta, ok := img.at(metaRVA, metaSize)
	if !ok {
		return nil, fmt.Errorf("metadata root at RVA %#x is outside every section", metaRVA)
	}
	md, ok := parseMetadata(meta)
	if !ok {
		return nil, fmt.Errorf("metadata root is not a BSJB blob")
	}
	c := &cliView{md: md}
	raw, ok := md.data["#~"]
	if !ok {
		raw, ok = md.data["#-"]
	}
	if !ok || len(raw) < 24 {
		return nil, fmt.Errorf("no #~ table stream")
	}
	c.hs = raw[6]
	valid := u64le(raw, 8)
	if valid>>0x2D != 0 {
		return nil, fmt.Errorf("valid mask names tables past GenericParamConstraint")
	}
	off := 24
	for id := 0; id <= 0x2C; id++ {
		if valid&(1<<uint(id)) == 0 {
			continue
		}
		if off+4 > len(raw) {
			return nil, fmt.Errorf("row count table cut")
		}
		c.rows[id] = int(u32le(raw, off))
		off += 4
	}
	c.data = raw[off:]
	cur := 0
	for id := 0; id <= 0x2C; id++ {
		if c.rows[id] == 0 {
			continue
		}
		w, _ := colWidths(tableSchema[id], c.hs, &c.rows)
		for _, x := range w {
			c.size[id] += x
		}
		c.off[id] = cur
		cur += c.size[id] * c.rows[id]
	}
	if cur > len(c.data) {
		return nil, fmt.Errorf("tables need %d bytes, stream has %d", cur, len(c.data))
	}
	return c, nil
}

func (c *cliView) n(id int) int { return c.rows[id] }

func (c *cliView) row(id, i int) []byte {
	p := c.off[id] + i*c.size[id]
	return c.data[p : p+c.size[id]]
}

func (c *cliView) cols(id int) ([]int, []int) { return colWidths(tableSchema[id], c.hs, &c.rows) }

func (c *cliView) str(i uint32) string { return heapString(c.md.strings, i) }

// blob reads a #Blob entry: a compressed length prefix then that many bytes.
func (c *cliView) blob(i uint32) []byte {
	h := c.md.data["#Blob"]
	if i == 0 || int(i) >= len(h) {
		return nil
	}
	b := h[i:]
	var n, used int
	switch {
	case b[0]&0x80 == 0:
		n, used = int(b[0]), 1
	case b[0]&0xC0 == 0x80 && len(b) >= 2:
		n, used = int(b[0]&0x3F)<<8|int(b[1]), 2
	case b[0]&0xE0 == 0xC0 && len(b) >= 4:
		n, used = int(b[0]&0x1F)<<24|int(b[1])<<16|int(b[2])<<8|int(b[3]), 4
	default:
		return nil
	}
	if used+n > len(b) {
		return nil
	}
	return b[used : used+n]
}

// opSelector splits "<file>#<selector>" when the part before '#' is a real file,
// so a path that happens to contain '#' still works unsplit.
func opSelector(path string) (file, sel string) {
	i := strings.LastIndexByte(path, '#')
	if i <= 0 || i == len(path)-1 {
		return path, ""
	}
	if _, err := os.Stat(path[:i]); err != nil {
		return path, ""
	}
	return path[:i], path[i+1:]
}

// machoSectionData returns one named section's bytes, its load address and the
// image's pointer size (8 for 64-bit, 4 for 32-bit). The name may be given bare
// ("__objc_classlist") or as "SEG,sect".
func machoSectionData(path, name string) (data []byte, addr uint64, ptr int, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, 0, err
	}
	defer f.Close()
	want := name
	if _, after, ok := strings.Cut(name, ","); ok {
		want = after
	}
	var mf *macho.File
	var base int64
	if ff, ferr := macho.NewFatFile(f); ferr == nil && len(ff.Arches) > 0 {
		mf, base = ff.Arches[0].File, int64(ff.Arches[0].Offset)
	} else if tf, terr := macho.NewFile(f); terr == nil {
		mf = tf
	} else {
		return nil, 0, 0, fmt.Errorf("%s is not Mach-O", path)
	}
	ptr = 4
	if mf.Magic == macho.Magic64 {
		ptr = 8
	}
	for _, s := range mf.Sections {
		if s.Name != want {
			continue
		}
		if s.Size > opMaxFile {
			return nil, 0, 0, fmt.Errorf("%s,%s is %d bytes, over the cap", s.Seg, s.Name, s.Size)
		}
		b := make([]byte, s.Size)
		if _, rerr := f.ReadAt(b, base+int64(s.Offset)); rerr != nil && len(b) > 0 {
			return nil, 0, 0, rerr
		}
		return b, s.Addr, ptr, nil
	}
	return nil, 0, 0, fmt.Errorf("%s has no %s section", path, name)
}

// noDexError says the target holds no DEX image at all. That is a fact about
// the file, not a wrong argument: an op that indexes or searches DEX tables can
// answer "nothing matched" with rc=0, while an op that asks about one named
// class keeps refusing.
type noDexError struct{ msg string }

func (e noDexError) Error() string { return e.msg }

// dexReadBytes returns the DEX bytes of a target: a plain .dex file, or the
// classes*.dex entries of an APK/AAB zip (first dex that parses as one).
func dexReadBytes(path string) ([]byte, error) {
	if zr, err := zip.OpenReader(path); err == nil {
		defer zr.Close()
		for _, f := range zr.File {
			if !strings.HasSuffix(f.Name, ".dex") {
				continue
			}
			if b, ok := readEntry(f, opMaxFile); ok && len(b) >= dexHeaderSize && string(b[:4]) == "dex\n" {
				return b, nil
			}
		}
		b, err := opRead(path, opMaxFile)
		if err == nil && len(b) >= dexHeaderSize && string(b[:4]) == "dex\n" {
			return b, nil
		}
		return nil, noDexError{fmt.Sprintf("%s carries no classes*.dex", path)}
	}
	b, err := opRead(path, opMaxFile)
	if err != nil {
		return nil, err
	}
	if len(b) < dexHeaderSize || string(b[:4]) != "dex\n" {
		return nil, noDexError{fmt.Sprintf("%s is not a DEX image", path)}
	}
	return b, nil
}

// dexOpen builds the package's dexReader from raw bytes: string/type/method/
// class table offsets all come from the header.
func dexOpen(b []byte, d *Digest) (dexReader, error) {
	r := dexReader{b: b, end: len(b), d: d, strs: map[uint32]string{}}
	if len(b) < dexHeaderSize {
		return r, fmt.Errorf("dex is %d bytes and the header needs %d, so it is not a dex image", len(b), dexHeaderSize)
	}
	r.strSize, r.strOff = int(u32le(b, 0x38)), int(u32le(b, 0x3C))
	r.typSize, r.typOff = int(u32le(b, 0x40)), int(u32le(b, 0x44))
	r.metSize, r.metOff = int(u32le(b, 0x58)), int(u32le(b, 0x5C))
	r.clsOff = int(u32le(b, 0x64))
	if r.strSize != 0 && !dexIn(len(b), r.strOff, r.strSize, 4) {
		return r, fmt.Errorf("string_ids at %#x are not inside the file", r.strOff)
	}
	if r.typSize != 0 && !dexIn(len(b), r.typOff, r.typSize, 4) {
		return r, fmt.Errorf("type_ids at %#x are not inside the file", r.typOff)
	}
	if r.metSize != 0 && !dexIn(len(b), r.metOff, r.metSize, 8) {
		return r, fmt.Errorf("method_ids at %#x are not inside the file", r.metOff)
	}
	if !dexIn(len(b), r.clsOff, int(u32le(b, 0x60)), 32) {
		return r, fmt.Errorf("class_defs at %#x are not inside the file", r.clsOff)
	}
	return r, nil
}

// dexClassIndex finds the class_def whose descriptor matches "Lcom/foo/Bar;".
// Both "com.foo.Bar" and "Lcom/foo/Bar;" are accepted.
func dexClassIndex(r dexReader, want string) (int, error) {
	want = strings.TrimSuffix(strings.TrimPrefix(want, "L"), ";")
	want = strings.ReplaceAll(want, ".", "/")
	n := int(u32le(r.b, 0x60))
	for i := range n {
		def := r.clsOff + i*32
		if !dexIn(r.end, def, 32, 1) {
			break
		}
		name, ok := r.typeName(u32le(r.b, def))
		if !ok {
			continue
		}
		if strings.TrimSuffix(strings.TrimPrefix(name, "L"), ";") == want {
			return i, nil
		}
	}
	return -1, fmt.Errorf("no class %q in the dex", want)
}

// noSection reports whether err is machoSectionData's "no such section" miss.
func noSection(err error) bool {
	return err != nil && strings.Contains(err.Error(), " has no ")
}

// dexEntry is one class_data_item member: its table index, access flags and the
// code item offset (methods only).
type dexEntry struct {
	Idx     int
	Access  uint32
	CodeOff int
}

// dexClassData walks the class_data_item ULEB chain: static fields, instance
// fields, direct methods, virtual methods.
func dexClassData(r dexReader, off int) (fields, methods []dexEntry, err error) {
	read := func() (int, bool) {
		v, n, ok := dexULEB(r.b, off, r.end)
		if !ok || n <= 0 {
			return 0, false
		}
		off += n
		return v, true
	}
	ns, ok1 := read()
	ni, ok2 := read()
	nd, ok3 := read()
	nv, ok4 := read()
	if !ok1 || !ok2 || !ok3 || !ok4 {
		return nil, nil, fmt.Errorf("class_data at %#x is not a complete item", off)
	}
	total := ns + ni + nd + nv
	if total < 0 || total > 200000 {
		return nil, nil, fmt.Errorf("class_data declares %d members, which is not a plausible count", total)
	}
	group := func(count, withCode int, dst *[]dexEntry) error {
		idx := 0
		for i := range count {
			d, ok := read()
			if !ok {
				return fmt.Errorf("member %d of %d is not fully encoded", i, count)
			}
			idx += d
			acc, ok := read()
			if !ok {
				return fmt.Errorf("access flags of member %d are not fully encoded", i)
			}
			e := dexEntry{Idx: idx, Access: uint32(acc)}
			if withCode != 0 {
				code, ok := read()
				if !ok {
					return fmt.Errorf("code offset of member %d is not fully encoded", i)
				}
				e.CodeOff = code
			}
			*dst = append(*dst, e)
		}
		return nil
	}
	if err := group(ns, 0, &fields); err != nil {
		return nil, nil, err
	}
	if err := group(ni, 0, &fields); err != nil {
		return nil, nil, err
	}
	if err := group(nd, 1, &methods); err != nil {
		return nil, nil, err
	}
	if err := group(nv, 1, &methods); err != nil {
		return nil, nil, err
	}
	return fields, methods, nil
}

// dexTypeName resolves one type_ids index to its descriptor string.
func dexTypeName(r dexReader, idx uint32) (string, bool) {
	if idx == dexNoIndex {
		return "", false
	}
	return r.typeName(idx)
}

// dexMethodFlag renders the ACC_* bits that matter for a listing.
func dexMethodFlag(a uint32) string {
	var out []string
	for _, f := range []struct {
		bit  uint32
		name string
	}{{0x1, "public"}, {0x2, "private"}, {0x4, "protected"}, {0x8, "static"}, {0x10, "final"},
		{0x100, "native"}, {0x400, "abstract"}, {0x10000, "constructor"}, {0x20000, "declared_synchronized"}} {
		if a&f.bit != 0 {
			out = append(out, f.name)
		}
	}
	return strings.Join(out, ",")
}

func capN(in []string, n int) []string {
	if len(in) > n {
		return in[:n]
	}
	return in
}

// nulStr returns the first NUL-terminated string of b, or all of b when it holds
// no terminator. Shared by the FDT property reader and the BEAM CInf chunk.
func nulStr(b []byte) string {
	if before, _, ok := bytes.Cut(b, []byte{0}); ok {
		return string(before)
	}
	return string(b)
}
