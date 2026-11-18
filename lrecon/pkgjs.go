package main

import (
	"bytes"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
)

// Packaged JavaScript runtimes are ordinary host binaries with a payload
// appended or injected into a segment, section or note. They register as post
// readers: the magic switch already named the host, so Kind never changes here.

const pkgjsMax = 32 << 20

// pkgjsNative is the cheap prefilter shared by all four readers: every target is
// a thin Mach-O, ELF or PE host.
func pkgjsNative(head []byte, _ int64) bool {
	return isMachO(head) || bytes.HasPrefix(head, []byte("\x7fELF")) || bytes.HasPrefix(head, []byte("MZ"))
}

func init() {
	register(reader{
		format:  "pkg",
		reasons: []string{"pkg-payload-missing", "pkg-layout-invalid", "pkg-vfs-invalid", "pkgjs-too-large"},
		match:   pkgjsNative,
		inspect: inspectPkg,
		post:    true,
	})
	register(reader{
		format:  "bun",
		reasons: []string{"bun-trailer-missing", "bun-trailer-unverified"},
		match:   pkgjsNative,
		inspect: inspectBun,
		post:    true,
	})
	register(reader{
		format:  "deno-compile",
		reasons: []string{"deno-trailer-unverified", "pkgjs-too-large"},
		match:   pkgjsNative,
		inspect: inspectDenoCompile,
		post:    true,
	})
	register(reader{
		format:  "node-sea",
		reasons: []string{"sea-blob-missing", "sea-blob-invalid", "sea-note-unverified", "pkgjs-too-large"},
		match:   pkgjsNative,
		inspect: inspectNodeSEA,
		post:    true,
	})
}

// readFileAt reads exactly n bytes at off; nil when the range does not fit.
func readFileAt(path string, off, n int64) []byte {
	if off < 0 || n < 0 || n > pkgjsMax {
		return nil
	}
	if n == 0 {
		return []byte{}
	}
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	b := make([]byte, n)
	if _, err := f.ReadAt(b, off); err != nil {
		return nil
	}
	return b
}

func fileSize(d *Digest, path string) int64 {
	if d.FileSize > 0 {
		return d.FileSize
	}
	st, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return st.Size()
}

func readAllLimit(r io.Reader, n int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, n))
	if err == nil && int64(len(b)) != n {
		err = io.ErrUnexpectedEOF
	}
	return b, err
}

// scanFileMulti is a single pass over the file looking for several literal
// sentinels at once. Windows overlap by max pattern length - 1 so a match that
// straddles a chunk boundary is still found. First offset per pattern, -1 if
// absent.
func scanFileMulti(path string, pats [][]byte) []int64 {
	out := make([]int64, len(pats))
	maxPat := 0
	for i, p := range pats {
		out[i] = -1
		if len(p) > maxPat {
			maxPat = len(p)
		}
	}
	if maxPat == 0 {
		return out
	}
	f, err := os.Open(path)
	if err != nil {
		return out
	}
	defer f.Close()
	const chunk = 1 << 20
	buf := make([]byte, chunk+maxPat-1)
	base := int64(0)
	for {
		n, err := io.ReadFull(f, buf)
		for i, p := range pats {
			if n == 0 || out[i] >= 0 || len(p) == 0 {
				continue
			}
			if j := bytes.Index(buf[:n], p); j >= 0 {
				out[i] = base + int64(j)
			}
		}
		if err != nil || n <= maxPat-1 {
			break
		}
		copy(buf, buf[n-(maxPat-1):n])
		base += int64(n - (maxPat - 1))
	}
	return out
}

func printablePath(b []byte) bool {
	for _, c := range b {
		if c < 0x20 || c == 0x7f {
			return false
		}
	}
	return true
}

// jsValue finds key in a JS prelude, skips the spaces/'='/':' after it, and
// decodes the JSON value that follows. Later occurrences are tried, so a global
// comment or a member access does not hide the real assignment.
func jsValue(b []byte, key string) ([]byte, bool) {
	kb := []byte(key)
	from := 0
	for {
		i := bytes.Index(b[from:], kb)
		if i < 0 {
			return nil, false
		}
		i += from
		from = i + len(kb)
		end := min(from+24, len(b))
		j := from
		for j < end && (b[j] == ' ' || b[j] == '=' || b[j] == ':') {
			j++
		}
		if j >= end || !(b[j] == '{' || b[j] == '"' || b[j] == '-' || (b[j] >= '0' && b[j] <= '9')) {
			continue
		}
		var raw json.RawMessage
		if err := json.NewDecoder(bytes.NewReader(b[j:])).Decode(&raw); err != nil {
			return nil, false
		}
		return raw, true
	}
}

// --- vercel/pkg -------------------------------------------------------------

// The four build-time slots keep their literal names and are overwritten with a
// decimal and a space pad, so the sentinel survives and the width fixes the
// field.
var pkgSlots = []struct {
	key   string
	width int
}{
	{"var PAYLOAD_POSITION = '", 22},
	{"var PAYLOAD_SIZE = '", 18},
	{"var PRELUDE_POSITION = '", 22},
	{"var PRELUDE_SIZE = '", 18},
}

func inspectPkg(path string, d *Digest) {
	pats := make([][]byte, len(pkgSlots))
	for i, s := range pkgSlots {
		pats[i] = []byte(s.key)
	}
	at := scanFileMulti(path, pats)
	if at[0] < 0 {
		return
	}
	vals := make([]int64, len(pkgSlots))
	patched := false
	for i, s := range pkgSlots {
		name := slotName(s.key)
		if at[i] < 0 {
			d.skip("pkg-payload-missing", "slot "+name+" is absent")
			return
		}
		b := readFileAt(path, at[i]+int64(len(s.key)), int64(s.width))
		if b == nil {
			d.skip("pkg-payload-missing", "slot "+name+" window runs past EOF")
			return
		}
		digits := 0
		for digits < len(b) && b[digits] >= '0' && b[digits] <= '9' {
			digits++
		}
		if digits == 0 || strings.Trim(string(b[digits:]), " ") != "" {
			d.skip("pkg-layout-invalid", "slot "+name+" is not a space-padded decimal")
			return
		}
		if digits < len(b) {
			patched = true
		}
		v, err := strconv.ParseInt(string(b[:digits]), 10, 64)
		if err != nil {
			d.skip("pkg-layout-invalid", "slot "+name+" does not fit int64")
			return
		}
		vals[i] = v
	}
	size := fileSize(d, path)
	payloadPos, payloadSize := vals[0], vals[1]
	preludePos, preludeSize := vals[2], vals[3]
	if payloadPos < 0 || payloadSize < 0 || preludeSize <= 0 ||
		preludePos != payloadPos+payloadSize || preludePos+preludeSize != size {
		d.skip("pkg-layout-invalid", fmt.Sprintf("slots do not close at EOF: payload %d+%d, prelude %d+%d, file %d",
			payloadPos, payloadSize, preludePos, preludeSize, size))
		return
	}
	if preludeSize > pkgjsMax {
		d.skip("pkgjs-too-large", fmt.Sprintf("prelude is %d bytes", preludeSize))
		return
	}
	prelude := readFileAt(path, preludePos, preludeSize)
	if prelude == nil {
		d.skip("pkg-payload-missing", "prelude range is unreadable")
		return
	}
	vfs, ok := jsValue(prelude, "VIRTUAL_FILESYSTEM")
	if !ok {
		d.skip("pkg-vfs-invalid", "no decodable VIRTUAL_FILESYSTEM payload")
		return
	}
	var files map[string]map[string][]json.Number
	dec := json.NewDecoder(bytes.NewReader(vfs))
	dec.UseNumber()
	if err := dec.Decode(&files); err != nil {
		d.skip("pkg-vfs-invalid", err.Error())
		return
	}
	rev := map[string]string{}
	if raw, ok := jsValue(prelude, "DICT"); ok {
		var dict map[string]string
		if json.Unmarshal(raw, &dict) == nil {
			for name, key := range dict {
				rev[key] = name
			}
		}
	}
	paths := make([]string, 0, len(files))
	sizes := make(map[string]int64, len(files))
	for key, stores := range files {
		if len(stores) == 0 {
			continue // directory entry, not a file
		}
		var n int64
		for _, store := range stores {
			if len(store) >= 2 {
				if sz, err := store[1].Int64(); err == nil && sz > n {
					n = sz
				}
			}
		}
		p := pkgDeref(key, rev)
		paths = append(paths, p)
		sizes[p] = n
	}
	sort.Strings(paths)
	total := len(paths)
	if total > 512 {
		d.Notes = append(d.Notes, fmt.Sprintf("pkg VFS lists %d files; only the first 512 are reported", total))
		paths = paths[:512]
	}
	for _, p := range paths {
		d.Deps = append(d.Deps, Dep{Path: p, Version: strconv.FormatInt(sizes[p], 10)})
	}
	d.Capabilities = append(d.Capabilities,
		fmt.Sprintf("pkg:files=%d", total),
		fmt.Sprintf("pkg:payload_offset=%d", payloadPos))
	mode := "plain build-time slots"
	if patched {
		mode = "in-place patched slots with a space-padded overlay"
	}
	d.Notes = append(d.Notes, fmt.Sprintf("pkg payload %d bytes at %d, prelude %d bytes at %d: %s",
		payloadSize, payloadPos, preludeSize, preludePos, mode))
	if raw, ok := jsValue(prelude, "DOCOMPRESS"); ok {
		var c json.Number
		if json.Unmarshal(raw, &c) == nil {
			switch c.String() {
			case "1":
				d.Notes = append(d.Notes, "pkg VFS is gzip-compressed; paths are keyed through DICT")
			case "2":
				d.Notes = append(d.Notes, "pkg VFS is brotli-compressed; paths are keyed through DICT")
			}
		}
	}
	if raw, ok := jsValue(prelude, "DEFAULT_ENTRYPOINT"); ok {
		var ep string
		if json.Unmarshal(raw, &ep) == nil && ep != "" {
			d.Notes = append(d.Notes, "pkg default entrypoint: "+ep)
		}
	}
	d.parsed()
	d.scanned(preludeSize)
}

func slotName(key string) string {
	return strings.TrimSuffix(strings.TrimPrefix(key, "var "), " = '")
}

// pkgDeref turns a compressed VFS key back into path segments through the
// reverse file dictionary. Plain keys are already full paths and pass through.
func pkgDeref(key string, rev map[string]string) string {
	if len(rev) == 0 {
		return key
	}
	parts := strings.Split(key, "/")
	for i, seg := range parts {
		if name, ok := rev[seg]; ok {
			parts[i] = name
		}
	}
	return strings.Join(parts, "/")
}

// --- Bun single-file compile ------------------------------------------------

var bunTrailer = []byte("\n---- Bun! ----\n")

const (
	bunModuleSize = 52
	bunDamage     = "---- Bun! ----"
)

func inspectBun(path string, d *Digest) {
	size := fileSize(d, path)
	if size <= 0 {
		return
	}
	magic, carrier, found := bunCarrier(path, size)
	if !found {
		return
	}
	if magic < 0 {
		d.skip("bun-trailer-missing", carrier+" carrier without a trailer")
		return
	}
	if !bunDecode(path, magic, d) {
		d.skip("bun-trailer-unverified", fmt.Sprintf("trailer at %#x has no valid offsets table", magic))
	}
}

// bunCarrier locates the trailer in every documented carrier: a plain appended
// tail, a Mach-O __BUN segment, a PE .bun section or the ELF BUN_COMPILED
// symbol. The boolean reports that a carrier exists even when the trailer is
// damaged, which is a skip rather than silence.
func bunCarrier(path string, size int64) (int64, string, bool) {
	if m := tailMagic(path, size, 48); m >= 0 {
		return m, "eof", true
	}
	if b := readFileAt(path, size-min(size, 48), min(size, 48)); b != nil && bytes.Contains(b, []byte(bunDamage)) {
		return -1, "eof", true
	}
	if m, ok := bunMachO(path); ok {
		return m, "__BUN", true
	}
	if m, ok := bunPE(path); ok {
		return m, ".bun", true
	}
	if m, ok := bunELF(path, size); ok {
		return m, "BUN_COMPILED", true
	}
	return -1, "", false
}

func tailMagic(path string, end, window int64) int64 {
	start := max(end-window, 0)
	b := readFileAt(path, start, end-start)
	if b == nil {
		return -1
	}
	if i := bytes.LastIndex(b, bunTrailer); i >= 0 {
		return start + int64(i)
	}
	return -1
}

func bunMachO(path string) (int64, bool) {
	f, err := macho.Open(path)
	if err != nil {
		return -1, false
	}
	defer f.Close()
	s := f.Segment("__BUN")
	if s == nil {
		return -1, false
	}
	if s.Filesz <= 0 || s.Filesz > pkgjsMax {
		return -1, true
	}
	b, err := readAllLimit(s.Open(), int64(s.Filesz))
	if err != nil {
		return -1, true
	}
	if i := bytes.LastIndex(b, bunTrailer); i >= 0 {
		return int64(s.Offset) + int64(i), true
	}
	return -1, true
}

func bunPE(path string) (int64, bool) {
	f, err := pe.Open(path)
	if err != nil {
		return -1, false
	}
	defer f.Close()
	for _, s := range f.Sections {
		if strings.TrimRight(s.Name, "\x00") != ".bun" {
			continue
		}
		if s.Size == 0 || s.Size > pkgjsMax {
			return -1, true
		}
		b, err := s.Data()
		if err != nil {
			return -1, true
		}
		if i := bytes.LastIndex(b, bunTrailer); i >= 0 {
			return int64(s.Offset) + int64(i), true
		}
		return -1, true
	}
	return -1, false
}

func bunELF(path string, size int64) (int64, bool) {
	f, err := elf.Open(path)
	if err != nil {
		return -1, false
	}
	defer f.Close()
	syms, err := f.Symbols()
	if err != nil {
		return -1, false
	}
	for _, s := range syms {
		if s.Name != "BUN_COMPILED" {
			continue
		}
		off, ok := elfVaddrOffset(f, s.Size)
		if !ok {
			return -1, true
		}
		hdr := readFileAt(path, off, 8)
		if hdr == nil {
			return -1, true
		}
		n := int64(binary.LittleEndian.Uint64(hdr))
		end := off + 8 + n
		if n <= 0 || end > size {
			return -1, true
		}
		if m := tailMagic(path, end, 48); m >= 0 {
			return m, true
		}
		return -1, true
	}
	return -1, false
}

func elfVaddrOffset(f *elf.File, vaddr uint64) (int64, bool) {
	for _, p := range f.Progs {
		if p.Type != elf.PT_LOAD || p.Filesz == 0 {
			continue
		}
		if vaddr >= p.Vaddr && vaddr < p.Vaddr+p.Filesz {
			return int64(p.Off) + int64(vaddr-p.Vaddr), true
		}
	}
	return 0, false
}

// bunDecode reads the 32-byte offsets table that sits immediately before the
// trailer, then the module table it points at. Layout verified on Bun 1.4.0.
func bunDecode(path string, magic int64, d *Digest) bool {
	tabOff := magic - 32
	if tabOff < 0 {
		return false
	}
	tab := readFileAt(path, tabOff, 32)
	if tab == nil {
		return false
	}
	byteCount := int64(binary.LittleEndian.Uint64(tab[0:8]))
	modOff := int64(binary.LittleEndian.Uint32(tab[8:12]))
	modLen := int64(binary.LittleEndian.Uint32(tab[12:16]))
	entryID := binary.LittleEndian.Uint32(tab[16:20])
	flags := binary.LittleEndian.Uint32(tab[28:32])
	if byteCount <= 0 || byteCount > pkgjsMax {
		return false
	}
	if modLen <= 0 || modLen > 512*bunModuleSize || modLen%bunModuleSize != 0 {
		return false
	}
	base := tabOff - byteCount
	modStart := base + modOff
	if base < 0 || modStart < 0 || modStart+modLen > tabOff {
		return false
	}
	mods := readFileAt(path, modStart, modLen)
	if mods == nil {
		return false
	}
	count := int(modLen / bunModuleSize)
	if int(entryID) >= count {
		return false
	}
	bytecode := 0
	for i := range count {
		rec := mods[i*bunModuleSize:]
		if binary.LittleEndian.Uint32(rec[28:32]) != 0 {
			bytecode++
		}
	}
	entry := mods[int(entryID)*bunModuleSize:]
	nameOff := int64(binary.LittleEndian.Uint32(entry[0:4]))
	nameLen := int64(binary.LittleEndian.Uint32(entry[4:8]))
	contLen := int64(binary.LittleEndian.Uint32(entry[12:16]))
	if nameLen <= 0 || nameLen > 4096 {
		return false
	}
	name := readFileAt(path, base+nameOff, nameLen)
	if name == nil || !printablePath(name) {
		return false
	}
	d.Deps = append(d.Deps, Dep{Path: string(name), Version: strconv.FormatInt(contLen, 10)})
	d.Capabilities = append(d.Capabilities,
		fmt.Sprintf("bun:modules=%d", count),
		fmt.Sprintf("bun:bytecode=%d", bytecode),
		fmt.Sprintf("bun:entry_id=%d", entryID),
		fmt.Sprintf("bun:flags=0x%x", flags))
	d.Notes = append(d.Notes, fmt.Sprintf("bun compiled payload: %d module(s), %d with bytecode, entry %s (%d bytes)",
		count, bytecode, name, contLen))
	if flags>>5 != 0 {
		d.Notes = append(d.Notes, "bun trailer flags carry trailing records after the trailer (ignored)")
	}
	d.parsed()
	d.scanned(32 + modLen + nameLen)
	return true
}

// --- deno compile -----------------------------------------------------------

var (
	denoMagic    = []byte("d3n0l4nd")
	denoSentinel = []byte("<~sui-data~>")
)

const (
	denoNoteName = "SUI"
	denoNoteType = 0x53554901
	denoResource = "D3N0L4ND"
)

func inspectDenoCompile(path string, d *Digest) {
	size := fileSize(d, path)
	h := readFileAt(path, 0, 8)
	if h == nil {
		return
	}
	switch {
	case bytes.HasPrefix(h, []byte("\x7fELF")):
		notes, _ := elfNoteRecords(path)
		for _, n := range notes {
			if n.name == denoNoteName && n.typ == denoNoteType {
				denoPayload(n.desc, n.off, "elf-note", d)
				return
			}
		}
	case bytes.HasPrefix(h, []byte("MZ")):
		if f, err := pe.Open(path); err == nil {
			defer f.Close()
			if b, off, ok := peResource(path, f, 10, denoResource); ok {
				denoPayload(b, off, "pe-rcdata", d)
			}
		}
	case isMachO(h) && len(h) >= 8:
		cpu := binary.LittleEndian.Uint32(h[4:8])
		switch cpu {
		case 0x0100000c: // arm64: payload in the __SUI segment
			if b, off, ok := machoSegment(path, "__SUI"); ok {
				denoPayload(b, off, "macho-__SUI", d)
			}
		case 0x01000007: // amd64: append-only EOF sentinel
			b, off, state := denoEOF(path, size)
			switch state {
			case 1:
				denoPayload(b, off, "macho-eof-sentinel", d)
			case 2:
				d.skip("deno-trailer-unverified", "macho-eof-sentinel trailer is truncated or its length does not fit")
			}
		default:
			if denoEvidence(path, size) {
				d.skip("deno-trailer-unverified", fmt.Sprintf("platform=macho-0x%x has no verified payload carrier", cpu))
			}
		}
	}
}

// denoEOF reads the amd64 trailer: 12-byte sentinel, 0xDEADBEEF, u64 payload
// length, then the payload. State 0 is absent, 1 is usable, 2 is damaged.
func denoEOF(path string, size int64) ([]byte, int64, int) {
	if size < 24 {
		return nil, 0, 0
	}
	tail := readFileAt(path, size-24, 24)
	if tail == nil || !bytes.Equal(tail[:12], denoSentinel) || binary.LittleEndian.Uint32(tail[12:16]) != 0xdeadbeef {
		return nil, 0, 0
	}
	n := int64(binary.LittleEndian.Uint64(tail[16:24]))
	start := size - 24 - n
	if n < 16 || n > pkgjsMax || start < 0 {
		return nil, 0, 2
	}
	b := readFileAt(path, start, n)
	if b == nil || !bytes.Equal(b[:8], denoMagic) {
		return nil, 0, 2
	}
	return b, start, 1
}

// denoEvidence keeps a skip honest: only a tail that actually looks like deno
// output earns a refusal on a platform with no verified carrier.
func denoEvidence(path string, size int64) bool {
	tail := readFileAt(path, size-min(size, 64), min(size, 64))
	return tail != nil && (bytes.Contains(tail, denoMagic) || bytes.Contains(tail, denoSentinel))
}

func denoPayload(b []byte, off int64, carrier string, d *Digest) {
	if len(b) > pkgjsMax {
		d.skip("pkgjs-too-large", fmt.Sprintf("%s payload is %d bytes", carrier, len(b)))
		return
	}
	if len(b) < 16 || !bytes.Equal(b[:8], denoMagic) || !bytes.Equal(b[len(b)-8:], denoMagic) {
		d.skip("deno-trailer-unverified", carrier+": payload lacks the d3n0l4nd magic at both ends")
		return
	}
	d.Capabilities = append(d.Capabilities,
		fmt.Sprintf("deno:payload_bytes=%d", len(b)),
		"deno:carrier="+carrier)
	d.Notes = append(d.Notes, fmt.Sprintf("deno compile payload %d bytes at %#x (%s)", len(b), off, carrier))
	d.claim("deno-compile", carrier, off)
	d.parsed()
	d.scanned(int64(len(b)))
}

// --- Node single executable applications ------------------------------------

const (
	seaMagic     = 0x0143DA20
	seaResource  = "NODE_SEA_BLOB"
	seaFuseStart = "NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2:"
)

func inspectNodeSEA(path string, d *Digest) {
	size := fileSize(d, path)
	h := readFileAt(path, 0, 4)
	if h == nil {
		return
	}
	var blob []byte
	var off int64
	var carrier string
	found := false
	switch {
	case bytes.HasPrefix(h, []byte("\x7fELF")):
		notes, _ := elfNoteRecords(path)
		for _, n := range notes {
			if n.name == seaResource {
				blob, off, carrier, found = n.desc, n.off, "elf-note", true
				break
			}
		}
	case bytes.HasPrefix(h, []byte("MZ")):
		if f, err := pe.Open(path); err == nil {
			blob, off, found = peResource(path, f, 10, seaResource)
			f.Close()
			carrier = "pe-rcdata"
		}
	case isMachO(h):
		blob, off, found = machoSection(path, "__NODE_SEA_BLOB")
		carrier = "macho-section"
	}
	if !found {
		if at := scanFileMulti(path, [][]byte{[]byte(seaFuseStart)})[0]; at >= 0 {
			d.skip("sea-blob-missing", fmt.Sprintf("NODE_SEA_FUSE present at %#x with no NODE_SEA_BLOB container", at))
		}
		return
	}
	if len(blob) < 8 || binary.LittleEndian.Uint32(blob[:4]) != seaMagic {
		d.skip("sea-note-unverified", carrier+": NODE_SEA_BLOB without the SEA blob magic")
		return
	}
	flags, width, codePath, mainLen, ok := seaHeader(blob)
	if !ok {
		d.skip("sea-blob-invalid", "blob header does not validate")
		return
	}
	fuse := scanFileMulti(path, [][]byte{[]byte(seaFuseStart)})[0]
	form := "resource"
	if off+int64(len(blob)) == size {
		form = "appended-eof"
	}
	header := "v20"
	switch width {
	case 9:
		header = "v22-v24"
	case 10:
		header = "v25+"
	}
	if flags&0x02 != 0 || flags&0x08 != 0 {
		d.Notes = append(d.Notes, "node SEA blob carries a snapshot and/or assets section; only sizes are reported")
	}
	d.Deps = append(d.Deps, Dep{Path: codePath, Version: strconv.FormatUint(mainLen, 10)})
	d.Capabilities = append(d.Capabilities,
		fmt.Sprintf("sea:flags=0x%02x", flags),
		"sea:carrier="+carrier,
		"sea:form="+form,
		"sea:header="+header,
		fmt.Sprintf("sea:blob_bytes=%d", len(blob)),
		fmt.Sprintf("sea:main_bytes=%d", mainLen))
	d.Notes = append(d.Notes, fmt.Sprintf("node SEA blob %d bytes at %#x: flags 0x%x, code path %s, main code %d bytes (source body withheld)",
		len(blob), off, flags, codePath, mainLen))
	d.claim("sea-blob-magic", carrier, off)
	if fuse >= 0 {
		d.claim("sea-fuse", "NODE_SEA_FUSE", fuse)
	}
	d.parsed()
	d.scanned(int64(len(blob)))
}

// seaHeader validates the version-width header and the code path that follows.
// Width is inferred from its own constraints: a wrong pick almost never leaves a
// printable code path and a main length that fits the container.
func seaHeader(b []byte) (uint32, int, string, uint64, bool) {
	flags := binary.LittleEndian.Uint32(b[4:8])
	if flags > 0x7f {
		return 0, 0, "", 0, false
	}
	for _, width := range []int{10, 9, 8} {
		if len(b) < width {
			continue
		}
		if width == 9 && b[8] > 2 {
			continue
		}
		if width == 10 && (b[8] > 2 || b[9] > 1) {
			continue
		}
		p, next, ok := seaString(b, width)
		if !ok {
			continue
		}
		mainLen, ok := seaU64(b, next)
		if !ok || mainLen > uint64(len(b)-next) {
			continue
		}
		return flags, width, p, mainLen, true
	}
	return 0, 0, "", 0, false
}

func seaString(b []byte, off int) (string, int, bool) {
	n, ok := seaU64(b, off)
	if !ok || n == 0 || n > 4096 || n > uint64(len(b)-off-8) {
		return "", 0, false
	}
	s := b[off+8 : off+8+int(n)]
	for _, c := range s {
		if c < 0x20 || c == 0x7f {
			return "", 0, false
		}
	}
	return string(s), off + 8 + int(n), true
}

func seaU64(b []byte, off int) (uint64, bool) {
	if off < 0 || off+8 > len(b) {
		return 0, false
	}
	return binary.LittleEndian.Uint64(b[off : off+8]), true
}

// --- container helpers ------------------------------------------------------

type noteRecord struct {
	name string
	typ  uint32
	desc []byte
	off  int64
}

func elfNoteRecords(path string) ([]noteRecord, bool) {
	f, err := elf.Open(path)
	if err != nil {
		return nil, false
	}
	defer f.Close()
	var out []noteRecord
	// A note can live in a PT_NOTE segment, in an SHT_NOTE section, or in both;
	// only walking the segments misses every section-only note, .note.gnu.build-id
	// in particular on Go and GCC linked ELF files.
	seen := map[string]bool{}
	add := func(rs []noteRecord) {
		for _, r := range rs {
			k := fmt.Sprintf("%d/%s/%d/%x", r.off, r.name, r.typ, r.desc)
			if seen[k] {
				continue
			}
			seen[k] = true
			out = append(out, r)
		}
	}
	for _, p := range f.Progs {
		if p.Type != elf.PT_NOTE || p.Filesz == 0 || p.Filesz > pkgjsMax {
			continue
		}
		b, err := readAllLimit(p.Open(), int64(p.Filesz))
		if err != nil {
			continue
		}
		add(parseNotes(b, f.ByteOrder, int64(p.Off)))
	}
	for _, s := range f.Sections {
		if s.Type != elf.SHT_NOTE || s.Size == 0 || s.Size > pkgjsMax {
			continue
		}
		b, err := readAllLimit(s.Open(), int64(s.Size))
		if err != nil {
			continue
		}
		add(parseNotes(b, f.ByteOrder, int64(s.Offset)))
	}
	return out, true
}

// parseNotes walks one PT_NOTE segment. A malformed record ends the walk rather
// than guessing past it.
func parseNotes(b []byte, bo binary.ByteOrder, base int64) []noteRecord {
	var out []noteRecord
	for len(b) >= 12 {
		namesz := int(bo.Uint32(b[0:4]))
		descsz := int(bo.Uint32(b[4:8]))
		typ := bo.Uint32(b[8:12])
		if 12+namesz > len(b) {
			break
		}
		descStart := align4(12 + namesz)
		descEnd := descStart + descsz
		if descStart > len(b) || descEnd > len(b) {
			break
		}
		out = append(out, noteRecord{
			name: strings.TrimRight(string(b[12:12+namesz]), "\x00"),
			typ:  typ,
			desc: b[descStart:descEnd],
			off:  base + int64(descStart),
		})
		next := align4(descEnd)
		if next <= 0 || next > len(b) {
			break
		}
		b = b[next:]
		base += int64(next)
	}
	return out
}

func align4(n int) int { return (n + 3) &^ 3 }

func machoSegment(path, name string) ([]byte, int64, bool) {
	f, err := macho.Open(path)
	if err != nil {
		return nil, 0, false
	}
	defer f.Close()
	s := f.Segment(name)
	if s == nil || s.Filesz == 0 || s.Filesz > pkgjsMax {
		return nil, 0, false
	}
	b, err := readAllLimit(s.Open(), int64(s.Filesz))
	if err != nil {
		return nil, 0, false
	}
	return b, int64(s.Offset), true
}

func machoSection(path, name string) ([]byte, int64, bool) {
	f, err := macho.Open(path)
	if err != nil {
		return nil, 0, false
	}
	defer f.Close()
	for _, s := range f.Sections {
		if s.Name != name {
			continue
		}
		if s.Size == 0 || s.Size > pkgjsMax {
			return nil, 0, false
		}
		b, err := s.Data()
		if err != nil {
			return nil, 0, false
		}
		return b, int64(s.Offset), true
	}
	return nil, 0, false
}

func peResourceDir(f *pe.File) pe.DataDirectory {
	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader64:
		if len(oh.DataDirectory) > 2 {
			return oh.DataDirectory[2]
		}
	case *pe.OptionalHeader32:
		if len(oh.DataDirectory) > 2 {
			return oh.DataDirectory[2]
		}
	}
	return pe.DataDirectory{}
}

// peResource returns the first language variant of RT_typ/name, which is how
// both deno and Node store their payload.
func peResource(path string, f *pe.File, typ uint32, name string) ([]byte, int64, bool) {
	dir := peResourceDir(f)
	if dir.VirtualAddress == 0 || dir.Size == 0 {
		return nil, 0, false
	}
	root := dir.VirtualAddress
	ents, ok := peRsrcEntries(path, f, root)
	if !ok {
		return nil, 0, false
	}
	sub, ok := peRsrcPick(path, f, root, ents, typ, "")
	if !ok || sub&0x80000000 == 0 {
		return nil, 0, false
	}
	ents, ok = peRsrcEntries(path, f, root+(sub&0x7fffffff))
	if !ok {
		return nil, 0, false
	}
	sub, ok = peRsrcPick(path, f, root, ents, 0, name)
	if !ok || sub&0x80000000 == 0 {
		return nil, 0, false
	}
	ents, ok = peRsrcEntries(path, f, root+(sub&0x7fffffff))
	if !ok || len(ents) == 0 || ents[0].off&0x80000000 != 0 {
		return nil, 0, false
	}
	hdr, ok := peReadRVA(path, f, root+ents[0].off, 16)
	if !ok {
		return nil, 0, false
	}
	sz := int64(binary.LittleEndian.Uint32(hdr[4:8]))
	if sz <= 0 || sz > pkgjsMax {
		return nil, 0, false
	}
	off, ok := peOffset(f, binary.LittleEndian.Uint32(hdr[0:4]))
	if !ok {
		return nil, 0, false
	}
	b := readFileAt(path, off, sz)
	if b == nil {
		return nil, 0, false
	}
	return b, off, true
}

type peRsrcEntry struct {
	name uint32
	off  uint32
}

func peRsrcEntries(path string, f *pe.File, dirRVA uint32) ([]peRsrcEntry, bool) {
	hdr, ok := peReadRVA(path, f, dirRVA, 16)
	if !ok {
		return nil, false
	}
	n := int(binary.LittleEndian.Uint16(hdr[12:14])) + int(binary.LittleEndian.Uint16(hdr[14:16]))
	if n < 0 || n > 4096 {
		return nil, false
	}
	b, ok := peReadRVA(path, f, dirRVA+16, int64(n*8))
	if !ok {
		return nil, false
	}
	out := make([]peRsrcEntry, n)
	for i := range out {
		out[i].name = binary.LittleEndian.Uint32(b[i*8:])
		out[i].off = binary.LittleEndian.Uint32(b[i*8+4:])
	}
	return out, true
}

func peRsrcPick(path string, f *pe.File, root uint32, ents []peRsrcEntry, id uint32, name string) (uint32, bool) {
	for _, e := range ents {
		named := e.name&0x80000000 != 0
		if name == "" {
			if !named && e.name == id {
				return e.off, true
			}
			continue
		}
		if !named {
			continue
		}
		if s, ok := peRsrcString(path, f, root+(e.name&0x7fffffff)); ok && strings.EqualFold(s, name) {
			return e.off, true
		}
	}
	return 0, false
}

func peRsrcString(path string, f *pe.File, rva uint32) (string, bool) {
	h, ok := peReadRVA(path, f, rva, 2)
	if !ok {
		return "", false
	}
	n := int(binary.LittleEndian.Uint16(h))
	if n == 0 || n > 256 {
		return "", false
	}
	b, ok := peReadRVA(path, f, rva+2, int64(n*2))
	if !ok {
		return "", false
	}
	var sb strings.Builder
	for i := range n {
		c := binary.LittleEndian.Uint16(b[i*2:])
		if c > 0x7f {
			return "", false
		}
		sb.WriteByte(byte(c))
	}
	return sb.String(), true
}

func peReadRVA(path string, f *pe.File, rva uint32, n int64) ([]byte, bool) {
	off, ok := peOffset(f, rva)
	if !ok {
		return nil, false
	}
	b := readFileAt(path, off, n)
	return b, b != nil
}
