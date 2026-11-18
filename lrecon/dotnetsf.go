package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// .NET single-file bundle (dotnet/runtime apphost): a native host image that
// carries a 32-byte marker, an int64 locator before it and a header table with
// one FileEntry per bundled file. The outer image holds no CLR metadata; the
// managed assemblies are entries inside it.
const (
	bundleMarkerLen  = 32
	bundleMaxFiles   = 512
	bundleMaxPath    = 4096
	bundleMaxSidecar = 1 << 20
	bundleHeadRead   = 512
)

var bundleMarker = []byte{
	0x8B, 0x12, 0x02, 0xB9, 0x6A, 0x61, 0x20, 0x38,
	0x72, 0x7B, 0x93, 0x02, 0x14, 0xD7, 0xA0, 0x32,
	0x13, 0xF5, 0xB9, 0xE6, 0xEF, 0xAE, 0x33, 0x18,
	0xEE, 0x3B, 0x2D, 0xCE, 0x24, 0xB3, 0x6A, 0xAE,
}

var dotnetsfReasons = []string{
	"dotnetsf-marker-missing",
	"dotnetsf-version-unverified",
	"dotnetsf-header-invalid",
	"dotnetsf-truncated",
	"ecma335-container-singlefile",
}

func init() {
	register(reader{
		format:  "dotnet-singlefile",
		reasons: append(append([]string{}, dotnetsfReasons...), managedReasons...),
		match: func(head []byte, size int64) bool {
			// The bundle is appended to the native apphost, and that host is a
			// PE on Windows, a Mach-O on macOS and an ELF on Linux.
			if bytes.HasPrefix(head, []byte("MZ")) || bytes.HasPrefix(head, []byte("\x7fELF")) {
				return true
			}
			if len(head) >= 4 {
				be, le := binary.BigEndian.Uint32(head), binary.LittleEndian.Uint32(head)
				for _, m := range []uint32{0xfeedface, 0xfeedfacf} {
					if be == m || le == m {
						return true
					}
				}
			}
			return false
		},
		inspect: inspectDotNetSingleFile,
		post:    true,
	})
}

// dotnetApphostHint is the hostfxr entry point every .NET apphost imports,
// bundle or not. It gates the full-file marker search so unrelated native
// images are not streamed.
var dotnetApphostHint = []byte("hostfxr_main_bundle_startupinfo")

// bundleHeader is the parsed header table prefix; entries start at entriesFrom.
type bundleHeader struct {
	major, minor                   uint32
	files                          int32
	depOff, depSize, rtOff, rtSize int64
	id                             string
	entriesFrom                    int64
}

// parseBundleHeader walks: major u32, minor u32, file count i32, 7-bit
// length-prefixed bundle id, then (v2+) deps/runtimeconfig ranges and flags.
func parseBundleHeader(b []byte) (bundleHeader, bool) {
	var h bundleHeader
	if len(b) < 12 {
		return h, false
	}
	h.major = binary.LittleEndian.Uint32(b)
	h.minor = binary.LittleEndian.Uint32(b[4:])
	h.files = int32(binary.LittleEndian.Uint32(b[8:]))
	if h.files <= 0 {
		return h, false
	}
	off := 12
	id, n, ok := read7(b, off, bundleMaxPath)
	if !ok {
		return h, false
	}
	h.id = id
	off += n
	if h.major >= 2 {
		const sidecar = 32 // deps range + runtimeconfig range
		if len(b) < off+sidecar+8 {
			return h, false
		}
		h.depOff = int64(binary.LittleEndian.Uint64(b[off:]))
		h.depSize = int64(binary.LittleEndian.Uint64(b[off+8:]))
		h.rtOff = int64(binary.LittleEndian.Uint64(b[off+16:]))
		h.rtSize = int64(binary.LittleEndian.Uint64(b[off+24:]))
		off += sidecar + 8 // flags u64
	}
	h.entriesFrom = int64(off)
	return h, true
}

// bundleEntry is one FileEntry row. Order is size-then-compressed-then-type:
// offset i64, size i64, [compressed i64 when major >= 6], type u8, path.
type bundleEntry struct {
	offset, size, compressed int64
	kind                     uint8
	path                     string
}

func parseBundleEntry(b []byte, major uint32) (bundleEntry, int, bool) {
	var e bundleEntry
	fixed := 16
	if major >= 6 {
		fixed = 24
	}
	if len(b) < fixed+1 {
		return e, 0, false
	}
	e.offset = int64(binary.LittleEndian.Uint64(b))
	e.size = int64(binary.LittleEndian.Uint64(b[8:]))
	pos := 16
	if major >= 6 {
		e.compressed = int64(binary.LittleEndian.Uint64(b[16:]))
		pos = 24
	}
	e.kind = b[pos]
	pos++
	p, n, ok := read7(b, pos, bundleMaxPath)
	if !ok {
		return e, 0, false
	}
	e.path = p
	return e, pos + n, true
}

// read7 decodes a BinaryWriter 7-bit length prefix (max 5 bytes) and the bytes
// after it, refusing lengths beyond max.
func read7(b []byte, off, max int) (string, int, bool) {
	n, shift := 0, uint(0)
	for i := range 5 {
		if off+i >= len(b) {
			return "", 0, false
		}
		c := b[off+i]
		n |= int(c&0x7f) << shift
		shift += 7
		if c&0x80 == 0 {
			start := off + i + 1
			if n < 0 || n > max || start+n > len(b) {
				return "", 0, false
			}
			return string(b[start : start+n]), i + 1 + n, true
		}
	}
	return "", 0, false
}

// findBundleMarker streams a whole-file search for the 32-byte marker. The
// marker sits mid-file, not at EOF, so no bounded window can find it.
func findBundleMarker(f *os.File, size int64) (int64, bool) {
	const chunk = 1 << 20
	buf := make([]byte, chunk+bundleMarkerLen-1)
	pos, keep := int64(0), 0
	for pos < size {
		n, _ := f.ReadAt(buf[keep:], pos)
		if n <= 0 {
			break
		}
		window := buf[:keep+n]
		if i := bytes.Index(window, bundleMarker); i >= 0 {
			return pos - int64(keep) + int64(i), true
		}
		if n < bundleMarkerLen-1 {
			break
		}
		keep = bundleMarkerLen - 1
		copy(buf, window[len(window)-keep:])
		pos += int64(n)
	}
	return 0, false
}

func inspectDotNetSingleFile(path string, d *Digest) {
	switch d.Kind {
	case "pe", "macho", "elf":
	default:
		return
	}
	// Cheap gate before the whole-file marker scan on the Mach-O/ELF hosts: a
	// non-.NET native image does not import the hostfxr bundle entry point.
	// PE keeps the historical unconditional scan (its apphosts are small and
	// the marker is the only witness there).
	if d.Kind != "pe" && !bytes.Contains(head(path, 1<<20), dotnetApphostHint) {
		return
	}
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		return
	}
	size := st.Size()
	if size < bundleMarkerLen+8 {
		return
	}
	sig, found := findBundleMarker(f, size)
	if !found {
		// shortcut: a stripped or cut apphost can keep hostpolicy's bundling
		// env var name while losing the marker; a plain native PE keeps neither.
		if bytes.Contains(head(path, 1<<20), []byte("DOTNET_BUNDLE_EXTRACT_BASE_DIR")) {
			d.skip("dotnetsf-marker-missing", "bundle env var present, 32-byte marker absent")
		}
		return
	}
	d.scanned(size)
	d.claim("dotnet-singlefile", "bundle-marker", sig)
	if sig < 8 {
		d.skip("dotnetsf-header-invalid", "locator would start before the file")
		return
	}
	loc := make([]byte, 8)
	if _, err := f.ReadAt(loc, sig-8); err != nil {
		d.skip("dotnetsf-header-invalid", "locator unreadable")
		return
	}
	headerOff := int64(binary.LittleEndian.Uint64(loc))
	if headerOff < 0 || headerOff >= size {
		d.skip("dotnetsf-header-invalid", "header offset past EOF")
		return
	}

	hb := make([]byte, bundleHeadRead)
	n, _ := f.ReadAt(hb, headerOff)
	hb = hb[:n]
	if len(hb) < 8 {
		d.skip("dotnetsf-header-invalid", "header shorter than version fields")
		return
	}
	major, minor := binary.LittleEndian.Uint32(hb), binary.LittleEndian.Uint32(hb[4:])
	if !((major == 6 && minor == 0) || (major == 2 && minor == 0)) {
		d.skip("dotnetsf-version-unverified", fmt.Sprintf("%d.%d", major, minor))
		return
	}
	h, ok := parseBundleHeader(hb)
	if !ok {
		d.skip("dotnetsf-header-invalid", fmt.Sprintf("%d.%d header fields", major, minor))
		return
	}
	d.parsed()

	mobileCap(d, "dotnet-singlefile")
	mobileCap(d, fmt.Sprintf("dotnet-singlefile:files=%d", h.files))
	mobileCap(d, fmt.Sprintf("dotnet-singlefile:major=%d", major))

	buf := make([]byte, 32+bundleMaxPath)
	pos := headerOff + h.entriesFrom
	limit := int(h.files)
	capped := false
	if limit > bundleMaxFiles {
		limit, capped = bundleMaxFiles, true
	}
	var assemblies, natives int
	for i := 0; i < limit; i++ {
		n, _ := f.ReadAt(buf, pos)
		e, used, ok := parseBundleEntry(buf[:n], major)
		if !ok {
			d.skip("dotnetsf-truncated", "entry "+strconv.Itoa(i))
			return
		}
		pos += int64(used)
		if e.offset < 0 || e.size < 0 || e.offset+e.size > size {
			d.skip("dotnetsf-truncated", "payload out of range: "+e.path)
			return
		}
		d.parsed()
		if e.path != "" {
			d.Deps = append(d.Deps, Dep{Path: e.path, Version: strconv.FormatInt(e.size, 10) + "B"})
		}
		switch e.kind {
		case 1:
			assemblies++
		case 2:
			natives++
		}
	}
	if capped {
		d.Notes = append(d.Notes, fmt.Sprintf("bundle: %d of %d entries listed (cap %d)", limit, h.files, bundleMaxFiles))
	}

	note := fmt.Sprintf("container: dotnet-singlefile apphost, major %d, %d bundled file(s)", major, h.files)
	if h.id != "" {
		note += " (id " + h.id + ")"
	}
	d.Notes = append(d.Notes, note)
	d.Notes = append(d.Notes, fmt.Sprintf("bundled: %d assembly, %d native, %d other", assemblies, natives, limit-assemblies-natives))

	tc := "dotnet-singlefile"
	if rt := bundleRuntimeTarget(readBundleRange(f, size, h.depOff, h.depSize)); rt != "" {
		tc += " " + rt
	}
	if ver := bundleRuntimeVersion(readBundleRange(f, size, h.rtOff, h.rtSize)); ver != "" {
		tc += " runtime " + ver
	}
	if d.Toolchain == "" {
		d.Toolchain = tc
	} else {
		d.Notes = append(d.Notes, tc)
	}
	deepNote(d, "read the bundle header table for the entry list, then open the bundled assemblies to recover the managed types and methods")
}

// readBundleRange returns a bounded sidecar slice (deps.json / runtimeconfig)
// only when the recorded range is real; nothing is guessed from a bad offset.
func readBundleRange(f *os.File, size, off, n int64) []byte {
	if n <= 0 || off < 0 || off+n > size {
		return nil
	}
	if n > bundleMaxSidecar {
		n = bundleMaxSidecar
	}
	b := make([]byte, n)
	if _, err := f.ReadAt(b, off); err != nil {
		return nil
	}
	return b
}

var (
	bundleRuntimeRe = regexp.MustCompile(`"runtimeTarget"\s*:\s*\{[^}]*?"name"\s*:\s*"([^"]+)"`)
	bundleTFMRe     = regexp.MustCompile(`"tfm"\s*:\s*"([^"]+)"`)
	bundleFwVerRe   = regexp.MustCompile(`"framework"\s*:\s*\{[^}]*?"version"\s*:\s*"([^"]+)"`)
)

// bundleRuntimeTarget pulls the deps.json runtime target ("framework/rid") and
// keeps the framework half.
func bundleRuntimeTarget(b []byte) string {
	m := bundleRuntimeRe.FindSubmatch(b)
	if m == nil {
		return ""
	}
	return strings.TrimSpace(strings.SplitN(string(m[1]), "/", 2)[0])
}

// bundleRuntimeVersion prefers runtimeconfig's framework version, falling back
// to its tfm moniker.
func bundleRuntimeVersion(b []byte) string {
	if m := bundleFwVerRe.FindSubmatch(b); m != nil {
		return string(m[1])
	}
	if m := bundleTFMRe.FindSubmatch(b); m != nil {
		return string(m[1])
	}
	return ""
}
