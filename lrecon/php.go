package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"strconv"
)

// PHP runtime artifacts (R13 in notes-r.md): the opcache file cache has a fixed
// header behind a magic; a phar has no magic at all, only a stub terminator and
// a manifest, so it registers as a post reader.

var (
	opcacheMagic = []byte("OPCACHE\x00")
	pharHalt     = []byte("__HALT_COMPILER();")
)

const (
	maxPharBytes    = 32 << 20  // whole-file read cap
	maxPharManifest = 100 << 20 // archive-declared manifest cap
	maxPharDeps     = 256
	pharFixedLen    = 18         // count+api+flags+alias_len+metadata_len
	pharSigWhole    = 0x00F00000 // whole-archive gzip/bzip2
	pharEntryZlib   = 0x1000     // entry flags & 0x0000F000
	pharEntryBzip2  = 0x2000
)

var pharSigLens = map[uint32]int{1: 16, 2: 20, 3: 32, 4: 64}
var pharSigNames = map[uint32]string{1: "md5", 2: "sha1", 3: "sha256", 4: "sha512"}

func init() {
	register(reader{
		format:  "php-opcache",
		reasons: []string{"opcache-header-unverified", "opcache-truncated"},
		match: func(head []byte, size int64) bool {
			return bytes.HasPrefix(head, opcacheMagic)
		},
		inspect: inspectOpcache,
	})
	register(reader{
		format:     "phar",
		post:       true,
		claimsKind: true,
		reasons:    []string{"phar-manifest-invalid", "phar-api-version-unverified", "phar-signature-length-mismatch", "phar-too-large", "phar-tar-based", "phar-zip-based", "phar-whole-file-compressed"},
		match: func(head []byte, size int64) bool {
			return bytes.Contains(head, pharHalt)
		},
		inspect: inspectPhar,
	})
}

// inspectOpcache reads the one script record in a file-cache file. The path
// convention carries the realpath, so only the header is read.
func inspectOpcache(path string, d *Digest) {
	st, err := os.Stat(path)
	if err != nil {
		return
	}
	size := st.Size()
	if size < 60 {
		d.skip("opcache-truncated", fmt.Sprintf("%d-byte file cannot hold a header", size))
		return
	}
	n := min(size, 80)
	b := make([]byte, n)
	f, err := os.Open(path)
	if err != nil {
		return
	}
	_, err = io.ReadFull(f, b)
	f.Close()
	if err != nil {
		d.skip("opcache-truncated", err.Error())
		return
	}
	d.scanned(int64(len(b)))

	// hdrSize is not a constant: 80 on LP64, 60 on ILP32, and the header struct
	// is binary-identical across PHP 7.0-8.6. Every later offset depends on it,
	// so anything outside the known sizes is a refusal, not a guess.
	mem8 := binary.LittleEndian.Uint64(b[40:48])
	str8 := binary.LittleEndian.Uint64(b[48:56])
	hdr, width := int64(-1), 8
	if mem8 <= uint64(size) && str8 <= uint64(size)-mem8 {
		if h := size - int64(mem8) - int64(str8); h == 80 || h == 72 || h == 64 {
			hdr = h
		}
	}
	if hdr < 0 {
		// ILP32: the ulongs are 4 bytes, so the 8-byte read above straddles them.
		mem4 := uint64(binary.LittleEndian.Uint32(b[40:44]))
		str4 := uint64(binary.LittleEndian.Uint32(b[44:48]))
		if mem4+str4 <= uint64(size) && size-int64(mem4)-int64(str4) == 60 {
			hdr, width = 60, 4
		}
	}
	if hdr < 0 {
		if mem8 > uint64(size) || str8 > uint64(size)-mem8 {
			d.skip("opcache-truncated", "declared memory and string pools exceed the file")
		} else {
			d.skip("opcache-header-unverified", fmt.Sprintf("%d-byte header", size-int64(mem8)-int64(str8)))
		}
		return
	}

	var memSize, strSize, timestamp uint64
	if width == 4 {
		memSize = uint64(binary.LittleEndian.Uint32(b[40:44]))
		strSize = uint64(binary.LittleEndian.Uint32(b[44:48]))
		timestamp = uint64(binary.LittleEndian.Uint32(b[52:56]))
	} else {
		// The timestamp field starts at 64, so a 64-byte header ends before it:
		// reading there would take pool bytes as a timestamp.
		if len(b) < 72 || hdr < 72 {
			d.skip("opcache-header-unverified", "header ends before the timestamp field")
			return
		}
		memSize, strSize = mem8, str8
		timestamp = binary.LittleEndian.Uint64(b[64:72])
	}

	systemID := string(b[8:40])
	d.Capabilities = append(d.Capabilities,
		"opcache:system_id="+systemID,
		fmt.Sprintf("opcache:mem_size=%d", memSize),
		fmt.Sprintf("opcache:str_size=%d", strSize),
		fmt.Sprintf("opcache:script_timestamp=%d", timestamp))
	// The system id hashes PHP_VERSION + extension and binary ids one way: it
	// names a build, never a version, so version recovery is refused here.
	d.Notes = append(d.Notes, "opcache: script path is <file_cache>/<32-char system_id>/<realpath>.bin (a second 32-char accel_uname_id dir on Windows); system_id is one-way, so the PHP version is not recoverable from it")
	d.parsed()
}

// phpCursor is a bounded little-endian reader shared by the phar manifest.
type phpCursor struct {
	b   []byte
	off int
}

func (c *phpCursor) u32() (uint32, bool) {
	if c.off+4 > len(c.b) {
		return 0, false
	}
	v := binary.LittleEndian.Uint32(c.b[c.off:])
	c.off += 4
	return v, true
}

func (c *phpCursor) be16() (uint16, bool) {
	if c.off+2 > len(c.b) {
		return 0, false
	}
	v := binary.BigEndian.Uint16(c.b[c.off:])
	c.off += 2
	return v, true
}

func (c *phpCursor) take(n int) ([]byte, bool) {
	if n < 0 || n > len(c.b)-c.off {
		return nil, false
	}
	b := c.b[c.off : c.off+n]
	c.off += n
	return b, true
}

// inspectPhar validates the stub terminator and the manifest, then lists the
// entries. Every structural mismatch is a registered refusal.
func inspectPhar(path string, d *Digest) {
	st, err := os.Stat(path)
	if err != nil {
		return
	}
	size := st.Size()
	if size > maxPharBytes {
		d.skip("phar-too-large", fmt.Sprintf("%d bytes", size))
		return
	}
	b, err := readCapped(path, maxPharBytes)
	if err != nil {
		return
	}
	// Every offset below is a slice into b, so the file size that survives the
	// read is len(b): the stat above only refused a file that was already too
	// big, and a file that shrank in between would slice past the end.
	size = int64(len(b))
	if size > maxPharBytes {
		d.skip("phar-too-large", fmt.Sprintf("%d bytes after read", len(b)))
		return
	}
	d.scanned(int64(len(b)))
	if d.Format == "" {
		d.Format = "phar"
	}

	switch {
	case bytes.HasPrefix(b, []byte("PK\x03\x04")), bytes.HasPrefix(b, []byte("PK\x05\x06")):
		d.skip("phar-zip-based", "zip container, no stub+manifest")
		return
	case len(b) > 262 && string(b[257:262]) == "ustar":
		d.skip("phar-tar-based", "tar container, no stub+manifest")
		return
	case bytes.HasPrefix(b, []byte{0x1f, 0x8b}), bytes.HasPrefix(b, []byte("BZh")):
		d.skip("phar-whole-file-compressed", "compressed container, no stub+manifest")
		return
	}

	i := bytes.Index(b, pharHalt)
	if i < 0 {
		d.skip("phar-manifest-invalid", "stub terminator not found")
		return
	}
	p := i + len(pharHalt)
	// Optional " ?>" and the one allowed line break between stub and manifest.
	if p < len(b) && b[p] == ' ' {
		p++
	}
	if p+1 < len(b) && b[p] == '?' && b[p+1] == '>' {
		p += 2
	}
	if p+1 < len(b) && b[p] == '\r' && b[p+1] == '\n' {
		p += 2
	} else if p < len(b) && b[p] == '\n' {
		p++
	}

	c := &phpCursor{b: b, off: p}
	manifestLen, ok := c.u32()
	if !ok || manifestLen < pharFixedLen || manifestLen > maxPharManifest {
		d.skip("phar-manifest-invalid", fmt.Sprintf("manifest length %d", manifestLen))
		return
	}
	base := p + 4
	end := int64(base) + int64(manifestLen)
	if end > int64(len(b)) {
		d.skip("phar-manifest-invalid", fmt.Sprintf("manifest length %d exceeds the file", manifestLen))
		return
	}
	m := &phpCursor{b: b[base:end]}
	count, ok := m.u32()
	if !ok || count == 0 {
		d.skip("phar-manifest-invalid", "entry count is zero or truncated")
		return
	}
	api, ok := m.be16()
	if !ok {
		d.skip("phar-manifest-invalid", "api version truncated")
		return
	}
	if api&0xFFF0 < 0x1000 {
		d.skip("phar-api-version-unverified", fmt.Sprintf("0x%04x", api))
		return
	}
	gflags, ok := m.u32()
	if !ok {
		d.skip("phar-manifest-invalid", "global flags truncated")
		return
	}
	if gflags&pharSigWhole != 0 {
		d.skip("phar-whole-file-compressed", fmt.Sprintf("global flags 0x%08x", gflags))
		return
	}
	aliasLen, ok := m.u32()
	if !ok {
		d.skip("phar-manifest-invalid", "alias length truncated")
		return
	}
	metaLen, ok := m.u32()
	if !ok {
		d.skip("phar-manifest-invalid", "metadata length truncated")
		return
	}
	if _, ok := m.take(int(aliasLen) + int(metaLen)); !ok {
		d.skip("phar-manifest-invalid", "alias or metadata exceeds the manifest")
		return
	}

	var contents int64
	var deps, zlib, bzip2 int
	for i := range count {
		nameLen, ok := m.u32()
		if !ok || nameLen == 0 {
			d.skip("phar-manifest-invalid", fmt.Sprintf("entry %d name truncated", i))
			return
		}
		name, ok := m.take(int(nameLen))
		if !ok {
			d.skip("phar-manifest-invalid", fmt.Sprintf("entry %d name exceeds the manifest", i))
			return
		}
		uncompressed, ok := m.u32()
		if !ok {
			d.skip("phar-manifest-invalid", fmt.Sprintf("entry %d size truncated", i))
			return
		}
		// timestamp, crc32: read but not surfaced.
		if _, ok := m.u32(); !ok {
			d.skip("phar-manifest-invalid", fmt.Sprintf("entry %d timestamp truncated", i))
			return
		}
		compressed, ok := m.u32()
		if !ok {
			d.skip("phar-manifest-invalid", fmt.Sprintf("entry %d compressed size truncated", i))
			return
		}
		if _, ok := m.u32(); !ok {
			d.skip("phar-manifest-invalid", fmt.Sprintf("entry %d crc32 truncated", i))
			return
		}
		eflags, ok := m.u32()
		if !ok {
			d.skip("phar-manifest-invalid", fmt.Sprintf("entry %d flags truncated", i))
			return
		}
		emeta, ok := m.u32()
		if !ok {
			d.skip("phar-manifest-invalid", fmt.Sprintf("entry %d metadata length truncated", i))
			return
		}
		if _, ok := m.take(int(emeta)); !ok {
			d.skip("phar-manifest-invalid", fmt.Sprintf("entry %d metadata exceeds the manifest", i))
			return
		}
		contents += int64(compressed)
		if deps < maxPharDeps {
			d.Deps = append(d.Deps, Dep{Path: string(name), Version: strconv.FormatUint(uint64(uncompressed), 10)})
			deps++
		}
		switch eflags & 0x0000F000 {
		case pharEntryZlib:
			zlib++
		case pharEntryBzip2:
			bzip2++
		}
	}
	if m.off != len(m.b) {
		d.skip("phar-manifest-invalid", fmt.Sprintf("%d trailing manifest bytes", len(m.b)-m.off))
		return
	}
	if end+contents > size {
		d.skip("phar-manifest-invalid", fmt.Sprintf("entry sizes exceed the file by %d bytes", end+contents-size))
		return
	}

	d.Capabilities = append(d.Capabilities,
		fmt.Sprintf("phar:api_version=%#x", api),
		fmt.Sprintf("phar:entries=%d", count))
	if deps < int(count) {
		d.Notes = append(d.Notes, fmt.Sprintf("phar: %d entries, deps capped at %d", count, maxPharDeps))
	}
	if zlib+bzip2 > 0 {
		d.Notes = append(d.Notes, fmt.Sprintf("phar: compression zlib=%d bzip2=%d", zlib, bzip2))
	}

	// EOF signature: signature bytes, u32le flags, "GBMB". Fixed-length digests
	// store no length; openssl signatures put u32le sigLen before the flags.
	if size >= 12 && string(b[size-4:]) == "GBMB" {
		sf := binary.LittleEndian.Uint32(b[size-8:])
		if want, fixed := pharSigLens[sf]; fixed {
			got := size - 8 - end - contents
			if got != int64(want) {
				d.skip("phar-signature-length-mismatch", fmt.Sprintf("%s is %d bytes, not %d", pharSigNames[sf], got, want))
				return
			}
			d.Capabilities = append(d.Capabilities, "phar:signature="+pharSigNames[sf])
			d.Notes = append(d.Notes, "phar: signature "+pharSigNames[sf]+" in the GBMB trailer")
		} else if sf == 0x10 || sf == 0x11 || sf == 0x12 {
			sigLen := int64(binary.LittleEndian.Uint32(b[size-12:]))
			got := size - 12 - end - contents
			if got != sigLen {
				d.skip("phar-signature-length-mismatch", fmt.Sprintf("openssl signature is %d bytes, not %d", got, sigLen))
				return
			}
			d.Capabilities = append(d.Capabilities, fmt.Sprintf("phar:signature=openssl(0x%02x)", sf))
			d.Notes = append(d.Notes, fmt.Sprintf("phar: openssl signature (0x%02x) in the GBMB trailer", sf))
		} else {
			d.Capabilities = append(d.Capabilities, fmt.Sprintf("phar:signature=unknown(0x%04x)", sf))
		}
	}
	d.parsed()
}
