package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// Rust .rlib is a Unix ar archive: the lib.rmeta member carries the rustc
// metadata blob ("rust\0\0\0", one METADATA_VERSION byte, a length-prefixed
// version string at +16, +40 on master), and every codegen-unit member names
// the crate a second time. The container itself has no magic beyond ar, so this
// is a post reader: it never outranks a real magic kind.

const (
	rlibMagic      = "!<arch>\n"
	rlibMetaMagic  = "rust\x00\x00\x00"
	rlibHeaderSize = 60
	rlibMaxMembers = 4096
	rlibMetaScan   = 1 << 20 // the metadata member is a few hundred KiB
	rlibBlobWindow = 96      // version byte at +7, string at +16, master at +40
	rlibNameTable  = 1 << 20 // GNU "//" long-name table, bounded like the rest
	rlibMaxName    = 256
)

// rlibMetadataVersions maps the on-disk METADATA_VERSION byte to what the reader
// can honestly name. 11 is master: the layout is known, the release is not.
var rlibMetadataVersions = map[byte]string{10: "1.92", 11: "master"}

func init() {
	reasonRegistry["rlib"] = reasonSet(
		"rlib-archive-invalid",
		"rlib-metadata-absent",
		"rlib-name-mismatch",
		"rlib-too-many-members",
		"rlib-too-big",
		"rlib-version-unverified",
	)
	register(reader{
		format: "rlib",
		reasons: []string{
			"rlib-archive-invalid",
			"rlib-metadata-absent",
			"rlib-name-mismatch",
			"rlib-too-many-members",
			"rlib-too-big",
			"rlib-version-unverified",
		},
		post:    true,
		match:   rlibMatch,
		inspect: inspectRlib,
	})
}

// rlibMatch is the cheap prefilter: every static library is ar, so the file
// name decides ownership in inspectRlib, which sets the kind only for .rlib.
func rlibMatch(head []byte, _ int64) bool {
	return bytes.HasPrefix(head, []byte(rlibMagic))
}

// rlibMember is one ar entry with its name resolved: BSD archives store the
// name at the start of the payload ("#1/<len>"), GNU appends '/' in the field.
type rlibMember struct {
	name string
	off  int64 // payload start
	size int64
}

func inspectRlib(path string, d *Digest) {
	name := base(path)
	if !strings.HasSuffix(name, ".rlib") {
		return // every ar archive matches the prefilter; only .rlib is ours
	}
	d.Kind, d.Format = "rlib", "rlib"
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	members, err := rlibMembers(f, d.FileSize)
	if err != nil {
		d.skip("rlib-archive-invalid", err.Error())
		return
	}
	if len(members) >= rlibMaxMembers {
		d.skip("rlib-too-many-members", fmt.Sprintf("%d members", len(members)))
	}
	d.parsed()
	d.Capabilities = append(d.Capabilities, fmt.Sprintf("rlib:members=%d", len(members)))

	crate, ok := rlibFileCrate(name)
	if ok {
		d.claim(crate, "rlib-filename", 0)
	}
	if cgu, at, found := rlibCguCrate(members); found {
		switch {
		case !ok:
			d.claim(cgu, "rlib-cgu", at)
		case cgu == crate:
			d.claim(cgu, "rlib-cgu", at)
			d.Capabilities = append(d.Capabilities, "rlib:crate="+cgu)
		default:
			d.skip("rlib-name-mismatch", fmt.Sprintf("filename %s, cgu %s", crate, cgu))
		}
	}
	rlibMetadata(f, members, d)
}

// rlibMembers walks the bounded header chain. short headers at EOF are normal
// padding; anything else is a broken archive rather than a shorter one.
func rlibMembers(f *os.File, fileSize int64) ([]rlibMember, error) {
	var magic [8]byte
	if _, err := io.ReadFull(f, magic[:]); err != nil || string(magic[:]) != rlibMagic {
		return nil, fmt.Errorf("no %q magic", rlibMagic)
	}
	var (
		out  []rlibMember
		long []byte // GNU "//" long-name table, resolved after the walk
		hdr  [rlibHeaderSize]byte
		at   = int64(len(rlibMagic))
	)
	for len(out) < rlibMaxMembers {
		n, err := io.ReadFull(f, hdr[:])
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			if n == 0 {
				break
			}
			return nil, fmt.Errorf("short member header at %d", at)
		}
		if err != nil {
			return nil, err
		}
		if string(hdr[58:60]) != "`\n" {
			return nil, fmt.Errorf("bad member terminator at %d", at)
		}
		size, err := strconv.ParseInt(strings.TrimSpace(string(hdr[48:58])), 10, 64)
		if err != nil || size < 0 {
			return nil, fmt.Errorf("bad member size %q at %d", strings.TrimSpace(string(hdr[48:58])), at)
		}
		data := at + rlibHeaderSize
		if data+size > fileSize {
			return nil, fmt.Errorf("member at %d declares %d bytes past EOF", at, size)
		}
		raw := strings.TrimRight(string(hdr[:16]), " ")
		m := rlibMember{off: data, size: size}
		switch {
		case strings.HasPrefix(raw, "#1/"):
			nameLen, err := strconv.ParseInt(raw[3:], 10, 64)
			if err != nil || nameLen <= 0 || nameLen > size {
				return nil, fmt.Errorf("bad BSD name %q at %d", raw, at)
			}
			buf := make([]byte, nameLen)
			if _, err := f.ReadAt(buf, data); err != nil {
				return nil, fmt.Errorf("BSD name at %d: %w", at, err)
			}
			m.name = strings.TrimRight(string(buf), "\x00")
			m.off, m.size = data+nameLen, size-nameLen
		case raw == "//":
			long = make([]byte, min(size, int64(rlibNameTable)))
			if _, err := f.ReadAt(long, data); err != nil {
				return nil, fmt.Errorf("long-name table at %d: %w", at, err)
			}
		default:
			m.name = strings.TrimSuffix(raw, "/")
		}
		if raw != "//" {
			out = append(out, m)
		}
		at = data + size + size&1
		if _, err := f.Seek(at, io.SeekStart); err != nil {
			return nil, err
		}
	}
	for i := range out {
		if n, ok := strings.CutPrefix(out[i].name, "/"); ok {
			out[i].name = rlibLongName(long, n)
		}
	}
	return out, nil
}

// rlibLongName resolves a GNU "/<offset>" member name in the "//" table, whose
// entries are "<name>/\n".
func rlibLongName(table []byte, off string) string {
	i, err := strconv.Atoi(off)
	if err != nil || i < 0 || i >= len(table) {
		return ""
	}
	name := table[i:]
	if end := bytes.IndexByte(name, '\n'); end >= 0 {
		name = name[:end]
	}
	if len(name) > rlibMaxName {
		name = name[:rlibMaxName]
	}
	return strings.TrimSuffix(string(name), "/")
}

// rlibFileCrate reads the crate out of lib<name>-<hash>.rlib.
func rlibFileCrate(name string) (string, bool) {
	name = strings.TrimSuffix(name, ".rlib")
	name = strings.TrimPrefix(name, "lib")
	crate := name
	if i := strings.LastIndexByte(name, '-'); i > 0 && rlibHash(name[i+1:]) {
		crate = name[:i]
	}
	return crate, crate != "" && crate != name
}

// rlibCguCrate reads the crate out of a codegen-unit member name:
// lib<name>.<name>.<hex>-cgu.N.rcgu.o (rustc also drops the lib prefix).
func rlibCguCrate(members []rlibMember) (string, int64, bool) {
	for _, m := range members {
		if !strings.HasSuffix(m.name, ".rcgu.o") || !strings.Contains(m.name, "-cgu.") {
			continue
		}
		n := strings.TrimPrefix(m.name, "lib")
		first, _, ok := strings.Cut(n, ".")
		if !ok {
			continue
		}
		if i := strings.LastIndexByte(first, '-'); i > 0 && rlibHash(first[i+1:]) {
			first = first[:i]
		}
		if first != "" {
			return first, m.off, true
		}
	}
	return "", 0, false
}

func rlibHash(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// rlibMetadata reads only the first rlibBlobWindow bytes of the metadata blob:
// the version byte and the version string live there, and the rest of the
// member is metadata this reader does not claim to decode.
func rlibMetadata(f *os.File, members []rlibMember, d *Digest) {
	var meta *rlibMember
	for i := range members {
		if members[i].name == "lib.rmeta" {
			meta = &members[i]
			break
		}
	}
	if meta == nil {
		d.skip("rlib-metadata-absent", "no lib.rmeta member")
		return
	}
	limit := min(meta.size, rlibMetaScan)
	buf, ok := allocCeil(d, "rlib", limit, "rlib-too-big")
	if !ok {
		return
	}
	n, _ := f.ReadAt(buf, meta.off)
	buf = buf[:n]
	d.scannedAt(meta.off, int64(n))
	i := bytes.Index(buf, []byte(rlibMetaMagic))
	if i < 0 {
		d.skip("rlib-metadata-absent", "no rust magic in lib.rmeta")
		return
	}
	blob := buf[i:]
	if len(blob) < 8 {
		d.skip("rlib-metadata-absent", "rust magic without a version byte")
		return
	}
	if len(blob) > rlibBlobWindow {
		blob = blob[:rlibBlobWindow]
	}
	ver := blob[7]
	rel, known := rlibMetadataVersions[ver]
	d.Capabilities = append(d.Capabilities, fmt.Sprintf("rlib:metadata=%d", ver))
	if !known {
		d.skip("rlib-version-unverified", fmt.Sprintf("METADATA_VERSION=%d", ver))
		return
	}
	off := 16
	if ver == 11 {
		off = 40
	}
	if len(blob) > off {
		if l := int(blob[off]); l > 0 && off+1+l <= len(blob) {
			if v, ok := rlibToolchain(string(blob[off+1 : off+1+l])); ok {
				d.Toolchain = "rustc " + v
			}
		}
	}
	if d.Toolchain == "" {
		if rel == "master" {
			d.Notes = append(d.Notes, "rlib: master metadata (11) carries no release string")
		} else {
			d.Toolchain = "rustc " + rel
		}
	}
}

// rlibToolchain turns "rustc 1.92.0 (hash date)" into "1.92.0".
func rlibToolchain(s string) (string, bool) {
	if !strings.HasPrefix(s, "rustc ") {
		return "", false
	}
	fields := strings.Fields(s)
	if len(fields) < 2 {
		return "", false
	}
	return fields[1], true
}
