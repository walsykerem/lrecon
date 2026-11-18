package main

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Probe sniffs magic bytes first, then runs the cheapest inventory for that kind.
// Order matters: fat Mach-O before thin, asar before zip.
func Probe(path string) (d Digest, err error) {
	// Single refusal point: every completed digest must name only registered
	// reasons, or the caller gets an error instead of a plausible-looking answer.
	defer func() {
		d.Plan = digestPlan(d.Kind)
		if err == nil {
			// A reader that could not finish read a cut or corrupt target: no
			// absence answer may come out of it, so the whole digest is marked
			// partial before the gate runs. The flag states the scan, not the
			// parse: bytes_scanned == file_size means nothing was cut.
			if nativeParseFailed(d) {
				d.Truncated = d.BytesScanned < d.FileSize
			}
			d.gateAbsence()
			err = d.checkReasons()
		}
	}()
	// A digest that never scans for constants must say so: an absent field
	// reads as "nothing found", which is a different claim.
	d = Digest{ContractVersion: contractVersion, Path: path, Kind: "unknown",
		Constants: consts{constNotScanned}, Target: Target{HashScope: "none"}}
	// Stat before Open: opening a FIFO blocks until a writer shows up, and a
	// device file has no stable content to digest.
	st, err := os.Stat(path)
	if err != nil {
		return d, err
	}
	if st.IsDir() {
		// Only a macOS bundle is an artifact a reader can open inward. Any other
		// directory is a container the caller must inspect themselves, so naming
		// it succeeds would answer "what is this" with a non-answer.
		if !isAppBundle(path) {
			return d, fmt.Errorf("%s: is a directory, not an app bundle; name the artifact inside it", path)
		}
		inspectBundle(path, &d)
		AddUpdaterCaps(&d)
		return d, nil
	}
	if !st.Mode().IsRegular() {
		return d, fmt.Errorf("%s: not a regular file (%s)", path, st.Mode().Type())
	}
	if st.Size() == 0 {
		// A zero-byte target has no magic, no hash and no identity to report:
		// answering "unknown" would claim a format question was asked of bytes
		// that do not exist.
		return d, fmt.Errorf("%s: cannot read an empty target (0 bytes)", path)
	}
	d.FileSize = st.Size()
	f, err := os.Open(path)
	if err != nil {
		return d, err
	}
	defer f.Close()
	// Hash before the readers run: the target identity is the bytes on disk, and
	// one pass here keeps every reader from re-reading for it. The same pass
	// keeps the leading bytes, so the head costs no second seek+read and a short
	// read cannot silently truncate it.
	var headBuf [512]byte
	hc := headCapture{buf: headBuf[:]}
	var body io.Reader = f
	d.Target, err = hashTargetN(body, st.Size(), st.Size(), &hc)
	if err != nil {
		return d, err
	}
	// The file may change under a long read: a short read must be an error, not
	// a prefix hash labelled whole-file. Stat again so an in-place rewrite with
	// the same length is caught too.
	if st2, serr := os.Stat(path); serr != nil {
		return d, serr
	} else if st2.Size() != st.Size() || !st2.ModTime().Equal(st.ModTime()) {
		return d, fmt.Errorf("%s: cannot read a moving target (size %d -> %d, mtime changed)", path, st.Size(), st2.Size())
	}
	head, n := hc.buf[:hc.n], hc.n
	if n < 4 {
		d.Notes = append(d.Notes, "file smaller than 4 bytes")
		return d, nil
	}

	switch {
	case fatMachOTruncated(head, st.Size()):
		d.Kind, d.Format = "macho", "fat"
		d.Truncated = true
		d.Notes = append(d.Notes, fmt.Sprintf("fat header declares slices past EOF: file cut at %d bytes", st.Size()))
	case fatMachOOK(head, st.Size()):
		d.Kind, d.Format = "macho", "fat"
		inspectNative(path, &d)
	case isMachO(head):
		d.Kind, d.Format = "macho", "thin"
		inspectNative(path, &d)
	case bytes.HasPrefix(head, []byte("\x7fELF")):
		d.Kind = "elf"
		inspectNative(path, &d)
	case bytes.HasPrefix(head, []byte("MZ")):
		d.Kind = "pe"
		inspectNative(path, &d)
	case isAsar(head):
		d.Kind = "asar"
		inspectAsar(path, &d)
	case isDex(head):
		d.Kind = "dex"
		inspectDex(path, &d)
	case isBinaryXML(head):
		d.Kind = "android-manifest"
		inspectAndroidManifest(path, &d)
	case bytes.HasPrefix(head, []byte("\xc6\x1f\xbc\x03")):
		d.Kind = "hermes"
		deepNote(&d, "read the bytecode table to recover the function names, the string pool and the source file names the snapshot was built from")
	case bytes.HasPrefix(head, []byte("\xf5\xf5\xdc\xdc")):
		d.Kind = "flutter"
		if n >= 52 {
			d.FlutterHash = dartVersionHash(head[20:])
		}
		deepNote(&d, "map the snapshot hash to the matching Dart release, then read the data sections to recover the compiled code and the class list")
	case bytes.HasPrefix(head, []byte("\x00asm")) && n >= 8:
		d.Kind, d.Format = "wasm", fmt.Sprintf("v%d", binary.LittleEndian.Uint32(head[4:8]))
		d.Capabilities = append(d.Capabilities, "wasm")
		deepNote(&d, "read the section table to recover the type, import, function and export lists, then decode the function bodies")
	case bytes.HasPrefix(head, []byte("SQLite format 3\x00")):
		d.Kind = "sqlite"
		inspectSQLite(path, &d)
		if n >= 20 {
			// header bytes 18 and 19 are the write and read format versions
			ver := fmt.Sprintf("%d/%d", head[18], head[19])
			if d.SQLiteVersion != "" {
				ver += " lib " + d.SQLiteVersion
			}
			d.SQLiteVersion = ver
		}
	case bytes.HasPrefix(head, []byte("bplist00")) || isXMLPlist(head):
		d.Kind = "plist"
		inspectPlist(path, &d)
	case bytes.HasPrefix(head, []byte("NIBArchive")):
		d.Kind = "nib"
		deepNote(&d, "read the compiled interface archive to recover the object graph, the outlet names and the actions behind the screen")
	case isCodeSignature(head):
		d.Kind = "signature"
		deepNote(&d, "read the code directory and the requirement blobs to recover the signing identity, the team id and the sealed resources")
	case bytes.HasPrefix(head, []byte("CARV")):
		d.Kind = "car"
		deepNote(&d, "read the resource archive index to recover the asset names, their types and the compression of each entry")
	case bytes.HasPrefix(head, []byte("PK\x03\x04")):
		d.Kind = "zip"
		if !inspectArchive(path, &d) {
			deepNote(&d, "zip container: read the entry table to inventory the member names and sizes")
		}
	case pcapKind(head) != "":
		d.Kind, d.Format = "pcap", pcapKind(head)
		inspectPcap(path, &d)
	case firmwareKind(head) != "":
		d.Kind, d.Format = "firmware", firmwareKind(head)
		inspectFirmware(path, &d)
	default:
		// 0xcafebabe is shared with fat Mach-O (handled above), so a file that
		// reaches here claims the class magic only if its constant pool
		// opens: random bytes behind the magic must stay unknown, not be
		// named java by a reader that claims any plausible header.
		if len(head) >= 4 && binary.BigEndian.Uint32(head) == javaMagic && !plausibleClassHead(head) {
			break
		}
		if !dispatch(path, head, st.Size(), &d) && looksText(head) {
			d.Kind = "text"
			inspectPlainManifest(path, &d)
			deepNote(&d, "read the text itself before parsing: a config, a script or a log answers the question without a container parser")
		}
	}
	// section-name formats (Swift metadata) carry no magic of their own: the
	// Mach-O reader above already claimed the file, so they get their turn after
	// the switch.
	dispatchPost(path, head, st.Size(), &d)
	inspectManaged(path, &d)
	// Non-native formats carry no section map for scanSection; without a
	// whole-file pass their constants field would stay not_scanned even
	// though the reader read every byte.
	if len(d.Constants) == 1 && d.Constants[0] == constNotScanned {
		wholeFileConstants(path, &d)
	}
	// One settle pass, after every reader: a language claim needs a marker and a
	// mangling family from disjoint ranges, and no reader owns both. emit() holds
	// its settled set per call, so a second pass would append the same claims and
	// unknown entries again.
	d.settleLanguage()
	if d.Kind == "pe-dotnet" {
		// native PE parse cannot know the CLR-only machine (0xc020); managed.go owns this file
		d.Notes = dropNotes(d.Notes, "native: unrecognized PE machine")
	}
	if d.Kind == "unknown" {
		lead := head
		if len(lead) > 8 {
			lead = lead[:8]
		}
		d.Notes = append(d.Notes, fmt.Sprintf("no known magic; identify the format from the leading bytes before reading further (leading=%s)", hex.EncodeToString(lead)))
	}
	AddUpdaterCaps(&d)
	return d, nil
}

// digestPlan names the route the digest's kind needs: one static row in
// skill/SKILL.md, so a caller reads five plans instead of 235 op names.
func digestPlan(kind string) string {
	switch kind {
	case "macho", "elf", "pe":
		return kind
	case "apk", "ipa", "dex", "android-manifest":
		return "mobile"
	}
	return "generic"
}

func isMachO(h []byte) bool {
	if len(h) < 4 {
		return false
	}
	m := binary.LittleEndian.Uint32(h)
	return m == 0xfeedface || m == 0xfeedfacf
}

func isFatMachO(h []byte) bool {
	if len(h) < 4 {
		return false
	}
	return binary.BigEndian.Uint32(h) == 0xcafebabe
}

// fatMachOOK pins down the universal-binary magic, which Java class files and
// some jars also carry: the header must declare 1..64 architectures, the first
// architecture must name a real CPU, the table must fit in the file and the
// first slice must start after it. A byte-swapped header stays unknown, as it
// did before this check.
func fatMachOOK(h []byte, size int64) bool {
	if len(h) < 24 || !isFatMachO(h) {
		return false
	}
	n := int64(binary.BigEndian.Uint32(h[4:8]))
	if n < 1 || n > 64 || size < 8+20*n {
		return false
	}
	if !machoCPUType(binary.BigEndian.Uint32(h[8:12])) {
		return false
	}
	off := int64(binary.BigEndian.Uint32(h[16:20]))
	sz := int64(binary.BigEndian.Uint32(h[20:24]))
	return off >= 8+20*n && off+sz <= size
}

// machoCPUType reports whether t is a Mach-O CPU type. A Java class file
// carries the same magic and parks its version number where the CPU type
// belongs, so the type is what tells the two apart.
func machoCPUType(t uint32) bool {
	switch t {
	case 1, 6, 7, 11, 12, 13, 14, 15, 18, // x86, m68k, hppa, arm, m88k, sparc, i860, ppc
		0x01000007, 0x0100000c, 0x01000012: // x86_64, arm64, ppc64
		return true
	}
	return false
}

// nativeParseFailed reports a native reader error. Only this case may rewrite
// Truncated: other readers own their Truncated flag (pcap sets it on a cut
// record even when every byte in the file was scanned).
func nativeParseFailed(d Digest) bool {
	for _, n := range d.Notes {
		if strings.HasPrefix(n, "native: ") {
			return true
		}
	}
	return false
}

// parseFailed reports a reader that stopped before a complete parse. Each
// reader records that in its own note wording, so the check names the wordings;
// a failed parse cannot answer "not detected" even after a whole-file read.
// ponytail: note wording is a closed set for this release; a new reader that
// records a failure must add its prefix here, or tag notes with one shared marker.
func parseFailed(d Digest) bool {
	for _, n := range d.Notes {
		for _, p := range []string{
			"native: ", "asar: open:", "asar: truncated", "asar: malformed",
			"asar: implausible", "dex: open:", "dex: truncated",
			"java: ", "pyc: ", "zip: ", "android-manifest: open:",
			"android-manifest: truncated", "manifest: AXML parse failed",
			"manifest: XML parse failed", "sqlite: header truncated",
			"compress: xz payload not decoded",
		} {
			if strings.HasPrefix(n, p) {
				return true
			}
		}
	}
	return false
}

// fatMachOTruncated recognizes a real universal binary whose payload was cut:
// the cafebabe header is followed by a plausible arch count, so "no known
// magic" would be a wrong answer.
func fatMachOTruncated(h []byte, size int64) bool {
	if len(h) < 24 || !isFatMachO(h) {
		return false
	}
	n := int64(binary.BigEndian.Uint32(h[4:8]))
	if !machoCPUType(binary.BigEndian.Uint32(h[8:12])) {
		return false
	}
	return n >= 1 && n <= 64 && size >= 8+20*n && !fatMachOOK(h, size)
}

// plausibleClassHead tells a real class-file header from a fuzz target that
// happens to carry the shared 0xcafebabe magic. javaMatch only sees a version
// and a pool count, so a Class entry must resolve to a Utf8 name within the
// head: random bytes behind the magic can pass both but never name a class.
// The walk is tolerant here (a big pool running past the 512-byte head still
// resolves its first names), and the reader still owns the full parse; this
// only refuses to name a kind the leading bytes do not support.
func plausibleClassHead(h []byte) bool {
	if len(h) < 10 || binary.BigEndian.Uint32(h) != javaMagic {
		return false
	}
	maj := int(binary.BigEndian.Uint16(h[6:8]))
	if maj < 51 { // before module descriptors the pool often opens with Object
		_, _, off, ok := javaConstantPool(h, int(binary.BigEndian.Uint16(h[8:10])))
		if ok {
			return true
		}
		if off <= 11 {
			return false
		}
	}
	names := map[int]string{}
	off := 10
	for i := 1; i < int(binary.BigEndian.Uint16(h[8:10])); i++ {
		if off+1 > len(h) {
			return false
		}
		tag := h[off]
		off++
		switch tag {
		case 1:
			if off+2 > len(h) {
				return false
			}
			n := int(binary.BigEndian.Uint16(h[off:]))
			off += 2
			if off+n > len(h) {
				return false
			}
			names[i] = string(h[off : off+n])
			off += n
		case 7:
			if off+2 > len(h) {
				return false
			}
			if _, ok := names[int(binary.BigEndian.Uint16(h[off:]))]; ok {
				return true
			}
			off += 2
		case 5, 6:
			off += 8
			i++
		case 3, 4, 9, 10, 11, 12, 17, 18:
			off += 4
		case 8, 16, 19, 20:
			off += 2
		case 15:
			off += 3
		default:
			return false
		}
	}
	return false
}

// Asar: [uint32 4][uint32 pickleLen][uint32 payloadLen][uint32 jsonLen][json...]
func isAsar(h []byte) bool {
	if len(h) < 20 || binary.LittleEndian.Uint32(h) != 4 {
		return false
	}
	jsonLen := binary.LittleEndian.Uint32(h[12:16])
	return jsonLen > 2 && jsonLen < 64<<20 && h[16] == '{'
}

func looksText(h []byte) bool {
	if len(h) == 0 {
		return false
	}
	bad := 0
	for _, c := range h {
		if c == 0 {
			return false
		}
		if c < 9 || (c > 13 && c < 32) {
			bad++
		}
	}
	return bad*10 < len(h)
}

func base(p string) string { return filepath.Base(p) }

// hashTargetN reads want bytes once and fills the target identity: sha256 of
// the bytes, plus the git blob id, sha1 over "blob <n>\0" + the same bytes.
// headCapture keeps the first len(buf) bytes written through it, so Probe can
// hash and take the head in one pass over the file.
type headCapture struct {
	buf []byte
	n   int
}

func (h *headCapture) Write(p []byte) (int, error) {
	if h.n < len(h.buf) {
		h.n += copy(h.buf[h.n:], p)
	}
	return len(p), nil
}

// maxDigest caps the bytes one target identity reads: a 1 GB blob must not
// cost 1 GB of I/O and RAM for a hash nobody reads in full.
const maxDigest = 64 << 20

// hashTargetN hashes want bytes and reports the target as size bytes. A read
// that ends before want is an error: the usual reason is the file shrinking or
// being rewritten during the read, and returning that prefix would label a
// partial hash whole-file (final.md 399).
func hashTargetN(r io.Reader, size, want int64, head io.Writer) (Target, error) {
	scope := "whole-file"
	if want > maxDigest {
		want, scope = maxDigest, fmt.Sprintf("first-%d-bytes", maxDigest)
	}
	h256, h1 := sha256.New(), sha1.New()
	fmt.Fprintf(h1, "blob %d\x00", want)
	w := io.MultiWriter(h256, h1)
	if head != nil {
		w = io.MultiWriter(h256, h1, head)
	}
	n, err := io.Copy(w, io.LimitReader(r, want))
	if err != nil {
		return Target{}, fmt.Errorf("cannot read %d bytes of the target: %w", want, err)
	}
	if n != want {
		return Target{}, fmt.Errorf("cannot read %d bytes of the target: read stopped at %d, the file changed while it was read", want, n)
	}
	return Target{
		Size:       size,
		FileSHA256: hex.EncodeToString(h256.Sum(nil)),
		HashScope:  scope,
		HashBytes:  n,
		GitOID:     "gitoid:blob:sha1:" + hex.EncodeToString(h1.Sum(nil)),
	}, nil
}

// isAppBundle is the one directory shape Probe may open inward: a macOS .app
// wrapper, or a bundle whose Info.plist names its executable. Everything else
// is a container, not an artifact.
func isAppBundle(p string) bool {
	p = filepath.Clean(p)
	if strings.HasSuffix(strings.ToLower(p), ".app") {
		return true
	}
	return isFile(filepath.Join(p, "Contents", "Info.plist"))
}

func dropNotes(in []string, prefix string) []string {
	out := in[:0]
	for _, n := range in {
		if !strings.HasPrefix(n, prefix) {
			out = append(out, n)
		}
	}
	return out
}
