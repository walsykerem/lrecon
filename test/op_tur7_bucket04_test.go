package main

// Tur 7 bucket 04: routing over the real artifact fleet the repo already ships
// under env/ and smoke/. Every collected file is handed to the built CLI as a
// target, and the kind it reports must equal the kind this file derives from the
// target's own bytes: ELF/PE/Mach-O magics, the fat-header table, the PE CLR
// data directory, the zip member layout (classes*.dex, AndroidManifest.xml,
// BundleConfig.pb, Payload/*.app/Info.plist), the wasm version word. Nothing
// here calls Probe or any package route helper: the expectation comes from the
// bytes read below. The whole-file sha256 is recomputed too, so a canned or
// plausibility-matched answer cannot pass.

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
)

const t7b04Cap = 300

// t7b04RepoRoot is the checkout root: this file lives in <root>/lrecon, so the
// test finds its fixtures without a path baked into the source.
func t7b04RepoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate this test file")
	}
	return filepath.Dir(filepath.Dir(file))
}

type t7b04Want struct {
	kind   string
	format string // "" when this kind's format is not derivable from the magic
}

type t7b04Artifact struct {
	path string
	size int64
	want t7b04Want
}

func TestTur7Bucket04Route(t *testing.T) {
	arts := t7b04Collect(t)
	if len(arts) < 100 {
		t.Fatalf("collected only %d binary artifacts under <root>/{env,smoke}; the fleet vanished", len(arts))
	}
	seen := map[string]int{}
	for _, a := range arts {
		seen[a.want.kind]++
	}
	// A sweep that only routes one family proves nothing about routing.
	for _, k := range []string{"elf", "macho", "pe", "pe-dotnet", "apk", "wasm"} {
		if seen[k] == 0 {
			t.Fatalf("fleet has no %s artifact (seen %v)", k, seen)
		}
	}
	for _, a := range arts {
		stdout, stderr, code := runCLIAll(t, "--json", a.path)
		if strings.Contains(stderr, "panic:") || strings.Contains(stdout, "panic:") {
			t.Fatalf("%s: tool panicked: %s", a.path, stderr)
		}
		if code != 0 {
			t.Fatalf("%s: exit %d, want 0; stdout=%q stderr=%q", a.path, code, stdout, stderr)
		}
		if strings.TrimSpace(stdout) == "" {
			t.Fatalf("%s: empty stdout for a %s target", a.path, a.want.kind)
		}
		var d Digest
		if err := json.Unmarshal([]byte(stdout), &d); err != nil {
			t.Fatalf("%s: stdout is not a digest: %v\n%s", a.path, err, stdout)
		}
		if d.Kind != a.want.kind {
			t.Fatalf("%s: magic says %s, tool reported kind %q", a.path, a.want.kind, d.Kind)
		}
		if a.want.format != "" && d.Format != a.want.format {
			t.Fatalf("%s: header says format %q, tool reported %q", a.path, a.want.format, d.Format)
		}
		if d.Target.Size != a.size {
			t.Fatalf("%s: target size %d, stat says %d", a.path, d.Target.Size, a.size)
		}
		scope, hashBytes, sum := t7b04Hash(a.path, a.size)
		if d.Target.HashScope != scope || d.Target.HashBytes != hashBytes {
			t.Fatalf("%s: hash scope %q/%d, want %q/%d", a.path, d.Target.HashScope, d.Target.HashBytes, scope, hashBytes)
		}
		if d.Target.FileSHA256 != sum {
			t.Fatalf("%s: digest hash %q, bytes on disk hash to %q", a.path, d.Target.FileSHA256, sum)
		}
	}
}

// t7b04Collect walks both artifact roots, derives the expected route from each
// file's own head, sorts, and caps. The cap is applied after the sort so the
// selection is stable across runs.
func t7b04Collect(t *testing.T) []t7b04Artifact {
	t.Helper()
	var cands []string
	root0 := t7b04RepoRoot(t)
	for _, root := range []string{filepath.Join(root0, "env"), filepath.Join(root0, "smoke")} {
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !d.Type().IsRegular() {
				return nil
			}
			cands = append(cands, p)
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}
	sort.Strings(cands)
	var out []t7b04Artifact
	for _, p := range cands {
		if len(out) == t7b04Cap {
			break
		}
		want, size, ok, err := t7b04Expect(p)
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		if ok {
			out = append(out, t7b04Artifact{path: p, size: size, want: want})
		}
	}
	return out
}

// t7b04Expect derives the route from the bytes, not from lrecon's tables.
func t7b04Expect(p string) (t7b04Want, int64, bool, error) {
	st, err := os.Stat(p)
	if err != nil {
		return t7b04Want{}, 0, false, err
	}
	if st.Size() == 0 {
		return t7b04Want{}, 0, false, nil // an empty file has no format
	}
	f, err := os.Open(p)
	if err != nil {
		return t7b04Want{}, 0, false, err
	}
	var head [512]byte
	n, err := io.ReadFull(f, head[:])
	f.Close()
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return t7b04Want{}, 0, false, err
	}
	h := head[:n]
	switch {
	case len(h) >= 4 && string(h[:4]) == "\x7fELF":
		return t7b04Want{kind: "elf"}, st.Size(), true, nil
	case len(h) >= 2 && h[0] == 'M' && h[1] == 'Z':
		kind, err := t7b04PECLRKind(p, st.Size())
		if err != nil {
			return t7b04Want{}, 0, false, err
		}
		return t7b04Want{kind: kind}, st.Size(), true, nil
	case len(h) >= 4 && (binary.LittleEndian.Uint32(h) == 0xfeedface || binary.LittleEndian.Uint32(h) == 0xfeedfacf):
		return t7b04Want{kind: "macho", format: "thin"}, st.Size(), true, nil
	case len(h) >= 24 && binary.BigEndian.Uint32(h) == 0xcafebabe:
		if !t7b04FatOK(h, st.Size()) {
			return t7b04Want{}, 0, false, nil // java class, not universal binary
		}
		return t7b04Want{kind: "macho", format: "fat"}, st.Size(), true, nil
	case len(h) >= 4 && string(h[:4]) == "PK\x03\x04":
		kind, err := t7b04ZipKind(p)
		if err != nil {
			return t7b04Want{}, 0, false, err
		}
		return t7b04Want{kind: kind}, st.Size(), true, nil
	case len(h) >= 16 && string(h[:16]) == "SQLite format 3\x00":
		return t7b04Want{kind: "sqlite"}, st.Size(), true, nil
	case len(h) >= 8 && string(h[:4]) == "\x00asm":
		return t7b04Want{kind: "wasm", format: "v" + strconv.FormatUint(uint64(binary.LittleEndian.Uint32(h[4:8])), 10)}, st.Size(), true, nil
	case len(h) >= 8 && string(h[:8]) == "bplist00":
		return t7b04Want{kind: "plist"}, st.Size(), true, nil
	case len(h) >= 4 && string(h[:4]) == "\xc6\x1f\xbc\x03":
		return t7b04Want{kind: "hermes"}, st.Size(), true, nil
	case len(h) >= 4 && string(h[:4]) == "\xf5\xf5\xdc\xdc":
		return t7b04Want{kind: "flutter"}, st.Size(), true, nil
	case len(h) >= 8 && string(h[:4]) == "dex\n" && isDecimal(h[4:7]):
		return t7b04Want{kind: "dex"}, st.Size(), true, nil
	}
	return t7b04Want{}, 0, false, nil
}

func isDecimal(b []byte) bool {
	for _, c := range b {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// t7b04DigestCap is the byte budget the digest contract publishes for a target
// identity: past it the hash is honestly labelled as a prefix.
const t7b04DigestCap = 64 << 20

// t7b04Hash recomputes what the target identity should say: whole-file for a
// file inside the budget, else the documented prefix.
func t7b04Hash(p string, size int64) (string, int64, string) {
	n, scope := size, "whole-file"
	if n > t7b04DigestCap {
		n = t7b04DigestCap
		scope = "first-" + strconv.FormatInt(n, 10) + "-bytes"
	}
	f, err := os.Open(p)
	if err != nil {
		return scope, n, ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, n)); err != nil {
		return scope, n, ""
	}
	return scope, n, hex.EncodeToString(h.Sum(nil))
}

// t7b04PECLRKind reads the PE optional header's data directory 14 (CLR runtime
// header) and maps its RVA through the section table. A present, in-file header
// of at least the 72-byte CLI size names a managed assembly.
func t7b04PECLRKind(p string, size int64) (string, error) {
	b, err := os.ReadFile(p)
	if err != nil {
		return "", err
	}
	if len(b) < 0x40 || string(b[:2]) != "MZ" {
		return "pe", nil
	}
	e := int64(binary.LittleEndian.Uint32(b[0x3c:]))
	if e+24 > int64(len(b)) || string(b[e:e+4]) != "PE\x00\x00" {
		return "pe", nil
	}
	nsec := int64(binary.LittleEndian.Uint16(b[e+6:]))
	optsz := int64(binary.LittleEndian.Uint16(b[e+20:]))
	opt := e + 24
	if opt+optsz > int64(len(b)) {
		return "pe", nil
	}
	var dd int64
	switch binary.LittleEndian.Uint16(b[opt:]) {
	case 0x10b:
		dd = opt + 96
	case 0x20b:
		dd = opt + 112
	default:
		return "pe", nil
	}
	if dd+15*8 > int64(len(b)) {
		return "pe", nil
	}
	dir := dd + 14*8
	rva := int64(binary.LittleEndian.Uint32(b[dir:]))
	sz := int64(binary.LittleEndian.Uint32(b[dir+4:]))
	if rva == 0 || sz < 72 {
		return "pe", nil
	}
	sec := opt + optsz
	for i := int64(0); i < nsec; i++ {
		o := sec + i*40
		if o+40 > int64(len(b)) {
			return "pe", nil
		}
		vs := int64(binary.LittleEndian.Uint32(b[o+8:]))
		va := int64(binary.LittleEndian.Uint32(b[o+12:]))
		rs := int64(binary.LittleEndian.Uint32(b[o+16:]))
		ra := int64(binary.LittleEndian.Uint32(b[o+20:]))
		if rva < va || rva >= va+max(vs, rs) {
			continue
		}
		off := ra + (rva - va)
		if off+72 <= size && off+72 <= int64(len(b)) {
			return "pe-dotnet", nil
		}
		return "pe", nil
	}
	return "pe", nil
}

// t7b04FatOK reads the fat header the way the format defines it: 1..64 slices,
// table inside the file, first slice after the table and inside the file.
func t7b04FatOK(h []byte, size int64) bool {
	n := int64(binary.BigEndian.Uint32(h[4:8]))
	if n < 1 || n > 64 || size < 8+20*n || int64(len(h)) < 8+20*n {
		return false
	}
	off := int64(binary.BigEndian.Uint32(h[16:20]))
	sz := int64(binary.BigEndian.Uint32(h[20:24]))
	return off >= 8+20*n && off+sz <= size
}

// t7b04ZipKind classifies a PK target by its member layout: BundleConfig.pb is
// an app bundle, Payload/<x>.app/Info.plist an iOS package, classes*.dex or a
// root AndroidManifest.xml an Android package. Anything else stays a plain zip.
func t7b04ZipKind(p string) (string, error) {
	zr, err := zip.OpenReader(p)
	if err != nil {
		return "zip", nil // magic says zip; the index is unreadable
	}
	defer zr.Close()
	ext := strings.ToLower(filepath.Ext(p))
	var payload, appPlist, manifest, dex, bundle bool
	for _, f := range zr.File {
		if strings.HasSuffix(f.Name, "/") {
			continue
		}
		low := strings.ToLower(f.Name)
		base := path.Base(low)
		switch {
		case base == "bundleconfig.pb":
			bundle = true
		case base == "androidmanifest.xml":
			manifest = true
		case strings.HasPrefix(low, "classes") && strings.HasSuffix(low, ".dex"):
			dex = true
		}
		if strings.HasPrefix(low, "payload/") {
			payload = true
			if strings.HasSuffix(low, ".app/info.plist") {
				appPlist = true
			}
		}
	}
	switch {
	case ext == ".aab" || bundle:
		return "aab", nil
	case ext == ".ipa" || (payload && appPlist):
		return "ipa", nil
	case ext == ".apk" || manifest || dex:
		return "apk", nil
	}
	return "zip", nil
}
