package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// maxExtract caps one written payload so a zip bomb cannot fill the disk.
var maxExtract int64 = 512 << 20

// maxExtractAll caps the whole tree: one archive of many small members must not fill the disk either.
// Both are vars so a test can lower them without writing gigabytes.
var maxExtractAll int64 = 2 << 30

// extractLimit is the live per-member cap. LRECON_BUNDLE_CAP_BYTES may lower it
// for one run, never raise it, and is read per call so an operator or a test can
// tighten the cap without rebuilding. The vars stay the ceiling because a test
// lowers them directly. cappedByEnv returns the effective cap so callers can
// surface it as cap_bytes instead of hiding the env.
//
// ponytail: no separate flag — one env var, one source of truth, measured via
// cap_bytes on extract_artifact / analyze_web_bundle / get_evidence_bundle.
func extractLimit() int64 { return cappedByEnv(maxExtract) }

// extractTotalLimit is extractLimit for the whole tree.
func extractTotalLimit() int64 { return cappedByEnv(maxExtractAll) }

func cappedByEnv(ceiling int64) int64 {
	if v := os.Getenv("LRECON_BUNDLE_CAP_BYTES"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 && n < ceiling {
			return n
		}
	}
	return ceiling
}

// capWords names a cap that can be far below a megabyte (a 64-byte test cap
// must not print as "0 MB").
func capWords(limit int64) string {
	if limit >= 1<<20 {
		return fmt.Sprintf("%d MB", limit>>20)
	}
	return fmt.Sprintf("%d bytes", limit)
}

// ExtractPayload writes one archive member into the working directory
// (zip/apk/ipa via archive/zip, asar via its header file table) and records
// the written path in d.Extracted. Only the base name is created, so a hostile
// member path cannot escape the working directory.
func ExtractPayload(pathName, member string, d *Digest) error {
	return ExtractPayloadTo(pathName, member, ".", d)
}

// ExtractPayloadTo is ExtractPayload with an explicit destination directory, so
// --extract can write into -o DIR instead of the process working directory.
func ExtractPayloadTo(pathName, member, dir string, d *Digest) error {
	if err := checkMember(member); err != nil {
		return err
	}
	// -o DIR may not exist yet. Create it here so a direct caller and the CLI
	// write to the same place; a directory this call created is rolled back on
	// failure, one that already existed is left alone.
	_, statErr := os.Stat(dir)
	created := os.IsNotExist(statErr)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("--extract: %s: %w", dir, err)
	}
	err := extractPayloadInto(pathName, member, dir, d)
	if err != nil && created {
		os.RemoveAll(dir)
	}
	return err
}

func extractPayloadInto(pathName, member, dir string, d *Digest) error {
	f, err := os.Open(pathName)
	if err != nil {
		return fmt.Errorf("--extract: %s: %w", pathName, err)
	}
	head := make([]byte, 20) // isAsar needs 20 bytes
	n, _ := io.ReadFull(f, head)
	if n >= 20 && isAsar(head[:n]) {
		defer f.Close()
		return extractAsar(f, pathName, member, dir, d)
	}
	f.Close()
	return extractZip(pathName, member, dir, d)
}

// ExtractAll writes every archive member under dir, keeping relative paths
// (zip/apk/ipa via archive/zip, asar via its header file table). Every member
// goes through checkMember, so nothing can be written outside dir; symlinks and
// asar unpacked stubs are skipped rather than materialised.
func ExtractAll(pathName, dir string, d *Digest) error {
	return ExtractAllCtx(context.Background(), pathName, dir, d)
}

// ExtractAllCtx is ExtractAll with a cancellation point per member: a slow or
// hostile archive cannot outlive the caller's budget.
func ExtractAllCtx(ctx context.Context, pathName, dir string, d *Digest) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if dir == "" {
		return errors.New("--extract-all: empty output directory")
	}
	// A directory this call created is rolled back on failure, so a cap trip
	// cannot leave gigabytes behind. One that already existed is left as it is:
	// its other contents are not ours to delete.
	_, statErr := os.Stat(dir)
	created := os.IsNotExist(statErr)
	// Create the tree root up front: an archive with no writable member still
	// owns the directory the digest reports, instead of pointing at nothing.
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("--extract-all: %s: %w", dir, err)
	}
	err := extractAllInto(ctx, pathName, dir, d)
	if err != nil && created {
		os.RemoveAll(dir)
	}
	return err
}

func extractAllInto(ctx context.Context, pathName, dir string, d *Digest) error {
	f, err := os.Open(pathName)
	if err != nil {
		return fmt.Errorf("--extract-all: %s: %w", pathName, err)
	}
	head := make([]byte, 20)
	n, _ := io.ReadFull(f, head)
	if n >= 20 && isAsar(head[:n]) {
		defer f.Close()
		return extractAsarAll(ctx, f, pathName, dir, d)
	}
	f.Close()
	return extractZipAll(ctx, pathName, dir, d)
}

// checkMember rejects anything that is not a plain relative archive path.
func checkMember(m string) error {
	switch {
	case m == "":
		return errors.New("--extract: empty member name")
	case path.IsAbs(m) || filepath.IsAbs(m):
		return fmt.Errorf("--extract: %q is an absolute path", m)
	case strings.Contains(m, `\`):
		return fmt.Errorf("--extract: %q contains a backslash", m)
	}
	if slices.Contains(strings.Split(m, "/"), "..") {
		return fmt.Errorf("--extract: %q contains a .. path element", m)
	}
	return nil
}

func extractZip(pathName, member, dir string, d *Digest) error {
	zr, err := zip.OpenReader(pathName)
	if err != nil {
		return fmt.Errorf("--extract: %s is neither a zip/apk/ipa nor an asar: %w", filepath.Base(pathName), err)
	}
	defer zr.Close()
	per := extractLimit()

	for _, f := range zr.File {
		if f.Name != member {
			continue
		}
		if f.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("--extract: %q is a symlink", member)
		}
		if f.UncompressedSize64 > uint64(per) {
			return sizeErr(member, int64(f.UncompressedSize64), per)
		}
		rc, err := f.Open()
		if err != nil {
			return fmt.Errorf("--extract: open %q: %w", member, err)
		}
		defer rc.Close()
		return writeMember(member, rc, dir, d)
	}
	return notFound(member, pathName)
}

// asarHeader parses the 16-byte frame plus the JSON file table and returns the
// body base offset. jsonLen is capped: a hostile header must not pick the alloc.
func asarHeader(f *os.File, verb string) (*asarNode, int64, error) {
	var hdr [16]byte
	if _, err := f.ReadAt(hdr[:], 0); err != nil {
		return nil, 0, fmt.Errorf("%s: asar header: %w", verb, err)
	}
	jsonLen := int64(binary.LittleEndian.Uint32(hdr[12:16]))
	if jsonLen <= 0 || jsonLen > 64<<20 {
		return nil, 0, fmt.Errorf("%s: asar header JSON length %d out of range", verb, jsonLen)
	}
	// Same framing inspectAsar uses: bodies start after the padded pickle.
	base := int64(8) + int64(binary.LittleEndian.Uint32(hdr[4:8]))
	if base < 16+jsonLen || base > 16+jsonLen+16 {
		base = (16 + jsonLen + 3) &^ 3
	}
	raw := make([]byte, jsonLen)
	if _, err := f.ReadAt(raw, 16); err != nil {
		return nil, 0, fmt.Errorf("%s: asar header JSON: %w", verb, err)
	}
	var root asarNode
	if err := json.Unmarshal(raw, &root); err != nil {
		return nil, 0, fmt.Errorf("%s: asar header JSON: %w", verb, err)
	}
	return &root, base, nil
}

func extractAsar(f *os.File, pathName, member, dir string, d *Digest) error {
	root, base, err := asarHeader(f, "--extract")
	if err != nil {
		return err
	}

	limit := extractLimit()
	n := lookupNode(root, member)
	switch {
	case n == nil:
		return notFound(member, pathName)
	case n.Files != nil:
		return fmt.Errorf("--extract: %q is a directory", member)
	case n.Link != "":
		return fmt.Errorf("--extract: %q is a symlink to %s", member, n.Link)
	case n.Unpacked:
		return fmt.Errorf("--extract: %q lives in %s.unpacked beside the archive", member, strings.TrimSuffix(filepath.Base(pathName), filepath.Ext(pathName)))
	case n.Size > limit:
		return sizeErr(member, n.Size, limit)
	}
	buf, ok := readAsarBody(f, base, n, limit, "extract", d)
	if !ok {
		return fmt.Errorf("--extract: %q body unreadable", member)
	}
	return writeMember(member, bytes.NewReader(buf), dir, d)
}

func writeMember(member string, r io.Reader, dir string, d *Digest) error {
	name := path.Base(member)
	limit := extractLimit()
	n, err := writeCapped(dir, name, r, limit)
	if err != nil {
		return fmt.Errorf("--extract: %s: %w", name, err)
	}
	d.Extracted = name
	d.Notes = append(d.Notes, fmt.Sprintf("extracted %s (%d bytes)", name, n))
	return nil
}

// writeCapped streams r into a temp file beside name and renames it only after
// a clean, under-limit copy, so a bad member never destroys a file already there.
func writeCapped(dir, name string, r io.Reader, limit int64) (int64, error) {
	tmp, err := os.CreateTemp(dir, "."+name+".tmp-*")
	if err != nil {
		return 0, err
	}
	tmpName := tmp.Name()
	n, err := io.Copy(tmp, io.LimitReader(r, limit+1))
	if err == nil {
		err = tmp.Chmod(0o644)
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil && n > limit {
		err = fmt.Errorf("%d bytes, above the %s extraction cap", n, capWords(limit))
	}
	if err == nil {
		err = os.Rename(tmpName, filepath.Join(dir, name))
	}
	if err != nil {
		os.Remove(tmpName)
	}
	return n, err
}

func sizeErr(member string, size, limit int64) error {
	return fmt.Errorf("--extract: %q is %d bytes, above the %s extraction cap", member, size, capWords(limit))
}

func notFound(member, pathName string) error {
	return fmt.Errorf("--extract: %q is not in %s", member, filepath.Base(pathName))
}

func extractZipAll(ctx context.Context, pathName, dir string, d *Digest) error {
	zr, err := zip.OpenReader(pathName)
	if err != nil {
		return fmt.Errorf("--extract-all: %s is neither a zip/apk/ipa nor an asar: %w", filepath.Base(pathName), err)
	}
	defer zr.Close()
	per, all := extractLimit(), extractTotalLimit()
	files, links := 0, 0
	var total int64
	for _, f := range zr.File {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("--extract-all: %s: %w", filepath.Base(pathName), err)
		}
		if err := checkMember(f.Name); err != nil {
			return err
		}
		if f.FileInfo().IsDir() {
			continue
		}
		if f.Mode()&os.ModeSymlink != 0 {
			links++
			continue
		}
		if f.UncompressedSize64 > uint64(per) {
			return sizeErr(f.Name, int64(f.UncompressedSize64), per)
		}
		if int64(f.UncompressedSize64) > all-total {
			return fmt.Errorf("--extract-all: total bytes, above the %s total cap", capWords(all))
		}
		rc, err := f.Open()
		if err != nil {
			return fmt.Errorf("--extract-all: open %q: %w", f.Name, err)
		}
		n, err := writeTree(dir, f.Name, rc, min(per, all-total))
		rc.Close()
		if err != nil {
			return err
		}
		total += n
		files++
	}
	d.Notes = append(d.Notes, extractNote(files, links, dir))
	return nil
}

func extractAsarAll(ctx context.Context, f *os.File, _, dir string, d *Digest) error {
	root, base, err := asarHeader(f, "--extract-all")
	if err != nil {
		return err
	}
	files, skips := 0, 0
	per, all := extractLimit(), extractTotalLimit()
	var total int64
	var walk func(prefix string, node *asarNode) error
	walk = func(prefix string, node *asarNode) error {
		for _, name := range sortedNodeKeys(node.Files) {
			if err := ctx.Err(); err != nil {
				return fmt.Errorf("--extract-all: %w", err)
			}
			child := node.Files[name]
			rel := prefix + name
			if err := checkMember(rel); err != nil {
				return err
			}
			if child.Files != nil {
				if err := walk(rel+"/", child); err != nil {
					return err
				}
				continue
			}
			if child.Link != "" || child.Unpacked {
				skips++
				continue
			}
			if child.Size > per {
				return sizeErr(rel, child.Size, per)
			}
			if child.Size > all-total {
				return fmt.Errorf("--extract-all: total bytes, above the %s total cap", capWords(all))
			}
			limit := min(per, all-total)
			buf, ok := readAsarBody(f, base, child, limit, "--extract-all: "+rel, d)
			// A zero-size member reads as (nil, true): it is a real empty file,
			// not a read failure, and aborting the whole tree on it made any
			// archive holding an empty file unextractable.
			if !ok {
				return fmt.Errorf("--extract-all: %q body unreadable", rel)
			}
			n, err := writeTree(dir, rel, bytes.NewReader(buf), limit)
			if err != nil {
				return err
			}
			total += n
			files++
		}
		return nil
	}
	if err := walk("", root); err != nil {
		return err
	}
	d.Notes = append(d.Notes, extractNote(files, skips, dir))
	return nil
}

// writeTree writes one member under dir; checkMember already ran, so the join
// cannot escape. limit is what this member may add before the disk cap trips.
func writeTree(dir, member string, r io.Reader, limit int64) (int64, error) {
	out := filepath.Join(dir, filepath.FromSlash(member))
	parent := filepath.Dir(out)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return 0, fmt.Errorf("--extract-all: %s: %w", member, err)
	}
	// The archive cannot plant a link here (those members are skipped), but -o
	// DIR is user-supplied and may already hold one: link/passwd would otherwise
	// be written through it, outside the tree. Resolve the parent and refuse.
	root, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return 0, fmt.Errorf("--extract-all: %s: %w", member, err)
	}
	real, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return 0, fmt.Errorf("--extract-all: %s: %w", member, err)
	}
	if real != root && !strings.HasPrefix(real, root+string(os.PathSeparator)) {
		return 0, fmt.Errorf("--extract-all: %s: %s is a symlink out of %s", member, parent, dir)
	}
	n, err := writeCapped(parent, filepath.Base(out), r, limit)
	if err != nil {
		return n, fmt.Errorf("--extract-all: %s: %w", member, err)
	}
	return n, nil
}

func extractNote(files, skips int, dir string) string {
	note := fmt.Sprintf("extracted %d files into %s", files, dir)
	if skips > 0 {
		note += fmt.Sprintf("; %d skipped (symlink or unpacked)", skips)
	}
	return note
}

func sortedNodeKeys(m map[string]*asarNode) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
