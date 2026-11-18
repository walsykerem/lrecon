package main

import (
	"archive/zip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeZipSymlink(t *testing.T, name, entry, target string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	f, err := os.Create(p)
	if err != nil {
		t.Fatalf("create %s: %v", p, err)
	}
	zw := zip.NewWriter(f)
	h := &zip.FileHeader{Name: entry, Method: zip.Store}
	h.SetMode(os.ModeSymlink | 0o777)
	w, err := zw.CreateHeader(h)
	if err != nil {
		t.Fatalf("zip symlink entry: %v", err)
	}
	if _, err := w.Write([]byte(target)); err != nil {
		t.Fatalf("zip symlink write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close %s: %v", p, err)
	}
	return p
}

func TestExtractPayloadZIP(t *testing.T) {
	zipPath := writeZip(t, "app.apk", []zipEntry{
		{"classes.dex", []byte("dex\n035 data")},
		{"lib/arm64-v8a/libfoo.so", []byte("\x7fELF data")},
	})
	linkPath := writeZipSymlink(t, "sym.zip", "link.so", "/etc/passwd")
	plainPath := filepath.Join(t.TempDir(), "plain.txt")
	if err := os.WriteFile(plainPath, []byte("not an archive"), 0o644); err != nil {
		t.Fatalf("write plain: %v", err)
	}

	cases := []struct {
		name     string
		archive  string
		member   string
		wantFile string
		wantData string
		wantErr  string
	}{
		{name: "root member", archive: zipPath, member: "classes.dex", wantFile: "classes.dex", wantData: "dex\n035 data"},
		{name: "nested member writes base name", archive: zipPath, member: "lib/arm64-v8a/libfoo.so", wantFile: "libfoo.so", wantData: "\x7fELF data"},
		{name: "missing member", archive: zipPath, member: "nope.bin", wantErr: `"nope.bin" is not in app.apk`},
		{name: "absolute path", archive: zipPath, member: "/etc/passwd", wantErr: "is an absolute path"},
		{name: "dotdot element", archive: zipPath, member: "../evil", wantErr: "contains a .. path element"},
		{name: "dotdot deep", archive: zipPath, member: "../../evil", wantErr: "contains a .. path element"},
		{name: "backslash", archive: zipPath, member: `lib\evil`, wantErr: "contains a backslash"},
		{name: "symlink entry", archive: linkPath, member: "link.so", wantErr: "is a symlink"},
		{name: "not a container", archive: plainPath, member: "classes.dex", wantErr: "is neither a zip/apk/ipa nor an asar"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			t.Chdir(dir)
			var d Digest
			err := ExtractPayload(tc.archive, tc.member, &d)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want containing %q", err, tc.wantErr)
				}
				if d.Extracted != "" {
					t.Fatalf("Extracted = %q on error", d.Extracted)
				}
				return
			}
			if err != nil {
				t.Fatalf("ExtractPayload: %v", err)
			}
			got, err := os.ReadFile(filepath.Join(dir, tc.wantFile))
			if err != nil {
				t.Fatalf("read %s: %v", tc.wantFile, err)
			}
			if string(got) != tc.wantData {
				t.Fatalf("%s = %q, want %q", tc.wantFile, got, tc.wantData)
			}
			if d.Extracted != tc.wantFile {
				t.Fatalf("Extracted = %q, want %q", d.Extracted, tc.wantFile)
			}
			if !notesContain(d, "extracted "+tc.wantFile) || !notesContain(d, "bytes)") {
				t.Fatalf("notes = %v, want extracted size note", d.Notes)
			}
		})
	}
}

// writeZipMixed builds a zip with one plain file and one symlink entry.
func writeZipMixed(t *testing.T, name, entry, target, plain string, body []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	f, err := os.Create(p)
	if err != nil {
		t.Fatalf("create %s: %v", p, err)
	}
	zw := zip.NewWriter(f)
	h := &zip.FileHeader{Name: entry, Method: zip.Store}
	h.SetMode(os.ModeSymlink | 0o777)
	w, err := zw.CreateHeader(h)
	if err != nil {
		t.Fatalf("zip symlink entry: %v", err)
	}
	if _, err := w.Write([]byte(target)); err != nil {
		t.Fatalf("zip symlink write: %v", err)
	}
	pw, err := zw.Create(plain)
	if err != nil {
		t.Fatalf("zip entry %s: %v", plain, err)
	}
	if _, err := pw.Write(body); err != nil {
		t.Fatalf("zip write %s: %v", plain, err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close %s: %v", p, err)
	}
	return p
}

func TestExtractAllZIP(t *testing.T) {
	bad := writeZip(t, "bad.apk", []zipEntry{{"../evil.txt", []byte("x")}})
	badDir := t.TempDir()
	var d0 Digest
	if err := ExtractAll(bad, badDir, &d0); err == nil || !strings.Contains(err.Error(), "contains a .. path element") {
		t.Fatalf("traversal err = %v", err)
	}
	if _, err := os.Stat(filepath.Join(badDir, "evil.txt")); err == nil {
		t.Fatal("traversal member landed inside dir")
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(badDir), "evil.txt")); err == nil {
		t.Fatal("traversal member landed outside dir")
	}
	fresh := filepath.Join(t.TempDir(), "fresh")
	if err := ExtractAll(bad, fresh, &d0); err == nil {
		t.Fatal("traversal zip accepted into a fresh dir")
	}
	if _, err := os.Stat(fresh); !os.IsNotExist(err) {
		t.Fatal("failed extract-all left the directory it created behind")
	}

	good := writeZipMixed(t, "ok.apk", "link.so", "/etc/passwd", "a/b.txt", []byte("hi"))
	out := filepath.Join(t.TempDir(), "tree")
	var d Digest
	if err := ExtractAll(good, out, &d); err != nil {
		t.Fatalf("ExtractAll: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(out, "a", "b.txt"))
	if err != nil {
		t.Fatalf("read a/b.txt: %v", err)
	}
	if string(got) != "hi" {
		t.Fatalf("a/b.txt = %q", got)
	}
	if _, err := os.Lstat(filepath.Join(out, "link.so")); err == nil {
		t.Fatal("symlink was materialised")
	}
	if !notesContain(d, "extracted 1 files") || !notesContain(d, "1 skipped") {
		t.Fatalf("notes = %v", d.Notes)
	}
}

func TestExtractPayloadAsar(t *testing.T) {
	src := writeAsarArchive(t, t.TempDir(), "app.asar", map[string][]byte{
		"package.json":  []byte(`{"main":"index.js"}`),
		"lib/index.js":  []byte("console.log(1)"),
		"lib/empty.bin": {},
	})

	dir := t.TempDir()
	t.Chdir(dir)

	var d Digest
	if err := ExtractPayload(src, "lib/index.js", &d); err != nil {
		t.Fatalf("ExtractPayload: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "index.js"))
	if err != nil {
		t.Fatalf("read index.js: %v", err)
	}
	if string(got) != "console.log(1)" {
		t.Fatalf("index.js = %q", got)
	}
	if d.Extracted != "index.js" {
		t.Fatalf("Extracted = %q", d.Extracted)
	}
	if !notesContain(d, "extracted index.js (14 bytes)") {
		t.Fatalf("notes = %v", d.Notes)
	}

	var de Digest
	if err := ExtractPayload(src, "lib/empty.bin", &de); err != nil {
		t.Fatalf("empty body: %v", err)
	}
	if fi, err := os.Stat("empty.bin"); err != nil || fi.Size() != 0 {
		t.Fatalf("empty.bin stat = %v, %v", fi, err)
	}

	var dd Digest
	if err := ExtractPayload(src, "lib", &dd); err == nil || !strings.Contains(err.Error(), "is a directory") {
		t.Fatalf("directory err = %v", err)
	}

	var dm Digest
	if err := ExtractPayload(src, "missing.js", &dm); err == nil || !strings.Contains(err.Error(), `"missing.js" is not in app.asar`) {
		t.Fatalf("missing err = %v", err)
	}

	var dt Digest
	if err := ExtractPayload(src, "../evil", &dt); err == nil || !strings.Contains(err.Error(), "contains a .. path element") {
		t.Fatalf("traversal err = %v", err)
	}
}

// A symlink already sitting inside -o DIR must not become a way out of it: the
// archive cannot plant one, but the destination is user-supplied.
func TestExtractAllSymlinkEscapeBlocked(t *testing.T) {
	outside := t.TempDir()
	out := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(out, "link")); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	src := writeZip(t, "l.zip", []zipEntry{{"link/pwned.txt", []byte("x")}})
	var d Digest
	err := ExtractAll(src, out, &d)
	if err == nil || !strings.Contains(err.Error(), "symlink out of") {
		t.Fatalf("err = %v, want a symlink-out-of refusal", err)
	}
	if _, err := os.Stat(filepath.Join(outside, "pwned.txt")); err == nil {
		t.Fatal("member was written through the symlink, outside the output tree")
	}
}

// An archive with nothing writable still owns the directory the caller reports.
func TestExtractAllEmptyArchiveCreatesDir(t *testing.T) {
	src := writeZip(t, "empty.zip", nil)
	out := filepath.Join(t.TempDir(), "tree")
	var d Digest
	if err := ExtractAll(src, out, &d); err != nil {
		t.Fatalf("ExtractAll: %v", err)
	}
	if fi, err := os.Stat(out); err != nil || !fi.IsDir() {
		t.Fatalf("output dir = %v, %v", fi, err)
	}
}

// Single-member extraction into a missing -o DIR must land inside that DIR, not
// beside the process working directory and not fail on a destination the caller
// was about to create anyway.
func TestExtractSingleCreatesMissingDir(t *testing.T) {
	src := writeZip(t, "one.zip", []zipEntry{{"a.txt", []byte("hello")}})
	out := filepath.Join(t.TempDir(), "deep", "tree")
	var d Digest
	if err := ExtractPayloadTo(src, "a.txt", out, &d); err != nil {
		t.Fatalf("ExtractPayloadTo: %v", err)
	}
	b, err := os.ReadFile(filepath.Join(out, "a.txt"))
	if err != nil || string(b) != "hello" {
		t.Fatalf("a.txt = %q, %v; want hello inside %s", b, err, out)
	}
}

// A member shorter than the file already at the destination must replace it:
// a leftover tail would silently corrupt the extracted artifact.
func TestExtractSingleOverwritesExistingFile(t *testing.T) {
	src := writeZip(t, "ow.zip", []zipEntry{{"a.txt", []byte("new")}})
	out := t.TempDir()
	dst := filepath.Join(out, "a.txt")
	if err := os.WriteFile(dst, []byte("old-content-that-is-longer"), 0o644); err != nil {
		t.Fatalf("seed %s: %v", dst, err)
	}
	var d Digest
	if err := ExtractPayloadTo(src, "a.txt", out, &d); err != nil {
		t.Fatalf("ExtractPayloadTo: %v", err)
	}
	b, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("read %s: %v", dst, err)
	}
	if string(b) != "new" {
		t.Fatalf("a.txt = %q, want the member body only", b)
	}
}

// TestExtractAllAsarZeroByteMember checks an empty member is written as an
// empty file instead of aborting the whole tree: real archives ship 0-byte
// files (a README stub, an empty .json), and "body unreadable" on one of them
// made every member after it unreachable.
func TestExtractAllAsarZeroByteMember(t *testing.T) {
	src := writeAsarArchive(t, t.TempDir(), "app.asar", map[string][]byte{
		"empty.md":     {},
		"dist/main.js": []byte("x=1\n"),
	})
	out := filepath.Join(t.TempDir(), "tree")
	var d Digest
	if err := ExtractAll(src, out, &d); err != nil {
		t.Fatalf("ExtractAll: %v", err)
	}
	for _, rel := range []string{"empty.md", "dist/main.js"} {
		if _, err := os.Stat(filepath.Join(out, rel)); err != nil {
			t.Fatalf("member %q missing: %v", rel, err)
		}
	}
	if fi, err := os.Stat(filepath.Join(out, "empty.md")); err != nil || fi.Size() != 0 {
		t.Fatalf("empty.md = %v, %v; want a 0-byte file", fi, err)
	}
}

// TestExtractSingleAsarZeroByteMember is the same empty member through the
// one-member path, which must write a 0-byte file rather than refuse it.
func TestExtractSingleAsarZeroByteMember(t *testing.T) {
	src := writeAsarArchive(t, t.TempDir(), "one.asar", map[string][]byte{"empty.md": {}})
	out := t.TempDir()
	var d Digest
	if err := ExtractPayloadTo(src, "empty.md", out, &d); err != nil {
		t.Fatalf("ExtractPayloadTo: %v", err)
	}
	fi, err := os.Stat(filepath.Join(out, "empty.md"))
	if err != nil {
		t.Fatalf("empty.md missing: %v", err)
	}
	if fi.Size() != 0 {
		t.Fatalf("empty.md size = %d, want 0", fi.Size())
	}
}
