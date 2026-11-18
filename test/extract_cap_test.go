package main

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// setExtractCaps lowers the disk caps for one test.
func setExtractCaps(t *testing.T, per, all int64) {
	t.Helper()
	oldPer, oldAll := maxExtract, maxExtractAll
	maxExtract, maxExtractAll = per, all
	t.Cleanup(func() { maxExtract, maxExtractAll = oldPer, oldAll })
}

// lieZipSizes rewrites the central directory so named members claim fewer
// uncompressed bytes than their bodies carry.
func lieZipSizes(t *testing.T, path string, declared map[string]uint32) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	for i := 0; ; {
		j := bytes.Index(b[i:], []byte("PK\x01\x02"))
		if j < 0 {
			break
		}
		c := i + j
		nameLen := int(binary.LittleEndian.Uint16(b[c+28:]))
		extraLen := int(binary.LittleEndian.Uint16(b[c+30:]))
		commentLen := int(binary.LittleEndian.Uint16(b[c+32:]))
		if d, ok := declared[string(b[c+46:c+46+nameLen])]; ok {
			binary.LittleEndian.PutUint32(b[c+24:], d)
		}
		i = c + 46 + nameLen + extraLen + commentLen
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func assertNoTemp(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".") && strings.Contains(e.Name(), ".tmp-") {
			t.Fatalf("left temp file %s behind", e.Name())
		}
	}
}

func TestExtractPayloadLyingMemberKeepsFile(t *testing.T) {
	zp := writeZip(t, "liar.apk", []zipEntry{{"liar.bin", bytes.Repeat([]byte("A"), 40)}})
	lieZipSizes(t, zp, map[string]uint32{"liar.bin": 1})

	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.WriteFile("liar.bin", []byte("keep me"), 0o644); err != nil {
		t.Fatalf("seed liar.bin: %v", err)
	}
	var d Digest
	if err := ExtractPayload(zp, "liar.bin", &d); err == nil {
		t.Fatal("lying member was accepted")
	}
	if d.Extracted != "" {
		t.Fatalf("Extracted = %q on error", d.Extracted)
	}
	got, err := os.ReadFile("liar.bin")
	if err != nil {
		t.Fatalf("pre-existing liar.bin is gone: %v", err)
	}
	if string(got) != "keep me" {
		t.Fatalf("liar.bin = %q, want the old content", got)
	}
	assertNoTemp(t, dir)
}

func TestExtractAllLyingMemberKeepsFile(t *testing.T) {
	zp := writeZip(t, "liar.apk", []zipEntry{{"sub/liar.bin", bytes.Repeat([]byte("A"), 40)}})
	lieZipSizes(t, zp, map[string]uint32{"sub/liar.bin": 1})

	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sub", "liar.bin"), []byte("keep me"), 0o644); err != nil {
		t.Fatalf("seed liar.bin: %v", err)
	}
	var d Digest
	if err := ExtractAll(zp, dir, &d); err == nil {
		t.Fatal("lying member was accepted")
	}
	got, err := os.ReadFile(filepath.Join(dir, "sub", "liar.bin"))
	if err != nil {
		t.Fatalf("pre-existing liar.bin is gone: %v", err)
	}
	if string(got) != "keep me" {
		t.Fatalf("liar.bin = %q, want the old content", got)
	}
	assertNoTemp(t, filepath.Join(dir, "sub"))
}

func TestExtractAllTotalCapTrips(t *testing.T) {
	zp := writeZip(t, "two.apk", []zipEntry{
		{"a.bin", bytes.Repeat([]byte("a"), 20)},
		{"b.bin", bytes.Repeat([]byte("b"), 20)},
	})
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "b.bin"), []byte("keep me"), 0o644); err != nil {
		t.Fatalf("seed b.bin: %v", err)
	}
	setExtractCaps(t, maxExtract, 30)

	var d Digest
	err := ExtractAll(zp, dir, &d)
	if err == nil || !strings.Contains(err.Error(), "total cap") {
		t.Fatalf("err = %v, want the total cap", err)
	}
	got, rerr := os.ReadFile(filepath.Join(dir, "b.bin"))
	if rerr != nil {
		t.Fatalf("pre-existing b.bin is gone: %v", rerr)
	}
	if string(got) != "keep me" {
		t.Fatalf("b.bin = %q, want the old content", got)
	}
	if _, serr := os.Stat(filepath.Join(dir, "a.bin")); serr != nil {
		t.Fatalf("honest first member was not written: %v", serr)
	}
	assertNoTemp(t, dir)
}

func TestWriteTreeBudgetCountsBytes(t *testing.T) {
	setExtractCaps(t, 1<<20, 30)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "b.bin"), []byte("keep me"), 0o644); err != nil {
		t.Fatalf("seed b.bin: %v", err)
	}
	if _, err := writeTree(dir, "a.bin", strings.NewReader(strings.Repeat("a", 20)), maxExtractAll); err != nil {
		t.Fatalf("first member: %v", err)
	}
	_, err := writeTree(dir, "b.bin", strings.NewReader(strings.Repeat("b", 20)), maxExtractAll-20)
	if err == nil || !strings.Contains(err.Error(), "extraction cap") {
		t.Fatalf("err = %v, want the cap", err)
	}
	if got, rerr := os.ReadFile(filepath.Join(dir, "b.bin")); rerr != nil || string(got) != "keep me" {
		t.Fatalf("b.bin = %q, %v; want the old content", got, rerr)
	}
	if fi, serr := os.Stat(filepath.Join(dir, "a.bin")); serr != nil || fi.Size() != 20 {
		t.Fatalf("a.bin = %v, %v; want 20 bytes", fi, serr)
	}
	assertNoTemp(t, dir)
}

func TestExtractAllAsarTotalCapTrips(t *testing.T) {
	src := writeAsarArchive(t, t.TempDir(), "app.asar", map[string][]byte{
		"a.bin": bytes.Repeat([]byte("a"), 8),
		"b.bin": bytes.Repeat([]byte("b"), 8),
	})
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "b.bin"), []byte("keep me"), 0o644); err != nil {
		t.Fatalf("seed b.bin: %v", err)
	}
	setExtractCaps(t, maxExtract, 10)

	var d Digest
	err := ExtractAll(src, dir, &d)
	if err == nil || !strings.Contains(err.Error(), "total cap") {
		t.Fatalf("err = %v, want the total cap", err)
	}
	if got, rerr := os.ReadFile(filepath.Join(dir, "b.bin")); rerr != nil || string(got) != "keep me" {
		t.Fatalf("b.bin = %q, %v; want the old content", got, rerr)
	}
	assertNoTemp(t, dir)
}

func TestExtractHonestSmallStaysIntact(t *testing.T) {
	setExtractCaps(t, 1<<20, 2<<20)
	zp := writeZip(t, "ok.apk", []zipEntry{
		{"a.txt", []byte("hello")},
		{"d/b.txt", []byte("world")},
	})

	dir := t.TempDir()
	t.Chdir(dir)
	var d Digest
	if err := ExtractPayload(zp, "d/b.txt", &d); err != nil {
		t.Fatalf("ExtractPayload: %v", err)
	}
	if got, err := os.ReadFile("b.txt"); err != nil || string(got) != "world" {
		t.Fatalf("b.txt = %q, %v", got, err)
	}

	out := filepath.Join(t.TempDir(), "tree")
	var d2 Digest
	if err := ExtractAll(zp, out, &d2); err != nil {
		t.Fatalf("ExtractAll: %v", err)
	}
	for name, want := range map[string]string{"a.txt": "hello", "d/b.txt": "world"} {
		got, err := os.ReadFile(filepath.Join(out, name))
		if err != nil || string(got) != want {
			t.Fatalf("%s = %q, %v; want %q", name, got, err, want)
		}
	}
	assertNoTemp(t, out)
	assertNoTemp(t, filepath.Join(out, "d"))
}
