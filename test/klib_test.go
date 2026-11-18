package main

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// Synthetic .klib bytes only: a zip built in memory and protobuf written by
// hand, so the test carries no fixture binary and no generated proto code.

func klibArchive(t *testing.T, name string, files map[string][]byte) string {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for entry, body := range files {
		w, err := zw.Create(entry)
		if err != nil {
			t.Fatalf("zip create %s: %v", entry, err)
		}
		if _, err := w.Write(body); err != nil {
			t.Fatalf("zip write %s: %v", entry, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

func pbVarintBytes(v uint64) []byte {
	var out []byte
	for v >= 0x80 {
		out = append(out, byte(v)|0x80)
		v >>= 7
	}
	return append(out, byte(v))
}

func pbBytesField(num int, body []byte) []byte {
	out := pbVarintBytes(uint64(num<<3 | 2))
	out = append(out, pbVarintBytes(uint64(len(body)))...)
	return append(out, body...)
}

// klibFragment writes a PackageFragment: one StringTable, the fq_name string
// and the packed class_name ids that point into that table.
func klibFragment(pkg string, classes ...string) []byte {
	var table []byte
	for _, s := range append([]string{pkg}, classes...) {
		table = append(table, pbBytesField(1, []byte(s))...)
	}
	out := pbBytesField(1, table)
	out = append(out, pbBytesField(173, []byte(pkg))...)
	var ids []byte
	for i := 1; i <= len(classes); i++ {
		ids = append(ids, pbVarintBytes(uint64(i))...)
	}
	return append(out, pbBytesField(174, ids)...)
}

func klibManifest(abi, meta, comp string) []byte {
	return []byte("abi_version=" + abi + "\nmetadata_version=" + meta + "\ncompiler_version=" + comp + "\n")
}

func klibHasSkip(d Digest, reason string) bool {
	for _, s := range d.Skipped {
		if s.Reason == reason {
			return true
		}
	}
	return false
}

func TestKlibPackageFragment(t *testing.T) {
	path := klibArchive(t, "sample.klib", map[string][]byte{
		"default/manifest": klibManifest("1.8.0", "1.8.0", "2.0.0"),
		"default/linkdata/0_kotlin.collections.knm": klibFragment(
			"kotlin.collections",
			"kotlin.collections.List",
			"kotlin.collections.MutableList",
		),
	})
	d, err := Probe(path)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if d.Kind != "zip" || d.Format != "klib" {
		t.Fatalf("kind/format = %q/%q, want zip/klib", d.Kind, d.Format)
	}
	if d.Toolchain != "kotlin 2.0.0" {
		t.Fatalf("toolchain = %q", d.Toolchain)
	}
	want := []string{
		"kotlin.collections",
		"kotlin.collections.List",
		"kotlin.collections.MutableList",
	}
	if len(d.Imports) != len(want) {
		t.Fatalf("imports = %v, want %v", d.Imports, want)
	}
	for i := range want {
		if d.Imports[i] != want[i] {
			t.Fatalf("imports = %v, want %v", d.Imports, want)
		}
	}
	if d.Coverage == nil || d.Coverage.Parsed != 1 || d.Coverage.Unknown != 0 {
		t.Fatalf("coverage = %+v, want parsed 1", d.Coverage)
	}
	if len(d.Skipped) != 0 {
		t.Fatalf("skipped = %+v, want none", d.Skipped)
	}
	if !containsStr(d.Capabilities, "klib:abi=1.8.0") || !containsStr(d.Capabilities, "klib:metadata=1.8.0") {
		t.Fatalf("capabilities = %v", d.Capabilities)
	}
}

func TestKlibRefusals(t *testing.T) {
	fragment := klibFragment("kotlin.collections", "kotlin.collections.List")
	cases := []struct {
		name  string
		files map[string][]byte
		want  string
	}{
		{
			name:  "manifest lacks abi_version",
			files: map[string][]byte{"default/manifest": []byte("metadata_version=1.8.0\n"), "default/linkdata/0_a.knm": fragment},
			want:  "klib-manifest-missing",
		},
		{
			name:  "manifest absent",
			files: map[string][]byte{"default/linkdata/0_a.knm": fragment},
			want:  "klib-manifest-missing",
		},
		{
			name:  "unverified metadata_version",
			files: map[string][]byte{"default/manifest": klibManifest("1.8.0", "9.9.9", "9.0.0"), "default/linkdata/0_a.knm": fragment},
			want:  "klib-version-unverified",
		},
		{
			name:  "corrupt protobuf length",
			files: map[string][]byte{"default/manifest": klibManifest("1.8.0", "1.8.0", "2.0.0"), "default/linkdata/0_a.knm": {0x0a, 0x64, 0x01, 0x02}},
			want:  "klib-protobuf-invalid",
		},
		{
			name:  "no linkdata",
			files: map[string][]byte{"default/manifest": klibManifest("1.8.0", "1.8.0", "2.0.0")},
			want:  "klib-linkdata-missing",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d, err := Probe(klibArchive(t, "sample.klib", c.files))
			if err != nil {
				t.Fatalf("Probe: %v", err)
			}
			if !klibHasSkip(d, c.want) {
				t.Fatalf("skipped = %+v, want reason %q", d.Skipped, c.want)
			}
		})
	}
}

// A non-zip head must never be claimed, and a zip with a non-klib name is left
// to the zip reader: the post pass runs on every zip.
func TestKlibNotClaimed(t *testing.T) {
	for _, head := range [][]byte{[]byte("default/manifest"), []byte("PK\x05\x06")} {
		d := Digest{Kind: "unknown"}
		dispatchPost("plain.klib", head, int64(len(head)), &d)
		if d.Format != "" || len(d.Skipped) != 0 || len(d.Imports) != 0 {
			t.Fatalf("non-zip head %q claimed: %+v", head, d)
		}
	}
	files := map[string][]byte{
		"default/manifest":         klibManifest("1.8.0", "1.8.0", "2.0.0"),
		"default/linkdata/0_a.knm": klibFragment("kotlin.collections", "kotlin.collections.List"),
	}
	d, err := Probe(klibArchive(t, "sample.zip", files))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if d.Format == "klib" || len(d.Imports) != 0 {
		t.Fatalf("zip named .zip taken as klib: %+v", d)
	}
}
