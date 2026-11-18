package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Synthetic .rlib bytes only: ar headers and a metadata blob written by hand,
// so the test carries no fixture binary and no rust toolchain.

type rlibEntry struct {
	name string
	body []byte
}

// rlibWrite lays out an ar archive the way rustc does; bsd selects the macOS
// "#1/<len>" name form, GNU the 16-byte name field with a trailing slash.
func rlibWrite(t *testing.T, filename string, bsd bool, entries []rlibEntry) string {
	t.Helper()
	var (
		buf  bytes.Buffer
		long []byte
		refs = make([]int, len(entries))
	)
	for i, e := range entries {
		if !bsd && len(e.name) > 15 {
			refs[i] = len(long)
			long = append(append(long, e.name...), '/', '\n')
		}
	}
	buf.WriteString("!<arch>\n")
	if len(long) > 0 {
		rlibHeader(&buf, "//", long)
	}
	for i, e := range entries {
		name, body := e.name, e.body
		switch {
		case bsd:
			name = fmt.Sprintf("#1/%d", len(e.name))
			body = append([]byte(e.name), e.body...)
		case refs[i] > 0 || (len(long) > 0 && len(e.name) > 15):
			name = fmt.Sprintf("/%d", refs[i])
		default:
			name = e.name + "/"
		}
		rlibHeader(&buf, name, body)
	}
	path := filepath.Join(t.TempDir(), filename)
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

func rlibHeader(buf *bytes.Buffer, name string, body []byte) {
	fmt.Fprintf(buf, "%-16s%-12d%-6d%-6d%-8o%-10d`\n", name, 0, 0, 0, 0o644, len(body))
	buf.Write(body)
	if len(body)%2 == 1 {
		buf.WriteByte('\n')
	}
}

// rlibBlob builds the metadata preamble: magic, METADATA_VERSION byte and the
// length-prefixed rustc version string at verAt (+16, or +40 on master).
func rlibBlob(ver byte, verAt int, version string) []byte {
	b := make([]byte, 96)
	copy(b, "rust\x00\x00\x00")
	b[7] = ver
	b[verAt] = byte(len(version))
	copy(b[verAt+1:], version)
	return b
}

func rlibCgu(name string) []byte { return []byte("cgu object for " + name) }

func rlibHasSkip(d Digest, reason string) bool {
	for _, s := range d.Skipped {
		if s.Reason == reason {
			return true
		}
	}
	return false
}

func rlibHasCap(d Digest, prefix string) bool {
	for _, c := range d.Capabilities {
		if strings.HasPrefix(c, prefix) {
			return true
		}
	}
	return false
}

const rlibFooHash = "0123456789abcdef"

func TestRlibMetadataVersion10(t *testing.T) {
	meta := append(bytes.Repeat([]byte{0}, 64), rlibBlob(10, 16, "rustc 1.92.0 (ded5c06cf 2025-12-08)")...)
	path := rlibWrite(t, "libfoo-"+rlibFooHash+".rlib", false, []rlibEntry{
		{name: "lib.rmeta", body: meta},
		{name: "libfoo.foo." + rlibFooHash + "-cgu.0.rcgu.o", body: rlibCgu("foo")},
	})
	d, err := Probe(path)
	if err != nil {
		t.Fatal(err)
	}
	if d.Kind != "rlib" || d.Format != "rlib" {
		t.Fatalf("kind/format = %q/%q, want rlib/rlib", d.Kind, d.Format)
	}
	if d.Toolchain != "rustc 1.92.0" {
		t.Fatalf("toolchain = %q, want rustc 1.92.0", d.Toolchain)
	}
	if !rlibHasCap(d, "rlib:metadata=10") || !rlibHasCap(d, "rlib:members=2") {
		t.Fatalf("capabilities = %v", d.Capabilities)
	}
	if !rlibHasCap(d, "rlib:crate=foo") || !d.witnessed("foo") {
		t.Fatalf("crate not verified from filename and cgu: caps=%v claims=%+v", d.Capabilities, d.Claims)
	}
	if len(d.Skipped) != 0 {
		t.Fatalf("unexpected skips: %+v", d.Skipped)
	}
}

func TestRlibMasterMetadata(t *testing.T) {
	path := rlibWrite(t, "libfoo-"+rlibFooHash+".rlib", false, []rlibEntry{
		{name: "lib.rmeta", body: rlibBlob(11, 40, "rustc 1.93.0-nightly (abc 2026-01-01)")},
		{name: "foo-" + rlibFooHash + ".foo." + rlibFooHash + "-cgu.0.rcgu.o", body: rlibCgu("foo")},
	})
	d, err := Probe(path)
	if err != nil {
		t.Fatal(err)
	}
	if d.Toolchain != "rustc 1.93.0-nightly" {
		t.Fatalf("toolchain = %q, want rustc 1.93.0-nightly", d.Toolchain)
	}
	if !rlibHasCap(d, "rlib:metadata=11") {
		t.Fatalf("capabilities = %v", d.Capabilities)
	}
}

func TestRlibNameMismatch(t *testing.T) {
	path := rlibWrite(t, "libfoo-"+rlibFooHash+".rlib", false, []rlibEntry{
		{name: "lib.rmeta", body: rlibBlob(10, 16, "rustc 1.92.0 (ded5c06cf 2025-12-08)")},
		{name: "libbar.bar." + rlibFooHash + "-cgu.0.rcgu.o", body: rlibCgu("bar")},
	})
	d, err := Probe(path)
	if err != nil {
		t.Fatal(err)
	}
	if !rlibHasSkip(d, "rlib-name-mismatch") {
		t.Fatalf("no rlib-name-mismatch: %+v", d.Skipped)
	}
	if rlibHasCap(d, "rlib:crate=") || d.witnessed("foo") {
		t.Fatalf("mismatched crate claimed: caps=%v claims=%+v", d.Capabilities, d.Claims)
	}
}

func TestRlibMetadataAbsent(t *testing.T) {
	path := rlibWrite(t, "libfoo-"+rlibFooHash+".rlib", false, []rlibEntry{
		{name: "libfoo.foo." + rlibFooHash + "-cgu.0.rcgu.o", body: rlibCgu("foo")},
	})
	d, err := Probe(path)
	if err != nil {
		t.Fatal(err)
	}
	if !rlibHasSkip(d, "rlib-metadata-absent") {
		t.Fatalf("no rlib-metadata-absent: %+v", d.Skipped)
	}
	if d.Toolchain != "" || rlibHasCap(d, "rlib:metadata=") {
		t.Fatalf("toolchain claimed without metadata: %q %v", d.Toolchain, d.Capabilities)
	}
}

func TestRlibArchiveInvalid(t *testing.T) {
	path := filepath.Join(t.TempDir(), "broken.rlib")
	if err := os.WriteFile(path, append([]byte("!<arch>\n"), bytes.Repeat([]byte{'X'}, 60)...), 0o644); err != nil {
		t.Fatal(err)
	}
	d, err := Probe(path)
	if err != nil {
		t.Fatal(err)
	}
	if !rlibHasSkip(d, "rlib-archive-invalid") {
		t.Fatalf("no rlib-archive-invalid: %+v", d.Skipped)
	}
}

func TestRlibVersionUnverified(t *testing.T) {
	path := rlibWrite(t, "libfoo-"+rlibFooHash+".rlib", false, []rlibEntry{
		{name: "lib.rmeta", body: rlibBlob(99, 16, "rustc 9.9.9 (unknown)")},
	})
	d, err := Probe(path)
	if err != nil {
		t.Fatal(err)
	}
	if !rlibHasSkip(d, "rlib-version-unverified") {
		t.Fatalf("no rlib-version-unverified: %+v", d.Skipped)
	}
	if d.Toolchain != "" {
		t.Fatalf("toolchain claimed for unknown version: %q", d.Toolchain)
	}
}

func TestRlibBsdMemberNames(t *testing.T) {
	path := rlibWrite(t, "libfoo-"+rlibFooHash+".rlib", true, []rlibEntry{
		{name: "lib.rmeta", body: rlibBlob(10, 16, "rustc 1.92.0 (ded5c06cf 2025-12-08)")},
		{name: "libfoo.foo." + rlibFooHash + "-cgu.0.rcgu.o", body: rlibCgu("foo")},
	})
	d, err := Probe(path)
	if err != nil {
		t.Fatal(err)
	}
	if d.Toolchain != "rustc 1.92.0" || !d.witnessed("foo") {
		t.Fatalf("bsd names not read: toolchain=%q claims=%+v skips=%+v", d.Toolchain, d.Claims, d.Skipped)
	}
}

// A plain static library is ar too, so the post reader must leave it alone.
func TestRlibPlainArchiveUntouched(t *testing.T) {
	path := rlibWrite(t, "libfoo.a", false, []rlibEntry{
		{name: "lib.rmeta", body: rlibBlob(10, 16, "rustc 1.92.0 (ded5c06cf 2025-12-08)")},
	})
	d, err := Probe(path)
	if err != nil {
		t.Fatal(err)
	}
	if d.Kind != "unknown" || rlibHasCap(d, "rlib:") || len(d.Skipped) != 0 {
		t.Fatalf("non-rlib archive touched: kind=%q caps=%v skips=%+v", d.Kind, d.Capabilities, d.Skipped)
	}
}
