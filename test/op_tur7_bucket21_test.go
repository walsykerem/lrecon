package main

// Cross-target contamination at the op layer: open_binary must answer from the
// bytes of the target it was handed, never from the previous answer. Two real
// fixtures of different kinds (ELF, Mach-O) are opened A, B, copy-of-A, A; each
// answer is checked against an independent hash of that file, and the second
// answer for A must be byte-identical to the first.

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

type t21OpenBinary struct {
	Document   string `json:"document"`
	Handle     string `json:"handle"`
	Kind       string `json:"kind"`
	Format     string `json:"format"`
	Size       int64  `json:"size"`
	SHA256     string `json:"sha256"`
	GitOID     string `json:"gitoid"`
	HashScope  string `json:"hash_scope"`
	BinarySize int64  `json:"binary_size"`
}

func t21Open(t *testing.T, path string) t21OpenBinary {
	t.Helper()
	res, err := runOp("open_binary", path)
	if err != nil {
		t.Fatalf("open_binary(%s): %v", path, err)
	}
	b, err := json.Marshal(res)
	if err != nil {
		t.Fatalf("open_binary(%s) does not marshal: %v", path, err)
	}
	var m t21OpenBinary
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("open_binary(%s) is not an identity object: %v\n%s", path, err, b)
	}
	return m
}

// t21Expect hashes the file itself, so a leaked or cached answer cannot match.
func t21Expect(t *testing.T, path string) (sha256hex, gitoid string, size int64) {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	h256 := sha256.Sum256(body)
	h1 := sha1.New()
	fmt.Fprintf(h1, "blob %d\x00", len(body))
	h1.Write(body)
	return hex.EncodeToString(h256[:]), "gitoid:blob:sha1:" + hex.EncodeToString(h1.Sum(nil)), int64(len(body))
}

func t21AssertIdentity(t *testing.T, label string, m t21OpenBinary, path, kind string) {
	t.Helper()
	wantSHA, wantGit, wantSize := t21Expect(t, path)
	if m.Document != path {
		t.Errorf("%s document = %q, want %q", label, m.Document, path)
	}
	if m.Handle != "none" {
		t.Errorf("%s handle = %q, want none (stateless)", label, m.Handle)
	}
	if m.Kind != kind {
		t.Errorf("%s kind = %q, want %q", label, m.Kind, kind)
	}
	if m.Format == "" {
		t.Errorf("%s format is empty", label)
	}
	if m.HashScope != "whole-file" {
		t.Errorf("%s hash_scope = %q, want whole-file (fixture is under the digest cap)", label, m.HashScope)
	}
	if m.SHA256 != wantSHA {
		t.Errorf("%s sha256 = %s, want %s from the file bytes", label, m.SHA256, wantSHA)
	}
	if m.GitOID != wantGit {
		t.Errorf("%s gitoid = %s, want %s", label, m.GitOID, wantGit)
	}
	if m.Size != wantSize || m.BinarySize != wantSize {
		t.Errorf("%s size/binary_size = %d/%d, want %d", label, m.Size, m.BinarySize, wantSize)
	}
}

func TestTur7Bucket21OpenBinaryCrossTarget(t *testing.T) {
	elf := s3Fix("elf")
	macho := s3Fix("macho")

	firstA := t21Open(t, elf)
	t21AssertIdentity(t, "open A (elf)", firstA, elf, "elf")

	b := t21Open(t, macho)
	t21AssertIdentity(t, "open B (macho) after A", b, macho, "macho")

	// B was answered after A; nothing of A may survive in it.
	for _, c := range []struct {
		field string
		a, b  any
	}{
		{"document", firstA.Document, b.Document},
		{"kind", firstA.Kind, b.Kind},
		{"format", firstA.Format, b.Format},
		{"sha256", firstA.SHA256, b.SHA256},
		{"gitoid", firstA.GitOID, b.GitOID},
		{"size", firstA.Size, b.Size},
	} {
		if c.a == c.b {
			t.Errorf("B inherited A's %s (%v): the second open reused the first target's state", c.field, c.a)
		}
	}

	// A copy of A under a new path: same bytes, other document name. Identity
	// must follow the bytes, document must follow the path, not the earlier open.
	copyPath := filepath.Join(t.TempDir(), "copy-of-elf")
	body, err := os.ReadFile(elf)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	if err := os.WriteFile(copyPath, body, 0o644); err != nil {
		t.Fatalf("write copy: %v", err)
	}
	clone := t21Open(t, copyPath)
	t21AssertIdentity(t, "open A-copy", clone, copyPath, "elf")
	if clone.SHA256 != firstA.SHA256 || clone.GitOID != firstA.GitOID || clone.Size != firstA.Size || clone.Kind != firstA.Kind {
		t.Errorf("A-copy identity = %+v, want A's identity %+v", clone, firstA)
	}

	// Reopening A after B and the copy must reproduce A exactly.
	secondA := t21Open(t, elf)
	if !reflect.DeepEqual(secondA, firstA) {
		t.Fatalf("reopening A = %+v, want the first answer %+v", secondA, firstA)
	}
}
