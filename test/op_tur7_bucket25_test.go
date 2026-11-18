package main

// Tur 7 bucket 25: search_bytes against a nonce planted at a known file offset
// in a copy of a real binary. Proves the answer is read from the file bytes:
// exact offset/address, per-byte wildcard masking, and no cached first result
// across consecutive queries in one process.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const tur7b25NonceLen = 12

// tur7b25Nonce derives its bytes at runtime so the literal sequence is not
// embedded in the test binary (which is the file being searched).
func tur7b25Nonce() []byte {
	n := make([]byte, tur7b25NonceLen)
	seed := byte(0x91)
	for i := range n {
		seed = seed*31 + 7
		n[i] = seed
	}
	return n
}

func tur7b25Hex(b []byte) string {
	parts := make([]string, len(b))
	for i, v := range b {
		parts[i] = fmt.Sprintf("%02x", v)
	}
	return strings.Join(parts, " ")
}

func tur7b25Search(t *testing.T, path, pattern string) (int, []patternHit, map[string]any) {
	t.Helper()
	t.Setenv("LRECON_PATTERN", pattern)
	v, err := runOp("search_bytes", path)
	if err != nil {
		t.Fatalf("search_bytes(%q): %v", pattern, err)
	}
	m, ok := v.(map[string]any)
	if !ok {
		t.Fatalf("search_bytes(%q): result is not a map: %v", pattern, v)
	}
	hits, ok := m["hits"].(int)
	if !ok {
		t.Fatalf("search_bytes(%q): hits is not an int: %v", pattern, m["hits"])
	}
	matches, ok := m["matches"].([]patternHit)
	if !ok {
		t.Fatalf("search_bytes(%q): matches is not []patternHit: %v", pattern, m["matches"])
	}
	return hits, matches, m
}

func tur7b25Plant(t *testing.T, path string, off uint64, b []byte) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteAt(b, int64(off)); err != nil {
		t.Fatal(err)
	}
}

func TestTur7Bucket25SearchBytesPlantedOffset(t *testing.T) {
	src, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(t.TempDir(), "planted-copy")
	if err := os.WriteFile(dst, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	_, secs, err := nativeSections(dst)
	if err != nil {
		t.Fatalf("nativeSections(%s): %v", dst, err)
	}
	// First section in file order that can hold two nonces far apart; early
	// offset keeps the planted bytes inside the scanned prefix.
	var sec fileSection
	found := false
	for _, s := range secs {
		if s.Size >= 4096 && s.Off+s.Size <= uint64(len(raw)) {
			sec, found = s, true
			break
		}
	}
	if !found {
		t.Fatalf("no usable file-backed section in %d sections of %s", len(secs), src)
	}

	nonceA, nonceB := tur7b25Nonce(), tur7b25Nonce()
	for i := range nonceB {
		nonceB[i] ^= 0xff
	}
	offA := sec.Off + sec.Size/2
	offB := sec.Off + sec.Size/4
	if offA+uint64(len(nonceA)) > sec.Off+sec.Size || offB+uint64(len(nonceB)) > offA {
		t.Fatalf("section %s too small to plant: off=%#x size=%#x", sec.Name, sec.Off, sec.Size)
	}

	patA, patB := tur7b25Hex(nonceA), tur7b25Hex(nonceB)
	// Precondition: neither nonce exists before planting, so any later hit is
	// the byte this test wrote.
	if hits, _, _ := tur7b25Search(t, dst, patA); hits != 0 {
		t.Fatalf("nonce A already present %d times before planting", hits)
	}
	if hits, _, _ := tur7b25Search(t, dst, patB); hits != 0 {
		t.Fatalf("nonce B already present %d times before planting", hits)
	}

	tur7b25Plant(t, dst, offA, nonceA)
	tur7b25Plant(t, dst, offB, nonceB)

	// Query 1: A resolves to the byte offset this test wrote, with the address
	// derived from the section base.
	hits, matches, m := tur7b25Search(t, dst, patA)
	if hits != 1 || len(matches) != 1 {
		t.Fatalf("nonce A: hits=%d matches=%v, want exactly 1", hits, matches)
	}
	if matches[0].Off != offA {
		t.Fatalf("nonce A: file_offset=%#x, want %#x", matches[0].Off, offA)
	}
	if want := sec.Addr + (offA - sec.Off); matches[0].Addr != want {
		t.Fatalf("nonce A: address=%#x, want %#x", matches[0].Addr, want)
	}
	if matches[0].At != sec.Name {
		t.Fatalf("nonce A: section=%q, want %q", matches[0].At, sec.Name)
	}
	if m["length"] != len(nonceA) || m["normalized"] != patA {
		t.Fatalf("nonce A: length=%v normalized=%q, want %d/%q", m["length"], m["normalized"], len(nonceA), patA)
	}

	// Query 2: a different pattern in the same process must not inherit query 1.
	hits, matches, _ = tur7b25Search(t, dst, patB)
	if hits != 1 || len(matches) != 1 || matches[0].Off != offB {
		t.Fatalf("nonce B after A: hits=%d matches=%v, want one at %#x", hits, matches, offB)
	}

	// Query 3: A again, still A's own offset (no memoized first answer).
	hits, matches, _ = tur7b25Search(t, dst, patA)
	if hits != 1 || len(matches) != 1 || matches[0].Off != offA {
		t.Fatalf("nonce A on repeat: hits=%d matches=%v, want one at %#x", hits, matches, offA)
	}

	// Destroy one byte of A: the full pattern must stop matching at all.
	tur7b25Plant(t, dst, offA+3, []byte{nonceA[3] ^ 0xff})
	if hits, matches, _ := tur7b25Search(t, dst, patA); hits != 0 || len(matches) != 0 {
		t.Fatalf("nonce A with byte 3 flipped: hits=%d matches=%v, want none", hits, matches)
	}

	// Same byte as a wildcard: the hit comes back at A's offset, proving the
	// mask skips exactly that byte instead of matching the original pattern.
	wild := strings.Split(patA, " ")
	wild[3] = "??"
	wildPat := strings.Join(wild, " ")
	hits, matches, m = tur7b25Search(t, dst, wildPat)
	foundAt := -1
	for i, h := range matches {
		if h.Off == offA {
			foundAt = i
		}
	}
	if hits < 1 || foundAt < 0 {
		t.Fatalf("wildcard pattern %q: hits=%d matches=%v, want a hit at %#x", wildPat, hits, matches, offA)
	}
	if m["normalized"] != wildPat {
		t.Fatalf("wildcard normalized=%q, want %q", m["normalized"], wildPat)
	}

	// Query after the wildcard still reads B's real offset, not a stale hit.
	hits, matches, _ = tur7b25Search(t, dst, patB)
	if hits != 1 || len(matches) != 1 || matches[0].Off != offB {
		t.Fatalf("nonce B after wildcard: hits=%d matches=%v, want one at %#x", hits, matches, offB)
	}
}
