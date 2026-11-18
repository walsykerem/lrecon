package main

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// A 10 KB blob must not be copied whole into the answer: value is capped, len
// keeps the real length, and strings_truncated says the cut happened (final.md 405).
func TestCapValuesCutsLongRow(t *testing.T) {
	long := strings.Repeat("A", 10001)
	hits := []stringHit{{Value: long, Len: len(long)}, {Value: "short", Len: 5}}
	cut, blob := capValues(hits)
	if !cut || !blob {
		t.Fatalf("capValues = cut %v blob %v, want both true for a 10001-byte value", cut, blob)
	}
	if len(hits[0].Value) > listStringsValueMax+len("…") {
		t.Errorf("value len = %d, want <= %d plus the ellipsis", len(hits[0].Value), listStringsValueMax)
	}
	if !strings.HasSuffix(hits[0].Value, "…") {
		t.Errorf("value = %q, want the cut marked", hits[0].Value)
	}
	if hits[0].Len != 10001 {
		t.Errorf("len = %d, want the original 10001", hits[0].Len)
	}
	if hits[1].Value != "short" || hits[1].Len != 5 {
		t.Errorf("short row changed: %+v", hits[1])
	}
	// A table-sized 1 KB value is shortened but stays below the notice line.
	small := []stringHit{{Value: strings.Repeat("B", 1000), Len: 1000}}
	if cut, blob := capValues(small); !cut || blob {
		t.Fatalf("capValues(1000) = cut %v blob %v, want true/false", cut, blob)
	}
}

func TestCapValueKeepsUTF8(t *testing.T) {
	s := strings.Repeat("a", 511) + "世界世界"
	got := capValue(s, 512)
	if !utf8.ValidString(got) {
		t.Fatalf("cut value is not valid UTF-8: %q", got)
	}
	if len(got) > 512+len("…") {
		t.Fatalf("cut value is %d bytes, want <= 512 plus the ellipsis", len(got))
	}
}
