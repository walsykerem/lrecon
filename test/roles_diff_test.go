package main

import (
	"strings"
	"testing"
)

// --diff has to name the target identity: two different files are a change,
// even when every other field matches.
func TestDiffDigestsTargetIdentity(t *testing.T) {
	a := writeTemp(t, "a.bin", []byte("alpha payload"))
	b := writeTemp(t, "b.bin", []byte("bravo payload, longer"))
	da, err := Probe(a)
	if err != nil {
		t.Fatalf("probe %s: %v", a, err)
	}
	db, err := Probe(b)
	if err != nil {
		t.Fatalf("probe %s: %v", b, err)
	}
	lines := DiffDigests(da, db)
	hit := false
	for _, l := range lines {
		for _, k := range []string{"sha256 ", "size ", "gitoid "} {
			if strings.HasPrefix(l, k) {
				hit = true
			}
		}
	}
	if !hit {
		t.Fatalf("diff of two different files names no identity change: %v", lines)
	}
}

// The same file diffed against itself is not a change.
func TestDiffDigestsSameFileNoDiff(t *testing.T) {
	p := writeTemp(t, "same.bin", []byte("one payload"))
	da, err := Probe(p)
	if err != nil {
		t.Fatalf("probe %s: %v", p, err)
	}
	db, err := Probe(p)
	if err != nil {
		t.Fatalf("probe %s: %v", p, err)
	}
	if got := DiffDigests(da, db); len(got) != 0 {
		t.Fatalf("self diff = %v, want empty", got)
	}
}
