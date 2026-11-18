package main

import (
	"os"
	"testing"
)

// A bare --op infers a target only when the choice is unambiguous; two files
// or an empty dir still refuse.
func TestInferTarget(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	if p, _, ok := inferTarget(); ok {
		t.Fatalf("empty dir inferred %q", p)
	}
	if err := os.WriteFile("a.bin", []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if p, conf, ok := inferTarget(); !ok || p != "./a.bin" || conf != 0.6 {
		t.Fatalf("one file = %q/%v/%v, want ./a.bin/0.6/true", p, conf, ok)
	}
	if err := os.WriteFile("b.bin", []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if p, _, ok := inferTarget(); ok {
		t.Fatalf("two files inferred %q", p)
	}
	t.Setenv("LRECON_TARGET", "b.bin")
	if p, conf, ok := inferTarget(); !ok || p != "b.bin" || conf != 0.9 {
		t.Fatalf("LRECON_TARGET = %q/%v/%v, want b.bin/0.9/true", p, conf, ok)
	}
}

// A bare --op must not guess a target from a hidden file or a directory, and a
// stale LRECON_TARGET must fall through to the unambiguous-file rule instead of
// failing outright.
func TestInferTargetSkipsNonFilesAndStaleEnv(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("LRECON_TARGET", "")

	if err := os.Mkdir("subdir", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(".hidden", []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if p, _, ok := inferTarget(); ok {
		t.Fatalf("inferred %q from a dir plus a hidden file", p)
	}

	if err := os.WriteFile("only.bin", []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if p, conf, ok := inferTarget(); !ok || p != "./only.bin" || conf != 0.6 {
		t.Fatalf("one file with a hidden neighbour = %q/%v/%v", p, conf, ok)
	}

	for _, stale := range []string{"absent.bin", "subdir"} {
		t.Setenv("LRECON_TARGET", stale)
		if p, conf, ok := inferTarget(); !ok || p != "./only.bin" || conf != 0.6 {
			t.Fatalf("stale LRECON_TARGET=%q = %q/%v/%v, want fallback", stale, p, conf, ok)
		}
	}
}
