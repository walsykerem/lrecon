package main

import (
	"os"
	"path/filepath"
	"testing"
)

func mustAbs(t *testing.T, path string) string {
	t.Helper()
	abs, err := filepath.Abs(path)
	if err != nil {
		t.Fatal(err)
	}
	return abs
}

func TestMustAbs(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ in, want string }{
		{"foo/bar", filepath.Join(wd, "foo/bar")},
		{filepath.Join(wd, "baz"), filepath.Join(wd, "baz")},
		{".", wd},
	} {
		if got := mustAbs(t, c.in); got != c.want {
			t.Fatalf("mustAbs(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
