package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestReadCappedEnforcesCap simulates the real readCapped contract: a file at
// or under the limit returns its exact bytes, a file over the limit fails
// loudly instead of returning a truncated prefix, and a missing file errors.
func TestReadCappedEnforcesCap(t *testing.T) {
	dir := t.TempDir()

	cases := []struct {
		name    string
		content string
		limit   int64
		want    string
		wantErr string
	}{
		{name: "under cap", content: "hello", limit: 16, want: "hello"},
		{name: "exactly at cap", content: "12345678", limit: 8, want: "12345678"},
		{name: "empty file", content: "", limit: 8, want: ""},
		{name: "one byte over cap", content: "123456789", limit: 8, wantErr: "larger than the 8-byte cap"},
		{name: "far over cap", content: strings.Repeat("x", 4096), limit: 16, wantErr: "larger than the 16-byte cap"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := filepath.Join(dir, strings.ReplaceAll(c.name, " ", "_")+".bin")
			if err := os.WriteFile(p, []byte(c.content), 0o644); err != nil {
				t.Fatal(err)
			}
			got, err := readCapped(p, c.limit)
			if c.wantErr != "" {
				if err == nil {
					t.Fatalf("readCapped(%q, %d) succeeded with %q, want error containing %q", c.name, c.limit, got, c.wantErr)
				}
				if !strings.Contains(err.Error(), c.wantErr) {
					t.Fatalf("error = %q, want it to contain %q", err.Error(), c.wantErr)
				}
				if got != nil {
					t.Fatalf("over-cap read returned %d bytes, want nil (no silent prefix)", len(got))
				}
				return
			}
			if err != nil {
				t.Fatalf("readCapped(%q, %d): %v", c.name, c.limit, err)
			}
			if string(got) != c.want {
				t.Fatalf("readCapped = %q, want %q", got, c.want)
			}
		})
	}
}

func TestReadCappedMissingFile(t *testing.T) {
	_, err := readCapped(filepath.Join(t.TempDir(), "nope.bin"), 10)
	if err == nil {
		t.Fatal("readCapped on a missing file returned nil error")
	}
	if !os.IsNotExist(err) {
		t.Fatalf("error = %v, want a not-exist error", err)
	}
}
