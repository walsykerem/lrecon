package main

import "testing"

// The asar header tree is the only source of truth about what the archive
// holds; package.json's "main" is a second, weaker description of the same
// fact. The two must be allowed to disagree, and the reader's answer must say
// which side won: an extensionless main resolves through the implicit
// candidates in the reader's order (.js before /index.js) and carries the
// tree's own byte size, while a main no member carries is named as missing
// instead of being echoed as if it existed.
func TestTur7Bucket01AsarMainTreeResolution(t *testing.T) {
	cases := []struct {
		name     string
		main     string
		files    map[string][]byte
		wantNote string
		absent   string
	}{
		{
			// Both candidates exist: the declared "dist/out" is neither one of
			// them, so the note has to name the resolved path and its size.
			name: "extensionless prefers the .js candidate over index.js",
			main: "./dist/out",
			files: map[string][]byte{
				"dist/out.js":       make([]byte, 11),
				"dist/out/index.js": make([]byte, 777),
			},
			wantNote: "main entry: dist/out.js (11 bytes)",
			absent:   "(777 bytes)",
		},
		{
			// Only the directory form exists, so the second candidate is the
			// one the tree can actually back.
			name: "falls through to the index.js candidate",
			main: "dist/main",
			files: map[string][]byte{
				"dist/main/index.js": make([]byte, 42),
			},
			wantNote: "main entry: dist/main/index.js (42 bytes)",
			absent:   "missing from tree",
		},
		{
			// No candidate exists: the declared value must survive verbatim and
			// no size may be invented for it.
			name:     "names the declared main as missing",
			main:     "dist/gone",
			files:    map[string][]byte{"index.js": []byte("x=1\n")},
			wantNote: "main entry: dist/gone missing from tree",
			absent:   "(0 bytes)",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			files := map[string][]byte{"package.json": []byte(`{"main":"` + c.main + `"}`)}
			for p, b := range c.files {
				files[p] = b
			}
			d := probeAsar(t, files)
			if d.AsarMain != c.main {
				t.Fatalf("asar_main = %q, want the declared %q kept as declared", d.AsarMain, c.main)
			}
			if !notesContain(d, c.wantNote) {
				t.Fatalf("notes = %v, want %q", d.Notes, c.wantNote)
			}
			if notesContain(d, c.absent) {
				t.Fatalf("notes = %v, want no %q", d.Notes, c.absent)
			}
		})
	}
}
