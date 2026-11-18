package main

// Evergreen 17: negative controls on a .go extension. A reader that answers
// "text, readable" for every input proves nothing, so four junk files are
// driven through the real CLI digest. Each must end in a refusal or an empty
// finding, never a source finding. One genuine corpus .go is the positive
// control, so a tool that rejects everything cannot pass either.

import (
	"bytes"
	"encoding/json"
	"go/parser"
	"go/token"
	"image"
	"image/color"
	"image/png"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type ev17Digest struct {
	Kind     string          `json:"kind"`
	Format   string          `json:"format"`
	Plan     string          `json:"plan"`
	Exports  int             `json:"exports"`
	Symbols  string          `json:"symbols"`
	Slices   int             `json:"slices"`
	FileSize int64           `json:"file_size"`
	Error    string          `json:"error"`
	Claims   json.RawMessage `json:"claims"`
	Coverage json.RawMessage `json:"coverage"`
	Target   json.RawMessage `json:"target"`
}

// ev17TargetSHA reads the per-file hash out of the target object. The refusal
// envelope carries the path string there instead, so a missing object is "".
func ev17TargetSHA(d ev17Digest) string {
	var t struct {
		SHA256 string `json:"file_sha256"`
	}
	if len(d.Target) == 0 {
		return ""
	}
	_ = json.Unmarshal(d.Target, &t)
	return t.SHA256
}

func ev17Run(t *testing.T, path string) (ev17Digest, string, string, int) {
	t.Helper()
	stdout, stderr, code := runCLIAll(t, "--json", path)
	var d ev17Digest
	if s := strings.TrimSpace(stdout); s != "" {
		if err := json.Unmarshal([]byte(s), &d); err != nil {
			t.Fatalf("%s: stdout is not one JSON envelope: %v\n%s", filepath.Base(path), err, stdout)
		}
	}
	return d, stdout, stderr, code
}

func ev17SHA(t *testing.T, path string) string {
	t.Helper()
	got := fileDigest(path)
	if got == "" {
		t.Fatalf("%s: cannot hash fixture", path)
	}
	return got
}

// ev17NoSourceFinding is the negative-control contract: no format, no export
// count, no symbol table, no slices and no claim/coverage blocks may be made up
// for a file that carries no parseable structure.
func ev17NoSourceFinding(t *testing.T, label string, d ev17Digest) {
	t.Helper()
	if d.Format != "" || d.Exports != 0 || d.Symbols != "" || d.Slices != 0 {
		t.Fatalf("%s: positive source finding on junk: %+v", label, d)
	}
	if len(d.Claims) != 0 && string(d.Claims) != "null" {
		t.Fatalf("%s: claims emitted for junk: %s", label, d.Claims)
	}
	if len(d.Coverage) != 0 && string(d.Coverage) != "null" {
		t.Fatalf("%s: coverage emitted for junk: %s", label, d.Coverage)
	}
}

func ev17Write(t *testing.T, path string, body []byte) string {
	t.Helper()
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

func TestEvergreen17NegativeControlsRejected(t *testing.T) {
	if buildErr != nil || cliPath == "" {
		t.Fatalf("cli binary unavailable: buildErr=%v path=%q\n%s", buildErr, cliPath, buildLog)
	}
	dir := t.TempDir()

	// (a) A real PNG under a .go name. The extension must not buy a source
	// reading; the leading bytes win and the tool says it does not know.
	img := image.NewRGBA(image.Rect(0, 0, 4, 4))
	for x := 0; x < 4; x++ {
		for y := 0; y < 4; y++ {
			img.Set(x, y, color.RGBA{uint8(60 * x), uint8(60 * y), 7, 255})
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatalf("encode png: %v", err)
	}
	pngGo := ev17Write(t, filepath.Join(dir, "png.go"), buf.Bytes())
	pngD, pngOut, _, pngCode := ev17Run(t, pngGo)
	if pngCode != 0 {
		t.Fatalf("(a) png.go: exit %d, want 0 (a refusal envelope, not a crash)", pngCode)
	}
	if pngD.Kind != "unknown" {
		t.Fatalf("(a) png.go: kind=%q, want %q; extension overruled the magic bytes: %s", pngD.Kind, "unknown", pngOut)
	}
	if ev17TargetSHA(pngD) != ev17SHA(t, pngGo) {
		t.Fatalf("(a) png.go: digest sha %q is not the file's sha", ev17TargetSHA(pngD))
	}
	ev17NoSourceFinding(t, "(a) png.go", pngD)

	// (b) A zero-byte .go. Nothing to read: a typed io refusal.
	emptyGo := ev17Write(t, filepath.Join(dir, "empty.go"), nil)
	emptyD, emptyOut, emptyErr, emptyCode := ev17Run(t, emptyGo)
	if emptyCode != 2 {
		t.Fatalf("(b) empty.go: exit %d, want 2; stdout=%s stderr=%s", emptyCode, emptyOut, emptyErr)
	}
	if !strings.Contains(emptyErr, "cannot read an empty target (0 bytes)") {
		t.Fatalf("(b) empty.go: refusal text missing; stderr=%q", emptyErr)
	}
	if emptyD.Kind != "io" || emptyD.Error == "" {
		t.Fatalf("(b) empty.go: want kind=io with an error, got %+v", emptyD)
	}
	ev17NoSourceFinding(t, "(b) empty.go", emptyD)

	// (c) A broken syntax tree. The fixture really is unparseable (checked with
	// go/parser below), so the digest must not claim any structure for it.
	brokenSrc := []byte("package x\n\nfunc {\n")
	brokenGo := ev17Write(t, filepath.Join(dir, "broken.go"), brokenSrc)
	if _, err := parser.ParseFile(token.NewFileSet(), brokenGo, brokenSrc, 0); err == nil {
		t.Fatalf("(c) fixture is not broken Go source")
	}
	brokenD, brokenOut, _, brokenCode := ev17Run(t, brokenGo)
	if brokenCode != 0 {
		t.Fatalf("(c) broken.go: exit %d; stdout=%s", brokenCode, brokenOut)
	}
	if brokenD.Kind != "text" {
		t.Fatalf("(c) broken.go: kind=%q, want %q (bytes are text, syntax is not parsed)", brokenD.Kind, "text")
	}
	ev17NoSourceFinding(t, "(c) broken.go", brokenD)

	// (d) `package x` only, no declarations. The oracle confirms zero decls, so
	// any export or symbol the tool reports would be invented.
	pkgSrc := []byte("package x\n")
	pkgGo := ev17Write(t, filepath.Join(dir, "pkgonly.go"), pkgSrc)
	fset := token.NewFileSet()
	pkgFile, err := parser.ParseFile(fset, pkgGo, pkgSrc, 0)
	if err != nil || len(pkgFile.Decls) != 0 {
		t.Fatalf("(d) fixture is not declaration-free Go source: err=%v decls=%d", err, len(pkgFile.Decls))
	}
	pkgD, pkgOut, _, pkgCode := ev17Run(t, pkgGo)
	if pkgCode != 0 {
		t.Fatalf("(d) pkgonly.go: exit %d; stdout=%s", pkgCode, pkgOut)
	}
	if pkgD.Kind != "text" {
		t.Fatalf("(d) pkgonly.go: kind=%q, want %q", pkgD.Kind, "text")
	}
	ev17NoSourceFinding(t, "(d) pkgonly.go", pkgD)

	// Positive control: one real .go from the corpus, accepted and read. Its
	// size and hash must be its own, so the four negatives above cannot pass by
	// a canned answer for every target.
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	real := filepath.Join(wd, "types.go")
	realSrc, err := os.ReadFile(real)
	if err != nil {
		t.Fatalf("positive control %s: %v", real, err)
	}
	realFile, err := parser.ParseFile(token.NewFileSet(), real, realSrc, 0)
	if err != nil || len(realFile.Decls) == 0 {
		t.Fatalf("positive control %s is not real Go source: err=%v decls=%d", real, err, len(realFile.Decls))
	}
	if ev17TargetSHA(pngD) == ev17SHA(t, real) {
		t.Fatalf("positive control and (a) share a hash, so targets are not read per file")
	}
	realD, realOut, _, realCode := ev17Run(t, real)
	if realCode != 0 {
		t.Fatalf("positive control %s: rejected with exit %d; stdout=%s", real, realCode, realOut)
	}
	if realD.Kind != "text" {
		t.Fatalf("positive control %s: kind=%q, want %q", real, realD.Kind, "text")
	}
	if realD.FileSize != int64(len(realSrc)) {
		t.Fatalf("positive control %s: file_size=%d, want %d", real, realD.FileSize, len(realSrc))
	}
	if ev17TargetSHA(realD) != ev17SHA(t, real) {
		t.Fatalf("positive control %s: digest sha %q is not the file's sha", real, ev17TargetSHA(realD))
	}
	ev17NoSourceFinding(t, "positive control "+filepath.Base(real), realD)
}
