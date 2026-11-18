package main

// TestTur7Bucket02Routing pins the detector's kind vocabulary against the skill
// contract: every kind detect.go can emit must be named in router.md's `## kinds`
// table, every kind named there must be reachable from real bytes, and each one
// must be produced by Probe on its own fixture. The code side is read as Go
// source (assignments and the initial composite literal), the doc side as the
// router contract, and the claim is settled by running Probe, not by grep.

import (
	"archive/zip"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

const tur7b02Router = "../skill/references/router.md"

func TestTur7Bucket02Routing(t *testing.T) {
	doc, err := os.ReadFile(tur7b02Router)
	if err != nil {
		t.Fatalf("read the router contract: %v", err)
	}
	code := tur7b02DetectKindLiterals(t)
	docKinds := tur7b02RouterKinds(t, string(doc))
	plans := tur7b02DocPlans(t, string(doc))

	for _, kind := range tur7b02Sorted(code) {
		if !docKinds[kind] {
			t.Errorf("detect.go emits kind %q but router.md `## kinds` documents no route row for it", kind)
		}
	}
	for _, kind := range tur7b02Sorted(docKinds) {
		if !code[kind] {
			t.Errorf("router.md documents kind %q but detect.go cannot emit it", kind)
		}
	}

	fixtures := map[string]func(*testing.T) string{
		"unknown":          tur7b02Unknown,
		"macho":            tur7b02Path("testdata/fixtures/macho"),
		"elf":              tur7b02Path("testdata/fixtures/elf"),
		"pe":               tur7b02Path("testdata/fixtures/pe.exe"),
		"asar":             tur7b02Path("testdata/fixtures/electron/app.asar"),
		"dex":              tur7b02Path("testdata/fixtures/apk/classes.dex"),
		"android-manifest": tur7b02AndroidManifest,
		"hermes":           tur7b02Magic("index.hbc", []byte{0xc6, 0x1f, 0xbc, 0x03}),
		"flutter":          tur7b02Path("testdata/fixtures/dart/app.jit"),
		"wasm":             tur7b02Path("testdata/fixtures/wasm.wasm"),
		"sqlite":           tur7b02Path("testdata/fixtures/sqlite/fixture.db"),
		"plist":            tur7b02Path("testdata/fixtures/keyed/archive.plist"),
		"nib":              tur7b02Path("testdata/fixtures/nib/interface.nib"),
		"signature":        tur7b02Magic("sig.bin", []byte{0xfa, 0xde, 0x0c, 0x02}),
		"car":              tur7b02Magic("Assets.car", []byte("CARV")),
		"zip":              tur7b02Zip,
		"pcap":             tur7b02Path("testdata/fixtures/pcap/fixture.pcap"),
		"firmware":         tur7b02Path("testdata/fixtures/fdt/board.dtb"),
		"text":             tur7b02Text,
	}
	for _, kind := range tur7b02Sorted(code) {
		if fixtures[kind] == nil {
			t.Fatalf("detect.go emits kind %q and this test has no fixture to reach it", kind)
		}
	}
	if len(fixtures) != len(code) {
		t.Fatalf("fixture table has %d kinds, detect.go emits %d", len(fixtures), len(code))
	}

	for _, kind := range tur7b02Sorted(code) {
		d, err := Probe(fixtures[kind](t))
		if err != nil {
			t.Fatalf("%s fixture: Probe: %v", kind, err)
		}
		if d.Kind != kind {
			t.Fatalf("%s: kind = %q, want %q", kind, d.Kind, kind)
		}
		if !plans[d.Plan] {
			t.Fatalf("%s: plan = %q, router.md `## Digest plan` names no such plan", kind, d.Plan)
		}
		if d.FileSize <= 0 || len(d.Target.FileSHA256) != 64 {
			t.Fatalf("%s: file_size=%d file_sha256=%q, the digest did not read the target", kind, d.FileSize, d.Target.FileSHA256)
		}
	}
}

// tur7b02DetectKindLiterals collects every kind detect.go can stamp on a Digest:
// `d.Kind = "..."` (single or paired with Format) and the Kind key of the initial
// composite literal. A non-literal assignment is a failure: the fixture table
// could not follow it.
func tur7b02DetectKindLiterals(t *testing.T) map[string]bool {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "detect.go", nil, 0)
	if err != nil {
		t.Fatalf("parse detect.go: %v", err)
	}
	kinds := map[string]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.AssignStmt:
			if len(n.Lhs) != len(n.Rhs) {
				return true
			}
			for i, lhs := range n.Lhs {
				sel, ok := lhs.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "Kind" {
					continue
				}
				lit, ok := n.Rhs[i].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					t.Fatalf("detect.go:%d assigns d.Kind a non-literal", fset.Position(n.Pos()).Line)
				}
				s, err := strconv.Unquote(lit.Value)
				if err != nil {
					t.Fatalf("detect.go:%d kind literal: %v", fset.Position(n.Pos()).Line, err)
				}
				kinds[s] = true
			}
		case *ast.CompositeLit:
			for _, el := range n.Elts {
				kv, ok := el.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				key, ok := kv.Key.(*ast.Ident)
				if !ok || key.Name != "Kind" {
					continue
				}
				lit, ok := kv.Value.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				if s, err := strconv.Unquote(lit.Value); err == nil {
					kinds[s] = true
				}
			}
		}
		return true
	})
	return kinds
}

// tur7b02RouterKinds reads the kinds router.md owns for detect.go: the sentence
// under `## kinds` that starts "detect.go names" ends at the next semicolon and
// lists the detector's vocabulary; other emitters (bundle, mobile, managed,
// registry readers) are named after it and are out of this test's scope.
func tur7b02RouterKinds(t *testing.T, doc string) map[string]bool {
	t.Helper()
	at := strings.Index(doc, "detect.go names ")
	if at < 0 {
		t.Fatal("router.md has no `## kinds` sentence starting \"detect.go names\"")
	}
	sentence := doc[at:]
	if end := strings.IndexByte(sentence, ';'); end >= 0 {
		sentence = sentence[:end]
	}
	kinds := map[string]bool{}
	for _, m := range regexp.MustCompile("`([a-z0-9-]+)`").FindAllStringSubmatch(sentence, -1) {
		kinds[m[1]] = true
	}
	if len(kinds) == 0 {
		t.Fatalf("router.md detector kind sentence names no kind: %q", sentence)
	}
	return kinds
}

// tur7b02DocPlans reads the plan ids from the `## Digest plan` table.
func tur7b02DocPlans(t *testing.T, doc string) map[string]bool {
	t.Helper()
	at := strings.Index(doc, "## Digest plan")
	if at < 0 {
		t.Fatal("router.md has no `## Digest plan` table")
	}
	plans := map[string]bool{}
	for _, line := range strings.Split(doc[at:], "\n") {
		if m := regexp.MustCompile(`^\| ` + "`" + `([a-z]+)` + "`" + ` \|`).FindStringSubmatch(line); m != nil {
			plans[m[1]] = true
		}
	}
	if len(plans) == 0 {
		t.Fatal("`## Digest plan` table names no plan")
	}
	return plans
}

func tur7b02Sorted(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

func tur7b02Path(rel string) func(*testing.T) string {
	return func(t *testing.T) string {
		t.Helper()
		if _, err := os.Stat(rel); err != nil {
			t.Fatalf("fixture %s: %v", rel, err)
		}
		return rel
	}
}

// tur7b02Magic builds a target from a magic prefix plus filler, for kinds whose
// reader only owes a handoff note.
func tur7b02Magic(name string, magic []byte) func(*testing.T) string {
	return func(t *testing.T) string {
		t.Helper()
		body := make([]byte, 64)
		copy(body, magic)
		p := filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(p, body, 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		return p
	}
}

func tur7b02Unknown(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "blob.bin")
	if err := os.WriteFile(p, []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}, 0o644); err != nil {
		t.Fatalf("write blob: %v", err)
	}
	return p
}

func tur7b02AndroidManifest(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "AndroidManifest.xml")
	if err := os.WriteFile(p, binaryManifest(0x100), 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	return p
}

// tur7b02Zip builds a one-entry store-method archive with a fixed timestamp, so
// the bytes are the same on every run.
func tur7b02Zip(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "bundle.zip")
	f, err := os.Create(p)
	if err != nil {
		t.Fatalf("create zip: %v", err)
	}
	zw := zip.NewWriter(f)
	w, err := zw.CreateHeader(&zip.FileHeader{Name: "a.txt", Method: zip.Store, Modified: time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatalf("zip header: %v", err)
	}
	if _, err := w.Write([]byte("lrecon\n")); err != nil {
		t.Fatalf("zip body: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}
	return p
}

func tur7b02Text(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "notes.txt")
	if err := os.WriteFile(p, []byte("lrecon tur7 bucket02 plain text fixture, nothing to parse here\n"), 0o644); err != nil {
		t.Fatalf("write text: %v", err)
	}
	return p
}
