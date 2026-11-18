package main

// A name matcher flips when the names change; an analyzer that reads the file
// does not. This test renames every identifier (and every comment) of a real
// corpus program, proves the rewrite is AST-equivalent to the original before
// anything is compared, builds both versions, and requires the tool's
// structured verdict (digest fields, plan, inspect_go_binary) to be identical.
// If the rewrite is wrong the test fails on the AST check, so a broken rewrite
// can never masquerade as a tool defect.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/scanner"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

// evergreen18Source is a real corpus program: one package variable, one helper
// and one entry point, standard library only, so both the original and the
// renamed copy compile into real native images the analyzer can read.
const evergreen18Source = "../env/sim300/run/20261031-130729/w/001-go-elf-ghidra/gosrc-app/main.go"

const evergreen18Module = "example.com/evergreen18"

// evergreen18Rename is the planned rewrite: names for identifiers, comment
// text by byte offset. Both are derived from one AST visit.
type evergreen18Rename struct {
	idents   map[string]string
	comments map[int]string
}

// evergreen18KeepNames is everything the rewrite must not touch: the package
// clause, the buildable entry points, predeclared names, import names and the
// blank identifier.
func evergreen18KeepNames(f *ast.File) map[string]bool {
	keep := map[string]bool{
		"main": true, "init": true, "_": true,
		"append": true, "bool": true, "byte": true, "cap": true, "close": true,
		"complex": true, "complex64": true, "complex128": true, "copy": true,
		"delete": true, "error": true, "false": true, "float32": true,
		"float64": true, "imag": true, "int": true, "int8": true, "int16": true,
		"int32": true, "int64": true, "iota": true, "len": true, "make": true,
		"new": true, "nil": true, "panic": true, "print": true, "println": true,
		"real": true, "recover": true, "rune": true, "string": true, "true": true,
		"uint": true, "uint8": true, "uint16": true, "uint32": true, "uint64": true,
		"uintptr": true, "any": true, "comparable": true, "min": true, "max": true,
		"clear": true,
	}
	keep[f.Name.Name] = true
	for _, imp := range f.Imports {
		if imp.Name != nil {
			keep[imp.Name.Name] = true
			continue
		}
		p := strings.Trim(imp.Path.Value, `"`)
		keep[p[strings.LastIndexAny(p, "/")+1:]] = true
	}
	return keep
}

// evergreen18Renamable marks every identifier occurrence the rewrite may move.
// Selector suffixes, struct fields, composite-literal keys and import aliases
// belong to a type declared somewhere else, so they stay verbatim.
func evergreen18Renamable(f *ast.File) map[*ast.Ident]bool {
	bound := map[*ast.Ident]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.SelectorExpr:
			bound[n.Sel] = true
		case *ast.StructType:
			for _, fld := range n.Fields.List {
				for _, id := range fld.Names {
					bound[id] = true
				}
			}
		case *ast.InterfaceType:
			for _, fld := range n.Methods.List {
				for _, id := range fld.Names {
					bound[id] = true
				}
			}
		case *ast.KeyValueExpr:
			if id, ok := n.Key.(*ast.Ident); ok {
				bound[id] = true
			}
		case *ast.ImportSpec:
			if n.Name != nil {
				bound[n.Name] = true
			}
		}
		return true
	})
	keep := evergreen18KeepNames(f)
	free := map[*ast.Ident]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && !bound[id] && !keep[id.Name] {
			free[id] = true
		}
		return true
	})
	return free
}

func evergreen18CommentText(old string, n int) string {
	if strings.HasPrefix(old, "/*") {
		return fmt.Sprintf("/* zc%02d */", n)
	}
	return fmt.Sprintf("// zc%02d", n)
}

// evergreen18Plan builds the rewrite from the original source only.
func evergreen18Plan(t *testing.T, src []byte) (*ast.File, *token.FileSet, *evergreen18Rename) {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "main.go", src, parser.ParseComments)
	if err != nil {
		t.Fatalf("%s does not parse: %v", evergreen18Source, err)
	}
	names := map[string]bool{}
	for id := range evergreen18Renamable(f) {
		names[id.Name] = true
	}
	sorted := make([]string, 0, len(names))
	for n := range names {
		sorted = append(sorted, n)
	}
	sort.Strings(sorted)
	r := &evergreen18Rename{idents: make(map[string]string, len(sorted)), comments: map[int]string{}}
	for i, n := range sorted {
		r.idents[n] = fmt.Sprintf("zq%03d", i)
	}
	tf := fset.File(f.Pos())
	seq := 0
	for _, cg := range f.Comments {
		for _, c := range cg.List {
			r.comments[tf.Offset(c.Pos())] = evergreen18CommentText(c.Text, seq)
			seq++
		}
	}
	return f, fset, r
}

// evergreen18Rewrite replaces identifier and comment tokens in place, leaving
// every byte that is not one of those tokens exactly where it was.
func (r *evergreen18Rename) rewrite(t *testing.T, src []byte) []byte {
	t.Helper()
	tf := token.NewFileSet().AddFile("main.go", 1, len(src))
	var s scanner.Scanner
	s.Init(tf, src, nil, scanner.ScanComments)
	var out bytes.Buffer
	last := 0
	for {
		pos, tok, lit := s.Scan()
		if tok == token.EOF {
			break
		}
		if tok != token.IDENT && tok != token.COMMENT {
			continue
		}
		off := tf.Offset(pos)
		repl := ""
		if tok == token.IDENT {
			repl = r.idents[lit]
		} else {
			repl = r.comments[off]
		}
		if repl == "" {
			continue
		}
		out.Write(src[last:off])
		out.WriteString(repl)
		last = off + len(lit)
	}
	out.Write(src[last:])
	return out.Bytes()
}

// evergreen18Squash drops layout so the comparison is about structure, not the
// column a renamed identifier happens to end on.
func evergreen18Squash(s string) string {
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		lines[i] = strings.Join(strings.Fields(line), " ")
	}
	return strings.Join(lines, "\n")
}

// evergreen18Equivalent refuses to compare tool verdicts unless the copy is the
// original AST with exactly the planned identifier and comment names: the
// original AST gets the planned rewrite applied and both are printed by
// go/printer, so a stray rename, a dropped comment or a changed declaration
// fails here loudly instead of looking like a tool defect.
func evergreen18Equivalent(t *testing.T, src, copySrc []byte, r *evergreen18Rename) {
	t.Helper()
	printOne := func(name string, body []byte, apply bool) string {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, name, body, parser.ParseComments)
		if err != nil {
			t.Fatalf("renamed copy does not parse (%s): %v", name, err)
		}
		if apply {
			for id := range evergreen18Renamable(f) {
				if nw, ok := r.idents[id.Name]; ok {
					id.Name = nw
				}
			}
			tf := fset.File(f.Pos())
			for _, cg := range f.Comments {
				for _, c := range cg.List {
					if nw, ok := r.comments[tf.Offset(c.Pos())]; ok {
						c.Text = nw
					}
				}
			}
		}
		var buf bytes.Buffer
		cfg := printer.Config{Mode: printer.UseSpaces | printer.TabIndent, Tabwidth: 8}
		if err := cfg.Fprint(&buf, fset, f); err != nil {
			t.Fatalf("print %s: %v", name, err)
		}
		return evergreen18Squash(buf.String())
	}
	want := printOne("original.go", src, true)
	got := printOne("copy.go", copySrc, false)
	if want != got {
		t.Fatalf("rename bomb is NOT AST-equivalent to %s, refusing to compare tool verdicts:\n--- original AST after the planned rewrite ---\n%s\n--- renamed copy ---\n%s", evergreen18Source, want, got)
	}
}

func evergreen18Build(t *testing.T, dir string, src []byte) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"), src, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module "+evergreen18Module+"\n\ngo 1.22\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	out := filepath.Join(dir, "prog")
	cmd := exec.CommandContext(ctx, "go", "build", "-trimpath", "-buildvcs=false", "-o", out, ".")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GO111MODULE=on", "GOWORK=off", "GOTOOLCHAIN=local")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build of %s failed (the analyzer needs a real image): %v: %s", dir, err, b)
	}
	return out
}

// evergreen18Verdict is the structured answer, never the prose: the digest with
// its build identity removed, the planned next step, and the Go build-info op.
func evergreen18Verdict(t *testing.T, bin string) (map[string]any, Digest) {
	t.Helper()
	d, err := Probe(bin)
	if err != nil {
		t.Fatalf("Probe(%s): %v", bin, err)
	}
	raw, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	v := map[string]any{}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	// Fields that describe this build, not the program: two honest reads of two
	// different images must differ here.
	for _, k := range []string{"target", "uuid", "build_id", "entrypoint", "bytes_scanned", "file_size"} {
		delete(v, k)
	}
	planRaw, err := json.Marshal(buildPlan(d, bin))
	if err != nil {
		t.Fatal(err)
	}
	planMap := map[string]any{}
	if err := json.Unmarshal(planRaw, &planMap); err != nil {
		t.Fatal(err)
	}
	delete(planMap, "cmd") // the command carries the temp path
	if next, ok := planMap["next"].([]any); ok {
		for i, step := range next {
			if s, ok := step.(string); ok {
				next[i] = strings.ReplaceAll(s, bin, "<target>")
			}
		}
	}
	v["plan_detail"] = planMap
	v["inspect_go_binary"] = opStatic(t, "inspect_go_binary", bin)
	return v, d
}

func TestEvergreen18RenameBombSemanticStable(t *testing.T) {
	src, err := os.ReadFile(evergreen18Source)
	if err != nil {
		t.Fatalf("corpus source %s unreadable: %v", evergreen18Source, err)
	}
	_, _, r := evergreen18Plan(t, src)
	if len(r.idents) < 3 {
		t.Fatalf("rename plan touched only %d identifier(s) (%v); the bomb is too weak to prove anything", len(r.idents), r.idents)
	}
	copySrc := r.rewrite(t, src)
	if bytes.Equal(src, copySrc) {
		t.Fatalf("renamed copy is byte-identical to %s: nothing was renamed", evergreen18Source)
	}
	evergreen18Equivalent(t, src, copySrc, r)

	dir := t.TempDir()
	origBin := evergreen18Build(t, filepath.Join(dir, "orig"), src)
	copyBin := evergreen18Build(t, filepath.Join(dir, "copy"), copySrc)

	// The rename must have reached the artifact, otherwise the verdict could be
	// stable simply because both images are the same build.
	origBytes, err := os.ReadFile(origBin)
	if err != nil {
		t.Fatal(err)
	}
	copyBytes, err := os.ReadFile(copyBin)
	if err != nil {
		t.Fatal(err)
	}
	moved := 0
	for old, nw := range r.idents {
		if len(old) < 5 {
			continue
		}
		if bytes.Contains(origBytes, []byte(old)) && !bytes.Contains(copyBytes, []byte(old)) && bytes.Contains(copyBytes, []byte(nw)) {
			moved++
		}
	}
	if moved == 0 {
		t.Fatalf("no renamed identifier reached the compiled image; the rename bomb never landed")
	}

	origVerdict, origDigest := evergreen18Verdict(t, origBin)
	copyVerdict, copyDigest := evergreen18Verdict(t, copyBin)

	// A verdict that is equal because it is empty would pass any target: pin the
	// fields this image must answer, then compare the whole structure.
	if k := origVerdict["kind"]; k != "macho" && k != "elf" && k != "pe" {
		t.Fatalf("verdict kind = %v, want a native image kind", k)
	}
	planDetail, ok := origVerdict["plan_detail"].(map[string]any)
	if !ok || planDetail["op"] == "" || planDetail["op"] == nil {
		t.Fatalf("plan_detail carries no op: %v", origVerdict["plan_detail"])
	}
	goInfo, ok := origVerdict["inspect_go_binary"].(map[string]any)
	if !ok {
		t.Fatalf("inspect_go_binary verdict = %v", origVerdict["inspect_go_binary"])
	}
	if names, _ := goInfo["names"].(string); !strings.HasPrefix(names, "pclntab:") {
		t.Fatalf("inspect_go_binary names = %v, want a pclntab count", goInfo["names"])
	}
	if _, ok := origVerdict["slices"]; !ok {
		t.Fatalf("verdict has no slices field: %v", origVerdict)
	}
	if origDigest.Target.FileSHA256 == copyDigest.Target.FileSHA256 {
		t.Fatalf("both builds hash to %s: the two images are identical, the rename never ran", origDigest.Target.FileSHA256)
	}

	if !reflect.DeepEqual(origVerdict, copyVerdict) {
		a, _ := json.MarshalIndent(origVerdict, "", "  ")
		b, _ := json.MarshalIndent(copyVerdict, "", "  ")
		t.Fatalf("structured verdict moved when only names changed:\n--- original ---\n%s\n--- renamed ---\n%s", a, b)
	}
}
