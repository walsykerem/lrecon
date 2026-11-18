package main

import (
	"encoding/json"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// The prior false PRESENT came from a checker that grepped the skill's own
// markdown for feature phrases: the docs mention every feature, so the checker
// always "found" them. This test feeds those same documents to the real CLI as
// if they were targets and requires them to be rejected as non-source, while
// genuine .go files must be accepted. Source identity comes from the Go
// grammar, never from prose or from the digest's `kind` (a .md and a .go are
// both `kind:"text"`, so `kind` alone is exactly the evidence that lied).

type ev11Digest struct {
	Kind      string `json:"kind"`
	Plan      string `json:"plan"`
	Toolchain string `json:"toolchain"`
	Exports   int    `json:"exports"`
	FileSize  int64  `json:"file_size"`
}

const (
	ev11Source    = "go-source"
	ev11NonSource = "non-source"
)

func ev11Read(t *testing.T, bin, target string) ev11Digest {
	t.Helper()
	out, err := exec.Command(bin, target, "--json").Output()
	if err != nil {
		t.Fatalf("lrecon %s --json: %v", target, err)
	}
	var d ev11Digest
	if err := json.Unmarshal(out, &d); err != nil {
		t.Fatalf("lrecon %s --json: bad digest: %v", target, err)
	}
	if d.Kind == "" {
		t.Fatalf("lrecon %s --json: empty kind, target was not read", target)
	}
	return d
}

// ev11Verdict is the whole classification: the CLI must read the target, and
// the bytes must parse as a Go package clause. Prose never does.
func ev11Verdict(t *testing.T, bin, path string) (string, ev11Digest) {
	t.Helper()
	d := ev11Read(t, bin, path)
	_, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.PackageClauseOnly)
	if err == nil {
		return ev11Source, d
	}
	return ev11NonSource, d
}

func ev11Docs(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(dir, func(p string, e os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !e.IsDir() && filepath.Ext(p) == ".md" {
			out = append(out, p)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", dir, err)
	}
	sort.Strings(out)
	return out
}

// ev11GoSample spreads a fixed stride over the sorted corpus so the sample is
// deterministic and not one directory's flavour.
func ev11GoSample(t *testing.T, root string, want int) []string {
	t.Helper()
	var all []string
	err := filepath.WalkDir(root, func(p string, e os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if e.IsDir() && e.Name() == ".git" {
			return filepath.SkipDir
		}
		if !e.IsDir() && filepath.Ext(p) == ".go" {
			all = append(all, p)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	sort.Strings(all)
	if len(all) <= want {
		return all
	}
	step := len(all) / want
	out := make([]string, 0, want)
	for i := 0; i < len(all) && len(out) < want; i += step {
		out = append(out, all[i])
	}
	return out
}

func TestEvergreen11MarkdownSelfAntigen(t *testing.T) {
	bin := "./lrecon"
	if _, err := os.Stat(bin); err != nil {
		t.Fatalf("real CLI missing at %s: %v", bin, err)
	}
	if v, err := exec.Command(bin, "--version").Output(); err != nil || !strings.HasPrefix(strings.TrimSpace(string(v)), "lrecon ") {
		t.Fatalf("%s --version = %q, %v: not the real CLI", bin, v, err)
	}
	docs := ev11Docs(t, filepath.Join("..", "skill"))
	if len(docs) < 5 {
		t.Fatalf("expected the skill's own documents, got %d", len(docs))
	}
	goFiles := ev11GoSample(t, "..", 24)
	if len(goFiles) < 20 {
		t.Fatalf("expected genuine .go files, got %d", len(goFiles))
	}

	docVerdicts := map[string]int{}
	for _, p := range docs {
		v, d := ev11Verdict(t, bin, p)
		docVerdicts[v]++
		if v != ev11NonSource {
			t.Errorf("doc %s classified %q: the skill's own markdown must be rejected as non-source", p, v)
		}
		// The trap: the CLI calls a document `kind:"text"` just like it calls a
		// .go file `kind:"text"`. That value is not evidence of source.
		if d.Kind != "text" || d.Plan != "generic" {
			t.Errorf("doc %s: digest kind=%q plan=%q, want text/generic", p, d.Kind, d.Plan)
		}
	}

	goVerdicts := map[string]int{}
	for _, p := range goFiles {
		v, d := ev11Verdict(t, bin, p)
		goVerdicts[v]++
		if v != ev11Source {
			t.Errorf("source %s classified %q: genuine .go files must be accepted", p, v)
		}
		// A .go file that embeds fixture magic (a test writing phar/zip bytes)
		// can make the CLI claim that container; the grammar still decides
		// source-ness, so only the read itself is pinned here.
		if d.Exports != 0 {
			t.Errorf("source %s: digest exports=%d, want 0 for a text target", p, d.Exports)
		}
		if fi, err := os.Stat(p); err != nil || fi.Size() != d.FileSize {
			t.Errorf("source %s: digest file_size=%d does not match the file", p, d.FileSize)
		}
	}

	// Both directions must be non-empty and the two verdicts must differ: a
	// classifier that returns one constant fails here, not just above.
	if docVerdicts[ev11NonSource] != len(docs) {
		t.Fatalf("doc verdicts = %v, want all %q", docVerdicts, ev11NonSource)
	}
	if goVerdicts[ev11Source] != len(goFiles) {
		t.Fatalf("source verdicts = %v, want all %q", goVerdicts, ev11Source)
	}
	if len(docVerdicts) == 1 && len(goVerdicts) == 1 {
		for k := range docVerdicts {
			if _, same := goVerdicts[k]; same {
				t.Fatalf("markdown and .go got the same verdict %q: not distinguishable", k)
			}
		}
	}
	t.Logf("docs=%d verdict=%s | source=%d verdict=%s", len(docs), ev11NonSource, len(goFiles), ev11Source)
}
