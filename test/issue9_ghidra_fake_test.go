package main

// ISSUE9: the nine Ghidra ext ops that had no targeted test. lane06FakeGhidra
// stands in for analyzeHeadless, so each op's exact argv, its argument refusal
// and the missing-engine refusal are checked without a real Ghidra install.

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type issue9GhidraOp struct {
	name string
	run  func(string, []string) (any, error)
	args []string
}

func issue9GhidraOps(t *testing.T) []issue9GhidraOp {
	t.Helper()
	keystore := filepath.Join(t.TempDir(), "ghidra.keystore")
	if err := os.WriteFile(keystore, []byte("ks"), 0o600); err != nil {
		t.Fatal(err)
	}
	return []issue9GhidraOp{
		{"ghidra_analysis_timeout", ghidraAnalysisTimeout, []string{"120"}},
		{"ghidra_commit", ghidraCommit, []string{"checkpoint 1"}},
		{"ghidra_connect", ghidraConnect, nil},
		{"ghidra_keystore", ghidraKeystore, []string{keystore}},
		{"ghidra_library_paths", ghidraLibraryPaths, []string{"/opt/ghidra/libs"}},
		{"ghidra_loader", ghidraLoader, []string{"elf"}},
		{"ghidra_mirror", ghidraMirror, nil},
		{"ghidra_overwrite", ghidraOverwrite, nil},
		{"ghidra_readonly", ghidraReadonly, nil},
	}
}

func TestIssue9GhidraOpsBuildCommand(t *testing.T) {
	old := opOutput
	opOutput = ""
	t.Cleanup(func() { opOutput = old })
	lane06FakeGhidra(t)
	keystore := issue9GhidraOps(t)[3].args[0]

	cases := []struct {
		op   string
		run  func(string, []string) (any, error)
		args []string
		want []string
	}{
		{"analysis_timeout", ghidraAnalysisTimeout, []string{"120"}, []string{"<dir>", "lrecon", "-analysisTimeoutPerFile", "120", "-import", "app.bin"}},
		{"commit", ghidraCommit, []string{"checkpoint 1"}, []string{"<dir>", "lrecon", "-commit", "checkpoint 1", "-import", "app.bin"}},
		{"connect", ghidraConnect, []string{"-p"}, []string{"<dir>", "lrecon", "-connect", "-import", "app.bin", "-p"}},
		{"keystore", ghidraKeystore, []string{keystore}, []string{"<dir>", "lrecon", "-keystore", keystore, "-import", "app.bin"}},
		{"library_paths", ghidraLibraryPaths, []string{"/opt/ghidra/libs"}, []string{"<dir>", "lrecon", "-librarySearchPaths", "/opt/ghidra/libs", "-import", "app.bin"}},
		{"loader", ghidraLoader, []string{"elf", "-loader-arg", "x"}, []string{"<dir>", "lrecon", "-loader", "elf", "-import", "app.bin", "-loader-arg", "x"}},
		{"mirror", ghidraMirror, nil, []string{"<dir>", "lrecon", "-mirror", "-import", "app.bin"}},
		{"overwrite", ghidraOverwrite, nil, []string{"<dir>", "lrecon", "-overwrite", "-import", "app.bin"}},
		{"readonly", ghidraReadonly, nil, []string{"<dir>", "lrecon", "-readOnly", "-import", "app.bin"}},
	}
	for _, c := range cases {
		t.Run(c.op, func(t *testing.T) {
			v, err := c.run("app.bin", c.args)
			out := lane06ExtOut(t, v, err, "analyzeHeadless", c.want...)
			if !strings.HasSuffix(out.Args[0], "/project") {
				t.Fatalf("%s project dir = %q, want .../project", c.op, out.Args[0])
			}
		})
	}
}

func TestIssue9GhidraOpsNeedArgs(t *testing.T) {
	rtNoTools(t)
	t.Setenv("LRECON_GHIDRA", filepath.Join(t.TempDir(), "absent-analyzeHeadless"))
	for _, c := range issue9GhidraOps(t) {
		if c.name == "ghidra_connect" || c.name == "ghidra_mirror" ||
			c.name == "ghidra_overwrite" || c.name == "ghidra_readonly" {
			continue
		}
		t.Run(c.name, func(t *testing.T) {
			_, err := c.run("app.bin", nil)
			var ref *extRefusal
			if !errors.As(err, &ref) || ref.kind != kindNeedsArg || !strings.Contains(ref.msg, "needs an argument") {
				t.Fatalf("%s without its argument = %v, want kindNeedsArg", c.name, err)
			}
		})
	}
}

func TestIssue9GhidraKeystoreRejectsDirectory(t *testing.T) {
	rtNoTools(t)
	t.Setenv("LRECON_GHIDRA", filepath.Join(t.TempDir(), "absent-analyzeHeadless"))
	_, err := ghidraKeystore("app.bin", []string{t.TempDir()})
	var ref *extRefusal
	if !errors.As(err, &ref) || ref.kind != kindNeedsArg || !strings.Contains(ref.msg, "keystore file") {
		t.Fatalf("directory keystore = %v, want a keystore-file refusal", err)
	}
}

func TestIssue9GhidraOpsRefuseMissingEngine(t *testing.T) {
	rtNoTools(t)
	t.Setenv("LRECON_GHIDRA", filepath.Join(t.TempDir(), "absent-analyzeHeadless"))
	for _, c := range issue9GhidraOps(t) {
		t.Run(c.name, func(t *testing.T) {
			_, err := c.run("app.bin", c.args)
			var ref *extRefusal
			if !errors.As(err, &ref) || ref.kind != kindNoEngine || !strings.Contains(ref.msg, "not installed") {
				t.Fatalf("%s without Ghidra = %v, want kindNoEngine", c.name, err)
			}
		})
	}
}
