package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// evergreen05FakeGo puts a /bin/sh shim named `go` on PATH. --deep hands a Go
// binary to `go tool objdump`, so a token this shim prints can only reach the
// result if lrecon really spawned the subprocess and copied its stdout.
func evergreen05FakeGo(t *testing.T, body string) {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "go")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+":/bin:/usr/bin")
}

func TestEvergreen05DecoyTokenDifferential(t *testing.T) {
	// The target is a real Go binary (the CLI built by TestMain): --deep reads
	// its symbol table in-process and then shells out to `go`.
	if buildErr != nil || cliPath == "" {
		t.Fatalf("cli binary unavailable: buildErr=%v path=%q\n%s", buildErr, cliPath, buildLog)
	}

	const tokenA = "evergreen05-decoy-token-a7f3"
	const tokenB = "evergreen05-decoy-failure-b9c2"

	// A: the subprocess answers. Its stdout must show up in the wrapper output.
	evergreen05FakeGo(t, "echo "+tokenA+"\nexit 0")
	outA, codeA := runCLI(t, "--deep", "main.main", cliPath)
	if codeA != 0 {
		t.Fatalf("branch A exit %d, want 0; output:\n%s", codeA, outA)
	}
	if !strings.Contains(outA, tokenA) {
		t.Fatalf("branch A output lacks the subprocess token %q, so the answer did not come from `go tool objdump`:\n%s", tokenA, outA)
	}

	// B: the subprocess fails. The distinct stderr text must be surfaced, and
	// the success-only token must not reappear. Observed: exit stays 0 because
	// DeepScan reports the failed engine and still returns the symbol line, so
	// the failure gate is the text, not the status code.
	evergreen05FakeGo(t, "echo "+tokenB+" >&2\nexit 3")
	outB, _ := runCLI(t, "--deep", "main.main", cliPath)
	if !strings.Contains(outB, tokenB) {
		t.Fatalf("branch B output swallowed the subprocess failure %q:\n%s", tokenB, outB)
	}
	if !strings.Contains(outB, "go tool objdump did not run") {
		t.Fatalf("branch B output does not name the failed engine:\n%s", outB)
	}
	if strings.Contains(outB, tokenA) {
		t.Fatalf("branch B output still carries the branch-A token %q, so it was not produced by this run:\n%s", tokenA, outB)
	}
}
