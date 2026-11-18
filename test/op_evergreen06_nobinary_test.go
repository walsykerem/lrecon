package main

// Evergreen 06: skill/scripts/find.sh is the shell shim that routes one target
// to "$LRECON" (or bare `lrecon` from PATH). When that binary is unreachable
// the wrapper has to fail loudly: exit non-zero with an error line. A silent
// exit 0 carrying a success verdict would grade every .go file PRESENT without
// ever running the tool, which is a fake by construction.

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type e06Run struct {
	code   int
	stdout string
	stderr string
}

// e06Loud is the acceptance bar for an unreachable tool: non-zero exit, an
// error line naming the failure, and no success verdict on stdout.
func e06Loud(r e06Run) bool {
	if r.code == 0 || r.stdout != "" {
		return false
	}
	if !strings.Contains(r.stderr, "No such file or directory") &&
		!strings.Contains(r.stderr, "not found") {
		return false
	}
	return !strings.Contains(r.stdout, "kind: text") && !strings.Contains(r.stdout, "PRESENT")
}

// e06Env builds a child env with PATH, HOME and every LRECON* input controlled
// by the test, so the caller's shell cannot supply a working binary.
func e06Env(pathValue, lrecon, home string, extra ...string) []string {
	env := make([]string, 0, len(os.Environ())+3)
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		if k == "PATH" || k == "HOME" || k == "LRECON" || strings.HasPrefix(k, "LRECON_") {
			continue
		}
		env = append(env, kv)
	}
	env = append(env, "PATH="+pathValue, "HOME="+home)
	if lrecon != "" {
		env = append(env, "LRECON="+lrecon)
	}
	return append(env, extra...)
}

func e06RunShim(t *testing.T, bash, shim, target string, env []string) e06Run {
	t.Helper()
	cmd := exec.Command(bash, shim, "--budget", "4096", "--", target)
	cmd.Env = env
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	r := e06Run{stdout: out.String(), stderr: errb.String()}
	if err == nil {
		return r
	}
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("running wrapper: %v", err)
	}
	r.code = ee.ExitCode()
	return r
}

func TestEvergreen06MissingBinaryFailsLoud(t *testing.T) {
	if buildErr != nil {
		t.Fatalf("go build failed: %v\n%s", buildErr, buildLog)
	}
	if cliPath == "" {
		t.Fatal("cli binary was not built")
	}
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	root := filepath.Dir(wd)
	target := filepath.Join(root, "lrecon", "ops.go")
	fi, err := os.Stat(target)
	if err != nil || !fi.Mode().IsRegular() || filepath.Ext(target) != ".go" || !filepath.IsAbs(target) {
		t.Fatalf("target fixture %s is not an absolute regular .go file: %v", target, err)
	}
	shim, err := filepath.Abs(filepath.Join(root, "skill", "scripts", "find.sh"))
	if err != nil {
		t.Fatalf("abs shim: %v", err)
	}
	if _, err := os.Stat(shim); err != nil {
		t.Fatalf("skill shim %s missing: %v", shim, err)
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Fatalf("bash not found: %v", err)
	}
	emptyPath := t.TempDir()
	home := t.TempDir()

	// 1) Documented LRECON override pointed at a path that does not exist.
	bad := filepath.Join(t.TempDir(), "missing", "lrecon")
	got := e06RunShim(t, bash, shim, target, e06Env(emptyPath, bad, home))
	if !e06Loud(got) {
		t.Fatalf("LRECON=%s degraded silently: exit=%d stdout=%q stderr=%q",
			bad, got.code, got.stdout, got.stderr)
	}
	if !strings.Contains(got.stderr, bad) {
		t.Fatalf("error does not name the unreachable binary %q: %q", bad, got.stderr)
	}

	// 2) LRECON unset and no lrecon anywhere on PATH.
	got = e06RunShim(t, bash, shim, target, e06Env(emptyPath, "", home))
	if !e06Loud(got) {
		t.Fatalf("empty PATH degraded silently: exit=%d stdout=%q stderr=%q",
			got.code, got.stdout, got.stderr)
	}
	if !strings.Contains(got.stderr, "lrecon: not found") {
		t.Fatalf("error does not say lrecon was not found: %q", got.stderr)
	}

	// 3) The same operation succeeds once the built binary is reachable, so the
	//    test proves the distinction rather than the absence of a failure.
	ok := e06RunShim(t, bash, shim, target, e06Env(emptyPath, cliPath, home))
	if ok.code != 0 {
		t.Fatalf("reachable binary failed: exit=%d stderr=%q", ok.code, ok.stderr)
	}
	if ok.stderr != "" {
		t.Fatalf("reachable binary wrote stderr %q", ok.stderr)
	}
	if !strings.Contains(ok.stdout, "kind: text") {
		t.Fatalf("reachable binary produced no digest for %s: %q", target, ok.stdout)
	}

	// 4) The predicate rejects a silent degradation, so an exit-0 success line
	//    can never pass for a loud failure.
	silent := filepath.Join(t.TempDir(), "silent.sh")
	if err := os.WriteFile(silent, []byte("#!/bin/sh\necho 'kind: text'\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("write silent shim: %v", err)
	}
	if e06Loud(e06RunShim(t, bash, silent, target, e06Env(emptyPath, "", home))) {
		t.Fatal("predicate accepted an exit-0 success line as a loud failure")
	}
}
