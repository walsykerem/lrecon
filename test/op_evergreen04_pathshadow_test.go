package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The skill ships a shell shim (skill/scripts/find.sh) that shells out to
// "$LRECON" when set and to bare `lrecon` (PATH lookup) otherwise. This pins
// that behaviour: a PATH-shadowing fake must be invoked with the caller's real
// target path, and its output must reach the wrapper's stdout untouched.

const e04Poison = "POISON-E04-PATHSHADOW"

type e04Record struct {
	Args  []string `json:"args"`
	Stdin string   `json:"stdin"`
}

// e04Fake writes an executable shim that logs one JSON line per invocation and
// then prints the poison marker, so a hidden real-binary bypass cannot be
// mistaken for success.
func e04Fake(t *testing.T, dir string) string {
	t.Helper()
	p := filepath.Join(dir, "lrecon")
	body := "#!/bin/sh\n" +
		`printf '{"args":[' >> "$E04_REC"` + "\n" +
		"sep=\n" +
		`for a in "$@"; do printf '%s"%s"' "$sep" "$a" >> "$E04_REC"; sep=,; done` + "\n" +
		`in=$(cat)` + "\n" +
		`printf '],"stdin":"%s"}\n' "$in" >> "$E04_REC"` + "\n" +
		"echo " + e04Poison + "\n" +
		"exit 0\n"
	if err := os.WriteFile(p, []byte(body), 0o755); err != nil {
		t.Fatalf("write fake: %v", err)
	}
	return p
}

// e04Env builds a child env with a clean PATH/LRECON/E04_REC so the caller's
// shell cannot influence the lookup.
func e04Env(pathValue, rec string, extra ...string) []string {
	var env []string
	for _, kv := range os.Environ() {
		k := kv[:strings.IndexByte(kv, '=')]
		if k == "PATH" || k == "LRECON" || k == "E04_REC" {
			continue
		}
		env = append(env, kv)
	}
	env = append(env, "PATH="+pathValue, "E04_REC="+rec)
	return append(env, extra...)
}

func e04Run(t *testing.T, shim, target string, env []string) string {
	t.Helper()
	cmd := exec.Command("bash", shim, "--budget", "4096", "--", target)
	cmd.Env = env
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		t.Fatalf("wrapper failed: %v stderr=%q", err, errb.String())
	}
	return out.String()
}

// e04Invocations parses the JSON-lines log and requires at least one call.
func e04Invocations(t *testing.T, rec string) []e04Record {
	t.Helper()
	raw, err := os.ReadFile(rec)
	if err != nil {
		t.Fatalf("fake was never invoked (no log): %v", err)
	}
	var recs []e04Record
	for _, line := range bytes.Split(bytes.TrimSpace(raw), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var r e04Record
		if err := json.Unmarshal(line, &r); err != nil {
			t.Fatalf("bad log line %q: %v", line, err)
		}
		recs = append(recs, r)
	}
	if len(recs) == 0 {
		t.Fatal("fake recorded zero invocations")
	}
	return recs
}

func TestEvergreen04PathShadowArgv(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	root := filepath.Dir(wd)
	target := filepath.Join(root, "lrecon", "ops.go")
	if fi, err := os.Stat(target); err != nil || !fi.Mode().IsRegular() {
		t.Fatalf("target fixture %s unusable: %v", target, err)
	}
	if !filepath.IsAbs(target) || !strings.HasSuffix(target, ".go") || !strings.HasPrefix(target, root+string(os.PathSeparator)) {
		t.Fatalf("target %q is not an absolute .go under %s", target, root)
	}
	shim, err := filepath.Abs(filepath.Join(root, "skill", "scripts", "find.sh"))
	if err != nil {
		t.Fatalf("abs shim: %v", err)
	}
	if _, err := os.Stat(shim); err != nil {
		t.Fatalf("skill shim %s missing: %v", shim, err)
	}

	tmp := t.TempDir()
	fakeDir := filepath.Join(tmp, "bin")
	if err := os.MkdirAll(fakeDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	fake := e04Fake(t, fakeDir)
	minPath := "/usr/bin:/bin:/usr/sbin:/sbin"

	// 1) PATH shadowing: bare `lrecon` must resolve to the fake.
	rec1 := filepath.Join(tmp, "rec1.jsonl")
	out1 := e04Run(t, shim, target, e04Env(fakeDir+":"+minPath, rec1))
	if !strings.Contains(out1, e04Poison) {
		t.Fatalf("poison marker missing from wrapper stdout %q: real binary bypassed the fake", out1)
	}
	calls1 := e04Invocations(t, rec1)
	if got, want := calls1[0].Args[0], "--max-bytes"; got != want {
		t.Fatalf("first scripted arg = %q, want %q (argv %v)", got, want, calls1[0].Args)
	}
	if !e04HasArg(calls1[0].Args, target) {
		t.Fatalf("target %q not passed to fake; argv=%v", target, calls1[0].Args)
	}
	for _, a := range calls1[0].Args {
		if strings.Contains(a, string(os.PathSeparator)+"skill"+string(os.PathSeparator)) {
			t.Fatalf("doc path %q leaked into argv %v", a, calls1[0].Args)
		}
	}

	// 2) Documented LRECON override routes to the fake even with it off PATH.
	rec2 := filepath.Join(tmp, "rec2.jsonl")
	out2 := e04Run(t, shim, target, e04Env(minPath, rec2, "LRECON="+fake))
	if !strings.Contains(out2, e04Poison) {
		t.Fatalf("LRECON override ignored, stdout=%q", out2)
	}
	calls2 := e04Invocations(t, rec2)
	if !e04HasArg(calls2[0].Args, target) {
		t.Fatalf("LRECON run missing target %q; argv=%v", target, calls2[0].Args)
	}
}

func e04HasArg(args []string, want string) bool {
	for _, a := range args {
		if a == want {
			return true
		}
	}
	return false
}
