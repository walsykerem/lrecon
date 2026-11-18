package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

var (
	cliPath  string
	buildErr error
	buildLog string
)

// fileDigest identifies a file's bytes, or "" when it cannot be read.
func fileDigest(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

func TestMain(m *testing.M) {
	pkgDir, _ := os.Getwd()
	before, _ := os.ReadDir(pkgDir)
	binary := filepath.Join(pkgDir, "lrecon")
	binaryBefore := fileDigest(binary)
	dir, err := os.MkdirTemp("", "lrecon-cli-")
	if err != nil {
		buildErr = err
	} else {
		cliPath = filepath.Join(dir, "lrecon")
		cmd := exec.Command("go", "build", "-o", cliPath, ".")
		var out bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &out
		buildErr = cmd.Run()
		buildLog = out.String()
	}
	code := m.Run()
	// A test that writes into the checkout breaks the tracked binary and leaves
	// debris behind; fail the suite instead of silently dirtying the repo.
	if after, err := os.ReadDir(pkgDir); err == nil {
		seen := make(map[string]bool, len(before))
		for _, e := range before {
			seen[e.Name()] = true
		}
		for _, e := range after {
			if !seen[e.Name()] {
				fmt.Fprintf(os.Stderr, "test wrote %s inside the repo tree; use t.TempDir()\n", filepath.Join(pkgDir, e.Name()))
				code = 1
			}
		}
	}
	if now := fileDigest(binary); now != "" && binaryBefore != "" && now != binaryBefore {
		fmt.Fprintln(os.Stderr, "test rewrote the tracked lrecon binary; build into t.TempDir()")
		code = 1
	}
	if dir != "" {
		os.RemoveAll(dir)
	}
	os.Exit(code)
}

// runCLI runs the built binary and returns stdout plus the exit code.
func runCLI(t *testing.T, args ...string) (string, int) {
	t.Helper()
	stdout, _, code := runCLIAll(t, args...)
	return stdout, code
}

// runCLIAll runs the built binary and returns stdout, stderr and the exit code.
func runCLIAll(t *testing.T, args ...string) (string, string, int) {
	t.Helper()
	if buildErr != nil {
		t.Fatalf("go build failed: %v\n%s", buildErr, buildLog)
	}
	if cliPath == "" {
		t.Fatal("cli binary was not built")
	}
	cmd := exec.Command(cliPath, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	code := 0
	if err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("run %v: %v", args, err)
		}
		code = exitErr.ExitCode()
	}
	return stdout.String(), stderr.String(), code
}

func TestCLIJSONOutput(t *testing.T) {
	target := writeTemp(t, "plain.txt", []byte("hello lrecon\n"))
	out, code := runCLI(t, "--json", target)
	if code != 0 {
		t.Fatalf("exit %d, want 0; output:\n%s", code, out)
	}
	var d Digest
	if err := json.Unmarshal([]byte(out), &d); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, out)
	}
	if d.Kind != "text" {
		t.Fatalf("kind = %q, want text", d.Kind)
	}
	if d.ContractVersion != contractVersion {
		t.Fatalf("contract_version = %d, want %d", d.ContractVersion, contractVersion)
	}
	if d.Target.HashScope != "whole-file" || d.Target.HashBytes != int64(len("hello lrecon\n")) {
		t.Fatalf("target = %+v, want the whole file hashed", d.Target)
	}
	if len(d.Target.FileSHA256) != 64 || !strings.HasPrefix(d.Target.GitOID, "gitoid:blob:sha1:") {
		t.Fatalf("target hashes missing: %+v", d.Target)
	}
}

// The same input must produce the same bytes twice, even from another directory:
// a digest that moves with cwd cannot be compared or cached.
func TestCLIJSONDeterministic(t *testing.T) {
	target := writeTemp(t, "det.txt", []byte("deterministic\n"))
	first, code := runCLI(t, "--json", target)
	if code != 0 {
		t.Fatalf("exit %d, want 0; output:\n%s", code, first)
	}
	second, code := runCLI(t, "--json", target)
	if code != 0 {
		t.Fatalf("second exit %d, want 0", code)
	}
	if first != second {
		t.Fatalf("two runs differ:\n%s\n%s", first, second)
	}
	copied := writeTemp(t, "det-copy.txt", []byte("deterministic\n"))
	other, code := runCLI(t, "--json", copied)
	if code != 0 {
		t.Fatalf("copy exit %d, want 0", code)
	}
	if first != other {
		t.Fatalf("same bytes under another path produce another digest:\n%s\n%s", first, other)
	}
}

// The default budget is 4096 bytes; a digest larger than that must still emit
// complete JSON, or every `--json` consumer breaks on real binaries.
func TestCLIJSONNotTruncated(t *testing.T) {
	// A Go binary with a real dependency list is the cheapest target whose
	// digest JSON clears 4096 bytes on every host: the fixture is cross-built
	// with GOOS=darwin, so the answer does not depend on where the test runs.
	out, code := runCLI(t, "--json", goFixtureDeps(t, 120))
	if code != 0 {
		t.Fatalf("exit %d, want 0", code)
	}
	if len(out) <= 4096 {
		t.Fatalf("digest only %d bytes, too small to prove truncation", len(out))
	}
	var d Digest
	if err := json.Unmarshal([]byte(out), &d); err != nil {
		t.Fatalf("truncated JSON at default budget: %v", err)
	}
}

func TestCLINoArgsExitsNonZero(t *testing.T) {
	_, code := runCLI(t)
	if code == 0 {
		t.Fatal("exit 0 with no target, want non-zero")
	}
}

func TestCLIMaxBytes(t *testing.T) {
	out, code := runCLI(t, "--max-bytes", "40", cliPath)
	if code != 0 {
		t.Fatalf("exit %d, want 0; output:\n%s", code, out)
	}
	if out == "" {
		t.Fatal("empty output")
	}
	if !strings.HasSuffix(out, "\n") {
		t.Fatalf("output does not end with a whole line:\n%q", out)
	}
	// The body honours the budget; the truncation note is added on top on purpose.
	body := out
	if before, _, ok := strings.Cut(out, "note: truncated at "); ok {
		body = before
	}
	if len(body) > 40 {
		t.Fatalf("body %d bytes, --max-bytes 40 ignored:\n%q", len(body), body)
	}
}

// One whole JSON on stdout is the contract: --max-bytes must not cut it.
func TestCLIMaxBytesNeverCutsJSON(t *testing.T) {
	out, code := runCLI(t, "--json", "--max-bytes", "40", cliPath)
	if code != 0 {
		t.Fatalf("exit %d, want 0; output:\n%s", code, out)
	}
	var v map[string]any
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		t.Fatalf("--json --max-bytes 40 is not parseable JSON: %v\n%q", err, out)
	}
	if v["kind"] == nil {
		t.Fatalf("digest lost its kind: %q", out)
	}
}

// Two targets in one call used to print one digest and exit 0 — a dropped target
// that looks like success. It must refuse instead.
func TestCLIMultipleTargetsExit2(t *testing.T) {
	a := writeTemp(t, "a.txt", []byte("a\n"))
	b := writeTemp(t, "b.txt", []byte("b\n"))
	out, code := runCLI(t, a, b)
	if code != 2 {
		t.Fatalf("exit %d, want 2; output:\n%s", code, out)
	}
	if out != "" && !strings.Contains(out, `"kind"`) {
		t.Fatalf("wrote a digest for a multi-target call:\n%s", out)
	}
}

// --diff OLD must accept a saved --json digest: sniffing it as text produced
// "kind text -> macho" instead of comparing fields. A difference exits 1
// (diffoscope semantics); exit 2 is reserved for "could not answer".
func TestCLIDiffSavedJSON(t *testing.T) {
	saved := writeTemp(t, "old.json", []byte(`{"contract_version":1,"Kind":"macho","Format":"fat","Slices":2}`))
	target := writeTemp(t, "new.txt", []byte("hello\n"))
	out, code := runCLI(t, "--diff", saved, target)
	if code != 1 {
		t.Fatalf("exit %d, want 1 (a difference is a result); output:\n%s", code, out)
	}
	if !strings.Contains(out, "kind macho -> text") {
		t.Fatalf("saved digest not used as the baseline:\n%s", out)
	}
}

// Exit 2 means lrecon could not answer, so stdout carries one complete envelope
// and stderr the same reason behind the lrecon: prefix, in both modes: a caller
// never has to special-case the mode it asked for. A partial document reads as
// a digest to anything that ignores the exit code.
func TestCLIExit2OneEnvelope(t *testing.T) {
	saved := writeTemp(t, "old.json", []byte(`{"Kind":"macho"}`))
	target := writeTemp(t, "new.txt", []byte("hello\n"))
	if os.Geteuid() == 0 {
		t.Skip("root reads a 0o000 file, so it is not an unreadable path")
	}
	unreadable := writeTemp(t, "secret.bin", []byte("x"))
	if err := os.Chmod(unreadable, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(unreadable, 0o600) })
	cases := []struct {
		name string
		args []string
		json bool
	}{
		{"unreadable path", []string{unreadable}, false},
		{"json plus diff", []string{"--json", "--diff", saved, target}, true},
		{"unknown flag", []string{"--nope", target}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			stdout, stderr, code := runCLIAll(t, c.args...)
			if code != 2 {
				t.Fatalf("exit %d, want 2; stderr:\n%s", code, stderr)
			}
			if !strings.Contains(stderr, "lrecon: ") {
				t.Fatalf("stderr = %q, want the lrecon: prefix", stderr)
			}
			if !c.json {
				// Item 70: the stdout envelope is a --json / --op promise. Plain
				// text mode answers on stderr, and exit 2 means there is no digest.
				if stdout != "" {
					t.Fatalf("text mode wrote stdout:\n%s", stdout)
				}
				return
			}
			var env struct {
				Error string `json:"error"`
				Kind  string `json:"kind"`
			}
			if err := json.Unmarshal([]byte(stdout), &env); err != nil {
				t.Fatalf("stdout is not one envelope: %v\n%s", err, stdout)
			}
			switch env.Kind {
			case "bad_arg", "usage", "io":
			default:
				t.Fatalf("kind = %q, want a refusal kind: %s", env.Kind, stdout)
			}
		})
	}
}

// A real .app is Universal; formatting it as "app" made every Mach-O open fail.
func TestCLIAppBundleFat(t *testing.T) {
	ls, err := os.ReadFile(lsPath)
	if err != nil {
		t.Skipf("no fat fixture: %v", err)
	}
	root := t.TempDir()
	exe := filepath.Join(root, "Test.app", "Contents", "MacOS", "Test")
	if err := os.MkdirAll(filepath.Dir(exe), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(exe, ls, 0o755); err != nil {
		t.Fatal(err)
	}
	out, code := runCLI(t, "--json", filepath.Join(root, "Test.app"))
	if code != 0 {
		t.Fatalf("exit %d, want 0; output:\n%s", code, out)
	}
	var d Digest
	if err := json.Unmarshal([]byte(out), &d); err != nil {
		t.Fatalf("bad JSON: %v\n%s", err, out)
	}
	if d.Kind != "macho" || d.Format != "fat" {
		t.Fatalf("kind/format = %q/%q, want macho/fat", d.Kind, d.Format)
	}
	if d.Slices != 2 {
		t.Fatalf("slices = %d, want 2", d.Slices)
	}
	for _, n := range d.Notes {
		if strings.Contains(n, "invalid magic") {
			t.Fatalf("fat bundle misread as a broken file: %v", d.Notes)
		}
	}
}

// A website target is out of scope. It must be declined, not reported as a
// missing local file.
func TestCLIDeclinesWebsiteTarget(t *testing.T) {
	stdout, stderr, code := runCLIAll(t, "https://example.com")
	if code != 2 {
		t.Fatalf("exit %d, want 2; stdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	if !strings.Contains(strings.ToLower(stderr), "website") {
		t.Fatalf("stderr does not mention website:\n%s", stderr)
	}
	if strings.Contains(stderr, "no such file") {
		t.Fatalf("stderr reports a filesystem error for a website target:\n%s", stderr)
	}
	if stdout != "" {
		t.Fatalf("text mode decline wrote stdout:\n%s", stdout)
	}
	if !strings.HasPrefix(stderr, "lrecon: ") {
		t.Fatalf("stderr = %q, want the lrecon: prefix", stderr)
	}
}

// The same decline in --json mode: one JSON object on stdout, exit 2.
func TestCLIDeclinesWebsiteTargetJSON(t *testing.T) {
	stdout, stderr, code := runCLIAll(t, "--json", "https://example.com")
	if code != 2 {
		t.Fatalf("exit %d, want 2; stdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	if !strings.HasPrefix(stderr, "lrecon: ") {
		t.Fatalf("stderr = %q, want the lrecon: prefix", stderr)
	}
	var env struct {
		Error string `json:"error"`
		Kind  string `json:"kind"`
	}
	if err := json.Unmarshal([]byte(stdout), &env); err != nil {
		t.Fatalf("stdout is not one envelope: %v\n%s", err, stdout)
	}
	if env.Kind != "out_of_scope" {
		t.Fatalf("kind = %q, want out_of_scope; envelope: %s", env.Kind, stdout)
	}
	if !strings.Contains(strings.ToLower(env.Error), "website") {
		t.Fatalf("envelope = %q, want a website decline", stdout)
	}
}

// A live process is not a file: the CLI must say so, not open a path.
func TestCLIDeclinesRuntimePID(t *testing.T) {
	_, stderr, code := runCLIAll(t, "--pid", "1234")
	if code != 2 {
		t.Fatalf("exit %d, want 2; stderr:\n%s", code, stderr)
	}
	if !strings.Contains(strings.ToLower(stderr), "runtime") {
		t.Fatalf("stderr does not mention runtime:\n%s", stderr)
	}
}

// The same decline for a pid target written in the target slot.
func TestCLIDeclinesRuntimePIDTarget(t *testing.T) {
	_, stderr, code := runCLIAll(t, "pid:1234")
	if code != 2 {
		t.Fatalf("exit %d, want 2; stderr:\n%s", code, stderr)
	}
	if !strings.Contains(strings.ToLower(stderr), "runtime") {
		t.Fatalf("stderr does not mention runtime:\n%s", stderr)
	}
}

// Declines are narrow: a real local file still gets its digest.
func TestCLIReadsLocalFileTarget(t *testing.T) {
	target := writeTemp(t, "app.sqlite", []byte("SQLite format 3\x00"))
	out, code := runCLI(t, target)
	if code != 0 {
		t.Fatalf("exit %d, want 0; output:\n%s", code, out)
	}
	if !strings.Contains(out, "kind: sqlite") {
		t.Fatalf("no digest for a local file:\n%s", out)
	}
}

// -o names a directory: each call writes its own digest file there and a
// second call gets a non-colliding name instead of overwriting the first.
func TestCLIOutputDirectory(t *testing.T) {
	target := writeTemp(t, "out.txt", []byte("hello lrecon\n"))
	dir := t.TempDir()
	for i := range 2 {
		stdout, stderr, code := runCLIAll(t, "-o", dir, target)
		if code != 0 {
			t.Fatalf("call %d exit %d, want 0; stderr:\n%s", i+1, code, stderr)
		}
		if stdout != "" {
			t.Fatalf("call %d stdout not empty with -o dir:\n%s", i+1, stdout)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read -o dir: %v", err)
	}
	if len(entries) != 2 || entries[0].Name() == entries[1].Name() {
		t.Fatalf("-o dir entries = %v, want two distinct digest files", entries)
	}
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		var d Digest
		if err := json.Unmarshal(b, &d); err != nil {
			t.Fatalf("%s is not valid JSON: %v", e.Name(), err)
		}
		if d.Kind != "text" {
			t.Fatalf("%s kind = %q, want text", e.Name(), d.Kind)
		}
	}
}

// -o writes the JSON document to a file and keeps stdout empty, so a digest
// can be saved for --diff without shell redirection.
func TestCLIOutputFile(t *testing.T) {
	target := writeTemp(t, "out.txt", []byte("hello lrecon\n"))
	dest := filepath.Join(t.TempDir(), "digest.json")
	stdout, stderr, code := runCLIAll(t, "-o", dest, target)
	if code != 0 {
		t.Fatalf("exit %d, want 0; stderr:\n%s", code, stderr)
	}
	if stdout != "" {
		t.Fatalf("stdout not empty with -o:\n%s", stdout)
	}
	b, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("read -o file: %v", err)
	}
	var d Digest
	if err := json.Unmarshal(b, &d); err != nil {
		t.Fatalf("-o file is not valid JSON: %v", err)
	}
	if d.Kind != "text" {
		t.Fatalf("kind = %q, want text", d.Kind)
	}
}

// --deep with a name that is not in the symbol table used to print the reason
// and exit 0. Docs promise rc=2 for "could not answer"; a skip that exits 0
// passes a sweep as success.
func TestCLIDeepUnknownSymbolExit2(t *testing.T) {
	if _, err := os.Stat(lsPath); err != nil {
		t.Skipf("no fat fixture: %v", err)
	}
	stdout, stderr, code := runCLIAll(t, "--deep", "nosuchsym", lsPath)
	if code != 2 {
		t.Fatalf("exit %d, want 2; stderr:\n%s", code, stderr)
	}
	if !strings.Contains(stderr, "no symbol table entry") {
		t.Fatalf("stderr = %q, want the spelling message", stderr)
	}
	// A named mode answers on stdout: a refusal with an empty stdout leaves
	// the caller with rc=2 and no machine-readable reason.
	var env struct {
		Op    *string `json:"op"`
		Error string  `json:"error"`
		Kind  string  `json:"kind"`
	}
	if err := json.Unmarshal([]byte(stdout), &env); err != nil {
		t.Fatalf("stdout is not one envelope: %v\n%s", err, stdout)
	}
	if env.Op == nil || *env.Op != "deep" {
		t.Fatalf("envelope op = %v, want deep; envelope: %s", env.Op, stdout)
	}
	if env.Error == "" || env.Kind == "" {
		t.Fatalf("envelope is missing error or kind: %s", stdout)
	}
}

// A flag value that names a path must not be taken for the positional target:
// extracting positionals by text ate --diff's operand and reported needs_arg
// instead of the flag conflict.
func TestCLIDiffFlagValueNotTarget(t *testing.T) {
	if _, err := os.Stat(lsPath); err != nil {
		t.Skipf("no fat fixture: %v", err)
	}
	stdout, stderr, code := runCLIAll(t, "--diff", lsPath, "--json", lsPath)
	if code != 2 {
		t.Fatalf("exit %d, want 2; stderr:\n%s", code, stderr)
	}
	var env struct {
		Error string `json:"error"`
		Kind  string `json:"kind"`
	}
	if err := json.Unmarshal([]byte(stdout), &env); err != nil {
		t.Fatalf("stdout is not one envelope: %v\n%s", err, stdout)
	}
	if env.Kind != "usage" {
		t.Fatalf("kind = %q, want usage; envelope: %s", env.Kind, stdout)
	}
	if !strings.Contains(env.Error, "cannot be combined") {
		t.Fatalf("envelope does not name the flag conflict: %s", stdout)
	}
}

// A JSON body that fails to decode was silently replaced by a fresh probe, so
// a corrupt baseline answered for the file's bytes and could read as "no
// differences". It must refuse instead.
func TestCLIDiffCorruptSavedDigest(t *testing.T) {
	saved := writeTemp(t, "old.json", []byte(`{"contract_version":1,"kind":`))
	target := writeTemp(t, "new.txt", []byte("hello\n"))
	stdout, stderr, code := runCLIAll(t, "--diff", saved, target)
	if code != 2 {
		t.Fatalf("exit %d, want 2; stderr:\n%s", code, stderr)
	}
	if !strings.Contains(stderr, "does not decode") {
		t.Fatalf("stderr = %q, want a decode refusal", stderr)
	}
	if stdout != "" {
		t.Fatalf("text mode wrote stdout:\n%s", stdout)
	}
}

// --ext-op answers go through the same cap as --op: a small answer keeps its
// op/target/result shape, and one over the cap says where it was written
// instead of printing it in-line.
func TestCLIExtOpAnswerCap(t *testing.T) {
	if _, err := exec.LookPath("adb"); err != nil {
		t.Skip("no adb fixture")
	}
	out, code := runCLI(t, "--ext-op", "adb_disconnect")
	if code != 0 {
		t.Fatalf("exit %d, want 0; output:\n%s", code, out)
	}
	var small map[string]any
	if err := json.Unmarshal([]byte(out), &small); err != nil {
		t.Fatalf("stdout is not one answer: %v\n%s", err, out)
	}
	if _, spilled := small["written_to"]; spilled {
		t.Fatalf("small answer was spilled:\n%s", out)
	}
	if small["op"] != "adb_disconnect" {
		t.Fatalf("op = %v, want adb_disconnect: %s", small["op"], out)
	}
	if _, ok := small["result"]; !ok {
		t.Fatalf("answer lost its result: %s", out)
	}

	t.Setenv("LRECON_ANSWER_CAP_BYTES", "64")
	out, code = runCLI(t, "--ext-op", "adb_disconnect")
	if code != 0 {
		t.Fatalf("capped exit %d, want 0; output:\n%s", code, out)
	}
	var spilled map[string]any
	if err := json.Unmarshal([]byte(out), &spilled); err != nil {
		t.Fatalf("stdout is not one answer: %v\n%s", err, out)
	}
	to, ok := spilled["written_to"].(string)
	if !ok || to == "" {
		t.Fatalf("answer over the cap was not spilled:\n%s", out)
	}
	t.Cleanup(func() { os.Remove(to) })
	if spilled["truncated"] != true {
		t.Fatalf("spilled answer does not say truncated: %s", out)
	}
}
