package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// TestTur7Bucket24ScrubSanitise takes the hygiene angle the other scrub tests do
// not: the target itself is hostile. Its name and its bytes carry a live-looking
// token, a home-directory absolute path, ANSI escapes and multibyte UTF-8, and
// the answer must still be offsets into the raw bytes — stable across two runs,
// carrying no byte of the target — while the refusal path keeps its typed
// envelope and leaves the escaping to encoding/json.
func TestTur7Bucket24ScrubSanitise(t *testing.T) {
	// Assembled at run time so this file never holds a live-looking secret.
	secret := "AKIA" + "ABCDEFGHIJKLMNOP"
	token := "Zx9Qw2Lm7Vb4Nt8Kp3Rc6Yd1Hf5Jg0SaEwUoPiTl"
	home := "/Users/" + "someone/.aws/credentials"
	content := []byte("\x1b[2K\r" + home + " unicode=\u79d8\u5bc6 key=" + secret + " token=" + token + "\n")

	// The file name repeats the hostile bytes: an answer that echoes the path
	// leaks them without ever reading the file.
	dir := t.TempDir()
	name := secret + "-\x1b[31m" + "red\x1b[0m.txt"
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := runScrubOutput(path)
	if err != nil {
		t.Fatal(err)
	}
	got := res.(scrubResult)

	// Byte offsets are computed from the raw content, independently of the
	// scanner: the UTF-8 and the escape bytes before the token must not shift
	// them, and the entropy run keeps its "token=" prefix.
	want := []scrubFinding{
		{Offset: bytes.Index(content, []byte(secret)), Pattern: "aws-akia", Length: len(secret)},
		{Offset: bytes.Index(content, []byte("token="+token)), Pattern: "entropy-40", Length: len("token=" + token)},
	}
	if !reflect.DeepEqual(got.Findings, want) {
		t.Fatalf("findings = %+v, want %+v", got.Findings, want)
	}
	if got.Scrubbed != len(want) || got.Clean {
		t.Fatalf("scrubbed=%d clean=%v, want %d findings", got.Scrubbed, got.Clean, len(want))
	}

	b, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	// No byte of the target reaches the answer: not the secret, not the token,
	// not the caller's home path, not the temp dir, not the escaped name — and
	// no escape byte in raw or JSON-escaped form.
	for _, leaked := range []string{secret, token, home, dir, name, "\x1b", `\u001b`, "\r", `\r`} {
		if strings.Contains(string(b), leaked) {
			t.Fatalf("scrub result leaks target bytes %q: %s", leaked, b)
		}
	}

	again, err := runScrubOutput(path)
	if err != nil {
		t.Fatal(err)
	}
	b2, err := json.Marshal(again)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b, b2) {
		t.Fatalf("non-deterministic:\n%s\n%s", b, b2)
	}

	// The same bytes under a different name must answer identically: nothing
	// derived from the path may reach the structured result.
	plain := filepath.Join(t.TempDir(), "plain.txt")
	if err := os.WriteFile(plain, content, 0o644); err != nil {
		t.Fatal(err)
	}
	other, err := runScrubOutput(plain)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(other, again) {
		t.Fatalf("path changed the result: %+v vs %+v", other, again)
	}

	// Refusal half: the live-session op must answer with a typed envelope even
	// when the target name is a token plus escapes, and the free-text reason
	// must carry none of it. encoding/json escapes the control bytes in the
	// echoed target, so the raw stream stays one line — scrub_output then finds
	// exactly the caller's own token, which is the point of the field.
	bin := filepath.Join(t.TempDir(), "lrecon")
	build := exec.Command("go", "build", "-o", bin, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	cmd := exec.Command(bin, "--op", "resume_frida_session", "--json", path)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err = cmd.Run()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 2 {
		t.Fatalf("refusal exit = %v, want 2; stdout=%q stderr=%q", err, stdout.String(), stderr.String())
	}
	var e struct {
		Kind   string `json:"kind"`
		Error  string `json:"error"`
		Target string `json:"target"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &e); err != nil {
		t.Fatalf("parse refusal %q: %v", stdout.String(), err)
	}
	if e.Kind != string(kindOutOfScope) {
		t.Fatalf("kind = %q, want %q; err=%q", e.Kind, kindOutOfScope, e.Error)
	}
	if e.Target != path {
		t.Fatalf("target field = %q, want the caller's path verbatim", e.Target)
	}
	if strings.ContainsAny(stdout.String(), "\x1b\r") {
		t.Fatalf("raw escape byte on the wire: %q", stdout.String())
	}
	for _, leaked := range []string{secret, home, "\x1b"} {
		if strings.Contains(e.Error, leaked) {
			t.Fatalf("refusal reason leaks %q: %q", leaked, e.Error)
		}
	}
	refusal := filepath.Join(t.TempDir(), "refusal.json")
	if err := os.WriteFile(refusal, stdout.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	rres, err := runScrubOutput(refusal)
	if err != nil {
		t.Fatal(err)
	}
	rf := rres.(scrubResult)
	wantRefusal := scrubFinding{Offset: bytes.Index(stdout.Bytes(), []byte(secret)), Pattern: "aws-akia", Length: len(secret)}
	if rf.Scrubbed != 1 || !reflect.DeepEqual(rf.Findings, []scrubFinding{wantRefusal}) {
		t.Fatalf("refusal scan = %+v, want exactly %+v", rf.Findings, wantRefusal)
	}
}
