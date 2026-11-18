package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScrubOutputFindings(t *testing.T) {
	dir := t.TempDir()
	// Every literal below is assembled at run time so this file never holds a
	// live-looking secret (C24-negative: the golden output has no match bytes).
	secret := "AKIA" + "ABCDEFGHIJKLMNOP"
	pem := "-----BEGIN " + "RSA PRIVATE KEY-----"
	body := "before " + secret + " middle " + pem + " after\n"
	path := filepath.Join(dir, "a.txt")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := runScrubOutput(path)
	if err != nil {
		t.Fatal(err)
	}
	got := res.(scrubResult)
	if got.Scrubbed != 2 || got.Clean {
		t.Fatalf("scrubbed = %d clean = %v, want 2 findings: %+v", got.Scrubbed, got.Clean, got.Findings)
	}
	if got.Findings[0].Pattern != "aws-akia" || got.Findings[0].Length != len(secret) {
		t.Fatalf("first finding = %+v", got.Findings[0])
	}
	if got.Findings[1].Pattern != "pem-private-key" {
		t.Fatalf("second finding = %+v", got.Findings[1])
	}
	// The answer must not quote the match: offset, pattern id, length only.
	b, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	for _, leaked := range []string{secret, pem} {
		if strings.Contains(string(b), leaked) {
			t.Fatalf("scrub result leaks the match: %s", b)
		}
	}
}

func TestScrubOutputClean(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "clean.txt")
	if err := os.WriteFile(path, []byte("plain prose with no token in it\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := runScrubOutput(path)
	if err != nil {
		t.Fatal(err)
	}
	got := res.(scrubResult)
	if !got.Clean || got.Scrubbed != 0 || len(got.Findings) != 0 {
		t.Fatalf("clean file = %+v, want scrubbed:0 clean:true", got)
	}
}

func TestScrubOutputEntropyGate(t *testing.T) {
	// 40+ printable non-space bytes at random, no known prefix: only the
	// entropy gate can catch it.
	token := "Zx9Qw2Lm7Vb4Nt8Kp3Rc6Yd1Hf5Jg0SaEwUoPiTl"
	res := scrubBytes([]byte("token=" + token + "\n"))
	if res.Scrubbed != 1 || res.Findings[0].Pattern != "entropy-40" {
		t.Fatalf("entropy finding = %+v", res.Findings)
	}
	// The same length of low-entropy text is not a token.
	if r := scrubBytes([]byte(strings.Repeat("a", 64) + "\n")); r.Scrubbed != 0 {
		t.Fatalf("low-entropy run reported: %+v", r.Findings)
	}
}

func TestScrubOutputNeedsArg(t *testing.T) {
	if _, err := runScrubOutput(""); err == nil {
		t.Fatal("empty argument: want a needs-argument error")
	}
	if label := opNeedsExtra["scrub_output"]; label != "arg" {
		t.Fatalf("opNeedsExtra[scrub_output] = %q, want arg", label)
	}
}
