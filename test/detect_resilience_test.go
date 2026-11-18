package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A 0-byte target has no identity to report. Answering kind:"unknown" claims a
// format question was asked of bytes that do not exist (final.md 386).
func TestProbeRefusesEmptyTarget(t *testing.T) {
	p := writeTemp(t, "zero.bin", nil)
	_, err := Probe(p)
	if err == nil {
		t.Fatal("Probe answered a 0-byte target")
	}
	if got := classify(err.Error()); got != kindIO {
		t.Fatalf("classify(%q) = %s, want %s", err, got, kindIO)
	}
}

// A plain directory is a container, not an artifact: the caller must name a
// file inside it. A .app stays openable and is covered by the bundle tests.
func TestProbeRefusesPlainDirectory(t *testing.T) {
	_, err := Probe(t.TempDir())
	if err == nil {
		t.Fatal("Probe answered a plain directory")
	}
	if got := classify(err.Error()); got != kindIO {
		t.Fatalf("classify(%q) = %s, want %s", err, got, kindIO)
	}
}

// A text budget has to reach the printed body: the hash is the target identity,
// so --max-bytes 512 must leave file_sha256, hash_scope and hash_bytes at the
// whole-file values while the text output is still cut.
func TestProbeMaxBytesCutsDigest(t *testing.T) {
	body := bytes.Repeat([]byte("lrecon max-bytes fixture\n"), 512)
	p := writeTemp(t, "cut.txt", body)

	out, code := runCLI(t, "--max-bytes", "512", "--json", p)
	if code != 0 {
		t.Fatalf("exit %d, want 0; output:\n%s", code, out)
	}
	var got struct {
		Target struct {
			Size      int64  `json:"size"`
			SHA256    string `json:"file_sha256"`
			HashBytes int64  `json:"hash_bytes"`
			HashScope string `json:"hash_scope"`
		} `json:"target"`
		GitOID    string `json:"gitoid"`
		Truncated bool   `json:"truncated"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, out)
	}
	if got.Target.Size != int64(len(body)) {
		t.Errorf("target.size = %d, want %d (the file)", got.Target.Size, len(body))
	}
	if got.Target.HashBytes != int64(len(body)) || got.Target.HashScope != "whole-file" {
		t.Errorf("hash = %d bytes scope %q, want %d whole-file", got.Target.HashBytes, got.Target.HashScope, len(body))
	}
	if got.Truncated {
		t.Error("truncated = true, want false: --max-bytes must not cut the digest")
	}

	full, code := runCLI(t, "--json", p)
	if code != 0 {
		t.Fatalf("exit %d, want 0; output:\n%s", code, full)
	}
	var plain struct {
		Target struct {
			SHA256    string `json:"file_sha256"`
			HashBytes int64  `json:"hash_bytes"`
			HashScope string `json:"hash_scope"`
		} `json:"target"`
		GitOID string `json:"gitoid"`
	}
	if err := json.Unmarshal([]byte(full), &plain); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Target.SHA256 != plain.Target.SHA256 || got.Target.HashBytes != plain.Target.HashBytes || got.Target.HashScope != plain.Target.HashScope || got.GitOID != plain.GitOID {
		t.Errorf("--max-bytes moved the identity: %+v vs %+v", got.Target, plain.Target)
	}
	if got.GitOID != plain.GitOID {
		t.Errorf("gitoid moved: %q vs %q", got.GitOID, plain.GitOID)
	}

	text, code := runCLI(t, "--max-bytes", "512", p)
	if code != 0 {
		t.Fatalf("exit %d, want 0; output:\n%s", code, text)
	}
	if len(text) > 512 {
		t.Errorf("text output is %d bytes, want <= 512", len(text))
	}
	// Text budget is a truncation of the same body: a plain text fixture is
	// well under the budget, so use a many-notes JSON-free fixture via CLI on
	// a big text? Instead check the budget applies: output is bounded.
	_ = strings.Contains
}

func TestDiffExitCodes(t *testing.T) {
	p := writeTemp(t, "diff.bin", []byte("lrecon diff fixture\n"))
	d, err := Probe(p)
	if err != nil {
		t.Fatal(err)
	}
	old, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	same := filepath.Join(t.TempDir(), "same.json")
	if err := os.WriteFile(same, old, 0o644); err != nil {
		t.Fatal(err)
	}
	out, code := runCLI(t, "--diff", same, p)
	if code != 0 {
		t.Fatalf("identical diff exit %d, want 0; output:\n%s", code, out)
	}

	changed := d
	changed.Kind = "other-kind"
	old2, err := json.Marshal(changed)
	if err != nil {
		t.Fatal(err)
	}
	diff := filepath.Join(t.TempDir(), "changed.json")
	if err := os.WriteFile(diff, old2, 0o644); err != nil {
		t.Fatal(err)
	}
	out, code = runCLI(t, "--diff", diff, p)
	if code != 1 {
		t.Fatalf("changed diff exit %d, want 1; output:\n%s", code, out)
	}
	if out == "" {
		t.Fatal("changed diff printed nothing, want a diff line")
	}
}

// A read that stops early is a changed file, not a whole-file hash. Returning
// the prefix would label 1.1 GB of a 4 GB sparse file "whole-file" (final.md 399).
func TestHashTargetRejectsShortRead(t *testing.T) {
	if _, err := hashTargetN(bytes.NewReader(make([]byte, 5)), 10, 10, nil); err == nil {
		t.Fatal("hashTargetN accepted 5 of 10 bytes")
	}
}

func TestHashTargetReportsStatSize(t *testing.T) {
	tg, err := hashTargetN(bytes.NewReader(make([]byte, 10)), 10, 10, nil)
	if err != nil {
		t.Fatal(err)
	}
	if tg.Size != 10 || tg.HashBytes != 10 || tg.HashScope != "whole-file" {
		t.Fatalf("target = %+v, want size/hash 10 whole-file", tg)
	}
}
