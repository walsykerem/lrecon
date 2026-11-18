package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

// TestTextEndsWithEvidence pins the attestation pointer: last line, sha256
// prefix, 64 hex digits, and the value is the hash of the canonical JSON, not of
// the text that carries it (which would depend on the budget).
func TestTextEndsWithEvidence(t *testing.T) {
	d, err := Probe(writeTemp(t, "chunk.luac", lua51()))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	out := digestText(d, 4096)
	if len(out) > 4096 {
		t.Fatalf("digestText is %d bytes, budget is 4096", len(out))
	}
	if !strings.HasSuffix(out, "\n") {
		t.Fatalf("output does not end in a newline: %q", out)
	}
	last := out[strings.LastIndex(out[:len(out)-1], "\n")+1:]
	if !strings.HasPrefix(last, "evidence: sha256:") {
		t.Fatalf("last line is %q, want evidence pointer", last)
	}
	hexPart := strings.TrimSuffix(strings.TrimPrefix(last, "evidence: sha256:"), "\n")
	if len(hexPart) != 64 {
		t.Fatalf("evidence digest is %d hex chars, want 64: %q", len(hexPart), hexPart)
	}
	if _, err := hex.DecodeString(hexPart); err != nil {
		t.Fatalf("evidence digest is not hex: %v", err)
	}
	c, err := canonicalJSON(d)
	if err != nil {
		t.Fatalf("canonicalJSON: %v", err)
	}
	sum := sha256.Sum256(c)
	if got := hex.EncodeToString(sum[:]); got != hexPart {
		t.Fatalf("evidence = %s, want sha256 of canonical JSON = %s", hexPart, got)
	}
	// Canonical form: sorted keys, no indentation.
	if !bytes.HasPrefix(c, []byte(`{"asar_files":`)) {
		t.Fatalf("canonical JSON is not key-sorted: %.60s", c)
	}
	if bytes.Contains(c, []byte("\n")) {
		t.Fatalf("canonical JSON carries a newline: %.60q", c)
	}
}

// TestEvidenceStableAcrossDirectories copies the same bytes into two temp dirs:
// the pointer names the document, and Path is outside the contract, so where the
// file lives cannot move the hash.
func TestEvidenceStableAcrossDirectories(t *testing.T) {
	a, err := Probe(writeTemp(t, "same.bin", lua51()))
	if err != nil {
		t.Fatalf("Probe a: %v", err)
	}
	b, err := Probe(writeTemp(t, "same.bin", lua51()))
	if err != nil {
		t.Fatalf("Probe b: %v", err)
	}
	if a.Path == b.Path {
		t.Fatalf("fixtures landed in the same directory: %s", a.Path)
	}
	ea, err := evidenceLine(a)
	if err != nil {
		t.Fatalf("evidence a: %v", err)
	}
	eb, err := evidenceLine(b)
	if err != nil {
		t.Fatalf("evidence b: %v", err)
	}
	if ea != eb {
		t.Fatalf("evidence moved with the directory:\n%s%s", ea, eb)
	}
}

// TestEvidenceSurvivesTruncation: a cut body must still end with the whole
// pointer, otherwise the reader loses the only way to verify what it was given.
func TestEvidenceSurvivesTruncation(t *testing.T) {
	d, err := Probe(writeTemp(t, "big.luac", lua51()))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	d.Notes = make([]string, 200)
	for i := range d.Notes {
		d.Notes[i] = "note that makes the text overflow the small budget"
	}
	ev, err := evidenceLine(d)
	if err != nil {
		t.Fatalf("evidenceLine: %v", err)
	}
	out := digestText(d, 512)
	if !strings.HasSuffix(out, ev) {
		t.Fatalf("truncation cut the evidence line:\n%s", out[len(out)-120:])
	}
	if !strings.Contains(out, "note: truncated at ") {
		t.Fatalf("truncated output carries no truncation note:\n%s", out)
	}
	if len(out) > 512 {
		t.Fatalf("truncated output is %d bytes, budget is 512", len(out))
	}
}

// TestExplain prints the attribution behind one field: claim, offset and rule
// sha, plus the refusal reason when the field could not be produced.
func TestExplain(t *testing.T) {
	target := writeTemp(t, "chunk.luac", lua51())
	out, code := runCLI(t, "--explain", "toolchain", target)
	if code != 0 {
		t.Fatalf("exit %d, want 0; output:\n%s", code, out)
	}
	for _, want := range []string{"field: toolchain", "claim: lua 5.1 (luac-header @0x0)", "rule_id: luac-header", "rule_sha: sha256:"} {
		if !strings.Contains(out, want) {
			t.Fatalf("explanation lacks %q:\n%s", want, out)
		}
	}

	cut := writeTemp(t, "cut.luac", lua51()[:5])
	out, code = runCLI(t, "--explain", "lua", cut)
	if code != 0 {
		t.Fatalf("reason explain exit %d, want 0; output:\n%s", code, out)
	}
	if !strings.Contains(out, "reason: lua-truncated:") {
		t.Fatalf("explanation lacks the refusal reason:\n%s", out)
	}

	out, code = runCLI(t, "--explain", "no-such-field", target)
	if code != 2 {
		t.Fatalf("unknown field exit %d, want 2; output:\n%s", code, out)
	}
	if out != "" {
		t.Fatalf("unknown field wrote stdout:\n%s", out)
	}
}

// TestRuleShaStable: the rule digest covers the rule identity, never a byte
// offset, so two runs and two builds agree.
func TestRuleShaStable(t *testing.T) {
	a, b := ruleSHA("luac-header"), ruleSHA("luac-header")
	if a != b {
		t.Fatalf("rule_sha unstable: %s vs %s", a, b)
	}
	if a == ruleSHA("lua-truncated") {
		t.Fatal("different rules share one rule_sha")
	}
	if !strings.HasPrefix(a, "sha256:") || len(a) != len("sha256:")+64 {
		t.Fatalf("rule_sha = %q, want sha256:<64 hex>", a)
	}
	target := writeTemp(t, "chunk.luac", lua51())
	one, code := runCLI(t, "--explain", "toolchain", target)
	if code != 0 {
		t.Fatalf("exit %d, want 0", code)
	}
	two, _ := runCLI(t, "--explain", "toolchain", target)
	if one != two {
		t.Fatalf("explanation changed between runs:\n%s\n%s", one, two)
	}
}

// TestEvidenceIsNotSelfReferential guards the documented falsifier: hashing
// Text() would make the pointer move with the budget and never match --json.
func TestEvidenceIsNotSelfReferential(t *testing.T) {
	d, err := Probe(writeTemp(t, "chunk.luac", lua51()))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	full := digestText(d, 0)
	small := digestText(d, 512)
	fullEv := full[strings.LastIndex(strings.TrimSuffix(full, "\n"), "\n")+1:]
	smallEv := small[strings.LastIndex(strings.TrimSuffix(small, "\n"), "\n")+1:]
	if fullEv != smallEv {
		t.Fatalf("evidence followed the budget: %q vs %q", fullEv, smallEv)
	}
	raw, err := json.Marshal(d)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	sum := sha256.Sum256(raw)
	if strings.Contains(full, hex.EncodeToString(sum[:])) {
		t.Fatal("evidence is sha256 of json.Marshal output, want canonical JSON")
	}
}
