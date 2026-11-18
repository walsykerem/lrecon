package main

// Tur 7 bucket 27: a verifier is only real if a near-identical twin gets the
// other verdict. Each pair below is one artifact and a copy that differs by a
// single bit (same size, same mtime); the verifier must separate them AND name
// the reason it refused, so a constant "pass" or a constant "fail" both fail
// here.

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

// tur7B27Note reports whether a notes array carries the exact caveat name.
func tur7B27Note(m map[string]any, want string) bool {
	notes, _ := m["notes"].([]any)
	for _, n := range notes {
		if s, _ := n.(string); s == want {
			return true
		}
	}
	return false
}

// tur7B27Sample picks a 16-byte window inside a mapped section, plus a second
// offset in the same section outside that window, so the control twin stays a
// parseable artifact and only the sampled address decides the verdict.
func tur7B27Sample(t *testing.T, path string) (addr string, off, control int64) {
	t.Helper()
	secs, err := metaSectionTable(path)
	if err != nil || len(secs) == 0 {
		t.Fatalf("section table: %v (%d sections)", err, len(secs))
	}
	raw := metaReadFile(t, path)
	for _, s := range secs {
		if s.Size >= 96 && s.Off+96 <= uint64(len(raw)) {
			return fmt.Sprintf("%#x", s.Addr+4), int64(s.Off + 4), int64(s.Off + 64)
		}
	}
	t.Fatalf("fixture has no section with a 96-byte run: the fixture builder changed")
	return "", 0, 0
}

// tur7B27Flip returns a copy with exactly one byte inverted.
func tur7B27Flip(raw []byte, at int64) []byte {
	out := append([]byte(nil), raw...)
	out[at] ^= 0xff
	return out
}

func TestTur7Bucket27VerifierTwins(t *testing.T) {
	metaTestState(t)
	pe := metaManagedPE(t)
	raw := metaReadFile(t, pe)
	addr, off, control := tur7B27Sample(t, pe)
	want := metaHex(raw[off : off+16])

	metaMustRun(t, "record_unknown", metaTestArg(t, map[string]any{
		"file": pe, "address": addr, "hypothesis": "a counter update nobody has named",
	}))
	metaMustRun(t, "update_unknown", metaTestArg(t, map[string]any{
		"address": addr, "resolution": "increments the counter",
	}))

	st, err := os.Stat(pe)
	if err != nil {
		t.Fatal(err)
	}
	twin := writeTemp(t, "twin.exe", tur7B27Flip(raw, off))
	// Same size and same mtime: only the content can tell these apart.
	if err := os.Chtimes(twin, st.ModTime(), st.ModTime()); err != nil {
		t.Fatal(err)
	}
	tb := metaReadFile(t, twin)
	if len(tb) != len(raw) {
		t.Fatalf("twin size %d, source %d", len(tb), len(raw))
	}
	diffs := 0
	for i := range raw {
		if raw[i] != tb[i] {
			diffs++
		}
	}
	if diffs != 1 {
		t.Fatalf("twin differs in %d bytes, want exactly 1", diffs)
	}

	resolution := "increments the counter"
	pass := metaMustRun(t, "verify_unknown_resolution", metaTestArg(t, map[string]any{
		"file": pe, "address": addr, "resolution": resolution,
	}))
	if !metaBool(t, pass, "verified") || !metaBool(t, pass, "bytes_verified") || !metaBool(t, pass, "persisted") {
		t.Fatalf("source artifact did not verify: %v", pass)
	}

	fail := metaMustRun(t, "verify_unknown_resolution", metaTestArg(t, map[string]any{
		"file": twin, "address": addr, "resolution": resolution,
	}))
	if metaBool(t, fail, "verified") || metaBool(t, fail, "bytes_verified") || metaBool(t, fail, "persisted") {
		t.Fatalf("one-bit twin verified: %v", fail)
	}
	if note := metaStr(t, fail, "note"); !strings.Contains(note, "bytes at the address do not match the recorded bytes") {
		t.Fatalf("twin refusal did not name the byte mismatch: %q", note)
	}
	if metaStr(t, fail, "expected") != want || metaStr(t, fail, "actual") == want {
		t.Fatalf("twin bytes not reported honestly: %v", fail)
	}

	// The check is address-local: a flip outside the recorded window still
	// passes, so the refusal above is the byte comparison and not a whole-file
	// hash in disguise.
	controlTwin := writeTemp(t, "control.exe", tur7B27Flip(raw, control))
	outside := metaMustRun(t, "verify_unknown_resolution", metaTestArg(t, map[string]any{
		"file": controlTwin, "address": addr, "resolution": resolution,
	}))
	if !metaBool(t, outside, "verified") || !metaBool(t, outside, "bytes_verified") {
		t.Fatalf("a flip outside the recorded window failed the byte check: %v", outside)
	}
	if metaStr(t, outside, "actual") != want {
		t.Fatalf("control actual = %q, want recorded %q", metaStr(t, outside, "actual"), want)
	}

	sha, err := metaFileSHA256(pe)
	if err != nil {
		t.Fatal(err)
	}
	immPass := metaMustRun(t, "verify_target_immutability", metaTestArg(t, map[string]any{
		"file": pe, "expect": sha,
	}))
	immTwin := metaMustRun(t, "verify_target_immutability", metaTestArg(t, map[string]any{
		"file": twin, "expect": sha,
	}))
	if !metaBool(t, immPass, "match") || metaBool(t, immPass, "mutated") {
		t.Fatalf("source artifact reported mutated: %v", immPass)
	}
	if metaBool(t, immTwin, "match") || !metaBool(t, immTwin, "mutated") {
		t.Fatalf("one-bit twin reported unchanged: %v", immTwin)
	}
	if !tur7B27Note(immTwin, "target-mutated") {
		t.Fatalf("twin lost the target-mutated caveat: %v", immTwin)
	}
	if metaStr(t, immTwin, "target_sha256") == sha {
		t.Fatalf("twin kept the source digest: %v", immTwin)
	}
	if metaNum(t, immTwin, "size") != metaNum(t, immPass, "size") || metaStr(t, immTwin, "mtime") != metaStr(t, immPass, "mtime") {
		t.Fatalf("twin is not stat-identical: pass=%v twin=%v", immPass, immTwin)
	}

	copyPath := writeTemp(t, "copy.exe", raw)
	eqPass := metaMustRun(t, "verify_output_equivalence", metaTestArg(t, map[string]any{
		"old": pe, "new": copyPath,
	}))
	eqTwin := metaMustRun(t, "verify_output_equivalence", metaTestArg(t, map[string]any{
		"old": pe, "new": twin,
	}))
	if !metaBool(t, eqPass, "equivalent") {
		t.Fatalf("byte-identical copy not equivalent: %v", eqPass)
	}
	if metaBool(t, eqTwin, "equivalent") {
		t.Fatalf("one-bit twin reported equivalent: %v", eqTwin)
	}
	if !tur7B27Note(eqTwin, "equivalence-diverged") {
		t.Fatalf("twin lost the equivalence-diverged caveat: %v", eqTwin)
	}
	if metaStr(t, eqTwin, "original_sha256") == metaStr(t, eqTwin, "reconstructed_sha256") {
		t.Fatalf("diverged hashes reported equal: %v", eqTwin)
	}

	// The point of the pairs: one verdict per pair, not one verdict always.
	if metaBool(t, pass, "verified") == metaBool(t, fail, "verified") {
		t.Fatalf("verify_unknown_resolution returned the same verdict for source and twin: pass=%v twin=%v", pass, fail)
	}
	if metaBool(t, immPass, "match") == metaBool(t, immTwin, "match") {
		t.Fatalf("verify_target_immutability returned the same verdict for source and twin: pass=%v twin=%v", immPass, immTwin)
	}
	if metaBool(t, eqPass, "equivalent") == metaBool(t, eqTwin, "equivalent") {
		t.Fatalf("verify_output_equivalence returned the same verdict for source and twin: pass=%v twin=%v", eqPass, eqTwin)
	}
}
