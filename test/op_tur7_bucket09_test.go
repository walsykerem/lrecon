package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// TestTur7Bucket09EvidenceLosslessRoundTrip proves the evidence bundle is a
// lossless carrier of the source digest, not just a file that verifies: the
// fields import recovers must equal the fields the digest engine produced for
// the artifact, byte for byte and entry for entry. Then it moves one byte
// inside the exported file - a hex digit of the recorded artifact sha256, so
// the JSON still decodes and only the attribution is wrong - and requires
// import to refuse with the attestation error that names the file, the claimed
// digest and the digest the bytes actually carry.
func TestTur7Bucket09EvidenceLosslessRoundTrip(t *testing.T) {
	metaTestState(t)
	art := metaManagedPE(t)
	abs, err := filepath.Abs(art)
	if err != nil {
		t.Fatalf("abs %s: %v", art, err)
	}

	out := filepath.Join(t.TempDir(), "managed.evidence.json")
	oldOut := opOutput
	opOutput = out
	t.Cleanup(func() { opOutput = oldOut })

	exp := metaMustRun(t, "export_evidence_bundle", art)
	if got := metaStr(t, exp, "bundle_file"); got != out {
		t.Fatalf("bundle_file = %q, want -o destination %q", got, out)
	}

	// The source of truth the bundle must reproduce: the digest engine's own
	// answer for the artifact, read fresh rather than through the exporter.
	d, err := loadDigest(abs)
	if err != nil {
		t.Fatalf("loadDigest %s: %v", abs, err)
	}
	sum, size, err := metaObjectSHA(abs)
	if err != nil {
		t.Fatalf("metaObjectSHA %s: %v", abs, err)
	}
	evLine, err := evidenceLine(d)
	if err != nil {
		t.Fatalf("evidenceLine: %v", err)
	}
	evLine = strings.TrimSpace(evLine)
	if len(d.Claims) == 0 && len(d.Notes) == 0 && d.Symbols == "" && d.Names == "" {
		t.Fatalf("fixture digest carries no claims, notes, symbols or names: nothing to prove is carried losslessly")
	}

	raw := metaReadFile(t, out)
	if got := metaStr(t, exp, "bundle_sha256"); got != metaSHA256(raw) {
		t.Fatalf("export bundle_sha256 = %q, want sha256 of the written bytes %q", got, metaSHA256(raw))
	}
	att := metaStr(t, exp, "attestation")
	if !strings.HasPrefix(att, "sha256:") {
		t.Fatalf("export attestation = %q, want sha256: prefix", att)
	}

	// Untouched bundle: import must recover every structured field.
	imp, err := metaTestRun(t, "import_evidence_bundle", metaTestArg(t, map[string]any{"file": out, "expect": art}))
	if err != nil {
		t.Fatalf("import of the fresh bundle: %v", err)
	}
	for _, flag := range []string{"verified", "artifact_checked", "artifact_match", "size_match"} {
		if !metaBool(t, imp, flag) {
			t.Fatalf("import of the fresh bundle: %s = false: %v", flag, imp)
		}
	}
	if got := metaStr(t, imp, "attestation"); got != att {
		t.Fatalf("import attestation = %q, export reported %q", got, att)
	}
	if got := metaStr(t, imp, "bundle_sha256"); got != metaSHA256(raw) {
		t.Fatalf("import bundle_sha256 = %q, want sha256 of the stored bytes %q", got, metaSHA256(raw))
	}
	if got := metaStr(t, imp, "artifact_sha256"); got != sum {
		t.Fatalf("import artifact_sha256 = %q, want %q", got, sum)
	}

	got, ok := imp["bundle"].(map[string]any)
	if !ok {
		t.Fatalf("import carries no bundle object: %v", imp)
	}
	want := map[string]any{
		"kind":      "lrecon.evidence/1",
		"artifact":  abs,
		"sha256":    sum,
		"size":      float64(size),
		"symbols":   d.Symbols,
		"names":     d.Names,
		"coverage":  d.coverageClaim(),
		"evidence":  evLine,
		"toolchain": d.Toolchain,
	}
	if d.Kind != "" {
		want["artifact_kind"] = d.Kind
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("import bundle[%q] = %#v, source digest says %#v", k, got[k], v)
		}
	}
	if _, present := got["artifact_kind"]; d.Kind == "" && present {
		t.Errorf("import invented artifact_kind %#v for a digest with no kind", got["artifact_kind"])
	}

	var wantClaims []any
	for _, c := range d.Claims {
		wantClaims = append(wantClaims, fmt.Sprintf("%s (%s @%#x)", c.Value, c.Source, c.ByteOffset))
	}
	if !reflect.DeepEqual(got["claims"], wantClaims) {
		t.Errorf("import claims = %#v, source digest claims = %#v", got["claims"], wantClaims)
	}
	var wantNotes []any
	for _, n := range d.Notes {
		wantNotes = append(wantNotes, n)
	}
	if !reflect.DeepEqual(got["notes"], wantNotes) {
		t.Errorf("import notes = %#v, source digest notes = %#v", got["notes"], wantNotes)
	}
	// One byte, inside the recorded artifact sha256. JSON stays valid and the
	// field still decodes, so only the attestation can catch it.
	mutated := append([]byte(nil), raw...)
	key := []byte(`"sha256":"`)
	i := bytes.Index(mutated, key)
	if i < 0 {
		t.Fatalf("exported bundle has no sha256 field: %s", raw)
	}
	start := i + len(key)
	if start >= len(mutated) || !isLowerHex(mutated[start]) {
		t.Fatalf("exported sha256 value starts with %q, not hex", mutated[start:min(start+1, len(mutated))])
	}
	repl := byte('0')
	if mutated[start] == '0' {
		repl = '1'
	}
	exportedSHA := string(mutated[start : start+64])
	mutated[start] = repl
	if bytes.Equal(mutated, raw) {
		t.Fatal("byte mutation did not change the bundle")
	}
	var w metaEvidenceWrapper
	if err := json.Unmarshal(mutated, &w); err != nil {
		t.Fatalf("mutated bundle no longer decodes as JSON, so the rejection would not prove attribution: %v", err)
	}
	if w.Bundle.SHA256 == exportedSHA {
		t.Fatalf("mutation did not land in the bundle sha256 field: %q", w.Bundle.SHA256)
	}
	if err := os.WriteFile(out, mutated, 0o644); err != nil {
		t.Fatalf("rewrite %s: %v", out, err)
	}

	res, err := metaTestRun(t, "import_evidence_bundle", metaTestArg(t, map[string]any{"file": out, "expect": art}))
	if err == nil {
		t.Fatalf("import accepted a bundle with one mutated byte: %v", res)
	}
	if res != nil {
		t.Fatalf("rejected import still returned a partial answer: %v", res)
	}
	ae, ok := errors.AsType[*metaAttestationError](err)
	if !ok {
		t.Fatalf("want *metaAttestationError, got %T: %v", err, err)
	}
	if ae.File != out {
		t.Errorf("attestation error names %q, want the bundle it read %q", ae.File, out)
	}
	if ae.Claimed != att {
		t.Errorf("attestation error claimed %q, the file still attests %q", ae.Claimed, att)
	}
	if ae.Actual == ae.Claimed {
		t.Errorf("attestation error says claimed and actual are both %q", ae.Actual)
	}
	if !strings.HasPrefix(ae.Actual, "sha256:") || len(ae.Actual) != len("sha256:")+64 {
		t.Errorf("attestation error actual %q is not a sha256 digest", ae.Actual)
	}
	wantMsg := fmt.Sprintf("%s: attestation mismatch: the file does not carry the digest it claims (%q), content hashes to %q", out, ae.Claimed, ae.Actual)
	if err.Error() != wantMsg {
		t.Errorf("attestation error text = %q, want %q", err.Error(), wantMsg)
	}

	// Neither export nor the rejected import may touch the artifact.
	if after, _, err := metaObjectSHA(abs); err != nil || after != sum {
		t.Fatalf("artifact changed during the round trip: sha256 %q (err %v), want %q", after, err, sum)
	}
}

func isLowerHex(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f')
}
