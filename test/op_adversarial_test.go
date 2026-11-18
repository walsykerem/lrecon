package main

import (
	"encoding/binary"
	"encoding/json"
	"hash/crc32"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifyTargetImmutabilityStable(t *testing.T) {
	raw := []byte("stable artifact bytes\n")
	p := writeTemp(t, "stable.bin", raw)
	sum, err := metaFileSHA256(p)
	if err != nil {
		t.Fatal(err)
	}
	m := metaMustRun(t, "verify_target_immutability", metaTestArg(t, map[string]any{
		"file":   p,
		"expect": sum,
	}))
	if !metaBool(t, m, "match") || metaBool(t, m, "mutated") {
		t.Fatalf("unchanged target = %v", m)
	}
	if metaStr(t, m, "recorded_sha256") != sum || metaStr(t, m, "target_sha256") != sum {
		t.Fatalf("hashes = %v", m)
	}
}

func TestVerifyTargetImmutabilityMutated(t *testing.T) {
	p := writeTemp(t, "mut.bin", []byte("original bytes\n"))
	sum, err := metaFileSHA256(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("rewritten bytes!\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	m := metaMustRun(t, "verify_target_immutability", metaTestArg(t, map[string]any{
		"file":   p,
		"expect": sum,
	}))
	if metaBool(t, m, "match") || !metaBool(t, m, "mutated") {
		t.Fatalf("mutated target = %v", m)
	}
	notes, _ := m["notes"].([]any)
	found := false
	for _, n := range notes {
		if n == "target-mutated" {
			found = true
		}
	}
	if !found {
		t.Fatalf("mutated target lost the target-mutated caveat: %v", m)
	}
}

func TestVerifyOutputEquivalence(t *testing.T) {
	a := writeTemp(t, "original.bin", []byte("same payload\n"))
	b := writeTemp(t, "reconstruction.bin", []byte("same payload\n"))
	m := metaMustRun(t, "verify_output_equivalence", metaTestArg(t, map[string]any{
		"old": a,
		"new": b,
	}))
	if !metaBool(t, m, "equivalent") || metaStr(t, m, "original_sha256") != metaStr(t, m, "reconstructed_sha256") {
		t.Fatalf("identical bytes = %v", m)
	}

	c := writeTemp(t, "diverged.bin", []byte("same payload!\n"))
	bad := metaMustRun(t, "verify_output_equivalence", metaTestArg(t, map[string]any{
		"old": a,
		"new": c,
	}))
	if metaBool(t, bad, "equivalent") {
		t.Fatalf("altered byte reported equivalent: %v", bad)
	}
	if enc, err := metaCanonical(bad); err != nil || !strings.Contains(string(enc), "equivalence-diverged") {
		t.Fatalf("divergence lost the equivalence-diverged caveat: %v (%v)", bad, err)
	}
}

func TestVerifyTargetImmutabilityMissingFile(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "absent.bin")
	if _, err := metaTestRun(t, "verify_target_immutability", metaTestArg(t, map[string]any{
		"file":   missing,
		"expect": strings.Repeat("ab", 32),
	})); err == nil {
		t.Fatal("verify_target_immutability accepted a missing target")
	}
}

// Adversarial compression headers: a magic prefix is a cheap claim; the header
// parser must still refuse reserved bits, bad checksums and out-of-range fields
// with a recorded skip instead of naming a stream the bytes do not describe.
func TestCompressHeaderReservedAndBadFields(t *testing.T) {
	skipReason := func(d Digest, want string) {
		t.Helper()
		for _, s := range d.Skipped {
			if s.Reason == want {
				return
			}
		}
		t.Fatalf("skipped = %+v, want reason %q", d.Skipped, want)
	}

	// gzip with a reserved FLG bit set must be refused.
	gzip := make([]byte, 10)
	gzip[0], gzip[1], gzip[2], gzip[3] = 0x1f, 0x8b, 8, 0x20
	var gd Digest
	if _, ok := compressHeader("gzip", gzip, &gd); ok {
		t.Fatal("gzip with reserved flg bit accepted")
	}
	skipReason(gd, "compress-header-invalid")
	if !strings.Contains(gd.Skipped[0].Detail, "reserved flg bits") {
		t.Fatalf("gzip detail = %q", gd.Skipped[0].Detail)
	}

	// xz with a nonzero reserved stream flag byte must be refused.
	xz := []byte{0xfd, '7', 'z', 'X', 'Z', 0x00, 0x01, 0x01, 0, 0, 0, 0}
	var xd Digest
	if _, ok := compressHeader("xz", xz, &xd); ok {
		t.Fatal("xz with reserved stream flag accepted")
	}
	skipReason(xd, "compress-header-invalid")
	if !strings.Contains(xd.Skipped[0].Detail, "reserved stream flag") {
		t.Fatalf("xz reserved detail = %q", xd.Skipped[0].Detail)
	}

	// xz whose CRC32 does not cover the flags must be refused even with a
	// known check type.
	xz = []byte{0xfd, '7', 'z', 'X', 'Z', 0x00, 0x00, 0x01, 0xff, 0xff, 0xff, 0xff}
	flags := []byte{0x00, 0x01}
	binary.LittleEndian.PutUint32(xz[8:12], crc32.ChecksumIEEE(flags)^0x1)
	var xc Digest
	if _, ok := compressHeader("xz", xz, &xc); ok {
		t.Fatal("xz with corrupted flags crc32 accepted")
	}
	skipReason(xc, "compress-header-invalid")
	if !strings.Contains(xc.Skipped[0].Detail, "crc32 mismatch") {
		t.Fatalf("xz crc detail = %q", xc.Skipped[0].Detail)
	}

	// lzma props >= 225 and an out-of-range dictionary are both refused.
	props := make([]byte, 5)
	props[0] = 225
	var pd Digest
	if _, ok := compressHeader("lzma", props, &pd); ok {
		t.Fatal("lzma with out-of-range props accepted")
	}
	skipReason(pd, "compress-header-invalid")
	if !strings.Contains(pd.Skipped[0].Detail, "props") {
		t.Fatalf("lzma props detail = %q", pd.Skipped[0].Detail)
	}
	dict := make([]byte, 5)
	binary.LittleEndian.PutUint32(dict[1:5], 2048)
	var dd Digest
	if _, ok := compressHeader("lzma", dict, &dd); ok {
		t.Fatal("lzma with small dictionary accepted")
	}
	skipReason(dd, "compress-header-invalid")
	if !strings.Contains(dd.Skipped[0].Detail, "dictionary") {
		t.Fatalf("lzma dictionary detail = %q", dd.Skipped[0].Detail)
	}
}

// A corrupt or stale saved digest is not "no differences": loadDigest must
// refuse it rather than let a comparison silently read it as a clean baseline.
func TestLoadDigestRefusesCorruptAndStaleBaseline(t *testing.T) {
	corrupt := writeTemp(t, "corrupt.json", []byte("{not json"))
	if _, err := loadDigest(corrupt); err == nil {
		t.Fatal("loadDigest accepted a corrupt saved digest")
	}

	stale, err := json.Marshal(Digest{ContractVersion: contractVersion + 1, Kind: "text"})
	if err != nil {
		t.Fatal(err)
	}
	stalePath := writeTemp(t, "stale.json", stale)
	if _, err := loadDigest(stalePath); err == nil {
		t.Fatal("loadDigest accepted a stale contract_version")
	}

	good, err := json.Marshal(Digest{ContractVersion: contractVersion, Kind: "text"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := loadDigest(writeTemp(t, "good.json", good)); err != nil {
		t.Fatalf("loadDigest refused a current digest: %v", err)
	}
}

// compare_application_versions must distinguish a byte-identical release from
// a rebuild with the same identity and from a genuine identity change. The two
// sides are saved digests, so metaSideOf must not re-hash their own bytes.
func TestCompareApplicationVersionsVerdicts(t *testing.T) {
	save := func(name, sha string, d Digest) string {
		t.Helper()
		d.ContractVersion = contractVersion
		d.Kind = "pe"
		d.Target = Target{FileSHA256: sha, Size: 1024, HashScope: "file:1024", HashBytes: 1024}
		b, err := json.Marshal(d)
		if err != nil {
			t.Fatal(err)
		}
		return writeTemp(t, name, b)
	}
	run := func(a, b string) map[string]any {
		t.Helper()
		return metaMustRun(t, "compare_application_versions", metaTestArg(t, map[string]any{"old": a, "new": b}))
	}

	sha := strings.Repeat("ab", 32)
	a := save("old.json", sha, Digest{MobileSDK: "14.0", BuildID: "build-1"})
	bSame := save("same.json", sha, Digest{MobileSDK: "14.0", BuildID: "build-1"})
	if m := run(a, bSame); metaStr(t, m, "verdict") != "same bytes" || !metaBool(t, m, "same_release") {
		t.Fatalf("identical digests = %v", m)
	}

	// Only a build detail moved: identity survives, bytes do not.
	bBuild := save("rebuild.json", strings.Repeat("cd", 32), Digest{MobileSDK: "14.0", BuildID: "build-2"})
	m := run(a, bBuild)
	if metaStr(t, m, "verdict") != "same application identity, different build" || metaBool(t, m, "same_release") {
		t.Fatalf("rebuild = %v", m)
	}
	if metaNum(t, m, "count") == 0 {
		t.Fatalf("rebuild lost its per-field change: %v", m)
	}

	// The SDK is an identity field: this is a new release, not a rebuild.
	bSDK := save("sdk.json", strings.Repeat("ef", 32), Digest{MobileSDK: "15.0", BuildID: "build-1"})
	m = run(a, bSDK)
	if v := metaStr(t, m, "verdict"); !strings.HasPrefix(v, "application identity changed:") || !strings.Contains(v, "mobile_sdk") {
		t.Fatalf("sdk bump = %v", m)
	}
	ident, _ := m["identity_changed"].([]any)
	if len(ident) == 0 || ident[0] != "mobile_sdk" {
		t.Fatalf("identity_changed = %v", m["identity_changed"])
	}
}

// ggufValue decodes one typed GGUF metadata value. Unknown types, cut buffers
// and runaway nesting must be named as errors rather than silently decoded as
// zero — a corrupt GGUF must not look like a model with clean metadata.
func TestGGUFValueRefusesUnknownTypeAndRunawayNesting(t *testing.T) {
	if _, _, err := ggufValue(&ggCursor{}, 99, 0); err == nil || !strings.Contains(err.Error(), "unknown value type 99") {
		t.Fatalf("unknown type = %v", err)
	}
	if _, _, err := ggufValue(&ggCursor{}, 0, 5); err == nil || !strings.Contains(err.Error(), "deeper than 4") {
		t.Fatalf("deep nesting = %v", err)
	}
	if _, _, err := ggufValue(&ggCursor{}, 8, 0); err == nil || !strings.Contains(err.Error(), "cut string") {
		t.Fatalf("cut string = %v", err)
	}
	// An array whose element type is unknown fails before reading any element.
	bad := make([]byte, 4)
	binary.LittleEndian.PutUint32(bad, 99)
	if _, _, err := ggufValue(&ggCursor{b: bad}, 9, 0); err == nil || !strings.Contains(err.Error(), "array element type 99 is unknown") {
		t.Fatalf("unknown array element = %v", err)
	}
	// A well-formed uint8 still decodes: the refusals are specific, not blanket.
	v, name, err := ggufValue(&ggCursor{b: []byte{0x7f}}, 0, 0)
	if err != nil || name != "uint8" || v != uint8(0x7f) {
		t.Fatalf("uint8 = %v/%q/%v", v, name, err)
	}
}

// set_addresses_names rejects an incomplete job before it reaches Ghidra: the
// caller's own mistake is bad_arg, not "install Ghidra", and the error names
// the exact label that is not an address/name pair.
func TestSetAddressesNamesRejectsIncompleteLabels(t *testing.T) {
	old := ghidraFinder
	t.Cleanup(func() { ghidraFinder = old })
	ghidraFinder = func() (string, string, error) { return "/fake/analyzeHeadless", "/fake/project", nil }

	elf := filepath.Join("testdata", "fixtures", "elf")
	for _, c := range []struct {
		job, want string
	}{
		{`{"file":"` + elf + `","labels":[]}`, `set_addresses_names: job needs "labels"`},
		{`{"file":"` + elf + `","labels":[{"address":"0x1400","name":"ok"},{"address":"0x1500"}]}`, "set_addresses_names: labels[1] is not a pair of address and name"},
	} {
		p := filepath.Join(t.TempDir(), "job.json")
		if err := os.WriteFile(p, []byte(c.job), 0o644); err != nil {
			t.Fatal(err)
		}
		_, err := runOp("set_addresses_names", p)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Fatalf("job %s = %v, want %q", c.job, err, c.want)
		}
	}
}
