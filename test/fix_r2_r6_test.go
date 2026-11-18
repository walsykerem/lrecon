package main

import "testing"

// R2: a CodeDirectory that seals no pages recomputed no hashes. "hashes_ok"
// would be a false attestation.
func TestCsVerifyPagesZeroPagesNotOK(t *testing.T) {
	cd := &csCodeDirectory{HashTypeID: 1, HashType: "sha1", HashSize: 20, PageSize: 4096, CodeLimit: 0, CodeSlots: 0}
	v := csVerifyPages(cd, nil)
	if v.HashesOK || v.PagesChecked != 0 || v.Reason == "" {
		t.Fatalf("csVerifyPages(zero pages) = %+v, want HashesOK=false and a reason", v)
	}
}

// R6: a reader that fails to parse an asar header cannot answer "not detected"
// for missing constants, even when every byte was read.
func TestParseFailureGatesAbsenceEvenOnFullRead(t *testing.T) {
	d := Digest{
		FileSize:     8,
		BytesScanned: 8,
		Constants:    consts{constNotDetected},
		JIT:          jitNotDetected,
		Names:        nameNotRecovered,
		Notes:        []string{"asar: malformed header JSON: unexpected end"},
	}
	d.gateAbsence()
	if len(d.Constants) != 1 || d.Constants[0] != constNotScanned {
		t.Fatalf("constants = %v, want not_scanned", d.Constants)
	}
	if d.JIT != constNotScanned || d.Names != constNotScanned {
		t.Fatalf("jit/names = %q/%q, want not_scanned", d.JIT, d.Names)
	}
}
