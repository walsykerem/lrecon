package main

import (
	"bytes"
	"strings"
	"testing"
)

// LRECON_BUNDLE_CAP_BYTES lowers both extraction caps for one run; a 64-byte cap
// must stop a 100 MB member, and it must not print as "0 MB" (final.md 403).
func TestExtractEnvCapLowersLimits(t *testing.T) {
	t.Setenv("LRECON_BUNDLE_CAP_BYTES", "64")
	if got := extractLimit(); got != 64 {
		t.Errorf("extractLimit = %d, want 64", got)
	}
	if got := extractTotalLimit(); got != 64 {
		t.Errorf("extractTotalLimit = %d, want 64", got)
	}
	if got := capWords(64); got != "64 bytes" {
		t.Errorf("capWords(64) = %q, want bytes", got)
	}

	zp := writeZip(t, "bomb.apk", []zipEntry{
		{"zeros.bin", bytes.Repeat([]byte{0}, 100)},
	})
	var d Digest
	err := ExtractAll(zp, t.TempDir(), &d)
	if err == nil || !strings.Contains(err.Error(), "extraction cap") {
		t.Fatalf("err = %v, want the 64-byte extraction cap", err)
	}
}

// The env can only lower a cap, never raise it.
func TestExtractEnvCapCannotRaise(t *testing.T) {
	oldPer, oldAll := maxExtract, maxExtractAll
	maxExtract, maxExtractAll = 10, 20
	t.Cleanup(func() { maxExtract, maxExtractAll = oldPer, oldAll })
	t.Setenv("LRECON_BUNDLE_CAP_BYTES", "1000")
	if got := extractLimit(); got != 10 {
		t.Errorf("extractLimit = %d, want the 10-byte ceiling", got)
	}
	if got := extractTotalLimit(); got != 20 {
		t.Errorf("extractTotalLimit = %d, want the 20-byte ceiling", got)
	}
}
