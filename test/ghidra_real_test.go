package main

import (
	"os"
	"path/filepath"
	"testing"
)

// requireRealGhidra gates the tests that actually run analyzeHeadless. A cold
// import costs minutes and writes a Ghidra project, so it is opt-in and never
// runs in CI. LRECON_GHIDRA_CACHE and LRECON_STATE point at the test's temp
// dir, so the run leaves the user's project and session state untouched.
func requireRealGhidra(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("real ghidra import")
	}
	if os.Getenv("CI") != "" {
		t.Skip("real ghidra import is skipped in CI")
	}
	if os.Getenv("LRECON_OPS_GHIDRA") != "1" {
		t.Skip("real ghidra import is opt-in: set LRECON_OPS_GHIDRA=1")
	}
	if _, _, err := findGhidra(); err != nil {
		t.Skip("ghidra analyzeHeadless not installed")
	}
	root := t.TempDir()
	t.Setenv("LRECON_GHIDRA_CACHE", filepath.Join(root, "ghidra-cache"))
	t.Setenv("LRECON_STATE", filepath.Join(root, "state"))
	t.Setenv("LRECON_GHIDRA_TIMEOUT", "300s")
}
