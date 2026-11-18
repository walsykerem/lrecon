package main

import (
	"debug/macho"
	"fmt"
	"strings"
	"testing"
)

// metaRealTarget returns a thin Mach-O with a code address inside __TEXT,__text.
// The Rust fixture is tracked and already thin, so no host binary and no lipo
// thinning is needed.
func metaRealTarget(t *testing.T) (string, string) {
	t.Helper()
	if mf, err := macho.Open(fixtureRust); err == nil {
		mf.Close()
		return fixtureRust, metaRealFuncAddr(t, fixtureRust)
	}
	t.Skipf("%s is not a thin Mach-O", fixtureRust)
	return "", ""
}

// metaRealFuncAddr returns a code address Ghidra's analyzer will have turned
// into a function: a defined N_SECT symbol inside the executable section. That
// is what trace_application_feature needs; a bare section start may hold data.
func metaRealFuncAddr(t *testing.T, path string) string {
	t.Helper()
	mf, err := macho.Open(path)
	if err != nil {
		t.Skipf("not a thin Mach-O: %v", err)
	}
	defer mf.Close()
	if mf.Symtab == nil {
		t.Skip("no symbol table")
	}
	var text *macho.Section
	for _, s := range mf.Sections {
		if s.Seg == "__TEXT" && s.Name == "__text" && s.Size >= 16 {
			text = s
			break
		}
	}
	if text == nil {
		t.Skip("no __TEXT,__text section")
	}
	for _, s := range mf.Symtab.Syms {
		if s.Type&0x0e == 0x0e || s.Sect == 0 || !strings.HasPrefix(s.Name, "_") {
			continue
		}
		if s.Value >= text.Addr && s.Value < text.Addr+text.Size {
			return fmt.Sprintf("0x%x", s.Value)
		}
	}
	return fmt.Sprintf("0x%x", text.Addr)
}

// TestMetaGhidraReal runs route G against a real analyzeHeadless. The fake shim
// proves wiring; this proves the script compiles in Ghidra and that the values
// it reports are the ones the project really stored.
func TestMetaGhidraReal(t *testing.T) {
	if testing.Short() {
		t.Skip("real ghidra import")
	}
	if _, err := metaGhidraPath(); err != nil {
		t.Skip("ghidra analyzeHeadless not installed")
	}
	// A cold real import outlasts the 50 s op budget, and this test asserts on
	// stored values rather than on the timeout envelope.
	t.Setenv("LRECON_GHIDRA_TIMEOUT", "300s")
	target, addr := metaRealTarget(t)

	// PRE, not PLATE: "PRE" was the mode the Go side asked for while Meta.java
	// had no branch for it, so this exact case used to fail in the field.
	pre := metaMustRun(t, "set_comment", metaTestArg(t, map[string]any{
		"file": target, "address": addr, "text": "lrecon real pre comment",
	}))
	if got := metaStr(t, pre, "stored"); !strings.Contains(got, "lrecon real pre comment") {
		t.Fatalf("set_comment stored %q, want the text it asked for: %v", got, pre)
	}
	if got := metaStr(t, pre, "address"); got != strings.TrimPrefix(addr, "0x") && got != addr {
		t.Fatalf("set_comment address = %q, want %q", got, addr)
	}

	tr := metaMustRun(t, "trace_application_feature", metaTestArg(t, map[string]any{
		"file": target, "address": addr, "count": 4,
	}))
	if got := metaStr(t, tr, "function"); got == "" {
		t.Fatalf("trace named no function for %s: %v", addr, tr)
	}
	if _, ok := tr["callers"].([]any); !ok {
		t.Fatalf("callers is not a list: %v", tr)
	}
}
