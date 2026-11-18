package main

import (
	"os"
	"path/filepath"
	"testing"
)

func sigFixture(t *testing.T, name string, body []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, body, 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return p
}

func sigWitnesses(d *Digest, value string) int {
	n := 0
	for _, w := range d.witnesses {
		if w.Axis == "sig" && w.Value == value {
			n++
		}
	}
	return n
}

// TestSigpackShippedPackLoads: the embedded pack must load whole. A dropped
// rule at load means a marker the digest silently never looks for, so the test
// fails rather than skipping the rule.
func TestSigpackShippedPackLoads(t *testing.T) {
	sigOnce.Do(loadSigpack)
	if sigErr != nil {
		t.Fatalf("loadSigpack: %v", sigErr)
	}
	if len(sigPats) == 0 {
		t.Fatal("no rules loaded")
	}
	if len(sigDrops) != 0 {
		t.Fatalf("rules refused at load: %v", sigDrops)
	}
	seen := map[string]bool{}
	for _, p := range sigPats {
		if seen[p.id] {
			t.Fatalf("duplicate rule id %q", p.id)
		}
		seen[p.id] = true
		if len(p.lit) < atomLen || !strongAtom(p.lit) {
			t.Fatalf("rule %q loaded with a weak atom %x", p.id, p.lit)
		}
		if p.lang == "" {
			t.Fatalf("rule %q loaded without a language", p.id)
		}
	}
}

// TestCompileSigRuleRefusals: every untrustworthy rule is refused by name, so
// the reason in the digest matches what the pack actually did.
func TestCompileSigRuleRefusals(t *testing.T) {
	good := sigRule{ID: "x", Lang: "lua", Hex: "1b4c7561", At: "0"}
	if pat, why := compileSigRule(good); why != "" || len(pat.lit) != 4 || pat.at != "0" {
		t.Fatalf("good rule = %+v, %q", pat, why)
	}
	cases := []struct {
		name string
		rule sigRule
		why  string
	}{
		{"short", sigRule{ID: "a", Lang: "go", Str: "abc"}, "sigpack-weak-atom"},
		{"repeat", sigRule{ID: "b", Lang: "go", Str: "ababab"}, "sigpack-weak-atom"},
		{"zeros", sigRule{ID: "c", Lang: "go", Hex: "00000000"}, "sigpack-weak-atom"},
		{"two-values", sigRule{ID: "d", Lang: "go", Str: "aabbaa"}, "sigpack-weak-atom"},
		{"position", sigRule{ID: "e", Lang: "go", Str: "runtime", At: "tail"}, "sigpack-at-unsupported"},
		{"badhex", sigRule{ID: "f", Lang: "go", Hex: "zzzzzzzz"}, "sigpack-schema"},
		{"empty", sigRule{ID: "g", Lang: "go"}, "sigpack-schema"},
	}
	for _, c := range cases {
		if _, why := compileSigRule(c.rule); why != c.why {
			t.Errorf("%s: why = %q, want %q", c.name, why, c.why)
		}
	}
}

// TestSigOffsetsAtZero: an at:"0" rule is evidence only at the first byte, and
// the any rule still finds the same literal further in.
func TestSigOffsetsAtZero(t *testing.T) {
	zero := sigPat{id: "z", at: "0", lit: []byte("FOR1")}
	if got := sigOffsets([]byte("xxFOR1"), zero, 2); len(got) != 0 {
		t.Fatalf("at 0 matched at %v, want none", got)
	}
	if got := sigOffsets([]byte("FOR1xx"), zero, 2); len(got) != 1 || got[0] != 0 {
		t.Fatalf("at 0 = %v, want [0]", got)
	}
	any := sigPat{id: "a", at: "any", lit: []byte("FOR1")}
	if got := sigOffsets([]byte("xxFOR1xxFOR1"), any, 2); len(got) != 2 || got[0] != 2 || got[1] != 8 {
		t.Fatalf("any = %v, want [2 8]", got)
	}
	if got := sigOffsets([]byte("FOR1FOR1FOR1FOR1"), any, 1); len(got) != 1 || got[0] != 0 {
		t.Fatalf("limit = %v, want [0]", got)
	}
}

// TestSigpackNeedsTwoMechanisms: a marker alone is not a language. The same
// marker plus the mangling family on a disjoint range is.
func TestSigpackNeedsTwoMechanisms(t *testing.T) {
	p := sigFixture(t, "macho", []byte("\x00\x00\x00\x00core::panicking\x00rust_begin_unwind\x00"))

	d := &Digest{Kind: "macho"}
	info, err := os.Stat(p)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	d.FileSize = info.Size()
	inspectSigpack(p, d)
	if got := sigWitnesses(d, "rust"); got == 0 {
		t.Fatal("no rust marker witnesses")
	}
	d.settleLanguage()
	if len(d.Claims) != 0 {
		t.Fatalf("markers alone produced a claim: %+v", d.Claims)
	}
	if len(d.Unknown) != 1 || d.Unknown[0].Slot != "language" {
		t.Fatalf("Unknown = %+v, want one language entry", d.Unknown)
	}

	// The mangling classifier reading a different range is the second mechanism.
	d.witness(Witness{Axis: "mangling", Class: "mangling:legacy", Value: "rust-legacy", Start: 1000, End: 1010})
	d.settleLanguage()
	var claimed []string
	for _, c := range d.Claims {
		if c.Slot == "language" {
			claimed = append(claimed, c.Value)
		}
	}
	if len(claimed) != 1 || claimed[0] != "rust" {
		t.Fatalf("language claims = %v, want [rust]; claims=%+v unknown=%+v wit=%+v", claimed, d.Claims, d.Unknown, d.witnesses)
	}
}

// TestSigpackAntiMarkersCancel: two families in one file are evidence for
// neither, and an unrelated marker in the same read still lands.
func TestSigpackAntiMarkersCancel(t *testing.T) {
	body := []byte("_ZSt core::panicking lua_pcall")
	p := sigFixture(t, "mixed", body)
	d := &Digest{Kind: "elf", FileSize: int64(len(body))}
	inspectSigpack(p, d)
	if n := sigWitnesses(d, "c++"); n != 0 {
		t.Fatalf("c++ witnesses = %d, want 0 (rust marker cancels)", n)
	}
	if n := sigWitnesses(d, "rust"); n != 0 {
		t.Fatalf("rust witnesses = %d, want 0 (c++ marker cancels)", n)
	}
	if n := sigWitnesses(d, "lua"); n != 1 {
		t.Fatalf("lua witnesses = %d, want 1", n)
	}
}

// TestSigpackOneWitnessPerLanguage: a file stuffed with one marker cannot
// crowd the digest, and a second marker of the same language adds nothing a
// claim could use.
func TestSigpackOneWitnessPerLanguage(t *testing.T) {
	body := make([]byte, 0, 200)
	for range 40 {
		body = append(body, "lua_pcall\x00"...)
	}
	p := sigFixture(t, "spam", body)
	d := &Digest{Kind: "macho", FileSize: int64(len(body))}
	inspectSigpack(p, d)
	if n := sigWitnesses(d, "lua"); n != 1 {
		t.Fatalf("lua witnesses = %d, want 1", n)
	}
}

// TestSigpackTruncatedIsSaidOutLoud: a marker past the scan window must appear
// as a skip, never as "absent".
func TestSigpackTruncatedIsSaidOutLoud(t *testing.T) {
	p := filepath.Join(t.TempDir(), "big")
	f, err := os.Create(p)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := f.WriteString("lua_pcall"); err != nil {
		t.Fatalf("write head: %v", err)
	}
	if _, err := f.WriteAt([]byte("swift_allocObject"), maxSigScan+16); err != nil {
		t.Fatalf("write tail: %v", err)
	}
	if err := f.Truncate(maxSigScan + 64); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	f.Close()

	d := &Digest{Kind: "macho", FileSize: maxSigScan + 64}
	inspectSigpack(p, d)
	if n := sigWitnesses(d, "lua"); n != 1 {
		t.Fatalf("lua witnesses = %d, want 1 from the scanned window", n)
	}
	if n := sigWitnesses(d, "swift"); n != 0 {
		t.Fatalf("swift witnesses = %d, want 0 (past the window)", n)
	}
	var truncated bool
	for _, s := range d.Skipped {
		if s.Reason == "sigpack-truncated" {
			truncated = true
		}
	}
	if !truncated {
		t.Fatalf("Skipped = %+v, want sigpack-truncated", d.Skipped)
	}
}

// TestSigpackSkipsNonBinaryKinds: the pack only speaks about executable
// containers it was asked to inspect.
func TestSigpackSkipsNonBinaryKinds(t *testing.T) {
	body := []byte("lua_pcall")
	p := sigFixture(t, "text", body)
	d := &Digest{Kind: "text", FileSize: int64(len(body))}
	inspectSigpack(p, d)
	if len(d.witnesses) != 0 {
		t.Fatalf("witnesses = %+v, want none for a text target", d.witnesses)
	}
}
