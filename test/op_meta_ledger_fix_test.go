package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// metaLedgerFixSample returns an address whose bytes the fixture really holds,
// so a verify call gets past the mapping check and the byte comparison is what
// decides.
func metaLedgerFixSample(t *testing.T, pe string) (string, []byte) {
	t.Helper()
	secs, err := metaSectionTable(pe)
	if err != nil || len(secs) == 0 {
		t.Fatalf("section table: %v (%d sections)", err, len(secs))
	}
	raw := metaReadFile(t, pe)
	for _, s := range secs {
		if s.Size >= 64 && s.Off+20 < uint64(len(raw)) {
			return fmt.Sprintf("%#x", s.Addr+4), raw[s.Off+4 : s.Off+20]
		}
	}
	t.Fatalf("fixture has no section large enough to sample: the fixture builder changed")
	return "", nil
}

// metaLedgerFixState reads unknowns.json as persisted, or zero when it is absent.
func metaLedgerFixState(t *testing.T, state string) metaUnknownState {
	t.Helper()
	var st metaUnknownState
	b, err := os.ReadFile(filepath.Join(state, "unknowns.json"))
	if err != nil {
		return st
	}
	if err := json.Unmarshal(b, &st); err != nil {
		t.Fatalf("unknowns.json: %v", err)
	}
	return st
}

// TestVerifyResolutionChecksTheAnswer pins both halves of the contract: a
// resolution that contradicts the recorded one is not verified and not written,
// and a verification that did not pass never marks the unknown resolved.
func TestVerifyResolutionChecksTheAnswer(t *testing.T) {
	state := metaTestState(t)
	pe := metaManagedPE(t)
	addr, _ := metaLedgerFixSample(t, pe)

	metaMustRun(t, "record_unknown", metaTestArg(t, map[string]any{
		"file": pe, "address": addr, "hypothesis": "one unnamed function",
	}))
	metaMustRun(t, "update_unknown", metaTestArg(t, map[string]any{
		"file": pe, "address": addr, "resolution": "doubles the counter",
	}))

	wrong := metaMustRun(t, "verify_unknown_resolution", metaTestArg(t, map[string]any{
		"file": pe, "address": addr, "resolution": "main entry point of the program",
	}))
	if metaBool(t, wrong, "verified") {
		t.Fatalf("a contradicting resolution verified: %v", wrong)
	}
	if wrong["resolution_match"] != false {
		t.Fatalf("resolution_match = %v, want false", wrong["resolution_match"])
	}
	if metaStr(t, wrong, "resolution") != "doubles the counter" {
		t.Fatalf("the wrong resolution was echoed as recorded: %v", wrong)
	}
	if u := metaLedgerFixState(t, state).Unknowns[0]; u.Resolution != "doubles the counter" || !u.Resolved {
		t.Fatalf("wrong resolution was written: %v", u)
	}

	// Case, surrounding space, inner runs of space and trailing punctuation do
	// not make two answers different; the words still must match.
	right := metaMustRun(t, "verify_unknown_resolution", metaTestArg(t, map[string]any{
		"file": pe, "address": addr, "resolution": "  Doubles   the counter. ",
	}))
	if !metaBool(t, right, "verified") || !metaBool(t, right, "persisted") {
		t.Fatalf("matching resolution did not persist: %v", right)
	}
	if u := metaLedgerFixState(t, state).Unknowns[0]; !u.Resolved {
		t.Fatalf("matching resolution did not resolve the entry: %v", u)
	}

	// apply:false is read-only even on a passing check.
	before, _ := json.Marshal(metaLedgerFixState(t, state))
	readOnly := metaMustRun(t, "verify_unknown_resolution", metaTestArg(t, map[string]any{
		"file": pe, "address": addr, "resolution": "doubles the counter", "apply": false,
	}))
	if !metaBool(t, readOnly, "verified") || metaBool(t, readOnly, "persisted") {
		t.Fatalf("apply:false = %v, want verified and not persisted", readOnly)
	}
	after, _ := json.Marshal(metaLedgerFixState(t, state))
	if string(before) != string(after) {
		t.Fatal("apply:false rewrote state")
	}

	// Two different answers in one call are a bad argument, not a coin toss.
	if _, err := metaTestRun(t, "verify_unknown_resolution", metaTestArg(t, map[string]any{
		"file": pe, "address": addr, "resolution": "doubles the counter", "resolved_as": "halves it",
	})); err == nil {
		t.Fatal("conflicting resolution/resolved_as was accepted")
	}
}

// TestVerifyTamperedBytesNeverResolve is the stale-bytes half: the recorded
// answer must not become resolved just because a resolution was supplied.
func TestVerifyTamperedBytesNeverResolve(t *testing.T) {
	state := metaTestState(t)
	pe := metaManagedPE(t)
	addr, _ := metaLedgerFixSample(t, pe)

	metaMustRun(t, "record_unknown", metaTestArg(t, map[string]any{
		"address": addr, "bytes": "deadbeefdeadbeefdeadbeefdeadbeef", "hypothesis": "not the real bytes",
	}))
	bad := metaMustRun(t, "verify_unknown_resolution", metaTestArg(t, map[string]any{
		"file": pe, "address": addr, "resolution": "this must not be recorded",
	}))
	if metaBool(t, bad, "verified") || metaBool(t, bad, "persisted") {
		t.Fatalf("mismatched bytes verified: %v", bad)
	}
	if u := metaLedgerFixState(t, state).Unknowns[0]; u.Resolved || u.Resolution != "" {
		t.Fatalf("mismatched bytes resolved the entry: %v", u)
	}
}

// TestRecordUnknownRefusesUnmappedAddress keeps a silent empty record from
// becoming an unverifiable entry: a refusal, never a silent accept.
func TestRecordUnknownRefusesUnmappedAddress(t *testing.T) {
	state := metaTestState(t)
	pe := metaManagedPE(t)
	_, err := metaTestRun(t, "record_unknown", metaTestArg(t, map[string]any{
		"file": pe, "address": "0x0", "hypothesis": "nothing lives at zero",
	}))
	if err == nil || !strings.Contains(err.Error(), "is not mapped to a file offset") {
		t.Fatalf("unmapped address: want a refusal, got %v", err)
	}
	if st := metaLedgerFixState(t, state); len(st.Unknowns) != 0 {
		t.Fatalf("unmapped address was recorded: %v", st.Unknowns)
	}

	// Supplied bytes are the caller's claim: still recordable without the file.
	if _, err := metaTestRun(t, "record_unknown", metaTestArg(t, map[string]any{
		"address": "0x0", "bytes": "00", "hypothesis": "the zero byte itself",
	})); err != nil {
		t.Fatalf("explicit bytes were refused: %v", err)
	}
}

// TestCoverageNamesItsSource stops the op from reporting one number while a
// different population produced it.
func TestCoverageNamesItsSource(t *testing.T) {
	state := metaTestState(t)
	pe := metaManagedPE(t)

	metaMustRun(t, "build_reconstruction_obligation_ledger", metaTestArg(t, map[string]any{
		"file": pe, "state": state,
		"unresolved": []map[string]any{{"symbol": "parse", "reason": "cff"}},
	}))
	addr, _ := metaLedgerFixSample(t, pe)
	metaMustRun(t, "record_unknown", metaTestArg(t, map[string]any{
		"file": pe, "address": addr, "hypothesis": "entry",
	}))
	metaMustRun(t, "update_unknown", metaTestArg(t, map[string]any{
		"address": addr, "resolution": "the import thunk",
	}))

	byState := metaMustRun(t, "evaluate_reconstruction_coverage", metaTestArg(t, map[string]any{"state": state}))
	c, _ := byState["coverage"].(map[string]any)
	if c["source"] != "ledger" || metaNum(t, c, "resolved") != 1 || metaNum(t, c, "unresolved") != 1 {
		t.Fatalf("ledger coverage = %v", c)
	}

	byJob := metaMustRun(t, "evaluate_reconstruction_coverage", metaTestArg(t, map[string]any{
		"resolved":   []string{"main"},
		"unresolved": []map[string]any{{"symbol": "parse", "reason": "cff"}},
	}))
	cj, _ := byJob["coverage"].(map[string]any)
	if cj["source"] != "job" {
		t.Fatalf("job coverage source = %v", cj["source"])
	}

	// A ledger that names a different artifact must not answer for this file.
	other := writeTemp(t, "padded.dll", append(metaReadFile(t, pe), '\n'))
	byOther := metaMustRun(t, "evaluate_reconstruction_coverage", metaTestArg(t, map[string]any{
		"file": other, "state": state,
	}))
	co, _ := byOther["coverage"].(map[string]any)
	if co["source"] == "ledger" {
		t.Fatalf("foreign ledger was used: %v", co)
	}
	if note, _ := co["note"].(string); !strings.Contains(note, "ignored the ledger") {
		t.Fatalf("foreign ledger not named: %v", co)
	}
}
