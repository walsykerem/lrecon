package main

// TUR5 go19 simulation: real behavior of evaluate_reconstruction_coverage.
// Exercises all three sources (job lists, state ledger, artifact digest), the
// ledger identity guard, and the read-only state lookup. No production code is
// changed; every fixture is written under t.TempDir().

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func t5g19WriteJSON(t *testing.T, name string, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func t5g19Coverage(t *testing.T, jobPath string) (metaCoverage, []string) {
	t.Helper()
	res, err := runEvaluateCoverage(jobPath)
	if err != nil {
		t.Fatalf("runEvaluateCoverage(%s): %v", jobPath, err)
	}
	m, ok := res.(map[string]any)
	if !ok {
		t.Fatalf("result = %T, want map", res)
	}
	cov, ok := m["coverage"].(metaCoverage)
	if !ok {
		t.Fatalf("coverage = %T, want metaCoverage", m["coverage"])
	}
	reasons, _ := m["reasons"].([]string)
	return cov, reasons
}

func TestTur5Go19CoverageFromJobLists(t *testing.T) {
	job := t5g19WriteJSON(t, "job.json", map[string]any{
		"resolved": []string{"a", "b", "c"},
		"unresolved": []metaObligation{
			{Symbol: "x", Reason: "truncated"},
			{Symbol: "y", Reason: "truncated"},
			{Symbol: "z", Reason: ""},
		},
	})
	cov, reasons := t5g19Coverage(t, job)
	if cov.Source != "job" || cov.Resolved != 3 || cov.Unresolved != 3 || cov.Total != 6 {
		t.Fatalf("job coverage = %+v", cov)
	}
	if cov.Percent != 50 {
		t.Fatalf("percent = %v, want 50", cov.Percent)
	}
	if cov.ByReason["truncated"] != 2 || cov.ByReason["unstated"] != 1 {
		t.Fatalf("by_reason = %v", cov.ByReason)
	}
	if strings.Join(reasons, ",") != "truncated,unstated" {
		t.Fatalf("reasons = %v, want sorted truncated,unstated", reasons)
	}
	if !strings.Contains(cov.Claim, "3 of 6 symbols resolved") || !strings.Contains(cov.Claim, "source: job") {
		t.Fatalf("claim = %q", cov.Claim)
	}
}

func TestTur5Go19CoverageFromStateLedger(t *testing.T) {
	state := t.TempDir()
	unk := metaUnknownState{Kind: metaUnknownsKind, Unknowns: []metaUnknown{
		{Address: "0x1", Resolved: true, Resolution: "printf"},
		{Address: "0x2", Resolved: true, Resolution: "  "},
		{Address: "0x3", Hypothesis: "data"},
	}}
	b, _ := json.Marshal(unk)
	if err := os.WriteFile(filepath.Join(state, "unknowns.json"), b, 0o644); err != nil {
		t.Fatal(err)
	}
	led := metaLedger{Kind: metaLedgerKind, Rows: []metaObligation{{Symbol: "0x4", Reason: "oblig"}}}
	b, _ = json.Marshal(led)
	if err := os.WriteFile(filepath.Join(state, "obligations.json"), b, 0o644); err != nil {
		t.Fatal(err)
	}
	job := t5g19WriteJSON(t, "job.json", map[string]any{"state": state})
	cov, reasons := t5g19Coverage(t, job)
	if cov.Source != "ledger" || cov.Resolved != 1 || cov.Unresolved != 3 || cov.Total != 4 {
		t.Fatalf("ledger coverage = %+v", cov)
	}
	if cov.Percent != 25 {
		t.Fatalf("percent = %v, want 25", cov.Percent)
	}
	if cov.ByReason["unresolved-unknown"] != 2 || cov.ByReason["oblig"] != 1 {
		t.Fatalf("by_reason = %v", cov.ByReason)
	}
	if cov.Basis["unknowns_resolved"] != 1 || cov.Basis["unknowns_open"] != 2 || cov.Basis["ledger_rows"] != 1 {
		t.Fatalf("basis = %v", cov.Basis)
	}
	if strings.Join(reasons, ",") != "oblig,unresolved-unknown" {
		t.Fatalf("reasons = %v", reasons)
	}
}

func TestTur5Go19CoverageFileModeFromDigest(t *testing.T) {
	t.Setenv("LRECON_STATE", t.TempDir())
	digest := t5g19WriteJSON(t, "digest.json", map[string]any{
		"kind": "macho", "contract_version": contractVersion,
		"exports": 3, "names": "local:2",
		"skipped": []map[string]any{
			{"reason": "reader-a", "detail": "d1"},
			{"reason": "reader-b", "detail": "d2"},
		},
	})
	job := t5g19WriteJSON(t, "job.json", map[string]any{"file": digest})
	cov, _ := t5g19Coverage(t, job)
	if cov.Source != "file" || cov.Resolved != 5 || cov.Unresolved != 2 || cov.Total != 7 {
		t.Fatalf("file coverage = %+v", cov)
	}
	if cov.Basis["exports"] != 3 || cov.Basis["local_names"] != 2 || cov.Basis["skipped_readers"] != 2 {
		t.Fatalf("basis = %v", cov.Basis)
	}
	if !strings.Contains(cov.Note, "file mode") {
		t.Fatalf("note = %q", cov.Note)
	}
}

func TestTur5Go19CoverageLedgerMismatchFallsBackToFile(t *testing.T) {
	state := t.TempDir()
	led := metaLedger{
		Kind: metaLedgerKind, Artifact: "other.bin",
		SHA256: "0000000000000000000000000000000000000000000000000000000000000000",
		Rows:   []metaObligation{{Symbol: "0x9", Reason: "foreign"}},
	}
	b, _ := json.Marshal(led)
	if err := os.WriteFile(filepath.Join(state, "obligations.json"), b, 0o644); err != nil {
		t.Fatal(err)
	}
	digest := t5g19WriteJSON(t, "digest.json", map[string]any{
		"kind": "macho", "contract_version": contractVersion,
		"exports": 1, "names": "not_recovered",
	})
	job := t5g19WriteJSON(t, "job.json", map[string]any{"file": digest, "state": state})
	cov, _ := t5g19Coverage(t, job)
	if cov.Source != "file" || cov.Resolved != 1 || cov.Unresolved != 0 {
		t.Fatalf("mismatch coverage = %+v", cov)
	}
	if !strings.Contains(cov.Note, "ignored the ledger") {
		t.Fatalf("note = %q, want ledger rejection", cov.Note)
	}
}

func TestTur5Go19CoverageTotalZeroRefuses(t *testing.T) {
	t.Setenv("LRECON_STATE", t.TempDir())
	digest := t5g19WriteJSON(t, "digest.json", map[string]any{
		"kind": "plain", "contract_version": contractVersion,
		"exports": 0, "names": "not_recovered",
	})
	job := t5g19WriteJSON(t, "job.json", map[string]any{"file": digest})
	if _, err := runEvaluateCoverage(job); err == nil || !strings.Contains(err.Error(), "yields nothing measurable") {
		t.Fatalf("err = %v, want nothing-measurable refusal", err)
	}
}

func TestTur5Go19MetaStateRootIfAnyReadOnly(t *testing.T) {
	t.Setenv("LRECON_STATE", "")
	missing := filepath.Join(t.TempDir(), "not-created")
	if got := metaStateRootIfAny("ignored", metaJob{State: missing}); got != "" {
		t.Fatalf("missing state root = %q, want empty", got)
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Fatalf("read-only lookup created %s: %v", missing, err)
	}
	dir := t.TempDir()
	if got := metaStateRootIfAny(dir, metaJob{}); got != dir {
		t.Fatalf("path-as-state root = %q, want %q", got, dir)
	}
}
