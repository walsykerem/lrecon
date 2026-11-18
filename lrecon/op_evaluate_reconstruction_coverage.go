package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// metaCoverage is the bounded claim this op makes: how many symbols were
// resolved, how many were not, and the ratio between them. Source names where
// the counts came from (job lists, the state ledger, or the artifact's own
// digest), so the claim can be checked instead of trusted.
type metaCoverage struct {
	Source     string         `json:"source"`
	Resolved   int            `json:"resolved"`
	Unresolved int            `json:"unresolved"`
	Total      int            `json:"total"`
	Percent    float64        `json:"percent"`
	ByReason   map[string]int `json:"by_reason,omitempty"`
	Basis      map[string]int `json:"basis,omitempty"`
	Claim      string         `json:"claim"`
	Note       string         `json:"note,omitempty"`
}

func init() {
	registerOp(op{
		name:  "evaluate_reconstruction_coverage",
		route: "L",
		needs: true,
		desc:  "Measure reconstruction coverage from a job's resolved/unresolved lists, the state ledger (unknowns.json + obligations.json) when no lists are given, or the artifact's own digest as a last resort; the answer names its source.",
		run:   runEvaluateCoverage,
	})
}

func runEvaluateCoverage(path string) (any, error) {
	job, err := metaLoadJob(path)
	if err != nil {
		return nil, err
	}
	cov := metaCoverage{ByReason: map[string]int{}, Basis: map[string]int{}}
	var unresolved []metaObligation
	switch {
	case len(job.Resolved) > 0 || len(job.Unresolved) > 0:
		// Explicit lists win: the caller handed over the population to measure.
		cov.Source = "job"
		cov.Resolved = len(job.Resolved)
		unresolved = job.Unresolved
		cov.Basis["job_resolved"] = len(job.Resolved)
		cov.Basis["job_unresolved"] = len(job.Unresolved)
	default:
		fromState, err := metaCoverageFromState(path, job, &cov, &unresolved)
		if err != nil {
			return nil, err
		}
		if !fromState {
			if job.File == "" {
				return nil, fmt.Errorf("evaluate_reconstruction_coverage: job has no \"resolved\" or \"unresolved\" symbols, the state dir holds no ledger, and no file was given to read skipped readers from")
			}
			if err := metaCoverageFromFile(job.File, &cov, &unresolved); err != nil {
				return nil, err
			}
		}
	}
	cov.Unresolved = len(unresolved)
	cov.Total = cov.Resolved + cov.Unresolved
	if cov.Total == 0 {
		return nil, fmt.Errorf("evaluate_reconstruction_coverage: job has no \"resolved\" or \"unresolved\" symbols, the state dir holds no ledger rows, and %s yields nothing measurable", job.File)
	}
	for _, r := range unresolved {
		reason := r.Reason
		if reason == "" {
			reason = "unstated"
		}
		cov.ByReason[reason]++
	}
	cov.Percent = float64(cov.Resolved) / float64(cov.Total) * 100
	reasons := make([]string, 0, len(cov.ByReason))
	for r := range cov.ByReason {
		reasons = append(reasons, r)
	}
	sort.Strings(reasons)
	cov.Claim = fmt.Sprintf("%d of %d symbols resolved (%.1f%%); %d unresolved across %d reason(s); source: %s", cov.Resolved, cov.Total, cov.Percent, cov.Unresolved, len(reasons), cov.Source)
	return map[string]any{"coverage": cov, "reasons": reasons}, nil
}

// metaStateRootIfAny is metaStateRoot without the mkdir: a read-only measurement
// must not create a state directory just to look inside it.
func metaStateRootIfAny(path string, job metaJob) string {
	isDir := func(p string) bool {
		fi, err := os.Stat(p)
		return err == nil && fi.IsDir()
	}
	for _, c := range []string{job.State, os.Getenv("LRECON_STATE")} {
		if c != "" {
			if isDir(c) {
				return c
			}
			return ""
		}
	}
	if isDir(path) {
		return path
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	if d := filepath.Join(home, ".lrecon"); isDir(d) {
		return d
	}
	return ""
}

// metaCoverageFromState reads the ledger an earlier op persisted: resolved
// unknowns are the resolved side, open unknowns plus obligation rows are the
// unresolved side. It reports false when the state dir holds no rows, so the
// caller can fall through to the file.
func metaCoverageFromState(path string, job metaJob, cov *metaCoverage, unresolved *[]metaObligation) (bool, error) {
	root := metaStateRootIfAny(path, job)
	if root == "" {
		return false, nil
	}
	var unk metaUnknownState
	hasUnknowns, err := metaReadState(filepath.Join(root, "unknowns.json"), metaUnknownsKind, &unk)
	if err != nil {
		return false, err
	}
	var led metaLedger
	hasLedger, err := metaReadState(filepath.Join(root, "obligations.json"), metaLedgerKind, &led)
	if err != nil {
		return false, err
	}
	// A ledger names one artifact. Measuring a different file through it would
	// be a claim about bytes it never read, so the whole state dir is set aside:
	// its unknowns belong to that other artifact too.
	if hasLedger && job.File != "" && led.Artifact != "" && led.SHA256 != "" {
		if sum, _, err := metaObjectSHA(job.File); err == nil && sum != led.SHA256 {
			cov.Note = fmt.Sprintf("ignored the ledger in %s: it names %s (sha256 %s), not %s", root, led.Artifact, led.SHA256, job.File)
			return false, nil
		}
	}
	resolved, open := 0, 0
	for _, u := range unk.Unknowns {
		if u.Resolved && strings.TrimSpace(u.Resolution) != "" {
			resolved++
			continue
		}
		open++
		*unresolved = append(*unresolved, metaObligation{
			Symbol:   u.Address,
			Reason:   "unresolved-unknown",
			Evidence: "unknowns.json:" + u.Hypothesis,
		})
	}
	if hasUnknowns {
		cov.Basis["unknowns_resolved"] = resolved
		cov.Basis["unknowns_open"] = open
	}
	rows := 0
	if hasLedger {
		rows = len(led.Rows)
		cov.Basis["ledger_rows"] = rows
		*unresolved = append(*unresolved, led.Rows...)
	}
	if resolved+open+rows == 0 {
		return false, nil
	}
	cov.Source = "ledger"
	cov.Resolved = resolved
	cov.Note = strings.TrimSpace(cov.Note + fmt.Sprintf(" ledger read from %s", root))
	return true, nil
}

// metaCoverageFromFile counts what the artifact's own digest recovered: named
// exports and local names are the resolved side, skipped readers the other.
// Without this a bare file always measured 0% even when symbols were read.
func metaCoverageFromFile(path string, cov *metaCoverage, unresolved *[]metaObligation) error {
	d, err := loadDigest(path)
	if err != nil {
		return err
	}
	local := metaLocalNames(d.Names)
	for _, s := range d.Skipped {
		*unresolved = append(*unresolved, metaObligation{
			Symbol:   s.Reason,
			Reason:   s.Detail,
			Evidence: "digest:skipped",
		})
	}
	cov.Source = "file"
	cov.Resolved = d.Exports + local
	cov.Basis["exports"] = d.Exports
	cov.Basis["local_names"] = local
	cov.Basis["skipped_readers"] = len(d.Skipped)
	cov.Note = strings.TrimSpace(cov.Note + fmt.Sprintf(" file mode: %d exported symbol(s) + %d recovered local name(s) read from the digest, %d skipped reader(s)", d.Exports, local, len(d.Skipped)))
	return nil
}

// metaLocalNames reads the count out of the digest's "local:<n>" names value;
// "not_recovered" and anything else count as zero.
func metaLocalNames(v string) int {
	rest, ok := strings.CutPrefix(v, "local:")
	if !ok {
		return 0
	}
	n, err := strconv.Atoi(rest)
	if err != nil || n < 0 {
		return 0
	}
	return n
}
