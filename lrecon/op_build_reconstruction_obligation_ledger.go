package main

import (
	"fmt"
	"path/filepath"
	"strings"
)

// metaLedger is `obligations.json`: every piece of the artifact the readers did
// not explain, with the reason and where it was left open.
type metaLedger struct {
	Kind     string           `json:"kind"`
	Artifact string           `json:"artifact"`
	SHA256   string           `json:"sha256"`
	Rows     []metaObligation `json:"rows"`
	ByReason map[string]int   `json:"by_reason"`
	Updated  string           `json:"updated"`
}

const metaLedgerKind = "lrecon.obligations/1"

func init() {
	registerOp(op{
		name:  "build_reconstruction_obligation_ledger",
		route: "L",
		needs: true,
		desc:  "Build the obligation ledger (unresolved symbols, each with a reason) from a job's rows or from the artifact's own skipped-reader list, and persist it to <state>/obligations.json.",
		run:   runBuildLedger,
	})
}

func runBuildLedger(path string) (any, error) {
	job, err := metaLoadJob(path)
	if err != nil {
		return nil, err
	}
	target := job.File
	if target == "" {
		target = path
	}
	sum, _, err := metaObjectSHA(target)
	if err != nil {
		return nil, err
	}
	rows := job.Unresolved
	if len(rows) == 0 {
		d, err := loadDigest(target)
		if err != nil {
			return nil, err
		}
		base := filepath.Base(target)
		for i, s := range d.Skipped {
			rows = append(rows, metaObligation{
				Symbol:   s.Reason,
				Reason:   s.Detail,
				Evidence: fmt.Sprintf("digest:%s skipped[%d]", base, i),
				Owner:    "reader:" + strings.SplitN(s.Reason, "-", 2)[0],
			})
		}
	}
	if rows == nil {
		rows = []metaObligation{}
	}
	byReason := map[string]int{}
	for _, r := range rows {
		reason := r.Reason
		if reason == "" {
			reason = "unstated"
		}
		byReason[reason]++
	}
	ledger := metaLedger{Kind: metaLedgerKind, Artifact: target, SHA256: sum, Rows: rows, ByReason: byReason, Updated: metaNow()}
	root, err := metaStateRoot(path, job)
	if err != nil {
		return nil, err
	}
	file, err := metaStateFile(root, "obligations.json")
	if err != nil {
		return nil, err
	}
	// A ledger is per artifact: a second artifact in the same state dir is a
	// conflict, not an overwrite. Same artifact rebuilds in place.
	var prev metaLedger
	exists, err := metaReadState(file, metaLedgerKind, &prev)
	if err != nil {
		return nil, err
	}
	if exists && prev.SHA256 != "" && prev.SHA256 != sum {
		return nil, fmt.Errorf("state conflict: %s already holds the ledger for %s (sha256 %s), refusing to replace it with %s (%s)", file, prev.Artifact, prev.SHA256, target, sum)
	}
	if err := metaWriteJSON(file, ledger); err != nil {
		return nil, err
	}
	return map[string]any{
		"ledger":           ledger,
		"count":            len(rows),
		"replaced":         exists,
		"obligations_file": file,
	}, nil
}
