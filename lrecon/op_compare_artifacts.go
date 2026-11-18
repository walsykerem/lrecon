package main

import (
	"fmt"
	"os"
)

// metaSide is the identity half of a comparison: what each side is, independent
// of the diff.
type metaSide struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
	Kind   string `json:"kind"`
	Format string `json:"format"`
}

func metaSideOf(path string) (metaSide, Digest, error) {
	d, err := loadDigest(path)
	if err != nil {
		return metaSide{}, Digest{}, err
	}
	side := metaSide{Path: path, Kind: d.Kind, Format: d.Format, SHA256: d.Target.FileSHA256, Size: d.Target.Size}
	if d.Path == "" {
		// loadDigest leaves Path empty only when it read a saved --json digest.
		// Such a file describes another artifact, so hashing it would report the
		// digest's own bytes as the artifact identity (a digest of T compared with
		// T would then claim a different build).
		return side, d, nil
	}
	if fi, err := os.Stat(path); err == nil && !fi.IsDir() {
		sum, err := metaFileSHA256(path)
		if err != nil {
			return side, d, err
		}
		side.SHA256, side.Size = sum, fi.Size()
	}
	return side, d, nil
}

// metaComparePair is the job contract both compare ops share: "old" and "new"
// name the two sides (an artifact or a saved --json digest).
func metaComparePair(job metaJob) (metaSide, Digest, metaSide, Digest, error) {
	if job.Old == "" || job.New == "" {
		return metaSide{}, Digest{}, metaSide{}, Digest{}, fmt.Errorf("job needs \"old\" and \"new\" (each an artifact path or a saved digest json)")
	}
	aSide, a, err := metaSideOf(job.Old)
	if err != nil {
		return metaSide{}, Digest{}, metaSide{}, Digest{}, fmt.Errorf("old: %w", err)
	}
	bSide, b, err := metaSideOf(job.New)
	if err != nil {
		return metaSide{}, Digest{}, metaSide{}, Digest{}, fmt.Errorf("new: %w", err)
	}
	return aSide, a, bSide, b, nil
}

func init() {
	registerOp(op{
		name:  "compare_artifacts",
		route: "L",
		needs: true,
		desc:  "Diff two artifacts (job {\"old\",\"new\"}) field by field: each change names the exact digest json path with its before and after value, plus the two file identities.",
		run:   runCompareArtifacts,
	})
}

func runCompareArtifacts(path string) (any, error) {
	job, err := metaLoadJob(path)
	if err != nil {
		return nil, err
	}
	aSide, a, bSide, b, err := metaComparePair(job)
	if err != nil {
		return nil, fmt.Errorf("compare_artifacts: %w", err)
	}
	changes := metaChanges(a, b)
	return map[string]any{
		"old":       aSide,
		"new":       bSide,
		"changes":   changes,
		"count":     len(changes),
		"identical": len(changes) == 0,
	}, nil
}
