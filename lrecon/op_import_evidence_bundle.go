package main

import "os"

func init() {
	registerOp(op{
		name:  "import_evidence_bundle",
		route: "L",
		needs: true,
		desc:  "Import an evidence bundle: verify its attestation, then check the recorded artifact sha256 against the file on disk (job \"file\" = bundle, optional \"expect\" = artifact path).",
		run:   runImportEvidenceBundle,
	})
}

func runImportEvidenceBundle(path string) (any, error) {
	job, err := metaLoadJob(path)
	if err != nil {
		return nil, err
	}
	p := job.File
	if p == "" {
		p = path
	}
	w, raw, err := metaReadEvidenceFile(p)
	if err != nil {
		return nil, err
	}
	res := map[string]any{
		"bundle_file":      p,
		"bundle":           w.Bundle,
		"attestation":      w.Attestation,
		"verified":         true,
		"bundle_sha256":    metaSHA256(raw),
		"artifact_checked": false,
	}
	artifact := w.Bundle.Artifact
	if job.Expect != "" {
		artifact = job.Expect
	}
	if artifact == "" {
		return res, nil
	}
	if _, err := os.Stat(artifact); err != nil {
		res["artifact_checked"] = false
		res["artifact_note"] = "recorded artifact is not on disk: " + artifact
		return res, nil
	}
	sum, size, err := metaObjectSHA(artifact)
	if err != nil {
		return nil, err
	}
	res["artifact_checked"] = true
	res["artifact"] = artifact
	res["artifact_sha256"] = sum
	res["size_match"] = size == w.Bundle.Size
	res["artifact_match"] = sum == w.Bundle.SHA256
	// Attestation verified is not artifact verified: a drifted or resized
	// artifact must not import as a verified bundle.
	if !res["artifact_match"].(bool) || !res["size_match"].(bool) {
		res["verified"] = false
	}
	if sum != w.Bundle.SHA256 {
		res["drift"] = "artifact bytes changed since the bundle was exported"
	}
	return res, nil
}
