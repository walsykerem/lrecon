package main

import (
	"encoding/json"
	"errors"
	"os"
	"strconv"
)

func init() {
	registerOp(op{
		name:  "get_evidence_bundle",
		route: "L",
		needs: true,
		desc:  "Read an exported evidence bundle back, verifying its attestation; a job's \"file\" names the bundle (or the artifact whose .evidence.json should be read).",
		run:   runGetEvidenceBundle,
	})
}

func runGetEvidenceBundle(path string) (any, error) {
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
		// A corrupt bundle is a refusal, never a lookup: substituting a
		// sibling <path>.evidence.json here would report some other file as
		// verified. Only a non-bundle target (an artifact path) falls back.
		if _, ok := errors.AsType[*metaAttestationError](err); ok {
			return nil, err
		}
		alt := p + ".evidence.json"
		w2, raw2, err2 := metaReadEvidenceFile(alt)
		if err2 != nil {
			return nil, err
		}
		p, w, raw = alt, w2, raw2
	}
	out := map[string]any{
		"bundle_file":   p,
		"bundle":        w.Bundle,
		"attestation":   w.Attestation,
		"verified":      true,
		"bundle_sha256": metaSHA256(raw),
		"cap_bytes":     evidenceBundleCap(),
	}
	return capEvidenceBundle(out)
}

// evidenceBundleCapDefault keeps one bundle inside a single readable answer.
// A bundle over the cap is spilled whole to a temp file and the answer becomes
// a pointer: verified and hashed, but not inline, so a caller cannot mistake a
// truncated blob for the whole bundle. The spill is a temp file, never a write
// beside the target: this op is read-only (-o is refused for it), and an op
// that writes a file is told where by -o (op_export_evidence_bundle.go:11-25).
const evidenceBundleCapDefault = 5 << 20

func evidenceBundleCap() int {
	if v := os.Getenv("LRECON_BUNDLE_CAP_BYTES"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return evidenceBundleCapDefault
}

func capEvidenceBundle(out map[string]any) (any, error) {
	capBytes := evidenceBundleCap()
	b, err := json.Marshal(out)
	if err != nil || len(b) <= capBytes {
		return out, nil
	}
	src, _ := out["bundle_file"].(string)
	f, err := os.CreateTemp("", "lrecon-bundle-*.json")
	if err != nil {
		return nil, err
	}
	dst := f.Name()
	if _, err := f.Write(b); err != nil {
		f.Close()
		os.Remove(dst)
		return nil, err
	}
	if err := f.Close(); err != nil {
		os.Remove(dst)
		return nil, err
	}
	return map[string]any{
		"bundle_file":   src,
		"written_to":    dst,
		"bytes":         len(b),
		"cap_bytes":     capBytes,
		"verified":      out["verified"],
		"bundle_sha256": out["bundle_sha256"],
		"incomplete":    false,
		"basis":         "bundle over the in-line cap spilled whole to written_to (temp file, not beside the target); export_evidence_bundle -o writes a durable copy; cap_bytes reflects LRECON_BUNDLE_CAP_BYTES when set",
		"coverage":      "complete-in-file",
	}, nil
}
