// final.md R13/R1: the two adversarial checks that keep a verification honest.
//
// verify_target_immutability re-reads the artifact after a digest was taken and
// compares it with the recorded hash, so a claim about bytes that changed under
// the analysis is a mismatch, not a stale pass. verify_output_equivalence puts
// the original and the reconstruction through the same hash, so "reconstructed"
// is a byte-level claim and not a resemblance.

package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"
)

func init() {
	registerOp(op{
		name:  "verify_target_immutability",
		route: "L",
		needs: true,
		desc:  "Re-hash the target and compare it with the recorded digest (job {\"file\",\"expect\"}: a sha256 hex or a saved --json digest); match false is mutated true with the target-mutated caveat.",
		run:   runVerifyTargetImmutability,
	})
	registerOp(op{
		name:  "verify_output_equivalence",
		route: "L",
		needs: true,
		desc:  "Hash both sides of a reconstruction (job {\"old\",\"new\"}) and report byte equivalence; a divergence carries the equivalence-diverged caveat.",
		run:   runVerifyOutputEquivalence,
	})
}

// advFileSHA256 is the byte identity of one side, hashed twice: hashTargetN
// refuses a short read and the second stat catches an in-place rewrite of the
// same length, the two ways a moving target used to pass as a stable one.
func advFileSHA256(path string) (Target, os.FileInfo, error) {
	st, err := os.Stat(path)
	if err != nil {
		return Target{}, nil, err
	}
	if st.IsDir() {
		return Target{}, nil, fmt.Errorf("%s is a directory: a byte hash needs a file", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return Target{}, nil, err
	}
	defer f.Close()
	t, err := hashTargetN(f, st.Size(), st.Size(), nil)
	if err != nil {
		return Target{}, nil, err
	}
	st2, err := os.Stat(path)
	if err != nil {
		return Target{}, nil, err
	}
	if st2.Size() != st.Size() || !st2.ModTime().Equal(st.ModTime()) {
		return Target{}, nil, fmt.Errorf("%s: cannot hash a moving target (size %d -> %d, mtime changed)", path, st.Size(), st2.Size())
	}
	return t, st, nil
}

// advRecordedSHA256 resolves the recorded side: a hash literal, or a saved
// --json digest whose target.file_sha256 is the recorded identity.
func advRecordedSHA256(expect string) (string, error) {
	expect = strings.TrimSpace(expect)
	if expect == "" {
		return "", fmt.Errorf("job needs \"expect\" (recorded sha256 hex or a saved digest json)")
	}
	if b, err := hex.DecodeString(expect); err == nil && len(b) == 32 {
		return strings.ToLower(expect), nil
	}
	d, err := loadDigest(expect)
	if err != nil {
		return "", err
	}
	if d.Target.FileSHA256 == "" {
		return "", fmt.Errorf("%s records no file_sha256", expect)
	}
	return strings.ToLower(d.Target.FileSHA256), nil
}

func runVerifyTargetImmutability(path string) (any, error) {
	job, err := opLoadJob(path)
	if err != nil {
		return nil, err
	}
	target := job.File
	if target == "" {
		target = path
	}
	recorded, err := advRecordedSHA256(job.Expect)
	if err != nil {
		return nil, fmt.Errorf("verify_target_immutability: %w", err)
	}
	t, st, err := advFileSHA256(target)
	if err != nil {
		return nil, err
	}
	match := t.HashScope == "whole-file" && t.FileSHA256 == recorded
	notes := []string{}
	if !match {
		notes = append(notes, "target-mutated")
	}
	return map[string]any{
		"file":            target,
		"target_sha256":   t.FileSHA256,
		"recorded_sha256": recorded,
		"match":           match,
		"mutated":         !match,
		"size":            st.Size(),
		"mtime":           st.ModTime().UTC().Format(time.RFC3339Nano),
		"hash_scope":      t.HashScope,
		"notes":           notes,
	}, nil
}

func runVerifyOutputEquivalence(path string) (any, error) {
	job, err := opLoadJob(path)
	if err != nil {
		return nil, err
	}
	if job.Old == "" || job.New == "" {
		return nil, fmt.Errorf("verify_output_equivalence: job needs \"old\" and \"new\" (original and reconstruction)")
	}
	a, _, err := advFileSHA256(job.Old)
	if err != nil {
		return nil, fmt.Errorf("verify_output_equivalence: original: %w", err)
	}
	b, _, err := advFileSHA256(job.New)
	if err != nil {
		return nil, fmt.Errorf("verify_output_equivalence: reconstruction: %w", err)
	}
	equivalent := a.HashScope == b.HashScope && a.FileSHA256 == b.FileSHA256
	notes := []string{}
	if !equivalent {
		notes = append(notes, "equivalence-diverged")
	}
	return map[string]any{
		"original":             job.Old,
		"reconstructed":        job.New,
		"original_sha256":      a.FileSHA256,
		"reconstructed_sha256": b.FileSHA256,
		"equivalent":           equivalent,
		"notes":                notes,
	}, nil
}
