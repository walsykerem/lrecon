package main

import (
	"fmt"
	"strings"
)

func init() {
	registerOp(op{
		name:  "verify_unknown_resolution",
		route: "L",
		needs: true,
		desc:  "Re-read the bytes at a recorded unknown's address and check them against the stored bytes and the recorded resolution; verified is true only when both agree, and state is written only on a passed verification (never with apply:false).",
		run:   runVerifyUnknownResolution,
	})
}

// metaNormResolution is the comparison form of a resolution sentence. Case,
// surrounding space, runs of whitespace and trailing punctuation do not make
// two answers different; the words do. Exact-after-normalization keeps the
// check machine-checkable: it either agrees or it does not.
func metaNormResolution(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.Join(strings.Fields(s), " ")
	return strings.TrimRight(s, ".;:, ")
}

func metaSameResolution(a, b string) bool {
	na, nb := metaNormResolution(a), metaNormResolution(b)
	return na != "" && na == nb
}

// metaWantedResolution picks the job's resolution claim. Both spellings are
// accepted; two different claims are a bad argument, not a coin toss.
func metaWantedResolution(job metaJob) (string, error) {
	a, b := strings.TrimSpace(job.Resolution), strings.TrimSpace(job.ResolvedAs)
	switch {
	case a == "" && b == "":
		return "", nil
	case a == "":
		return b, nil
	case b == "" || metaSameResolution(a, b):
		return a, nil
	}
	return "", fmt.Errorf("verify_unknown_resolution: \"resolution\" and \"resolved_as\" disagree (%q vs %q); the job must be one resolution, not two", a, b)
}

func runVerifyUnknownResolution(path string) (any, error) {
	job, err := opLoadJob(path)
	if err != nil {
		return nil, err
	}
	if job.Address == "" {
		return nil, fmt.Errorf("verify_unknown_resolution: job needs \"address\"")
	}
	wanted, err := metaWantedResolution(job)
	if err != nil {
		return nil, err
	}
	root, err := metaStateRoot(path, job)
	if err != nil {
		return nil, err
	}
	file, err := metaStateFile(root, "unknowns.json")
	if err != nil {
		return nil, err
	}
	var st metaUnknownState
	exists, err := metaReadState(file, metaUnknownsKind, &st)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, fmt.Errorf("verify_unknown_resolution: no unknowns recorded in %s", root)
	}
	var rec *metaUnknown
	for i := range st.Unknowns {
		if st.Unknowns[i].Address == job.Address {
			rec = &st.Unknowns[i]
			break
		}
	}
	if rec == nil {
		return nil, fmt.Errorf("verify_unknown_resolution: no unknown at %s in %s", job.Address, file)
	}
	// apply:false makes the op read-only: it reports, it does not record.
	apply := job.Apply == nil || *job.Apply
	res := map[string]any{
		"address":    rec.Address,
		"hypothesis": rec.Hypothesis,
		"resolution": rec.Resolution,
		"resolved":   rec.Resolved,
		"expected":   rec.Bytes,
		"apply":      apply,
		"persisted":  false,
	}
	if wanted != "" {
		res["claimed_resolution"] = wanted
	}
	if job.File == "" {
		res["verified"] = false
		res["note"] = "no binary supplied: the recorded bytes cannot be re-read"
		return res, nil
	}
	if rec.Bytes == "" {
		res["verified"] = false
		res["note"] = "recorded entry has no bytes to compare"
		return res, nil
	}
	want, err := metaHexBytes(rec.Bytes)
	if err != nil {
		return nil, err
	}
	addr, err := metaParseAddr(rec.Address)
	if err != nil {
		return nil, err
	}
	place, err := metaLocate(job.File, addr)
	if err != nil {
		return nil, err
	}
	res["section"] = place.Section
	res["file_offset"] = place.Offset
	if !place.Exact {
		res["verified"] = false
		res["note"] = "address is not inside a mapped section of " + job.File
		return res, nil
	}
	got := readFileAt(job.File, place.Offset, int64(len(want)))
	if got == nil {
		res["verified"] = false
		res["note"] = "recorded bytes lie outside the file"
		return res, nil
	}
	res["actual"] = metaHex(got)
	bytesOK := metaHex(got) == metaHex(want)
	res["bytes_verified"] = bytesOK
	res["verified"] = bytesOK

	// The resolution is a second claim, and it is checked against the recorded
	// answer, never written past a disagreement.
	mismatch := false
	if wanted != "" {
		if rec.Resolution != "" {
			mismatch = !metaSameResolution(wanted, rec.Resolution)
			res["resolution_match"] = !mismatch
		} else {
			// Nothing recorded yet: the job supplies the first answer.
			res["resolution_match"] = "unrecorded"
		}
	}
	if !bytesOK {
		res["note"] = "bytes at the address do not match the recorded bytes; nothing recorded"
		return res, nil
	}
	if mismatch {
		res["verified"] = false
		res["note"] = fmt.Sprintf("resolution %q does not match the recorded %q; nothing recorded", wanted, rec.Resolution)
		return res, nil
	}
	if wanted == "" {
		res["note"] = "no resolution in the job: bytes re-read only, nothing recorded"
		return res, nil
	}
	if !apply {
		res["note"] = "apply is false: verified, nothing written"
		return res, nil
	}
	rec.Resolution, rec.Resolved = wanted, true
	if err := metaWriteJSON(file, st); err != nil {
		return nil, err
	}
	res["resolution"], res["resolved"], res["persisted"] = rec.Resolution, rec.Resolved, true
	return res, nil
}
