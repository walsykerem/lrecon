package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// --- output paths: -o, and only -o ---
//
// These ops used to derive their output path from the target, so exporting
// /bin/ls tried /bin/.ls.evidence.json.tmp* and an analysis dirtied the tree it
// was reading. The rule now: an op that writes a file or a tree is told where
// by -o, and the target's directory is never a default.
//
//	-o FILE   a one-file op writes exactly that file
//	-o DIR    a one-file op writes DIR/<target base><suffix>
//	-o DIR    a tree op writes the tree under DIR itself
//
// The CLI refuses a writing op without -o (needs_arg, exit 2) before the op
// runs, so not one byte is created. An in-process caller (a test, an embedder)
// still gets a place to write: a fresh directory under the system temp dir, or
// the job's explicit "state" root. The CLI reaches neither.

// opOutput is the -o value of the running --op call. main sets it once; every
// writing op reads it through exportFileDest/exportDirDest.
var opOutput string

// opWritesOutput says which ops write, and what -o may name for them. A writing
// op without -o, or a read-only op with it, is a bad call: exit 2, nothing
// written to disk or stdout.
var opWritesOutput = map[string]string{
	"export_evidence_bundle":    "FILE|DIR",
	"export_environment_bundle": "FILE|DIR",
	"export_web_scripts":        "DIR",
	"extract_firmware":          "DIR",
	"extract_artifact":          "DIR",
	"pull_adb_package":          "DIR",
}

// opArgError is a refusal about the call itself, not the target's file. The
// class is the machine-readable part: needs_arg when a required argument is
// missing, bad_arg when it is present but wrong.
type opArgError struct {
	kind errorKind
	msg  string
}

// Error returns the bare message: the CLI classifies a run error from its text
// (classify in errors.go), so a "bad_arg: " prefix here would make every
// in-run argument refusal come back as kind "internal". Each message below
// names its class in prose ("must be", "is not", "not supported") for that.
func (e *opArgError) Error() string { return e.msg }

// checkOpOutput is the CLI gate in front of --op. A writing op without -o is
// unanswerable, and -o on a read-only op would be silently dropped while the
// caller waits for a file.
func checkOpOutput(name, out string) error {
	if name == "" {
		return nil // -o is the digest destination on the plain path
	}
	spec, writes := opWritesOutput[name]
	if !writes {
		if strings.TrimSpace(out) != "" {
			return &opArgError{kindBadArg, fmt.Sprintf("-o does not apply to --op %q: its result goes to stdout and is not written to a file", name)}
		}
		return nil
	}
	if strings.TrimSpace(out) == "" {
		return &opArgError{kindNeedsArg, fmt.Sprintf("--op %q writes %s and needs -o %s; without it nothing is written beside the target", name, spec, spec)}
	}
	return nil
}

// exportFileDest is the destination of a one-file op: -o FILE, or -o DIR plus
// the target's base name and the op's suffix. state is a job's explicit state
// root, honored only when -o is absent.
func exportFileDest(op, target, suffix, state string) (string, error) {
	if strings.TrimSpace(opOutput) == "" && state != "" {
		root, err := metaMkdir(state)
		if err != nil {
			return "", err
		}
		abs, err := filepath.Abs(target)
		if err != nil {
			return "", err
		}
		return filepath.Join(root, filepath.Base(abs)+suffix), nil
	}
	return exportDest(op, target, suffix, false)
}

// exportDirDest is the destination of a tree op: -o DIR names the tree root.
func exportDirDest(op, target string) (string, error) {
	return exportDest(op, target, "", true)
}

func exportDest(op, target, suffix string, tree bool) (string, error) {
	abs, err := filepath.Abs(target)
	if err != nil {
		return "", err
	}
	out := strings.TrimSpace(opOutput)
	if out == "" {
		// An in-process caller with no -o gets a fresh directory under the
		// system temp dir, never in the caller's working directory and never
		// beside the target. The CLI refuses such a call outright, so this path
		// is only reached from package tests and library callers. The startup
		// sweeper removes these once they are an hour old.
		dir, err := tempDir("lrecon-" + op + "-")
		if err != nil {
			return "", err
		}
		if tree {
			return dir, nil
		}
		return filepath.Join(dir, filepath.Base(abs)+suffix), nil
	}
	dest, err := filepath.Abs(out)
	if err != nil {
		return "", err
	}
	if fi, err := os.Stat(dest); err == nil {
		switch {
		case fi.IsDir() && !tree:
			dest = filepath.Join(dest, filepath.Base(abs)+suffix)
		case fi.IsDir():
			// -o names the tree root itself.
		case tree:
			return "", &opArgError{kindBadArg, fmt.Sprintf("-o %s names a file, but --op %s writes a directory: -o must be a directory", out, op)}
		}
	}
	if dest == abs {
		return "", &opArgError{kindBadArg, fmt.Sprintf("-o %s is not a usable destination: it would overwrite the artifact this op reads", out)}
	}
	// The string compare above misses a symlink or a hardlink to the artifact:
	// os.Stat follows both, and a destination that is the same file would make
	// the export read bytes it is about to replace.
	if src, err := os.Stat(abs); err == nil {
		if fi, err := os.Stat(dest); err == nil && os.SameFile(fi, src) {
			return "", &opArgError{kindBadArg, fmt.Sprintf("-o %s is not a usable destination: it is the same file as the artifact this op reads", out)}
		}
	}
	return dest, nil
}

// metaEvidence is the bundle body: what the artifact is, the digest fields an
// agent would otherwise re-read the file for, and the evidence pointer that
// makes the fields verifiable.
type metaEvidence struct {
	Kind      string   `json:"kind"`
	Artifact  string   `json:"artifact"`
	SHA256    string   `json:"sha256"`
	Size      int64    `json:"size"`
	ArtKind   string   `json:"artifact_kind,omitempty"`
	Toolchain string   `json:"toolchain,omitempty"`
	Symbols   string   `json:"symbols,omitempty"`
	Names     string   `json:"names,omitempty"`
	Coverage  string   `json:"coverage,omitempty"`
	Claims    []string `json:"claims,omitempty"`
	Notes     []string `json:"notes,omitempty"`
	Evidence  string   `json:"evidence"`
}

// metaEvidenceWrapper is the on-disk shape: the bundle plus a sha256 over its
// canonical JSON, so a hand-edited field is caught on import instead of read.
type metaEvidenceWrapper struct {
	Bundle      metaEvidence `json:"bundle"`
	Attestation string       `json:"attestation"`
}

func init() {
	registerOp(op{
		name:  "export_evidence_bundle",
		route: "L",
		needs: true,
		desc:  "Export a self-verifying evidence bundle (artifact identity, digest symbols/names/claims/notes, evidence pointer, attestation) into -o (a FILE, or a DIR for <name>.evidence.json); writes nothing beside the artifact.",
		run:   runExportEvidenceBundle,
	})
}

func metaBuildEvidence(target string) (metaEvidenceWrapper, []byte, error) {
	abs, err := filepath.Abs(target)
	if err != nil {
		return metaEvidenceWrapper{}, nil, err
	}
	sum, size, err := metaObjectSHA(abs)
	if err != nil {
		return metaEvidenceWrapper{}, nil, err
	}
	d, err := loadDigest(abs)
	if err != nil {
		return metaEvidenceWrapper{}, nil, err
	}
	ev := metaEvidence{
		Kind:      "lrecon.evidence/1",
		Artifact:  abs,
		SHA256:    sum,
		Size:      size,
		ArtKind:   d.Kind,
		Toolchain: d.Toolchain,
		Symbols:   d.Symbols,
		Names:     d.Names,
		Coverage:  d.coverageClaim(),
		Notes:     d.Notes,
	}
	for _, c := range d.Claims {
		ev.Claims = append(ev.Claims, fmt.Sprintf("%s (%s @%#x)", c.Value, c.Source, c.ByteOffset))
	}
	line, err := evidenceLine(d)
	if err != nil {
		return metaEvidenceWrapper{}, nil, err
	}
	ev.Evidence = strings.TrimSpace(line)
	canon, err := metaCanonical(ev)
	if err != nil {
		return metaEvidenceWrapper{}, nil, err
	}
	w := metaEvidenceWrapper{Bundle: ev, Attestation: "sha256:" + metaSHA256(canon)}
	file, err := metaCanonical(w)
	if err != nil {
		return metaEvidenceWrapper{}, nil, err
	}
	return w, append(file, '\n'), nil
}

func runExportEvidenceBundle(path string) (any, error) {
	job, err := metaLoadJob(path)
	if err != nil {
		return nil, err
	}
	target := job.File
	if target == "" {
		target = path
	}
	w, b, err := metaBuildEvidence(target)
	if err != nil {
		return nil, err
	}
	// -o names where the bundle goes; the target's directory is not ours.
	dest, err := exportFileDest("export_evidence_bundle", target, ".evidence.json", job.State)
	if err != nil {
		return nil, err
	}
	if err := metaCreateBytes(dest, b); err != nil {
		return nil, err
	}
	return map[string]any{
		"bundle_file":   dest,
		"bundle":        w.Bundle,
		"attestation":   w.Attestation,
		"bundle_sha256": metaSHA256(b),
	}, nil
}

// metaAttestationError is a bundle whose bytes do not match its own
// attestation. It is a distinct class from "not a bundle": a caller may fall
// back to <path>.evidence.json for a non-bundle target, but must never answer
// with a sibling file after the named bundle failed verification.
type metaAttestationError struct {
	File    string
	Claimed string
	Actual  string
}

func (e *metaAttestationError) Error() string {
	return fmt.Sprintf("%s: attestation mismatch: the file does not carry the digest it claims (%q), content hashes to %q", e.File, e.Claimed, e.Actual)
}

// metaReadEvidenceFile verifies the attestation before returning anything: an
// unverifiable bundle is an error, not a partial answer.
func metaReadEvidenceFile(file string) (metaEvidenceWrapper, []byte, error) {
	var w metaEvidenceWrapper
	b, err := os.ReadFile(file)
	if err != nil {
		return w, nil, err
	}
	if err := json.Unmarshal(b, &w); err != nil {
		return w, nil, fmt.Errorf("%s: not an evidence bundle: %v", file, err)
	}
	if w.Bundle.Kind == "" {
		return w, nil, fmt.Errorf("%s: not an evidence bundle (no bundle object)", file)
	}
	canon, err := metaCanonical(w.Bundle)
	if err != nil {
		return w, nil, err
	}
	if want := "sha256:" + metaSHA256(canon); w.Attestation != want {
		return w, nil, &metaAttestationError{File: file, Claimed: w.Attestation, Actual: want}
	}
	return w, b, nil
}
