package main

import (
	"archive/tar"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// metaEnvManifest names every byte in an environment bundle. It carries no
// timestamp on purpose: two exports of the same inputs must hash the same.
type metaEnvManifest struct {
	Kind     string         `json:"kind"`
	Artifact string         `json:"artifact"`
	Entries  []metaEnvEntry `json:"entries"`
}

type metaEnvEntry struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
	Path   string `json:"path,omitempty"`
}

func init() {
	registerOp(op{
		name:  "export_environment_bundle",
		route: "L",
		needs: true,
		desc:  "Export a deterministic tar (manifest.json + artifact bytes, fixed mode/mtime, no owner) into -o (a FILE, or a DIR for <name>.env.tar); identical inputs give identical bytes, nothing is written beside the artifact.",
		run:   runExportEnvironmentBundle,
	})
}

func runExportEnvironmentBundle(path string) (any, error) {
	job, err := metaLoadJob(path)
	if err != nil {
		return nil, err
	}
	target := job.File
	if target == "" {
		target = path
	}
	abs, err := filepath.Abs(target)
	if err != nil {
		return nil, err
	}
	manifest := metaEnvManifest{Kind: "lrecon.env/1", Artifact: filepath.Base(abs)}
	type member struct {
		name string
		b    []byte
	}
	var members []member
	// One read per input, then the bytes serve both the hash and the tar: a
	// second stat+hash pass over the same file could disagree with the first
	// if something rewrote it in between.
	b, err := os.ReadFile(abs)
	if err != nil {
		return nil, err
	}
	members = append(members, member{"files/" + manifest.Artifact, b})
	manifest.Entries = append(manifest.Entries, metaEnvEntry{Name: "files/" + manifest.Artifact, SHA256: metaSHA256(b), Size: int64(len(b)), Path: abs})
	// A member name is what a tar reader lands on, so two inputs with the same
	// base name would collide: the second would shadow the first on extraction
	// while the manifest still listed both. Refuse the bundle instead of
	// shipping one that cannot be unpacked faithfully.
	seen := map[string]string{"files/" + manifest.Artifact: abs}
	for _, inc := range job.Include {
		incAbs, err := filepath.Abs(inc)
		if err != nil {
			return nil, err
		}
		name := "files/" + filepath.Base(incAbs)
		if prev, dup := seen[name]; dup {
			return nil, &opArgError{kindBadArg, fmt.Sprintf("include %s and %s both export as %s: one base name for two inputs is not supported", prev, incAbs, name)}
		}
		seen[name] = incAbs
		ib, err := os.ReadFile(incAbs)
		if err != nil {
			return nil, err
		}
		members = append(members, member{name, ib})
		manifest.Entries = append(manifest.Entries, metaEnvEntry{Name: name, SHA256: metaSHA256(ib), Size: int64(len(ib)), Path: incAbs})
	}
	man, err := metaCanonical(manifest)
	if err != nil {
		return nil, err
	}
	// -o names where the tar goes; the target's directory is not ours.
	dest, err := exportFileDest("export_environment_bundle", target, ".env.tar", job.State)
	if err != nil {
		return nil, err
	}
	if dir := filepath.Dir(dest); dir != "" {
		if _, err := metaMkdir(dir); err != nil {
			return nil, err
		}
	}
	// The tar is streamed into a temp file next to dest while the hash is
	// computed, so a bundle costs one pass and no second copy in memory.
	tmp, err := os.CreateTemp(filepath.Dir(dest), "."+filepath.Base(dest)+".tmp*")
	if err != nil {
		return nil, err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	defer tmp.Close()
	h := sha256.New()
	tw := tar.NewWriter(io.MultiWriter(tmp, h))
	if err := metaWriteTar(tw, "manifest.json", append(man, '\n'), 0o644); err != nil {
		return nil, err
	}
	for _, m := range members {
		if err := metaWriteTar(tw, m.name, m.b, 0o644); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := tmp.Sync(); err != nil {
		return nil, err
	}
	size := int64(0)
	if fi, err := tmp.Stat(); err == nil {
		size = fi.Size()
	}
	if err := tmp.Close(); err != nil {
		return nil, err
	}
	sum := fmt.Sprintf("%x", h.Sum(nil))
	result := map[string]any{
		"bundle":        dest,
		"bundle_sha256": sum,
		"bundle_size":   size,
		"manifest":      manifest,
		"deterministic": true,
	}
	// Create-only, like every derived artifact: the same bytes at dest are an
	// idempotent re-export, different bytes are a conflict. Nothing is
	// overwritten quietly.
	if fi, err := os.Stat(dest); err == nil {
		esum, err := metaFileSHA256(dest)
		if err != nil {
			return nil, err
		}
		if esum != sum || fi.Size() != size {
			return nil, fmt.Errorf("state conflict: %s already exists with different content; refusing to overwrite a different artifact", dest)
		}
		return result, nil
	}
	// shortcut: a writer can create dest between the check and the rename, and
	// rename would replace it. Export is single-writer per state root today;
	// upgrade to linkat/O_EXCL staging if two exporters ever share a root.
	if err := os.Rename(tmpName, dest); err != nil {
		return nil, err
	}
	return result, nil
}
