package main

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// 40. open_jeb_project — y6: a "project" is lrecon's own decoded directory.
// apktool writes into <dir>.tmp-<pid> and the finished tree is renamed into
// place, so a half-decoded directory never counts as a project. Freshness is
// the artifact itself: the APK's classes.dex sha256, kept next to the decoded
// tree, is compared before any work is redone.
func init() {
	registerOp(op{
		name:  "open_jeb_project",
		route: "Y",
		desc:  "apktool d <apk> -o <dir>.tmp-<pid> then atomic rename to <apk>.jebproj; reuses the dir while its classes.dex sha256 matches the APK's (final.md y6, item 40)",
		needs: true,
		run:   opOpenJebProject,
	})
}

const jebdProjectAlt = "install apktool and run `apktool d <apk> -o <dir>`; the decoded tree is produced by apktool itself, so there is no Go replacement (final.md y6)"

type jebdProject struct {
	Dir     string `json:"dir"`
	Fresh   bool   `json:"fresh"`
	Decoded bool   `json:"decoded"`
	// Engine names the decoder that actually built the tree: apktool, never JEB.
	Engine     string `json:"engine"`
	ClassesDEX string `json:"classes_dex_sha256"`
	Note       string `json:"note,omitempty"`
}

// jebProjectNote is the project-level sentence: apktool built the tree, and the
// op name must not imply JEB produced it.
func jebProjectNote(installed bool) string {
	if installed {
		return "JEB is installed but exposes no non-interactive project route; apktool d built this tree (final.md y2)"
	}
	return "JEB is not installed on this host; apktool d built this tree (final.md y2)"
}

// jebdMarkFile is the project's freshness marker: one sha256 over the APK
// entries apktool's output depends on.
const jebdMarkFile = "lrecon-apk.sha256"

// jebdAPKMark is that key. classes.dex alone let a manifest- or resource-only
// change reuse a stale tree, so the manifest and the resource table are hashed
// in too. The dex bytes come back because the project stores its own copy.
func jebdAPKMark(apk string) (mark, dexSum string, dex []byte, err error) {
	zr, err := zip.OpenReader(apk)
	if err != nil {
		return "", "", nil, fmt.Errorf("%s is not a readable APK zip: %w", apk, err)
	}
	defer zr.Close()
	// Every entry is part of the key: apktool copies unknown files (assets,
	// lib, META-INF) into the tree as well as decoding the manifest, the
	// resource table and every classes*.dex, so any changed entry makes the
	// tree stale. Sorting makes the key a function of the entries, not of the
	// zip's central-directory order.
	files := append([]*zip.File(nil), zr.File...)
	sort.Slice(files, func(i, j int) bool { return files[i].Name < files[j].Name })
	h := sha256.New()
	for _, f := range files {
		rc, err := f.Open()
		if err != nil {
			return "", "", nil, err
		}
		b, err := io.ReadAll(io.LimitReader(rc, opMaxFile))
		rc.Close()
		if err != nil {
			return "", "", nil, err
		}
		fmt.Fprintf(h, "%s:%d\n", f.Name, len(b))
		h.Write(b)
		if f.Name != "classes.dex" {
			continue
		}
		if len(b) == 0 {
			return "", "", nil, fmt.Errorf("%s carries an empty classes.dex", apk)
		}
		dex = b
		s := sha256.Sum256(b)
		dexSum = hex.EncodeToString(s[:])
	}
	if dex == nil {
		return "", "", nil, fmt.Errorf("%s has no classes.dex entry", apk)
	}
	return hex.EncodeToString(h.Sum(nil)), dexSum, dex, nil
}

func opOpenJebProject(target string) (any, error) {
	if !rt2Installed("apktool") {
		return skipf("apktool not installed: %s", jebdProjectAlt), nil
	}
	mark, sum, dex, err := jebdAPKMark(target)
	if err != nil {
		return nil, err
	}
	dir := target + ".jebproj"
	if projMark, err := os.ReadFile(filepath.Join(dir, jebdMarkFile)); err == nil && strings.TrimSpace(string(projMark)) == mark {
		return jebdProject{Dir: dir, Fresh: true, Engine: "apktool", ClassesDEX: sum,
			Note: "manifest, resources and classes.dex unchanged; project reused without re-decoding"}, nil
	}
	tmp := dir + ".tmp-" + strconv.Itoa(os.Getpid())
	if _, err := os.Stat(tmp); err == nil {
		return nil, fmt.Errorf("temp project dir %s already exists; remove it and retry", tmp)
	}
	if _, sk, err := rt2RunTimeout("apktool", jebdProjectAlt, rt2APKTimeout(), "d", target, "-o", tmp); sk != nil || err != nil {
		// A failed decode must not leave the temp tree behind: the next call
		// refuses a temp dir that already exists, so a crash mid-decode would
		// otherwise poison the project forever.
		os.RemoveAll(tmp)
		return sk, err
	}
	st, err := os.Stat(tmp)
	if err != nil || !st.IsDir() {
		os.RemoveAll(tmp)
		return nil, fmt.Errorf("apktool exited 0 but created no project dir at %s", tmp)
	}
	if err := os.WriteFile(filepath.Join(tmp, "classes.dex"), dex, 0o644); err != nil {
		os.RemoveAll(tmp)
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(tmp, jebdMarkFile), []byte(mark+"\n"), 0o644); err != nil {
		os.RemoveAll(tmp)
		return nil, err
	}
	// Rename the stale tree aside first: rename(2) refuses a non-empty target,
	// and this way <dir> is either the old project or the new one, never half.
	old := ""
	if _, err := os.Stat(dir); err == nil {
		old = dir + ".old-" + strconv.Itoa(os.Getpid())
		if err := os.Rename(dir, old); err != nil {
			return nil, err
		}
	}
	if err := os.Rename(tmp, dir); err != nil {
		if old != "" {
			if rerr := os.Rename(old, dir); rerr != nil {
				// The old project is still on disk under .old-<pid>; say where,
				// because the caller now has no <dir> to reuse.
				return nil, fmt.Errorf("%w; the previous project could not be moved back from %s: %v", err, old, rerr)
			}
		}
		return nil, err
	}
	if old != "" {
		os.RemoveAll(old)
	}
	return jebdProject{Dir: dir, Fresh: false, Decoded: true, Engine: "apktool", ClassesDEX: sum,
		Note: jebProjectNote(jebInstalled())}, nil
}
