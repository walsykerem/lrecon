package main

// Evergreen 09: the shipped binary must digest every Go source file the repo
// actually has, and nothing else. lrecon has no directory/corpus target
// (`lrecon --json DIR` refuses with "is a directory, not an app bundle"), so the
// tool's own enumeration is its supported single-target mode applied to each
// path git reports: whatever it digests successfully is its processed set.
//
// Truth set: `git ls-files` (.go, tracked plus untracked non-ignored). Each
// claimed digest must carry the whole-file SHA-256 and size of that exact file,
// so a claim always names bytes that exist. Set equality is checked in both
// directions, and the corpus size is floored so it cannot silently shrink.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
)

const ev09MinCorpus = 500

type ev09Target struct {
	Size   int64  `json:"size"`
	SHA256 string `json:"file_sha256"`
	Scope  string `json:"hash_scope"`
}

type ev09Digest struct {
	Kind      string     `json:"kind"`
	Target    ev09Target `json:"target"`
	Truncated bool       `json:"truncated"`
	Error     string     `json:"error"`
}

// errEv09Gone means the path vanished between git listing it and the probe; a
// sibling writer removing a file is not a coverage gap, so the caller drops it
// from the truth set instead of failing.
var errEv09Gone = errors.New("file gone")

func ev09GitGoFiles(t *testing.T, root string) []string {
	t.Helper()
	cmd := exec.Command("git", "-C", root, "ls-files", "-z", "--cached", "--others", "--exclude-standard", "--", "*.go")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git ls-files: %v", err)
	}
	seen := map[string]bool{}
	var paths []string
	for _, p := range strings.Split(string(out), "\x00") {
		if p == "" {
			continue
		}
		rel := strings.TrimPrefix(filepath.ToSlash(filepath.Clean(p)), "./")
		if seen[rel] {
			continue
		}
		seen[rel] = true
		paths = append(paths, rel)
	}
	sort.Strings(paths)
	return paths
}

func ev09Probe(bin, root, rel string) error {
	abs := filepath.Join(root, filepath.FromSlash(rel))
	b, err := os.ReadFile(abs)
	if err != nil {
		if os.IsNotExist(err) {
			return errEv09Gone
		}
		return fmt.Errorf("%s: read: %v", rel, err)
	}
	out, err := exec.Command(bin, "--json", abs).Output()
	if err != nil {
		return fmt.Errorf("%s: digest failed: %v", rel, err)
	}
	var d ev09Digest
	if err := json.Unmarshal(out, &d); err != nil {
		return fmt.Errorf("%s: digest is not JSON: %v", rel, err)
	}
	if d.Error != "" {
		return fmt.Errorf("%s: digest error: %s", rel, d.Error)
	}
	if d.Kind == "" {
		return fmt.Errorf("%s: digest claims no kind", rel)
	}
	if d.Truncated {
		return fmt.Errorf("%s: digest is truncated, the file was not fully processed", rel)
	}
	sum := sha256.Sum256(b)
	if want := hex.EncodeToString(sum[:]); d.Target.SHA256 != want {
		return fmt.Errorf("%s: claimed sha256 %s, file is %s", rel, d.Target.SHA256, want)
	}
	if d.Target.Size != int64(len(b)) {
		return fmt.Errorf("%s: claimed size %d, file is %d", rel, d.Target.Size, len(b))
	}
	if d.Target.Scope != "whole-file" {
		return fmt.Errorf("%s: hash scope %q, want whole-file", rel, d.Target.Scope)
	}
	return nil
}

func TestEvergreen09InventorySetEquality(t *testing.T) {
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatalf("repo root: %v", err)
	}
	bin := filepath.Join(root, "lrecon", "lrecon")
	if fi, err := os.Stat(bin); err != nil || fi.Mode()&0o111 == 0 {
		t.Fatalf("%s is not an executable binary: %v", bin, err)
	}

	truth := ev09GitGoFiles(t, root)
	if len(truth) <= ev09MinCorpus {
		t.Fatalf("corpus shrank: git reports %d .go files, want more than %d", len(truth), ev09MinCorpus)
	}

	// A set that claims everything must not be mistaken for coverage: paths that
	// do not name a file have to be refused, so a green run means real files.
	for _, p := range []string{filepath.Join(root, "lrecon", "no-such-file.go"), filepath.Join(root, "lrecon", "testdata")} {
		if out, err := exec.Command(bin, "--json", p).Output(); err == nil {
			t.Fatalf("%s: claimed to process %s; a claim without bytes proves nothing", bin, p)
		} else if len(out) > 0 {
			var d ev09Digest
			if json.Unmarshal(out, &d) == nil && d.Kind != "" && d.Error == "" {
				t.Fatalf("%s: claimed kind %q for %s", bin, d.Kind, p)
			}
		}
	}

	workers := runtime.NumCPU()
	if workers > 8 {
		workers = 8
	}
	errs := make([]error, len(truth))
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	for i, rel := range truth {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, rel string) {
			defer wg.Done()
			defer func() { <-sem }()
			errs[i] = ev09Probe(bin, root, rel)
		}(i, rel)
	}
	wg.Wait()

	processed := make(map[string]bool, len(truth))
	var failures []string
	var gone []string
	for i, rel := range truth {
		switch {
		case errs[i] == nil:
			processed[rel] = true
		case errors.Is(errs[i], errEv09Gone):
			gone = append(gone, rel)
		default:
			failures = append(failures, errs[i].Error())
		}
	}
	if len(gone) > 0 {
		kept := truth[:0]
		for _, rel := range truth {
			if _, dropped := processed[rel]; dropped || !ev09Contains(gone, rel) {
				kept = append(kept, rel)
			}
		}
		truth = kept
	}
	if len(failures) > 0 {
		sort.Strings(failures)
		if len(failures) > 10 {
			failures = failures[:10]
		}
		t.Fatalf("%d of %d .go files were not processed: %s", len(failures), len(truth), strings.Join(failures, "; "))
	}

	// Set equality, both directions: nothing claimed that does not exist (every
	// claim matched a real file's bytes above), nothing existing unprocessed.
	var missing []string
	for _, rel := range truth {
		if !processed[rel] {
			missing = append(missing, rel)
		}
	}
	inTruth := make(map[string]bool, len(truth))
	for _, rel := range truth {
		inTruth[rel] = true
	}
	var extra []string
	for rel := range processed {
		if !inTruth[rel] {
			extra = append(extra, rel)
		}
	}
	if len(missing) > 0 || len(extra) > 0 {
		sort.Strings(extra)
		t.Fatalf("inventory is not the corpus: %d missing %v, %d claimed but absent %v", len(missing), missing, len(extra), extra)
	}
	if len(processed) != len(truth) {
		t.Fatalf("processed %d paths, corpus has %d", len(processed), len(truth))
	}

	tests := 0
	for _, rel := range truth {
		if strings.HasSuffix(rel, "_test.go") {
			tests++
		}
	}
	if tests == 0 || tests == len(truth) {
		t.Fatalf("corpus is one-sided: %d files, %d test", len(truth), tests)
	}
	t.Logf("EV09 corpus=%d test=%d non_test=%d processed=%d dropped_vanished=%d", len(truth), tests, len(truth)-tests, len(processed), len(gone))
}

func ev09Contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
