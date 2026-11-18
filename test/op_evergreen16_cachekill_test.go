package main

// A verdict must never outlive the bytes it was derived from. This test takes a
// real .go file, asks the real binary for a structured comparison verdict,
// rewrites the file in place with a real structural change, and requires the
// verdict to move. Restoring the bytes must restore the verdict exactly.
//
// lrecon keeps no source-verdict cache: the only persistence is the Ghidra
// project cache, and ghidraEntryKey hashes the target bytes rather than its
// path. Both layers are checked here, because a path-keyed lookup is the one
// way a remembered answer could survive a rewrite.

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
)

var (
	evergreen16BuildOnce sync.Once
	evergreen16Bin       string
	evergreen16BuildErr  error
)

// evergreen16Binary builds the CLI once; calling internal ops directly would
// skip the invocation path a user actually reaches.
func evergreen16Binary(t *testing.T) string {
	t.Helper()
	evergreen16BuildOnce.Do(func() {
		dir, err := os.MkdirTemp("", "evergreen16-bin-")
		if err != nil {
			evergreen16BuildErr = err
			return
		}
		evergreen16Bin = filepath.Join(dir, "lrecon-evergreen16")
		cmd := exec.Command("go", "build", "-o", evergreen16Bin, ".")
		var out bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &out
		if err := cmd.Run(); err != nil {
			evergreen16BuildErr = &evergreen16RunError{err: err, out: out.String()}
		}
	})
	if evergreen16BuildErr != nil {
		t.Fatalf("build lrecon: %v", evergreen16BuildErr)
	}
	return evergreen16Bin
}

type evergreen16RunError struct {
	err error
	out string
}

func (e *evergreen16RunError) Error() string { return e.err.Error() + "\n" + e.out }

// evergreen16CompareVerdict is the structured answer compare_artifacts gives for
// (frozen digest of the file, live file). It is a verdict about bytes, not a
// handle: every field must be recomputed from whatever is on disk right now.
type evergreen16CompareVerdict struct {
	Identical bool `json:"identical"`
	Count     int  `json:"count"`
	New       struct {
		SHA256 string `json:"sha256"`
		Size   int64  `json:"size"`
		Kind   string `json:"kind"`
	} `json:"new"`
}

func evergreen16Compare(t *testing.T, bin, jobPath string) evergreen16CompareVerdict {
	t.Helper()
	out, err := exec.Command(bin, "--json", "--op", "compare_artifacts", jobPath).Output()
	if err != nil {
		t.Fatalf("compare_artifacts: %v\n%s", err, out)
	}
	var env struct {
		Op     string                    `json:"op"`
		Result evergreen16CompareVerdict `json:"result"`
	}
	if err := json.Unmarshal(out, &env); err != nil {
		t.Fatalf("compare_artifacts: not JSON: %v\n%s", err, out)
	}
	if env.Op != "compare_artifacts" {
		t.Fatalf("compare_artifacts: envelope names %q\n%s", env.Op, out)
	}
	return env.Result
}

// evergreen16CacheKey is the key the one persistent cache would use for this
// path. If it were derived from the path alone, a rewrite would keep the old
// answer reachable.
func evergreen16CacheKey(t *testing.T, path string) string {
	t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return ghidraEntryKey(path, "1.0.0", st)
}

func TestEvergreen16CacheCannotMaskChange(t *testing.T) {
	bin := evergreen16Binary(t)
	dir := t.TempDir()

	source := "op_open_binary.go"
	original, err := os.ReadFile(source)
	if err != nil {
		t.Fatalf("read %s: %v", source, err)
	}
	if len(original) == 0 || !bytes.Contains(original, []byte("package ")) {
		t.Fatalf("%s is not a Go source file", source)
	}

	subject := filepath.Join(dir, "subject.go")
	if err := os.WriteFile(subject, original, 0o644); err != nil {
		t.Fatalf("write subject: %v", err)
	}

	baseline := filepath.Join(dir, "baseline.json")
	if out, err := exec.Command(bin, "--json", "-o", baseline, subject).CombinedOutput(); err != nil {
		t.Fatalf("freeze baseline digest: %v\n%s", err, out)
	}
	job := filepath.Join(dir, "job.json")
	if err := os.WriteFile(job, []byte(`{"old":"`+baseline+`","new":"`+subject+`"}`), 0o600); err != nil {
		t.Fatalf("write job: %v", err)
	}

	// Step 1: the file as shipped matches its own frozen digest.
	first := evergreen16Compare(t, bin, job)
	if !first.Identical || first.Count != 0 {
		t.Fatalf("unmodified copy does not match its digest: identical=%v count=%d", first.Identical, first.Count)
	}
	if first.New.Kind != "text" || first.New.Size != int64(len(original)) {
		t.Fatalf("unmodified copy verdict: kind=%q size=%d want text/%d", first.New.Kind, first.New.Size, len(original))
	}
	keyBefore := evergreen16CacheKey(t, subject)

	// Step 2: same path, new bytes carrying a real structural change (one added
	// function declaration, so the change is source-visible, not a padding byte).
	marker := "\nfunc evergreen16Marker() int { return 16 }\n"
	changed := append(append([]byte{}, original...), []byte(marker)...)
	if err := os.WriteFile(subject, changed, 0o644); err != nil {
		t.Fatalf("rewrite subject: %v", err)
	}

	second := evergreen16Compare(t, bin, job)
	if second.Identical {
		t.Fatalf("stale verdict: rewritten file still reported identical to its old digest")
	}
	if second.Count == 0 {
		t.Fatalf("stale verdict: rewritten file reported zero changes")
	}
	if second.New.SHA256 == first.New.SHA256 {
		t.Fatalf("stale verdict: sha256 did not move after rewrite: %s", second.New.SHA256)
	}
	if want := first.New.Size + int64(len(marker)); second.New.Size != want {
		t.Fatalf("rewritten copy size=%d want %d", second.New.Size, want)
	}
	if second.New.Kind != first.New.Kind {
		t.Fatalf("rewrite changed routing kind from %q to %q; this test wants a content change inside one kind", first.New.Kind, second.New.Kind)
	}

	keyChanged := evergreen16CacheKey(t, subject)
	if keyChanged == keyBefore {
		t.Fatalf("cache key %s survives a content rewrite: a cached verdict would mask the change", keyBefore)
	}

	// Step 3: restore the original bytes; the verdict must come back exactly.
	if err := os.WriteFile(subject, original, 0o644); err != nil {
		t.Fatalf("restore subject: %v", err)
	}
	third := evergreen16Compare(t, bin, job)
	if !third.Identical || third.Count != 0 {
		t.Fatalf("restored copy does not match its digest again: identical=%v count=%d", third.Identical, third.Count)
	}
	if third.New.SHA256 != first.New.SHA256 || third.New.Size != first.New.Size {
		t.Fatalf("restored verdict drifted: sha=%s size=%d want %s/%d",
			third.New.SHA256, third.New.Size, first.New.SHA256, first.New.Size)
	}
	if keyRestored := evergreen16CacheKey(t, subject); keyRestored != keyBefore {
		t.Fatalf("restored bytes produce cache key %s, want the original %s", keyRestored, keyBefore)
	}

	// No verdict cache was materialised beside the target: only the copy, its
	// frozen digest and the job exist, so the second verdict could not have been
	// served from anywhere but the bytes.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read temp dir: %v", err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	if got, want := strings.Join(names, ","), "baseline.json,job.json,subject.go"; got != want {
		t.Fatalf("temp dir holds %q, want %q: an extra file is a place a stale verdict could live", got, want)
	}

	t.Logf("verdicts: unchanged identical=%v sha=%s; rewritten identical=%v sha=%s; restored identical=%v sha=%s; cache key moved %s -> %s",
		first.Identical, first.New.SHA256[:12], second.Identical, second.New.SHA256[:12], third.Identical, third.New.SHA256[:12], keyBefore, keyChanged)
}
