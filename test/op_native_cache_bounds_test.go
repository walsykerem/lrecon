package main

// Bounds and races the audit found in the Ghidra cache: the key missed the
// script version, the per-entry answer store had no cap, prune deleted after
// releasing the lock, and discard kept the answers of a rejected analysis.

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestGhidraCacheKeyVersioned(t *testing.T) {
	path := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(path, []byte("same bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	first := ghidraEntryKey(path, "12.1.4", st)
	if again := ghidraEntryKey(path, "12.1.4", st); again != first {
		t.Fatalf("same inputs keyed %q then %q", first, again)
	}
	if ghidraEntryKey(path, "12.1.5", st) == first {
		t.Fatal("a Ghidra upgrade kept the entry key")
	}
	// A lrecon upgrade can change NativeOp.java without touching target or
	// engine: the key must move or the new semantics read an old answer.
	old := ghidraScriptSource
	ghidraScriptSource = old + "\n// upgraded"
	defer func() { ghidraScriptSource = old }()
	if ghidraEntryKey(path, "12.1.4", st) == first {
		t.Fatal("a postScript change kept the entry key")
	}
}

func TestGhidraAnswerStoreBounded(t *testing.T) {
	dir := t.TempDir()
	meta := filepath.Join(dir, "meta.json")
	if err := os.WriteFile(meta, []byte(`{"program":"x"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	stale := time.Now().Add(-8 * 24 * time.Hour)
	if err := os.Chtimes(meta, stale, stale); err != nil {
		t.Fatal(err)
	}
	// A hit is use: the entry's meta mtime must move or an active entry ages out.
	ghidraAnswerStore(dir, "list_names", nil, map[string]any{"ok": true})
	if _, ok := ghidraAnswerHit(dir, "list_names", nil); !ok {
		t.Fatal("stored answer is not a hit")
	}
	if st, err := os.Stat(meta); err != nil || time.Since(st.ModTime()) > time.Minute {
		t.Fatalf("hit did not refresh meta mtime: %v %v", st, err)
	}

	// Age: an answer older than the entry TTL goes on the next store.
	oldAnswer := ghidraAnswerPath(dir, "old_command", nil)
	if err := os.WriteFile(oldAnswer, []byte(`{"old":true}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(oldAnswer, stale, stale); err != nil {
		t.Fatal(err)
	}
	ghidraAnswerStore(dir, "fresh_command", nil, map[string]any{"ok": true})
	if _, err := os.Stat(oldAnswer); !os.IsNotExist(err) {
		t.Fatalf("stale answer survived store prune: %v", err)
	}

	// Count: prune keeps the newest ghidraAnswerMaxFiles answers.
	countDir := t.TempDir()
	base := time.Now().Add(-time.Hour)
	for i := 0; i <= ghidraAnswerMaxFiles; i++ {
		p := filepath.Join(countDir, fmt.Sprintf("answer-%04d.json", i))
		if err := os.WriteFile(p, []byte(`{}`), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(p, base.Add(time.Duration(i)*time.Second), base.Add(time.Duration(i)*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	ghidraAnswerPrune(countDir)
	if got := answerCount(t, countDir); got != ghidraAnswerMaxFiles {
		t.Fatalf("answer count %d, want %d", got, ghidraAnswerMaxFiles)
	}

	// Total size: prune drops the oldest until the entry fits.
	sizeDir := t.TempDir()
	half := int64(ghidraAnswerMaxBytes/2 + 1)
	for i, name := range []string{"answer-a.json", "answer-b.json"} {
		p := filepath.Join(sizeDir, name)
		if err := os.WriteFile(p, []byte(`{}`), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Truncate(p, half); err != nil {
			t.Fatal(err)
		}
		when := base.Add(time.Duration(i) * time.Second)
		if err := os.Chtimes(p, when, when); err != nil {
			t.Fatal(err)
		}
	}
	ghidraAnswerPrune(sizeDir)
	if got := answerCount(t, sizeDir); got != 1 {
		t.Fatalf("size-bound kept %d answers, want 1", got)
	}

	// Read: an oversized answer is truncated and therefore a miss, not an OOM.
	bigDir := t.TempDir()
	big := ghidraAnswerPath(bigDir, "big", nil)
	if err := os.WriteFile(big, []byte(`{"a":1}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(big, ghidraReadMax+1); err != nil {
		t.Fatal(err)
	}
	if b, err := ghidraReadCapped(big); err != nil || int64(len(b)) != ghidraReadMax {
		t.Fatalf("capped read = %d bytes, %v; want %d", len(b), err, ghidraReadMax)
	}
	if _, ok := ghidraAnswerHit(bigDir, "big", nil); ok {
		t.Fatal("oversized answer was served as a hit")
	}
}

func answerCount(t *testing.T, dir string) int {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(dir, "answer-*.json"))
	if err != nil {
		t.Fatal(err)
	}
	return len(paths)
}

func TestGhidraPruneHoldsLock(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "key")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	meta := filepath.Join(dir, "meta.json")
	if err := os.WriteFile(meta, []byte(`{"program":"x"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	stale := time.Now().Add(-8 * 24 * time.Hour)
	if err := os.Chtimes(meta, stale, stale); err != nil {
		t.Fatal(err)
	}
	unlock, err := ghidraLock(dir)
	if err != nil {
		t.Fatal(err)
	}
	ghidraPrune(root)
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("prune deleted an entry whose lock it did not hold: %v", err)
	}
	unlock()
	ghidraPrune(root)
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("stale entry survived prune after release: %v", err)
	}
}

func TestGhidraDiscardRemovesAnswers(t *testing.T) {
	dir := t.TempDir()
	entry := &ghidraEntry{dir: dir}
	if err := os.MkdirAll(filepath.Join(dir, "project"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "meta.json"), []byte(`{"program":"x"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	answers, err := filepath.Glob(filepath.Join(dir, "answer-*.json"))
	if err != nil {
		t.Fatal(err)
	}
	answer := ghidraAnswerPath(dir, "list_names", nil)
	if err := os.WriteFile(answer, []byte(`{"ok":true}`), 0o644); err != nil {
		t.Fatal(err)
	}
	entry.discard()
	for _, p := range append(answers, answer, filepath.Join(dir, "meta.json"), filepath.Join(dir, "project")) {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("discard kept %s: %v", p, err)
		}
	}
}
