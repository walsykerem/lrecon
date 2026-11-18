//go:build unix

package main

// Cache tests need no Ghidra install: they cover the key, the disabled path,
// pruning, the lock and a corrupt entry. The real import timing is the CLI run.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestGhidraCacheKeyTracksBytes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(path, []byte("first"), 0o644); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	first := ghidraCacheKey(path, st)
	if len(first) != 16 {
		t.Fatalf("key %q is %d chars, want 16", first, len(first))
	}
	st2, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if again := ghidraCacheKey(path, st2); again != first {
		t.Fatalf("same file keyed %q then %q", first, again)
	}
	if err := os.Chtimes(path, time.Now(), time.Now().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	old, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if rebuilt := ghidraCacheKey(path, old); rebuilt == first {
		t.Fatalf("new mtime kept key %q: a rebuilt binary would answer with stale analysis", rebuilt)
	}
	if old.Size() != st.Size() {
		t.Fatal("fixture size changed; the mtime assertion above proves nothing")
	}
}

func TestGhidraCacheRootSwitch(t *testing.T) {
	t.Setenv("LRECON_GHIDRA_CACHE", "off")
	if root, ok := ghidraCacheRoot(); ok || root != "" {
		t.Fatalf("off returned %q,%v; want disabled", root, ok)
	}
	t.Setenv("LRECON_GHIDRA_CACHE", "/tmp/lrecon-cache-probe")
	if root, ok := ghidraCacheRoot(); !ok || root != "/tmp/lrecon-cache-probe" {
		t.Fatalf("override returned %q,%v", root, ok)
	}
	t.Setenv("LRECON_GHIDRA_CACHE", "")
	root, ok := ghidraCacheRoot()
	if !ok || filepath.Base(root) != "lrecon-ghidra" {
		t.Fatalf("default root %q,%v, want .../lrecon-ghidra", root, ok)
	}
}

func TestGhidraTimeoutEnv(t *testing.T) {
	t.Setenv("LRECON_GHIDRA_TIMEOUT", "")
	if got := ghidraTimeout(); got != ghidraTimeoutDefault {
		t.Fatalf("unset returned %s, want default %s", got, ghidraTimeoutDefault)
	}
	t.Setenv("LRECON_GHIDRA_TIMEOUT", "45m")
	if got := ghidraTimeout(); got != 45*time.Minute {
		t.Fatalf("45m returned %s", got)
	}
	t.Setenv("LRECON_GHIDRA_TIMEOUT", "900")
	if got := ghidraTimeout(); got != 900*time.Second {
		t.Fatalf("bare seconds returned %s, want 15m", got)
	}
	// A bad value must not silently shrink the budget to zero, which would make
	// every Ghidra op fail instantly.
	for _, bad := range []string{"nonsense", "-5", "0"} {
		t.Setenv("LRECON_GHIDRA_TIMEOUT", bad)
		if got := ghidraTimeout(); got != ghidraTimeoutDefault {
			t.Fatalf("%q returned %s, want default", bad, got)
		}
	}
}

func TestGhidraPruneDropsStale(t *testing.T) {
	root := t.TempDir()
	old := time.Now().Add(-8 * 24 * time.Hour)
	for _, key := range []string{"aaa", "bbb", "ccc"} {
		dir := filepath.Join(root, key)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		meta := filepath.Join(dir, "meta.json")
		if err := os.WriteFile(meta, []byte(`{"program":"x"}`), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(meta, old, old); err != nil {
			t.Fatal(err)
		}
	}
	fresh := filepath.Join(root, "ddd")
	if err := os.MkdirAll(fresh, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fresh, "meta.json"), []byte(`{"program":"y"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	ghidraPrune(root)
	for _, key := range []string{"aaa", "bbb", "ccc"} {
		if _, err := os.Stat(filepath.Join(root, key)); !os.IsNotExist(err) {
			t.Errorf("stale entry %s survived prune (err=%v)", key, err)
		}
	}
	if _, err := os.Stat(filepath.Join(fresh, "meta.json")); err != nil {
		t.Errorf("fresh entry was pruned: %v", err)
	}
}

func TestGhidraPruneKeepsLiveEntry(t *testing.T) {
	root := t.TempDir()
	// A run in progress: the dir is old enough to look like debris, but the
	// flock says a run is inside it, and pruning would delete its project.
	busy := filepath.Join(root, "live")
	if err := os.MkdirAll(busy, 0o755); err != nil {
		t.Fatal(err)
	}
	unlock, err := ghidraLock(busy)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	// Seconds-old dir without a lock: a run between MkdirAll and ghidraLock.
	starting := filepath.Join(root, "starting")
	if err := os.MkdirAll(starting, 0o755); err != nil {
		t.Fatal(err)
	}
	// Debris from a killed import is still collected.
	debris := filepath.Join(root, "debris")
	if err := os.MkdirAll(debris, 0o755); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-time.Hour)
	for _, dir := range []string{busy, debris} {
		if err := os.Chtimes(dir, old, old); err != nil {
			t.Fatal(err)
		}
	}

	ghidraPrune(root)

	for _, dir := range []string{busy, starting} {
		if _, err := os.Stat(dir); err != nil {
			t.Fatalf("prune deleted a live entry (%s): %v", filepath.Base(dir), err)
		}
	}
	if _, err := os.Stat(filepath.Join(debris, "meta.json")); err == nil {
		t.Fatal("debris was given a meta.json by a test bug")
	}
	if _, err := os.Stat(filepath.Join(busy, "lock")); err != nil {
		t.Fatalf("prune deleted the lock of a live entry: %v", err)
	}
	if _, err := os.Stat(debris); !os.IsNotExist(err) {
		t.Errorf("meta-less debris survived prune (err=%v)", err)
	}
}

func TestGhidraLockIsExclusive(t *testing.T) {
	dir := t.TempDir()
	var mu sync.Mutex
	inside, peak := 0, 0
	var wg sync.WaitGroup
	done := make(chan struct{}, 2)
	for range 2 {
		wg.Go(func() {
			unlock, err := ghidraLock(dir)
			if err != nil {
				t.Errorf("lock: %v", err)
				done <- struct{}{}
				return
			}
			mu.Lock()
			inside++
			if inside > peak {
				peak = inside
			}
			mu.Unlock()
			time.Sleep(250 * time.Millisecond) // longer than one poll, so the other waits
			mu.Lock()
			inside--
			mu.Unlock()
			unlock()
			done <- struct{}{}
		})
	}
	deadline := time.After(10 * time.Second)
	for range 2 {
		select {
		case <-done:
		case <-deadline:
			t.Fatal("a goroutine never got the lock: two runs would share one Ghidra project")
		}
	}
	wg.Wait()
	if peak != 1 {
		t.Fatalf("%d goroutines held the lock at once, want 1", peak)
	}
	// The file stays (removing it would let two runs flock two inodes); what
	// matters is that the kernel released the lock.
	unlock, err := ghidraLock(dir)
	if err != nil {
		t.Fatalf("lock not released after unlock: %v", err)
	}
	unlock()
}

func TestGhidraLookupRejectsCorruptMeta(t *testing.T) {
	root := t.TempDir()
	key := "0123456789abcdef"
	dir := filepath.Join(root, key)
	if err := os.MkdirAll(filepath.Join(dir, "project"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "meta.json"), []byte(`{"program":`), 0o644); err != nil {
		t.Fatal(err)
	}
	meta, ok := ghidraLookup(root, key)
	if ok || meta.Program != "" {
		t.Fatalf("corrupt meta reported entry %+v,%v; want no valid entry", meta, ok)
	}
	if err := os.WriteFile(filepath.Join(dir, "meta.json"), []byte(`{"program":""}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, ok := ghidraLookup(root, key); ok {
		t.Fatal("entry without a program name was reported valid")
	}
	if err := os.WriteFile(filepath.Join(dir, "meta.json"), []byte(`{"program":"ls"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if meta, ok := ghidraLookup(root, key); !ok || meta.Program != "ls" {
		t.Fatalf("valid entry = %+v,%v", meta, ok)
	}
	if _, err := os.Stat(filepath.Join(root, "ffffffffffffffff")); !os.IsNotExist(err) {
		t.Fatalf("unexpected entry (err=%v)", err)
	}
}

// TestGhidraCachedRunAnswersRepeatedCommand pins item 37: the second op on the
// same target must not pay another JVM start, so it answers from the entry.
func TestGhidraCachedRunAnswersRepeatedCommand(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("same bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	runs := filepath.Join(dir, "runs.log")
	shim := ghidraShim(t, dir, fmt.Sprintf(`echo run >> '%s'
for a in "$@"; do out="$a"; done
printf '{"functions":1}' > "$out"
`, runs))
	t.Setenv("LRECON_GHIDRA_TIMEOUT", "20s")
	root := filepath.Join(dir, "cache")
	if _, mode, err := ghidraCachedRun(shim, root, target, "12.1.4", "list_names", st, nil); err != nil || mode != "fresh" {
		t.Fatalf("first op = %q,%v; want a fresh import", mode, err)
	}
	res, mode, err := ghidraCachedRun(shim, root, target, "12.1.4", "list_names", st, nil)
	if err != nil || mode != "cached" {
		t.Fatalf("second identical op = %q,%v; want the stored answer", mode, err)
	}
	if got := fmt.Sprint(res["functions"]); got != "1" {
		t.Fatalf("cached answer = %q, want the first run's body", got)
	}
	if b, err := os.ReadFile(runs); err != nil || strings.Count(string(b), "run") != 1 {
		t.Fatalf("headless runs = %q,%v; want exactly one", string(b), err)
	}
}
