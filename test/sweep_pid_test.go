package main

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestTempOwnerPid(t *testing.T) {
	for _, c := range []struct {
		name string
		pid  int
		ok   bool
	}{
		{"lrecon-extract_artifact-p1234-5678", 1234, true},
		{"lrecon-cli-123456789", 0, false}, // MkdirTemp random suffix is not a pid
		{"lrecon-native-p1-x", 0, false},   // pid 1 is never one of ours
		{"other-p12-x", 0, false},
	} {
		pid, ok := tempOwnerPid(c.name)
		if pid != c.pid || ok != c.ok {
			t.Fatalf("tempOwnerPid(%q) = (%d, %v), want (%d, %v)", c.name, pid, ok, c.pid, c.ok)
		}
	}
}

func TestTempDirRecordsOwner(t *testing.T) {
	dir, err := tempDir("lrecon-owntest-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	if pid, ok := tempOwnerPid(filepath.Base(dir)); !ok || pid != os.Getpid() {
		t.Fatalf("tempDir(%q) = %q, owner (%d, %v), want pid %d", "lrecon-owntest-", dir, pid, ok, os.Getpid())
	}
}

func TestSweepTempDirsKeepsLiveOwner(t *testing.T) {
	old := time.Now().Add(-2 * time.Hour)
	mk := func(name string) string {
		dir := filepath.Join(os.TempDir(), name)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(dir, old, old); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	live := mk("lrecon-sweeptest-p" + strconv.Itoa(os.Getpid()) + "-1")
	dead := mk("lrecon-sweeptest-p999999-1")
	t.Cleanup(func() { os.RemoveAll(live); os.RemoveAll(dead) })

	sweepTempDirs(time.Hour)
	if _, err := os.Stat(live); err != nil {
		t.Fatalf("sweep removed a live owner's tree: %v", err)
	}
	if _, err := os.Stat(dead); !os.IsNotExist(err) {
		t.Fatalf("sweep kept a dead owner's tree: %v", err)
	}
}
