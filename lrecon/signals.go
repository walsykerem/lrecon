package main

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// sweepTempDirs removes stale lrecon-* work trees from the system temp dir.
// Every op removes its own tree on the way out; a killed process cannot, so an
// hour-old leftover is garbage. A tree another lrecon is still writing must not
// be touched, so the name carries its owner pid and only a dead pid's tree is
// removed; a tree with no recorded pid cannot be proven abandoned and stays.
func sweepTempDirs(olderThan time.Duration) {
	entries, err := os.ReadDir(os.TempDir())
	if err != nil {
		return
	}
	cutoff := time.Now().Add(-olderThan)
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), "lrecon-") {
			continue
		}
		info, err := e.Info()
		if err != nil || info.ModTime().After(cutoff) {
			continue
		}
		pid, ok := tempOwnerPid(e.Name())
		if !ok || pidAlive(pid) {
			continue
		}
		os.RemoveAll(filepath.Join(os.TempDir(), e.Name()))
	}
}

// tempDir creates a work tree whose name records this process, so a later
// lrecon can tell an abandoned tree from one a live run still owns.
func tempDir(prefix string) (string, error) {
	return os.MkdirTemp("", fmt.Sprintf("%s-p%d-", prefix, os.Getpid()))
}

// tempOwnerPid reads the pid a work-tree name records: lrecon-<op>-p<pid>-<rand>.
// The pid segment is explicit ("p123") so MkdirTemp's all-digit random suffix
// is never mistaken for a pid.
func tempOwnerPid(name string) (int, bool) {
	rest, ok := strings.CutPrefix(name, "lrecon-")
	if !ok {
		return 0, false
	}
	for part := range strings.SplitSeq(rest, "-") {
		if len(part) < 2 || part[0] != 'p' {
			continue
		}
		if pid, err := strconv.Atoi(part[1:]); err == nil && pid > 1 {
			return pid, true
		}
	}
	return 0, false
}

// A4: a Ctrl-C or a SIGTERM must take the whole child process group with it.
// analyzeHeadless is a shell wrapper around java, so signalling only lrecon
// leaves java holding the pipes (the same reason ghidraExec sets Setpgid).
// Groups are registered when started and removed once reaped.

var childGroups sync.Map // pgid -> struct{}

func trackGroup(pgid int) {
	if pgid > 0 {
		childGroups.Store(pgid, struct{}{})
	}
}

func untrackGroup(pgid int) {
	childGroups.Delete(pgid)
}

// reapTrackedGroups asks every live group to stop, then kills what is left.
// Returns the groups it signalled, for the message on stderr.
func reapTrackedGroups(grace time.Duration) []int {
	var groups []int
	childGroups.Range(func(k, _ any) bool {
		groups = append(groups, k.(int))
		return true
	})
	for _, pgid := range groups {
		termGroup(pgid)
	}
	deadline := time.Now().Add(grace)
	for _, pgid := range groups {
		for groupAlive(pgid) && time.Now().Before(deadline) {
			time.Sleep(20 * time.Millisecond)
		}
		killGroup(pgid)
	}
	return groups
}

// installSignalReaper runs once from main. os.Exit skips deferred cleanup, so
// the groups are reaped here rather than in a defer that may never run.
func installSignalReaper() {
	sweepTempDirs(time.Hour)
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	go func() {
		sig := <-ch
		groups := reapTrackedGroups(5 * time.Second)
		fmt.Fprintf(os.Stderr, "lrecon: interrupted (%v), killed %d child process group(s)\n", sig, len(groups))
		os.Exit(130)
	}()
}
