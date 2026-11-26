//go:build unix

package main

import (
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

// A4: the claim is that a signal takes the child process group down, not that
// Setpgid appears somewhere. This starts a real group, registers it the way
// ghidraExec callers do, runs the reaper and asks the kernel whether the group
// is gone.
func TestSignalReaperKillsChildGroup(t *testing.T) {
	if os.Getenv("CI") != "" && os.Getenv("LRECON_REAL_PROCESS_TESTS") != "1" {
		t.Skip("real process/signal test; set LRECON_REAL_PROCESS_TESTS=1 to run in CI")
	}
	cmd := exec.Command("sh", "-c", "sleep 30")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Skipf("cannot start sh: %v", err)
	}
	pgid := cmd.Process.Pid
	trackGroup(pgid)
	defer func() {
		syscall.Kill(-pgid, syscall.SIGKILL)
		cmd.Wait()
		untrackGroup(pgid)
	}()

	groups := reapTrackedGroups(2 * time.Second)
	if len(groups) != 1 || groups[0] != pgid {
		t.Fatalf("reaper signalled %v, want [%d]", groups, pgid)
	}
	cmd.Wait()
	if err := syscall.Kill(-pgid, 0); err == nil {
		t.Fatalf("group %d survived the reaper", pgid)
	}
}

func TestSignalReaperWithNoChildren(t *testing.T) {
	if groups := reapTrackedGroups(10 * time.Millisecond); len(groups) != 0 {
		t.Fatalf("reaper signalled %v with no registered groups", groups)
	}
}
