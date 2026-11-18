//go:build unix

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

// Process groups, liveness probes and advisory locks are POSIX calls. The
// Windows equivalents live behind the same five helpers in proc_windows.go, so
// no op file has to be split per platform.

// setpgroup puts the child in its own group so Cancel can kill the helpers it
// spawned: a shell wrapper around java leaves java holding our pipes.
func setpgroup(cmd *exec.Cmd) { cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} }

// killGroup kills the whole group. A group that is already gone is not an
// error: every caller only needs it dead. pgid<=0 is refused because kill(-0)
// is kill(0): it would signal lrecon's own group, not a child's. A reaped
// leader can hand its pgid to an unrelated group; if neither the leader nor the
// group answers, there is nothing of ours left to signal.
func killGroup(pgid int) error {
	if pgid <= 0 {
		return fmt.Errorf("killGroup: invalid process group %d", pgid)
	}
	if !pidAlive(pgid) && !groupAlive(pgid) {
		return nil
	}
	if err := syscall.Kill(-pgid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
		return err
	}
	return nil
}

// termGroup asks the group to stop; killGroup finishes what it leaves.
func termGroup(pgid int) {
	if pgid <= 0 {
		return
	}
	syscall.Kill(-pgid, syscall.SIGTERM)
}

// groupAlive asks about the group, not its leader. kill(-pgid) keeps the group
// visible while any member lives; kill(pgid) called a wrapper's group dead the
// moment the wrapper exited and left java holding the pipes.
func groupAlive(pgid int) bool {
	if pgid <= 0 {
		return false
	}
	return syscall.Kill(-pgid, 0) == nil
}

// pidAlive asks the kernel whether pid exists without signalling it. EPERM
// means it exists and belongs to someone else. pid<=0 is not a process: kill(0,
// 0) asks about our own group and kill(-1, 0) about every process we may
// signal, so both used to answer yes.
func pidAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}

// lockFile takes an exclusive advisory lock without waiting. ok=false with a
// nil error means another process holds it. Closing f releases the lock.
func lockFile(f *os.File) (ok bool, err error) {
	err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
		return false, nil
	}
	return false, err
}
