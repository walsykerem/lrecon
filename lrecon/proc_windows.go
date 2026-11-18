//go:build windows

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"unsafe"
)

// Windows side of the five helpers proc_unix.go defines. There is no killpg
// and no flock: a tree is ended with taskkill /T (the same "the JVM under the
// wrapper must die too" contract) and an exclusive lock is LockFileEx on the
// same handle.

// setpgroup is the POSIX grouping; taskkill /T walks the tree by parent pid
// instead, so there is nothing to set.
func setpgroup(cmd *exec.Cmd) {}

// killGroup kills pid and everything it spawned. pid<=0 is refused: there is
// no tree to walk, and taskkill would be asked about an invalid process.
func killGroup(pgid int) error {
	if pgid <= 0 {
		return fmt.Errorf("killGroup: invalid process group %d", pgid)
	}
	err := exec.Command("taskkill", "/T", "/F", "/PID", strconv.Itoa(pgid)).Run()
	if _, ok := errors.AsType[*exec.ExitError](err); ok {
		return nil // taskkill exits 128 for a pid that is already gone
	}
	return err
}

// termGroup asks the tree to close; killGroup finishes what it leaves.
func termGroup(pgid int) {
	if pgid <= 0 {
		return
	}
	exec.Command("taskkill", "/T", "/PID", strconv.Itoa(pgid)).Run()
}

func groupAlive(pgid int) bool { return pidAlive(pgid) }

// pidAlive opens the pid with query rights. Access denied still means the
// process is there, just not ours. CreateProcess on a dead pid fails
// ERROR_INVALID_PARAMETER.
func pidAlive(pid int) bool {
	if pid <= 0 { // not a process: OpenProcess would answer for handle 0 instead
		return false
	}
	h, err := syscall.OpenProcess(syscall.PROCESS_QUERY_INFORMATION, false, uint32(pid))
	if err != nil {
		return errors.Is(err, syscall.ERROR_ACCESS_DENIED)
	}
	syscall.CloseHandle(h)
	return true
}

var (
	kernel32       = syscall.NewLazyDLL("kernel32.dll")
	procLockFileEx = kernel32.NewProc("LockFileEx")
)

const (
	lockfileExclusiveLock = 0x00000002
	errorLockViolation    = syscall.Errno(33)
)

// lockFile takes an exclusive lock without waiting; ok=false with a nil error
// means another process holds it. Closing f releases the lock.
func lockFile(f *os.File) (ok bool, err error) {
	var ol syscall.Overlapped
	r1, _, e := procLockFileEx.Call(uintptr(f.Fd()), lockfileExclusiveLock, 0, 1, 0, uintptr(unsafe.Pointer(&ol)))
	if r1 != 0 {
		return true, nil
	}
	if errors.Is(e, errorLockViolation) {
		return false, nil
	}
	return false, e
}
