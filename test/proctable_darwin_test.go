package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestDarwinProcMatches feeds the record decoder a fabricated table so the
// offsets are pinned without depending on what happens to be running.
func TestDarwinProcMatches(t *testing.T) {
	b := make([]byte, 3*darwinKinfoProcSize)
	put := func(rec, pid int, comm string) {
		base := rec * darwinKinfoProcSize
		b[base+darwinPidOffset] = byte(pid)
		b[base+darwinPidOffset+1] = byte(pid >> 8)
		b[base+darwinPidOffset+2] = byte(pid >> 16)
		b[base+darwinPidOffset+3] = byte(pid >> 24)
		copy(b[base+darwinCommOffset:base+darwinCommOffset+darwinCommLen], comm)
	}
	put(0, 42, "Cutter")
	put(1, 43, "zsh")
	put(2, 0, "unused") // free slot: pid 0 must be skipped

	got, plausible := darwinProcMatches(b, "cutter")
	if plausible != 2 {
		t.Fatalf("plausible = %d, want 2", plausible)
	}
	if len(got) != 1 || got[0] != "42 Cutter" {
		t.Fatalf("matches = %q, want [\"42 Cutter\"]", got)
	}
}

// TestFindProcessesSelf proves the real sysctl path returns what ps would:
// a child process is listed under its own command name.
func TestFindProcessesSelf(t *testing.T) {
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Skipf("cannot start sleep: %v", err)
	}
	defer func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		got, err := findProcesses("sleep")
		if err != nil {
			t.Fatalf("findProcesses: %v", err)
		}
		for _, line := range got {
			if strings.HasPrefix(line, strconv.Itoa(cmd.Process.Pid)+" ") {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("child pid %d not in kernel process table (got %q)", cmd.Process.Pid, got)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// putKinfoRec writes one fabricated kinfo_proc record: pid little-endian at
// darwinPidOffset, command name at darwinCommOffset.
func putKinfoRec(b []byte, rec, pid int, comm string) {
	base := rec * darwinKinfoProcSize
	b[base+darwinPidOffset] = byte(pid)
	b[base+darwinPidOffset+1] = byte(pid >> 8)
	b[base+darwinPidOffset+2] = byte(pid >> 16)
	b[base+darwinPidOffset+3] = byte(pid >> 24)
	copy(b[base+darwinCommOffset:base+darwinCommOffset+darwinCommLen], comm)
}

// TestDarwinProcRowsPartialTailRecord pins the "Sysctl drops one trailing NUL"
// case: a buffer that ends mid-record decodes the whole records before it and
// never reads past the end. findProcesses/listProcesses pad first; the decoder
// itself must stay bounded either way.
func TestDarwinProcRowsPartialTailRecord(t *testing.T) {
	tail := 100 // a truncated third record, as sysctl can return it
	b := make([]byte, 2*darwinKinfoProcSize+tail)
	putKinfoRec(b, 0, 41, "first")
	putKinfoRec(b, 1, 42, "second")

	rows, plausible := darwinProcRows(b)
	if plausible != 2 || len(rows) != 2 {
		t.Fatalf("unpadded: plausible=%d rows=%d, want 2/2", plausible, len(rows))
	}
	if rows[0].PID != 41 || rows[1].Comm != "second" {
		t.Fatalf("unpadded rows = %+v", rows)
	}

	padded := append(b, make([]byte, darwinKinfoProcSize-tail)...)
	rows, plausible = darwinProcRows(padded)
	if plausible != 2 || len(rows) != 2 {
		t.Fatalf("padded: plausible=%d rows=%d, want 2/2", plausible, len(rows))
	}
	if _, plausible := darwinProcRows(nil); plausible != 0 {
		t.Fatalf("empty buffer plausible=%d, want 0", plausible)
	}
}

// TestPidAliveRejectsNonPositive pins the fix: kill(0, 0) asks about our own
// process group and kill(-1, 0) about every process we may signal, so both
// answered "alive" for a pid that is not a process at all. A caller polling a
// child's pid read as stuck forever.
func TestPidAliveRejectsNonPositive(t *testing.T) {
	for _, pid := range []int{0, -1, -4242} {
		if pidAlive(pid) {
			t.Fatalf("pidAlive(%d) = true; that is our group / every process, not pid %d", pid, pid)
		}
	}
	if !pidAlive(os.Getpid()) {
		t.Fatal("pidAlive(self) = false")
	}

	cmd := exec.Command("true")
	if err := cmd.Start(); err != nil {
		t.Skipf("cannot start true: %v", err)
	}
	pid := cmd.Process.Pid
	_ = cmd.Wait()
	deadline := time.Now().Add(2 * time.Second)
	for pidAlive(pid) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if pidAlive(pid) {
		t.Skipf("pid %d was reused before the reap was observable", pid)
	}
}

// TestGroupAliveFollowsWholeGroup pins the fix: groupAlive used kill(pgid, 0),
// which only asks about the group leader. A wrapper that exits while the JVM it
// started keeps running made the group look dead, so reapTrackedGroups skipped
// straight to a no-op and left the child behind.
func TestGroupAliveFollowsWholeGroup(t *testing.T) {
	if os.Getenv("CI") != "" && os.Getenv("LRECON_REAL_PROCESS_TESTS") != "1" {
		t.Skip("real process/signal test; set LRECON_REAL_PROCESS_TESTS=1 to run in CI")
	}
	cmd := exec.Command("sh", "-c", "sleep 30 & exit 0")
	setpgroup(cmd)
	if err := cmd.Start(); err != nil {
		t.Skipf("cannot start sh: %v", err)
	}
	pgid := cmd.Process.Pid
	if err := cmd.Wait(); err != nil {
		t.Fatalf("leader did not exit cleanly: %v", err)
	}
	defer killGroup(pgid) // idempotent: ESRCH is not an error

	if err := syscall.Kill(pgid, 0); err == nil {
		t.Skipf("pid %d still resolves after the leader was reaped", pgid)
	}
	if !groupAlive(pgid) {
		t.Fatalf("groupAlive(%d) = false while the orphaned sleep still holds the group", pgid)
	}
	if err := killGroup(pgid); err != nil {
		t.Fatalf("killGroup(%d): %v", pgid, err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for groupAlive(pgid) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if groupAlive(pgid) {
		t.Fatalf("group %d still alive after SIGKILL", pgid)
	}
}

// TestKillGroupRejectsNonPositive pins the guard that keeps kill(-0) from
// signalling lrecon's own group: killGroup(0) used to be kill(0, SIGKILL), i.e.
// suicide for the whole process group.
func TestKillGroupRejectsNonPositive(t *testing.T) {
	for _, pgid := range []int{0, -3} {
		err := killGroup(pgid)
		if err == nil || !strings.Contains(err.Error(), "invalid process group") {
			t.Fatalf("killGroup(%d) = %v, want invalid process group error", pgid, err)
		}
		if groupAlive(pgid) {
			t.Fatalf("groupAlive(%d) = true", pgid)
		}
	}
	termGroup(0) // reaching the next line is the assertion: it did not signal us
	if !pidAlive(os.Getpid()) {
		t.Fatal("termGroup(0) signalled the test process's own group")
	}
}

// TestLockFileExcludesSecondHandle pins the cache lock contract the native ops
// rely on: the second holder is told "busy" (false, nil), not "error", and the
// lock is released when the first handle closes.
func TestLockFileExcludesSecondHandle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "native.lock")
	first, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatalf("open first: %v", err)
	}
	defer first.Close()
	second, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatalf("open second: %v", err)
	}
	defer second.Close()

	if ok, err := lockFile(first); !ok || err != nil {
		t.Fatalf("first lockFile = %v, %v; want true, nil", ok, err)
	}
	if ok, err := lockFile(second); ok || err != nil {
		t.Fatalf("second lockFile = %v, %v; want false, nil (busy is not an error)", ok, err)
	}
	first.Close()
	if ok, err := lockFile(second); !ok || err != nil {
		t.Fatalf("lockFile after release = %v, %v; want true, nil", ok, err)
	}
}

// TestFindProcessesMiss pins the negative path: a name nobody runs is an empty
// list and no error, so list_cutter_sessions reports "none running" instead of
// failing.
func TestFindProcessesMiss(t *testing.T) {
	name := "lrecon-no-such-proc-" + strconv.Itoa(os.Getpid())
	got, err := findProcesses(name)
	if err != nil {
		t.Fatalf("findProcesses(%q): %v", name, err)
	}
	if len(got) != 0 {
		t.Fatalf("findProcesses(%q) = %q, want empty", name, got)
	}
}

// TestListProcessesSelf pins the whole-table path list_frida_processes uses:
// our own pid is in the kernel table with a non-empty command name.
func TestListProcessesSelf(t *testing.T) {
	rows, err := listProcesses()
	if err != nil {
		t.Fatalf("listProcesses: %v", err)
	}
	if len(rows) < 5 {
		t.Fatalf("listProcesses returned %d rows; a live host has more", len(rows))
	}
	for _, r := range rows {
		if r.PID == os.Getpid() {
			if r.Comm == "" {
				t.Fatalf("own row has empty comm: %+v", r)
			}
			return
		}
	}
	t.Fatalf("own pid %d missing from %d rows", os.Getpid(), len(rows))
}

// darwinProcRowsNoHint is the pre-optimization decoder: appends onto a nil
// slice, so the table is copied through every growth step. Kept only so the
// benchmark can price the capacity hint in darwinProcRows.
func darwinProcRowsNoHint(b []byte) (rows []procRow, plausible int) {
	for base := 0; base+darwinKinfoProcSize <= len(b); base += darwinKinfoProcSize {
		rec := b[base : base+darwinKinfoProcSize]
		pid := int(rec[darwinPidOffset]) | int(rec[darwinPidOffset+1])<<8 |
			int(rec[darwinPidOffset+2])<<16 | int(rec[darwinPidOffset+3])<<24
		if pid <= 0 || pid > 1<<24 {
			continue
		}
		plausible++
		comm := strings.TrimSpace(string(rec[darwinCommOffset : darwinCommOffset+darwinCommLen]))
		if i := strings.IndexByte(comm, 0); i >= 0 {
			comm = strings.TrimSpace(comm[:i])
		}
		rows = append(rows, procRow{PID: pid, Comm: comm})
	}
	return rows, plausible
}

func procTableFixture(records int) []byte {
	b := make([]byte, records*darwinKinfoProcSize)
	for i := range records {
		putKinfoRec(b, i, 100+i, "proc")
	}
	return b
}

func BenchmarkDarwinProcRows(b *testing.B) {
	table := procTableFixture(2000)
	b.ReportAllocs()
	for b.Loop() {
		if _, plausible := darwinProcRows(table); plausible != 2000 {
			b.Fatalf("plausible = %d", plausible)
		}
	}
}

func BenchmarkDarwinProcRowsNoHint(b *testing.B) {
	table := procTableFixture(2000)
	b.ReportAllocs()
	for b.Loop() {
		if _, plausible := darwinProcRowsNoHint(table); plausible != 2000 {
			b.Fatalf("plausible = %d", plausible)
		}
	}
}
