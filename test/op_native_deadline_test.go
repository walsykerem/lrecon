//go:build unix

package main

// B1/B8: a Ghidra run over its budget must answer with a structured timeout
// envelope and leave no process behind, and the cache lock must give up after
// LRECON_GHIDRA_LOCK_WAIT and take over a lock whose owner is gone. No real
// Ghidra is used: a fake analyzeHeadless shim stands in, so these run anywhere.

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// ghidraShim writes a fake analyzeHeadless whose body runs under /bin/sh.
func ghidraShim(t *testing.T, dir, body string) string {
	t.Helper()
	p := filepath.Join(dir, "analyzeHeadless")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func ghidraShimPID(t *testing.T, path string) int {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("shim never wrote its pid: %v", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		t.Fatalf("shim pid %q: %v", b, err)
	}
	return pid
}

// TestGhidraDeadlineEnvelope pins the two stages a fresh import can be in when
// the budget runs out: no script output yet is "import", a cached program is
// "analyze", and in both cases the whole process group must be dead on return.
func TestGhidraDeadlineEnvelope(t *testing.T) {
	cases := []struct {
		name    string
		program string
		stage   string
	}{
		{"fresh-import", "", "import"},
		{"cached-analyze", "target", "analyze"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			pidFile := filepath.Join(dir, "shim.pid")
			shim := ghidraShim(t, dir, fmt.Sprintf("echo $$ > '%s'\nsleep 5\n", pidFile))
			t.Setenv("LRECON_GHIDRA_TIMEOUT", "1s")
			res, err := ghidraHeadless(shim, filepath.Join(dir, "work"), "/bin/ls", "list_names", nil, tc.program, false)
			if err != nil {
				t.Fatalf("overrun returned a plain error, want an envelope: %v", err)
			}
			// error=timeout is the deterministic exit: ghidraHeadless only writes
			// it when errors.Is(ctx.Err(), context.DeadlineExceeded), so no wall
			// clock reading is needed to prove the deadline fired.
			if res["error"] != "timeout" || res["stage"] != tc.stage {
				t.Fatalf("envelope = %v, want error=timeout stage=%s", res, tc.stage)
			}
			if _, partial := res["partial"]; partial {
				t.Fatalf("envelope claims a partial answer but the shim wrote none: %v", res)
			}
			pid := ghidraShimPID(t, pidFile)
			if !processGone(pid) {
				syscall.Kill(pid, syscall.SIGKILL)
				t.Fatalf("shim pid %d survived the deadline: the process group was not killed", pid)
			}
		})
	}
}

// TestGhidraDeadlineKeepsPartialAnswer: when the postScript flushed an answer
// but the run overran, the envelope keeps it and says stage=post.
func TestGhidraDeadlineKeepsPartialAnswer(t *testing.T) {
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "shim.pid")
	body := fmt.Sprintf("echo $$ > '%s'\n"+
		"for a in \"$@\"; do out=\"$a\"; done\n"+
		"printf '{\"functions\":2}' > \"$out\"\n"+
		"sleep 5\n", pidFile)
	shim := ghidraShim(t, dir, body)
	t.Setenv("LRECON_GHIDRA_TIMEOUT", "1s")
	res, err := ghidraHeadless(shim, filepath.Join(dir, "work"), "/bin/ls", "list_names", nil, "", false)
	if err != nil {
		t.Fatalf("overrun returned a plain error, want an envelope: %v", err)
	}
	if res["error"] != "timeout" || res["stage"] != "post" || res["partial"] != true {
		t.Fatalf("envelope = %v, want error=timeout stage=post partial=true", res)
	}
	partial, ok := res["result"].(map[string]any)
	if !ok || partial["functions"] != float64(2) {
		t.Fatalf("partial answer = %#v, want the script's functions=2", res["result"])
	}
	pid := ghidraShimPID(t, pidFile)
	if !processGone(pid) {
		syscall.Kill(pid, syscall.SIGKILL)
		t.Fatalf("shim pid %d survived the deadline: the process group was not killed", pid)
	}
}

// deadPID spawns and reaps a process so its pid is provably no longer alive.
func deadPID(t *testing.T) int {
	t.Helper()
	cmd := exec.Command("true")
	if err := cmd.Start(); err != nil {
		t.Skipf("cannot spawn a short-lived process: %v", err)
	}
	pid := cmd.Process.Pid
	cmd.Wait()
	if ghidraPIDAlive(pid) {
		t.Skipf("pid %d was reused before the test", pid)
	}
	return pid
}

// TestGhidraLockTakesOverStaleOwner: a lock file left by a dead run must not
// block the cache. flock is already free, so the takeover is immediate, logged,
// and the metadata is replaced with our pid.
func TestGhidraLockTakesOverStaleOwner(t *testing.T) {
	dir := t.TempDir()
	lockPath := filepath.Join(dir, "lock")
	dead := deadPID(t)
	old := time.Now().Add(-3 * time.Hour)
	if err := os.WriteFile(lockPath, fmt.Appendf(nil, "%d %d\n", dead, old.UnixNano()), 0o644); err != nil {
		t.Fatal(err)
	}
	var logs []string
	prev := ghidraLockLog
	ghidraLockLog = func(format string, a ...any) { logs = append(logs, fmt.Sprintf(format, a...)) }
	t.Cleanup(func() { ghidraLockLog = prev })
	t.Setenv("LRECON_GHIDRA_TIMEOUT", "1s")
	unlock, err := ghidraLock(dir)
	if err != nil {
		t.Fatalf("lock left by a dead pid was not taken over: %v", err)
	}
	defer unlock()
	if !strings.Contains(strings.Join(logs, "\n"), "stale lock") {
		t.Fatalf("takeover was not logged: %v", logs)
	}
	owner, ok := ghidraLockRead(lockPath)
	if !ok || owner.PID != os.Getpid() {
		t.Fatalf("lock metadata = %+v,%v, want our pid %d", owner, ok, os.Getpid())
	}
}

// TestGhidraLockWaitIsBounded: a live holder blocks, but only until
// LRECON_GHIDRA_LOCK_WAIT, never for the old deadline-sized window.
func TestGhidraLockWaitIsBounded(t *testing.T) {
	dir := t.TempDir()
	unlock, err := ghidraLock(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	t.Setenv("LRECON_GHIDRA_LOCK_WAIT", "300ms")
	start := time.Now()
	if _, err := ghidraLock(dir); err == nil {
		t.Fatal("a second lock was granted while the first was held")
	} else if !strings.Contains(err.Error(), "lock") {
		t.Fatalf("wait error does not name the lock: %v", err)
	}
	// This contract is temporal by nature, so the band is wide on purpose: the
	// lower edge proves the wait happened, the upper only catches a wait that
	// fell back to the 30s default.
	if elapsed := time.Since(start); elapsed < 250*time.Millisecond || elapsed > 3*time.Second {
		t.Fatalf("wait was %s, want about 300ms", elapsed)
	}
}

// TestGhidraCacheKeyIsContentAddressed pins B1's key: sha256 of the bytes and
// the Ghidra build. Path and mtime must not decide it, and neither may the op
// command: every G op answers from the same analysed program, so a per-command
// key made each op import the same bytes again (39 cold imports per binary).
func TestGhidraCacheKeyIsContentAddressed(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a")
	b := filepath.Join(dir, "b")
	for _, p := range []string{a, b} {
		if err := os.WriteFile(p, []byte("same bytes"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	sa, err := os.Stat(a)
	if err != nil {
		t.Fatal(err)
	}
	sb, err := os.Stat(b)
	if err != nil {
		t.Fatal(err)
	}
	key := ghidraEntryKey(a, "12.1.4", sa)
	if again := ghidraEntryKey(b, "12.1.4", sb); again != key {
		t.Fatalf("same bytes at two paths keyed %q and %q", key, again)
	}
	if ghidraEntryKey(a, "12.1.5", sa) == key {
		t.Fatal("a different Ghidra version reused the key")
	}
	if err := os.WriteFile(a, []byte("other bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	sa2, err := os.Stat(a)
	if err != nil {
		t.Fatal(err)
	}
	if ghidraEntryKey(a, "12.1.4", sa2) == key {
		t.Fatal("changed bytes kept the key")
	}
}

// TestGhidraCacheKeyIgnoresCommand: two G ops on the same bytes are two queries
// against one analysis. Keying by command is what made a 39-command sweep
// import the same binary 39 times, each import ~50 s and each vulnerable to the
// caller's 60 s cap.
func TestGhidraCachedRunSharesOneEntryAcrossCommands(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("same bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	modes := filepath.Join(dir, "modes.log")
	shim := ghidraShim(t, dir, fmt.Sprintf(`case " $* " in
  *" -process "*) echo reused >> '%s' ;;
  *) echo fresh >> '%s' ;;
esac
for a in "$@"; do out="$a"; done
printf '{"ok":true}' > "$out"
`, modes, modes))
	t.Setenv("LRECON_GHIDRA_TIMEOUT", "20s")
	root := filepath.Join(dir, "cache")
	if _, mode, err := ghidraCachedRun(shim, root, target, "12.1.4", "list_names", st, nil); err != nil || mode != "fresh" {
		t.Fatalf("first op = %q,%v; want a fresh import", mode, err)
	}
	if _, mode, err := ghidraCachedRun(shim, root, target, "12.1.4", "list_segments", st, nil); err != nil || mode != "reused" {
		t.Fatalf("second op on the same bytes = %q,%v; want reused, not a second import", mode, err)
	}
	if b, err := os.ReadFile(modes); err != nil || strings.Count(string(b), "fresh") != 1 {
		t.Fatalf("import count = %q,%v; want exactly one", string(b), err)
	}
}

// TestGhidraCachedRunKeepsEntryAfterRefusal: an in-band script refusal (a bad
// address, no such function) is an answer about a complete analysis, not a
// broken import. Dropping the entry made the next op pay the ~100 s import
// again, so one typo cost every later call a cold run.
func TestGhidraCachedRunKeepsEntryAfterRefusal(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("same bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	bad := ghidraShim(t, dir, `for a in "$@"; do out="$a"; done
printf '{"error":"java.lang.IllegalArgumentException: no function named 0x1"}' > "$out"
`)
	t.Setenv("LRECON_GHIDRA_TIMEOUT", "20s")
	root := filepath.Join(dir, "cache")
	res, mode, err := ghidraCachedRun(bad, root, target, "12.1.4", "analyze_function", st, nil)
	if err == nil || !isScriptRefusal(err) || mode != "" || res != nil {
		t.Fatalf("refusal = %v,%q,%v; want a script refusal with no answer", err, mode, res)
	}
	good := ghidraShim(t, dir, `case " $* " in
  *" -process "*) echo reused >&2 ;;
esac
for a in "$@"; do out="$a"; done
printf '{"functions":1}' > "$out"
`)
	if _, mode, err := ghidraCachedRun(good, root, target, "12.1.4", "analyze_function", st, nil); err != nil || mode != "reused" {
		t.Fatalf("op after a refusal = %q,%v; want reused (the analysis was kept)", mode, err)
	}
}

// TestGhidraBudgetScalesWithTargetSize pins C7's acceptance: the deadline is a
// function of the target, not one fixed 2 minute window. A 34 MB Go binary
// legitimately needs minutes; a 4 KB shim must not inherit that budget.
func TestGhidraBudgetScalesWithTargetSize(t *testing.T) {
	if got := ghidraBudget(4096); got != ghidraTimeoutDefault {
		t.Fatalf("4 KiB budget = %s, want the %s floor", got, ghidraTimeoutDefault)
	}
	if got, want := ghidraBudget(10<<20), ghidraTimeoutDefault+10*ghidraBudgetPerMiB; got != want {
		t.Fatalf("10 MiB budget = %s, want %s", got, want)
	}
	if got := ghidraBudget(100 << 30); got != ghidraBudgetMax {
		t.Fatalf("100 GiB budget = %s, want the %s cap", got, ghidraBudgetMax)
	}
}

// TestGhidraTimeoutForPathSeesSizeAndEnv: the path-based lookup must read the
// file, and an explicit LRECON_GHIDRA_TIMEOUT must win in both directions.
func TestGhidraTimeoutForPathSeesSizeAndEnv(t *testing.T) {
	dir := t.TempDir()
	small := filepath.Join(dir, "small.bin")
	big := filepath.Join(dir, "big.bin")
	if err := os.WriteFile(small, []byte("MZ"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(big, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(big, 8<<20); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LRECON_GHIDRA_TIMEOUT", "")
	if got := ghidraTimeoutForPath(small); got != ghidraTimeoutDefault {
		t.Fatalf("small file = %s, want %s", got, ghidraTimeoutDefault)
	}
	if got := ghidraTimeoutForPath(big); got <= ghidraTimeoutDefault {
		t.Fatalf("8 MiB file = %s, want more than the %s floor", got, ghidraTimeoutDefault)
	}
	if got := ghidraTimeoutForPath(filepath.Join(dir, "absent.bin")); got != ghidraTimeoutDefault {
		t.Fatalf("absent file = %s, want %s", got, ghidraTimeoutDefault)
	}
	t.Setenv("LRECON_GHIDRA_TIMEOUT", "45m")
	if got := ghidraTimeoutForPath(big); got != 45*time.Minute {
		t.Fatalf("env override = %s, want 45m", got)
	}
	t.Setenv("LRECON_GHIDRA_TIMEOUT", "1ms")
	if got := ghidraTimeoutForPath(big); got != time.Millisecond {
		t.Fatalf("forced budget = %s, want 1ms", got)
	}
}
