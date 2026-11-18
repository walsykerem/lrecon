package main

// One Ghidra project per (binary, size, mtime), reused by every G item: the
// first call imports and analyses, the other 38 reopen the program with
// -process, which turns 39 ten-second imports into one.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	ghidraCacheMaxEntries = 20
	ghidraCacheMaxAge     = 7 * 24 * time.Hour
	ghidraLockPoll        = 200 * time.Millisecond
	ghidraLockWaitDefault = 30 * time.Second
	// Per-entry answer bounds: one file per (command,args) pair, so an op run
	// over many addresses would otherwise grow the entry without limit.
	ghidraAnswerMaxFiles = 128
	ghidraAnswerMaxBytes = 64 << 20
	ghidraReadMax        = 32 << 20
)

// ghidraScriptSource is the postScript source the cache key pins. A test swaps
// it to prove that a script change invalidates an entry.
var ghidraScriptSource = nativeOpScript

// ghidraScriptDigest identifies the postScript source. The entry key includes
// it because a lrecon upgrade can change NativeOp.java while the target bytes
// and the Ghidra build stay the same; without it the new answer semantics would
// be served from an entry the old script built.
func ghidraScriptDigest(script string) string {
	sum := sha256.Sum256([]byte(script))
	return hex.EncodeToString(sum[:])[:16]
}

// ghidraLockWait bounds a waiter: waiting for a live import is honest, waiting
// behind a holder that died or hung is B8's permanent lockout. It is separate
// from the op budget so a caller can give up sooner than a long import.
func ghidraLockWait(budget ...time.Duration) time.Duration {
	v := nativeEnv("LRECON_GHIDRA_LOCK_WAIT")
	if v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return time.Duration(n) * time.Second
		}
	}
	// A waiter has no reason to wait longer than the import it waits for;
	// the lock records that budget so stale detection needs no guess.
	if len(budget) > 0 && budget[0] > 0 {
		return budget[0]
	}
	return ghidraLockWaitDefault
}

// ghidraCacheRoot resolves the cache dir. LRECON_GHIDRA_CACHE=off disables the
// cache, any other value is the root, empty means the user cache dir.
func ghidraCacheRoot() (string, bool) {
	switch v := nativeEnv("LRECON_GHIDRA_CACHE"); {
	case strings.EqualFold(v, "off"):
		return "", false
	case v != "":
		// Absolute root: analyzeHeadless runs with cmd.Dir set to the entry, so
		// a relative root made -scriptPath and the project location resolve
		// against the entry and the run failed with "Script not found".
		if abs, err := filepath.Abs(v); err == nil {
			return abs, true
		}
		return v, true
	}
	base, err := os.UserCacheDir()
	if err != nil {
		return "", false
	}
	return filepath.Join(base, "lrecon-ghidra"), true
}

// ghidraEntryKey is B1's cache key: sha256 of the target's bytes, the Ghidra
// build and the postScript source. Hashing the file means a rebuild at the same
// path cannot answer from the previous analysis, while the same bytes copied to
// another path can share one import. The version keeps an older Ghidra from
// claiming an entry it did not build, and the script digest does the same for
// a lrecon upgrade that changes NativeOp.java.
//
// The op command is deliberately not part of the key. Every G op answers from
// the same analysed program, and only the postScript differs; keying by command
// made each op import the binary again (39 ops x ~50 s on a 150 KB Mach-O) and
// left a caller's 60 s cap to kill the import before it could answer.
func ghidraEntryKey(abs, version string, st os.FileInfo) string {
	f, err := os.Open(abs)
	if err != nil {
		return ghidraCacheKey(abs, st)
	}
	h := sha256.New()
	_, copyErr := io.Copy(h, f)
	f.Close()
	if copyErr != nil {
		return ghidraCacheKey(abs, st)
	}
	fmt.Fprintf(h, "\x00%s\x00%s", version, ghidraScriptDigest(ghidraScriptSource))
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// ghidraCacheKey is the fallback when the target's bytes cannot be read (an
// unreadable or special file): size and mtime still keep a rebuild from
// answering with the previous analysis under the same path. It cannot see a
// Ghidra or script upgrade, so a fallback entry may outlive one.
func ghidraCacheKey(abs string, st os.FileInfo) string {
	sum := sha256.Sum256(fmt.Appendf(nil, "%s\x00%d\x00%d", abs, st.Size(), st.ModTime().UnixNano()))
	return hex.EncodeToString(sum[:])[:16]
}

// ghidraMeta is what a cache hit needs: which program to reopen and when the
// entry was built. Program is the name analyzeHeadless gave the import.
type ghidraMeta struct {
	Target  string `json:"target"`
	Program string `json:"program"`
	Created string `json:"created"`
}

// ghidraLookup reports a usable entry. A half-written or corrupt entry is a
// miss, never a panic and never a guess.
func ghidraLookup(root, key string) (ghidraMeta, bool) {
	b, err := os.ReadFile(filepath.Join(root, key, "meta.json"))
	if err != nil {
		return ghidraMeta{}, false
	}
	var m ghidraMeta
	if err := json.Unmarshal(b, &m); err != nil || m.Program == "" {
		return ghidraMeta{}, false
	}
	if st, err := os.Stat(filepath.Join(root, key, "project")); err != nil || !st.IsDir() {
		return ghidraMeta{}, false
	}
	return m, true
}

// ghidraLockOwner is the last run that wrote the lock file. flock itself is
// released by the kernel when a process dies, so this metadata is what proves
// who held it and for how long: B8's stale lock came from having neither.
type ghidraLockOwner struct {
	PID    int
	Since  time.Time
	Budget time.Duration
}

// ghidraLockLog is a seam: the stale-takeover test reads the warning without
// capturing the process log.
var ghidraLockLog = log.Printf

func ghidraLockRead(path string) (ghidraLockOwner, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return ghidraLockOwner{}, false
	}
	fields := strings.Fields(string(b))
	if len(fields) < 2 {
		return ghidraLockOwner{}, false
	}
	pid, perr := strconv.Atoi(fields[0])
	ns, nerr := strconv.ParseInt(fields[1], 10, 64)
	if perr != nil || nerr != nil || pid <= 0 || ns <= 0 {
		return ghidraLockOwner{}, false
	}
	o := ghidraLockOwner{PID: pid, Since: time.Unix(0, ns)}
	if len(fields) >= 3 {
		if bns, err := strconv.ParseInt(fields[2], 10, 64); err == nil && bns > 0 {
			o.Budget = time.Duration(bns)
		}
	}
	return o, true
}

// ghidraPIDAlive: EPERM still means the pid exists.
func ghidraPIDAlive(pid int) bool {
	return pidAlive(pid)
}

// ghidraStaleLock names why a recorded holder no longer owns the entry: its pid
// is gone (take over at once) or it has held longer than twice the op budget (a
// hung run). Our own pid is never stale: another goroutine may hold it.
func ghidraStaleLock(o ghidraLockOwner, now time.Time) (string, bool) {
	if o.PID == os.Getpid() {
		return "", false
	}
	if !ghidraPIDAlive(o.PID) {
		return fmt.Sprintf("owner pid %d is gone", o.PID), true
	}
	budget := o.Budget
	if budget <= 0 {
		// Locks written before the budget field existed still get an answer.
		budget = ghidraTimeout()
	}
	if age := now.Sub(o.Since); age > 2*budget {
		return fmt.Sprintf("held for %s, over twice the %s budget", age.Round(time.Second), budget), true
	}
	return "", false
}

// ghidraClaim records this run as the holder, after logging a takeover when the
// previous owner is stale. The lock file stays (removing it would let two runs
// flock two inodes); only its metadata is replaced.
func ghidraClaim(f *os.File, path string, budget time.Duration) {
	now := time.Now()
	if owner, ok := ghidraLockRead(path); ok {
		if reason, stale := ghidraStaleLock(owner, now); stale {
			ghidraLockLog("lrecon: ghidra cache %s: taking over stale lock: %s", filepath.Dir(path), reason)
		}
	}
	if err := f.Truncate(0); err != nil {
		return
	}
	if _, err := f.Seek(0, 0); err != nil {
		return
	}
	if budget <= 0 {
		budget = ghidraTimeout()
	}
	fmt.Fprintf(f, "%d %d %d\n", os.Getpid(), now.UnixNano(), int64(budget))
}

// ghidraLock serialises import and -process runs on one entry: Ghidra itself
// refuses a second writer on a project. The lock is a kernel flock, so a run
// that dies releases it instead of leaving a file that has to be guessed about:
// an mtime heuristic let a slow import be mistaken for a dead one. B8: waiting
// is bounded by LRECON_GHIDRA_LOCK_WAIT, and a recorded owner that is dead (or
// older than twice the op budget) is taken over and logged, never waited on
// forever.
func ghidraLock(dir string, budget ...time.Duration) (func(), error) {
	var b time.Duration
	if len(budget) > 0 {
		b = budget[0]
	}
	path := filepath.Join(dir, "lock")
	// Never removed: two runs must not end up flocking two different inodes.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return nil, err
	}
	wait := ghidraLockWait(b)
	deadline := time.Now().Add(wait)
	for {
		switch ok, err := lockFile(f); {
		case ok:
			ghidraClaim(f, path, b)
			// A clean release empties the owner record. Leaving a dead pid
			// behind made every later run log "taking over stale lock", which
			// reads like a fault when it is only the previous run exiting.
			return func() {
				f.Truncate(0)
				f.Close()
			}, nil
		case err != nil:
			f.Close()
			return nil, err
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			f.Close()
			setRefuseStage("lock")
			if owner, ok := ghidraLockRead(path); ok {
				if reason, stale := ghidraStaleLock(owner, time.Now()); stale {
					return nil, fmt.Errorf("ghidra cache %s: lock wait timed out after %s (%s)", dir, wait, reason)
				}
			}
			return nil, fmt.Errorf("ghidra cache %s: lock wait timed out after %s (LRECON_GHIDRA_LOCK_WAIT)", dir, wait)
		}
		if remaining > ghidraLockPoll {
			remaining = ghidraLockPoll
		}
		time.Sleep(remaining)
	}
}

// ghidraRemoveIdle removes dir only while holding its lock: the try-lock and
// the RemoveAll are one step, so a run that acquires the entry can no longer
// have it deleted between an idle check and the delete. It reports whether it
// removed anything.
func ghidraRemoveIdle(dir string) bool {
	f, err := os.OpenFile(filepath.Join(dir, "lock"), os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return false
	}
	ok, err := lockFile(f)
	if err != nil || !ok {
		f.Close()
		return false
	}
	os.RemoveAll(dir)
	f.Close() // closing the only fd drops the flock; the dir is already gone
	return true
}

// ghidraAnswerPrune bounds one entry's answers: drop files older than the entry
// TTL, then the oldest until the count and total size fit. Best effort.
func ghidraAnswerPrune(dir string) {
	paths, err := filepath.Glob(filepath.Join(dir, "answer-*.json"))
	if err != nil {
		return
	}
	type answer struct {
		path string
		mod  time.Time
		size int64
	}
	var answers []answer
	var total int64
	for _, p := range paths {
		st, err := os.Stat(p)
		if err != nil {
			continue
		}
		if time.Since(st.ModTime()) > ghidraCacheMaxAge {
			os.Remove(p)
			continue
		}
		answers = append(answers, answer{p, st.ModTime(), st.Size()})
		total += st.Size()
	}
	sort.Slice(answers, func(i, j int) bool { return answers[i].mod.Before(answers[j].mod) })
	for len(answers) > ghidraAnswerMaxFiles || (total > ghidraAnswerMaxBytes && len(answers) > 0) {
		os.Remove(answers[0].path)
		total -= answers[0].size
		answers = answers[1:]
	}
}

// ghidraReadCapped bounds one answer read: a corrupt or runaway file must not
// turn a cache hit into a large allocation. A truncated answer fails JSON
// parsing and is treated as a miss.
func ghidraReadCapped(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, ghidraReadMax))
}

// ghidraPrune drops entries older than a week, then the oldest beyond the cap.
// Best effort: a cache cleanup failure must not fail the op.
func ghidraPrune(root string) {
	ents, err := os.ReadDir(root)
	if err != nil {
		return
	}
	type entry struct {
		dir string
		mod time.Time
	}
	var live []entry
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		dir := filepath.Join(root, e.Name())
		st, err := os.Stat(filepath.Join(dir, "meta.json"))
		if err != nil {
			// No meta: debris from a killed import. Age it out first, because a
			// run that has just created the dir has not written the meta yet.
			// The age is read before ghidraRemoveIdle, which bumps the dir's mtime.
			dst, err := os.Stat(dir)
			if err == nil && time.Since(dst.ModTime()) > ghidraTimeout() {
				ghidraRemoveIdle(dir)
			}
			continue
		}
		// An entry somebody holds is a working set, not debris: pruning it
		// under a concurrent run deletes its project and its cwd mid-import.
		if time.Since(st.ModTime()) > ghidraCacheMaxAge {
			if ghidraRemoveIdle(dir) {
				continue
			}
		}
		ghidraAnswerPrune(dir)
		live = append(live, entry{dir, st.ModTime()})
	}
	sort.Slice(live, func(i, j int) bool { return live[i].mod.Before(live[j].mod) })
	for len(live) > ghidraCacheMaxEntries {
		if !ghidraRemoveIdle(live[0].dir) {
			break // the oldest entry is in use; a later run finishes the job
		}
		live = live[1:]
	}
}

// ghidraEntry is one acquired cache slot: the directory, the program to reopen
// (empty means the caller must import), and the flock that makes both
// exclusive. Both postScript routes (NativeOp.java and Meta.java) share it, so
// one import serves every G op on a binary.
type ghidraEntry struct {
	dir     string
	program string
	unlock  func()
}

// ghidraAcquire locks the slot for abs and reports whether it already holds an
// analysed program. A miss clears a half-written project first, because
// importing into a directory that already holds a program collides.
func ghidraAcquire(root, abs, version string, st os.FileInfo) (*ghidraEntry, error) {
	key := ghidraEntryKey(abs, version, st)
	ghidraPrune(root) // before the entry exists: prune removes meta-less dirs
	dir := filepath.Join(root, key)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	unlock, err := ghidraLock(dir, ghidraBudget(st.Size()))
	if err != nil {
		return nil, err
	}
	e := &ghidraEntry{dir: dir, unlock: unlock}
	if m, ok := ghidraLookup(root, key); ok {
		e.program = m.Program
		return e, nil
	}
	os.RemoveAll(filepath.Join(dir, "project"))
	return e, nil
}

// pin records the analysed program so later ops reopen it instead of
// re-importing. It is also written when the postScript refused in-band: that
// refusal is an answer about a complete analysis, not a broken import.
func (e *ghidraEntry) pin(abs string) error {
	meta, _ := json.Marshal(ghidraMeta{Target: abs, Program: filepath.Base(abs), Created: time.Now().UTC().Format(time.RFC3339)})
	return os.WriteFile(filepath.Join(e.dir, "meta.json"), meta, 0o644)
}

// discard drops a project the run proved unusable (a corrupt or half-written
// import) while keeping the lock, so the retry imports into a clean directory.
// Its answers go too: they describe an analysis nobody can trust.
func (e *ghidraEntry) discard() {
	os.RemoveAll(filepath.Join(e.dir, "project"))
	os.Remove(filepath.Join(e.dir, "meta.json"))
	answers, _ := filepath.Glob(filepath.Join(e.dir, "answer-*.json"))
	for _, p := range answers {
		os.Remove(p)
	}
	e.program = ""
}

func (e *ghidraEntry) release() {
	if e.unlock != nil {
		e.unlock()
		e.unlock = nil
	}
}

// ghidraCachedRun reuses an analysed entry, and falls back to one fresh import
// when the entry turns out to be unusable. It never loops: one retry, then the
// error belongs to the caller.
//
// ponytail: an answer for the same command over the same target bytes is kept
// next to the project, so a repeated op costs a file read instead of a JVM
// start; a live JVM (pyghidra/Ghidra Server) would be the engine-level fix but
// is a new dependency.
func ghidraCachedRun(headless, root, abs, version, command string, st os.FileInfo, args []string) (map[string]any, string, error) {
	entry, err := ghidraAcquire(root, abs, version, st)
	if err != nil {
		return nil, "", err
	}
	defer entry.release()
	if res, ok := ghidraAnswerHit(entry.dir, command, args); ok {
		return res, "cached", nil
	}
	if entry.program != "" {
		res, err := ghidraHeadless(headless, entry.dir, abs, command, args, entry.program, false)
		if err == nil {
			// B1: a timeout is a final answer, not a reason to spend the whole
			// budget twice; the project stays for a later attempt.
			if ghidraTimedOut(res) {
				return res, "timeout", nil
			}
			ghidraAnswerStore(entry.dir, command, args, res)
			return res, "reused", nil
		}
		if isScriptRefusal(err) {
			// The project is intact; the op's own answer was the refusal. Keep
			// the entry: wiping it would make one bad address cost a fresh
			// import on every later call.
			return nil, "", err
		}
		// Stale project dir or bad meta: clear the program, keep the lock.
		entry.discard()
	}
	res, err := ghidraHeadless(headless, entry.dir, abs, command, args, "", false)
	if err != nil {
		if isScriptRefusal(err) {
			if perr := entry.pin(abs); perr != nil {
				return nil, "", perr
			}
			return nil, "", err
		}
		return nil, "", err
	}
	if ghidraTimedOut(res) {
		// A partial import is not a cache hit: pinning it would make the next
		// op reuse an analysis that never finished.
		return res, "timeout", nil
	}
	if err := entry.pin(abs); err != nil {
		return nil, "", err
	}
	ghidraAnswerStore(entry.dir, command, args, res)
	return res, "fresh", nil
}

// ghidraAnswerPath names one stored answer inside an entry. The entry itself is
// keyed by the target's bytes, the Ghidra build and the postScript source, so a
// rebuilt target, a newer engine or a new script can never read a previous
// answer. Answers are bounded by ghidraAnswerPrune.
func ghidraAnswerPath(dir, command string, args []string) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s\x00", command)
	for _, a := range args {
		fmt.Fprintf(h, "%s\x00", a)
	}
	return filepath.Join(dir, fmt.Sprintf("answer-%x.json", h.Sum(nil)[:8]))
}

func ghidraAnswerHit(dir, command string, args []string) (map[string]any, bool) {
	path := ghidraAnswerPath(dir, command, args)
	raw, err := ghidraReadCapped(path)
	if err != nil {
		return nil, false
	}
	var res map[string]any
	if json.Unmarshal(raw, &res) != nil || len(res) == 0 {
		// A half-written answer is not a hit; the next run overwrites it.
		os.Remove(path)
		return nil, false
	}
	// A hit is use: refresh the answer and the entry's meta so neither the TTL
	// nor the per-entry bounds evict an entry somebody keeps answering from.
	now := time.Now()
	os.Chtimes(path, now, now)
	os.Chtimes(filepath.Join(dir, "meta.json"), now, now)
	return res, true
}

func ghidraAnswerStore(dir, command string, args []string, res map[string]any) {
	raw, err := json.Marshal(res)
	if err != nil {
		return
	}
	if len(raw) > ghidraReadMax {
		return // a read would truncate it; do not store an answer we cannot serve
	}
	path := ghidraAnswerPath(dir, command, args)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
	}
	ghidraAnswerPrune(dir)
}
