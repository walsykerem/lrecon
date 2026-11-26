package main

// Shared plumbing for the NATIVE inventory items (final.md items 45-90):
// the Ghidra headless runner, the file-layout readers the pure-Go items use,
// the argument channel (env vars, because an op only receives a path) and the
// session file the navigation items share.

import (
	"bytes"
	"context"
	"debug/elf"
	"debug/gosym"
	"debug/macho"
	"debug/pe"
	_ "embed"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed ghidra/scripts/NativeOp.java
var nativeOpScript string

const (
	// B1: a Ghidra op that has not answered in its budget is a budget failure,
	// not a slow answer. The old 10m meant the CLI's own 20s cap killed the
	// process before the library could say why, so every G op looked hung.
	//
	// The floor is 50 s, not 2 min: a caller caps one op at 60 s (the table in
	// skill/references/ops.md, and every probe sweep), so a 120 s floor meant
	// the caller's SIGKILL landed before the timeout envelope and a cold Ghidra
	// run could only ever look like a hang. 50 s leaves room to answer -- data
	// or {error:"timeout",stage:...} -- inside that cap.
	//
	// A cold import of a big target still needs longer than 50 s. That is what
	// LRECON_GHIDRA_TIMEOUT is for: raise the budget for one run, and the single
	// shared cache entry it pins then serves every G op on that binary.
	ghidraTimeoutDefault = 50 * time.Second
	nativeScanCap        = 64 << 20 // bytes scanned for strings/patterns per target
	nativeRowsCap        = 100
)

// warmHint is the way out of a cold timeout: the answer is not "retry blindly",
// it is "pay for the import once with a budget that allows it". Every G op on
// that binary reuses the resulting project, so one long call replaces 39.
const warmHint = "cold import longer than the op budget: run once with LRECON_GHIDRA_TIMEOUT=180s to warm the shared cache; every G op on this binary then reuses it"

// ghidraTimeout is the analyzeHeadless budget per call. LRECON_GHIDRA_TIMEOUT
// (a Go duration, or bare seconds) raises it for big targets: a 34 MB Go
// binary does not finish importing inside the old 3m.
func ghidraTimeout() time.Duration {
	v := nativeEnv("LRECON_GHIDRA_TIMEOUT")
	if v == "" {
		return ghidraTimeoutDefault
	}
	if d, err := time.ParseDuration(v); err == nil && d > 0 {
		return d
	}
	if n, err := strconv.Atoi(v); err == nil && n > 0 {
		return time.Duration(n) * time.Second
	}
	return ghidraTimeoutDefault
}

const (
	// C7: the deadline has to follow the target, not a fixed 120 s. Ghidra's
	// import cost grows with input size (18 s for /bin/ls, minutes for a 34 MB
	// Go binary), so a flat cap either hangs a big target or wastes a small one.
	ghidraBudgetPerMiB = 12 * time.Second
	ghidraBudgetMax    = 30 * time.Minute
)

// ghidraBudget is the import budget for a target of this size: a two minute
// floor (the mailcase CLI cap was 20 s, too small to tell "hung" from "big")
// plus twelve seconds per MiB, capped at half an hour: 3 s/MiB timed out on cold
// imports and answered 0 functions where 12 s/MiB completes the scope.
func ghidraBudget(size int64) time.Duration {
	if size < 0 {
		size = 0
	}
	b := ghidraTimeoutDefault + time.Duration(size/(1<<20))*ghidraBudgetPerMiB
	if b > ghidraBudgetMax {
		return ghidraBudgetMax
	}
	return b
}

// ghidraTimeoutForPath is the budget one call gets. An explicit
// LRECON_GHIDRA_TIMEOUT still wins (an operator overriding the policy must not
// be overridden by a size heuristic); LRECON_OP_DEADLINE is the generic
// per-op switch and is honored as the fallback, otherwise the target's size
// decides.
func ghidraTimeoutForPath(path string) time.Duration {
	if nativeEnv("LRECON_GHIDRA_TIMEOUT") != "" {
		return ghidraTimeout()
	}
	if v := nativeEnv(opDeadlineEnv); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	if st, err := os.Stat(path); err == nil && !st.IsDir() {
		return ghidraBudget(st.Size())
	}
	return ghidraTimeoutDefault
}

// ghidraExec runs analyzeHeadless in its own process group so a timeout kills
// java too. The wrapper is a shell script; killing only it leaves java holding
// our pipes, and cmd.Run would never return.
func ghidraExec(ctx context.Context, name string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, name, args...)
	setpgroup(cmd)
	cmd.Cancel = func() error { return killGroup(cmd.Process.Pid) }
	cmd.WaitDelay = 5 * time.Second
	return cmd
}

// ghidraReap kills whatever analyzeHeadless left behind. The group id comes
// from cmd.Process.Pid taken before Wait: Wait releases the process and zeroes
// it, so a leaked java child can only be found by its group. When the wrapper
// exits before the deadline, exec never calls Cancel at all: it waits WaitDelay
// for the pipe java still holds, then returns ErrWaitDelay with java alive, so
// this reap is what actually ends the import.
func ghidraReap(pgid int) {
	if pgid > 0 {
		killGroup(pgid)
		untrackGroup(pgid)
	}
}

func ghidraSkipReason() string {
	return "ghidra analyzeHeadless not installed: run from a Ghidra 12.x install, see skill/references/ghidra.md"
}

// findGhidra locates analyzeHeadless: explicit LRECON_GHIDRA, then PATH, then
// the usual install roots. The newest version wins so a stale 11.x does not
// shadow 12.x. LRECON_GHIDRA is authoritative (a bad value is an error, not a
// silent fallback) so a test can prove the absent-tool path.
func findGhidra() (string, string, error) {
	if v := strings.TrimSpace(os.Getenv("LRECON_GHIDRA")); v != "" {
		if st, err := os.Stat(v); err == nil && !st.IsDir() {
			return v, ghidraVersion(v), nil
		}
		return "", "", fmt.Errorf("LRECON_GHIDRA=%s is not an executable file", v)
	}
	if v := strings.TrimSpace(os.Getenv("LRECON_ANALYZEHEADLESS")); v != "" {
		if st, err := os.Stat(v); err == nil && !st.IsDir() {
			return v, ghidraVersion(v), nil
		}
		return "", "", fmt.Errorf("LRECON_ANALYZEHEADLESS=%s is not an executable file", v)
	}
	if p, err := exec.LookPath("analyzeHeadless"); err == nil {
		return p, ghidraVersion(p), nil
	}
	var cands []string
	// GHIDRA_INSTALL_DIR is what Ghidra's own launcher exports; GHIDRA_HOME is
	// the older name people still use. Both point at <install>, not <install>/support.
	for _, key := range []string{"GHIDRA_INSTALL_DIR", "GHIDRA_HOME"} {
		if h := strings.TrimSpace(os.Getenv(key)); h != "" {
			cands = append(cands, filepath.Join(h, "support", "analyzeHeadless"))
		}
	}
	if home, err := os.UserHomeDir(); err == nil {
		for _, g := range []string{
			filepath.Join(home, "tools", "ghidra*", "support", "analyzeHeadless"),
			filepath.Join(home, "ghidra*", "support", "analyzeHeadless"),
		} {
			if m, err := filepath.Glob(g); err == nil {
				cands = append(cands, m...)
			}
		}
	}
	for _, g := range []string{
		"/opt/homebrew/Cellar/ghidra/*/libexec/support/analyzeHeadless",
		"/usr/local/Cellar/ghidra/*/libexec/support/analyzeHeadless",
		"/opt/ghidra*/support/analyzeHeadless",
		"/Applications/ghidra_*/support/analyzeHeadless",
	} {
		m, err := filepath.Glob(g)
		if err != nil {
			continue
		}
		cands = append(cands, m...)
	}
	sort.Strings(cands)
	for _, cand := range slices.Backward(cands) {
		if st, err := os.Stat(cand); err == nil && !st.IsDir() {
			return cand, ghidraVersion(cand), nil
		}
	}
	return "", "", errors.New("analyzeHeadless not found")
}

func ghidraVersion(headless string) string {
	root := filepath.Dir(filepath.Dir(headless)) // <install>/support/analyzeHeadless
	b, err := os.ReadFile(filepath.Join(root, "Ghidra", "application.properties"))
	if err == nil {
		for line := range strings.SplitSeq(string(b), "\n") {
			line = strings.TrimSpace(line)
			if v, ok := strings.CutPrefix(line, "application.version="); ok {
				return strings.TrimSpace(v)
			}
		}
	}
	if base := filepath.Base(root); base != "libexec" && base != "support" {
		return base
	}
	return "unknown"
}

// ghidraOp is the one runner every G item uses: one import, one postScript,
// one JSON answer. analyzeHeadless writes a mountain of log lines to stdout and
// its exit code does not report analysis failures, so the script's JSON file is
// the answer and stderr's first line is the error.
// ghidraFinder is a seam for the absent-tool test: findGhidra also globs the
// Homebrew install roots, so clearing PATH alone cannot prove the skip branch.
var ghidraFinder = findGhidra

// ghidraNativeKinds are the kinds ghidra headless can import: it decompiles
// native machine code, not bytecode or managed metadata.
var ghidraNativeKinds = map[string]bool{"elf": true, "macho": true, "pe": true}

// ghidraKindRefusal is the managed guard every route-G item shares: a managed
// assembly arrives as its own kind (pe-dotnet), so analyzeHeadless would import
// it and answer about a machine code file that does not exist. Returning a skip
// keeps the answer honest instead of empty. A directory or unreadable path gets
// nil here so the caller keeps its own message. Probe re-reads the target; that
// is noise next to one headless analysis.
func ghidraKindRefusal(path string) *skip {
	if path == "" {
		return nil
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil
	}
	st, err := os.Stat(abs)
	if err != nil || st.IsDir() {
		return nil
	}
	d, err := Probe(abs)
	if err != nil || ghidraNativeKinds[d.Kind] {
		return nil
	}
	return skipf("%s: no decompiler kind here; ghidra headless decompiles native code only", d.Kind)
}

// ghidraTimeoutRefusal turns the internal timeout envelope into the refusal the
// CLI contract promises: exit 2, kind:"timeout", stage. The envelope stays a map
// inside ghidraHeadless so a partial script answer is still observable there,
// but an op call has to answer "timed out" as a refusal, not exit 0 with
// result.error, which read like success to a caller checking rc.
func ghidraTimeoutRefusal(res map[string]any, command string) error {
	if v, _ := res["error"].(string); v != "timeout" {
		return nil
	}
	stage, _ := res["stage"].(string)
	if stage != "" {
		setRefuseStage(stage)
	}
	budget, _ := res["budget"].(string)
	if budget == "" {
		budget = "its deadline"
	}
	if stage == "" {
		return fmt.Errorf("ghidra %s timed out after %s; raise LRECON_GHIDRA_TIMEOUT or LRECON_OP_DEADLINE", command, budget)
	}
	return fmt.Errorf("ghidra %s timed out after %s (stage %s); raise LRECON_GHIDRA_TIMEOUT or LRECON_OP_DEADLINE", command, budget, stage)
}

func ghidraOp(path, command string, args ...string) (any, error) {
	if s := ghidraKindRefusal(path); s != nil {
		return s, nil
	}
	// The target is checked before the engine: a path that is not there was
	// never read, so it owes an io error rather than "install Ghidra".
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	st, err := os.Stat(abs)
	if err != nil {
		return nil, fmt.Errorf("%s: %v", path, err)
	} else if st.IsDir() {
		return nil, fmt.Errorf("%s is a directory, not a binary", path)
	}
	// K7: a universal binary hides which slice was analysed. Ghidra imports the
	// first one (measured on /usr/bin/aa: 357 functions, entry 0x100000798, the
	// x86-64 slice), so name it in the answer and refuse a request for a slice
	// this run cannot import instead of answering about the wrong one.
	arch, slices := ghidraSlice(abs)
	if want := strings.TrimSpace(os.Getenv("LRECON_ARCH")); want != "" && want != arch {
		return nil, fmt.Errorf("%s: Ghidra imports the first slice (%s) of %s; LRECON_ARCH=%s needs lipo -thin %s -output <slice> first", path, arch, slices, want, want)
	}
	headless, version, err := ghidraFinder()
	if err != nil {
		// Name the configured value, not just "not installed": a bad
		// LRECON_ANALYZEHEADLESS must be visible in the answer.
		return skipf("%s: %v", ghidraSkipReason(), err), nil
	}
	if root, cached := ghidraCacheRoot(); cached {
		res, _, err := ghidraCachedRun(headless, root, abs, version, command, st, args)
		if err != nil {
			return nil, err
		}
		if err := ghidraTimeoutRefusal(res, command); err != nil {
			return nil, err
		}
		// Cache provenance stays out of the answer: a cold run and a hit must
		// serialize byte-identically (123/126/391), and the timing already says
		// whether the project was reused.
		res["script"] = "NativeOp.java " + command
		res["ghidra_version"] = version
		if arch != "" {
			res["arch"] = arch
		}
		return res, nil
	}
	dir, err := tempDir("lrecon-native-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	res, err := ghidraHeadless(headless, dir, abs, command, args, "", true)
	if err != nil {
		return nil, err
	}
	if err := ghidraTimeoutRefusal(res, command); err != nil {
		return nil, err
	}
	res["script"] = "NativeOp.java " + command
	res["ghidra_version"] = version
	if arch != "" {
		res["arch"] = arch
	}
	return res, nil
}

// ghidraSlice names the slice of a Mach-O Ghidra will import and, for a
// universal binary, the full slice list the caller can choose from. A thin
// image or a non-Mach-O target answers with no slices; the arch is best effort
// and never fails an op that Ghidra itself may still analyse.
func ghidraSlice(path string) (arch, slices string) {
	if ff, err := macho.OpenFat(path); err == nil {
		defer ff.Close()
		names := make([]string, 0, len(ff.Arches))
		for _, a := range ff.Arches {
			names = append(names, sliceArch(a.Cpu, a.SubCpu))
		}
		if len(names) == 0 {
			return "", ""
		}
		return names[0], strings.Join(names, ",")
	}
	if f, err := macho.Open(path); err == nil {
		defer f.Close()
		return sliceArch(f.Cpu, f.SubCpu), ""
	}
	return "", ""
}

// sliceArch keeps the subtype lipo prints: an arm64e slice is what
// LRECON_ARCH must accept, and machoArch alone answers "arm64" for it.
func sliceArch(c macho.Cpu, sub uint32) string {
	if c == macho.CpuArm64 && sub&0xff == 2 {
		return "arm64e"
	}
	return machoArch(c)
}

// answerCapDefault is the most one JSON answer may occupy in-line. Past it the
// answer is written to a file and the caller is told where: a 10 MiB blob on
// stdout is not readable and not addressable, and a silently shortened answer
// would look complete.
const answerCapDefault = 10 << 20

// answerCap lets a test drive the spill path without producing 10 MiB of
// Ghidra output; the default stands unless the environment lowers it.
func answerCap() int {
	if v := os.Getenv("LRECON_ANSWER_CAP_BYTES"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n < answerCapDefault {
			return n
		}
	}
	return answerCapDefault
}

// capAnswer spills an oversized answer to a file and returns the envelope
// B13/404 asks for: written_to, count, truncated. It guards every op answer,
// not only Ghidra ones: a 10 MiB blob on stdout is not readable and a silently
// shortened answer would look complete.
func capAnswer(res map[string]any) map[string]any {
	capBytes := answerCap()
	// The cap must be measured on the bytes stdout prints, or indentation can
	// inflate an answer past the ceiling the envelope promised.
	b, err := json.MarshalIndent(res, "", "  ")
	if err != nil || len(b) <= capBytes {
		return res
	}
	f, err := os.CreateTemp("", "lrecon-answer-*.json")
	if err != nil {
		return res
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		os.Remove(f.Name())
		return res
	}
	if err := f.Close(); err != nil {
		os.Remove(f.Name())
		return res
	}
	out := map[string]any{
		"op":         res["op"],
		"written_to": f.Name(),
		"count":      answerRecords(b),
		"truncated":  true,
		"bytes":      len(b),
		"cap_bytes":  capBytes,
		"basis":      "full answer spilled to written_to; this envelope is a pointer, not the data",
	}
	if t, ok := res["target"]; ok {
		out["target"] = t
	}
	// An opt-in envelope travels with the pointer: a spilled answer still has
	// to say whether it is complete and how much it parsed. total is the
	// count-only cap state, so a pointer over a capped table keeps it.
	for _, key := range []string{"coverage", "partial", "total"} {
		if v, ok := res[key]; ok {
			out[key] = v
		}
	}
	return out
}

// answerRecords counts the records the spilled JSON holds, so a spilled pointer
// says how much is in the file rather than only how big it is. It reads the
// printed bytes, not the Go value: an op answers with its own structs and
// slices, and a type switch over []any / map[string]any saw none of them.
func answerRecords(b []byte) int {
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return 0
	}
	return recordsIn(v)
}

// recordsIn walks a nested value: an op wrapper carries the real answer under
// "result", so a top-level-only count reports an empty spill.
func recordsIn(v any) int {
	switch x := v.(type) {
	case []any:
		return len(x)
	case map[string]any:
		n := 0
		for _, v := range x {
			n += recordsIn(v)
		}
		return n
	}
	return 0
}

// ghidraTimeoutAnswer is the answer when one headless pass overruns its budget.
// It is an envelope, not a plain error line: stage names what ran out of time
// (a fresh import, a cached project being reopened, or the postScript after it
// had already written part of an answer), and partial carries whatever the
// script had flushed, so a long import is not thrown away without a trace.
// ghidraCompleteAnswer reads the postScript's answer and reports whether it is
// whole. NativeOp.java writes exactly one JSON object, in one write, after
// dispatch returns, so a parseable object carrying "op" is the entire answer
// rather than a prefix of one. An in-band "error" is the script refusing, not a
// completed read, so it stays on the refusal path.
func ghidraCompleteAnswer(path string) (map[string]any, bool) {
	b, err := os.ReadFile(path)
	if err != nil || len(b) == 0 {
		return nil, false
	}
	var res map[string]any
	if err := json.Unmarshal(b, &res); err != nil {
		return nil, false
	}
	if _, ok := res["op"]; !ok {
		return nil, false
	}
	if msg, _ := res["error"].(string); msg != "" {
		return nil, false
	}
	return res, true
}

func ghidraTimeoutAnswer(dir, abs, program string, budget time.Duration) map[string]any {
	stage := "import"
	if program != "" {
		stage = "analyze"
	}
	env := map[string]any{
		"error":  "timeout",
		"stage":  stage,
		"budget": budget.String(),
		"target": filepath.Base(abs),
	}
	if b, err := ghidraReadCapped(filepath.Join(dir, "result.json")); err == nil && len(b) > 0 {
		var partial map[string]any
		if json.Unmarshal(b, &partial) == nil && len(partial) > 0 {
			env["stage"] = "post"
			env["partial"] = true
			env["result"] = partial
		}
	}
	addWarmHint(env)
	return env
}

// addWarmHint explains a stage=import timeout: the way out is one long run that
// pins the shared cache entry, not a blind retry against the same budget.
func addWarmHint(env map[string]any) {
	if env["stage"] == "import" {
		env["hint"] = warmHint
	}
}

// ghidraScriptRefusal separates "the run finished, the op answered with a
// refusal" from "the run failed". The import and analysis are complete, so the
// project is reusable: a bad address must not throw away a 100 s import and make
// every later call re-import the same bytes.
type ghidraScriptRefusal struct{ msg string }

func (e *ghidraScriptRefusal) Error() string { return e.msg }

func isScriptRefusal(err error) bool {
	var r *ghidraScriptRefusal
	return errors.As(err, &r)
}

// writeIfChanged keeps a script's mtime when its bytes already match. Ghidra
// recompiles a postScript whose file is newer than its cached class, and that
// Java compile costs ~16 s on this install (measured: 16.7 s -> 0.8 s for the
// same script). Rewriting identical bytes made every cached Ghidra call pay it.
func writeIfChanged(path string, b []byte) error {
	if old, err := os.ReadFile(path); err == nil && bytes.Equal(old, b) {
		return nil
	}
	return os.WriteFile(path, b, 0o644)
}

// ghidraTimedOut reads the envelope back. The cache must not pin a partial
// import as reusable, and the caller must not fall back to a second import
// when the first one already spent the whole budget.
func ghidraTimedOut(res map[string]any) bool {
	v, _ := res["error"].(string)
	return v == "timeout"
}

// ghidraHeadless runs one analyzeHeadless pass over dir. An empty program means
// a fresh import into dir/project; otherwise the program already in that
// project is reopened with -process. deleteProject is the throwaway-tempdir
// behaviour, a cached project must survive its run.
func ghidraHeadless(headless, dir, abs, command string, args []string, program string, deleteProject bool) (map[string]any, error) {
	// analyzeHeadless refuses to create the project dir itself.
	project := filepath.Join(dir, "project")
	if err := os.MkdirAll(project, 0o755); err != nil {
		return nil, err
	}
	scripts := filepath.Join(dir, "scripts")
	if err := os.MkdirAll(scripts, 0o755); err != nil {
		return nil, err
	}
	if err := writeIfChanged(filepath.Join(scripts, "NativeOp.java"), []byte(nativeOpScript)); err != nil {
		return nil, err
	}
	out := filepath.Join(dir, "result.json")
	os.Remove(out) // a previous run's answer must not pass for this one
	timeout := ghidraTimeoutForPath(abs)
	argv := []string{project, "lrecon"}
	if program == "" {
		// Ghidra's own per-file analysis budget defaults to 300s and truncates a
		// big import (34 MB Go binary) even when our deadline allows more.
		argv = append(argv, "-import", abs,
			"-analysisTimeoutPerFile", strconv.Itoa(int(timeout.Seconds())))
	} else {
		// The project is already analysed: re-analysing it every call is the cost
		// this cache exists to remove.
		argv = append(argv, "-process", program, "-noanalysis")
	}
	argv = append(argv, "-scriptPath", scripts, "-postScript", "NativeOp.java", command, out)
	argv = append(argv, args...)
	if deleteProject {
		argv = append(argv, "-deleteProject")
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := ghidraExec(ctx, headless, argv...)
	cmd.Dir = dir
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			if stage, _ := ghidraTimeoutAnswer(dir, abs, program, timeout)["stage"].(string); stage != "" {
				setRefuseStage(stage)
			}
		}
		return nil, fmt.Errorf("ghidra analyzeHeadless: %v", err)
	}
	pgid := cmd.Process.Pid // Wait releases the process; the group outlives it
	trackGroup(pgid)        // A4: a signal takes java down with the wrapper
	runErr := cmd.Wait()
	ghidraReap(pgid)
	// ErrWaitDelay only says some child still held our pipes until the reap; the
	// script's JSON is the answer, so it is not a run failure when that arrived.
	if errors.Is(runErr, exec.ErrWaitDelay) {
		runErr = nil
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		// A complete postScript answer that outlived the exit budget is still
		// the answer: analyzeHeadless can spend a long time shutting the JVM
		// down (or lose the CPU to another import) after the script has written
		// its JSON. Discarding that made route-G ops look unsupported on
		// targets they had just analysed.
		if res, ok := ghidraCompleteAnswer(out); ok {
			res["deadline_overrun"] = timeout.String()
			return res, nil
		}
		// The group is dead by now (Cancel killed it, the reap covered a wrapper
		// that exited early). B1: an overrun is a structured answer, so a caller
		// can tell import from analyze from post instead of regexing a sentence.
		res := ghidraTimeoutAnswer(dir, abs, program, timeout)
		if stage, _ := res["stage"].(string); stage != "" {
			setRefuseStage(stage)
		}
		return res, nil
	}
	b, readErr := ghidraReadCapped(out)
	if readErr != nil || len(b) == 0 {
		return nil, fmt.Errorf("ghidra analyzeHeadless %q on %s: %s", command, filepath.Base(abs),
			rtCauseLine(stderr.String(), stdout.String(), runErr))
	}
	var res map[string]any
	if err := json.Unmarshal(b, &res); err != nil {
		return nil, fmt.Errorf("ghidra script %q wrote unparsable JSON: %v", command, err)
	}
	if msg, ok := res["error"].(string); ok && msg != "" {
		return res, &ghidraScriptRefusal{fmt.Sprintf("ghidra script %q refused: %s", command, msg)}
	}
	if runErr != nil {
		return nil, fmt.Errorf("ghidra analyzeHeadless %q on %s: %s", command, filepath.Base(abs),
			rtCauseLine(stderr.String(), stdout.String(), runErr))
	}
	return res, nil
}

// ------------------------------------------------------------------ arguments
//
// An op's run only receives a target path, so address/name/pattern arguments
// ride in on documented env vars. A missing argument is an error, never a
// default address that would quietly answer about the wrong bytes.

func nativeEnv(name string) string {
	return strings.TrimSpace(os.Getenv(name))
}

func nativeEnvHint(name, hint string) (string, error) {
	if v := nativeEnv(name); v != "" {
		return v, nil
	}
	return "", fmt.Errorf("%s is not set: %s", name, hint)
}

// nativeRef is one function: an address (LRECON_AT) or a symbol name (LRECON_NAME).
func nativeRef() (string, error) {
	if v := nativeEnv("LRECON_AT"); v != "" {
		return v, nil
	}
	if v := nativeEnv("LRECON_NAME"); v != "" {
		return v, nil
	}
	return "", errors.New("set LRECON_AT (address) or LRECON_NAME (symbol) for this op")
}

func nativePair() (string, string, error) {
	from, to := nativeEnv("LRECON_FROM"), nativeEnv("LRECON_TO")
	if from == "" || to == "" {
		return "", "", errors.New("set LRECON_FROM and LRECON_TO (address or symbol) for this op")
	}
	return from, to, nil
}

func nativeList() ([]string, error) {
	raw, err := nativeEnvHint("LRECON_ARGS", "a comma-separated list of addresses or symbols")
	if err != nil {
		return nil, err
	}
	var out []string
	for part := range strings.SplitSeq(raw, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("LRECON_ARGS is empty after splitting on commas")
	}
	return out, nil
}

func nativeParseNum(s string) (uint64, error) {
	t := strings.TrimSpace(s)
	base := 10
	if strings.HasPrefix(t, "0x") || strings.HasPrefix(t, "0X") {
		t, base = t[2:], 16
	}
	v, err := strconv.ParseUint(t, base, 64)
	if err == nil {
		return v, nil
	}
	if base == 10 {
		if v, err16 := strconv.ParseUint(t, 16, 64); err16 == nil {
			return v, nil
		}
	}
	return 0, fmt.Errorf("%q is not an address", s)
}

func nativeAddrArg() (uint64, error) {
	raw, err := nativeEnvHint("LRECON_AT", "an address (0x… or decimal) for this op")
	if err != nil {
		return 0, err
	}
	return nativeParseNum(raw)
}

// -------------------------------------------------------------------- session
//
// The navigation items (final.md 51,52,53,59,60,67,73,74) are the reader's own
// cursor: which document, which address, which procedure. It is a file on disk
// so it survives the one-shot CLI, and every write is atomic.

type nativeSession struct {
	// Kind marks the file as the one session artifact the navigation items and
	// binary_session share. Without it each writer saw the other's file as a
	// foreign artifact and refused to persist.
	Kind      string   `json:"kind,omitempty"`
	Project   string   `json:"project"`
	Document  string   `json:"document"`
	Cursor    uint64   `json:"cursor"`
	Procedure string   `json:"procedure,omitempty"`
	Documents []string `json:"documents,omitempty"`
	Opened    string   `json:"opened,omitempty"`
	Closed    bool     `json:"closed,omitempty"`
}

var errNoSession = errors.New("no session")

var (
	tempSessionOnce sync.Once
	tempSessionPath string
)

func sessionPath() string {
	if p := strings.TrimSpace(os.Getenv("LRECON_SESSION")); p != "" {
		return p
	}
	// LRECON_STATE already isolates every other lrecon state file. The
	// reader's cursor has to live in the same sandbox: otherwise a run with an
	// isolated state dir still reads and rewrites the real
	// ~/.lrecon/session.json, and answers about a document the caller never
	// opened.
	if dir := strings.TrimSpace(os.Getenv("LRECON_STATE")); dir != "" {
		return filepath.Join(dir, "session.json")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		// No home: keep the session inside a process-owned directory. MkdirTemp
		// creates it 0700 with an unpredictable name, so a local user cannot
		// pre-create or symlink the session file in the shared temp dir.
		tempSessionOnce.Do(func() {
			dir, err := os.MkdirTemp("", "lrecon-session-")
			if err != nil {
				return
			}
			tempSessionPath = filepath.Join(dir, "session.json")
		})
		if tempSessionPath != "" {
			return tempSessionPath
		}
		return ".lrecon-session.json"
	}
	return filepath.Join(home, ".lrecon", "session.json")
}

func loadSession() (nativeSession, error) {
	var s nativeSession
	b, err := os.ReadFile(sessionPath())
	if errors.Is(err, os.ErrNotExist) {
		return s, errNoSession
	}
	if err != nil {
		return s, err
	}
	if err := json.Unmarshal(b, &s); err != nil {
		return s, fmt.Errorf("%s: %v", sessionPath(), err)
	}
	return s, nil
}

func saveSession(s nativeSession) error {
	p := sessionPath()
	if s.Kind == "" {
		s.Kind = "lrecon.session/1"
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// sessionFor loads the session and refuses one recorded for another file: an
// answer about a different document is worse than no answer.
func sessionFor(path string) (nativeSession, error) {
	s, err := loadSession()
	if errors.Is(err, errNoSession) {
		return s, errors.New("no session: no document has been opened yet; run goto_address <target> first")
	}
	if err != nil {
		return s, err
	}
	if s.Document == "" {
		return s, errors.New("no document selected: run goto_address <target> first")
	}
	if path != "" {
		abs, err := filepath.Abs(path)
		if err != nil {
			return s, err
		}
		if abs != s.Document {
			// "is not" keeps this bad_arg: the caller named a file the session
			// was not opened on, which is an argument mistake, not a crash.
			return s, fmt.Errorf("%s is not the session document %s: run goto_address on it first", abs, s.Document)
		}
	}
	return s, nil
}

func selectDocument(s nativeSession, abs string) nativeSession {
	s.Document = abs
	s.Project = filepath.Base(filepath.Dir(abs))
	if s.Project == "" || s.Project == "." || s.Project == string(filepath.Separator) {
		s.Project = "default"
	}
	seen := slices.Contains(s.Documents, abs)
	if !seen {
		s.Documents = append(s.Documents, abs)
	}
	return s
}

// -------------------------------------------------------------- file layout

type fileSection struct {
	Name string
	Addr uint64
	Off  uint64
	Size uint64
	Exec bool
}

// nativeSections answers with the sections a reader can address: file-backed
// ranges only, because every pure-Go item here reads bytes from the file.
func nativeSections(path string) (string, []fileSection, error) {
	// Open first so a permission/IO problem is named as such; the format
	// openers below would otherwise all fail and look like a wrong format.
	f, err := os.Open(path)
	if err != nil {
		return "", nil, err
	}
	f.Close()
	if f, err := elf.Open(path); err == nil {
		defer f.Close()
		var out []fileSection
		for _, s := range f.Sections {
			if s.Type == elf.SHT_NOBITS || s.Size == 0 {
				continue
			}
			out = append(out, fileSection{Name: s.Name, Addr: s.Addr, Off: s.Offset, Size: s.Size,
				Exec: s.Flags&elf.SHF_EXECINSTR != 0})
		}
		if len(out) == 0 {
			return "elf", nil, fmt.Errorf("%s has no file-backed sections", path)
		}
		return "elf", out, nil
	}
	if ff, err := macho.OpenFat(path); err == nil {
		defer ff.Close()
		// Section offsets inside a universal slice are relative to the slice,
		// not to the file. Every reader here wants a file offset, so the slice
		// base has to be added once, here.
		return "macho", machoSections(ff.Arches[0].File, uint64(ff.Arches[0].Offset)), nil
	}
	if f, err := macho.Open(path); err == nil {
		defer f.Close()
		return "macho", machoSections(f, 0), nil
	}
	if f, err := pe.Open(path); err == nil {
		defer f.Close()
		base := peImageBase(f)
		var out []fileSection
		for _, s := range f.Sections {
			if s.Size == 0 {
				continue
			}
			out = append(out, fileSection{
				Name: strings.TrimRight(s.Name, "\x00"),
				Addr: base + uint64(s.VirtualAddress),
				Off:  uint64(s.Offset),
				Size: uint64(s.Size),
				Exec: s.Characteristics&peExecFlag != 0,
			})
		}
		if len(out) == 0 {
			return "pe", nil, fmt.Errorf("%s has no sections", path)
		}
		return "pe", out, nil
	}
	return "", nil, formatRefusal(path, "is not ELF, Mach-O or PE")
}

const peExecFlag = 0x20000000 // IMAGE_SCN_MEM_EXECUTE

func machoSections(f *macho.File, base uint64) []fileSection {
	var out []fileSection
	for _, s := range f.Sections {
		if s.Size == 0 || s.Offset == 0 {
			continue
		}
		out = append(out, fileSection{
			Name: s.Seg + "," + s.Name,
			Addr: s.Addr,
			Off:  base + uint64(s.Offset),
			Size: s.Size,
			Exec: s.Flags&0x80000000 != 0 || (s.Seg == "__TEXT" && s.Name == "__text"),
		})
	}
	return out
}

// machoSegments returns the file-backed segments. A page header or a
// __LINKEDIT blob belongs to a segment but to no section, so a section-only
// map cannot read the bytes at the image base even though the file has them.
func machoSegments(f *macho.File, base uint64) []fileSection {
	var out []fileSection
	for _, l := range f.Loads {
		seg, ok := l.(*macho.Segment)
		if !ok || seg.Filesz == 0 {
			continue
		}
		out = append(out, fileSection{
			Name: seg.Name,
			Addr: seg.Addr,
			Off:  base + uint64(seg.Offset),
			Size: seg.Filesz,
			Exec: seg.Prot&0x4 != 0,
		})
	}
	return out
}

// nativeSegments answers with the file-backed segment ranges (Mach-O
// segments, ELF PT_LOAD). It is the fallback for addresses that a section
// table cannot name.
func nativeSegments(path string) ([]fileSection, error) {
	if ff, err := macho.OpenFat(path); err == nil {
		defer ff.Close()
		return machoSegments(ff.Arches[0].File, uint64(ff.Arches[0].Offset)), nil
	}
	if f, err := macho.Open(path); err == nil {
		defer f.Close()
		return machoSegments(f, 0), nil
	}
	if f, err := elf.Open(path); err == nil {
		defer f.Close()
		var out []fileSection
		for i, p := range f.Progs {
			if p.Type != elf.PT_LOAD || p.Filesz == 0 {
				continue
			}
			out = append(out, fileSection{
				Name: fmt.Sprintf("PT_LOAD[%d]", i),
				Addr: p.Vaddr,
				Off:  p.Off,
				Size: p.Filesz,
				Exec: p.Flags&elf.PF_X != 0,
			})
		}
		return out, nil
	}
	if f, err := pe.Open(path); err == nil {
		defer f.Close()
		base := peImageBase(f)
		var out []fileSection
		for _, s := range f.Sections {
			if s.Size == 0 {
				continue
			}
			out = append(out, fileSection{
				Name: strings.TrimRight(s.Name, "\x00"),
				Addr: base + uint64(s.VirtualAddress),
				Off:  uint64(s.Offset),
				Size: uint64(s.Size),
				Exec: s.Characteristics&peExecFlag != 0,
			})
		}
		return out, nil
	}
	return nil, fmt.Errorf("%s is not ELF, Mach-O or PE", path)
}

// mapAddress resolves a virtual address to a file offset: sections first, then
// segments. The third result names which of the two matched, so an answer can
// say that a name like __TEXT is a segment and not a section.
func mapAddress(path string, addr uint64) (uint64, *fileSection, string) {
	if _, secs, err := nativeSections(path); err == nil {
		if s := sectionFor(secs, addr); s != nil {
			return s.Off + (addr - s.Addr), s, "section"
		}
	}
	if segs, err := nativeSegments(path); err == nil {
		if s := sectionFor(segs, addr); s != nil {
			return s.Off + (addr - s.Addr), s, "segment"
		}
	}
	return 0, nil, ""
}

// annotateFileOffset adds lrecon's own whole-file mapping to a Ghidra answer.
// Ghidra imports one slice of a universal binary, so its file_offset is
// relative to that slice; the same byte sits at slice_base+offset in the fat
// file the caller actually named. Both numbers are reported instead of
// silently rewriting one into the other.
func annotateFileOffset(path string, addr uint64, res any) any {
	m, ok := res.(map[string]any)
	if !ok {
		return res
	}
	off, sec, mapping := mapAddress(path, addr)
	if sec == nil {
		return res
	}
	m["file_offset_in_file"] = off
	m["mapping"] = mapping
	if g, ok := m["file_offset"].(float64); ok && g >= 0 && off >= uint64(g) {
		if base := off - uint64(g); base > 0 {
			m["slice_offset"] = base
			m["file_offset_basis"] = "slice"
		}
	}
	return m
}

func peImageBase(f *pe.File) uint64 {
	switch h := f.OptionalHeader.(type) {
	case *pe.OptionalHeader64:
		return h.ImageBase
	case *pe.OptionalHeader32:
		return uint64(h.ImageBase)
	}
	return 0
}

func nativeSectionBytes(path string, s fileSection, limit uint64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	n := s.Size
	if limit > 0 && n > limit {
		n = limit
	}
	b := make([]byte, n)
	read, err := f.ReadAt(b, int64(s.Off))
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	return b[:read], nil
}

func sectionFor(secs []fileSection, addr uint64) *fileSection {
	for i := range secs {
		if addr >= secs[i].Addr && addr < secs[i].Addr+secs[i].Size {
			return &secs[i]
		}
	}
	return nil
}

func fileOffsetFor(secs []fileSection, addr uint64) (uint64, *fileSection) {
	s := sectionFor(secs, addr)
	if s == nil {
		return 0, nil
	}
	return s.Off + (addr - s.Addr), s
}

// ---------------------------------------------------------------- functions

type nativeFunc struct {
	Name  string `json:"name"`
	Start uint64 `json:"start"`
	End   uint64 `json:"end"`
}

// nativeFunctions prefers pclntab for Go binaries (names survive stripping)
// and falls back to the symbol table. Sizes of zero are closed by the next
// start, never invented.
func nativeFunctions(path string) ([]nativeFunc, error) {
	if isGoBinary(path) {
		if fns, err := goFunctions(path); err == nil && len(fns) > 0 {
			return fns, nil
		}
	}
	if f, err := elf.Open(path); err == nil {
		defer f.Close()
		return elfFunctions(f)
	}
	if ff, err := macho.OpenFat(path); err == nil {
		defer ff.Close()
		return machoFunctions(ff.Arches[0].File)
	}
	if f, err := macho.Open(path); err == nil {
		defer f.Close()
		return machoFunctions(f)
	}
	if f, err := pe.Open(path); err == nil {
		defer f.Close()
		return peFunctions(f)
	}
	return nil, formatRefusal(path, "is not ELF, Mach-O or PE")
}

func goFunctions(path string) ([]nativeFunc, error) {
	fileSize := int64(0)
	if st, err := os.Stat(path); err == nil {
		fileSize = st.Size()
	}
	if f, err := elf.Open(path); err == nil {
		defer f.Close()
		if b, start, ok := elfPclntab(f, fileSize); ok {
			if fns := pclnFunctions(b, start); len(fns) > 0 {
				return fns, nil
			}
		}
		return nil, errors.New("no .gopclntab")
	}
	if ff, err := macho.OpenFat(path); err == nil {
		defer ff.Close()
		if b, start, ok := machoPclntab(ff.Arches[0].File); ok {
			if fns := pclnFunctions(b, start); len(fns) > 0 {
				return fns, nil
			}
		}
		return nil, errors.New("no __gopclntab")
	}
	f, err := macho.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if b, start, ok := machoPclntab(f); ok {
		if fns := pclnFunctions(b, start); len(fns) > 0 {
			return fns, nil
		}
	}
	return nil, errors.New("no __gopclntab")
}

func pclnFunctions(pcln []byte, textStart uint64) []nativeFunc {
	tab, err := gosym.NewTable(nil, gosym.NewLineTable(pcln, textStart))
	if err != nil {
		return nil
	}
	out := make([]nativeFunc, 0, len(tab.Funcs))
	for i := range tab.Funcs {
		fn := &tab.Funcs[i]
		if fn.End > fn.Entry {
			out = append(out, nativeFunc{Name: fn.Name, Start: fn.Entry, End: fn.End})
		}
	}
	sortFunctions(out)
	return out
}

func elfFunctions(f *elf.File) ([]nativeFunc, error) {
	syms, err := f.Symbols()
	if err != nil {
		syms, err = f.DynamicSymbols()
		if err != nil {
			return nil, fmt.Errorf("no symbol table: %v", err)
		}
	}
	var out []nativeFunc
	for _, s := range syms {
		if elf.ST_TYPE(s.Info) != elf.STT_FUNC || s.Section == elf.SHN_UNDEF || s.Value == 0 {
			continue
		}
		out = append(out, nativeFunc{Name: s.Name, Start: s.Value, End: s.Value + s.Size})
	}
	closeSizes(out)
	return nonEmpty(out)
}

func machoFunctions(f *macho.File) ([]nativeFunc, error) {
	if f.Symtab == nil {
		return nil, errors.New("no symbol table")
	}
	var out []nativeFunc
	for _, s := range f.Symtab.Syms {
		if s.Sect == 0 || s.Value == 0 || s.Type&0x0e == 0 { // 0x0e = N_TYPE; 0 = undefined
			continue
		}
		out = append(out, nativeFunc{Name: s.Name, Start: s.Value})
	}
	closeSizes(out)
	return nonEmpty(out)
}

func peFunctions(f *pe.File) ([]nativeFunc, error) {
	if len(f.Symbols) == 0 {
		return nil, errors.New("no COFF symbol table (stripped)")
	}
	base := peImageBase(f)
	var out []nativeFunc
	for _, s := range f.Symbols {
		if s.SectionNumber <= 0 || s.SectionNumber > int16(len(f.Sections)) || s.Value == 0 {
			continue
		}
		sec := f.Sections[s.SectionNumber-1]
		out = append(out, nativeFunc{Name: s.Name, Start: base + uint64(sec.VirtualAddress) + uint64(s.Value)})
	}
	closeSizes(out)
	return nonEmpty(out)
}

func nonEmpty(fns []nativeFunc) ([]nativeFunc, error) {
	if len(fns) == 0 {
		return nil, errors.New("no function symbols")
	}
	return fns, nil
}

// closeSizes turns "start only" entries into ranges by ending each at the next
// start: a symbol table without sizes still has an order.
func closeSizes(fns []nativeFunc) {
	sortFunctions(fns)
	for i := range fns {
		if fns[i].End > fns[i].Start {
			continue
		}
		if i+1 < len(fns) && fns[i+1].Start > fns[i].Start {
			fns[i].End = fns[i+1].Start
			continue
		}
		// Nothing after this entry closes the range. One byte is the least
		// invented extent, and without it current_procedure at the start of
		// the last function answers found=false about a function the table
		// itself just named.
		fns[i].End = fns[i].Start + 1
	}
}

func sortFunctions(fns []nativeFunc) {
	sort.Slice(fns, func(i, j int) bool { return fns[i].Start < fns[j].Start })
}

func containingFunction(fns []nativeFunc, addr uint64) *nativeFunc {
	i := sort.Search(len(fns), func(i int) bool { return fns[i].Start > addr }) - 1
	if i >= 0 && addr >= fns[i].Start && addr < fns[i].End {
		return &fns[i]
	}
	return nil
}

func nextFunction(fns []nativeFunc, addr uint64) *nativeFunc {
	i := sort.Search(len(fns), func(i int) bool { return fns[i].Start > addr })
	if i < len(fns) {
		return &fns[i]
	}
	return nil
}

func prevFunction(fns []nativeFunc, addr uint64) *nativeFunc {
	i := sort.Search(len(fns), func(i int) bool { return fns[i].Start >= addr }) - 1
	if i >= 0 {
		return &fns[i]
	}
	return nil
}

// ------------------------------------------------------------------ strings

type stringHit struct {
	Addr  uint64 `json:"address"`
	Off   uint64 `json:"file_offset"`
	Len   int    `json:"len"`
	Value string `json:"value"`
	ASCII bool   `json:"ascii"`
}

func nativePrintable(b byte) bool { return b >= 0x20 && b < 0x7f }

// nativeStringsScan is the extraction entry with the scan budget named by the
// caller. The op passes nativeScanCap; a test passes a small budget so the row
// cap and the scan cap can be distinguished without a 64 MB fixture.
func nativeStringsScan(path string, minLen, keep int, scanCap uint64) ([]stringHit, int, uint64, error) {
	return nativeStringsWalk(path, minLen, keep, scanCap, nil)
}

// nativeStringsWalk is the one extraction pass. onHit sees every string,
// including the ones past keep, and gets a Value even then, so a caller can
// count matches over the whole scanned prefix without retaining it. keep only
// bounds the returned slice; total always counts the prefix.
func nativeStringsWalk(path string, minLen, keep int, scanCap uint64, onHit func(stringHit)) ([]stringHit, int, uint64, error) {
	_, secs, err := nativeSections(path)
	if err != nil {
		return nil, 0, 0, err
	}
	var hits []stringHit
	total := 0
	var scanned uint64
	for _, s := range secs {
		if s.Exec || strings.HasPrefix(strings.TrimLeft(s.Name, ".,"), "debug") || s.Name == "" {
			continue
		}
		if scanned >= scanCap {
			break
		}
		b, err := nativeSectionBytes(path, s, scanCap-scanned)
		if err != nil {
			return nil, 0, scanned, err
		}
		scanned += uint64(len(b))
		for i := 0; i < len(b); {
			// ASCII run
			j := i
			for j < len(b) && nativePrintable(b[j]) {
				j++
			}
			if j-i >= minLen {
				total++
				h := stringHit{Addr: s.Addr + uint64(i), Off: s.Off + uint64(i), Len: j - i, ASCII: true}
				if len(hits) < keep || onHit != nil {
					h.Value = string(b[i:j])
				}
				if len(hits) < keep {
					hits = append(hits, h)
				}
				if onHit != nil {
					onHit(h)
				}
			}
			if j == i {
				i++
			} else {
				i = j
			}
		}
		// UTF-16LE run, aligned to the section start.
		for i := 0; i+2 <= len(b); {
			j := i
			for j+1 < len(b) && nativePrintable(b[j]) && b[j+1] == 0 {
				j += 2
			}
			if (j-i)/2 >= minLen {
				total++
				h := stringHit{Addr: s.Addr + uint64(i), Off: s.Off + uint64(i), Len: (j - i) / 2, ASCII: false}
				if len(hits) < keep || onHit != nil {
					var sb strings.Builder
					sb.Grow((j - i) / 2)
					for k := i; k < j; k += 2 {
						sb.WriteByte(b[k])
					}
					h.Value = sb.String()
				}
				if len(hits) < keep {
					hits = append(hits, h)
				}
				if onHit != nil {
					onHit(h)
				}
			}
			if j == i {
				i += 2
			} else {
				i = j
			}
		}
	}
	sort.Slice(hits, func(i, j int) bool { return hits[i].Off < hits[j].Off })
	return hits, total, scanned, nil
}

// nativeStringsSearch counts matches over the whole scanned prefix. keep only
// bounds the string slice used for reporting; matchCap bounds the returned
// matches. Neither cap hides the other: total > len(hits) is the keep cut,
// matched > len(matches) is the match cut.
func nativeStringsSearch(path string, minLen, keep, matchCap int, scanCap uint64, needle string) (hits, matches []stringHit, matched, total int, scanned uint64, err error) {
	hits, total, scanned, err = nativeStringsWalk(path, minLen, keep, scanCap, func(h stringHit) {
		if !strings.Contains(strings.ToLower(h.Value), needle) {
			return
		}
		matched++
		if len(matches) < matchCap {
			matches = append(matches, h)
		}
	})
	if err != nil {
		return nil, nil, 0, 0, 0, err
	}
	sort.Slice(matches, func(i, j int) bool { return matches[i].Off < matches[j].Off })
	return hits, matches, matched, total, scanned, nil
}

// ----------------------------------------------------------------- patterns

// parseBytePattern accepts "48 8b ?? c3", "48,8b,??,c3" or one hex string.
// mask[i] is false for a wildcard; anything else is a parse error so a typo
// cannot silently match everything.
func parseBytePattern(s string) ([]byte, []bool, error) {
	fields := strings.FieldsFunc(strings.TrimSpace(s), func(r rune) bool {
		return r == ' ' || r == ',' || r == '\t' || r == '-'
	})
	if len(fields) == 1 && len(fields[0]) > 2 && len(fields[0])%2 == 0 {
		var split []string
		for i := 0; i < len(fields[0]); i += 2 {
			split = append(split, fields[0][i:i+2])
		}
		fields = split
	}
	if len(fields) == 0 {
		return nil, nil, errors.New("empty byte pattern")
	}
	var pat []byte
	var mask []bool
	for _, f := range fields {
		f = strings.TrimPrefix(strings.TrimPrefix(f, "0x"), "0X")
		switch strings.ToLower(f) {
		case "?", "??", "**", "xx":
			pat = append(pat, 0)
			mask = append(mask, false)
			continue
		case "":
			return nil, nil, fmt.Errorf("empty byte in pattern %q", s)
		}
		v, err := strconv.ParseUint(f, 16, 8)
		if err != nil {
			return nil, nil, fmt.Errorf("byte %q in pattern %q is not hex", f, s)
		}
		pat = append(pat, byte(v))
		mask = append(mask, true)
	}
	return pat, mask, nil
}

func nativeMatch(b []byte, at int, pat []byte, mask []bool) bool {
	if at+len(pat) > len(b) {
		return false
	}
	for k := range pat {
		if mask[k] && b[at+k] != pat[k] {
			return false
		}
	}
	return true
}

type patternHit struct {
	Addr uint64 `json:"address"`
	Off  uint64 `json:"file_offset"`
	At   string `json:"section"`
}

func searchPattern(path string, pat []byte, mask []bool, keep int) ([]patternHit, int, uint64, error) {
	_, secs, err := nativeSections(path)
	if err != nil {
		return nil, 0, 0, err
	}
	var hits []patternHit
	total := 0
	var scanned uint64
	for _, s := range secs {
		if scanned >= nativeScanCap {
			break
		}
		b, err := nativeSectionBytes(path, s, nativeScanCap-scanned)
		if err != nil {
			return nil, 0, scanned, err
		}
		scanned += uint64(len(b))
		for i := 0; i+len(pat) <= len(b); i++ {
			if !nativeMatch(b, i, pat, mask) {
				continue
			}
			total++
			if len(hits) < keep {
				hits = append(hits, patternHit{Addr: s.Addr + uint64(i), Off: s.Off + uint64(i), At: s.Name})
			}
		}
	}
	return hits, total, scanned, nil
}

// ------------------------------------------------------------------ imports

type nativeAPI struct {
	Name    string `json:"name"`
	Library string `json:"library,omitempty"`
	Stub    uint64 `json:"slot,omitempty"`
	Section string `json:"section,omitempty"`
	Basis   string `json:"basis,omitempty"`
}

// nativeImports reads the import tables: the calls a binary makes into code it
// does not ship. Each row carries the address a reader can re-check (PLT/GOT
// slot for ELF, IAT slot for PE, pointer slot for Mach-O).
func nativeImports(path string) (string, []nativeAPI, error) {
	if f, err := elf.Open(path); err == nil {
		defer f.Close()
		rows, err := elfImports(f)
		return "elf", rows, err
	}
	if ff, err := macho.OpenFat(path); err == nil {
		defer ff.Close()
		rows, err := machoImports(ff.Arches[0].File)
		return "macho", rows, err
	}
	if f, err := macho.Open(path); err == nil {
		defer f.Close()
		rows, err := machoImports(f)
		return "macho", rows, err
	}
	if f, err := pe.Open(path); err == nil {
		f.Close()
		rows, err := peImports(path)
		return "pe", rows, err
	}
	return "", nil, formatRefusal(path, "is not ELF, Mach-O or PE")
}

func elfImports(f *elf.File) ([]nativeAPI, error) {
	dyn, err := f.DynamicSymbols()
	if err != nil {
		// A relocatable object or a static image has no .dynsym: the table was
		// looked for and is absent, so zero imports is the answer.
		return []nativeAPI{}, nil
	}
	slots := map[uint32]uint64{}
	for _, name := range []string{".rela.plt", ".rela.dyn"} {
		sec := f.Section(name)
		if sec == nil {
			continue
		}
		data, err := sec.Data()
		if err != nil {
			return nil, fmt.Errorf("%s: %v", name, err)
		}
		for off := 0; off+24 <= len(data); off += 24 {
			rOff := f.ByteOrder.Uint64(data[off:])
			rInfo := f.ByteOrder.Uint64(data[off+8:])
			sym := uint32(rInfo >> 32)
			if sym == 0 {
				continue
			}
			if _, dup := slots[sym]; !dup {
				slots[sym] = rOff
			}
		}
	}
	var rows []nativeAPI
	for i, s := range dyn {
		if s.Section != elf.SHN_UNDEF || s.Name == "" {
			continue
		}
		row := nativeAPI{Name: s.Name, Basis: "undefined .dynsym"}
		if slot, ok := slots[uint32(i)]; ok {
			row.Stub = slot
			row.Basis = ".rela relocation slot"
		}
		rows = append(rows, row)
	}
	if len(rows) == 0 {
		return nil, errors.New("no undefined dynamic symbols")
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Name < rows[j].Name })
	return rows, nil
}

// machoIndirectSlots maps an undefined symbol to its pointer slot. LC_DYSYMTAB
// stores one entry per __la_symbol_ptr/__got/__stub slot in IndirectSyms, and
// each section says where its run starts (reserved1); that is the address a
// caller needs. debug/macho drops reserved1/reserved2 from SectionHeader, so
// the section header is decoded from the segment command's raw bytes.
func machoIndirectSlots(f *macho.File) map[string]uint64 {
	slots := map[string]uint64{}
	if f.Symtab == nil || f.Dysymtab == nil {
		return slots
	}
	ptr := uint64(8)
	if f.Magic == macho.Magic32 {
		ptr = 4
	}
	for _, load := range f.Loads {
		raw := load.Raw()
		if len(raw) < 8 {
			continue
		}
		cmd := f.ByteOrder.Uint32(raw)
		nsects, secBase, secSize := 0, 0, 0
		switch cmd {
		case 0x19: // LC_SEGMENT_64
			if len(raw) >= 72 {
				nsects, secBase, secSize = int(f.ByteOrder.Uint32(raw[64:])), 72, 80
			}
		case 0x1: // LC_SEGMENT
			if len(raw) >= 56 {
				nsects, secBase, secSize = int(f.ByteOrder.Uint32(raw[48:])), 56, 68
			}
		}
		for i := 0; i < nsects; i++ {
			at := secBase + i*secSize
			if at+secSize > len(raw) {
				break
			}
			sect := raw[at : at+secSize]
			var addr, size uint64
			var flags, res1, res2 uint32
			if cmd == 0x19 {
				addr, size = f.ByteOrder.Uint64(sect[32:]), f.ByteOrder.Uint64(sect[40:])
				flags, res1, res2 = f.ByteOrder.Uint32(sect[64:]), f.ByteOrder.Uint32(sect[68:]), f.ByteOrder.Uint32(sect[72:])
			} else {
				addr, size = uint64(f.ByteOrder.Uint32(sect[32:])), uint64(f.ByteOrder.Uint32(sect[36:]))
				flags, res1, res2 = f.ByteOrder.Uint32(sect[56:]), f.ByteOrder.Uint32(sect[60:]), f.ByteOrder.Uint32(sect[64:])
			}
			kind := flags & 0xff
			stride := ptr
			switch kind {
			case 0x8: // S_SYMBOL_STUBS
				stride = uint64(res2)
				if stride == 0 {
					continue
				}
			case 0x6, 0x7: // non-lazy / lazy symbol pointers
			default:
				continue
			}
			for j := 0; ; j++ {
				idx := int(res1) + j
				if idx < 0 || idx >= len(f.Dysymtab.IndirectSyms) {
					break
				}
				off := uint64(j) * stride
				if off >= size {
					break
				}
				symIdx := f.Dysymtab.IndirectSyms[idx]
				if symIdx&0x80000000 != 0 || int(symIdx) >= len(f.Symtab.Syms) {
					continue
				}
				name := f.Symtab.Syms[symIdx].Name
				if _, seen := slots[name]; !seen {
					slots[name] = addr + off
				}
			}
		}
	}
	return slots
}

func machoImports(f *macho.File) ([]nativeAPI, error) {
	names, err := f.ImportedSymbols()
	if err != nil && len(names) == 0 {
		return nil, fmt.Errorf("no import symbols: %v", err)
	}
	slots := machoIndirectSlots(f)
	rows := make([]nativeAPI, 0, len(names))
	for _, n := range names {
		lib, sym := "", n
		if i := strings.LastIndex(n, "!"); i >= 0 {
			lib, sym = n[:i], n[i+1:]
		}
		row := nativeAPI{Name: sym, Library: lib, Basis: "LC_DYSYMTAB import"}
		if slot, ok := slots[sym]; ok {
			row.Stub = slot
			row.Basis = "LC_DYSYMTAB import slot"
		}
		rows = append(rows, row)
	}
	// A static image such as dyld imports nothing: the table was read and it
	// is empty, so this is an answer, not an lrecon failure (rc=0, no retry).
	return rows, nil
}

func peImports(path string) ([]nativeAPI, error) {
	fh, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	f, err := pe.NewFile(fh)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var dir pe.DataDirectory
	switch h := f.OptionalHeader.(type) {
	case *pe.OptionalHeader64:
		dir = h.DataDirectory[1]
	case *pe.OptionalHeader32:
		dir = h.DataDirectory[1]
	default:
		return nil, errors.New("no optional header")
	}
	if dir.VirtualAddress == 0 || dir.Size == 0 {
		// No import directory: the image really imports nothing.
		return []nativeAPI{}, nil
	}
	base := peImageBase(f)
	raw, err := peBlock(f, fh, dir.VirtualAddress, dir.Size)
	if err != nil {
		return nil, err
	}
	ptr := uint64(4)
	if _, ok := f.OptionalHeader.(*pe.OptionalHeader64); ok {
		ptr = 8
	}
	var rows []nativeAPI
	for off := 0; off+20 <= len(raw); off += 20 {
		desc := raw[off : off+20]
		oft := binary.LittleEndian.Uint32(desc[0:])
		nameRVA := binary.LittleEndian.Uint32(desc[12:])
		ft := binary.LittleEndian.Uint32(desc[16:])
		if oft == 0 && nameRVA == 0 && ft == 0 {
			break
		}
		libName, err := peCString(f, fh, nameRVA)
		if err != nil {
			return nil, fmt.Errorf("import descriptor %d: %v", off/20, err)
		}
		thunkRVA := oft
		if thunkRVA == 0 {
			thunkRVA = ft
		}
		thunk, err := peBlock(f, fh, thunkRVA, 0)
		if err != nil {
			return nil, fmt.Errorf("%s thunks: %v", libName, err)
		}
		for i := 0; uint64(i+1)*ptr <= uint64(len(thunk)); i++ {
			v := uint64(binary.LittleEndian.Uint32(thunk[i*int(ptr):]))
			if ptr == 8 {
				v = binary.LittleEndian.Uint64(thunk[i*int(ptr):])
			}
			if v == 0 {
				break
			}
			row := nativeAPI{Library: libName, Stub: base + uint64(ft) + uint64(i)*ptr,
				Section: "IAT", Basis: "import descriptor"}
			if v&(1<<(ptr*8-1)) != 0 {
				row.Name = fmt.Sprintf("#%d", v&0xffff)
			} else {
				name, err := peCString(f, fh, uint32(v)+2)
				if err != nil {
					return nil, fmt.Errorf("%s entry %d: %v", libName, i, err)
				}
				row.Name = name
			}
			rows = append(rows, row)
		}
	}
	if len(rows) == 0 {
		return nil, errors.New("import directory is empty")
	}
	return rows, nil
}

// peBlock returns the bytes of one RVA range (size 0 = to end of the section).
func peBlock(f *pe.File, fh *os.File, rva, size uint32) ([]byte, error) {
	for _, s := range f.Sections {
		if rva >= s.VirtualAddress && rva < s.VirtualAddress+s.VirtualSize {
			off := uint64(s.Offset) + uint64(rva-s.VirtualAddress)
			n := uint64(size)
			if n == 0 || n > uint64(s.Size) {
				n = uint64(s.Size) - uint64(rva-s.VirtualAddress)
			}
			if n == 0 {
				n = uint64(s.VirtualSize) - uint64(rva-s.VirtualAddress)
			}
			buf := make([]byte, n)
			read, err := fh.ReadAt(buf, int64(off))
			if err != nil && !errors.Is(err, io.EOF) {
				return nil, err
			}
			return buf[:read], nil
		}
	}
	return nil, fmt.Errorf("RVA 0x%x is not in any section", rva)
}

func peCString(f *pe.File, fh *os.File, rva uint32) (string, error) {
	b, err := peBlock(f, fh, rva, 256)
	if err != nil {
		return "", err
	}
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b), nil
}

// ------------------------------------------------------------- op conveniences

func nativeHexAddr(v uint64) string { return fmt.Sprintf("0x%x", v) }

func nativeStat(path string) (os.FileInfo, error) { return os.Stat(path) }

// nativePatternString re-renders a parsed pattern so the answer shows what matched,
// wildcards included.
func nativePatternString(pat []byte, mask []bool) string {
	parts := make([]string, len(pat))
	for i := range pat {
		if mask[i] {
			parts[i] = fmt.Sprintf("%02x", pat[i])
		} else {
			parts[i] = "??"
		}
	}
	return strings.Join(parts, " ")
}

// nativeHexArg is the LRECON_AT argument in the form the Ghidra script parses.
func nativeHexArg() (string, error) {
	a, err := nativeAddrArg()
	if err != nil {
		return "", err
	}
	return nativeHexAddr(a), nil
}

func absTarget(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	if st, err := os.Stat(abs); err != nil {
		return "", fmt.Errorf("%s: %v", path, err)
	} else if st.IsDir() {
		return "", fmt.Errorf("%s is a directory, not a file", path)
	}
	return abs, nil
}

func requireInSection(path string, addr uint64) (*fileSection, string, error) {
	_, sec, mapping := mapAddress(path, addr)
	if sec == nil {
		return nil, "", fmt.Errorf("address %s is not inside any file-backed section or segment of %s", nativeHexAddr(addr), filepath.Base(path))
	}
	return sec, mapping, nil
}

func loadOrInitSession() (nativeSession, error) {
	s, err := loadSession()
	if errors.Is(err, errNoSession) {
		return nativeSession{}, nil
	}
	return s, err
}

func nativeEnvUint(name string, def, max uint64) (uint64, error) {
	raw := nativeEnv(name)
	if raw == "" {
		return def, nil
	}
	v, err := nativeParseNum(raw)
	if err != nil {
		return 0, fmt.Errorf("%s: %v", name, err)
	}
	if v > max {
		return 0, fmt.Errorf("%s is %d, above the %d cap", name, v, max)
	}
	return v, nil
}

func nativeReadAt(path string, off, n uint64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b := make([]byte, n)
	read, err := f.ReadAt(b, int64(off))
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	return b[:read], nil
}

// nativeHexDump is 16 bytes per line with the offset, the layout a reader compares
// against objdump without a second tool.
func nativeHexDump(b []byte) string {
	var sb strings.Builder
	for i := 0; i < len(b); i += 16 {
		end := min(i+16, len(b))
		fmt.Fprintf(&sb, "%08x  ", i)
		for j := i; j < i+16; j++ {
			if j < end {
				fmt.Fprintf(&sb, "%02x ", b[j])
			} else {
				sb.WriteString("   ")
			}
		}
		sb.WriteString(" |")
		for j := i; j < end; j++ {
			if nativePrintable(b[j]) {
				sb.WriteByte(b[j])
			} else {
				sb.WriteByte('.')
			}
		}
		sb.WriteString("|\n")
	}
	return sb.String()
}

func nativeASCII(b []byte) string {
	var sb strings.Builder
	for _, c := range b {
		if nativePrintable(c) {
			sb.WriteByte(c)
		} else {
			sb.WriteByte('.')
		}
	}
	return sb.String()
}
 j++ {
			if j < end {
				fmt.Fprintf(&sb, "%02x ", b[j])
			} else {
				sb.WriteString("   ")
			}
		}
		sb.WriteString(" |")
		for j := i; j < end; j++ {
			if nativePrintable(b[j]) {
				sb.WriteByte(b[j])
			} else {
				sb.WriteByte('.')
			}
		}
		sb.WriteString("|\n")
	}
	return sb.String()
}

func nativeASCII(b []byte) string {
	var sb strings.Builder
	for _, c := range b {
		if nativePrintable(c) {
			sb.WriteByte(c)
		} else {
			sb.WriteByte('.')
		}
	}
	return sb.String()
}
