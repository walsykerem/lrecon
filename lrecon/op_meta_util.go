package main

// META section ops (final.md items 91-128): session state, evidence bundles,
// digest comparison and cross-version diffing.
//
// Filename contract, one row per file an op writes under a state root:
//
//	session.json     {kind,project,document,cursor,opened,closed}  binary_session, close_binary
//	obligations.json {kind,artifact,rows,by_reason}               build_reconstruction_obligation_ledger
//	unknowns.json    {kind,unknowns[]}                             record_unknown, update_unknown
//	bookmarks.json   [{file,address,note,created}]                 set_bookmark, list_bookmarks, unset_bookmark
//	config.json      {kind,deep,maxBytes,minString,updated}        update_analysis_settings, inspect_analysis_settings
//
// State root order: the job's "state" field, then LRECON_STATE, then the path
// when it is a directory, then ~/.lrecon. Every write is tmp+rename in the same
// directory, so a crash never leaves a half-written state file. A file that
// already holds a different artifact is a conflict, never silently replaced.

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"
)

// metaJob is the target of an op that needs more than one input: the CLI passes
// one path, so extra fields travel in a JSON object. A target that is not a job
// object (plain executable, saved digest, state directory) leaves every field
// empty and the op falls back to the path itself.
type metaJob struct {
	File       string           `json:"file"`
	State      string           `json:"state"`
	Old        string           `json:"old"`
	New        string           `json:"new"`
	View       string           `json:"view"`
	Address    string           `json:"address"`
	Text       string           `json:"text"`
	Note       string           `json:"note"`
	Name       string           `json:"name"`
	Count      int              `json:"count"`
	Labels     []metaLabel      `json:"labels"`
	Claims     []metaClaim      `json:"claims"`
	String     string           `json:"string"`
	Bytes      string           `json:"bytes"`
	Hypothesis string           `json:"hypothesis"`
	Resolution string           `json:"resolution"`
	ResolvedAs string           `json:"resolved_as"`
	Apply      *bool            `json:"apply"`
	Reason     string           `json:"reason"`
	Symbols    []metaObligation `json:"symbols"`
	Unresolved []metaObligation `json:"unresolved"`
	Crash      string           `json:"crash"`
	Plist      string           `json:"plist"`
	Include    []string         `json:"include"`
	Resolved   []string         `json:"resolved"`
	Rows       []metaObligation `json:"rows"`
	Expect     string           `json:"expect"`
	Deep       *bool            `json:"deep"`
	MaxBytes   *int             `json:"maxBytes"`
	MinString  *int             `json:"minString"`
}

type metaLabel struct {
	Address string `json:"address"`
	Name    string `json:"name"`
}

type metaClaim struct {
	Offset int64  `json:"offset"`
	Length int    `json:"length"`
	Expect string `json:"expect"`
}

type metaObligation struct {
	Symbol   string `json:"symbol"`
	Reason   string `json:"reason"`
	Evidence string `json:"evidence,omitempty"`
	Owner    string `json:"owner,omitempty"`
}

// metaJobKeys decides whether a JSON object is a job or an artifact that merely
// happens to be JSON (a saved digest).
var metaJobKeys = []string{"file", "state", "old", "new", "address", "text", "note", "name", "labels",
	"claims", "hypothesis", "resolution", "resolved_as", "apply", "crash", "plist", "unknowns", "rows", "resolved",
	"unresolved", "expect", "view", "string", "bytes", "reason", "include", "count", "symbols",
	"maxBytes", "minString", "deep"}

// metaLoadJob reads a job object when the target is one; anything else is the
// artifact path itself. A directory is always a state dir, never a job.
func metaLoadJob(path string) (metaJob, error) {
	if path == "" {
		return metaJob{}, nil
	}
	if fi, err := os.Stat(path); err == nil && fi.IsDir() {
		return metaJob{}, nil
	}
	b, err := readCapped(path, maxMetaRead)
	if err != nil {
		return metaJob{File: path}, nil
	}
	t := bytes.TrimLeft(b, " \t\r\n")
	if len(t) == 0 || t[0] != '{' {
		return metaJob{File: path}, nil
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(t, &raw); err != nil {
		return metaJob{File: path}, nil
	}
	isJob := false
	for _, k := range metaJobKeys {
		if _, ok := raw[k]; ok {
			isJob = true
			break
		}
	}
	if !isJob {
		return metaJob{File: path}, nil
	}
	var job metaJob
	if err := json.Unmarshal(t, &job); err != nil {
		return metaJob{}, fmt.Errorf("%s: job json: %v", path, err)
	}
	return job, nil
}

func metaNow() string { return time.Now().UTC().Format(time.RFC3339) }

// metaStateRoot resolves the state directory and creates it.
func metaStateRoot(path string, job metaJob) (string, error) {
	for _, c := range []string{job.State, os.Getenv("LRECON_STATE")} {
		if c != "" {
			return metaMkdir(c)
		}
	}
	if fi, err := os.Stat(path); err == nil && fi.IsDir() {
		return path, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return metaMkdir(filepath.Join(home, ".lrecon"))
}

func metaMkdir(dir string) (string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	return dir, nil
}

// metaStateFile names one state file inside a resolved root. A root that is a
// regular file is a conflict: state lives in a directory.
func metaStateFile(root, name string) (string, error) {
	if fi, err := os.Stat(root); err == nil && !fi.IsDir() {
		return "", fmt.Errorf("state conflict: %s is a file, not a state directory", root)
	}
	if _, err := metaMkdir(root); err != nil {
		return "", err
	}
	return filepath.Join(root, name), nil
}

// metaReadState decodes an object state file and refuses a file that holds a
// different artifact instead of overwriting it.
func metaReadState(file, kind string, v any) (bool, error) {
	b, err := readCapped(file, maxMetaRead)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var env struct {
		Kind string `json:"kind"`
	}
	if err := json.Unmarshal(b, &env); err != nil {
		return true, fmt.Errorf("state conflict: %s is not JSON (%v); refusing to overwrite a different artifact", file, err)
	}
	if env.Kind != kind {
		return true, fmt.Errorf("state conflict: %s holds %q, want %q; refusing to overwrite a different artifact", file, env.Kind, kind)
	}
	if err := json.Unmarshal(b, v); err != nil {
		return true, fmt.Errorf("state conflict: %s is not a %s: %v", file, kind, err)
	}
	return true, nil
}

// metaReadBookmarks reads bookmarks.json, which final.md fixes as a bare array,
// so the shape check is the artifact check.
func metaReadBookmarks(file string) ([]metaBookmark, bool, error) {
	b, err := readCapped(file, maxMetaRead)
	if os.IsNotExist(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	t := bytes.TrimLeft(b, " \t\r\n")
	if len(t) == 0 || t[0] != '[' {
		return nil, true, fmt.Errorf("state conflict: %s is not a bookmark array; refusing to overwrite a different artifact", file)
	}
	var out []metaBookmark
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, true, fmt.Errorf("state conflict: %s: %v", file, err)
	}
	return out, true, nil
}

// metaWriteJSON replaces a state file atomically: a reader sees the old bytes
// or the new bytes, never a torn document.
func metaWriteJSON(file string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return metaWriteBytes(file, append(b, '\n'), false)
}

// metaCreateBytes writes a derived artifact twice-safe: identical bytes are an
// idempotent success, different bytes on disk are a conflict.
func metaCreateBytes(file string, b []byte) error {
	return metaWriteBytes(file, b, true)
}

// metaLock serialises a state-file read-modify-write across processes: two
// lrecon runs adding a note would otherwise both read the old list and the
// later write would silently drop the earlier note. lockFile is non-blocking on
// both platforms, so this waits and gives up instead of hanging. Closing the
// file releases the lock. A leftover .lock file is harmless: the lock is the
// flock on the open handle, not the file's existence.
func metaLock(file string) (func(), error) {
	f, err := os.OpenFile(file+".lock", os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		ok, err := lockFile(f)
		if err != nil {
			f.Close()
			return nil, err
		}
		if ok {
			return func() { f.Close() }, nil
		}
		if time.Now().After(deadline) {
			f.Close()
			return nil, fmt.Errorf("state conflict: %s stays locked by another lrecon after 5s; nothing was written", file)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func metaWriteBytes(file string, b []byte, createOnly bool) error {
	if old, err := readCapped(file, maxMetaRead); err == nil && createOnly {
		if bytes.Equal(old, b) {
			return nil
		}
		return fmt.Errorf("state conflict: %s already exists with different content; refusing to overwrite a different artifact", file)
	}
	if dir := filepath.Dir(file); dir != "" {
		if _, err := metaMkdir(dir); err != nil {
			return err
		}
	}
	tmp, err := os.CreateTemp(filepath.Dir(file), "."+filepath.Base(file)+".tmp*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return err
	}
	if err := os.Rename(name, file); err != nil {
		os.Remove(name)
		return err
	}
	return nil
}

// metaCanonical is canonicalJSON generalized off Digest: marshal, decode with
// UseNumber so integers keep their literal form, re-marshal (map keys sort).
func metaCanonical(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var x any
	if err := dec.Decode(&x); err != nil {
		return nil, err
	}
	return json.Marshal(x)
}

func metaSHA256(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func metaFileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// metaChange is one field-level difference between two digests: the exact
// json path and both values, so a reader never has to re-diff by hand.
type metaChange struct {
	Path   string `json:"path"`
	Before any    `json:"before"`
	After  any    `json:"after"`
}

// metaChanges walks the digest contract field by field. Compound fields compare
// by their canonical JSON, so a nested change still names its top path; deps
// expand per path because that is the field a version bump actually moves.
func metaChanges(a, b Digest) []metaChange {
	out := []metaChange{}
	av, bv := depMap(a), depMap(b)
	for _, p := range unionKeys(av, bv) {
		x, aok := av[p]
		y, bok := bv[p]
		if aok && bok && x == y {
			continue
		}
		ch := metaChange{Path: "deps." + p}
		if aok {
			ch.Before = x
		}
		if bok {
			ch.After = y
		}
		out = append(out, ch)
	}
	va, vb := reflect.ValueOf(a), reflect.ValueOf(b)
	t := va.Type()
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if name == "" || name == "-" || name == "deps" {
			continue
		}
		x, err := metaCanonical(va.Field(i).Interface())
		if err != nil {
			continue
		}
		y, err := metaCanonical(vb.Field(i).Interface())
		if err != nil {
			continue
		}
		if bytes.Equal(x, y) {
			continue
		}
		out = append(out, metaChange{Path: name, Before: metaAny(x), After: metaAny(y)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

func metaAny(b []byte) any {
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return string(b)
	}
	return v
}

func metaHexBytes(s string) ([]byte, error) {
	s = strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(s, "0x", ""), " ", ""))
	if s == "" {
		return nil, nil
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("bad hex %q: %v", s, err)
	}
	return b, nil
}

// metaHex renders bytes as lower-case hex with no separator.
func metaHex(b []byte) string { return hex.EncodeToString(b) }

// metaObjectSHA is the file identity used by the bundles: whole-file sha256.
func metaObjectSHA(path string) (string, int64, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return "", 0, err
	}
	if fi.IsDir() {
		return "", 0, fmt.Errorf("%s is a directory; bundles take a single file", path)
	}
	sum, err := metaFileSHA256(path)
	return sum, fi.Size(), err
}

// --- Ghidra side (route G) ---

// metaGhidraPath finds analyzeHeadless. Route M and route G must agree on what
// "Ghidra is installed" means, so this defers to findGhidra (LRECON_GHIDRA,
// LRECON_ANALYZEHEADLESS, PATH, GHIDRA_INSTALL_DIR/GHIDRA_HOME, ~/tools/ghidra*,
// the homebrew cellars) instead of keeping a second, drifting list.
func metaGhidraPath() (string, error) {
	p, _, err := findGhidra()
	if err != nil {
		return "", fmt.Errorf("analyzeHeadless not found: install Ghidra, put it on PATH, or set LRECON_GHIDRA / LRECON_ANALYZEHEADLESS / GHIDRA_INSTALL_DIR")
	}
	return p, nil
}

// metaGhidraOp runs one import+postScript pass and turns a missing Ghidra into
// a skip value instead of an error: the tool is optional, the answer is not.
func metaGhidraOp(job metaJob, mode string, extra map[string]string) (any, error) {
	if s := ghidraKindRefusal(job.File); s != nil {
		return s, nil
	}
	gh, err := metaGhidraPath()
	if err != nil {
		return skipf("ghidra: %v", err), nil
	}
	res, err := metaGhidraRun(gh, job, mode, extra)
	if err != nil {
		return nil, err
	}
	return res, nil
}

// metaGhidraRun runs Meta.java against the target. Route M shares the route-G
// project cache: the analysis is a property of the binary, not of the op, so
// annotate/set_inline_comment reopen an already analysed program instead of
// paying a fresh import and a full analysis on every call. Those two were the
// slowest G ops for exactly that reason -- ~50 s each, every time, with the
// caller's cap deciding whether the answer arrived at all.
//
// With LRECON_GHIDRA_CACHE=off there is no shared entry, so the throwaway
// project path stays: one import, one script, one deleted project.
func metaGhidraRun(gh string, job metaJob, mode string, extra map[string]string) (map[string]any, error) {
	if job.File == "" {
		return nil, fmt.Errorf("no target artifact: pass the file path or a job json with \"file\"")
	}
	abs, err := filepath.Abs(job.File)
	if err != nil {
		return nil, err
	}
	fi, err := os.Stat(abs)
	if err != nil || fi.IsDir() {
		return nil, fmt.Errorf("%s: not a readable file", job.File)
	}
	root, cached := ghidraCacheRoot()
	if !cached {
		dir, err := tempDir("lrecon-meta-")
		if err != nil {
			return nil, err
		}
		defer os.RemoveAll(dir)
		return metaGhidraRunIn(gh, abs, dir, "", true, job, mode, extra)
	}
	entry, err := ghidraAcquire(root, abs, ghidraVersion(gh), fi)
	if err != nil {
		return nil, err
	}
	defer entry.release()
	res, err := metaGhidraRunIn(gh, abs, entry.dir, entry.program, false, job, mode, extra)
	if err == nil {
		if entry.program == "" {
			if perr := entry.pin(abs); perr != nil {
				return nil, perr
			}
		}
		return res, nil
	}
	if isMetaTimeout(err) {
		// A partial import is not reusable: leave the entry unpinned so the
		// next call starts clean instead of reopening an unfinished analysis.
		return nil, err
	}
	if isScriptRefusal(err) {
		// The analysis is complete; the op's own answer was the refusal.
		if entry.program == "" {
			if perr := entry.pin(abs); perr != nil {
				return nil, perr
			}
		}
		return nil, err
	}
	if entry.program == "" {
		return nil, err
	}
	// The stored project could not be reopened: import once into a clean
	// directory instead of leaving every later op to fail the same way.
	entry.discard()
	res, err = metaGhidraRunIn(gh, abs, entry.dir, "", false, job, mode, extra)
	if err != nil {
		return nil, err
	}
	if err := entry.pin(abs); err != nil {
		return nil, err
	}
	return res, nil
}

// metaGhidraRunIn runs one Meta.java pass in dir. program == "" imports abs;
// otherwise the analysed program is reopened without re-analysis. deleteProject
// belongs to the throwaway tempdir path only -- a cache entry must survive.
func metaGhidraRunIn(gh, abs, dir, program string, deleteProject bool, job metaJob, mode string, extra map[string]string) (map[string]any, error) {
	// Ghidra's own project name and layout: the NativeOp route imports into the
	// same slot, and -process can only reopen the name it was imported under.
	projDir := filepath.Join(dir, "project")
	if _, err := metaMkdir(projDir); err != nil {
		return nil, err
	}
	scriptDir := filepath.Join(dir, "scripts")
	if _, err := metaMkdir(scriptDir); err != nil {
		return nil, err
	}
	if err := writeIfChanged(filepath.Join(scriptDir, "Meta.java"), []byte(metaGhidraScript)); err != nil {
		return nil, err
	}
	out := filepath.Join(dir, "out.json")
	os.Remove(out) // a previous run's answer must not pass for this one
	lines := []string{"mode=" + mode, "out=" + out}
	for _, k := range []string{"address", "text", "name"} {
		lines = append(lines, k+"="+strings.ReplaceAll(strings.ReplaceAll(metaExtra(extra, k), "\r\n", " "), "\n", " "))
	}
	if c := metaExtra(extra, "count"); c != "" && job.Labels == nil {
		lines = append(lines, "count="+c)
	}
	if job.Labels != nil {
		lines = append(lines, "count="+strconv.Itoa(len(job.Labels)))
		for i, l := range job.Labels {
			lines = append(lines, fmt.Sprintf("label.%d.address=%s", i, l.Address))
			lines = append(lines, fmt.Sprintf("label.%d.name=%s", i, l.Name))
		}
	}
	argsPath := filepath.Join(dir, "args.txt")
	if err := metaWriteBytes(argsPath, []byte(strings.Join(lines, "\n")+"\n"), false); err != nil {
		return nil, err
	}
	budget := ghidraTimeoutForPath(abs)
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	argv := []string{projDir, "lrecon"}
	if program == "" {
		// Ghidra's own per-file analysis budget defaults to 300s and truncates a
		// big import even when our deadline allows more.
		argv = append(argv, "-import", abs, "-analysisTimeoutPerFile", strconv.Itoa(int(budget.Seconds())))
	} else {
		// The project is already analysed: re-analysing it every call is the
		// cost this cache exists to remove.
		argv = append(argv, "-process", program, "-noanalysis")
	}
	argv = append(argv, "-scriptPath", scriptDir, "-postScript", "Meta.java", argsPath)
	if deleteProject {
		argv = append(argv, "-deleteProject")
	}
	cmd := ghidraExec(ctx, gh, argv...)
	// Ghidra prints script compile errors on stdout and the JDK banner on stderr,
	// so both streams must be kept or a broken script looks like a JDK failure.
	// CombinedOutput would hide the pid Wait needs to reap the group, so the two
	// streams share one buffer and the run is started by hand.
	var logb bytes.Buffer
	cmd.Stdout = &logb
	cmd.Stderr = &logb
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("analyzeHeadless: %v", err)
	}
	pgid := cmd.Process.Pid // release on Wait zeroes it, the group survives
	trackGroup(pgid)        // A4: a signal takes java down with the wrapper
	runErr := cmd.Wait()
	ghidraReap(pgid)
	log := logb.Bytes()
	if ctx.Err() == context.DeadlineExceeded {
		// A deadline is a refusal, not an answer: the op must exit 2 with
		// kind=timeout instead of handing back a result whose only content is
		// an "error" field. The stage still rides on the envelope.
		return nil, metaTimeoutErrorFor(dir, abs, budget, program != "")
	}
	b, err := readCapped(out, maxMetaRead)
	if err != nil {
		return nil, fmt.Errorf("analyzeHeadless: %v: %s", runErr, metaDiag(string(log), 6))
	}
	var res map[string]any
	if err := json.Unmarshal(b, &res); err != nil {
		return nil, fmt.Errorf("Meta.java output: %v (%s)", err, metaTail(string(b), 2))
	}
	if e, _ := res["error"].(string); e != "" {
		return res, &ghidraScriptRefusal{"Meta.java: " + e}
	}
	return res, nil
}

// metaTimeoutError is the Meta.java deadline refusal. A cold entry times out
// in "import"; a reopened one in "analyze"; once the script has written part of
// an answer the stage is "post". The file stays for a later attempt, but the
// caller gets an error (exit 2, kind=timeout), never a rc=0 result.
type metaTimeout struct {
	stage  string
	budget time.Duration
	target string
}

func (e *metaTimeout) Error() string {
	return fmt.Sprintf("analyzeHeadless %s timed out after %s on %s; raise LRECON_GHIDRA_TIMEOUT or LRECON_OP_DEADLINE", e.stage, e.budget, e.target)
}

func metaTimeoutErrorFor(dir, abs string, budget time.Duration, warm bool) error {
	stage := "import"
	if warm {
		stage = "analyze"
	}
	if b, err := readCapped(filepath.Join(dir, "out.json"), maxMetaRead); err == nil && len(b) > 0 {
		stage = "post"
	}
	setRefuseStage(stage)
	return &metaTimeout{stage: stage, budget: budget, target: filepath.Base(abs)}
}

func isMetaTimeout(err error) bool {
	var t *metaTimeout
	return errors.As(err, &t)
}

func metaExtra(m map[string]string, k string) string {
	if m == nil {
		return ""
	}
	return m[k]
}

// metaArgs builds a Ghidra argument map from key/value pairs, dropping empty
// values so the script only sees what the job actually supplied.
func metaArgs(kv ...string) map[string]string {
	m := map[string]string{}
	for i := 0; i+1 < len(kv); i += 2 {
		if v := strings.TrimSpace(kv[i+1]); v != "" {
			m[kv[i]] = v
		}
	}
	return m
}

// metaGhidraTarget resolves the artifact a route-G job points at.
func metaGhidraTarget(path string, job metaJob) (string, error) {
	target := job.File
	if target == "" {
		target = path
	}
	abs, err := filepath.Abs(target)
	if err != nil {
		return "", err
	}
	fi, err := os.Stat(abs)
	if err != nil {
		return "", err
	}
	if fi.IsDir() {
		return "", fmt.Errorf("%s: a directory is not importable by analyzeHeadless", abs)
	}
	return abs, nil
}

// metaTail keeps the last n non-empty lines: Ghidra writes a lot of progress
// noise, and the useful line is always at the end.
func metaTail(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	var keep []string
	for _, l := range lines {
		if strings.TrimSpace(l) != "" {
			keep = append(keep, strings.TrimSpace(l))
		}
	}
	if len(keep) > n {
		keep = keep[len(keep)-n:]
	}
	return strings.Join(keep, " | ")
}

// metaDiag prefers the error lines over the tail: when Meta.java fails to
// compile, Ghidra buries the error mid-log under a ClassNotFound stack trace.
func metaDiag(s string, n int) string {
	var hits []string
	for l := range strings.SplitSeq(s, "\n") {
		if t := strings.TrimSpace(l); strings.Contains(t, "error:") || strings.HasPrefix(t, "ERROR") {
			if hits = append(hits, t); len(hits) == n {
				break
			}
		}
	}
	if len(hits) > 0 {
		return strings.Join(hits, " | ")
	}
	return metaTail(s, n)
}

// --- file layout: virtual address to file offset ---

// metaPlace is where an address lands on disk plus the nearest symbol before it.
type metaPlace struct {
	File    string `json:"file"`
	Address uint64 `json:"address,omitempty"`
	Offset  int64  `json:"offset"`
	Section string `json:"section,omitempty"`
	Segment string `json:"segment,omitempty"`
	Symbol  string `json:"symbol,omitempty"`
	Delta   int64  `json:"symbol_delta,omitempty"`
	Exact   bool   `json:"exact"` // the address is inside a mapped section
	Arch    string `json:"arch,omitempty"`
}

// metaSection is one mapped section of a Mach-O (every slice), ELF or PE image.
type metaSection struct {
	Name string
	Seg  string
	Arch string
	Addr uint64
	Size uint64
	Off  uint64
}

func metaSectionTable(path string) ([]metaSection, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(abs)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var head [4]byte
	if _, err := f.ReadAt(head[:], 0); err != nil {
		return nil, err
	}
	var out []metaSection
	switch {
	case isMachO(head[:]) || isFatMachO(head[:]):
		if ff, err := macho.NewFatFile(f); err == nil {
			defer ff.Close()
			for _, a := range ff.Arches {
				for _, s := range a.Sections {
					out = append(out, metaSection{Name: s.Name, Seg: s.Seg, Arch: machoArch(a.Cpu), Addr: s.Addr, Size: s.Size, Off: uint64(a.Offset) + uint64(s.Offset)})
				}
			}
			return out, nil
		}
		mf, err := macho.NewFile(f)
		if err != nil {
			return nil, err
		}
		for _, s := range mf.Sections {
			out = append(out, metaSection{Name: s.Name, Seg: s.Seg, Arch: machoArch(mf.Cpu), Addr: s.Addr, Size: s.Size, Off: uint64(s.Offset)})
		}
		return out, nil
	case len(head) >= 4 && head[0] == 0x7f && head[1] == 'E' && head[2] == 'L' && head[3] == 'F':
		ef, err := elf.NewFile(f)
		if err != nil {
			return nil, err
		}
		for _, s := range ef.Sections {
			if s.Type == elf.SHT_NOBITS {
				continue
			}
			out = append(out, metaSection{Name: s.Name, Addr: s.Addr, Size: s.Size, Off: s.Offset})
		}
		return out, nil
	case head[0] == 'M' && head[1] == 'Z':
		pf, err := pe.NewFile(f)
		if err != nil {
			return nil, err
		}
		for _, s := range pf.Sections {
			size := uint64(s.VirtualSize)
			if size == 0 {
				size = uint64(s.Size)
			}
			out = append(out, metaSection{Name: s.Name, Addr: metaPEImageBase(pf) + uint64(s.VirtualAddress), Size: size, Off: uint64(s.Offset)})
		}
		return out, nil
	}
	return nil, fmt.Errorf("%s: not a Mach-O, ELF or PE image", path)
}

// metaPEImageBase reads the preferred load address from the optional header.
func metaPEImageBase(f *pe.File) uint64 {
	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader64:
		return oh.ImageBase
	case *pe.OptionalHeader32:
		return uint64(oh.ImageBase)
	}
	return 0
}

// metaLocate maps a virtual address through the section table. A fat Mach-O is
// tried slice by slice and the slice that contains the address wins.
func metaLocate(path string, addr uint64) (metaPlace, error) {
	secs, err := metaSectionTable(path)
	if err != nil {
		return metaPlace{}, err
	}
	abs, _ := filepath.Abs(path)
	p := metaPlace{File: abs, Address: addr}
	for _, s := range secs {
		if s.Size == 0 || addr < s.Addr || addr >= s.Addr+s.Size {
			continue
		}
		p.Offset, p.Section, p.Segment, p.Arch, p.Exact = int64(s.Off+(addr-s.Addr)), s.Name, s.Seg, s.Arch, true
		p.Symbol, p.Delta = metaSymbolAt(path, addr)
		break
	}
	return p, nil
}

// metaLocateOffset maps a file offset back to its virtual address and symbol.
// trace_feature uses it on literal byte hits, which have offsets, not addresses.
func metaLocateOffset(path string, off int64) (metaPlace, error) {
	secs, err := metaSectionTable(path)
	if err != nil {
		return metaPlace{}, err
	}
	abs, _ := filepath.Abs(path)
	p := metaPlace{File: abs}
	u := uint64(off)
	for _, s := range secs {
		if s.Size == 0 || u < s.Off || u >= s.Off+s.Size {
			continue
		}
		p.Offset, p.Section, p.Segment, p.Arch, p.Exact = off, s.Name, s.Seg, s.Arch, true
		addr := s.Addr + (u - s.Off)
		p.Address = addr
		p.Symbol, p.Delta = metaSymbolAt(path, addr)
		break
	}
	return p, nil
}

// metaSymbolAt returns the nearest defined symbol at or before addr.
func metaSymbolAt(path string, addr uint64) (string, int64) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0
	}
	defer f.Close()
	var head [4]byte
	if _, err := f.ReadAt(head[:], 0); err != nil {
		return "", 0
	}
	best, delta := "", uint64(1<<63)
	consider := func(name string, v uint64) {
		if v == 0 || v > addr || addr-v >= delta || addr-v > 1<<24 {
			return
		}
		best, delta = name, addr-v
	}
	switch {
	case isMachO(head[:]):
		mf, err := macho.NewFile(f)
		if err != nil || mf.Symtab == nil {
			return "", 0
		}
		for _, s := range mf.Symtab.Syms {
			consider(s.Name, s.Value)
		}
	case len(head) >= 4 && head[0] == 0x7f && head[1] == 'E' && head[2] == 'L' && head[3] == 'F':
		ef, err := elf.NewFile(f)
		if err != nil {
			return "", 0
		}
		syms, err := ef.Symbols()
		if err != nil {
			return "", 0
		}
		for _, s := range syms {
			if int(s.Info&0xf) == int(elf.STT_SECTION) {
				continue
			}
			consider(s.Name, s.Value)
		}
	case head[0] == 'M' && head[1] == 'Z':
		pf, err := pe.NewFile(f)
		if err != nil {
			return "", 0
		}
		for _, s := range pf.Symbols {
			consider(s.Name, uint64(s.Value))
		}
	}
	if best == "" {
		return best, 0
	}
	return best, int64(delta)
}

// --- bundle members ---

// metaArchiveMembers lists a bundle as name->sha256. A zip-family archive
// (apk/aab/ipa/hap) is read member by member; a directory is walked.
func metaArchiveMembers(path string) (map[string]string, string, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, "", err
	}
	if fi.IsDir() {
		m := map[string]string{}
		err := filepath.WalkDir(path, func(p string, e os.DirEntry, err error) error {
			if err != nil || e.IsDir() {
				return err
			}
			rel, _ := filepath.Rel(path, p)
			sum, err := metaFileSHA256(p)
			if err != nil {
				return err
			}
			m[filepath.ToSlash(rel)] = sum
			return nil
		})
		return m, "dir", err
	}
	r, err := zip.OpenReader(path)
	if err != nil {
		return nil, "", fmt.Errorf("%s: not a zip/apk/aab/ipa/hap archive and not a directory", path)
	}
	defer r.Close()
	m := map[string]string{}
	for _, zf := range r.File {
		if zf.FileInfo().IsDir() {
			continue
		}
		if zf.UncompressedSize64 > uint64(opMaxFile) {
			return nil, "", fmt.Errorf("%s: member %s is %d bytes, over the %d-byte cap", path, zf.Name, zf.UncompressedSize64, opMaxFile)
		}
		rc, err := zf.Open()
		if err != nil {
			return nil, "", err
		}
		h := sha256.New()
		// The declared size is a hint, not a promise: a member that inflates
		// past the cap is refused, never hashed from a cut.
		n, cerr := io.Copy(h, io.LimitReader(rc, opMaxFile+1))
		rc.Close()
		if cerr != nil {
			return nil, "", cerr
		}
		if n > opMaxFile {
			return nil, "", fmt.Errorf("%s: member %s inflates past the %d-byte cap", path, zf.Name, opMaxFile)
		}
		m[zf.Name] = hex.EncodeToString(h.Sum(nil))
	}
	return m, "zip", nil
}

// metaArchiveMember reads one member out of a bundle directory or zip archive.
func metaArchiveMember(path, name string) ([]byte, error) {
	if fi, err := os.Stat(path); err == nil && fi.IsDir() {
		return opRead(filepath.Join(path, filepath.FromSlash(name)), opMaxFile)
	}
	r, err := zip.OpenReader(path)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	for _, zf := range r.File {
		if zf.Name != name {
			continue
		}
		if zf.UncompressedSize64 > uint64(opMaxFile) {
			return nil, fmt.Errorf("%s: member %s is %d bytes, over the %d-byte cap", path, zf.Name, zf.UncompressedSize64, opMaxFile)
		}
		rc, err := zf.Open()
		if err != nil {
			return nil, err
		}
		defer rc.Close()
		// The declared size is a hint, not a promise: a member that inflates
		// past the cap is refused, never read from a cut.
		b, err := io.ReadAll(io.LimitReader(rc, opMaxFile+1))
		if err != nil {
			return nil, err
		}
		if int64(len(b)) > opMaxFile {
			return nil, fmt.Errorf("%s: member %s inflates past the %d-byte cap", path, zf.Name, opMaxFile)
		}
		return b, nil
	}
	return nil, fmt.Errorf("%s: no member %q", path, name)
}

// --- MSBuild/tar helpers used by two ops ---

// metaTarEntry appends one deterministic tar member: mode 0644/0755, mtime 0,
// no owner names, so the archive hash depends on content only.
func metaWriteTar(tw *tar.Writer, name string, b []byte, mode int64) error {
	hdr := &tar.Header{Name: name, Mode: mode, Size: int64(len(b)), Typeflag: tar.TypeReg}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	_, err := tw.Write(b)
	return err
}

// metaParseAddr accepts 0x-prefixed and bare hex, and plain decimal.
func metaParseAddr(s string) (uint64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty address")
	}
	if v, err := strconv.ParseUint(strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X"), 16, 64); err == nil {
		return v, nil
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("bad address %q", s)
	}
	return v, nil
}

// metaCLIFacts is the managed table surface: the groups parseCLITables keeps
// private (TypeRef, MethodDef, Field, MemberRef) decoded with the same helpers.
type metaCLIFacts struct {
	Module   string        `json:"module"`
	Assembly string        `json:"assembly"`
	Types    []metaCLIType `json:"types"`
	TypeRefs []string      `json:"type_refs,omitempty"`
	Fields   []string      `json:"fields,omitempty"`
	Refs     []string      `json:"member_refs,omitempty"`
	AsmRefs  []string      `json:"assembly_refs,omitempty"`
	Rows     int           `json:"rows"`
}

type metaCLIType struct {
	Name    string   `json:"name"`
	Extends string   `json:"extends,omitempty"`
	Methods []string `json:"methods,omitempty"`
	Fields  []string `json:"fields,omitempty"`
}

func metaCLI(path string) (metaCLIFacts, error) {
	var out metaCLIFacts
	src, err := os.Open(path)
	if err != nil {
		return out, err
	}
	defer src.Close()
	img, ok := openPEImage(src)
	if !ok || img.cliRVA == 0 || img.cliSize < cliHeaderSize {
		return out, fmt.Errorf("%s: no CLR header (not a managed assembly)", path)
	}
	cli, ok := img.at(img.cliRVA, cliHeaderSize)
	if !ok {
		return out, fmt.Errorf("%s: CLI header out of range", path)
	}
	read := min(binary.LittleEndian.Uint32(cli[12:16]), maxMetaRead)
	meta, ok := img.at(binary.LittleEndian.Uint32(cli[8:12]), read)
	if !ok {
		return out, fmt.Errorf("%s: metadata root out of range", path)
	}
	md, ok := parseMetadata(meta)
	if !ok {
		return out, fmt.Errorf("%s: metadata root (BSJB) unreadable", path)
	}
	// Reuse the digest table reader for the groups it projects.
	var d Digest
	t := parseCLITables(md, &d)
	if !t.ok {
		return out, fmt.Errorf("%s: table stream refused: %s", path, strings.TrimSpace(strings.Join(d.Notes, "; ")))
	}
	out.Module, out.Assembly, out.AsmRefs = t.module, t.assembly, nil
	for _, r := range t.refs {
		out.AsmRefs = append(out.AsmRefs, r.Path)
	}
	raw, ok := md.data["#~"]
	if !ok {
		raw, ok = md.data["#-"]
	}
	if !ok || len(raw) < 24 {
		return out, fmt.Errorf("%s: table stream missing", path)
	}
	heapSizes := raw[6]
	valid := binary.LittleEndian.Uint64(raw[8:])
	var rows [0x2D]int
	off := 24
	for id := 0; id <= 0x2C; id++ {
		if valid&(1<<uint(id)) == 0 {
			continue
		}
		if off+4 > len(raw) {
			return out, fmt.Errorf("%s: row count table cut", path)
		}
		rows[id] = int(binary.LittleEndian.Uint32(raw[off:]))
		off += 4
	}
	data := raw[off:]
	tableOff, tableSize := [0x2D]int{}, [0x2D]int{}
	cur := 0
	for id := 0; id <= 0x2C; id++ {
		w, _ := colWidths(tableSchema[id], heapSizes, &rows)
		for _, x := range w {
			tableSize[id] += x
		}
		tableOff[id] = cur
		cur += tableSize[id] * rows[id]
	}
	if cur > len(data) {
		return out, fmt.Errorf("%s: tables need %d bytes, stream has %d", path, cur, len(data))
	}
	row := func(id, i int) []byte {
		p := tableOff[id] + i*tableSize[id]
		return data[p : p+tableSize[id]]
	}
	// Every table list below is row-aligned: TypeDef.Extends and the
	// MethodList/FieldList ranges are row indices, so a sorted or filtered
	// list would move members onto the wrong type.
	colStrings := func(id, col int) []string {
		if rows[id] == 0 {
			return nil
		}
		w, o := colWidths(tableSchema[id], heapSizes, &rows)
		v := make([]string, rows[id])
		for i := range v {
			v[i] = heapString(md.strings, idxAt(row(id, i), o[col], w[col]))
		}
		return v
	}
	qualify := func(name, ns []string) []string {
		v := make([]string, len(name))
		for i := range name {
			v[i] = name[i]
			if i < len(ns) && ns[i] != "" {
				v[i] = ns[i] + "." + name[i]
			}
		}
		return v
	}
	tdName := colStrings(0x02, 1)
	tdFull := qualify(tdName, colStrings(0x02, 2))
	// NestedClass (0x29) maps a TypeDef row to its enclosing TypeDef row. Row
	// order is not guaranteed enclosing-first, so resolve in passes; a nested
	// type's own namespace is empty and its identity is the enclosing name.
	if rows[0x29] > 0 && rows[0x02] > 0 {
		w, o := colWidths(tableSchema[0x29], heapSizes, &rows)
		for range 16 {
			changed := false
			for i := 0; i < rows[0x29]; i++ {
				r := row(0x29, i)
				nested := int(idxAt(r, o[0], w[0])) - 1
				encl := int(idxAt(r, o[1], w[1])) - 1
				if nested < 0 || encl < 0 || nested >= len(tdFull) || encl >= len(tdFull) || nested == encl {
					continue
				}
				want := tdFull[encl] + "+" + tdName[nested]
				if tdFull[nested] != want {
					tdFull[nested] = want
					changed = true
				}
			}
			if !changed {
				break
			}
		}
	}
	typeRefs := qualify(colStrings(0x01, 1), colStrings(0x01, 2))
	fields := colStrings(0x04, 1)
	refs := colStrings(0x0A, 1)
	// MethodDef columns are RVA, ImplFlags, Flags, Name: the name is column 3,
	// not the 2-byte Flags field at column 2.
	methods := colStrings(0x06, 3)
	out.TypeRefs, out.Fields, out.Refs = typeRefs, fields, refs
	extends := make([]string, rows[0x02])
	// TypeDef.Extends is a TypeDefOrRef coded index: 2 tag bits, high bits = row-1.
	if rows[0x02] > 0 {
		w, o := colWidths(tableSchema[0x02], heapSizes, &rows)
		for i := 0; i < rows[0x02]; i++ {
			v := idxAt(row(0x02, i), o[3], w[3])
			ridx := int(v >> 2)
			switch v & 3 {
			case 0:
				if ridx >= 1 && ridx <= len(tdFull) {
					extends[i] = tdFull[ridx-1]
				}
			case 1:
				if ridx >= 1 && ridx <= len(typeRefs) {
					extends[i] = typeRefs[ridx-1]
				}
			default:
				extends[i] = "typespec"
			}
		}
	}
	// TypeDef.MethodList is a 1-based MethodDef index: the range per type is
	// [row[i], row[i+1]) with the last type running to the method row count.
	methodList := func() []int {
		var starts []int
		if rows[0x02] == 0 {
			return nil
		}
		w, o := colWidths(tableSchema[0x02], heapSizes, &rows)
		for i := 0; i < rows[0x02]; i++ {
			starts = append(starts, int(idxAt(row(0x02, i), o[5], w[5])))
		}
		return starts
	}()
	fieldList := func() []int {
		var starts []int
		if rows[0x02] == 0 {
			return nil
		}
		w, o := colWidths(tableSchema[0x02], heapSizes, &rows)
		for i := 0; i < rows[0x02]; i++ {
			starts = append(starts, int(idxAt(row(0x02, i), o[4], w[4])))
		}
		return starts
	}()
	emitted := 0
	for i := 0; i < rows[0x02] && emitted < maxCLITypeDefs; i++ {
		if tdName[i] == "" || tdName[i] == "<Module>" {
			continue
		}
		typ := metaCLIType{Name: tdFull[i], Extends: extends[i],
			Methods: metaSlice(methods, methodList, i, len(methods)),
			Fields:  metaSlice(fields, fieldList, i, len(fields))}
		out.Types = append(out.Types, typ)
		emitted++
	}
	out.Rows = rows[0x01] + rows[0x02] + rows[0x04] + rows[0x06] + rows[0x0A]
	return out, nil
}

// metaSlice takes the (1-based) MethodList/FieldList range one TypeDef owns.
func metaSlice(list []string, starts []int, i, total int) []string {
	if len(starts) == 0 || i >= len(starts) {
		return nil
	}
	lo := starts[i] - 1
	hi := total
	if i+1 < len(starts) {
		hi = starts[i+1] - 1
	}
	if lo < 0 || lo >= total || hi > total || lo >= hi {
		return nil
	}
	return list[lo:hi]
}

// metaGhidraScript is the postScript every route-G op runs: one file, mode in
// the argument file, JSON out. It is written next to the imported binary so a
// Ghidra install needs no extra setup; JSON is emitted by hand because the
// script may only rely on what Ghidra always ships.
const metaGhidraScript = `import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayDeque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class Meta extends GhidraScript {
    static String js(String s) {
        if (s == null) return "null";
        StringBuilder b = new StringBuilder("\"");
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '"') b.append("\\\"");
            else if (c == '\\') b.append("\\\\");
            else if (c == '\n') b.append("\\n");
            else if (c == '\r') b.append("\\r");
            else if (c == '\t') b.append("\\t");
            else if (c < 0x20) b.append(String.format("\\u%04x", (int) c));
            else b.append(c);
        }
        return b.append('"').toString();
    }

    @Override
    public void run() throws Exception {
        String[] a = getScriptArgs();
        String out = null;
        String body;
        try {
            if (a.length < 1) throw new IllegalStateException("usage: Meta.java <args file>");
            Map<String, String> kv = new HashMap<>();
            for (String line : Files.readAllLines(Paths.get(a[0]), StandardCharsets.UTF_8)) {
                int i = line.indexOf('=');
                if (i > 0) kv.put(line.substring(0, i), line.substring(i + 1));
            }
            out = kv.get("out");
            String mode = kv.get("mode");
            if (mode == null || out == null) throw new IllegalStateException("args file names no mode/out");
            Listing lst = currentProgram.getListing();
            if (mode.equals("PLATE") || mode.equals("PRE") || mode.equals("EOL") || mode.equals("ANNOTATE")) {
                Address addr = toAddr(kv.get("address"));
                String text = kv.get("text");
                if (text == null) text = "";
                CommentType ct = mode.equals("PLATE") ? CommentType.PLATE
                    : mode.equals("PRE") ? CommentType.PRE
                    : mode.equals("EOL") ? CommentType.EOL : null;
                if (ct != null) lst.setComment(addr, ct, text);
                else {
                    Function f = getFunctionContaining(addr);
                    if (f == null) throw new IllegalStateException("no function contains " + addr);
                    f.setComment(text);
                }
                body = "\"address\":" + js(addr.toString()) + ",\"comment\":" + js(text)
                    + ",\"stored\":" + js(ct != null ? String.valueOf(lst.getComment(ct, addr))
                        : String.valueOf(getFunctionContaining(addr).getComment()));
            } else if (mode.equals("LABEL")) {
                Address addr = toAddr(kv.get("address"));
                Symbol s = createLabel(addr, kv.get("name"), true);
                // A created symbol is not proof it was stored: read the primary
                // symbol back so the caller sees what the program now holds.
                Symbol back = currentProgram.getSymbolTable().getPrimarySymbol(addr);
                body = "\"address\":" + js(addr.toString()) + ",\"name\":" + js(s.getName())
                    + ",\"applied\":" + (back != null) + ",\"readback\":"
                    + js(back != null ? back.getName() : "");
            } else if (mode.equals("LABELS")) {
                int n = Integer.parseInt(kv.getOrDefault("count", "0"));
                StringBuilder sb = new StringBuilder("\"labels\":[");
                for (int i = 0; i < n; i++) {
                    Address addr = toAddr(kv.get("label." + i + ".address"));
                    Symbol s = createLabel(addr, kv.get("label." + i + ".name"), true);
                    if (i > 0) sb.append(',');
                    sb.append("{\"address\":").append(js(addr.toString()))
                      .append(",\"name\":").append(js(s.getName())).append('}');
                }
                body = sb.append(']').toString();
            } else if (mode.equals("UNKNOWN")) {
                AddressSet covered = new AddressSet();
                for (Instruction ins : lst.getInstructions(true)) covered.add(ins.getMinAddress(), ins.getMaxAddress());
                for (Data d : lst.getDefinedData(true)) covered.add(d.getMinAddress(), d.getMaxAddress());
                AddressSet undef = currentProgram.getMemory().getLoadedAndInitializedAddressSet().subtract(covered);
                StringBuilder sb = new StringBuilder("\"ranges\":[");
                int n = 0;
                long total = 0;
                for (AddressRange r : undef.getAddressRanges()) {
                    if (n >= 100) break;
                    if (n > 0) sb.append(',');
                    sb.append("{\"start\":").append(js(r.getMinAddress().toString()))
                      .append(",\"end\":").append(js(r.getMaxAddress().toString()))
                      .append(",\"length\":").append(r.getLength()).append('}');
                    total += r.getLength();
                    n++;
                }
                body = sb.append("],\"bytes\":").append(total).append(",\"count\":").append(n).toString();
            } else if (mode.equals("TRACE")) {
                String text = kv.get("text");
                if (text != null && !text.isEmpty()) {
                    byte[] needle = text.getBytes(StandardCharsets.UTF_8);
                    Address found = currentProgram.getMemory().findBytes(currentProgram.getMinAddress(), needle, null, true, monitor);
                    if (found == null) throw new IllegalStateException("string not found: " + text);
                    StringBuilder sb = new StringBuilder("\"string\":").append(js(text))
                        .append(",\"address\":").append(js(found.toString())).append(",\"references\":[");
                    int n = 0;
                    for (Reference r : getReferencesTo(found)) {
                        Function f = getFunctionContaining(r.getFromAddress());
                        if (n++ > 0) sb.append(',');
                        sb.append("{\"from\":").append(js(r.getFromAddress().toString()))
                          .append(",\"function\":").append(js(f == null ? "" : f.getName())).append('}');
                        if (n >= 100) break;
                    }
                    body = sb.append(']').toString();
                } else {
                    // Address mode: walk callers outward, one level per round trip.
                    Address start = toAddr(kv.get("address"));
                    Function f = getFunctionContaining(start);
                    if (f == null) throw new IllegalStateException("no function contains " + start);
                    int depth = Integer.parseInt(kv.getOrDefault("count", "16"));
                    StringBuilder sb = new StringBuilder("\"address\":").append(js(start.toString()))
                        .append(",\"function\":").append(js(f.getName())).append(",\"callers\":[");
                    Set<Function> seen = new HashSet<>();
                    seen.add(f);
                    ArrayDeque<Function> queue = new ArrayDeque<>();
                    queue.add(f);
                    int n = 0;
                    for (int d = 0; d < depth && !queue.isEmpty() && n < 100; d++) {
                        int level = queue.size();
                        for (int i = 0; i < level && n < 100; i++) {
                            for (Function caller : queue.poll().getCallingFunctions(monitor)) {
                                if (!seen.add(caller)) continue;
                                if (n++ > 0) sb.append(',');
                                sb.append("{\"function\":").append(js(caller.getName()))
                                  .append(",\"entry\":").append(js(caller.getEntryPoint().toString())).append('}');
                                queue.add(caller);
                            }
                        }
                    }
                    body = sb.append("],\"count\":").append(n).toString();
                }
            } else {
                throw new IllegalStateException("unknown mode " + mode);
            }
        } catch (Exception e) {
            body = "\"error\":" + js(e.toString());
        }
        if (out != null) Files.write(Paths.get(out), ("{" + body + "}").getBytes(StandardCharsets.UTF_8));
        else println("META: " + body);
    }
}
`

// metaNode and metaEdge are the shared shape of the four application graphs.
// A node is a real member of the artifact; an edge names how two members relate.
type metaNode struct {
	Kind    string   `json:"kind"`
	Name    string   `json:"name"`
	Super   string   `json:"super,omitempty"`
	Methods []string `json:"methods,omitempty"`
	Detail  string   `json:"detail,omitempty"`
}

type metaEdge struct {
	From string `json:"from"`
	To   string `json:"to"`
	Kind string `json:"kind"` // contains|extends|references|declares
}

func metaGraphResult(nodes []metaNode, edges []metaEdge) map[string]any {
	if nodes == nil {
		nodes = []metaNode{}
	}
	if edges == nil {
		edges = []metaEdge{}
	}
	return map[string]any{"nodes": nodes, "edges": edges, "node_count": len(nodes), "edge_count": len(edges)}
}

// nz keeps a list field an array in the envelope. A nil slice marshals as
// null, and a caller that asks for [] ("no capabilities") then has to special
// case a type it was promised.
func nz(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}
