package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --op used to run before the live-target decline, so it stat()ed pid:1234 and
// reported a missing file instead of saying runtime targets are out of scope.
func TestOpDeclinesLiveTarget(t *testing.T) {
	stdout, stderr, code := runCLIAll(t, "--op", "list_procedures", "pid:1234")
	if code != 2 {
		t.Fatalf("exit %d, want 2; stdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	if stdout != "" {
		t.Fatalf("declined a live target but wrote stdout:\n%s", stdout)
	}
	if !strings.Contains(strings.ToLower(stderr), "runtime") {
		t.Fatalf("stderr does not mention runtime:\n%s", stderr)
	}
	if strings.Contains(stderr, "no such file") {
		t.Fatalf("stderr reports a filesystem error for a live target:\n%s", stderr)
	}
}

// A bare skip is a refusal with a reason, but it printed as JSON and exited 0,
// so a missing tool looked like an answer. A CARV catalog reaches the same
// branch without depending on which debuggers this host has installed.
func TestOpSkipRefuses(t *testing.T) {
	carv := writeTemp(t, "chunks.car", []byte("CARV\x00\x00\x00\x00"))
	stdout, stderr, code := runCLIAll(t, "--op", "inspect_asset_catalog", "--json", carv)
	if code != 2 {
		t.Fatalf("exit %d, want 2; stdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	if op, msg, kind := opEnvelope(t, stdout); op != "inspect_asset_catalog" || kind != "bad_arg" || !strings.Contains(msg, "CARV") {
		t.Fatalf("stdout envelope = op %q, msg %q, kind %q; want the skip reason as a bad_arg refusal", op, msg, kind)
	}
	if !strings.Contains(stderr, "CARV") {
		t.Fatalf("stderr does not carry the skip reason:\n%s", stderr)
	}
}

// --deep prints text, so --json cannot answer it. Under --json the refusal is
// still one machine answer on stdout (A1: a --json caller never parses prose),
// and it must name the conflict, not the missing symbol.
func TestDeepRefusesJSON(t *testing.T) {
	stdout, stderr, code := runCLIAll(t, "--json", "--deep", "zzz_no_such_symbol", "/bin/ls")
	if code != 2 {
		t.Fatalf("exit %d, want 2; stdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	if !strings.HasPrefix(stderr, "lrecon: ") {
		t.Fatalf("stderr = %q, want the prefixed refusal line", stderr)
	}
	var env struct {
		Op    *string `json:"op"`
		Error string  `json:"error"`
		Kind  string  `json:"kind"`
	}
	if err := json.Unmarshal([]byte(stdout), &env); err != nil {
		t.Fatalf("stdout is not one envelope: %v\n%s", err, stdout)
	}
	if env.Kind != "bad_arg" && env.Kind != "usage" {
		t.Fatalf("kind = %q, want bad_arg or usage; envelope: %s", env.Kind, stdout)
	}
	if !strings.Contains(env.Error, "--deep") {
		t.Fatalf("envelope does not name the --deep conflict:\n%s", stdout)
	}
	if strings.Contains(env.Error, "zzz_no_such_symbol") {
		t.Fatalf("refused on the symbol instead of the mode conflict:\n%s", stdout)
	}
}

// An explicit empty value used to read as an absent flag, so `--extract ""`
// printed a digest as if the extraction had succeeded.
func TestEmptyModeFlagsRefuse(t *testing.T) {
	for _, name := range []string{"--extract", "--extract-all", "--diff", "--explain"} {
		t.Run(name, func(t *testing.T) {
			stdout, stderr, code := runCLIAll(t, name, "", "/bin/ls")
			if code != 2 {
				t.Fatalf("exit %d, want 2; stdout:\n%s\nstderr:\n%s", code, stdout, stderr)
			}
			if stdout != "" {
				t.Fatalf("refused but wrote stdout:\n%s", stdout)
			}
			if !strings.Contains(stderr, name) {
				t.Fatalf("stderr does not name %s:\n%s", name, stderr)
			}
		})
	}
}

// The skip refusal is for bare skips only: a map result still answers with JSON.
func TestOpMapResultExit0(t *testing.T) {
	stdout, stderr, code := runCLIAll(t, "--op", "list_strings", "/bin/ls")
	if code != 0 {
		t.Fatalf("exit %d, want 0; stderr:\n%s", code, stderr)
	}
	var v struct {
		Op     string         `json:"op"`
		Result map[string]any `json:"result"`
	}
	if err := json.Unmarshal([]byte(stdout), &v); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, stdout)
	}
	if v.Op != "list_strings" || v.Result == nil {
		t.Fatalf("op/result = %q/%v, want list_strings and a map", v.Op, v.Result)
	}
}

// A route G item on the happy path: the moved declines must not swallow it.
func TestOpGhidraResultExit0(t *testing.T) {
	requireRealGhidra(t)
	stdout, stderr, code := runCLIAll(t, "--op", "list_segments", "/bin/ls")
	if code != 0 {
		t.Fatalf("exit %d, want 0; stderr:\n%s", code, stderr)
	}
	var v struct {
		Op     string         `json:"op"`
		Result map[string]any `json:"result"`
	}
	if err := json.Unmarshal([]byte(stdout), &v); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, stdout)
	}
	if v.Op != "list_segments" || v.Result == nil {
		t.Fatalf("op/result = %q/%v, want list_segments and a map", v.Op, v.Result)
	}
}

// -o writes the digest; an op prints its own document. Dropping -o silently
// left the caller reading a file that was never written.
func TestOpRefusesOutFile(t *testing.T) {
	out := filepath.Join(t.TempDir(), "digest.json")
	stdout, stderr, code := runCLIAll(t, "-o", out, "--op", "list_strings", "--json", "/bin/ls")
	if code != 2 {
		t.Fatalf("exit %d, want 2; stdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	if op, msg, kind := opEnvelope(t, stdout); op != "list_strings" || kind != "bad_arg" || !strings.Contains(msg, "-o") {
		t.Fatalf("stdout envelope = op %q, msg %q, kind %q; want a bad_arg refusal naming -o", op, msg, kind)
	}
	if !strings.Contains(stderr, "-o") {
		t.Fatalf("stderr does not name -o:\n%s", stderr)
	}
	if _, err := os.Stat(out); err == nil {
		t.Fatalf("refused but wrote %s", out)
	}
}

// opEnvelope reads the one-line --json refusal a --json caller parses.
func opEnvelope(t *testing.T, stdout string) (op, msg, kind string) {
	t.Helper()
	var env struct {
		Op    *string `json:"op"`
		Error string  `json:"error"`
		Kind  string  `json:"kind"`
	}
	if err := json.Unmarshal([]byte(stdout), &env); err != nil {
		t.Fatalf("stdout is not one envelope: %v\n%s", err, stdout)
	}
	if env.Op == nil {
		return "", env.Error, env.Kind
	}
	return *env.Op, env.Error, env.Kind
}

// comment's target is the first problem, not the job fields: a path that is not
// there was never read, so it kept its io error instead of claiming the job was
// missing "address"/"text" (the job was never opened at all).
func TestOpCommentMissingTargetIsIO(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "no-such-job.json")
	stdout, stderr, code := runCLIAll(t, "--op", "comment", "--json", missing)
	if code != 2 {
		t.Fatalf("exit %d, want 2; stdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	if !strings.HasPrefix(stderr, "lrecon: ") {
		t.Fatalf("stderr = %q, want the prefixed refusal line", stderr)
	}
	op, msg, kind := opEnvelope(t, stdout)
	if op != "comment" {
		t.Fatalf("op = %q, want comment; envelope: %s", op, stdout)
	}
	if kind != "io" {
		t.Fatalf("kind = %q, want io; envelope: %s", kind, stdout)
	}
	if !strings.Contains(msg, "no such file") || strings.Contains(msg, "job needs") {
		t.Fatalf("envelope does not name the missing target: %s", stdout)
	}
}

// An absent analyzeHeadless is a missing engine, not a missing argument. The
// shared route-M message offers "set LRECON_GHIDRA / ...", which classify()
// reads as needs_arg, so a caller went looking for a flag instead of Ghidra.
func TestOpCommentAbsentEngineIsNoEngine(t *testing.T) {
	// Deterministic absence: both env overrides are authoritative and do not
	// fall back to PATH or GHIDRA_INSTALL_DIR.
	t.Setenv("LRECON_GHIDRA", "")
	t.Setenv("LRECON_ANALYZEHEADLESS", filepath.Join(t.TempDir(), "no-headless"))
	job := writeTemp(t, "comment-job.json", []byte(`{"file":"/bin/ls","address":"0x1400","text":"plate note"}`))
	stdout, stderr, code := runCLIAll(t, "--op", "comment", "--json", job)
	if code != 2 {
		t.Fatalf("exit %d, want 2; stdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	if !strings.HasPrefix(stderr, "lrecon: ") {
		t.Fatalf("stderr = %q, want the prefixed refusal line", stderr)
	}
	op, msg, kind := opEnvelope(t, stdout)
	if op != "comment" {
		t.Fatalf("op = %q, want comment; envelope: %s", op, stdout)
	}
	if kind != "no_engine" {
		t.Fatalf("kind = %q, want no_engine; envelope: %s", kind, stdout)
	}
	if !strings.Contains(msg, "analyzeHeadless not installed") || strings.Contains(msg, "set LRECON_") {
		t.Fatalf("envelope does not name the missing engine: %s", stdout)
	}
}

// readWebTargetText bounds an asar to maxAsarWebText and everything else to
// maxWebText, and both say when the body was cut. These are the bounds the op's
// budget rests on, so they are asserted rather than assumed.
func TestReadWebTargetTextBounds(t *testing.T) {
	asarAt := func(n int) []byte {
		b := make([]byte, n)
		le := func(off int, v uint32) {
			b[off], b[off+1], b[off+2], b[off+3] = byte(v), byte(v>>8), byte(v>>16), byte(v>>24)
		}
		le(0, 4) // asar pickle header
		le(12, 5)
		b[16] = '{'
		for i := 20; i < n; i++ {
			b[i] = 'a'
		}
		return b
	}
	cases := []struct {
		name          string
		data          []byte
		wantLen       int
		wantTruncated bool
	}{
		{"asar-window", asarAt(maxAsarWebText + 64), maxAsarWebText, true},
		{"asar-exact", asarAt(maxAsarWebText), maxAsarWebText, false},
		{"text-small", []byte("console.log(1)\n"), 15, false},
		{"text-full", append([]byte("/*x*/"), make([]byte, 1<<20)...), 1<<20 + 5, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := writeTemp(t, c.name, c.data)
			src, truncated, err := readWebTargetText(p)
			if err != nil {
				t.Fatalf("read:%v", err)
			}
			if len(src) != c.wantLen || truncated != c.wantTruncated {
				t.Fatalf("len/truncated = %d/%v, want %d/%v", len(src), truncated, c.wantLen, c.wantTruncated)
			}
		})
	}
	// The two refusals readWebText already owned stay byte-identical.
	if _, _, err := readWebTargetText(filepath.Join(t.TempDir(), "nope")); err == nil || !strings.Contains(err.Error(), "no such file") {
		t.Fatalf("missing path err = %v, want a no-such-file error", err)
	}
	if _, _, err := readWebTargetText(t.TempDir()); err == nil || !strings.Contains(err.Error(), "is a directory: pass one file") {
		t.Fatalf("directory err = %v, want the readWebText refusal", err)
	}
}

// The deadline refusal must still name the target shape, even though the stage
// is now read when the timer fires instead of before the body runs: an asar and
// a plain input carry different stage values, and the envelope is the only place
// a caller learns which one ran out of time.
func TestRunOpDeadlineNamesStageOnTimeout(t *testing.T) {
	asar := filepath.Join(t.TempDir(), "app.asar")
	buf := make([]byte, 64)
	buf[0], buf[12], buf[16] = 4, 5, '{'
	if err := os.WriteFile(asar, buf, 0o644); err != nil {
		t.Fatal(err)
	}
	text := writeTemp(t, "plain.js", []byte("console.log(1)\n"))
	for _, c := range []struct{ path, stage string }{{asar, "asar"}, {text, "input"}} {
		// 0 is the already-spent budget: a real timer cannot beat -race's
		// scheduler to a no-op body, and the stage name is the assertion.
		t.Setenv(opDeadlineEnv, "0s")
		refuseStage = ""
		_, err := runOpDeadline(c.path, func() (any, error) { return nil, nil })
		if !isOpTimeout(err) {
			t.Fatalf("%s: err = %v, want a timeout", c.path, err)
		}
		var te *opTimeoutError
		if !errors.As(err, &te) || te.stage != c.stage {
			t.Fatalf("%s: stage = %q, want %q", c.path, te.stage, c.stage)
		}
		if refuseStage != c.stage {
			t.Fatalf("%s: refuseStage = %q, want %q", c.path, refuseStage, c.stage)
		}
	}
}

// BenchmarkRunOpDeadline is the A/B probe for reading the stage lazily: the same
// benchmark on the pre-change tree (targetStage before the body) is what
// report.md compares against.
func BenchmarkRunOpDeadline(b *testing.B) {
	p := filepath.Join(b.TempDir(), "app.js")
	if err := os.WriteFile(p, []byte("console.log(1)\n"), 0o644); err != nil {
		b.Fatal(err)
	}
	body := func() (any, error) { return nil, nil }
	b.ResetTimer()
	for b.Loop() {
		if _, err := runOpDeadline(p, body); err != nil {
			b.Fatal(err)
		}
	}
}
