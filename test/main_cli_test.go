package main

import (
	"flag"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// captureStdout runs fn with os.Stdout redirected, returning what it printed.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	defer func() { os.Stdout = old }()
	fn()
	w.Close()
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// captureStderr is captureStdout for the warning channel.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = w
	defer func() { os.Stderr = old }()
	fn()
	w.Close()
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// The inventory rows are the whole text output of --list-ops/--list-ext-ops, so
// both shapes must carry the same name/route/needs/desc.
func TestMainCLI(t *testing.T) {
	t.Run("listRows", func(t *testing.T) {
		table := map[string]op{"a": {name: "a", route: "L", desc: "first", needs: true}}
		rows := listRows([]string{"a"}, table)
		if len(rows) != 1 || rows[0].Name != "a" || rows[0].Route != "L" || rows[0].Desc != "first" {
			t.Fatalf("listRows = %+v", rows)
		}
		if got, _ := rows[0].Needs.([]string); len(got) != 1 || got[0] != "target" {
			t.Fatalf("needs = %#v, want [target]", rows[0].Needs)
		}
	})
	t.Run("listExtRows", func(t *testing.T) {
		table := map[string]extOp{"x": {name: "x", route: "Y", desc: "ext"}}
		rows := listExtRows([]string{"x"}, table)
		if len(rows) != 1 || rows[0].Name != "x" || rows[0].Route != "Y" || rows[0].Desc != "ext" {
			t.Fatalf("listExtRows = %+v", rows)
		}
	})
	t.Run("printListRows text", func(t *testing.T) {
		out := captureStdout(t, func() {
			printListRows([]listRow{{Name: "a"}, {Name: "b"}}, false)
		})
		if out != "a\nb\n" {
			t.Fatalf("text rows = %q", out)
		}
	})
	t.Run("printListRows json", func(t *testing.T) {
		out := captureStdout(t, func() {
			printListRows([]listRow{{Name: "a"}}, true)
		})
		if !strings.Contains(out, `"name": "a"`) {
			t.Fatalf("json rows = %q", out)
		}
	})

	t.Run("printExtRows text", func(t *testing.T) {
		rows := []listRow{{Name: "a", Route: "Y", Needs: true, Desc: "da"}, {Name: "b", Route: "G", Needs: false, Desc: "db"}}
		out := captureStdout(t, func() {
			printExtRows(rows, false, false)
		})
		if out != "a\nb\n" {
			t.Fatalf("ext text rows = %q", out)
		}
		out = captureStdout(t, func() {
			printExtRows(rows, false, true)
		})
		if out != "a\tY\ttrue\tda\nb\tG\tfalse\tdb\n" {
			t.Fatalf("ext full rows = %q", out)
		}
	})

	for _, c := range []struct {
		in   string
		want bool
	}{
		{"0", true}, {"42", true}, {"0x10", true}, {"0Xff", true},
		{"", false}, {"-1", false}, {"1f", false}, {"abc", false},
	} {
		if got := isByteCount(c.in); got != c.want {
			t.Errorf("isByteCount(%q) = %v, want %v", c.in, got, c.want)
		}
	}
	for _, c := range []struct {
		in   string
		want bool
	}{
		{"https://example.com", true}, {"www.example.com", true}, {"ssh://host", true},
		{"example.com", false}, {"://x", false}, {"/tmp/a://b", false}, {"x-y://z", true},
	} {
		if got := looksLikeWebsite(c.in); got != c.want {
			t.Errorf("looksLikeWebsite(%q) = %v, want %v", c.in, got, c.want)
		}
	}
	for _, c := range []struct {
		in   string
		want bool
	}{
		{"pid:1", true}, {"pid=1", true}, {"pid", false}, {"xpid:1", false},
	} {
		if got := looksLikePID(c.in); got != c.want {
			t.Errorf("looksLikePID(%q) = %v, want %v", c.in, got, c.want)
		}
	}
	for _, c := range []struct {
		in   string
		want bool
	}{
		{"nosuchprocessname", true}, {"", false}, {"dir/name", false}, {"name.txt", false},
	} {
		if got := looksLikeProcessName(c.in); got != c.want {
			t.Errorf("looksLikeProcessName(%q) = %v, want %v", c.in, got, c.want)
		}
	}
	// An existing path is a mistyped file, not a process name.
	existing := writeTemp(t, "exists.txt", []byte("x"))
	if looksLikeProcessName(existing) {
		t.Fatalf("existing path %q read as a process name", existing)
	}
}

// A directory -o gets one file per call and never overwrites; a file -o keeps a
// single destination.
func TestMainCLIWriteDigest(t *testing.T) {
	dir := t.TempDir()
	target := writeTemp(t, "my.target.txt", []byte("x"))
	for i := range 2 {
		if err := writeDigestFile(dir, target, "{}"); err != nil {
			t.Fatalf("call %d: %v", i+1, err)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, e := range entries {
		names[e.Name()] = true
	}
	if len(entries) != 2 || !names["my.target.json"] || !names["my.target-1.json"] {
		t.Fatalf("-o dir entries = %v", entries)
	}
	// A target with no base gets the fallback name instead of ".json".
	if err := writeDigestFile(dir, ".", "{}"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "digest.json")); err != nil {
		t.Fatalf("fallback name missing: %v", err)
	}
	single := filepath.Join(t.TempDir(), "digest.json")
	if err := writeDigestFile(single, target, `{"kind":"text"}`); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(single); err != nil || string(b) != `{"kind":"text"}` {
		t.Fatalf("single file = %q, %v", b, err)
	}
}

// --max-bytes is a text budget: it earns a warning only when the caller gave it
// and the machine answer is larger.
func TestMainCLIMaxBytesNote(t *testing.T) {
	fs := flag.NewFlagSet("lrecon", flag.ContinueOnError)
	fs.Int("max-bytes", 4096, "")
	if err := fs.Parse([]string{"--max-bytes", "10"}); err != nil {
		t.Fatal(err)
	}
	if out := captureStderr(t, func() { maxBytesNote(fs, 10, 20, "--op") }); !strings.Contains(out, "--max-bytes 10 does not apply to --op") {
		t.Fatalf("explicit note = %q", out)
	}
	if out := captureStderr(t, func() { maxBytesNote(fs, 10, 5, "--op") }); out != "" {
		t.Fatalf("fits but warned: %q", out)
	}
	bare := flag.NewFlagSet("lrecon", flag.ContinueOnError)
	bare.Int("max-bytes", 4096, "")
	if out := captureStderr(t, func() { maxBytesNote(bare, 10, 20, "--op") }); out != "" {
		t.Fatalf("default budget warned: %q", out)
	}
}

// The budget either holds the evidence line or goes to the body; it must never
// answer with a note over an empty body.
func TestMainCLIDigestTextOrBody(t *testing.T) {
	d := Digest{Kind: "text"}
	for _, limit := range []int{0, 1 << 20, 10} {
		if got := digestTextOrBody(d, limit); strings.Contains(got, "note: truncated at 0 of 0 bytes") {
			t.Fatalf("limit %d answered with a truncated empty body: %q", limit, got)
		}
	}
}

// The deadline refusal is written by the op goroutine and by the timer path at
// the same time; under -race this is the test that says the stage is protected.
// A4: progress is opt-in and advertised, and a short op with it on stays
// silent, so a caller can turn it on for the 30s Ghidra ops without every fast
// op writing to stderr.
func TestProgressFlag(t *testing.T) {
	stdout, stderr, code := runCLIAll(t, "--help", "--all")
	if code != 0 {
		t.Fatalf("--help --all exit %d, want 0", code)
	}
	if !strings.Contains(stdout+stderr, "-progress") {
		t.Fatalf("--help --all does not advertise -progress:\n%s%s", stdout, stderr)
	}
	target := writeTemp(t, "fast.txt", []byte(strings.Repeat("hello lrecon\n", 1000)))
	_, stderr, code = runCLIAll(t, target, "--op", "inspect_byte_entropy", "--json", "--progress")
	if code != 0 {
		t.Fatalf("exit %d, want 0", code)
	}
	if stderr != "" {
		t.Fatalf("a fast op wrote stderr with --progress: %q", stderr)
	}
}

func TestRefuseStage(t *testing.T) {
	t.Setenv(opDeadlineEnv, "1ms")
	stop := make(chan struct{})
	var body sync.WaitGroup
	body.Add(1)
	_, err := runOpDeadline(filepath.Join(t.TempDir(), "missing.bin"), func() (any, error) {
		defer body.Done()
		for {
			select {
			case <-stop:
				return nil, nil
			default:
				setRefuseStage("body")
			}
		}
	})
	if !isOpTimeout(err) {
		t.Fatalf("err = %v, want a timeout", err)
	}
	if got := takeRefuseStage(); got == "" {
		t.Fatal("timeout refusal left no stage")
	}
	close(stop)
	body.Wait()
}
