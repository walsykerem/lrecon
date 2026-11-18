package main

// Evergreen 01: a nonce the tool has never seen must come back from the bytes
// of the file it was written into, at the byte offset where it was written, and
// must not come back from a file that does not contain it. A wrapper that
// answers from documentation, or from the query string alone, cannot produce
// the real offset and the real surrounding bytes.

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// evergreen01Nonce returns "CANARY-" plus 16 hex characters. crypto/rand is
// the point (the tool cannot know it in advance); the fixed fallback keeps the
// test runnable on a host where the entropy source fails.
func evergreen01Nonce(t *testing.T) string {
	t.Helper()
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Logf("crypto/rand unavailable (%v); using fixed fallback nonce", err)
		return "CANARY-5f3a9c1d7e2b4068"
	}
	return "CANARY-" + hex.EncodeToString(b[:])
}

type evergreen01Hit struct {
	Offset  int64  `json:"offset"`
	Hex     string `json:"hex"`
	Context string `json:"context"`
}

type evergreen01Result struct {
	File   string           `json:"file"`
	String string           `json:"string"`
	Count  int              `json:"count"`
	Hits   []evergreen01Hit `json:"hits"`
}

type evergreen01Envelope struct {
	Op     string            `json:"op"`
	Result evergreen01Result `json:"result"`
	Error  string            `json:"error,omitempty"`
}

// evergreen01Trace runs one trace_feature string query against one file and
// returns the parsed envelope plus the raw stdout.
func evergreen01Trace(t *testing.T, dir, jobName, target, needle string) (evergreen01Envelope, string) {
	t.Helper()
	if cliPath == "" {
		t.Fatalf("no lrecon binary was built: %v %s", buildErr, buildLog)
	}
	jobPath := filepath.Join(dir, jobName+".job.json")
	job, err := json.Marshal(map[string]string{"file": target, "string": needle})
	if err != nil {
		t.Fatalf("marshal job: %v", err)
	}
	if err := os.WriteFile(jobPath, job, 0o644); err != nil {
		t.Fatalf("write job %s: %v", jobPath, err)
	}
	cmd := exec.Command(cliPath, jobPath, "--op", "trace_feature", "--json")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("lrecon trace_feature %s: %v\nstdout: %s\nstderr: %s", target, err, stdout.String(), stderr.String())
	}
	var env evergreen01Envelope
	if err := json.Unmarshal(stdout.Bytes(), &env); err != nil {
		t.Fatalf("decode %s output: %v\nraw: %s", target, err, stdout.String())
	}
	if env.Error != "" {
		t.Fatalf("lrecon reported %q for %s", env.Error, target)
	}
	return env, stdout.String()
}

func TestEvergreen01NonceCanary(t *testing.T) {
	// A representative slice: CLI entry, native format parsing, format
	// detection, the op registry, analysis reasons and skeleton analysis.
	realFiles := []string{
		"main.go",
		"native.go",
		"detect.go",
		"ops.go",
		"reasons.go",
		"skeleton.go",
	}
	nonce := evergreen01Nonce(t)
	dir := t.TempDir()

	type injected struct {
		path string
		want int64
	}
	var samples []injected
	var cleanBytes []byte

	for _, name := range realFiles {
		b, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read corpus file %s: %v", name, err)
		}
		if len(cleanBytes) == 0 {
			cleanBytes = append([]byte(nil), b...)
		}
		// Insert the nonce comment after the first line so the hit has bytes
		// on both sides; that makes the context window a real check.
		nl := bytes.IndexByte(b, '\n')
		if nl < 0 {
			t.Fatalf("%s has no newline", name)
		}
		at := nl + 1
		mutated := make([]byte, 0, len(b)+len(nonce)+8)
		mutated = append(mutated, b[:at]...)
		mutated = append(mutated, []byte("\n// "+nonce+"\n")...)
		mutated = append(mutated, b[at:]...)
		want := int64(bytes.Index(mutated, []byte(nonce)))
		if want < 0 {
			t.Fatalf("%s: injected nonce not found in the bytes written", name)
		}
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, mutated, 0o644); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
		samples = append(samples, injected{path: path, want: want})
	}

	for i, s := range samples {
		env, raw := evergreen01Trace(t, dir, "hit"+hex.EncodeToString([]byte{byte(i)}), s.path, nonce)
		if env.Op != "trace_feature" {
			t.Fatalf("%s: op = %q, want trace_feature", s.path, env.Op)
		}
		if env.Result.File != s.path {
			t.Fatalf("%s: answer is about %q, not the queried file", s.path, env.Result.File)
		}
		if !strings.Contains(raw, nonce) {
			t.Fatalf("%s: the nonce is missing from the output\n%s", s.path, raw)
		}
		if env.Result.Count < 1 || len(env.Result.Hits) < 1 {
			t.Fatalf("%s: nonce %s injected at offset %d but count=%d", s.path, nonce, s.want, env.Result.Count)
		}
		var matched bool
		for _, h := range env.Result.Hits {
			if h.Offset != s.want {
				continue
			}
			ctx, err := hex.DecodeString(h.Context)
			if err != nil {
				t.Fatalf("%s: hit context %q is not hex: %v", s.path, h.Context, err)
			}
			if !bytes.Contains(ctx, []byte(nonce)) {
				t.Fatalf("%s: context bytes at hit offset %d do not contain the nonce: %q", s.path, h.Offset, ctx)
			}
			matched = true
		}
		if !matched {
			t.Fatalf("%s: no hit at the injected byte offset %d (hits: %+v)", s.path, s.want, env.Result.Hits)
		}
	}

	// Same nonce, a file that does not contain it: zero hits, and the answer is
	// still about that file. Global leakage or a canned "found" answer fails here.
	cleanPath := filepath.Join(dir, "clean.go")
	if err := os.WriteFile(cleanPath, cleanBytes, 0o644); err != nil {
		t.Fatalf("write %s: %v", cleanPath, err)
	}
	if bytes.Contains(cleanBytes, []byte(nonce)) {
		t.Fatalf("clean copy unexpectedly contains the nonce")
	}
	env, raw := evergreen01Trace(t, dir, "clean", cleanPath, nonce)
	if env.Result.File != cleanPath {
		t.Fatalf("clean query answered about %q, not the queried file", env.Result.File)
	}
	if env.Result.Count != 0 || len(env.Result.Hits) != 0 {
		t.Fatalf("nonce %s leaked into a file that does not contain it: count=%d hits=%+v", nonce, env.Result.Count, env.Result.Hits)
	}
	if strings.Contains(raw, `"count":0`) == false {
		t.Fatalf("clean query did not report count 0: %s", raw)
	}
}
