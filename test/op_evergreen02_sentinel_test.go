package main

// Evergreen 02: the analyzer must read a file to its last byte, not just its head.
//
// A wrapper that samples the first N bytes (a head buffer, the first lines, or a
// prefix-scoped regex) still answers every "does this file contain X" question
// for X near the top. So each fixture here carries its evidence in the last line:
// a unique token plus an AWS-shaped canary, pushed past byte 8192 by trailing
// padding. Two whole-file readers are then asked about it through the real
// binary, one run per file:
//
//   scrub_output     - reports the offset of a secret-shaped run, so the answer
//                      is a byte position that only a full read can produce.
//   inspect_artifact - reports size and sha256 of the whole file, so the answer
//                      is a digest that changes if the tail is dropped.
//
// inspect_analysis_view's "raw" view prints the first 128 bytes only: a wrapper
// built on that view passes a head nonce and fails every check below. The
// negative direction is pinned too: no file's record may carry another file's
// token, digest or offset, so one cached or constant record cannot stand in for
// six files.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	e02HeadWindow = 8192 // bytes a head-only sampler may plausibly read
	e02TailWindow = 128  // the sentinel must sit inside the last 128 bytes
	e02Timeout    = 30 * time.Second
)

// e02Sources are real .go files in this package: stable names, all larger than
// the head window, and every one of them is a text target (kind "text").
var e02Sources = []string{
	"main.go", "dispatch.go", "errors.go", "bundle.go", "pcap.go", "wasm.go",
}

type e02ArtifactRecord struct {
	Op     string `json:"op"`
	Target string `json:"target"`
	Result struct {
		Kind   string `json:"kind"`
		Size   int64  `json:"size"`
		SHA256 string `json:"sha256"`
	} `json:"result"`
}

type e02ScrubRecord struct {
	Op     string `json:"op"`
	Target string `json:"target"`
	Result struct {
		Scrubbed int  `json:"scrubbed"`
		Clean    bool `json:"clean"`
		Findings []struct {
			Offset  int    `json:"offset"`
			Pattern string `json:"pattern"`
			Length  int    `json:"length"`
		} `json:"findings"`
	} `json:"result"`
}

// e02Env keeps the developer's shell out of the answer: no LRECON_/ADB_ input is
// inherited, so nothing but the command line decides a record.
func e02Env() []string {
	keep := map[string]bool{"PATH": true, "HOME": true, "TMPDIR": true, "LANG": true}
	env := make([]string, 0, len(keep))
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		if keep[k] {
			env = append(env, kv)
		}
	}
	return env
}

func e02Run(t *testing.T, bin, target, opName string, out any) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), e02Timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, target, "--op", opName, "--json")
	cmd.Env = e02Env()
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("%s %s %s: %v\nstderr: %s", filepath.Base(bin), filepath.Base(target), opName, err, stderr.String())
	}
	raw := stdout.String()
	if raw == "" {
		t.Fatalf("%s %s %s: empty stdout (stderr: %s)", filepath.Base(bin), filepath.Base(target), opName, stderr.String())
	}
	if err := json.Unmarshal([]byte(raw), out); err != nil {
		t.Fatalf("%s %s %s: not JSON: %v\n%s", filepath.Base(bin), filepath.Base(target), opName, err, raw)
	}
	return raw
}

// e02Fixture copies one real source file into dir, appends a deterministic
// padding block and then the sentinel as the final line, and returns the exact
// bytes written (read back from disk) plus the sentinel token and canary.
func e02Fixture(t *testing.T, dir string, i int, name string) (data []byte, token, canary string) {
	t.Helper()
	src, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("read source %s: %v", name, err)
	}
	// 16 uppercase letters make the canary match the AWS key shape the scrubber
	// reports; the token is unique per file and never repeats.
	canary = "AKIA" + strings.ToUpper(hex.EncodeToString(sha256Sum(fmt.Sprintf("e02-canary-%d", i))[:8]))
	token = fmt.Sprintf("EVERGREEN02-SENTINEL-%02d-%s", i,
		hex.EncodeToString(sha256Sum(fmt.Sprintf("e02-token-%d", i))[:6]))

	var buf bytes.Buffer
	buf.Write(src)
	if !bytes.HasSuffix(src, []byte("\n")) {
		buf.WriteByte('\n')
	}
	// Padding pushes the sentinel past any plausible head buffer; the sentinel
	// stays the last line so a tail read is the only way to reach it.
	// The count varies per file so two equal-sized sources still land their
	// sentinels on distinct offsets.
	for n := 0; n < 400+i*7; n++ {
		buf.WriteString("// evergreen02 padding line: the sentinel is not here\n")
	}
	buf.WriteString("// sentinel " + token + " " + canary + "\n")

	dest := filepath.Join(dir, fmt.Sprintf("fixture%02d_%s", i, filepath.Base(name)))
	if err := os.WriteFile(dest, buf.Bytes(), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	data, err = os.ReadFile(dest)
	if err != nil {
		t.Fatalf("read fixture back: %v", err)
	}
	return data, token, canary
}

func sha256Sum(s string) []byte {
	h := sha256.Sum256([]byte(s))
	return h[:]
}

func TestEvergreen02LastLineSentinel(t *testing.T) {
	bin, err := filepath.Abs("./lrecon")
	if err != nil {
		t.Fatalf("resolve binary: %v", err)
	}
	if st, err := os.Stat(bin); err != nil || st.Mode()&0o111 == 0 {
		t.Fatalf("real binary %s missing or not executable: %v", bin, err)
	}
	dir := t.TempDir()

	type fixture struct {
		path   string
		data   []byte
		token  string
		canary string
		offset int
		digest string
		raw    string // this file's own two output records, concatenated
	}
	files := make([]fixture, len(e02Sources))

	for i, name := range e02Sources {
		data, token, canary := e02Fixture(t, dir, i, name)
		off := bytes.LastIndex(data, []byte(canary))
		if off < 0 {
			t.Fatalf("%s: canary planted but not found in fixture", name)
		}
		if off <= e02HeadWindow {
			t.Fatalf("%s: sentinel at byte %d, must sit past the %d-byte head window", name, off, e02HeadWindow)
		}
		if tail := len(data) - off; tail > e02TailWindow {
			t.Fatalf("%s: sentinel %d bytes from EOF, must be within the last %d bytes", name, tail, e02TailWindow)
		}
		sum := sha256.Sum256(data)
		files[i] = fixture{
			path:   filepath.Join(dir, fmt.Sprintf("fixture%02d_%s", i, filepath.Base(name))),
			data:   data,
			token:  token,
			canary: canary,
			offset: off,
			digest: hex.EncodeToString(sum[:]),
		}
	}

	for i := range files {
		f := &files[i]

		var art e02ArtifactRecord
		artRaw := e02Run(t, bin, f.path, "inspect_artifact", &art)
		var scrub e02ScrubRecord
		scrubRaw := e02Run(t, bin, f.path, "scrub_output", &scrub)
		f.raw = artRaw + scanNewline + scrubRaw

		// inspect_artifact: the digest and size must cover the whole file, so a
		// head-capped read produces a different digest and a smaller size.
		if art.Result.Size != int64(len(f.data)) {
			t.Errorf("%s: inspect_artifact size %d, want whole file %d", filepath.Base(f.path), art.Result.Size, len(f.data))
		}
		if art.Result.SHA256 != f.digest {
			t.Errorf("%s: inspect_artifact sha256 %q, want whole-file digest %q (a head-only read cannot match)",
				filepath.Base(f.path), art.Result.SHA256, f.digest)
		}
		if art.Op != "inspect_artifact" {
			t.Errorf("%s: record op %q, want inspect_artifact", filepath.Base(f.path), art.Op)
		}

		// scrub_output: the reported offset is the planted canary's byte position,
		// which only a scanner that reached the tail can name.
		found := false
		for _, fi := range scrub.Result.Findings {
			if fi.Pattern != "aws-akia" {
				continue
			}
			found = true
			if fi.Offset != f.offset {
				t.Errorf("%s: aws-akia offset %d, want %d (the tail sentinel)", filepath.Base(f.path), fi.Offset, f.offset)
			}
			if fi.Length != len(f.canary) {
				t.Errorf("%s: aws-akia length %d, want %d", filepath.Base(f.path), fi.Length, len(f.canary))
			}
		}
		if !found {
			t.Errorf("%s: scrub_output reported no aws-akia finding; the tail sentinel at byte %d was not read (findings: %+v)",
				filepath.Base(f.path), f.offset, scrub.Result.Findings)
		}
		if scrub.Result.Clean {
			t.Errorf("%s: scrub_output says clean while a canary sits at byte %d", filepath.Base(f.path), f.offset)
		}
		if scrub.Op != "scrub_output" {
			t.Errorf("%s: record op %q, want scrub_output", filepath.Base(f.path), scrub.Op)
		}

		// The token is in the file's own bytes and therefore in what it represents;
		// a record that never saw the tail cannot carry its offset or digest.
		if !bytes.Contains(f.data, []byte(f.token)) {
			t.Errorf("%s: token missing from own fixture bytes", filepath.Base(f.path))
		}
	}

	// Negative direction: six distinct files must yield six distinct records. No
	// file's record may carry another file's token, digest or offset, so one
	// cached, constant or first-file-only answer fails here.
	for i := range files {
		for j := range files {
			if i == j {
				continue
			}
			if strings.Contains(files[i].raw, files[j].token) {
				t.Errorf("%s: record carries %s's sentinel token %q", filepath.Base(files[i].path), filepath.Base(files[j].path), files[j].token)
			}
			if strings.Contains(files[i].raw, files[j].digest) {
				t.Errorf("%s: record carries %s's whole-file digest", filepath.Base(files[i].path), filepath.Base(files[j].path))
			}
			if files[i].digest == files[j].digest {
				t.Errorf("%s and %s: identical digests, one record is standing in for two files",
					filepath.Base(files[i].path), filepath.Base(files[j].path))
			}
			if files[i].offset == files[j].offset {
				t.Errorf("%s and %s: identical sentinel offset %d, one answer is reused",
					filepath.Base(files[i].path), filepath.Base(files[j].path), files[i].offset)
			}
		}
	}
}

// scanNewline joins the two records of one file so a cross-file check cannot be
// satisfied by a token that leaks through either document.
const scanNewline = "\n"
