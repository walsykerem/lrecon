package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"testing"
)

// tur7TextDigest is decoded from the CLI's stdout, not from the Go digest type:
// the wire shape is what a consumer sees, and these are the fields the sweep
// claims about.
type tur7TextDigest struct {
	ContractVersion int             `json:"contract_version"`
	Kind            string          `json:"kind"`
	Format          string          `json:"format"`
	Slices          int             `json:"slices"`
	BytesScanned    int64           `json:"bytes_scanned"`
	FileSize        int64           `json:"file_size"`
	Truncated       bool            `json:"truncated"`
	Error           string          `json:"error"`
	Skipped         json.RawMessage `json:"skipped"`
	Target          struct {
		Size       int64  `json:"size"`
		FileSHA256 string `json:"file_sha256"`
		HashScope  string `json:"hash_scope"`
		HashBytes  int64  `json:"hash_bytes"`
	} `json:"target"`
}

// TestTur7Bucket03GoSourceSweep points the real CLI at every .go file in this
// package tree, one process per file, and checks the identity contract on each
// answer: this tree is source text, so a text answer parses nothing (slices 0,
// bytes_scanned 0, no skips) while the identity must be the whole file (size
// and sha256 from the bytes on disk). The only other answer allowed is the phar
// reader's magic-free match on the stub terminator, and the test predicts it
// from the file's first 512 bytes, so a canned digest or a prefix hash breaks
// here.
func TestTur7Bucket03GoSourceSweep(t *testing.T) {
	root, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if buildErr != nil || cliPath == "" {
		t.Fatalf("cli binary was not built: err=%v log=%s", buildErr, buildLog)
	}

	// lrecon takes exactly one target; the sweep below is a loop of one-target
	// calls, and the refusal is the proof that it has to be.
	files := []string{filepath.Join(root, "go.mod"), filepath.Join(root, "main.go")}
	out, _, code := runCLIAll(t, "--json", files[0], files[1])
	if code != 2 {
		t.Fatalf("two targets: exit %d, want 2 (lrecon must refuse to split a call)\n%s", code, out)
	}
	var refusal struct {
		ContractVersion int    `json:"contract_version"`
		Kind            string `json:"kind"`
		Error           string `json:"error"`
	}
	if err := json.Unmarshal([]byte(out), &refusal); err != nil {
		t.Fatalf("two targets: answer is not one JSON envelope: %v\n%.300s", err, out)
	}
	if refusal.ContractVersion != 1 || refusal.Kind != "usage" {
		t.Fatalf("two targets: contract_version=%d kind=%q, want 1/usage", refusal.ContractVersion, refusal.Kind)
	}
	if !bytes.Contains([]byte(refusal.Error), []byte("targets given")) {
		t.Fatalf("two targets: error %q does not name the target count", refusal.Error)
	}

	var walked []string
	var nonTest, testFiles int
	err = filepath.WalkDir(root, func(p string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() || filepath.Ext(p) != ".go" {
			return nil
		}
		walked = append(walked, p)
		if len(p) > 8 && p[len(p)-8:] == "_test.go" {
			testFiles++
		} else {
			nonTest++
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	if nonTest < 330 || testFiles < 275 {
		t.Fatalf("walk found %d non-test and %d test .go files, want at least 330/275", nonTest, testFiles)
	}
	sort.Strings(walked)

	answers := make([]tur7Answer, len(walked))
	failures := make(chan string, len(walked))
	workers := min(runtime.NumCPU(), 8)
	var wg sync.WaitGroup
	next := make(chan int)
	for w := 0; w < workers; w++ {
		wg.Go(func() {
			for i := range next {
				p := walked[i]
				a, err := tur7ProbeOne(p)
				if err != nil {
					failures <- err.Error()
					continue
				}
				answers[i] = a
			}
		})
	}
	for i := range walked {
		next <- i
	}
	close(next)
	wg.Wait()
	close(failures)

	var problems []string
	for f := range failures {
		problems = append(problems, f)
	}
	sort.Strings(problems)
	if len(problems) > 0 {
		if len(problems) > 12 {
			problems = append(problems[:12], fmt.Sprintf("... and %d more", len(problems)-12))
		}
		t.Fatalf("%d of %d files answered outside the identity contract:\n%s", len(problems), len(walked), joinLines(problems))
	}
	if len(answers) != len(walked) {
		t.Fatalf("%d answers for %d files: lrecon skipped a file", len(answers), len(walked))
	}

	// One digest per distinct byte sequence: two files with the same sha256 are
	// either identical content or a hash that never looked at the content.
	seen := make(map[string]string, len(answers))
	for _, a := range answers {
		if a.sum == "" {
			t.Fatalf("%s: empty file_sha256", a.path)
		}
		if other, dup := seen[a.sum]; dup {
			t.Fatalf("%s and %s share sha256 %s", other, a.path, a.sum)
		}
		seen[a.sum] = a.path
	}
	if len(seen) != len(answers) {
		t.Fatalf("%d distinct digests for %d files", len(seen), len(answers))
	}
	phars := 0
	for _, a := range answers {
		if a.phar {
			phars++
		}
	}
	t.Logf("swept %d .go files (%d non-test, %d test): %d text, %d phar-stub, %d distinct sha256", len(walked), nonTest, testFiles, len(answers)-phars, phars, len(seen))
}

// tur7ProbeOne runs the real binary on one file and checks the envelope. The
// file is read here as well, so the digest is compared against the bytes, not
// against itself.
type tur7Answer struct {
	path string
	sum  string
	size int64
	phar bool
}

func tur7ProbeOne(path string) (tur7Answer, error) {
	var last error
	// A sibling test may still be writing its own new file; one retry keeps the
	// sweep honest without accepting a stale answer.
	for range 2 {
		data, err := os.ReadFile(path)
		if err != nil {
			last = fmt.Errorf("%s: read: %v", path, err)
			continue
		}
		info, err := os.Stat(path)
		if err != nil {
			last = fmt.Errorf("%s: stat: %v", path, err)
			continue
		}
		cmd := exec.Command(cliPath, "--json", path)
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		runErr := cmd.Run()
		code := 0
		if runErr != nil {
			if exitErr, ok := runErr.(*exec.ExitError); ok {
				code = exitErr.ExitCode()
			} else {
				last = fmt.Errorf("%s: run: %v", path, runErr)
				continue
			}
		}
		if code != 0 {
			last = fmt.Errorf("%s: exit %d\nstderr: %s", path, code, stderr.String())
			continue
		}
		var d tur7TextDigest
		if err := json.Unmarshal(stdout.Bytes(), &d); err != nil {
			last = fmt.Errorf("%s: exit %d, not one JSON envelope: %v\n%.200s", path, code, err, stdout.String())
			continue
		}
		sum := sha256.Sum256(data)
		want := hex.EncodeToString(sum[:])
		size := int64(len(data))
		// The phar reader has no magic: it matches the stub terminator in the
		// first 512 bytes, and php.go / its own byteflip test carry that literal
		// in Go source (op_evergreen07_byteflip_test.go:5 records the same
		// classification). Predict the answer from the bytes rather than the name.
		wantPhar := bytes.Contains(clip512(data), []byte("__HALT_COMPILER();"))
		// A size or hash disagreement may mean a sibling test rewrote the file
		// between our read and the probe, so that case gets the one retry above;
		// everything else is a verdict about the answer itself.
		switch {
		case d.ContractVersion != 1:
			return tur7Answer{}, fmt.Errorf("%s: contract_version %d", path, d.ContractVersion)
		case d.Error != "":
			return tur7Answer{}, fmt.Errorf("%s: error field %q on a readable source file", path, d.Error)
		case d.Slices != 0:
			return tur7Answer{}, fmt.Errorf("%s: slices %d, want 0 (source text has no container slices)", path, d.Slices)
		case d.FileSize != size || d.Target.Size != size || info.Size() != size:
			last = fmt.Errorf("%s: file_size %d, target.size %d, stat %d, real %d", path, d.FileSize, d.Target.Size, info.Size(), size)
		case d.Target.FileSHA256 != want:
			last = fmt.Errorf("%s: file_sha256 %s, want %s", path, d.Target.FileSHA256, want)
		case d.Target.HashScope != "whole-file" || d.Target.HashBytes != size:
			return tur7Answer{}, fmt.Errorf("%s: hash_scope %q hash_bytes %d, want whole-file/%d", path, d.Target.HashScope, d.Target.HashBytes, size)
		case d.Truncated:
			return tur7Answer{}, fmt.Errorf("%s: truncated on a %d-byte source file", path, size)
		case stderr.Len() != 0:
			return tur7Answer{}, fmt.Errorf("%s: stderr on a clean probe: %q", path, stderr.String())
		case !wantPhar && d.Kind != "text":
			return tur7Answer{}, fmt.Errorf("%s: kind %q, want text (no phar stub in the head)", path, d.Kind)
		case !wantPhar && d.BytesScanned != 0:
			return tur7Answer{}, fmt.Errorf("%s: bytes_scanned %d, want 0 (a text probe must not parse its own source)", path, d.BytesScanned)
		case !wantPhar && string(d.Skipped) != "null":
			return tur7Answer{}, fmt.Errorf("%s: text answer carries skipped=%s", path, d.Skipped)
		case wantPhar && d.Kind != "phar":
			return tur7Answer{}, fmt.Errorf("%s: kind %q, want phar (head carries the stub terminator)", path, d.Kind)
		case wantPhar && (d.BytesScanned <= 0 || d.BytesScanned > size):
			return tur7Answer{}, fmt.Errorf("%s: bytes_scanned %d, want 1..%d of an inspected phar", path, d.BytesScanned, size)
		case wantPhar && !bytes.Contains(d.Skipped, []byte(`"phar-manifest-invalid"`)):
			return tur7Answer{}, fmt.Errorf("%s: phar claim without a manifest skip: skipped=%s", path, d.Skipped)
		default:
			return tur7Answer{path: path, sum: want, size: size, phar: wantPhar}, nil
		}
	}
	return tur7Answer{}, last
}

func joinLines(lines []string) string {
	var b bytes.Buffer
	for _, l := range lines {
		b.WriteString(l)
		b.WriteByte('\n')
	}
	return b.String()
}

// clip512 keeps the window the tool's head capture sees (detect.go:75).
func clip512(b []byte) []byte {
	if len(b) > 512 {
		return b[:512]
	}
	return b
}
