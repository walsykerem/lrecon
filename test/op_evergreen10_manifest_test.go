package main

// Evergreen 10: gapless per-file accounting over a real slice of the corpus.
// The test owns the manifest (sidecar): it picks the sample deterministically
// by sorted path, hashes each file itself, then checks that the tool's own
// per-file record names that exact argv path and reports the same digest, and
// that package/input/record counts stay 1:1 with no duplicate or missing row.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

const (
	eg10Root       = "/Users/keremurhan/walsyrea"
	eg10SampleSize = 10
)

type eg10Entry struct {
	Path   string   `json:"path"`
	Size   int64    `json:"size"`
	SHA256 string   `json:"sha256"`
	Argv   []string `json:"argv"`
}

type eg10Record struct {
	Op     string `json:"op"`
	Target string `json:"target"`
	Result struct {
		Document string `json:"document"`
		Kind     string `json:"kind"`
		Size     int64  `json:"size"`
		SHA256   string `json:"sha256"`
	} `json:"result"`
	Error string `json:"error"`
}

// eg10Sample walks the corpus once, keeps Go sources (test files are excluded:
// other agents add those concurrently), sorts by path, and takes the first
// distinct-by-content files so every ledger key is unique.
func eg10Sample(t *testing.T) []string {
	t.Helper()
	var all []string
	err := filepath.WalkDir(eg10Root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // an unreadable subtree cannot host a sample file
		}
		if d.IsDir() {
			name := d.Name()
			if p != eg10Root && (strings.HasPrefix(name, ".") || name == "node_modules" || name == "vendor") {
				return fs.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(p, ".go") && !strings.HasSuffix(p, "_test.go") {
			all = append(all, p)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", eg10Root, err)
	}
	sort.Strings(all)

	var paths []string
	digests := map[string]bool{}
	for _, p := range all {
		b, err := os.ReadFile(p)
		if err != nil || len(b) == 0 {
			continue
		}
		sum := sha256.Sum256(b)
		d := hex.EncodeToString(sum[:])
		if digests[d] {
			continue
		}
		digests[d] = true
		paths = append(paths, p)
		if len(paths) == eg10SampleSize {
			break
		}
	}
	if len(paths) < 8 {
		t.Fatalf("only %d distinct Go sources under %s, need at least 8", len(paths), eg10Root)
	}
	return paths
}

func TestEvergreen10PerFileManifest(t *testing.T) {
	if buildErr != nil {
		t.Fatalf("go build failed: %v\n%s", buildErr, buildLog)
	}
	if cliPath == "" {
		t.Fatal("cli binary was not built")
	}

	dir := t.TempDir()
	sample := eg10Sample(t)

	// The test's own manifest: digests come from the test's crypto/sha256, not
	// from the tool; argv is what the tool will actually be handed.
	want := make([]eg10Entry, 0, len(sample))
	for _, p := range sample {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("read %s: %v", p, err)
		}
		sum := sha256.Sum256(b)
		want = append(want, eg10Entry{
			Path:   p,
			Size:   int64(len(b)),
			SHA256: hex.EncodeToString(sum[:]),
			Argv:   []string{"--op", "inspect_artifact", "--json", p},
		})
	}
	sidecar := filepath.Join(dir, "input-manifest.json")
	raw, err := json.MarshalIndent(want, "", "  ")
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	if err := os.WriteFile(sidecar, raw, 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}

	// Reload it: the ledger under test is the persisted manifest, so a lost or
	// doubled entry here would be a real gap, not a slice artefact.
	var inputs []eg10Entry
	{
		b, err := os.ReadFile(sidecar)
		if err != nil {
			t.Fatalf("read back manifest: %v", err)
		}
		if err := json.Unmarshal(b, &inputs); err != nil {
			t.Fatalf("manifest is not JSON: %v", err)
		}
	}
	if len(inputs) != len(sample) {
		t.Fatalf("manifest has %d rows, sample has %d", len(inputs), len(sample))
	}
	byPath := make(map[string]eg10Entry, len(inputs))
	for _, e := range inputs {
		if _, dup := byPath[e.Path]; dup {
			t.Fatalf("manifest duplicates %s", e.Path)
		}
		if e.Argv[len(e.Argv)-1] != e.Path {
			t.Fatalf("manifest argv %v does not end in %s", e.Argv, e.Path)
		}
		byPath[e.Path] = e
	}

	var ledger []eg10Entry
	countByPath := map[string]int{}
	countByDigest := map[string]int{}
	for _, in := range inputs {
		cmd := exec.Command(cliPath, in.Argv...)
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		err := cmd.Run()
		code := 0
		if err != nil {
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) {
				t.Fatalf("run %v: %v", in.Argv, err)
			}
			code = exitErr.ExitCode()
		}
		if code != 0 {
			t.Fatalf("%v: exit %d, stderr:\n%s", in.Argv, code, stderr.String())
		}
		var rec eg10Record
		if err := json.Unmarshal(stdout.Bytes(), &rec); err != nil {
			t.Fatalf("%v: stdout is not one JSON record: %v\n%s", in.Argv, err, stdout.String())
		}
		if rec.Op != "inspect_artifact" {
			t.Errorf("%s: op = %q, want inspect_artifact (record: %+v)", in.Path, rec.Op, rec)
		}
		// The argv value the tool received must be the exact path; the tool
		// echoes it back as both target and document.
		if rec.Target != in.Path {
			t.Errorf("%s: tool target = %q, argv did not carry that path", in.Path, rec.Target)
		}
		if rec.Result.Document != in.Path {
			t.Errorf("%s: tool document = %q", in.Path, rec.Result.Document)
		}
		if rec.Result.Kind != "text" {
			t.Errorf("%s: kind = %q, want text for Go source", in.Path, rec.Result.Kind)
		}
		if rec.Result.Size != in.Size {
			t.Errorf("%s: tool size = %d, test size = %d", in.Path, rec.Result.Size, in.Size)
		}
		if rec.Result.SHA256 != in.SHA256 {
			t.Errorf("%s: tool sha256 = %q, test sha256 = %q", in.Path, rec.Result.SHA256, in.SHA256)
		}
		countByPath[rec.Target]++
		countByDigest[rec.Result.SHA256]++
		ledger = append(ledger, eg10Entry{
			Path:   rec.Target,
			Size:   rec.Result.Size,
			SHA256: rec.Result.SHA256,
		})
	}

	if len(ledger) != len(inputs) {
		t.Fatalf("ledger has %d rows for %d inputs", len(ledger), len(inputs))
	}
	for p, n := range countByPath {
		if n != 1 {
			t.Fatalf("%s produced %d output records, want exactly 1", p, n)
		}
		if _, ok := byPath[p]; !ok {
			t.Fatalf("%s is an output record with no input row", p)
		}
	}
	for p := range byPath {
		if countByPath[p] == 0 {
			t.Fatalf("input %s produced no output record (gap)", p)
		}
	}
	for d, n := range countByDigest {
		if n != 1 {
			t.Fatalf("digest %s reported %d times: duplicate or collided records", d, n)
		}
	}

	// Persisted observed ledger, counted the same way: rows == inputs, unique
	// paths, unique digests.
	observed := filepath.Join(dir, "observed-ledger.json")
	oraw, err := json.MarshalIndent(ledger, "", "  ")
	if err != nil {
		t.Fatalf("marshal ledger: %v", err)
	}
	if err := os.WriteFile(observed, oraw, 0o600); err != nil {
		t.Fatalf("write ledger: %v", err)
	}
	var back []eg10Entry
	{
		b, err := os.ReadFile(observed)
		if err != nil {
			t.Fatalf("read back ledger: %v", err)
		}
		if err := json.Unmarshal(b, &back); err != nil {
			t.Fatalf("ledger is not JSON: %v", err)
		}
	}
	if len(back) != len(inputs) {
		t.Fatalf("persisted ledger has %d rows, inputs %d", len(back), len(inputs))
	}
	seen := map[string]bool{}
	for _, e := range back {
		if seen[e.Path] {
			t.Fatalf("persisted ledger duplicates %s", e.Path)
		}
		seen[e.Path] = true
		want := byPath[e.Path]
		if e.SHA256 != want.SHA256 || e.Size != want.Size {
			t.Fatalf("persisted row %s drifted from the manifest", e.Path)
		}
	}
}
