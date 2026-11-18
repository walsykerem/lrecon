package main

// A per-file record must be a pure function of that file's bytes. If a shared
// accumulator or a cache keyed on position leaked between reads, the same file
// would answer differently depending on what was read before it. This drives
// the real binary over a fixed sample in sorted and shuffled order, then edits
// one copy and checks only its record moved.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// Real files from this repo, fixed so the sample cannot drift with the tree.
var evergreen15Sample = []string{
	"main.go", "detect.go", "digest_contract.go", "native.go",
	"bundle.go", "managed.go", "formats.go", "extract.go",
}

func evergreen15Record(t *testing.T, bin, path string) string {
	t.Helper()
	out, err := exec.Command(bin, path, "--json").Output()
	if err != nil {
		t.Fatalf("%s %s: %v", bin, path, err)
	}
	sum := sha256.Sum256(out)
	return hex.EncodeToString(sum[:])
}

func evergreen15Shuffle(t *testing.T, files []string, seed int64) []string {
	t.Helper()
	cp := append([]string(nil), files...)
	rand.New(rand.NewSource(seed)).Shuffle(len(cp), func(i, j int) { cp[i], cp[j] = cp[j], cp[i] })
	return cp
}

func TestEvergreen15ShuffleOrderStable(t *testing.T) {
	bin, err := filepath.Abs("lrecon")
	if err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(bin); err != nil || st.Mode()&0o111 == 0 {
		t.Fatalf("real lrecon binary is missing or not executable at %s (err=%v)", bin, err)
	}

	dir := t.TempDir()
	var files []string
	for _, name := range evergreen15Sample {
		b, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("sample file %s: %v", name, err)
		}
		dst := filepath.Join(dir, name)
		if err := os.WriteFile(dst, b, 0o644); err != nil {
			t.Fatal(err)
		}
		files = append(files, dst)
	}

	sorted := map[string]string{}
	for _, f := range files {
		sorted[filepath.Base(f)] = evergreen15Record(t, bin, f)
	}

	shuffled := map[string]string{}
	order := evergreen15Shuffle(t, files, 15)
	if filepath.Base(order[0]) == filepath.Base(files[0]) && filepath.Base(order[1]) == filepath.Base(files[1]) {
		t.Fatalf("fixed seed produced no shuffle: %v", order)
	}
	for _, f := range order {
		shuffled[filepath.Base(f)] = evergreen15Record(t, bin, f)
	}
	for name, want := range sorted {
		if got := shuffled[name]; got != want {
			t.Fatalf("%s record depends on read order: sorted sha256 %s, shuffled sha256 %s", name, want, got)
		}
	}

	// In-process Probe over the same set in a third order: a package-level
	// cache or accumulator would show up here, where one process reads all
	// files, not in the separate CLI invocations above.
	probed := func(order []string) map[string]string {
		m := map[string]string{}
		for _, f := range order {
			d, err := Probe(f)
			if err != nil {
				t.Fatalf("Probe %s: %v", f, err)
			}
			b, err := json.Marshal(d)
			if err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(b)
			m[filepath.Base(f)] = hex.EncodeToString(sum[:])
		}
		return m
	}
	inSorted := probed(files)
	inShuffled := probed(evergreen15Shuffle(t, files, 1501))
	for name, want := range inSorted {
		if got := inShuffled[name]; got != want {
			t.Fatalf("%s Probe record depends on read order: %s vs %s", name, want, got)
		}
	}

	// One changed input may only move its own record.
	mutated := filepath.Join(dir, "native.go")
	f, err := os.OpenFile(mutated, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("\n// order-probe mutation\n"); err != nil {
		f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	after := map[string]string{}
	for _, f := range evergreen15Shuffle(t, files, 77) {
		after[filepath.Base(f)] = evergreen15Record(t, bin, f)
	}
	if after["native.go"] == sorted["native.go"] {
		t.Fatal("appending bytes left native.go's record unchanged: the record is not derived from file content")
	}
	for name, want := range sorted {
		if name == "native.go" {
			continue
		}
		if got := after[name]; got != want {
			t.Fatalf("mutation of native.go changed the unrelated record %s: %s -> %s", name, want, got)
		}
	}
}
