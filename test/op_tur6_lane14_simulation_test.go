package main

// Tur 6 lane 14: probe. Reads the walsyrea skill text directly and detects
// platform-specific traps (per-arch/tool gotchas) and false-positive controls
// (decoys, "not a layer", exit-code checks). Finding is logged only; the test
// stays green regardless of outcome.

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

type tur6Lane14Finding struct {
	platformTrapLine  int
	falsePositiveLine int
}

// platform trap signals: a tool/arch gotcha that silently yields a wrong result.
var tur6Lane14PlatformTrapPhrases = []string{
	"silently misses",
	"different slice per tool",
	"not in a stock macos toolchain",
	"is a trap",
	"positional argument",
	"arm64e",
	"is not an object file",
	"with exit 0",
	"starting with '.'",
}

// false-positive signals: decoys and "this is not a layer/proof" guards.
var tur6Lane14FalsePositivePhrases = []string{
	"false positive",
	"proves nothing",
	"decoy",
	"exit code lies",
	"means a table exists",
	"separates decoy",
}

func tur6Lane14ContainsAny(hay string, needles []string) bool {
	for _, n := range needles {
		if strings.Contains(hay, n) {
			return true
		}
	}
	return false
}

// tur6Lane14Detect scans raw skill text and returns 1-based line numbers
// (0 = none) for platform traps and for false-positive controls.
func tur6Lane14Detect(text string) tur6Lane14Finding {
	var f tur6Lane14Finding
	for i, raw := range strings.Split(text, "\n") {
		ln := strings.ToLower(strings.TrimSpace(raw))
		line := i + 1
		if f.platformTrapLine == 0 && tur6Lane14ContainsAny(ln, tur6Lane14PlatformTrapPhrases) {
			f.platformTrapLine = line
		}
		if f.falsePositiveLine == 0 && tur6Lane14ContainsAny(ln, tur6Lane14FalsePositivePhrases) {
			f.falsePositiveLine = line
		}
	}
	return f
}

func tur6Lane14Status(f tur6Lane14Finding) string {
	if f.platformTrapLine > 0 && f.falsePositiveLine > 0 {
		return "PRESENT"
	}
	if f.platformTrapLine > 0 || f.falsePositiveLine > 0 {
		return "PARTIAL"
	}
	return "ABSENT"
}

func TestTur6Lane14PlatformTrapsFalsePositive(t *testing.T) {
	root := filepath.Join("..", "skill")
	paths := []string{
		filepath.Join(root, "SKILL.md"),
		filepath.Join(root, "README.md"),
	}
	if refs, err := filepath.Glob(filepath.Join(root, "references", "*.md")); err == nil {
		paths = append(paths, refs...)
	}

	best := "ABSENT"
	evidence := filepath.Join(root, "SKILL.md") + ":1"
	readAny := false
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		readAny = true
		f := tur6Lane14Detect(string(b))
		st := tur6Lane14Status(f)
		rank := map[string]int{"ABSENT": 0, "PARTIAL": 1, "PRESENT": 2}
		if rank[st] > rank[best] {
			best = st
			line := f.falsePositiveLine
			if line == 0 {
				line = f.platformTrapLine
			}
			if line == 0 {
				line = 1
			}
			evidence = p + ":" + strconv.Itoa(line)
		}
	}
	if !readAny {
		best = "ABSENT"
	}
	t.Logf("FIELD=platform_traps_false_positive STATUS=%s evidence=%s", best, evidence)
}

func TestTur6Lane14DetectorAccuracy(t *testing.T) {
	cases := []struct {
		name, text, want string
	}{
		{"present", "# Skill\nx86_64 prints $0x so #0x silently misses.\nA decoy FLAG is the usual false positive; the exit code separates decoy from real.\n", "PRESENT"},
		{"partial-trap-only", "# Skill\notool -l prints is not an object file with exit 0, grep quietly empty.\n", "PARTIAL"},
		{"partial-false-positive-only", "# Skill\nA low cmp count proves nothing; only rc=0 is a solve.\n", "PARTIAL"},
		{"absent", "# Skill\nplain text, no platform caveats or guards here\n", "ABSENT"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := tur6Lane14Status(tur6Lane14Detect(c.text)); got != c.want {
				t.Fatalf("tur6Lane14Status = %s, want %s", got, c.want)
			}
		})
	}
}
