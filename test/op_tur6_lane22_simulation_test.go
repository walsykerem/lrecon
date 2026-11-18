package main

// Tur 6 lane 22: probe. Reads the walsyrea skill text directly and detects
// fixed-filename contract language (mandated artifact names, no clock/random).
// Finding is logged only; the test stays green regardless of outcome.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type tur6L22Finding struct {
	chainLine int
	fixedLine int
	clockLine int
}

// Canonical artifact names mandated by the skill's stage chain.
var tur6L22ChainPhrases = []string{
	".digest.json",
	".op-<op>.json",
	".proof.txt",
	"$w/<name>",
}

// Language asserting the names are fixed / contractual.
var tur6L22FixedPhrases = []string{
	"fixed chain",
	"naming is the contract",
	"is fixed",
	"in this order",
}

// Language forbidding clock- or random-derived names.
var tur6L22ClockPhrases = []string{
	"clock- or random-derived artifact name",
	"random-derived artifact name",
	"two runs produce the same names",
	"no clock",
}

func tur6L22Any(hay string, needles []string) bool {
	for _, n := range needles {
		if strings.Contains(hay, n) {
			return true
		}
	}
	return false
}

// tur6L22Detect scans raw skill text and returns 1-based line numbers (0 = none)
// for: a fixed artifact-name chain, a "names are fixed/contract" assertion,
// and a ban on clock/random-derived names.
func tur6L22Detect(text string) tur6L22Finding {
	var f tur6L22Finding
	for i, raw := range strings.Split(text, "\n") {
		ln := strings.ToLower(strings.TrimSpace(raw))
		line := i + 1
		if f.chainLine == 0 && tur6L22Any(ln, tur6L22ChainPhrases) {
			f.chainLine = line
		}
		if f.fixedLine == 0 && tur6L22Any(ln, tur6L22FixedPhrases) {
			f.fixedLine = line
		}
		if f.clockLine == 0 && tur6L22Any(ln, tur6L22ClockPhrases) {
			f.clockLine = line
		}
	}
	return f
}

func tur6L22Status(f tur6L22Finding) string {
	if f.chainLine > 0 && f.fixedLine > 0 && f.clockLine > 0 {
		return "PRESENT"
	}
	if f.chainLine > 0 || f.fixedLine > 0 || f.clockLine > 0 {
		return "PARTIAL"
	}
	return "ABSENT"
}

func tur6L22Itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

func TestTur6Lane22FixedFilenamesPresence(t *testing.T) {
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
	var bestFinding tur6L22Finding
	readAny := false
	rank := map[string]int{"ABSENT": 0, "PARTIAL": 1, "PRESENT": 2}
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		readAny = true
		f := tur6L22Detect(string(b))
		st := tur6L22Status(f)
		if rank[st] > rank[best] {
			best = st
			bestFinding = f
			line := 1
			switch {
			case f.chainLine > 0:
				line = f.chainLine
			case f.fixedLine > 0:
				line = f.fixedLine
			case f.clockLine > 0:
				line = f.clockLine
			}
			evidence = p + ":" + tur6L22Itoa(line)
		}
	}
	if !readAny {
		best = "ABSENT"
	}
	_ = bestFinding
	t.Logf("FIELD=fixed_filenames STATUS=%s evidence=%s", best, evidence)
}

func TestTur6Lane22DetectorAccuracy(t *testing.T) {
	cases := []struct {
		name, text, want string
	}{
		{"present", "# Contract\nfixed chain, in this order:\n$W/<name>.digest.json -> $W/<name>.proof.txt\nNaming is the contract: no clock\n", "PRESENT"},
		{"present-limits", "# Limits\n- a clock- or random-derived artifact name: $W/<name>.digest.json is fixed, so two runs produce the same names.\n", "PRESENT"},
		{"partial-chain-only", "# Contract\n$W/<name>.digest.json\n", "PARTIAL"},
		{"partial-clause-only", "# Limits\nno clock in the name\n", "PARTIAL"},
		{"absent", "# Random\nplain text, no filenames here\n", "ABSENT"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := tur6L22Status(tur6L22Detect(c.text)); got != c.want {
				t.Fatalf("tur6L22Status = %s, want %s", got, c.want)
			}
		})
	}
}
