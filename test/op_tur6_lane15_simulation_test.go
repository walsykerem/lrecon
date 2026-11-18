package main

// Tur 6 lane 15: probe. Reads the walsyrea skill text directly and detects
// cheap verification probes (lint/check/diff/self-lint, cheap-before-expensive)
// plus an explicit approval gate before an expensive op (Ghidra cost / explicit go).
// Finding is logged only; the test stays green regardless of outcome.

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

type tur6Lane15Finding struct {
	cheapLine    int
	approvalLine int
}

// cheap probe signals: lint/check/diff/self-lint and cheap-before-expensive order.
var tur6Lane15CheapPhrases = []string{
	"cheap before expensive",
	"cheap first",
	"cheap probes",
	"cheap layer",
	"self-lint",
	"re-lint",
	"lint:",
	"--check",
	"--diff",
	"diff exactly",
	"digest → symbol/string op → ghidra",
}

// approval gate signals: announce the cost and get an explicit go before paying it.
var tur6Lane15ApprovalPhrases = []string{
	"get an explicit go",
	"explicit go",
	"say the cost before paying it",
	"state its cost",
	"announce it",
	"before a multi-minute op",
	"the only multi-minute",
}

func tur6Lane15ContainsAny(hay string, needles []string) bool {
	for _, n := range needles {
		if strings.Contains(hay, n) {
			return true
		}
	}
	return false
}

// tur6Lane15Detect scans raw skill text and returns 1-based line numbers
// (0 = none) for cheap verification probes and for the expensive-op approval gate.
func tur6Lane15Detect(text string) tur6Lane15Finding {
	var f tur6Lane15Finding
	for i, raw := range strings.Split(text, "\n") {
		ln := strings.ToLower(strings.TrimSpace(raw))
		line := i + 1
		if f.cheapLine == 0 && tur6Lane15ContainsAny(ln, tur6Lane15CheapPhrases) {
			f.cheapLine = line
		}
		if f.approvalLine == 0 && tur6Lane15ContainsAny(ln, tur6Lane15ApprovalPhrases) {
			f.approvalLine = line
		}
	}
	return f
}

func tur6Lane15Status(f tur6Lane15Finding) string {
	if f.cheapLine > 0 && f.approvalLine > 0 {
		return "PRESENT"
	}
	if f.cheapLine > 0 || f.approvalLine > 0 {
		return "PARTIAL"
	}
	return "ABSENT"
}

func TestTur6Lane15CheapVerificationProbes(t *testing.T) {
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
		f := tur6Lane15Detect(string(b))
		st := tur6Lane15Status(f)
		rank := map[string]int{"ABSENT": 0, "PARTIAL": 1, "PRESENT": 2}
		if rank[st] > rank[best] {
			best = st
			line := f.approvalLine
			if line == 0 {
				line = f.cheapLine
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
	t.Logf("FIELD=cheap_verification_probes STATUS=%s evidence=%s", best, evidence)
}

func TestTur6Lane15DetectorAccuracy(t *testing.T) {
	cases := []struct {
		name, text, want string
	}{
		{"present", "# Skill\nBefore Output, self-lint: Identify, Unpack, Recover, Prove.\nCheap before expensive: digest → symbol/string op → Ghidra.\nBefore a multi-minute op (Ghidra), state its cost and get an explicit go.\n", "PRESENT"},
		{"partial-cheap-only", "# Skill\nBefore Output, self-lint. Cheap before expensive: digest first.\n", "PARTIAL"},
		{"partial-approval-only", "# Skill\nSay the cost before paying it; announce it, run it once.\n", "PARTIAL"},
		{"absent", "# Skill\nplain text, no probes or gates here\n", "ABSENT"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := tur6Lane15Status(tur6Lane15Detect(c.text)); got != c.want {
				t.Fatalf("tur6Lane15Status = %s, want %s", got, c.want)
			}
		})
	}
}
