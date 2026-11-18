package main

// Tur 6 lane 04: probe. Reads the walsyrea skill text directly and detects
// "borrowed workflow" scope protection ("Keep scope exact" / do not expand)
// language. Finding is logged only; the test stays green regardless of outcome.

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

type tur6Lane04ScopeFinding struct {
	scopeHeadingLine int
	keepExactLine    int
	borrowedLine     int
	noExpandLine     int
}

var tur6Lane04KeepExactPhrases = []string{
	"keep scope exact",
	"scope exact",
}

var tur6Lane04BorrowedPhrases = []string{
	"borrowed workflow",
}

var tur6Lane04NoExpandPhrases = []string{
	"no further",
	"to the letter",
	"never the target",
	"do not expand",
	"and no further",
}

func tur6Lane04ContainsAny(hay string, needles []string) bool {
	for _, n := range needles {
		if strings.Contains(hay, n) {
			return true
		}
	}
	return false
}

// tur6Lane04Detect scans raw skill text and returns 1-based line numbers
// (0 = none) for a Scope heading, "Keep scope exact", "borrowed workflow",
// and no-expand language.
func tur6Lane04Detect(text string) tur6Lane04ScopeFinding {
	var f tur6Lane04ScopeFinding
	for i, raw := range strings.Split(text, "\n") {
		ln := strings.ToLower(strings.TrimSpace(raw))
		line := i + 1
		if f.scopeHeadingLine == 0 && (strings.HasPrefix(ln, "## scope") || strings.HasPrefix(ln, "# scope") || strings.HasPrefix(ln, "### scope")) {
			f.scopeHeadingLine = line
		}
		if f.keepExactLine == 0 && tur6Lane04ContainsAny(ln, tur6Lane04KeepExactPhrases) {
			f.keepExactLine = line
		}
		if f.borrowedLine == 0 && tur6Lane04ContainsAny(ln, tur6Lane04BorrowedPhrases) {
			f.borrowedLine = line
		}
		if f.noExpandLine == 0 && tur6Lane04ContainsAny(ln, tur6Lane04NoExpandPhrases) {
			f.noExpandLine = line
		}
	}
	return f
}

func tur6Lane04Status(f tur6Lane04ScopeFinding) string {
	n := 0
	if f.scopeHeadingLine > 0 {
		n++
	}
	if f.keepExactLine > 0 {
		n++
	}
	if f.borrowedLine > 0 {
		n++
	}
	if f.noExpandLine > 0 {
		n++
	}
	if n == 4 {
		return "PRESENT"
	}
	if n > 0 {
		return "PARTIAL"
	}
	return "ABSENT"
}

func TestTur6Lane04BorrowedWorkflowScopePresence(t *testing.T) {
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
		f := tur6Lane04Detect(string(b))
		st := tur6Lane04Status(f)
		rank := map[string]int{"ABSENT": 0, "PARTIAL": 1, "PRESENT": 2}
		if rank[st] > rank[best] {
			best = st
			line := 1
			switch {
			case f.keepExactLine > 0:
				line = f.keepExactLine
			case f.borrowedLine > 0:
				line = f.borrowedLine
			case f.noExpandLine > 0:
				line = f.noExpandLine
			case f.scopeHeadingLine > 0:
				line = f.scopeHeadingLine
			}
			evidence = p + ":" + strconv.Itoa(line)
		}
	}
	if !readAny {
		best = "ABSENT"
	}
	t.Logf("FIELD=borrowed_workflow_scope STATUS=%s evidence=%s", best, evidence)
}

func TestTur6Lane04DetectorAccuracy(t *testing.T) {
	cases := []struct {
		name, text, want string
	}{
		{"present", "## Scope\n- **Keep scope exact.** The ask names the artifact and the goal; anything else is\n  a borrowed workflow, followed to the letter of what it states and no further.\n", "PRESENT"},
		{"partial-scope-only", "# Random\n## Scope\nnothing else here\n", "PARTIAL"},
		{"partial-borrowed-only", "# Random\na borrowed workflow is mentioned\n", "PARTIAL"},
		{"absent", "# Random\nplain text, no scope rule here\n", "ABSENT"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := tur6Lane04Status(tur6Lane04Detect(c.text)); got != c.want {
				t.Fatalf("tur6Lane04Status = %s, want %s", got, c.want)
			}
		})
	}
}
