package main

// Tur 6 lane 05: probe. Reads the walsyrea skill text directly and detects
// an explicit "Creator editing boundary" section that protects hand-edited
// operator text. Finding is logged only; the test stays green regardless.

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

type tur6Lane05Finding struct {
	headingLine int
	langLine    int
}

var tur6Lane05BoundaryPhrases = []string{
	"wrote by hand",
	"written by hand",
	"is theirs",
	"name that line first",
	"change only that line",
	"explicit ask",
	"deleting is not cleaning up",
	"do not overwrite",
	"manual edits",
	"user edits",
	"preserve",
}

func tur6Lane05ContainsAny(hay string, needles []string) bool {
	for _, n := range needles {
		if strings.Contains(hay, n) {
			return true
		}
	}
	return false
}

// tur6Lane05Detect scans raw skill text and returns 1-based line numbers
// (0 = none) for a Creator-editing-boundary heading and preservation language.
func tur6Lane05Detect(text string) tur6Lane05Finding {
	var f tur6Lane05Finding
	for i, raw := range strings.Split(text, "\n") {
		ln := strings.ToLower(strings.TrimSpace(raw))
		line := i + 1
		if f.headingLine == 0 && strings.HasPrefix(ln, "## creator editing boundary") {
			f.headingLine = line
		}
		if f.langLine == 0 && tur6Lane05ContainsAny(ln, tur6Lane05BoundaryPhrases) {
			f.langLine = line
		}
	}
	return f
}

func tur6Lane05Status(f tur6Lane05Finding) string {
	if f.headingLine > 0 && f.langLine > 0 {
		return "PRESENT"
	}
	if f.headingLine > 0 || f.langLine > 0 {
		return "PARTIAL"
	}
	return "ABSENT"
}

func TestTur6Lane05CreatorEditingBoundary(t *testing.T) {
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
		f := tur6Lane05Detect(string(b))
		st := tur6Lane05Status(f)
		rank := map[string]int{"ABSENT": 0, "PARTIAL": 1, "PRESENT": 2}
		if rank[st] > rank[best] {
			best = st
			line := f.headingLine
			if line == 0 {
				line = f.langLine
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
	t.Logf("FIELD=creator_editing_boundary STATUS=%s evidence=%s", best, evidence)
}

func TestTur6Lane05DetectorAccuracy(t *testing.T) {
	cases := []struct {
		name, text, want string
	}{
		{"present", "## Creator editing boundary\nText the operator wrote by hand is theirs. Change only that line; rewriting needs an explicit ask.\n", "PRESENT"},
		{"partial-heading-only", "## Creator editing boundary\nSome unrelated filler text here.\n", "PARTIAL"},
		{"partial-lang-only", "# Random\nText the operator wrote by hand is theirs.\n", "PARTIAL"},
		{"absent", "# Random\nplain text, no boundary here\n", "ABSENT"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := tur6Lane05Status(tur6Lane05Detect(c.text)); got != c.want {
				t.Fatalf("tur6Lane05Status = %s, want %s", got, c.want)
			}
		})
	}
}
