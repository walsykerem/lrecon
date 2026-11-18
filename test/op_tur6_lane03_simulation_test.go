package main

// Tur 6 lane 03 probe: reads the walsyrea skill text directly and detects
// format / resolution / output-cleanliness ("scrub, clean, normalize") language.
// The finding is logged only; the test stays green regardless of outcome.

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

type tur6Lane03Finding struct {
	scrubLine      int
	sanitizeLine   int
	residueLine    int
	resolutionLine int
}

// tur6Lane03Detect scans raw skill text (line per line) and records the first
// 1-based line that mentions each cleanliness signal; 0 means none.
func tur6Lane03Detect(text string) tur6Lane03Finding {
	var f tur6Lane03Finding
	for i, raw := range strings.Split(text, "\n") {
		ln := strings.ToLower(strings.TrimSpace(raw))
		line := i + 1
		if f.scrubLine == 0 && strings.Contains(ln, "scrub") {
			f.scrubLine = line
		}
		if f.sanitizeLine == 0 && (strings.Contains(ln, "sanitiz") || strings.Contains(ln, "normaliz") ||
			strings.Contains(ln, "no space, no clock")) {
			f.sanitizeLine = line
		}
		if f.residueLine == 0 && (strings.Contains(ln, "residue") || strings.Contains(ln, "clean the dir") ||
			strings.Contains(ln, "not cleaning up") || strings.Contains(ln, "leftover") ||
			strings.Contains(ln, "cleanup")) {
			f.residueLine = line
		}
		if f.resolutionLine == 0 && (strings.Contains(ln, "verify_unknown_resolution") ||
			strings.Contains(ln, "resolution")) {
			f.resolutionLine = line
		}
	}
	return f
}

// tur6Lane03Status: PRESENT needs a clean signal (scrub OR residue), a format
// signal (sanitize) and a resolution signal. Any single dimension is PARTIAL.
func tur6Lane03Status(f tur6Lane03Finding) string {
	clean := f.scrubLine > 0 || f.residueLine > 0
	format := f.sanitizeLine > 0
	res := f.resolutionLine > 0
	if clean && format && res {
		return "PRESENT"
	}
	if clean || format || res {
		return "PARTIAL"
	}
	return "ABSENT"
}

func TestTur6Lane03FormatResolutionCleanPresence(t *testing.T) {
	root := filepath.Join("..", "skill")
	paths := []string{
		filepath.Join(root, "SKILL.md"),
		filepath.Join(root, "README.md"),
	}
	if refs, err := filepath.Glob(filepath.Join(root, "references", "*.md")); err == nil {
		paths = append(paths, refs...)
	}

	// Combine signals across the whole corpus; keep first signal as evidence.
	var combined tur6Lane03Finding
	evidence := filepath.Join(root, "SKILL.md") + ":1"
	readAny := false
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		readAny = true
		f := tur6Lane03Detect(string(b))
		if evidence == filepath.Join(root, "SKILL.md")+":1" {
			for _, line := range []int{f.scrubLine, f.sanitizeLine, f.residueLine, f.resolutionLine} {
				if line > 0 {
					evidence = p + ":" + strconv.Itoa(line)
					break
				}
			}
		}
		if f.scrubLine > 0 && (combined.scrubLine == 0 || f.scrubLine < combined.scrubLine) {
			combined.scrubLine = f.scrubLine
		}
		if f.sanitizeLine > 0 && (combined.sanitizeLine == 0 || f.sanitizeLine < combined.sanitizeLine) {
			combined.sanitizeLine = f.sanitizeLine
		}
		if f.residueLine > 0 && (combined.residueLine == 0 || f.residueLine < combined.residueLine) {
			combined.residueLine = f.residueLine
		}
		if f.resolutionLine > 0 && (combined.resolutionLine == 0 || f.resolutionLine < combined.resolutionLine) {
			combined.resolutionLine = f.resolutionLine
		}
	}
	status := "ABSENT"
	if readAny {
		status = tur6Lane03Status(combined)
	}
	t.Logf("FIELD=format_resolution_clean STATUS=%s evidence=%s", status, evidence)
}

func TestTur6Lane03DetectorAccuracy(t *testing.T) {
	cases := []struct {
		name, text, want string
	}{
		{"present", "## Stages\n<name> is sanitized basename, no space, no clock\nresidue that fails, not gets cleaned\nscrub_output, verify_unknown_resolution\n", "PRESENT"},
		{"partial-clean-only", "## Scope\nclean the DIR yourself\nscrub_output\n", "PARTIAL"},
		{"partial-format-only", "# Random\n<name> sanitized basename\n", "PARTIAL"},
		{"absent", "# Random\nplain text, no cleanliness language here\n", "ABSENT"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := tur6Lane03Status(tur6Lane03Detect(c.text)); got != c.want {
				t.Fatalf("tur6Lane03Status = %s, want %s", got, c.want)
			}
		})
	}
}
