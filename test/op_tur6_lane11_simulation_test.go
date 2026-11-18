package main

// Tur 6 lane 11: guard. Reads the walsyrea skill text directly and requires a
// precise description: frontmatter `description:` with a single main-job lead,
// an explicit positive trigger ("Use when"/"Use this skill") and a negative
// scope delimiter ("Not for ..."). The real skill must grade PRESENT; the
// detector's own grading is pinned by TestTur6Lane11DetectorAccuracy.

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

type tur6Lane11Finding struct {
	descLine    int // `description:` frontmatter present
	mainJobLine int // first sentence names one main job (verb + domain object)
	useWhenLine int // explicit positive trigger phrase
	scopeLine   int // negative scope delimiter
	invokeLine  int // `disable-model-invocation: true` (auto-trigger off)
}

var tur6Lane11PositiveTriggers = []string{
	"use when", "use this skill", "when to use", "trigger when", "invoke when",
}

var tur6Lane11ScopeDelimiters = []string{
	"not for", "out of scope", "not supported", "excludes", "not applicable",
}

var tur6Lane11ActionVerbs = []string{
	"identify", "unpack", "bypass", "crack", "analy", "reverse", "inspect",
	"detect", "extract", "examine", "recover", "decode", "debug", "reconstruct",
}

var tur6Lane11DomainObjects = []string{
	"binary", "app", "artifact", "executable", "malware", "firmware", "package",
}

func tur6Lane11ContainsAny(hay string, needles []string) bool {
	for _, n := range needles {
		if strings.Contains(hay, n) {
			return true
		}
	}
	return false
}

// tur6Lane11Detect scans raw skill text and returns 1-based line numbers
// (0 = none) for a description, its single-job lead, positive trigger,
// negative scope delimiter, and the auto-invocation switch.
func tur6Lane11Detect(text string) tur6Lane11Finding {
	var f tur6Lane11Finding
	var descVal string
	for i, raw := range strings.Split(text, "\n") {
		ln := strings.ToLower(strings.TrimSpace(raw))
		line := i + 1
		if f.descLine == 0 && strings.HasPrefix(ln, "description:") {
			f.descLine = line
			trimmed := strings.TrimSpace(raw)
			if idx := strings.Index(trimmed, ":"); idx >= 0 {
				descVal = strings.TrimSpace(trimmed[idx+1:])
			}
		}
		if f.useWhenLine == 0 && tur6Lane11ContainsAny(ln, tur6Lane11PositiveTriggers) {
			f.useWhenLine = line
		}
		if f.scopeLine == 0 && tur6Lane11ContainsAny(ln, tur6Lane11ScopeDelimiters) {
			f.scopeLine = line
		}
		if f.invokeLine == 0 && strings.Contains(ln, "disable-model-invocation: true") {
			f.invokeLine = line
		}
	}
	if descVal != "" {
		first := descVal
		if dot := strings.Index(first, "."); dot >= 0 {
			first = first[:dot]
		}
		low := strings.ToLower(first)
		if tur6Lane11ContainsAny(low, tur6Lane11ActionVerbs) &&
			tur6Lane11ContainsAny(low, tur6Lane11DomainObjects) {
			f.mainJobLine = f.descLine
		}
	}
	return f
}

// tur6Lane11Status: PRESENT needs a description with a single main-job lead,
// an explicit positive trigger AND a scope delimiter. Missing any precision
// signal (no "Use when", etc.) degrades to PARTIAL; no description -> ABSENT.
func tur6Lane11Status(f tur6Lane11Finding) string {
	if f.descLine == 0 {
		return "ABSENT"
	}
	if f.mainJobLine > 0 && f.useWhenLine > 0 && f.scopeLine > 0 {
		return "PRESENT"
	}
	return "PARTIAL"
}

func tur6Lane11EvidenceLine(f tur6Lane11Finding) int {
	switch {
	case f.descLine > 0:
		return f.descLine
	case f.useWhenLine > 0:
		return f.useWhenLine
	case f.scopeLine > 0:
		return f.scopeLine
	}
	return 1
}

func TestTur6Lane11DescriptionPrecisionPresence(t *testing.T) {
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
	var bestFinding tur6Lane11Finding
	readAny := false
	rank := map[string]int{"ABSENT": 0, "PARTIAL": 1, "PRESENT": 2}
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		readAny = true
		f := tur6Lane11Detect(string(b))
		st := tur6Lane11Status(f)
		if rank[st] > rank[best] ||
			(rank[st] == rank[best] && tur6Lane11EvidenceLine(f) > tur6Lane11EvidenceLine(bestFinding)) {
			best = st
			bestFinding = f
			evidence = p + ":" + strconv.Itoa(tur6Lane11EvidenceLine(f))
		}
	}
	if !readAny {
		best = "ABSENT"
	}
	t.Logf("FIELD=description_precision STATUS=%s evidence=%s", best, evidence)
	t.Logf("DETAIL desc=%d main_job=%d use_when=%d scope=%d auto_invoke_disabled=%d",
		bestFinding.descLine, bestFinding.mainJobLine, bestFinding.useWhenLine,
		bestFinding.scopeLine, bestFinding.invokeLine)
	if best != "PRESENT" {
		t.Errorf("walsyrea description is %s, want PRESENT (main-job lead + `Use when` trigger + scope delimiter)", best)
	}
}

func TestTur6Lane11DetectorAccuracy(t *testing.T) {
	cases := []struct {
		name, text, want string
	}{
		{
			"present",
			"---\n" +
				"name: x\n" +
				"description: Identify, unpack or crack a shipped binary or app. Use when reversing a shipped binary. Not for source repos.\n" +
				"---\n",
			"PRESENT",
		},
		{
			"present-use-this-skill",
			"---\n" +
				"description: Examine a shipped binary or app. Use this skill when inspecting an executable. Not for live processes.\n" +
				"---\n",
			"PRESENT",
		},
		{
			"present-skill-use-when",
			"---\n" +
				"description: Identify, unpack, bypass or crack a shipped binary or app. Use when reversing a shipped binary or app. Not for source repos or live processes.\n" +
				"---\n",
			"PRESENT",
		},
		{
			"partial-no-trigger",
			"---\n" +
				"description: Identify a shipped binary or app.\n" +
				"---\n",
			"PARTIAL",
		},
		{
			"partial-no-scope",
			"---\n" +
				"description: Identify a shipped binary or app. Use when reversing binaries.\n" +
				"---\n",
			"PARTIAL",
		},
		{
			"absent",
			"# Random\nplain text, no description frontmatter here\n",
			"ABSENT",
		},
		{
			"absent-body-trigger-only",
			"# Random\nUse when reversing. Not for source repos. but no description frontmatter\n",
			"ABSENT",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := tur6Lane11Status(tur6Lane11Detect(c.text)); got != c.want {
				t.Fatalf("tur6Lane11Status = %s, want %s", got, c.want)
			}
		})
	}
}
