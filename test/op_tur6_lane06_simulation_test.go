package main

// Tur 6 lane 06: probe. Reads the walsyrea skill text directly and detects
// pre-approved frontmatter authorization: an allowed-tools tool list plus
// disable-model-invocation inside the YAML frontmatter block. Finding is
// logged only; the test stays green regardless of outcome.

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

type tur6Lane06Finding struct {
	fmStart     int // line of opening ---
	fmEnd       int // line of closing --- (0 = unclosed)
	allowedLine int // allowed-tools: with a non-empty value, inside frontmatter
	invokeLine  int // disable-model-invocation: true, inside frontmatter
	toolCount   int // tools named by allowed-tools
}

// tur6Lane06Detect scans raw skill text and returns 1-based line numbers
// (0 = none) for frontmatter-delimited authorization keys. Keys outside the
// frontmatter block do not count.
func tur6Lane06Detect(text string) tur6Lane06Finding {
	var f tur6Lane06Finding
	inFM := false
	for i, raw := range strings.Split(text, "\n") {
		ln := strings.ToLower(strings.TrimSpace(raw))
		line := i + 1
		if ln == "---" {
			if !inFM && f.fmStart == 0 {
				f.fmStart = line
				inFM = true
			} else if inFM {
				f.fmEnd = line
				inFM = false
			}
			continue
		}
		if !inFM {
			continue
		}
		if f.allowedLine == 0 && strings.HasPrefix(ln, "allowed-tools:") {
			val := strings.TrimSpace(raw)
			if idx := strings.Index(val, ":"); idx >= 0 {
				val = strings.TrimSpace(val[idx+1:])
			}
			if val != "" {
				f.allowedLine = line
				f.toolCount = len(strings.Fields(val))
			}
		}
		if f.invokeLine == 0 && ln == "disable-model-invocation: true" {
			f.invokeLine = line
		}
	}
	return f
}

// tur6Lane06Status: PRESENT needs a non-empty allowed-tools value and the
// auto-invocation switch, both inside a closed frontmatter block. Missing
// either key (or an unclosed block) degrades to PARTIAL; neither -> ABSENT.
func tur6Lane06Status(f tur6Lane06Finding) string {
	if f.allowedLine == 0 && f.invokeLine == 0 {
		return "ABSENT"
	}
	if f.allowedLine > 0 && f.toolCount > 0 && f.invokeLine > 0 && f.fmEnd > 0 {
		return "PRESENT"
	}
	return "PARTIAL"
}

func tur6Lane06EvidenceLine(f tur6Lane06Finding) int {
	switch {
	case f.allowedLine > 0:
		return f.allowedLine
	case f.invokeLine > 0:
		return f.invokeLine
	case f.fmStart > 0:
		return f.fmStart
	}
	return 1
}

func TestTur6Lane06FrontmatterAuthorizationPresence(t *testing.T) {
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
	var bestFinding tur6Lane06Finding
	readAny := false
	rank := map[string]int{"ABSENT": 0, "PARTIAL": 1, "PRESENT": 2}
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		readAny = true
		f := tur6Lane06Detect(string(b))
		st := tur6Lane06Status(f)
		if rank[st] > rank[best] ||
			(rank[st] == rank[best] && tur6Lane06EvidenceLine(f) > tur6Lane06EvidenceLine(bestFinding)) {
			best = st
			bestFinding = f
			evidence = p + ":" + strconv.Itoa(tur6Lane06EvidenceLine(f))
		}
	}
	if !readAny {
		best = "ABSENT"
	}
	t.Logf("FIELD=frontmatter_auth STATUS=%s evidence=%s", best, evidence)
	t.Logf("DETAIL fm=%d-%d allowed_tools_line=%d tool_count=%d auto_invoke_disabled_line=%d",
		bestFinding.fmStart, bestFinding.fmEnd, bestFinding.allowedLine,
		bestFinding.toolCount, bestFinding.invokeLine)
}

func TestTur6Lane06DetectorAccuracy(t *testing.T) {
	cases := []struct {
		name, text, want string
	}{
		{
			"present",
			"---\nname: x\nallowed-tools: Bash Read Grep\n" +
				"disable-model-invocation: true\n---\n",
			"PRESENT",
		},
		{
			"partial-allowed-only",
			"---\nname: x\nallowed-tools: Bash Read\n---\n",
			"PARTIAL",
		},
		{
			"partial-invoke-only",
			"---\ndisable-model-invocation: true\n---\n",
			"PARTIAL",
		},
		{
			"partial-unclosed-frontmatter",
			"---\nallowed-tools: Bash Read\ndisable-model-invocation: true\n",
			"PARTIAL",
		},
		{
			"partial-empty-allowed-list",
			"---\nallowed-tools:\ndisable-model-invocation: true\n---\n",
			"PARTIAL",
		},
		{
			"absent-keys-in-body-only",
			"# Random\nallowed-tools: Bash Read\ndisable-model-invocation: true\n",
			"ABSENT",
		},
		{
			"absent",
			"# Random\nplain text, no frontmatter here\n",
			"ABSENT",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := tur6Lane06Status(tur6Lane06Detect(c.text)); got != c.want {
				t.Fatalf("tur6Lane06Status = %s, want %s", got, c.want)
			}
		})
	}
}
