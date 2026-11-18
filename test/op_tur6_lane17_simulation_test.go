package main

// Tur 6 lane 17: probe. Reads the walsyrea skill text directly and detects a
// precise "avoid redundant reruns" rule: an explicit no-rerun directive
// ("one probe, one result", "a re-run is not a check", "no re-run") and a
// reuse signal (cache hit avoids work / shared cache / run once). Finding is
// logged only; the test stays green regardless of outcome.

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

type tur6Lane17Finding struct {
	noRerunLine int // explicit directive: one probe one result / re-run not a check
	cacheLine   int // cache hit / shared cache avoids a repeat run
	runOnceLine int // "run once" / "never two at a time" cost rule
}

var tur6Lane17NoRerunPhrases = []string{
	"one probe, one result",
	"a re-run is not a check",
	"a rerun is not a check",
	"no re-run",
	"re-running a probe is not a check",
	"probe reruns as checks",
}

var tur6Lane17CachePhrases = []string{
	"a cache hit never runs",
	"cache hit never runs",
	"shares it",
	"one import per target",
	"exactly 1 (file lock",
}

var tur6Lane17RunOncePhrases = []string{
	"run once",
	"never two at a time",
	"prove ran once",
	"run it once",
	"once, never",
}

func tur6Lane17ContainsAny(hay string, needles []string) bool {
	for _, n := range needles {
		if strings.Contains(hay, n) {
			return true
		}
	}
	return false
}

// tur6Lane17Detect scans raw skill text and returns 1-based line numbers
// (0 = none) for the no-rerun directive, the cache-reuse signal and the
// run-once cost rule.
func tur6Lane17Detect(text string) tur6Lane17Finding {
	var f tur6Lane17Finding
	for i, raw := range strings.Split(text, "\n") {
		ln := strings.ToLower(strings.TrimSpace(raw))
		line := i + 1
		if f.noRerunLine == 0 && tur6Lane17ContainsAny(ln, tur6Lane17NoRerunPhrases) {
			f.noRerunLine = line
		}
		if f.cacheLine == 0 && (tur6Lane17ContainsAny(ln, tur6Lane17CachePhrases) ||
			(strings.Contains(ln, "cache") && strings.Contains(ln, "never"))) {
			f.cacheLine = line
		}
		if f.runOnceLine == 0 && tur6Lane17ContainsAny(ln, tur6Lane17RunOncePhrases) {
			f.runOnceLine = line
		}
	}
	return f
}

// tur6Lane17Status: PRESENT needs an explicit no-rerun directive plus a
// reuse/runtime signal (cache or run-once). Only the directive -> PARTIAL.
// No directive at all -> ABSENT.
func tur6Lane17Status(f tur6Lane17Finding) string {
	if f.noRerunLine == 0 {
		return "ABSENT"
	}
	if f.cacheLine > 0 || f.runOnceLine > 0 {
		return "PRESENT"
	}
	return "PARTIAL"
}

func tur6Lane17EvidenceLine(f tur6Lane17Finding) int {
	switch {
	case f.noRerunLine > 0:
		return f.noRerunLine
	case f.cacheLine > 0:
		return f.cacheLine
	case f.runOnceLine > 0:
		return f.runOnceLine
	}
	return 1
}

func TestTur6Lane17AvoidRedundantRerunsPresence(t *testing.T) {
	root := filepath.Join("..", "skill")
	paths := []string{filepath.Join(root, "SKILL.md")}
	if refs, err := filepath.Glob(filepath.Join(root, "references", "*.md")); err == nil {
		paths = append(paths, refs...)
	}

	best := "ABSENT"
	evidence := filepath.Join(root, "SKILL.md") + ":1"
	var bestFinding tur6Lane17Finding
	readAny := false
	rank := map[string]int{"ABSENT": 0, "PARTIAL": 1, "PRESENT": 2}
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		readAny = true
		f := tur6Lane17Detect(string(b))
		st := tur6Lane17Status(f)
		if rank[st] > rank[best] ||
			(rank[st] == rank[best] && tur6Lane17EvidenceLine(f) > tur6Lane17EvidenceLine(bestFinding)) {
			best = st
			bestFinding = f
			evidence = p + ":" + strconv.Itoa(tur6Lane17EvidenceLine(f))
		}
	}
	if !readAny {
		best = "ABSENT"
	}
	t.Logf("FIELD=avoid_redundant_reruns STATUS=%s evidence=%s", best, evidence)
	t.Logf("DETAIL no_rerun=%d cache_reuse=%d run_once=%d",
		bestFinding.noRerunLine, bestFinding.cacheLine, bestFinding.runOnceLine)
}

func TestTur6Lane17DetectorAccuracy(t *testing.T) {
	cases := []struct {
		name, text, want string
	}{
		{
			"present-directive-and-cache",
			"## No reruns\nOne probe, one result; a re-run is not a check.\n" +
				"a cache hit never runs it\n",
			"PRESENT",
		},
		{
			"present-directive-and-run-once",
			"- **One probe, one result.** Re-running a probe is not a check.\n" +
				"announce it, run it once, never two at a time\n",
			"PRESENT",
		},
		{
			"present-forbidden-and-cache",
			"Not authorized: probe reruns as checks.\n" +
				"one import per target: the cache lock\n",
			"PRESENT",
		},
		{
			"partial-directive-only",
			"One probe, one result; a re-run is not a check.\nplain prose\n",
			"PARTIAL",
		},
		{
			"absent-cache-only",
			"a cache hit never runs it\nrun once\n",
			"ABSENT",
		},
		{
			"absent-unrelated",
			"# Random\nplain text, no rerun rule here\n",
			"ABSENT",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := tur6Lane17Status(tur6Lane17Detect(c.text)); got != c.want {
				t.Fatalf("tur6Lane17Status = %s, want %s", got, c.want)
			}
		})
	}
}
