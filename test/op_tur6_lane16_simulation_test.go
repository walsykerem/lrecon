package main

// Tur 6 lane 16: probe. Reads the walsyrea skill text directly and detects the
// "trust the result, not logs" principle: rc=0 + required field, decoy
// rejection, and an explicit results-over-logs rule. Finding is logged only;
// the test stays green regardless of outcome.

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

type tur6L16Finding struct {
	principleLine int
	rcLine        int
	decoyLine     int
}

// Explicit "trust results, not logs" statements.
var tur6L16Principle = []string{
	"trust results, not logs",
	"trust the result",
	"result over log",
	"evidence over log",
	"no log trust",
	"no `flag`/log trust",
	"do not scrape the console",
}

// Exit-code-as-proof statements.
var tur6L16Rc = []string{
	"rc=0",
	"exit code separates decoy",
	"never stdout",
	"with exit 0",
	"with exit 0 and",
}

// Decoy / empty-result rejection statements.
var tur6L16Decoy = []string{
	"rc!=0",
	"decoy",
	"empty `result`",
	"empty result",
	"printed nothing usable",
	"did not succeed",
}

func tur6L16Any(hay string, needles []string) bool {
	for _, n := range needles {
		if strings.Contains(hay, n) {
			return true
		}
	}
	return false
}

func tur6L16Detect(text string) tur6L16Finding {
	var f tur6L16Finding
	for i, raw := range strings.Split(text, "\n") {
		ln := strings.ToLower(strings.TrimSpace(raw))
		line := i + 1
		if f.principleLine == 0 && tur6L16Any(ln, tur6L16Principle) {
			f.principleLine = line
		}
		if f.rcLine == 0 && tur6L16Any(ln, tur6L16Rc) {
			f.rcLine = line
		}
		if f.decoyLine == 0 && tur6L16Any(ln, tur6L16Decoy) {
			f.decoyLine = line
		}
	}
	return f
}

func tur6L16Status(f tur6L16Finding) string {
	n := 0
	if f.principleLine > 0 {
		n++
	}
	if f.rcLine > 0 {
		n++
	}
	if f.decoyLine > 0 {
		n++
	}
	if n == 3 {
		return "PRESENT"
	}
	if n > 0 {
		return "PARTIAL"
	}
	return "ABSENT"
}

func tur6L16EvidencePath(f tur6L16Finding, path string) string {
	line := 1
	switch {
	case f.principleLine > 0:
		line = f.principleLine
	case f.rcLine > 0:
		line = f.rcLine
	case f.decoyLine > 0:
		line = f.decoyLine
	}
	return path + ":" + strconv.Itoa(line)
}

func TestTur6Lane16TrustResultsNotLogs(t *testing.T) {
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
	rank := map[string]int{"ABSENT": 0, "PARTIAL": 1, "PRESENT": 2}
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		readAny = true
		f := tur6L16Detect(string(b))
		st := tur6L16Status(f)
		if rank[st] > rank[best] {
			best = st
			evidence = tur6L16EvidencePath(f, p)
		}
	}
	if !readAny {
		best = "ABSENT"
	}
	t.Logf("FIELD=trust_results_not_logs STATUS=%s evidence=%s", best, evidence)
}

func TestTur6Lane16DetectorAccuracy(t *testing.T) {
	cases := []struct {
		name, text, want string
	}{
		{"present", "- **Trust results, not logs.** `rc=0` plus the field you needed, or the stderr line. A probe that printed nothing usable did not succeed.\n", "PRESENT"},
		{"present-exit-code", "The **exit code** separates decoy from real, never stdout: a stdout match with rc!=0 is a decoy.\nTrust the result, not logs.\n", "PRESENT"},
		{"partial-principle-only", "Trust results, not logs.\n", "PARTIAL"},
		{"partial-rc-only", "solved needs the artifact running with exit 0 and one proof.\n", "PARTIAL"},
		{"absent", "# Random\nplain text, no result language here\n", "ABSENT"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := tur6L16Status(tur6L16Detect(c.text)); got != c.want {
				t.Fatalf("tur6L16Status = %s, want %s", got, c.want)
			}
		})
	}
}
