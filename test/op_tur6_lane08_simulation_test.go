package main

// Tur 6 lane 08: probe. Reads the walsyrea skill text directly and detects
// per-step "Done when" completion criteria: a Done-when heading plus observable,
// verifiable criteria for each of the Identify / Unpack / Recover / Prove steps.
// Finding is logged only; the test stays green regardless of outcome.

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

type tur6Lane08Finding struct {
	doneHeadingLine int
	stepLine        int
	observableLine  int
	exitLine        int
	stepNames       map[string]int
}

func tur6Lane08ContainsAny(hay string, needles []string) bool {
	for _, n := range needles {
		if strings.Contains(hay, n) {
			return true
		}
	}
	return false
}

// tur6Lane08Detect scans raw skill text and reports 1-based line numbers
// (0 = none) for a "Done when" heading, per-step criteria lines, observable /
// verifiable language, and an exit/stop criterion. It also returns the line at
// which each of Identify/Unpack/Recover/Prove first appears as a criterion.
func tur6Lane08Detect(text string) tur6Lane08Finding {
	f := tur6Lane08Finding{stepNames: map[string]int{}}
	var obsLine, exitLine, stepLine int
	inDone := false
	steps := []string{"identify", "unpack", "recover", "prove"}
	obs := []string{"observable", "verifi", "checked", "one verification run", "byte patch", "printed", "named"}
	exitPhrases := []string{"then stop", "exits with no further probes", "no further probes"}
	for i, raw := range strings.Split(text, "\n") {
		ln := strings.ToLower(strings.TrimSpace(raw))
		line := i + 1
		heading := strings.TrimLeft(ln, "# ")
		if heading == "done when" || strings.HasPrefix(ln, "## done when") || strings.HasPrefix(ln, "### done when") {
			if f.doneHeadingLine == 0 {
				f.doneHeadingLine = line
			}
			inDone = true
			continue
		}
		// A new heading of same/higher level ends the Done-when section.
		if inDone && strings.HasPrefix(ln, "#") {
			inDone = false
		}
		stepHere := false
		for _, s := range steps {
			if f.stepNames[s] == 0 && (strings.HasPrefix(ln, "- **"+s) || strings.HasPrefix(ln, "**"+s+"**:")) {
				f.stepNames[s] = line
				stepHere = true
			}
		}
		if stepHere && stepLine == 0 {
			stepLine = line
		}
		if obsLine == 0 && tur6Lane08ContainsAny(ln, obs) {
			obsLine = line
		}
		if exitLine == 0 && tur6Lane08ContainsAny(ln, exitPhrases) {
			exitLine = line
		}
	}
	f.stepLine = stepLine
	f.observableLine = obsLine
	f.exitLine = exitLine
	return f
}

func tur6Lane08StepCount(f tur6Lane08Finding) int {
	n := 0
	for _, s := range []string{"identify", "unpack", "recover", "prove"} {
		if f.stepNames[s] > 0 {
			n++
		}
	}
	return n
}

func tur6Lane08Status(f tur6Lane08Finding) string {
	steps := tur6Lane08StepCount(f)
	if f.doneHeadingLine > 0 && steps == 4 && f.observableLine > 0 && f.exitLine > 0 {
		return "PRESENT"
	}
	if f.doneHeadingLine > 0 || steps > 0 || f.observableLine > 0 || f.exitLine > 0 {
		return "PARTIAL"
	}
	return "ABSENT"
}

func tur6Lane08EvidenceLine(f tur6Lane08Finding) int {
	switch {
	case f.doneHeadingLine > 0:
		return f.doneHeadingLine
	case f.stepLine > 0:
		return f.stepLine
	case f.observableLine > 0:
		return f.observableLine
	case f.exitLine > 0:
		return f.exitLine
	}
	return 1
}

func TestTur6Lane08DoneWhenPresence(t *testing.T) {
	root := filepath.Join("..", "skill")
	paths := []string{
		filepath.Join(root, "SKILL.md"),
		filepath.Join(root, "README.md"),
	}
	if refs, err := filepath.Glob(filepath.Join(root, "references", "*.md")); err == nil {
		paths = append(paths, refs...)
	}

	best := "ABSENT"
	bestPath := filepath.Join(root, "SKILL.md")
	var bestFinding tur6Lane08Finding
	readAny := false
	rank := map[string]int{"ABSENT": 0, "PARTIAL": 1, "PRESENT": 2}
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		readAny = true
		f := tur6Lane08Detect(string(b))
		st := tur6Lane08Status(f)
		if rank[st] > rank[best] ||
			(rank[st] == rank[best] && tur6Lane08EvidenceLine(f) > tur6Lane08EvidenceLine(bestFinding)) {
			best = st
			bestFinding = f
			bestPath = p
		}
	}
	if !readAny {
		best = "ABSENT"
	}
	evidence := bestPath + ":" + strconv.Itoa(tur6Lane08EvidenceLine(bestFinding))
	t.Logf("FIELD=done_when STATUS=%s evidence=%s", best, evidence)
	t.Logf("DETAIL heading=%d identify=%d unpack=%d recover=%d prove=%d observable=%d exit=%d",
		bestFinding.doneHeadingLine, bestFinding.stepNames["identify"],
		bestFinding.stepNames["unpack"], bestFinding.stepNames["recover"],
		bestFinding.stepNames["prove"], bestFinding.observableLine, bestFinding.exitLine)
}

func TestTur6Lane08DetectorAccuracy(t *testing.T) {
	present := "## Done when\n" +
		"- **Identify**: `lrecon --json T` printed, `kind` named, one Route row run, then stop.\n" +
		"- **Unpack**: every layer is named in `LAYERS:` or `partial` names the unknown.\n" +
		"- **Recover**: a byte patch shows `EVIDENCE: 0x<offset>` plus before/after bytes.\n" +
		"- **Prove**: one verification run, then stop; `solved` only with that artifact.\n" +
		"- A verdict exits with no further probes.\n"
	cases := []struct {
		name, text, want string
	}{
		{"present", present, "PRESENT"},
		{"partial-heading-only", "# Random\n## Done when\nno steps listed here\n", "PARTIAL"},
		{"partial-exit-only", "# Random\nA verdict exits with no further probes.\n", "PARTIAL"},
		{"absent", "# Random\nplain text, no completion criteria here\n", "ABSENT"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := tur6Lane08Status(tur6Lane08Detect(c.text)); got != c.want {
				t.Fatalf("tur6Lane08Status = %s, want %s", got, c.want)
			}
		})
	}
}
