package main

// Tur 6 lane 02: probe. Reads the walsyrea skill text directly and detects a
// fixed artifact chain plus its filename contract ($W/<name>.digest.json ->
// .op-<op>.json -> .proof.txt, sanitized basename, FOREIGN note for the
// BRIEF.md/specs.json/PLAN.md/src/outputs example). Finding is logged only;
// the test stays green regardless of outcome.

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

type tur6Lane02ChainFinding struct {
	chainLine    int
	digestLine   int
	opLine       int
	proofLine    int
	sanitizeLine int
	foreignLine  int
}

func tur6Lane02ContainsAny(hay string, needles []string) bool {
	for _, n := range needles {
		if strings.Contains(hay, n) {
			return true
		}
	}
	return false
}

// tur6Lane02Detect scans raw skill text and returns 1-based line numbers
// (0 = none) for a fixed-chain declaration, each of the three fixed
// filenames, the sanitized-basename naming rule, and the FOREIGN note.
func tur6Lane02Detect(text string) tur6Lane02ChainFinding {
	var f tur6Lane02ChainFinding
	for i, raw := range strings.Split(text, "\n") {
		ln := strings.ToLower(strings.TrimSpace(raw))
		line := i + 1
		if f.chainLine == 0 && (strings.Contains(ln, "fixed chain") ||
			strings.Contains(ln, "artifact-chain contract")) {
			f.chainLine = line
		}
		if f.digestLine == 0 && strings.Contains(ln, ".digest.json") {
			f.digestLine = line
		}
		if f.opLine == 0 && strings.Contains(ln, ".op-<op>.json") {
			f.opLine = line
		}
		if f.proofLine == 0 && strings.Contains(ln, ".proof.txt") {
			f.proofLine = line
		}
		if f.sanitizeLine == 0 && strings.Contains(ln, "basename") &&
			strings.Contains(ln, "replaced") {
			f.sanitizeLine = line
		}
		if f.foreignLine == 0 && strings.Contains(ln, "brief.md") &&
			strings.Contains(ln, "foreign") {
			f.foreignLine = line
		}
	}
	return f
}

func tur6Lane02Status(f tur6Lane02ChainFinding) string {
	if f.chainLine > 0 && f.digestLine > 0 && f.opLine > 0 && f.proofLine > 0 &&
		f.sanitizeLine > 0 && f.foreignLine > 0 {
		return "PRESENT"
	}
	if f.chainLine > 0 || f.digestLine > 0 || f.opLine > 0 || f.proofLine > 0 ||
		f.sanitizeLine > 0 || f.foreignLine > 0 {
		return "PARTIAL"
	}
	return "ABSENT"
}

func tur6Lane02EvidenceLine(f tur6Lane02ChainFinding) int {
	switch {
	case f.chainLine > 0:
		return f.chainLine
	case f.digestLine > 0:
		return f.digestLine
	case f.opLine > 0:
		return f.opLine
	case f.proofLine > 0:
		return f.proofLine
	case f.sanitizeLine > 0:
		return f.sanitizeLine
	case f.foreignLine > 0:
		return f.foreignLine
	}
	return 1
}

func TestTur6Lane02ArtifactChainPresence(t *testing.T) {
	root := filepath.Join("..", "skill")
	paths := []string{
		filepath.Join(root, "SKILL.md"),
		filepath.Join(root, "README.md"),
	}
	if refs, err := filepath.Glob(filepath.Join(root, "references", "*.md")); err == nil {
		paths = append(paths, refs...)
	}
	if scripts, err := filepath.Glob(filepath.Join(root, "scripts", "*")); err == nil {
		paths = append(paths, scripts...)
	}

	best := "ABSENT"
	evidence := filepath.Join(root, "SKILL.md") + ":1"
	var bestFinding tur6Lane02ChainFinding
	readAny := false
	rank := map[string]int{"ABSENT": 0, "PARTIAL": 1, "PRESENT": 2}
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		readAny = true
		f := tur6Lane02Detect(string(b))
		st := tur6Lane02Status(f)
		if rank[st] > rank[best] ||
			(rank[st] == rank[best] && tur6Lane02EvidenceLine(f) > tur6Lane02EvidenceLine(bestFinding)) {
			best = st
			bestFinding = f
			evidence = p + ":" + strconv.Itoa(tur6Lane02EvidenceLine(f))
		}
	}
	if !readAny {
		best = "ABSENT"
	}
	t.Logf("FIELD=artifact_chain STATUS=%s evidence=%s", best, evidence)
	t.Logf("DETAIL chain=%d digest=%d op=%d proof=%d sanitize=%d foreign=%d",
		bestFinding.chainLine, bestFinding.digestLine, bestFinding.opLine,
		bestFinding.proofLine, bestFinding.sanitizeLine, bestFinding.foreignLine)
}

func TestTur6Lane02DetectorAccuracy(t *testing.T) {
	cases := []struct {
		name, text, want string
	}{
		{
			"present",
			"## Stages\n" +
				"This is the skill's own artifact-chain contract: fixed chain, in this order:\n" +
				"T  ->  $W/<name>.digest.json\n" +
				"   ->  $W/<name>.op-<op>.json\n" +
				"   ->  $W/<name>.proof.txt\n" +
				"`<name>` is the target basename with `[^A-Za-z0-9._-]` replaced by `-`\n" +
				"BRIEF.md/specs.json/PLAN.md/src/outputs FOREIGN (not this skill's chain); native $W chain authoritative.\n",
			"PRESENT",
		},
		{
			"partial-filenames-only",
			"# Random\n" +
				"$W/<name>.digest.json\n$W/<name>.op-<op>.json\n$W/<name>.proof.txt\n",
			"PARTIAL",
		},
		{
			"partial-foreign-only",
			"# Random\nBRIEF.md/specs.json/PLAN.md/src/outputs FOREIGN (not this skill's chain).\n",
			"PARTIAL",
		},
		{
			"absent",
			"# Random\nplain text, no artifact chain here\n",
			"ABSENT",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := tur6Lane02Status(tur6Lane02Detect(c.text)); got != c.want {
				t.Fatalf("tur6Lane02Status = %s, want %s", got, c.want)
			}
		})
	}
}
