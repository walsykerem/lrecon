package main

// Tur 6 lane 27: probe. Reads the walsyrea skill text directly and detects a
// programmatic, machine-readable JSON contract: a fixed contract_version, a
// fixed JSON digest/op envelope with named keys, and on-disk stage artifacts
// with a fixed suffix convention (.digest.json / .op-<op>.json / .proof.txt).
// Finding is logged only; the test stays green regardless of outcome.

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

type tur6Lane27Finding struct {
	versionLine  int // fixed "contract_version: 1" contract marker
	envelopeLine int // JSON envelope / fixed digest keys / --json machine-readable mode
	artifactLine int // .digest.json / .op-<op>.json / .proof.txt stage naming
}

var tur6Lane27VersionPhrases = []string{
	"contract_version: 1",
	"contract_version:1",
	"fixed at `contract_version",
	"defaults are explicit",
}

var tur6Lane27EnvelopePhrases = []string{
	"machine-readable",
	"digest keys are fixed",
	"top-level keys",
	"one envelope on **stdout**",
	"json envelope on **stdout**",
	"{\"contract_version\":1",
	"`--json` = the same",
	"keys machine-readable",
}

var tur6Lane27ArtifactPhrases = []string{
	".digest.json",
	".op-<op>.json",
	".op-",
	".proof.txt",
	"one file per stage",
	"naming is the contract",
}

func tur6Lane27ContainsAny(hay string, needles []string) bool {
	for _, n := range needles {
		if strings.Contains(hay, n) {
			return true
		}
	}
	return false
}

// tur6Lane27Detect scans raw skill text and returns 1-based line numbers
// (0 = none) for the fixed contract version, the JSON envelope/fixed-keys
// machine-readable declaration, and the on-disk stage artifact naming.
func tur6Lane27Detect(text string) tur6Lane27Finding {
	var f tur6Lane27Finding
	for i, raw := range strings.Split(text, "\n") {
		ln := strings.ToLower(strings.TrimSpace(raw))
		line := i + 1
		if f.versionLine == 0 && tur6Lane27ContainsAny(ln, tur6Lane27VersionPhrases) {
			f.versionLine = line
		}
		if f.envelopeLine == 0 && tur6Lane27ContainsAny(ln, tur6Lane27EnvelopePhrases) {
			f.envelopeLine = line
		}
		if f.artifactLine == 0 && tur6Lane27ContainsAny(ln, tur6Lane27ArtifactPhrases) {
			f.artifactLine = line
		}
	}
	return f
}

// tur6Lane27Status: PRESENT needs the fixed contract version plus a concrete
// machine-readable shape (JSON envelope / fixed keys, or fixed stage
// artifacts). Version alone -> PARTIAL. No version marker -> ABSENT.
func tur6Lane27Status(f tur6Lane27Finding) string {
	if f.versionLine == 0 {
		return "ABSENT"
	}
	if f.envelopeLine > 0 || f.artifactLine > 0 {
		return "PRESENT"
	}
	return "PARTIAL"
}

func tur6Lane27EvidenceLine(f tur6Lane27Finding) int {
	switch {
	case f.versionLine > 0:
		return f.versionLine
	case f.envelopeLine > 0:
		return f.envelopeLine
	case f.artifactLine > 0:
		return f.artifactLine
	}
	return 1
}

func TestTur6Lane27MachineReadableContractPresence(t *testing.T) {
	root := filepath.Join("..", "skill")
	paths := []string{filepath.Join(root, "SKILL.md")}
	if refs, err := filepath.Glob(filepath.Join(root, "references", "*.md")); err == nil {
		paths = append(paths, refs...)
	}

	best := "ABSENT"
	evidence := filepath.Join(root, "SKILL.md") + ":1"
	var bestFinding tur6Lane27Finding
	readAny := false
	rank := map[string]int{"ABSENT": 0, "PARTIAL": 1, "PRESENT": 2}
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		readAny = true
		f := tur6Lane27Detect(string(b))
		st := tur6Lane27Status(f)
		if rank[st] > rank[best] ||
			(rank[st] == rank[best] && tur6Lane27EvidenceLine(f) > tur6Lane27EvidenceLine(bestFinding)) {
			best = st
			bestFinding = f
			evidence = p + ":" + strconv.Itoa(tur6Lane27EvidenceLine(f))
		}
	}
	if !readAny {
		best = "ABSENT"
	}
	t.Logf("FIELD=machine_readable_contract STATUS=%s evidence=%s", best, evidence)
	t.Logf("DETAIL contract_version=%d json_envelope=%d stage_artifacts=%d",
		bestFinding.versionLine, bestFinding.envelopeLine, bestFinding.artifactLine)
}

func TestTur6Lane27DetectorAccuracy(t *testing.T) {
	cases := []struct {
		name, text, want string
	}{
		{
			"present-version-envelope-artifacts",
			"Defaults explicit: contract_version: 1 in every digest.\n" +
				"Every failure writes one envelope on stdout: {\"contract_version\":1,\"op\",\"error\"}.\n" +
				"T -> $W/<name>.digest.json -> $W/<name>.op-<op>.json -> $W/<name>.proof.txt\n",
			"PRESENT",
		},
		{
			"present-version-and-machine-readable",
			"contract_version: 1; keys are machine-readable, never truncated.\n" +
				"64 top-level keys are the whole digest.\n",
			"PRESENT",
		},
		{
			"present-version-and-artifacts-only",
			"digest keys fixed at contract_version: 1.\n" +
				"naming is the contract: .digest.json and .proof.txt\n",
			"PRESENT",
		},
		{
			"partial-version-only",
			"contract_version: 1 in every digest.\nplain prose, no shape declared\n",
			"PARTIAL",
		},
		{
			"absent-envelope-only",
			"--json = the same keys machine-readable\none envelope on stdout\n",
			"ABSENT",
		},
		{
			"absent-unrelated",
			"# Random\nplain text, no machine-readable contract here\n",
			"ABSENT",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := tur6Lane27Status(tur6Lane27Detect(c.text)); got != c.want {
				t.Fatalf("tur6Lane27Status = %s, want %s", got, c.want)
			}
		})
	}
}
