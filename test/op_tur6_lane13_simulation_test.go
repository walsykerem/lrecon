package main

// Tur 6 lane 13: guard. Reads the walsyrea skill text directly and weighs
// flexible-exploration language ("flexible", "adapt", "choose", "as needed",
// "when needed", "if applicable", "judgment", "optional", ...) against rigid,
// ritual language ("always", "must", "never", "exactly", "ritual", ...).
// The real skill must grade PRESENT; the grader is pinned by the detector
// accuracy test.

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

var tur6Lane13FlexPhrases = []string{
	"flexible", "adapt", "choose", "as needed", "when needed", "if applicable",
	"judgment", "where appropriate", "optional", "alternative", "either",
	"may use", "can use", "at your discretion",
}

var tur6Lane13RigidPhrases = []string{
	"always", "must", "never", "exactly", "forced", "ritual",
	"refusal or an order", "the only", "no other",
}

type tur6Lane13Finding struct {
	flexCount  int
	rigidCount int
	firstFlex  int // 1-based line of the first flexibility marker (0 = none)
	firstRigid int // 1-based line of the first rigidity marker (0 = none)
}

func tur6Lane13CountAny(low string, needles []string) int {
	n := 0
	for _, p := range needles {
		if strings.Contains(low, p) {
			n++
		}
	}
	return n
}

// tur6Lane13Detect scans raw skill text and counts distinct flexibility and
// rigidity phrases, recording the first line of each.
func tur6Lane13Detect(text string) tur6Lane13Finding {
	var f tur6Lane13Finding
	for i, raw := range strings.Split(text, "\n") {
		low := strings.ToLower(raw)
		line := i + 1
		if c := tur6Lane13CountAny(low, tur6Lane13FlexPhrases); c > 0 {
			f.flexCount += c
			if f.firstFlex == 0 {
				f.firstFlex = line
			}
		}
		if c := tur6Lane13CountAny(low, tur6Lane13RigidPhrases); c > 0 {
			f.rigidCount += c
			if f.firstRigid == 0 {
				f.firstRigid = line
			}
		}
	}
	return f
}

// tur6Lane13Status: ABSENT = no flexibility language at all.
// PARTIAL = some flexibility, but rigid/ritual language dominates or a single
// weak aside only. PRESENT = flexibility is offered and not swamped by ritual.
func tur6Lane13Status(f tur6Lane13Finding) string {
	if f.flexCount == 0 {
		return "ABSENT"
	}
	if f.flexCount < 2 || f.rigidCount > f.flexCount*2 {
		return "PARTIAL"
	}
	return "PRESENT"
}

func tur6Lane13EvidenceLine(f tur6Lane13Finding) int {
	if f.firstFlex > 0 {
		return f.firstFlex
	}
	if f.firstRigid > 0 {
		return f.firstRigid
	}
	return 1
}

func TestTur6Lane13FlexibleExplorationPresence(t *testing.T) {
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
	var bestFinding tur6Lane13Finding
	readAny := false
	rank := map[string]int{"ABSENT": 0, "PARTIAL": 1, "PRESENT": 2}
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		readAny = true
		f := tur6Lane13Detect(string(b))
		st := tur6Lane13Status(f)
		if rank[st] > rank[best] ||
			(rank[st] == rank[best] && (f.flexCount > bestFinding.flexCount ||
				(f.flexCount == bestFinding.flexCount && f.rigidCount > bestFinding.rigidCount))) {
			best = st
			bestFinding = f
			evidence = p + ":" + strconv.Itoa(tur6Lane13EvidenceLine(f))
		}
	}
	if !readAny {
		best = "ABSENT"
	}
	t.Logf("FIELD=flexible_exploration STATUS=%s evidence=%s", best, evidence)
	t.Logf("DETAIL flex_count=%d rigid_count=%d first_flex=%d first_rigid=%d",
		bestFinding.flexCount, bestFinding.rigidCount,
		bestFinding.firstFlex, bestFinding.firstRigid)
	if best != "PRESENT" {
		t.Errorf("skill flexible_exploration=%s (flex=%d rigid=%d), want PRESENT", best,
			bestFinding.flexCount, bestFinding.rigidCount)
	}
}

func TestTur6Lane13DetectorAccuracy(t *testing.T) {
	cases := []struct {
		name, text, want string
	}{
		{
			"present-flexible",
			"Choose either path as needed. Adapt the ritual to the target; use judgment where appropriate. Optional steps are fine.\n",
			"PRESENT",
		},
		{
			"present-choose-adapt",
			"Choose the probe that fits, adapt to what the target actually needs, an alternative when the digest points elsewhere.\n",
			"PRESENT",
		},
		{
			"partial-flex-outweighed",
			"Choose and adapt. You must always follow the ritual exactly; never deviate; the only path is forced.\n",
			"PARTIAL",
		},
		{
			"partial-weak-aside",
			"Run the tool when needed.\nYou must always follow the ritual exactly; never deviate.\n",
			"PARTIAL",
		},
		{
			"absent-rigid-only",
			"You must always do X. Never deviate. Do it exactly once, forced by the ritual.\n",
			"ABSENT",
		},
		{
			"absent-plain",
			"# Random\nplain procedural text with no choice language here\n",
			"ABSENT",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := tur6Lane13Status(tur6Lane13Detect(c.text)); got != c.want {
				t.Fatalf("tur6Lane13Status = %s, want %s", got, c.want)
			}
		})
	}
}
