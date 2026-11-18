package main

// Tur 6 lane 19: probe. Reads the walsyrea skill text directly and detects a
// lint script/instruction that audits SKILL.md itself: a tool whose stated
// purpose checks SKILL.md (sections/pin/coverage/trigger routing), the in-skill
// self-lint instruction, and an actual verification invocation. Finding is
// logged only; the test stays green regardless of outcome.

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

type tur6Lane19Finding struct {
	lintScriptLine int // a tool/script whose job is to check SKILL.md
	selfLintLine   int // the in-skill self-lint / re-lint instruction
	invocationLine int // a verification command that runs the SKILL.md checker
}

// lintScriptPhrases: a script or tool that audits SKILL.md itself.
var tur6Lane19LintScriptPhrases = []string{
	"skill_contract.py",
	"trigger_check.py",
	"skill.md sections",
	"route to skill.md",
	"routes to skill.md",
	"validates skill.md",
	"validate skill.md",
	"checks skill.md",
	"check skill.md",
	"audits skill.md",
	"audit skill.md",
	"skill.md coverage",
	"verify skill.md",
}

// selfLintPhrases: the skill's own self-lint / re-lint instruction.
var tur6Lane19SelfLintPhrases = []string{
	"self-lint",
	"self lint",
	"self-check",
	"re-lint",
}

// invocationPhrases: a concrete verification command running the SKILL.md checker.
var tur6Lane19InvocationPhrases = []string{
	"python3 tools/skill_contract.py",
	"python3 tools/trigger_check.py",
	"tools/skill_contract.py",
	"tools/trigger_check.py",
}

func tur6Lane19ContainsAny(hay string, needles []string) bool {
	for _, n := range needles {
		if n != "" && strings.Contains(hay, n) {
			return true
		}
	}
	return false
}

// tur6Lane19Detect scans raw skill text and returns 1-based line numbers
// (0 = none) for the SKILL.md-auditing script, the self-lint instruction,
// and the verification invocation.
func tur6Lane19Detect(text string) tur6Lane19Finding {
	var f tur6Lane19Finding
	for i, raw := range strings.Split(text, "\n") {
		ln := strings.ToLower(strings.TrimSpace(raw))
		line := i + 1
		if f.lintScriptLine == 0 && tur6Lane19ContainsAny(ln, tur6Lane19LintScriptPhrases) {
			f.lintScriptLine = line
		}
		if f.selfLintLine == 0 && tur6Lane19ContainsAny(ln, tur6Lane19SelfLintPhrases) {
			f.selfLintLine = line
		}
		if f.invocationLine == 0 && tur6Lane19ContainsAny(ln, tur6Lane19InvocationPhrases) {
			f.invocationLine = line
		}
	}
	return f
}

// tur6Lane19Status: PRESENT needs a SKILL.md-auditing script plus either the
// in-skill self-lint instruction or a real verification invocation. Only one
// signal -> PARTIAL. No SKILL.md-check signal -> ABSENT.
func tur6Lane19Status(f tur6Lane19Finding) string {
	if f.lintScriptLine == 0 && f.selfLintLine == 0 && f.invocationLine == 0 {
		return "ABSENT"
	}
	if f.lintScriptLine > 0 && (f.selfLintLine > 0 || f.invocationLine > 0) {
		return "PRESENT"
	}
	return "PARTIAL"
}

func tur6Lane19EvidenceLine(f tur6Lane19Finding) int {
	switch {
	case f.lintScriptLine > 0:
		return f.lintScriptLine
	case f.invocationLine > 0:
		return f.invocationLine
	case f.selfLintLine > 0:
		return f.selfLintLine
	}
	return 1
}

func TestTur6Lane19SelfLintSkillmdPresence(t *testing.T) {
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
	var bestFinding tur6Lane19Finding
	readAny := false
	rank := map[string]int{"ABSENT": 0, "PARTIAL": 1, "PRESENT": 2}
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		readAny = true
		f := tur6Lane19Detect(string(b))
		st := tur6Lane19Status(f)
		if rank[st] > rank[best] {
			best = st
			bestFinding = f
			evidence = p + ":" + strconv.Itoa(tur6Lane19EvidenceLine(f))
		}
	}
	if !readAny {
		best = "ABSENT"
	}
	t.Logf("FIELD=self_lint_skillmd STATUS=%s evidence=%s", best, evidence)
	t.Logf("DETAIL lint_script=%d self_lint=%d invocation=%d",
		bestFinding.lintScriptLine, bestFinding.selfLintLine, bestFinding.invocationLine)
}

func TestTur6Lane19DetectorAccuracy(t *testing.T) {
	cases := []struct {
		name, text, want string
	}{
		{
			"present-script-and-instruction",
			"# Skill\nBefore Output, self-lint: Identify, Unpack, Recover, Prove.\n" +
				"| skill_contract.py | SKILL.md sections, pin, op/ext-op coverage |\n",
			"PRESENT",
		},
		{
			"present-script-and-invocation",
			"| trigger_check.py | skill trigger phrases route to SKILL.md |\n" +
				"python3 tools/skill_contract.py && python3 tools/release_gate.py\n",
			"PRESENT",
		},
		{
			"partial-script-only",
			"| skill_contract.py | SKILL.md sections, pin, coverage |\nplain prose\n",
			"PARTIAL",
		},
		{
			"partial-self-lint-only",
			"Before Output, self-lint: Identify artifact, Unpack, Recover, Prove.\n",
			"PARTIAL",
		},
		{
			"absent-unrelated",
			"# Random\nplain text, no SKILL.md checker here\n",
			"ABSENT",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := tur6Lane19Status(tur6Lane19Detect(c.text)); got != c.want {
				t.Fatalf("tur6Lane19Status = %s, want %s", got, c.want)
			}
		})
	}
}
