package main

// Tur 6 lane 20: "goal_clarity" (skill'in tek bir ana hedefi net tanımlaması)
// alanını doğrudan skill metninden okuyup simüle eden probe. Bulgu loglanır;
// test her durumda yeşil kalır.

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

type tur6L20Finding struct {
	headingLine   int
	statementLine int
}

// Amaç/hedef başlığının gözlenebilir dili (ilk 20 satırda beklenir).
var tur6L20Headings = []string{
	"## goal",
	"# goal",
	"## purpose",
	"# purpose",
	"## objective",
	"# objective",
}

// Tek ve net ana hedefi anlatan cümle kalıpları.
var tur6L20Statements = []string{
	"name the layer",
	"one artifact in, one verdict out",
	"this skill helps",
	"helps you",
	"the goal is",
	"purpose is",
	"objective is",
	"identify, unpack",
}

func tur6L20Any(hay string, needles []string) bool {
	for _, n := range needles {
		if strings.Contains(hay, n) {
			return true
		}
	}
	return false
}

// tur6L20Detect ham metni tarar; 1-tabanlı satır numaraları döndürür (0 = yok).
const tur6L20MaxScan = 20

func tur6L20Detect(text string) tur6L20Finding {
	var f tur6L20Finding
	for i, raw := range strings.Split(text, "\n") {
		line := i + 1
		if line > tur6L20MaxScan {
			break
		}
		ln := strings.ToLower(strings.TrimSpace(raw))
		if f.headingLine == 0 && tur6L20Any(ln, tur6L20Headings) {
			f.headingLine = line
		}
		if f.statementLine == 0 && tur6L20Any(ln, tur6L20Statements) {
			f.statementLine = line
		}
	}
	return f
}

func tur6L20Status(f tur6L20Finding) string {
	if f.headingLine > 0 && f.statementLine > 0 {
		return "PRESENT"
	}
	if f.headingLine > 0 || f.statementLine > 0 {
		return "PARTIAL"
	}
	return "ABSENT"
}

func TestTur6Lane20GoalClarityPresence(t *testing.T) {
	root := filepath.Join("..", "skill")
	paths := []string{filepath.Join(root, "SKILL.md"), filepath.Join(root, "README.md")}
	if refs, err := filepath.Glob(filepath.Join(root, "references", "*.md")); err == nil {
		paths = append(paths, refs...)
	}

	best := "ABSENT"
	evidence := filepath.Join(root, "SKILL.md") + ":1"
	rank := map[string]int{"ABSENT": 0, "PARTIAL": 1, "PRESENT": 2}
	readAny := false
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		readAny = true
		f := tur6L20Detect(string(b))
		st := tur6L20Status(f)
		if rank[st] > rank[best] {
			best = st
			line := 1
			switch {
			case f.statementLine > 0:
				line = f.statementLine
			case f.headingLine > 0:
				line = f.headingLine
			}
			evidence = p + ":" + strconv.Itoa(line)
		}
	}
	if !readAny {
		best = "ABSENT"
	}
	t.Logf("FIELD=goal_clarity STATUS=%s evidence=%s", best, evidence)
}

func TestTur6Lane20DetectorAccuracy(t *testing.T) {
	cases := []struct {
		name, text, want string
	}{
		{"present", "# Skill\n\n## Goal\n\nName the layer an artifact hides behind — or prove there is none.\n", "PRESENT"},
		{"present-alt", "description: This skill helps you unpack a shipped binary.\n## Purpose\nClear single objective.\n", "PRESENT"},
		{"partial-heading-only", "## Goal\n\nTBD.\n", "PARTIAL"},
		{"partial-statement-only", "# Tool\nWe help you with binaries. Name the layer an artifact hides behind.\n", "PARTIAL"},
		{"absent", "## Install\nrun make\nsome unrelated text\n", "ABSENT"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := tur6L20Status(tur6L20Detect(c.text)); got != c.want {
				t.Fatalf("tur6L20Status = %s, want %s", got, c.want)
			}
		})
	}
}
