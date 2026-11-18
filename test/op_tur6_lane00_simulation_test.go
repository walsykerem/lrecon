package main

// Tur 6 lane 00: probe. Reads the walsyrea skill text directly and detects
// Goal / Gate (entry + exit, no step past the gate) language. Finding is logged
// only; the test stays green regardless of outcome.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type tur6GateFinding struct {
	goalLine int
	gateLine int
	langLine int
}

var tur6GatePhrases = []string{
	"must not proceed",
	"do not proceed",
	"no digest, no probe",
	"no re-run",
	"one probe, one result",
	"before output",
	"stop / no re-run",
	"exit gate",
	"**entry**",
	"**exit**",
	"no second probe",
}

func tur6ContainsAny(hay string, needles []string) bool {
	for _, n := range needles {
		if strings.Contains(hay, n) {
			return true
		}
	}
	return false
}

// tur6Detect scans raw skill text and returns line numbers (1-based, 0 = none)
// for a Goal heading, a Gate/Exit-gate heading, and observable gate language.
func tur6Detect(text string) tur6GateFinding {
	var f tur6GateFinding
	for i, raw := range strings.Split(text, "\n") {
		ln := strings.ToLower(strings.TrimSpace(raw))
		line := i + 1
		if f.goalLine == 0 && (strings.HasPrefix(ln, "## goal") || strings.HasPrefix(ln, "# goal") || strings.HasPrefix(ln, "### goal")) {
			f.goalLine = line
		}
		if f.gateLine == 0 && (strings.HasPrefix(ln, "## gate") || strings.HasPrefix(ln, "# gate") ||
			strings.HasPrefix(ln, "## exit gate") || strings.HasPrefix(ln, "# exit gate") || strings.HasPrefix(ln, "### exit gate")) {
			f.gateLine = line
		}
		if f.langLine == 0 && tur6ContainsAny(ln, tur6GatePhrases) {
			f.langLine = line
		}
	}
	return f
}

func tur6Status(f tur6GateFinding) string {
	if f.goalLine > 0 && f.gateLine > 0 && f.langLine > 0 {
		return "PRESENT"
	}
	if f.goalLine > 0 || f.gateLine > 0 || f.langLine > 0 {
		return "PARTIAL"
	}
	return "ABSENT"
}

func TestTur6Lane00GoalGatePresence(t *testing.T) {
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
	var bestFinding tur6GateFinding
	readAny := false
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		readAny = true
		f := tur6Detect(string(b))
		st := tur6Status(f)
		// Rank PRESENT > PARTIAL > ABSENT; keep the file that carries the gate.
		rank := map[string]int{"ABSENT": 0, "PARTIAL": 1, "PRESENT": 2}
		if rank[st] > rank[best] || (rank[st] == rank[best] && f.gateLine > 0 && bestFinding.gateLine == 0) {
			best = st
			bestFinding = f
			line := 1
			switch {
			case f.gateLine > 0:
				line = f.gateLine
			case f.langLine > 0:
				line = f.langLine
			case f.goalLine > 0:
				line = f.goalLine
			}
			evidence = p + ":" + itoa(line)
		}
	}
	if !readAny {
		best = "ABSENT"
	}
	t.Logf("FIELD=goal_gate STATUS=%s evidence=%s", best, evidence)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

func TestTur6Lane00DetectorAccuracy(t *testing.T) {
	cases := []struct {
		name, text, want string
	}{
		{"present", "## Goal\nname the layer\n## Gate\n- **Entry** no digest, no probe\n- **Exit** before Output, stop / no re-run before VERDICT\n", "PRESENT"},
		{"partial-goal-only", "# Random\n## Goal\nname the layer\n", "PARTIAL"},
		{"partial-lang-only", "# Random\nno digest, no probe\n", "PARTIAL"},
		{"absent", "# Random\nplain text, no gate here\n", "ABSENT"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := tur6Status(tur6Detect(c.text)); got != c.want {
				t.Fatalf("tur6Status = %s, want %s", got, c.want)
			}
		})
	}
}
