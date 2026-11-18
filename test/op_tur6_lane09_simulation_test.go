package main

// Tur 6 lane 09: probe. Reads the walsyrea skill text directly and detects
// early-exit / cost-discount gates (cheap-first, short-circuit, "use first
// output and stop", no-re-run). Finding is logged only; test stays green.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type tur6Lane09DiscountFinding struct {
	discountLine int
	exitLine     int
}

var tur6Lane09DiscountPhrases = []string{
	"cheap first",
	"cheap before expensive",
	"cheapest first",
	"cheaply",
	"cheap probes",
	"cost ladder",
	"cheap before",
}

var tur6Lane09ExitPhrases = []string{
	"use the first output and stop",
	"one probe, one result",
	"no re-run",
	"stop / no re-run",
	"no second probe",
	"stop before",
	"one import per query",
	"never start a second",
	"nothing is spawned for a single artifact",
}

func tur6Lane09ContainsAny(hay string, needles []string) bool {
	for _, n := range needles {
		if strings.Contains(hay, n) {
			return true
		}
	}
	return false
}

func tur6Lane09FirstLine(text string, needles []string) int {
	for i, raw := range strings.Split(text, "\n") {
		ln := strings.ToLower(strings.TrimSpace(raw))
		if tur6Lane09ContainsAny(ln, needles) {
			return i + 1
		}
	}
	return 0
}

// tur6Lane09Detect returns 1-based line numbers (0 = none) for the cheapest-
// first discount language and for the short-circuit / no-re-run exit language.
func tur6Lane09Detect(text string) tur6Lane09DiscountFinding {
	return tur6Lane09DiscountFinding{
		discountLine: tur6Lane09FirstLine(text, tur6Lane09DiscountPhrases),
		exitLine:     tur6Lane09FirstLine(text, tur6Lane09ExitPhrases),
	}
}

func tur6Lane09Status(f tur6Lane09DiscountFinding) string {
	if f.discountLine > 0 && f.exitLine > 0 {
		return "PRESENT"
	}
	if f.discountLine > 0 || f.exitLine > 0 {
		return "PARTIAL"
	}
	return "ABSENT"
}

func tur6Lane09EvidenceLine(f tur6Lane09DiscountFinding) int {
	if f.discountLine > 0 {
		return f.discountLine
	}
	return f.exitLine
}

func tur6Lane09Itoa(n int) string {
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

func TestTur6Lane09EarlyExitDiscountPresence(t *testing.T) {
	root := filepath.Join("..", "skill")
	paths := []string{filepath.Join(root, "SKILL.md")}
	if refs, err := filepath.Glob(filepath.Join(root, "references", "*.md")); err == nil {
		paths = append(paths, refs...)
	}

	best := "ABSENT"
	evidence := filepath.Join(root, "SKILL.md") + ":1"
	readAny := false
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		readAny = true
		f := tur6Lane09Detect(string(b))
		st := tur6Lane09Status(f)
		rank := map[string]int{"ABSENT": 0, "PARTIAL": 1, "PRESENT": 2}
		if rank[st] > rank[best] {
			best = st
			evidence = p + ":" + tur6Lane09Itoa(tur6Lane09EvidenceLine(f))
		}
	}
	if !readAny {
		best = "ABSENT"
	}
	t.Logf("FIELD=early_exit_discount STATUS=%s evidence=%s", best, evidence)
}

func TestTur6Lane09DetectorAccuracy(t *testing.T) {
	cases := []struct {
		name, text, want string
	}{
		{"present", "## Runtime rules\ncheap first. Digest, then symbol op, then Ghidra\n## Gate\nno re-run, one probe, one result\n", "PRESENT"},
		{"discount-only", "# Random\ncheapest first, reach the top rung last\n", "PARTIAL"},
		{"exit-only", "# Random\nthe same probe was already run; use the first output and stop\n", "PARTIAL"},
		{"absent", "# Random\nplain text without cost or short-circuit gates\n", "ABSENT"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := tur6Lane09Status(tur6Lane09Detect(c.text)); got != c.want {
				t.Fatalf("tur6Lane09Status = %s, want %s", got, c.want)
			}
		})
	}
}
