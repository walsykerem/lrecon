package main

// Tur 6 lane 18: probe. Reads the walsyrea skill text directly and detects
// cost/token/spend visibility: a dedicated cost-heading, a "say the cost
// before paying it" disclosure rule, a cheap-before-expensive ordering rule,
// and a concrete time/size budget. Signals are accumulated across all skill
// files because they are distributed (limits.md, contract.md, ghidra.md).
// Finding is logged only; the test stays green regardless of outcome.

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

type tur6Lane18Signal struct {
	path string
	line int
}

type tur6Lane18Finding struct {
	heading    tur6Lane18Signal
	headingPri int // 2 = "cost visibility" section, 1 = "cost ladder" section
	disclose   tur6Lane18Signal
	ordering   tur6Lane18Signal
	budget     tur6Lane18Signal
	consent    tur6Lane18Signal
}

func tur6Lane18ContainsAny(hay string, needles []string) bool {
	for _, n := range needles {
		if strings.Contains(hay, n) {
			return true
		}
	}
	return false
}

func tur6Lane18HasDigit(s string) bool {
	for _, r := range s {
		if r >= '0' && r <= '9' {
			return true
		}
	}
	return false
}

// tur6Lane18Scan folds one file's signals into f, keeping the first line for
// each signal (and the higher-priority heading). 1-based line numbers.
func tur6Lane18Scan(text, path string, f *tur6Lane18Finding) {
	headNeedles := []string{"cost visibility", "cost ladder"}
	discloseNeedles := []string{"say the cost before paying", "state its cost", "announce it", "say the cost"}
	orderNeedles := []string{"cheap before expensive", "cheapest first", "cheap first", "cost ladder"}
	consentNeedles := []string{"explicit go"}
	for i, raw := range strings.Split(text, "\n") {
		ln := strings.ToLower(strings.TrimSpace(raw))
		line := i + 1

		if strings.Contains(ln, "#") && tur6Lane18ContainsAny(ln, headNeedles) {
			pri := 1
			if strings.Contains(ln, "cost visibility") {
				pri = 2
			}
			if pri > f.headingPri {
				f.headingPri = pri
				f.heading = tur6Lane18Signal{path: path, line: line}
			}
		}
		if f.disclose.line == 0 && tur6Lane18ContainsAny(ln, discloseNeedles) {
			f.disclose = tur6Lane18Signal{path: path, line: line}
		}
		if f.ordering.line == 0 && tur6Lane18ContainsAny(ln, orderNeedles) {
			f.ordering = tur6Lane18Signal{path: path, line: line}
		}
		if f.budget.line == 0 && tur6Lane18HasDigit(ln) && strings.Contains(ln, "budget") {
			f.budget = tur6Lane18Signal{path: path, line: line}
		}
		if f.consent.line == 0 && tur6Lane18ContainsAny(ln, consentNeedles) {
			f.consent = tur6Lane18Signal{path: path, line: line}
		}
	}
}

// tur6Lane18Status: PRESENT needs a cost heading, a pre-pay disclosure rule,
// a cheap-first ordering rule and a concrete budget. Any subset -> PARTIAL,
// none -> ABSENT.
func tur6Lane18Status(f tur6Lane18Finding) string {
	if f.heading.line > 0 && f.disclose.line > 0 && f.ordering.line > 0 && f.budget.line > 0 {
		return "PRESENT"
	}
	if f.heading.line > 0 || f.disclose.line > 0 || f.ordering.line > 0 ||
		f.budget.line > 0 || f.consent.line > 0 {
		return "PARTIAL"
	}
	return "ABSENT"
}

func tur6Lane18Evidence(f tur6Lane18Finding) string {
	for _, s := range []tur6Lane18Signal{f.heading, f.disclose, f.budget, f.ordering, f.consent} {
		if s.line > 0 {
			return s.path + ":" + strconv.Itoa(s.line)
		}
	}
	return filepath.Join("..", "skill", "SKILL.md") + ":1"
}

func TestTur6Lane18CostVisibilityPresence(t *testing.T) {
	root := filepath.Join("..", "skill")
	paths := []string{
		filepath.Join(root, "SKILL.md"),
		filepath.Join(root, "README.md"),
	}
	if refs, err := filepath.Glob(filepath.Join(root, "references", "*.md")); err == nil {
		paths = append(paths, refs...)
	}

	var f tur6Lane18Finding
	readAny := false
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		readAny = true
		tur6Lane18Scan(string(b), p, &f)
	}
	best := tur6Lane18Status(f)
	if !readAny {
		best = "ABSENT"
		f = tur6Lane18Finding{}
	}
	t.Logf("FIELD=cost_visibility STATUS=%s evidence=%s", best, tur6Lane18Evidence(f))
	t.Logf("DETAIL heading=%s:%d disclose=%s:%d ordering=%s:%d budget=%s:%d consent=%s:%d",
		f.heading.path, f.heading.line, f.disclose.path, f.disclose.line,
		f.ordering.path, f.ordering.line, f.budget.path, f.budget.line,
		f.consent.path, f.consent.line)
}

func TestTur6Lane18DetectorAccuracy(t *testing.T) {
	present := "## Cost visibility\n" +
		"Say the cost before paying it; announce it, run it once.\n" +
		"Cheap before expensive: digest, then Ghidra.\n" +
		"Ghidra headless pass: 50 s + 12 s/MiB, 30 m cap budget; over budget -> timeout.\n" +
		"Before a multi-minute op, get an explicit go.\n"
	partial := "## Cost ladder\nCheapest first. Reach the top rung only when needed.\n"
	absent := "# Random\nplain text, no cost heading or spend disclosure here\n"
	cases := []struct {
		name, text, want string
	}{
		{"present", present, "PRESENT"},
		{"partial", partial, "PARTIAL"},
		{"absent", absent, "ABSENT"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var f tur6Lane18Finding
			tur6Lane18Scan(c.text, "synthetic.md", &f)
			if got := tur6Lane18Status(f); got != c.want {
				t.Fatalf("tur6Lane18Status = %s, want %s", got, c.want)
			}
		})
	}
}
