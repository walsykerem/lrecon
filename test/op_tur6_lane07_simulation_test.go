package main

// Tur 6 lane 07: probe. Reads the walsyrea skill text directly and detects
// whether negative scope / boundaries are stated at the TOP of the text
// (first 30 lines) via out-of-scope, not-supported, limits, never, do-not
// language. Finding is logged only; the test stays green regardless.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type lane07ScopeFinding struct {
	line    int      // earliest line (1-based) carrying a negative-scope marker
	heading int      // line of a dedicated not-supported / limits / forbidden heading
	markers []string // distinct marker labels seen in the first 30 lines
}

var lane07ScopeMarkers = []struct {
	label, needle string
}{
	{"out_of_scope", "out_of_scope"},
	{"out of scope", "out of scope"},
	{"not supported", "not supported"},
	{"not-supported", "not-supported"},
	{"limits", "limit"},
	{"boundaries", "boundar"},
	{"never", "never"},
	{"do not", "do not"},
	{"no disassembler", "no disassembler"},
	{"not for", "not for"},
	{"refused", "refus"},
	{"dropped", "dropped"},
	{"forbidden", "forbidden"},
}

func lane07Has(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func lane07IsScopeHeading(ln string) bool {
	for _, p := range []string{
		"## not supported", "### not supported", "## hard limits",
		"## forbidden", "## limits", "# limits", "## out of scope",
	} {
		if strings.HasPrefix(ln, p) {
			return true
		}
	}
	return false
}

// lane07DetectScope scans only the first 30 lines for negative-scope language.
func lane07DetectScope(text string) lane07ScopeFinding {
	var f lane07ScopeFinding
	for i, raw := range strings.Split(text, "\n") {
		line := i + 1
		if line > 30 {
			break
		}
		ln := strings.ToLower(strings.TrimSpace(raw))
		for _, m := range lane07ScopeMarkers {
			if strings.Contains(ln, m.needle) {
				if f.line == 0 {
					f.line = line
				}
				if !lane07Has(f.markers, m.label) {
					f.markers = append(f.markers, m.label)
				}
			}
		}
		if f.heading == 0 && lane07IsScopeHeading(ln) {
			f.heading = line
		}
	}
	return f
}

func lane07ScopeStatus(f lane07ScopeFinding) string {
	if f.line == 0 || f.line > 30 {
		return "ABSENT"
	}
	if (f.heading > 0 && f.heading <= 30) || len(f.markers) >= 2 {
		return "PRESENT"
	}
	return "PARTIAL"
}

func lane07Itoa(n int) string {
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

func TestTur6Lane07NegativeScopeTop(t *testing.T) {
	root := filepath.Join("..", "skill")
	// SKILL.md first: on an equal verdict the primary skill text wins.
	paths := []string{
		filepath.Join(root, "SKILL.md"),
		filepath.Join(root, "README.md"),
	}
	if refs, err := filepath.Glob(filepath.Join(root, "references", "*.md")); err == nil {
		paths = append(paths, refs...)
	}

	rank := map[string]int{"ABSENT": 0, "PARTIAL": 1, "PRESENT": 2}
	best := "ABSENT"
	evidence := filepath.Join(root, "SKILL.md") + ":1"
	readAny := false
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		readAny = true
		f := lane07DetectScope(string(b))
		st := lane07ScopeStatus(f)
		// Strict > keeps the first file (SKILL.md) on ties.
		if rank[st] > rank[best] {
			best = st
			line := f.line
			if line == 0 {
				line = f.heading
			}
			if line == 0 {
				line = 1
			}
			evidence = p + ":" + lane07Itoa(line)
		}
	}
	if !readAny {
		best = "ABSENT"
	}
	t.Logf("FIELD=negative_scope_top STATUS=%s evidence=%s", best, evidence)
}

func TestTur6Lane07DetectorAccuracy(t *testing.T) {
	cases := []struct {
		name, text, want string
	}{
		{
			"present-heading",
			"# Skill\n\n## Not supported\nsource repos, live processes\n\nout_of_scope ops are refused by name\n",
			"PRESENT",
		},
		{
			"present-multi-marker-no-heading",
			"# Skill\nNO disassembler, NO demangler. Not for source repos.\nlimits apply; do not re-run\n",
			"PRESENT",
		},
		{
			"partial-single-marker",
			"# Skill\nnever guess the layer\nplain body text\n",
			"PARTIAL",
		},
		{
			"absent-marker-after-30",
			strings.Repeat("filler line\n", 30) + "## Limits\nout_of_scope ops\n",
			"ABSENT",
		},
		{"absent-plain", "# Skill\nplain body text, no scope statement\n", "ABSENT"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := lane07ScopeStatus(lane07DetectScope(c.text)); got != c.want {
				t.Fatalf("lane07ScopeStatus = %s, want %s", got, c.want)
			}
		})
	}
}
