package main

// Tur 6 lane 12: guard. Reads the walsyrea SKILL.md body directly and scores
// leanness: repeated phrases, long paragraphs and "ceremonial" constraints are
// dead weight. A lean body has low dead-weight density; the real skill must
// grade PRESENT, and the grader is pinned by TestTur6Lane12DetectorAccuracy.

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

type tur6Lane12Finding struct {
	bodyLines    int
	longLines    int
	dupHits      int
	ceremonyHits int
	dead         int
	density      float64
	evidenceLine int
}

// phrases that, once repeated in the body, count as dead weight
var tur6Lane12RepeatPhrases = []string{
	"no re-run",
	"(checked)",
	"one artifact",
	"one layer",
	"stop",
	"one run",
}

// "ceremonial" constraints: present once they already add body weight
var tur6Lane12CeremonyPhrases = []string{
	"one probe, one result",
	"self-lint",
	"no fake",
	"one artifact in, one verdict out",
	"stop / no re-run",
	"to the letter",
	"keep scope exact",
}

const tur6Lane12LongLine = 300

// tur6Lane12Detect strips YAML frontmatter, then measures dead weight in the
// remaining body: over-long lines, repeated phrases (occurrences past the
// first) and ceremonial constraints. Density = dead / bodyLines.
func tur6Lane12Detect(text string) tur6Lane12Finding {
	raw := strings.Split(text, "\n")

	// locate frontmatter end (second line that is exactly ---)
	start := 0
	if len(raw) > 0 && strings.TrimSpace(raw[0]) == "---" {
		for i := 1; i < len(raw); i++ {
			if strings.TrimSpace(raw[i]) == "---" {
				start = i + 1
				break
			}
		}
	}

	f := tur6Lane12Finding{evidenceLine: 1}
	var lowered []string
	for i := start; i < len(raw); i++ {
		trimmed := strings.TrimSpace(raw[i])
		if trimmed == "" {
			continue
		}
		ln := strings.ToLower(trimmed)
		lowered = append(lowered, ln)
		if f.bodyLines == 0 {
			f.evidenceLine = i + 1 // first body line, default evidence
		}
		f.bodyLines++
		if len(trimmed) > tur6Lane12LongLine {
			f.longLines++
			if f.evidenceLine == 0 || (i+1) < f.evidenceLine || f.longLines == 1 {
				f.evidenceLine = i + 1 // first over-long line is the concrete finding
			}
		}
	}

	body := strings.Join(lowered, "\n")
	for _, p := range tur6Lane12RepeatPhrases {
		if n := strings.Count(body, p); n >= 2 {
			f.dupHits += n - 1
		}
	}
	for _, p := range tur6Lane12CeremonyPhrases {
		if strings.Contains(body, p) {
			f.ceremonyHits++
		}
	}
	f.dead = f.longLines + f.dupHits + f.ceremonyHits
	if f.bodyLines > 0 {
		f.density = float64(f.dead) / float64(f.bodyLines)
	}
	return f
}

// tur6Lane12Status grades leanness: low dead-weight density is PRESENT (lean),
// high density is ABSENT (not lean), the middle is PARTIAL.
func tur6Lane12Status(f tur6Lane12Finding) string {
	if f.bodyLines == 0 {
		return "ABSENT"
	}
	switch {
	case f.density < 0.15:
		return "PRESENT"
	case f.density < 0.45:
		return "PARTIAL"
	default:
		return "ABSENT"
	}
}

func TestTur6Lane12LeanBodyPresence(t *testing.T) {
	path := filepath.Join("..", "skill", "SKILL.md")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Logf("FIELD=lean_body STATUS=ABSENT evidence=%s:1", path)
		return
	}
	f := tur6Lane12Detect(string(b))
	status := tur6Lane12Status(f)
	evidence := path + ":" + strconv.Itoa(f.evidenceLine)
	t.Logf("FIELD=lean_body STATUS=%s evidence=%s", status, evidence)
	t.Logf("DETAIL bodyLines=%d longLines=%d dupHits=%d ceremonyHits=%d dead=%d density=%.3f",
		f.bodyLines, f.longLines, f.dupHits, f.ceremonyHits, f.dead, f.density)
	if status != "PRESENT" {
		t.Errorf("skill body lean_body=%s (density=%.3f), want PRESENT (<0.15 dead weight)", status, f.density)
	}
}

func TestTur6Lane12DetectorAccuracy(t *testing.T) {
	long := strings.Repeat("x", tur6Lane12LongLine+1)
	cases := []struct {
		name, text, want string
	}{
		{
			"lean",
			"---\nname: x\n---\n\n# walsyrea\n\n## Goal\nName the layer.\n\n## Route\n| kind | probe |\n|---|---|\n| elf | objdump |\n| pe | objdump |\n",
			"PRESENT",
		},
		{
			"lean-with-one-long-line",
			"---\nname: x\n---\n\n# walsyrea\n\n## Goal\nName the layer.\n\n" + long + "\n\n## Route\n| elf | objdump |\n| pe | objdump |\n| macho | otool |\n",
			"PRESENT",
		},
		{
			"mixed",
			"---\nname: x\n---\n\n# walsyrea\n\n## Gate\n- one probe, one result\n- no re-run\n- **Entry** no re-run\n- (checked)\n- one layer\n- stop\n" + long + "\n",
			"PARTIAL",
		},
		{
			"heavy",
			"---\nname: x\n---\n\n# walsyrea\n\n## Gate\none probe, one result\nself-lint\nno fake\none artifact in, one verdict out\nstop / no re-run\n" + long + "\n" + long + "\n" + long + "\n",
			"ABSENT",
		},
		{"empty-body", "---\nname: x\n---\n", "ABSENT"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := tur6Lane12Status(tur6Lane12Detect(c.text)); got != c.want {
				t.Fatalf("tur6Lane12Status = %s, want %s", got, c.want)
			}
		})
	}
}
