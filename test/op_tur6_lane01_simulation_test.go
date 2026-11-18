package main

// Tur 6 lane 01: "Setup ile başlama yasağı" alanını doğrudan skill metninden
// okuyup simüle eden probe. Bulgu loglanır; test her durumda yeşil kalır.

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

type tur6L01Finding struct {
	setupLine int
	banLine   int
	idLine    int
}

// "Setup ilk adım olamaz" yasağının gözlenebilir dili.
var tur6L01BanPhrases = []string{
	"no setup or toolchain",
	"setup only if the digest demands",
	"setup only if",
	"ceremony precedes",
	"do not start with setup",
	"never start with setup",
	"not before the digest",
}

// Kimlik önce, Setup sonra sırasını gösteren dil.
var tur6L01IdPhrases = []string{
	"identification only",
	"identification, not setup",
	"is identification",
	"no digest, no probe",
}

func tur6L01Any(hay string, needles []string) bool {
	for _, n := range needles {
		if strings.Contains(hay, n) {
			return true
		}
	}
	return false
}

// tur6L01Detect ham metni tarar; 1-tabanlı satır numaraları döndürür (0 = yok).
func tur6L01Detect(text string) tur6L01Finding {
	var f tur6L01Finding
	for i, raw := range strings.Split(text, "\n") {
		ln := strings.ToLower(strings.TrimSpace(raw))
		line := i + 1
		if f.setupLine == 0 && (strings.HasPrefix(ln, "## step 0: setup") || strings.HasPrefix(ln, "# setup") || strings.HasPrefix(ln, "## setup")) {
			f.setupLine = line
		}
		if f.banLine == 0 && tur6L01Any(ln, tur6L01BanPhrases) {
			f.banLine = line
		}
		if f.idLine == 0 && tur6L01Any(ln, tur6L01IdPhrases) {
			f.idLine = line
		}
	}
	return f
}

func tur6L01Status(f tur6L01Finding) string {
	if f.banLine > 0 && (f.setupLine > 0 || f.idLine > 0) {
		return "PRESENT"
	}
	if f.banLine > 0 || f.idLine > 0 || f.setupLine > 0 {
		return "PARTIAL"
	}
	return "ABSENT"
}

func TestTur6Lane01NoSetupFirstPresence(t *testing.T) {
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
		f := tur6L01Detect(string(b))
		st := tur6L01Status(f)
		if rank[st] > rank[best] {
			best = st
			line := 1
			switch {
			case f.banLine > 0:
				line = f.banLine
			case f.idLine > 0:
				line = f.idLine
			case f.setupLine > 0:
				line = f.setupLine
			}
			evidence = p + ":" + strconv.Itoa(line)
		}
	}
	if !readAny {
		best = "ABSENT"
	}
	t.Logf("FIELD=no_setup_first STATUS=%s evidence=%s", best, evidence)
}

func TestTur6Lane01DetectorAccuracy(t *testing.T) {
	cases := []struct {
		name, text, want string
	}{
		{"present", "## Step 0: Setup\nStep 0 is identification only; no setup or toolchain ceremony precedes it — setup only if the digest demands it\n", "PRESENT"},
		{"present-min", "## Setup\n--version is identification, not setup\nno setup or toolchain ceremony precedes it\n", "PRESENT"},
		{"partial-heading-only", "## Step 0: Setup\nrun the toolchain installer\n", "PARTIAL"},
		{"partial-ban-only", "no setup or toolchain ceremony precedes it\n", "PARTIAL"},
		{"absent", "# Random\nplain text, setup whenever you like\n", "ABSENT"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := tur6L01Status(tur6L01Detect(c.text)); got != c.want {
				t.Fatalf("tur6L01Status = %s, want %s", got, c.want)
			}
		})
	}
}
