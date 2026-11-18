package main

// Tur 6 lane 26: "verification_script_link" (skill doğrulama için somut
// script/komutlara referans veriyor mu?) alanını doğrudan skill metninden
// okuyup simüle eden probe. Bulgu loglanır; test her durumda yeşil kalır.

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

type tur6L26Finding struct {
	cats         int // distinct verification-script/command categories matched
	evidenceLine int // 1-based line with the most categories (first on tie)
	lineCats     int
}

// Each group is one kind of concrete verification-script/command reference.
var tur6L26Groups = [][]string{
	{"python3 tools/", "python tools/", "python3 scripts/", "python scripts/"},
	{".py"},
	{"--check"},
	{"go test"},
	{"go build"},
	{"bash scripts/", "sh scripts/", "bash tools/"},
	{"self-test", "selftest"},
	{"make test", "make check", "make all", "$ make"},
}

func tur6L26Any(hay string, needles []string) bool {
	for _, n := range needles {
		if strings.Contains(hay, n) {
			return true
		}
	}
	return false
}

// tur6L26Detect ham metni tarar; kategori sayısı ve en güçlü kanıt satırını döndürür.
func tur6L26Detect(text string) tur6L26Finding {
	seen := make(map[int]bool)
	var f tur6L26Finding
	for i, raw := range strings.Split(text, "\n") {
		line := i + 1
		ln := strings.ToLower(raw)
		n := 0
		for gi, group := range tur6L26Groups {
			if seen[gi] {
				continue
			}
			if tur6L26Any(ln, group) {
				seen[gi] = true
				n++
			}
		}
		if n > f.lineCats {
			f.lineCats = n
			f.evidenceLine = line
		}
	}
	f.cats = len(seen)
	return f
}

func tur6L26Status(f tur6L26Finding) string {
	switch {
	case f.cats >= 2:
		return "PRESENT"
	case f.cats == 1:
		return "PARTIAL"
	default:
		return "ABSENT"
	}
}

func TestTur6Lane26VerificationScriptLinkPresence(t *testing.T) {
	root := filepath.Join("..", "skill")
	paths := []string{filepath.Join(root, "SKILL.md"), filepath.Join(root, "README.md")}
	if refs, err := filepath.Glob(filepath.Join(root, "references", "*.md")); err == nil {
		paths = append(paths, refs...)
	}
	if scripts, err := filepath.Glob(filepath.Join(root, "scripts", "*")); err == nil {
		paths = append(paths, scripts...)
	}

	best := "ABSENT"
	bestCats := -1
	evidence := filepath.Join(root, "SKILL.md") + ":1"
	rank := map[string]int{"ABSENT": 0, "PARTIAL": 1, "PRESENT": 2}
	readAny := false
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		info, err := os.Stat(p)
		if err != nil || info.IsDir() {
			continue
		}
		readAny = true
		f := tur6L26Detect(string(b))
		st := tur6L26Status(f)
		if rank[st] > rank[best] || (rank[st] == rank[best] && f.cats > bestCats) {
			best = st
			bestCats = f.cats
			line := f.evidenceLine
			if line == 0 {
				line = 1
			}
			evidence = p + ":" + strconv.Itoa(line)
		}
	}
	if !readAny {
		best = "ABSENT"
	}
	t.Logf("FIELD=verification_script_link STATUS=%s evidence=%s", best, evidence)
}

func TestTur6Lane26DetectorAccuracy(t *testing.T) {
	cases := []struct {
		name, text, want string
	}{
		{"present", "## Verification\n\ncd lrecon && go test ./...\npython3 tools/skill_contract.py --check\n", "PRESENT"},
		{"present-alt", "python3 tools/op_smoke.py --check\n", "PRESENT"},
		{"partial-self-test", "Run the self-test.\n", "PARTIAL"},
		{"partial-go-only", "cd lrecon && go test ./...\n", "PARTIAL"},
		{"absent", "## Route\n| macho | otool -l T |\n", "ABSENT"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := tur6L26Status(tur6L26Detect(c.text)); got != c.want {
				t.Fatalf("tur6L26Status = %s, want %s", got, c.want)
			}
		})
	}
}
