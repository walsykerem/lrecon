package main

// Tur 6 lane 21: "Gate Entry/Exit kriterlerinin somutluğu" alanını doğrudan
// skill metninden okuyup simüle eden probe. Bulgu loglanır; test her durumda
// yeşil kalır.

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

type tur6Lane21Finding struct {
	gateLine  int  // "## Gate" başlığı
	entryLine int  // "- **Entry** — ..." satırı
	exitLine  int  // "- **Exit** — ..." satırı
	entryConc bool // Entry satırında doğrulanabilir somut sinyal
	exitConc  bool // Exit satırında doğrulanabilir somut sinyal
}

// Entry kriterini somut yaran gözlenebilir belirteçler.
var tur6Lane21EntryTokens = []string{
	"$lrecon", "--version", "--json", "lrecon 1.0.0", "exit 2", "{\"op\":null", "stderr",
}

// Exit kriterini somut yaran gözlenebilir belirteçler (çıktı alan adları).
var tur6Lane21ExitTokens = []string{
	"kind", "layers", "verdict", "evidence", "done-when", "self-lint",
}

func tur6Lane21ContainsAny(hay string, needles []string) bool {
	for _, n := range needles {
		if strings.Contains(hay, n) {
			return true
		}
	}
	return false
}

// tur6Lane21Concrete: satırda en az bir backtick çifti (komut/değer) VE
// alana özgü doğrulanabilir belirteç var mı?
func tur6Lane21Concrete(line string, tokens []string) bool {
	if strings.Count(line, "`") < 2 {
		return false
	}
	return tur6Lane21ContainsAny(line, tokens)
}

// tur6Lane21Detect ham metni tarar; 1-tabanlı satır numaraları döndürür (0 = yok).
func tur6Lane21Detect(text string) tur6Lane21Finding {
	var f tur6Lane21Finding
	for i, raw := range strings.Split(text, "\n") {
		ln := strings.ToLower(strings.TrimSpace(raw))
		line := i + 1
		if f.gateLine == 0 && (ln == "## gate" || ln == "# gate") {
			f.gateLine = line
			continue
		}
		rest := strings.TrimPrefix(ln, "- ")
		if f.entryLine == 0 && (strings.HasPrefix(rest, "**entry**") || strings.HasPrefix(ln, "entry —") || strings.HasPrefix(ln, "entry:")) {
			f.entryLine = line
			f.entryConc = tur6Lane21Concrete(ln, tur6Lane21EntryTokens)
			continue
		}
		if f.exitLine == 0 && (strings.HasPrefix(rest, "**exit**") || strings.HasPrefix(ln, "exit —") || strings.HasPrefix(ln, "exit:")) {
			f.exitLine = line
			f.exitConc = tur6Lane21Concrete(ln, tur6Lane21ExitTokens)
		}
	}
	return f
}

// tur6Lane21Status: PRESENT = Gate + Entry + Exit + ikisinin de somut/doğrulanabilir
// olması. Bir kriter eksik veya soyutsa PARTIAL. Gate yoksa ABSENT.
func tur6Lane21Status(f tur6Lane21Finding) string {
	if f.gateLine == 0 {
		return "ABSENT"
	}
	if f.entryLine > 0 && f.exitLine > 0 && f.entryConc && f.exitConc {
		return "PRESENT"
	}
	return "PARTIAL"
}

func tur6Lane21EvidenceLine(f tur6Lane21Finding) int {
	switch {
	case f.entryLine > 0:
		return f.entryLine
	case f.exitLine > 0:
		return f.exitLine
	case f.gateLine > 0:
		return f.gateLine
	}
	return 1
}

func TestTur6Lane21EntryExitCriteriaPresence(t *testing.T) {
	root := filepath.Join("..", "skill")
	paths := []string{filepath.Join(root, "SKILL.md"), filepath.Join(root, "README.md")}
	if refs, err := filepath.Glob(filepath.Join(root, "references", "*.md")); err == nil {
		paths = append(paths, refs...)
	}

	best := "ABSENT"
	evidence := filepath.Join(root, "SKILL.md") + ":1"
	var bestFinding tur6Lane21Finding
	readAny := false
	rank := map[string]int{"ABSENT": 0, "PARTIAL": 1, "PRESENT": 2}
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		readAny = true
		f := tur6Lane21Detect(string(b))
		st := tur6Lane21Status(f)
		if rank[st] > rank[best] {
			best = st
			bestFinding = f
			evidence = p + ":" + strconv.Itoa(tur6Lane21EvidenceLine(f))
		}
	}
	if !readAny {
		best = "ABSENT"
	}
	t.Logf("FIELD=entry_exit_criteria STATUS=%s evidence=%s", best, evidence)
	t.Logf("DETAIL gate=%d entry=%d exit=%d entry_concrete=%t exit_concrete=%t",
		bestFinding.gateLine, bestFinding.entryLine, bestFinding.exitLine,
		bestFinding.entryConc, bestFinding.exitConc)
}

func TestTur6Lane21DetectorAccuracy(t *testing.T) {
	cases := []struct {
		name, text, want string
	}{
		{
			"present",
			"## Gate\n" +
				"- **Entry** — `LRECON=${LRECON:-./lrecon/lrecon}`; `lrecon --version` is `lrecon 1.0.0`; `lrecon --json T` printed; failed digest is exit 2\n" +
				"- **Exit** — `Output` filled: `KIND`, `LAYERS`, `VERDICT`, `EVIDENCE` `0x<offset>`; self-lint via `references/limits.md#done-when`\n",
			"PRESENT",
		},
		{
			"partial-vague-entry",
			"## Gate\n" +
				"- **Entry** — make sure everything is ready before starting\n" +
				"- **Exit** — `Output` filled: `KIND`, `LAYERS`, `VERDICT`, `EVIDENCE`\n",
			"PARTIAL",
		},
		{
			"partial-missing-exit",
			"## Gate\n" +
				"- **Entry** — `LRECON=...`; `lrecon --version` is `lrecon 1.0.0`; `--json T` printed; exit 2\n",
			"PARTIAL",
		},
		{
			"partial-gate-only",
			"## Gate\nplain prose about rules\n",
			"PARTIAL",
		},
		{
			"absent",
			"# Random\nplain text, no gate section here\n",
			"ABSENT",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := tur6Lane21Status(tur6Lane21Detect(c.text)); got != c.want {
				t.Fatalf("tur6Lane21Status = %s, want %s", got, c.want)
			}
		})
	}
}
