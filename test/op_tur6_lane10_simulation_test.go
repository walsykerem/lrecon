package main

// Tur 6 lane 10: probe. Reads the walsyrea skill text directly and detects
// programmatic output contracts (machine-readable JSON schema, fixed keys,
// closed envelopes) plus the validation/check scripts tied to them. Finding is
// logged only; test stays green.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type tur6Lane10Finding struct {
	contractLine int
	checkLine    int
}

// contractPhrases: signals of a machine-readable, programmatically checkable
// output contract (schema version, fixed keys, JSON envelope, closed kinds).
var tur6Lane10ContractPhrases = []string{
	"machine-readable",
	"contract_version",
	"json envelope",
	"envelope on stdout",
	"one envelope on",
	"keys are fixed",
	"keys machine-readable",
	"fixed at",
}

// checkPhrases: signals of validation/check scripts bound to that contract.
var tur6Lane10CheckPhrases = []string{
	"--check",
	"check.sh",
	"--axes",
	"fail-closed",
	"verify sha pin",
	"lint:",
}

func tur6Lane10HasAny(line string, needles []string) bool {
	for _, n := range needles {
		if strings.Contains(line, n) {
			return true
		}
	}
	return false
}

func tur6Lane10FirstLine(text string, needles []string) int {
	for i, raw := range strings.Split(text, "\n") {
		if tur6Lane10HasAny(strings.ToLower(raw), needles) {
			return i + 1
		}
	}
	return 0
}

// tur6Lane10Detect returns 1-based line numbers (0 = none) for the
// machine-readable contract language and for the check-script language.
func tur6Lane10Detect(text string) tur6Lane10Finding {
	return tur6Lane10Finding{
		contractLine: tur6Lane10FirstLine(text, tur6Lane10ContractPhrases),
		checkLine:    tur6Lane10FirstLine(text, tur6Lane10CheckPhrases),
	}
}

func tur6Lane10Status(f tur6Lane10Finding) string {
	if f.contractLine > 0 && f.checkLine > 0 {
		return "PRESENT"
	}
	if f.contractLine > 0 || f.checkLine > 0 {
		return "PARTIAL"
	}
	return "ABSENT"
}

func tur6Lane10EvidenceLine(f tur6Lane10Finding) int {
	if f.contractLine > 0 {
		return f.contractLine
	}
	return f.checkLine
}

func tur6Lane10Itoa(n int) string {
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

func TestTur6Lane10ProgrammaticOutputContractsPresence(t *testing.T) {
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
	rank := map[string]int{"ABSENT": 0, "PARTIAL": 1, "PRESENT": 2}
	readAny := false
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		readAny = true
		f := tur6Lane10Detect(string(b))
		st := tur6Lane10Status(f)
		if rank[st] > rank[best] {
			best = st
			evidence = p + ":" + tur6Lane10Itoa(tur6Lane10EvidenceLine(f))
		}
	}
	if !readAny {
		best = "ABSENT"
	}
	t.Logf("FIELD=programmatic_output_contracts STATUS=%s evidence=%s", best, evidence)
}

func TestTur6Lane10DetectorAccuracy(t *testing.T) {
	cases := []struct {
		name, text, want string
	}{
		{"present", "# Contract\ncontract_version: 1; keys machine-readable and fixed\n## Validate\npython3 tools/op_smoke.py --check verifies sha pin\n", "PRESENT"},
		{"contract-only", "# Digest\n--json gives a JSON envelope; kind is a closed set\n", "PARTIAL"},
		{"check-only", "# Lint\nbash env/bench/check.sh --axes is fail-closed\n", "PARTIAL"},
		{"absent", "# Random\nplain prose with no schema and no validation script\n", "ABSENT"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := tur6Lane10Status(tur6Lane10Detect(c.text)); got != c.want {
				t.Fatalf("tur6Lane10Status = %s, want %s", got, c.want)
			}
		})
	}
}
