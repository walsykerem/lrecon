package main

// Tur 6 lane 24: guard. Reads the walsyrea skill text directly and requires
// destructive-approval-gate language: an explicit confirm/approval/backup gate
// before an irreversible action, not just weaker deletion-safety constraints.
// The real skill must grade PRESENT; the grader is pinned by the detector
// accuracy test.

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

type tur6l24Finding struct {
	gateLine  int
	guardLine int
}

// Explicit approval/confirmation/backup gate before a destructive action.
var tur6l24GatePhrases = []string{
	"approval", "approve before", "confirm before", "confirm before deleting",
	"before deleting", "ask before", "requires confirmation", "are you sure",
	"backup before", "back up before", "make a backup", "backup first",
	"force push", "force-push", "before force", "before deploy",
	"onay", "yedek",
}

// Safety constraints around deletion / preserving the original (weaker than a gate).
var tur6l24GuardPhrases = []string{
	"rm -rf", "unquoted delete", "delete the literal", "delete that exact dir",
	"only for throwaway", "never overwrites the digest", "writing into the target",
	"of=/dev/",
}

func tur6l24ContainsAny(hay string, needles []string) bool {
	for _, n := range needles {
		if strings.Contains(hay, n) {
			return true
		}
	}
	return false
}

// tur6l24Detect scans raw skill text and returns 1-based line numbers
// (0 = none) for an explicit approval gate and for deletion-safety guards.
func tur6l24Detect(text string) tur6l24Finding {
	var f tur6l24Finding
	for i, raw := range strings.Split(text, "\n") {
		ln := strings.ToLower(strings.TrimSpace(raw))
		line := i + 1
		if f.gateLine == 0 && tur6l24ContainsAny(ln, tur6l24GatePhrases) {
			f.gateLine = line
		}
		if f.guardLine == 0 && tur6l24ContainsAny(ln, tur6l24GuardPhrases) {
			f.guardLine = line
		}
	}
	return f
}

func tur6l24Status(f tur6l24Finding) string {
	if f.gateLine > 0 {
		return "PRESENT"
	}
	if f.guardLine > 0 {
		return "PARTIAL"
	}
	return "ABSENT"
}

func TestTur6Lane24DestructiveApprovalGatePresence(t *testing.T) {
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
	rank := map[string]int{"ABSENT": 0, "PARTIAL": 1, "PRESENT": 2}
	readAny := false
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		readAny = true
		f := tur6l24Detect(string(b))
		st := tur6l24Status(f)
		if rank[st] > rank[best] {
			best = st
			line := f.gateLine
			if line == 0 {
				line = f.guardLine
			}
			evidence = p + ":" + strconv.Itoa(line)
		}
	}
	if !readAny {
		best = "ABSENT"
	}
	t.Logf("FIELD=destructive_approval_gate STATUS=%s evidence=%s", best, evidence)
	if best != "PRESENT" {
		t.Errorf("skill destructive_approval_gate=%s, want PRESENT (approval/backup gate before irreversible steps)", best)
	}
}

func TestTur6Lane24DetectorAccuracy(t *testing.T) {
	cases := []struct {
		name, text, want string
	}{
		{"gate-present", "## Safety\napproval required before force push\ndelete that exact dir when done\n", "PRESENT"},
		{"approval-and-backup", "Before destructive steps: require approval and a backup.\n", "PRESENT"},
		{"backup-gate", "make a backup before deleting the project\n", "PRESENT"},
		{"guard-only", "unquoted `rm -rf $VAR`; quote it, or delete the literal path\n", "PARTIAL"},
		{"no-safety-language", "one target per call; keys machine-readable\n", "ABSENT"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := tur6l24Status(tur6l24Detect(c.text)); got != c.want {
				t.Fatalf("tur6l24Status = %s, want %s", got, c.want)
			}
		})
	}
}
