package main

// Tur 6 lane 25: "visual_evidence_probes" (görsel kanıt / doğrulama kanıtı:
// screenshot, diff evidence, capture, inspect frame) alanını doğrudan skill
// metninden okuyup simüle eden probe. Bulgu loglanır; test her durumda yeşil kalır.

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

type tur6L25Finding struct {
	visualLine   int
	evidenceLine int
}

// Görsel kanıt üreten/karşılaştıran operasyon adları (op-index / op-table).
var tur6L25VisualOps = []string{
	"capture_web_screenshot",
	"capture_adb_screen",
	"capture_browser_scenario",
	"capture_electron_scenario",
	"capture_native_ui_scenario",
	"capture_process_scenario",
	"compare_web_screenshots",
	"compare_web_captures",
	"inspect_web_page",
	"inspect_adb_display",
	"inspect_adb_window",
	"screenshot",
}

// Kanıt/doğrulama dili (diff evidence, replay, proof alanı).
var tur6L25EvidenceMarks = []string{
	"EVIDENCE",
	"evidence:",
	"proof",
	"solved needs",
	"diff exactly",
	"replayed",
	"input→output",
	"input->output",
	"before/after",
	"bytes you wrote",
}

func tur6L25Any(hay string, needles []string) bool {
	for _, n := range needles {
		if strings.Contains(hay, n) {
			return true
		}
	}
	return false
}

func tur6L25Detect(text string) tur6L25Finding {
	var f tur6L25Finding
	for i, raw := range strings.Split(text, "\n") {
		line := i + 1
		if f.visualLine == 0 && tur6L25Any(raw, tur6L25VisualOps) {
			f.visualLine = line
		}
		if f.evidenceLine == 0 && tur6L25Any(raw, tur6L25EvidenceMarks) {
			f.evidenceLine = line
		}
	}
	return f
}

func tur6L25Status(f tur6L25Finding) string {
	if f.visualLine > 0 && f.evidenceLine > 0 {
		return "PRESENT"
	}
	if f.visualLine > 0 || f.evidenceLine > 0 {
		return "PARTIAL"
	}
	return "ABSENT"
}

func TestTur6Lane25VisualEvidencePresence(t *testing.T) {
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
		f := tur6L25Detect(string(b))
		st := tur6L25Status(f)
		if rank[st] > rank[best] {
			best = st
			line := 1
			switch {
			case f.visualLine > 0:
				line = f.visualLine
			case f.evidenceLine > 0:
				line = f.evidenceLine
			}
			evidence = p + ":" + strconv.Itoa(line)
		}
	}
	if !readAny {
		best = "ABSENT"
	}
	t.Logf("FIELD=visual_evidence_probes STATUS=%s evidence=%s", best, evidence)
}

func TestTur6Lane25DetectorAccuracy(t *testing.T) {
	cases := []struct {
		name, text, want string
	}{
		{"present", "capture_web_screenshot and compare_web_screenshots\nEVIDENCE: 0x10: de ad\n", "PRESENT"},
		{"present-proof", "capture_adb_screen\nsolved needs the artifact running and a diff exactly equal to the bytes written\n", "PRESENT"},
		{"partial-visual-only", "capture_web_screenshot\nnothing about it here\n", "PARTIAL"},
		{"partial-evidence-only", "EVIDENCE: 0x0: ff\nno capture ops here\n", "PARTIAL"},
		{"absent", "## Install\nrun make\nsome unrelated text\n", "ABSENT"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := tur6L25Status(tur6L25Detect(c.text)); got != c.want {
				t.Fatalf("tur6L25Status = %s, want %s", got, c.want)
			}
		})
	}
}
