package main

// Evergreen08: a content-dependent detector must be killable by mutation.
//
// check_deception_signals reports only sentinels it actually finds in the bytes.
// Copies of two real corpus files are mutated to remove or neuter one sentinel
// each; the structured verdict (deception_risk plus the canary hit-id set) must
// move. Cosmetic copies (comment, whitespace) must keep it identical. A detector
// that always answers "indicators" fails the killed direction, one that always
// answers "none" fails the pristine baseline, so neither passes by output noise.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

type eg08Verdict struct {
	risk     string
	canaries []string
}

func eg08Read(t *testing.T, name string) []byte {
	t.Helper()
	body, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("read corpus file %s: %v", name, err)
	}
	if len(body) == 0 {
		t.Fatalf("corpus file %s is empty", name)
	}
	return body
}

// eg08Scan writes one body into a fresh temp file and returns the verdict the
// real binary reports for it.
func eg08Scan(t *testing.T, name string, body []byte) eg08Verdict {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, body, 0o644); err != nil {
		t.Fatal(err)
	}
	out, code := runCLI(t, "--op", "check_deception_signals", p)
	if code != 0 {
		t.Fatalf("check_deception_signals %s: exit %d, out=%s", name, code, out)
	}
	var env struct {
		Result struct {
			Risk    string `json:"deception_risk"`
			Classes []struct {
				Class string `json:"class"`
				Hits  []struct {
					ID string `json:"id"`
				} `json:"hits"`
			} `json:"classes"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		t.Fatalf("%s: not JSON: %v\n%s", name, err, out)
	}
	v := eg08Verdict{risk: env.Result.Risk}
	for _, c := range env.Result.Classes {
		if c.Class != "canary-credential" {
			continue
		}
		for _, h := range c.Hits {
			v.canaries = append(v.canaries, h.ID)
		}
	}
	sort.Strings(v.canaries)
	return v
}

// eg08Mutate applies one textual mutation and fails if the corpus no longer
// carries the exact text, so a drifting file cannot quietly weaken the test.
func eg08Mutate(t *testing.T, body []byte, old, new string, wantCount int) []byte {
	t.Helper()
	if got := strings.Count(string(body), old); got != wantCount {
		t.Fatalf("corpus drifted: %q appears %d times, want %d", old, got, wantCount)
	}
	return []byte(strings.ReplaceAll(string(body), old, new))
}

func eg08Same(a, b eg08Verdict) bool {
	if a.risk != b.risk || len(a.canaries) != len(b.canaries) {
		return false
	}
	for i := range a.canaries {
		if a.canaries[i] != b.canaries[i] {
			return false
		}
	}
	return true
}

func TestEvergreen08MutationKill(t *testing.T) {
	canarySrc := eg08Read(t, "op_check_deception.go")
	magicSrc := eg08Read(t, "op_inspect_il2cpp_metadata.go")

	base := eg08Scan(t, "baseline_canary.go", canarySrc)
	wantBase := []string{"0xFAB11BAF", "REA_TRAP", "__RE_CANARY__"}
	if base.risk != "indicators" || !eg08Same(base, eg08Verdict{risk: "indicators", canaries: wantBase}) {
		t.Fatalf("pristine verdict = %+v, want indicators with %v", base, wantBase)
	}

	// M1: the whole sentinel set is deleted. The detector must fall silent.
	m1 := eg08Mutate(t, canarySrc,
		"\t\"__RE_CANARY__\",\n\t\"REA_TRAP\",\n\t\"0xFAB11BAF\",\n", "", 1)
	// M2: one sentinel is neutered by a single digit. Only that hit may drop.
	m2 := eg08Mutate(t, canarySrc, "0xFAB11BAF", "0xFAB11BAE", 1)
	// M3: one sentinel entry is removed. The other two must survive.
	m3 := eg08Mutate(t, canarySrc, "\t\"REA_TRAP\",\n", "", 1)
	// M4: the IL2CPP magic constant is changed, killing the only canary-shaped
	// run in that real file. Its detector verdict must drop to none.
	m4 := eg08Mutate(t, magicSrc, "0xFAB11BAF", "0xFAB11BB0", 2)

	// C1/C2: cosmetic edits only. Both must leave the verdict untouched.
	c1 := eg08Mutate(t, canarySrc, "var canaryMarkers =",
		"// eg08 cosmetic control: comment only.\nvar canaryMarkers =", 1)
	c2 := append(append([]byte{}, canarySrc...), []byte("\n\n\t\n   \n")...)

	killed := []struct {
		name string
		body []byte
		risk string
		ids  []string
	}{
		{"M1_delete_all_sentinels", m1, "none", nil},
		{"M2_neuter_magic_sentinel", m2, "indicators", []string{"REA_TRAP", "__RE_CANARY__"}},
		{"M3_remove_trap_entry", m3, "indicators", []string{"0xFAB11BAF", "__RE_CANARY__"}},
		{"M4_change_il2cpp_magic", m4, "none", nil},
	}
	for _, k := range killed {
		got := eg08Scan(t, k.name+".go", k.body)
		if !eg08Same(got, eg08Verdict{risk: k.risk, canaries: k.ids}) {
			t.Fatalf("%s verdict = %+v, want risk=%s ids=%v", k.name, got, k.risk, k.ids)
		}
		if eg08Same(got, base) {
			t.Fatalf("%s left the verdict unchanged: %+v", k.name, got)
		}
	}

	for _, c := range []struct {
		name string
		body []byte
	}{
		{"C1_comment_only", c1},
		{"C2_whitespace_only", c2},
	} {
		if got := eg08Scan(t, c.name+".go", c.body); !eg08Same(got, base) {
			t.Fatalf("%s moved the verdict: %+v, want %+v", c.name, got, base)
		}
	}
}
