package main

import (
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
)

// planItem is one entry of the design plan in ../design-plan.md: the ticked or
// drafted headline plus every indented line under it, up to the next blank
// line.
type planItem struct {
	line int
	text string
}

// parsePlanItems splits the plan into entries; an entry starts at a line
// opening with "**`[" and absorbs the following non-blank lines.
func parsePlanItems(raw string) []planItem {
	var items []planItem
	cur := -1
	for i, ln := range strings.Split(raw, "\n") {
		switch {
		case strings.HasPrefix(ln, "**`["):
			items = append(items, planItem{line: i + 1, text: ln})
			cur = len(items) - 1
		case ln == "":
			cur = -1
		case cur >= 0:
			items[cur].text += "\n" + ln
		}
	}
	return items
}

var (
	planTestNameRE = regexp.MustCompile(`\bTest[A-Z][A-Za-z0-9_]*\b`)
	planNumberRE   = regexp.MustCompile(`\b\d+(\.\d+)?\b`)
)

// planProblems reports every way the plan can prove nothing: a ticked item
// without evidence or falsifier, a ticked item without a pinned number, a plan
// with no falsifier at all, or a ticked item citing a test that does not exist.
// Unticked items may stay drafts.
func planProblems(items []planItem, testExists func(string) bool) []string {
	var problems []string
	falsified, ticked := 0, 0
	var want []string
	for _, it := range items {
		if strings.Contains(it.text, "falsifier:") {
			falsified++
		}
		if !strings.Contains(it.text, "`[x]`") {
			continue
		}
		ticked++
		for _, key := range []string{"evidence:", "falsifier:"} {
			if !strings.Contains(it.text, key) {
				problems = append(problems, fmt.Sprintf("item at design-plan.md:%d ticked without %s", it.line, key))
			}
		}
		if !planNumberRE.MatchString(it.text) {
			problems = append(problems, fmt.Sprintf("item at design-plan.md:%d has no pinned number", it.line))
		}
		want = append(want, planTestNameRE.FindAllString(it.text, -1)...)
	}
	if falsified == 0 {
		problems = append(problems, "no plan item carries a falsifier: plan cannot fail, so it proves nothing")
	}
	for _, name := range want {
		if !testExists(name) {
			problems = append(problems, fmt.Sprintf("design-plan.md cites %s (%d item(s) ticked) but no such test exists", name, ticked))
		}
	}
	return problems
}

// listedTests asks the test binary which tests this package declares, so a
// plan item cannot cite a test that was renamed away.
func listedTests(t *testing.T) func(string) bool {
	t.Helper()
	out, err := exec.Command("go", "test", "-list", ".*", ".").Output()
	if err != nil {
		t.Fatalf("go test -list: %v", err)
	}
	listed := map[string]bool{}
	for ln := range strings.SplitSeq(string(out), "\n") {
		listed[strings.TrimSpace(ln)] = true
	}
	return func(name string) bool { return listed[name] }
}

// TestPlanItemsAreFalsifiable guards the design plan in ../design-plan.md: a
// ticked item must carry evidence, a falsifier and a pinned number, and every
// test it names must exist. Unticked items may stay drafts, but the plan as a
// whole must not be vacuous: at least one item must carry a falsifier.
//
// shortcut: Test… names are checked for ticked items only, so drafting an item
// cannot break the build; tighten to every item once all plan items are ticked.
func TestPlanItemsAreFalsifiable(t *testing.T) {
	raw, err := os.ReadFile("../design-plan.md")
	if err != nil {
		t.Skip("design-plan.md absent (fork checkout): plan not available")
	}

	items := parsePlanItems(string(raw))
	if len(items) < 9 {
		t.Fatalf("found %d plan items, want >= 9 (parser or report shape changed)", len(items))
	}

	var exists func(string) bool
	for _, p := range planProblems(items, func(name string) bool {
		if exists == nil {
			exists = listedTests(t)
		}
		return exists(name)
	}) {
		t.Error(p)
	}
}

// TestPlanRulesFlagVacuousItems pins the rule machinery itself, so the plan
// check stays exercised even where ../design-plan.md is absent.
func TestPlanRulesFlagVacuousItems(t *testing.T) {
	cases := []struct {
		name   string
		plan   string
		exists func(string) bool
		want   []string
	}{
		{
			name:   "ticked item without evidence",
			plan:   "**`[x]` vacuous item — falsifier: none needed; 2 rows\n",
			exists: func(string) bool { return true },
			want:   []string{"design-plan.md:1 ticked without evidence:"},
		},
		{
			name:   "ticked item without pinned number",
			plan:   "**`[x]` item — evidence: TestX passes; falsifier: rerun\n",
			exists: func(string) bool { return true },
			want:   []string{"design-plan.md:1 has no pinned number"},
		},
		{
			name:   "plan without any falsifier",
			plan:   "**`[x]` item — evidence: TestX passes; 3 runs\n",
			exists: func(string) bool { return true },
			want: []string{
				"design-plan.md:1 ticked without falsifier:",
				"no plan item carries a falsifier",
			},
		},
		{
			name:   "cites a test that does not exist",
			plan:   "**`[x]` item — evidence: TestGone passes; falsifier: rerun; 3 runs\n",
			exists: func(name string) bool { return name == "TestPresent" },
			want:   []string{"cites TestGone (1 item(s) ticked) but no such test exists"},
		},
		{
			name: "sound plan and draft item",
			plan: "**`[x]` item — evidence: TestPresent passes; falsifier: rerun; 3 runs\n" +
				" trace line stays with the item\n\n" +
				"**`[ ]` draft carries no claims yet\n",
			exists: func(name string) bool { return name == "TestPresent" },
			want:   nil,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			items := parsePlanItems(c.plan)
			if c.name == "sound plan and draft item" && len(items) != 2 {
				t.Fatalf("parsed %d plan items, want 2", len(items))
			}
			got := planProblems(items, c.exists)
			if len(got) != len(c.want) {
				t.Fatalf("problems = %q, want %d of %q", got, len(c.want), c.want)
			}
			for i, w := range c.want {
				if !strings.Contains(got[i], w) {
					t.Errorf("problem[%d] = %q, want it to contain %q", i, got[i], w)
				}
			}
		})
	}
}
