package main

// Tur 6 lane 28: probe. Reads the walsyrea skill text directly and detects two
// opposite routing directions: (1) does lrecon hand off / route / delegate to
// walsyrea, and (2) does walsyrea reference and actually call lrecon as a
// sub-workflow. Also verifies the ops.json simulated routing (127 L / 69 Y /
// 39 G of 235) against the real, callable lrecon binary. Findings are logged
// only; tests stay green regardless of outcome.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

type tur6Lane28Finding struct {
	refLine    int // weaker: prose reference to lrecon / walsyrea
	invokeLine int // stronger: concrete command or routing directive
}

// lrecon -> walsyrea directives: an explicit verb that sends control to
// walsyrea. Bare "walsyrea" (the skill naming itself) is NOT a route.
var tur6Lane28RouteToWalsyrea = []string{
	"route to walsyrea",
	"routes to walsyrea",
	"handoff to walsyrea",
	"hand off to walsyrea",
	"delegate to walsyrea",
	"refer to walsyrea",
	"call walsyrea",
	"calls walsyrea",
	"invoke walsyrea",
	"forward to walsyrea",
	"redirect to walsyrea",
	"walsyrea --json",
	"walsyrea --op",
	"walsyrea <target>",
	"→ walsyrea",
	"-> walsyrea",
}

// Weaker: prose treating walsyrea as a downstream step. The skill's own name
// in frontmatter/heading is deliberately NOT here (it is not a reference).
var tur6Lane28WalsyreaMention = []string{
	"then walsyrea",
	"switch to walsyrea",
	"run walsyrea",
	"walsyrea handles",
	"walsyrea decides",
	"walsyrea takes over",
	"hand over to walsyrea",
}

// walsyrea -> lrecon: concrete invocations / entrypoint definition.
var tur6Lane28UseLreconInvoke = []string{
	"lrecon --json",
	"lrecon --version",
	"lrecon --list-ops",
	"lrecon --extract-all",
	"lrecon --explain",
	"lrecon --op",
	"lrecon=${lrecon",
	"lrecon <target>",
}

// walsyrea -> lrecon: weaker prose references.
var tur6Lane28UseLreconRef = []string{
	"built against `lrecon",
	"one `lrecon",
	"`lrecon 1.0.0`",
}

func tur6Lane28ContainsAny(hay string, needles []string) bool {
	for _, n := range needles {
		if strings.Contains(hay, n) {
			return true
		}
	}
	return false
}

func tur6Lane28DetectRouteToWalsyrea(text string) tur6Lane28Finding {
	var f tur6Lane28Finding
	for i, raw := range strings.Split(text, "\n") {
		ln := strings.ToLower(strings.TrimSpace(raw))
		line := i + 1
		if f.invokeLine == 0 && tur6Lane28ContainsAny(ln, tur6Lane28RouteToWalsyrea) {
			f.invokeLine = line
		}
		if f.refLine == 0 && tur6Lane28ContainsAny(ln, tur6Lane28WalsyreaMention) {
			f.refLine = line
		}
	}
	return f
}

func tur6Lane28DetectUseLrecon(text string) tur6Lane28Finding {
	var f tur6Lane28Finding
	for i, raw := range strings.Split(text, "\n") {
		ln := strings.ToLower(strings.TrimSpace(raw))
		line := i + 1
		if f.invokeLine == 0 && tur6Lane28ContainsAny(ln, tur6Lane28UseLreconInvoke) {
			f.invokeLine = line
		}
		if f.refLine == 0 && tur6Lane28ContainsAny(ln, tur6Lane28UseLreconRef) {
			f.refLine = line
		}
	}
	return f
}

// routeToWalsyreaStatus: PRESENT needs an explicit lrecon->walsyrea routing
// directive. A bare self-mention of "walsyrea" -> PARTIAL. None -> ABSENT.
func tur6Lane28RouteToWalsyreaStatus(f tur6Lane28Finding) string {
	if f.invokeLine > 0 {
		return "PRESENT"
	}
	if f.refLine > 0 {
		return "PARTIAL"
	}
	return "ABSENT"
}

// useLreconStatus: PRESENT needs a concrete lrecon invocation / entrypoint;
// prose-only reference -> PARTIAL; none -> ABSENT.
func tur6Lane28UseLreconStatus(f tur6Lane28Finding) string {
	if f.invokeLine > 0 {
		return "PRESENT"
	}
	if f.refLine > 0 {
		return "PARTIAL"
	}
	return "ABSENT"
}

func tur6Lane28EvidenceLine(f tur6Lane28Finding) int {
	if f.invokeLine > 0 {
		return f.invokeLine
	}
	if f.refLine > 0 {
		return f.refLine
	}
	return 1
}

// tur6Lane28SkillPaths: SKILL.md plus every references/*.md.
func tur6Lane28SkillPaths() []string {
	root := filepath.Join("..", "skill")
	paths := []string{filepath.Join(root, "SKILL.md")}
	if refs, err := filepath.Glob(filepath.Join(root, "references", "*.md")); err == nil {
		paths = append(paths, refs...)
	}
	return paths
}

func TestTur6Lane28WalsyreaRoutingPresence(t *testing.T) {
	best := "ABSENT"
	evidence := filepath.Join("..", "skill", "SKILL.md") + ":1"
	var bestFinding tur6Lane28Finding
	rank := map[string]int{"ABSENT": 0, "PARTIAL": 1, "PRESENT": 2}
	for _, p := range tur6Lane28SkillPaths() {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		f := tur6Lane28DetectRouteToWalsyrea(string(b))
		st := tur6Lane28RouteToWalsyreaStatus(f)
		if rank[st] > rank[best] ||
			(rank[st] == rank[best] && tur6Lane28EvidenceLine(f) > tur6Lane28EvidenceLine(bestFinding)) {
			best = st
			bestFinding = f
			evidence = p + ":" + strconv.Itoa(tur6Lane28EvidenceLine(f))
		}
	}
	t.Logf("FIELD=walsyrea_routing STATUS=%s evidence=%s", best, evidence)
	t.Logf("DETAIL lrecon_to_walsyrea_directive=%d walsyrea_self_mention=%d",
		bestFinding.invokeLine, bestFinding.refLine)
}

func TestTur6Lane28WalsyreaUsesLreconPresence(t *testing.T) {
	best := "ABSENT"
	evidence := filepath.Join("..", "skill", "SKILL.md") + ":1"
	var bestFinding tur6Lane28Finding
	rank := map[string]int{"ABSENT": 0, "PARTIAL": 1, "PRESENT": 2}
	for _, p := range tur6Lane28SkillPaths() {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		f := tur6Lane28DetectUseLrecon(string(b))
		st := tur6Lane28UseLreconStatus(f)
		if rank[st] > rank[best] {
			best = st
			bestFinding = f
			evidence = p + ":" + strconv.Itoa(tur6Lane28EvidenceLine(f))
		}
	}
	t.Logf("FIELD=walsyrea_uses_lrecon STATUS=%s evidence=%s", best, evidence)
	t.Logf("DETAIL lrecon_invocation=%d lrecon_prose_ref=%d", bestFinding.invokeLine, bestFinding.refLine)
}

// tur6Lane28OpsJSONShape: reads the simulated routing table and counts routes.
type tur6Lane28OpsDoc struct {
	Ops []struct {
		Name  string `json:"name"`
		Route string `json:"route"`
	} `json:"ops"`
}

func tur6Lane28CountRoutes(d tur6Lane28OpsDoc) map[string]int {
	c := map[string]int{}
	for _, o := range d.Ops {
		c[o.Route]++
	}
	return c
}

func TestTur6Lane28OpsJSONSimRoutingCallable(t *testing.T) {
	opsPath := filepath.Join("testdata", "ops.json")
	b, err := os.ReadFile(opsPath)
	if err != nil {
		t.Logf("FIELD=walsyrea_sim_routing STATUS=ABSENT evidence=%s:unreadable", opsPath)
		return
	}
	var doc tur6Lane28OpsDoc
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Logf("FIELD=walsyrea_sim_routing STATUS=ABSENT evidence=%s:bad_json", opsPath)
		return
	}
	c := tur6Lane28CountRoutes(doc)
	shapeOK := len(doc.Ops) == 235 && c["L"] == 127 && c["Y"] == 69 && c["G"] == 39

	// The skill actually invokes these L-route ops; they must exist in the table.
	need := map[string]bool{"list_strings": false, "binary_overview": false,
		"inspect_artifact": false, "inspect_go_binary": false}
	found := 0
	for _, o := range doc.Ops {
		if _, ok := need[o.Name]; ok && o.Route == "L" {
			need[o.Name] = true
			found++
		}
	}

	// Callability evidence: the real binary exists and is executable.
	binPath := filepath.Join("lrecon")
	st, statErr := os.Stat(binPath)
	callable := statErr == nil && st.Mode()&0111 != 0

	status := "ABSENT"
	if shapeOK && callable {
		status = "PRESENT"
	} else if shapeOK || callable {
		status = "PARTIAL"
	}
	evidence := opsPath + ":3"
	if statErr == nil {
		evidence = binPath + ":1"
	}
	t.Logf("FIELD=walsyrea_sim_routing STATUS=%s evidence=%s", status, evidence)
	t.Logf("DETAIL ops=%d L=%d Y=%d G=%d skill_ops_found=%d binary_callable=%v",
		len(doc.Ops), c["L"], c["Y"], c["G"], found, callable)
}

func TestTur6Lane28DetectorAccuracy(t *testing.T) {
	routeCases := []struct {
		name, text, want string
	}{
		{
			"explicit-handoff",
			"# lrecon\nlrecon routes to walsyrea for the verdict.\n",
			"PRESENT",
		},
		{
			"explicit-delegate",
			"on a unknown layer, delegate to walsyrea\n",
			"PRESENT",
		},
		{
			"bare-name-only",
			"---\nname: walsyrea\n---\n# walsyrea\n",
			"ABSENT",
		},
		{
			"absent-self-name-not-route",
			"Built against `lrecon 1.0.0`; every `lrecon` here means $LRECON.\n",
			"ABSENT",
		},
	}
	for _, c := range routeCases {
		t.Run("route/"+c.name, func(t *testing.T) {
			if got := tur6Lane28RouteToWalsyreaStatus(tur6Lane28DetectRouteToWalsyrea(c.text)); got != c.want {
				t.Fatalf("routeStatus = %s, want %s", got, c.want)
			}
		})
	}

	useCases := []struct {
		name, text, want string
	}{
		{
			"entrypoint-and-digest",
			"**Entry** — `LRECON=${LRECON:-./lrecon/lrecon}`; every `lrecon` here means $LRECON.\n" +
				"- **Identify** — `lrecon --json T`.\n",
			"PRESENT",
		},
		{
			"invocation-only",
			"one `lrecon --json` digest gives kind, format.\n",
			"PRESENT",
		},
		{
			"prose-only",
			"Built against `lrecon 1.0.0`. One artifact in, one verdict out.\n",
			"PARTIAL",
		},
		{
			"absent-unrelated",
			"# Random\nplain text, no tool reference here\n",
			"ABSENT",
		},
	}
	for _, c := range useCases {
		t.Run("use/"+c.name, func(t *testing.T) {
			if got := tur6Lane28UseLreconStatus(tur6Lane28DetectUseLrecon(c.text)); got != c.want {
				t.Fatalf("useStatus = %s, want %s", got, c.want)
			}
		})
	}
}
