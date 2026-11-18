package main

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"sync"
)

// Static evasion indicators. This is a literal rule pack, not a runtime probe:
// lrecon never executes the target, so a hit says the artifact carries a marker
// (a string, an import name), never that the marker is reachable or that a
// sandbox would be fooled. Six families, one hit per rule (first offset), so a
// hostile file full of repeats cannot crowd the answer.

//go:embed evasion.json
var evasionJSON []byte

const evasionSchema = 1

type evadeRule struct {
	ID  string   `json:"id"`
	Str string   `json:"str,omitempty"`
	Re  string   `json:"regex,omitempty"`
	Not []string `json:"not,omitempty"`
}

type evadeFamily struct {
	Family string      `json:"family"`
	Rules  []evadeRule `json:"rules"`
}

type evadePack struct {
	Schema   int           `json:"schema_version"`
	Note     string        `json:"note"`
	Families []evadeFamily `json:"families"`
}

type evadePat struct {
	id  string
	lit []byte
	re  *regexp.Regexp
	not [][]byte
}

type evadeFam struct {
	family string
	pats   []evadePat
}

var (
	evadeOnce sync.Once
	evadePats []evadeFam
	evadeNote string
	evadeErr  error
)

// loadEvasion compiles the pack once. A rule with both a literal and a regex,
// or with neither, is refused whole by returning an error: a half-loaded pack
// would answer "absent" for rules that never ran.
func loadEvasion() {
	p := evadePack{}
	if err := json.Unmarshal(evasionJSON, &p); err != nil {
		evadeErr = fmt.Errorf("evasion pack: %v", err)
		return
	}
	if p.Schema != evasionSchema {
		evadeErr = fmt.Errorf("evasion pack: schema %d, this build reads %d", p.Schema, evasionSchema)
		return
	}
	if len(p.Families) == 0 {
		evadeErr = fmt.Errorf("evasion pack declares no families")
		return
	}
	var out []evadeFam
	seen := map[string]bool{}
	for _, f := range p.Families {
		if f.Family == "" || seen[f.Family] {
			evadeErr = fmt.Errorf("evasion pack: family %q is empty or duplicated", f.Family)
			return
		}
		seen[f.Family] = true
		fam := evadeFam{family: f.Family}
		for _, r := range f.Rules {
			pat, err := compileEvadeRule(r)
			if err != nil {
				evadeErr = fmt.Errorf("evasion pack, family %s: %v", f.Family, err)
				return
			}
			fam.pats = append(fam.pats, pat)
		}
		out = append(out, fam)
	}
	evadePats, evadeNote = out, p.Note
}

func compileEvadeRule(r evadeRule) (evadePat, error) {
	if r.ID == "" {
		return evadePat{}, fmt.Errorf("rule without id")
	}
	switch {
	case r.Str != "" && r.Re != "":
		return evadePat{}, fmt.Errorf("rule %s carries both a literal and a regex", r.ID)
	case r.Str != "":
		if len(r.Str) < 3 {
			return evadePat{}, fmt.Errorf("rule %s literal is shorter than 3 bytes", r.ID)
		}
		pat := evadePat{id: r.ID, lit: []byte(r.Str)}
		for _, n := range r.Not {
			if n != "" {
				pat.not = append(pat.not, []byte(n))
			}
		}
		return pat, nil
	case r.Re != "":
		re, err := regexp.Compile(r.Re)
		if err != nil {
			return evadePat{}, fmt.Errorf("rule %s regex: %v", r.ID, err)
		}
		return evadePat{id: r.ID, re: re}, nil
	}
	return evadePat{}, fmt.Errorf("rule %s has neither a literal nor a regex", r.ID)
}

func init() {
	registerOp(op{
		name:  "check_runtime_evasion",
		route: "L",
		needs: true,
		desc:  "STATIC evasion indicators: six families (debugger, VM, sandbox, anti-timing, remote-debug, synthetic-trace) matched as literals in the file; no execution, so a hit is a marker, not runtime behaviour.",
		run:   runCheckRuntimeEvasion,
	})
}

type evasionHit struct {
	ID     string `json:"id"`
	Offset int64  `json:"offset"`
}

type evasionFamilyResult struct {
	Family     string       `json:"family"`
	Hits       []evasionHit `json:"hits"`
	Confidence string       `json:"confidence"`
}

func runCheckRuntimeEvasion(path string) (any, error) {
	evadeOnce.Do(loadEvasion)
	if evadeErr != nil {
		return nil, evadeErr
	}
	win := head(path, maxSigScan)
	if len(win) == 0 {
		return nil, fmt.Errorf("%s: nothing to scan (empty or unreadable)", path)
	}
	families := make([]evasionFamilyResult, 0, len(evadePats))
	total := 0
	for _, fam := range evadePats {
		res := evasionFamilyResult{Family: fam.family, Hits: []evasionHit{}, Confidence: "static-indicator"}
		for _, p := range fam.pats {
			off, ok := evadeOffset(win, p)
			if !ok {
				continue
			}
			res.Hits = append(res.Hits, evasionHit{ID: p.id, Offset: off})
		}
		total += len(res.Hits)
		families = append(families, res)
	}
	out := map[string]any{
		"note":        evadeNote,
		"static_only": true,
		"families":    families,
		"indicators":  total,
		"scanned":     len(win),
	}
	if st, err := os.Stat(path); err == nil && int64(len(win)) < st.Size() {
		out["truncated_at"] = len(win)
	}
	return out, nil
}

// evadeOffset returns the first offset a rule matches at, or false. A rule with
// an anti-marker present anywhere in the window is cancelled: the file carries
// the decoy word, so neither reading is evidence.
func evadeOffset(win []byte, p evadePat) (int64, bool) {
	for _, n := range p.not {
		if bytes.Contains(win, n) {
			return 0, false
		}
	}
	if p.re != nil {
		if loc := p.re.FindIndex(win); loc != nil {
			return int64(loc[0]), true
		}
		return 0, false
	}
	if i := bytes.Index(win, p.lit); i >= 0 {
		return int64(i), true
	}
	return 0, false
}

// evasionFamilies names the embedded families, for tests and diagnostics.
func evasionFamilies() []string {
	evadeOnce.Do(loadEvasion)
	out := make([]string, 0, len(evadePats))
	for _, f := range evadePats {
		out = append(out, f.family)
	}
	sort.Strings(out)
	return out
}
