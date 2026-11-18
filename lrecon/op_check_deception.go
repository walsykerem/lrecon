package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

// Deception indicators: decoys planted to mislead a reverse engineer. Three
// classes, all STATIC — nothing here executes the target or follows a URL.
//
//   canary-credential  sentinel strings a target author planted on a path that
//                      a real credential never sits on
//   honey-sourcemap    a source map reference whose map (or whose sources) is
//                      absent, so recovering "originals" produces fiction
//   shadow-state-machine  a family of state/handler identifiers large enough to
//                      be a labyrinth; string-level only, no call-graph SCC
//
// A class that does not apply to this kind of target reports no hits, never a
// guessed one.

const (
	// deceptionScanCap bounds the string scan. Canaries sit in the data sections
	// of a normal binary; a marker past this window is reported as not scanned.
	deceptionScanCap = 16 << 20
	// maxDeceptionHits keeps a hostile file full of canaries from crowding out
	// every other class. One witness per marker id is all the answer needs.
	maxDeceptionHits = 64
	// shadowFamilyMin is the number of sibling identifiers a family needs before
	// the shape reads as a state machine rather than a naming habit.
	shadowFamilyMin = 8
)

func init() {
	registerOp(op{
		name:  "check_deception_signals",
		route: "L",
		needs: true,
		desc:  "STATIC anti-deception indicators in three classes: canary-credential sentinels, honey source maps whose originals do not exist, and string-level shadow state-machine families.",
		run:   runCheckDeception,
	})
}

type deceptionHit struct {
	ID     string `json:"id"`
	Offset *int64 `json:"offset,omitempty"`
	Detail string `json:"detail,omitempty"`
}

type deceptionClass struct {
	Class string         `json:"class"`
	Hits  []deceptionHit `json:"hits"`
}

func runCheckDeception(path string) (any, error) {
	win := head(path, deceptionScanCap)
	if len(win) == 0 {
		return nil, fmt.Errorf("%s: nothing to scan (empty or unreadable)", path)
	}
	classes := []deceptionClass{
		deceptionCanaries(win),
		deceptionHoneySourcemap(path),
		deceptionShadowState(win),
	}
	total := 0
	for _, c := range classes {
		total += len(c.Hits)
	}
	risk := "none"
	if total > 0 {
		risk = "indicators"
	}
	out := map[string]any{
		"note":           "STATIC indicators only: a marker or a dangling source map says a decoy was planted, not that the analysis was fooled. No execution and no network.",
		"static_only":    true,
		"classes":        classes,
		"deception_risk": risk,
	}
	if st, err := os.Stat(path); err == nil && int64(len(win)) < st.Size() {
		out["truncated_at"] = len(win)
	}
	return out, nil
}

// --- canary-credential ---

// canaryMarkers are sentinel strings no genuine credential path carries. They
// are matched as ASCII literals: a binary's own bytes are what a reader sees.
var canaryMarkers = []string{
	"__RE_CANARY__",
	"REA_TRAP",
	"0xFAB11BAF",
}

func deceptionCanaries(win []byte) deceptionClass {
	c := deceptionClass{Class: "canary-credential", Hits: []deceptionHit{}}
	for _, m := range canaryMarkers {
		off := bytes.Index(win, []byte(m))
		if off < 0 {
			continue
		}
		o := int64(off)
		c.Hits = append(c.Hits, deceptionHit{ID: m, Offset: &o})
		if len(c.Hits) >= maxDeceptionHits {
			break
		}
	}
	return c
}

// --- honey-sourcemap ---

// deceptionHoneySourcemap reports source map references that cannot resolve to a
// real map or to real sources. Only an asar or a JavaScript/TypeScript file can
// carry such a trailer; another kind answers with no hits (wrong kind, not
// "clean").
func deceptionHoneySourcemap(p string) deceptionClass {
	c := deceptionClass{Class: "honey-sourcemap", Hits: []deceptionHit{}}
	low := strings.ToLower(p)
	switch {
	case isAsar(head(p, 32)):
		for _, ref := range asarSourceMapRefs(p) {
			if strings.HasSuffix(ref, " (missing)") || strings.Contains(ref, "://") {
				c.Hits = append(c.Hits, deceptionHit{ID: "dangling-map", Detail: ref})
			}
		}
	case strings.HasSuffix(low, ".js"), strings.HasSuffix(low, ".cjs"), strings.HasSuffix(low, ".mjs"),
		strings.HasSuffix(low, ".jsx"), strings.HasSuffix(low, ".ts"), strings.HasSuffix(low, ".tsx"):
		c.Hits = append(c.Hits, scriptHoneyHits(p)...)
	case strings.HasSuffix(low, ".map"):
		c.Hits = append(c.Hits, mapHoneyHits(p)...)
	}
	if len(c.Hits) > maxDeceptionHits {
		c.Hits = c.Hits[:maxDeceptionHits]
	}
	return c
}

// scriptHoneyHits follows one script's source map trailer. lrecon never fetches,
// so a remote ref is a dangling map by definition.
func scriptHoneyHits(p string) []deceptionHit {
	body, err := opRead(p, opMaxFile)
	if err != nil {
		return nil
	}
	var out []deceptionHit
	for _, re := range []*regexp.Regexp{sourceMapRe, sourceMapBlockRe} {
		m := re.FindSubmatch(body)
		if m == nil {
			continue
		}
		ref := strings.TrimSpace(string(m[1]))
		switch {
		case strings.HasPrefix(ref, "data:"):
			var sm webSourceMap
			_, after, ok := strings.Cut(ref, "base64,")
			if !ok {
				out = append(out, deceptionHit{ID: "unreadable-inline-map", Detail: ref[:min(len(ref), 120)]})
				continue
			}
			if err := decodeBase64JSON(after, &sm); err != nil {
				out = append(out, deceptionHit{ID: "unreadable-inline-map", Detail: err.Error()})
				continue
			}
			out = append(out, mapBodyHoneyHits(&sm, p)...)
		case strings.Contains(ref, "://") || strings.HasPrefix(ref, "//"):
			out = append(out, deceptionHit{ID: "remote-map", Detail: ref})
		default:
			local := filepath.Join(filepath.Dir(p), filepath.FromSlash(strings.SplitN(ref, "?", 2)[0]))
			if _, err := os.Stat(local); err != nil {
				out = append(out, deceptionHit{ID: "dangling-map", Detail: ref})
			}
		}
	}
	return out
}

// mapHoneyHits reads a .map file itself: sources that do not exist beside it, or
// an empty sourcesContent column, are the honey shape.
func mapHoneyHits(p string) []deceptionHit {
	b, err := opRead(p, opMaxFile)
	if err != nil {
		return nil
	}
	var sm webSourceMap
	if err := json.Unmarshal(b, &sm); err != nil {
		return []deceptionHit{{ID: "unreadable-map", Detail: err.Error()}}
	}
	return mapBodyHoneyHits(&sm, p)
}

// mapBodyHoneyHits scores the sources of one parsed map. A map with no sources
// at all is not honey: it is simply a map that names nothing.
func mapBodyHoneyHits(sm *webSourceMap, where string) []deceptionHit {
	if len(sm.Sources) == 0 {
		return nil
	}
	missing, real := 0, 0
	var first string
	for _, s := range sm.Sources {
		if strings.Contains(s, "://") || strings.HasPrefix(s, "//") {
			continue
		}
		name := path.Clean(strings.TrimPrefix(s, "/"))
		if name == "." || name == ".." || strings.HasPrefix(name, "../") {
			continue // escapes the map's tree: not a claim about a local file
		}
		if _, err := os.Stat(filepath.Join(filepath.Dir(where), filepath.FromSlash(name))); err == nil {
			real++
			continue
		}
		missing++
		if first == "" {
			first = s
		}
	}
	if missing == 0 {
		return nil
	}
	embedded := 0
	for _, c := range sm.SourcesContent {
		if c != nil {
			embedded++
		}
	}
	if embedded > 0 {
		// A map that embeds its sources is a reversible pair even when the files
		// are not on disk; only a dangling name with no content is honey.
		return nil
	}
	return []deceptionHit{{
		ID:     "sources-not-on-disk",
		Detail: fmt.Sprintf("%d of %d sources absent, none embedded (first: %s)", missing, missing+real, first),
	}}
}

// asarSourceMapRefs lists an asar's source map trailers. The digest reader
// already walks the header and the packed scripts for exactly these refs, so the
// op reuses it instead of carrying a second asar walk.
func asarSourceMapRefs(p string) []string {
	d, err := Probe(p)
	if err != nil {
		return nil
	}
	return d.SourceMaps
}

// --- shadow-state-machine ---

// shadowIdentRe matches a plausible function/handler identifier in the data
// sections.
var shadowIdentRe = regexp.MustCompile(`[A-Za-z_$][A-Za-z0-9_$]{3,127}`)

// shadowSuffixRe matches a state-machine naming tail: the family root is what
// stays when the tail is removed.
var shadowSuffixRe = regexp.MustCompile(`(?i)(_?state|_?handler|_?dispatch|_?transition|_?step|_?case)$`)

// deceptionShadowState looks for a wide family of state/handler identifiers.
// This is string-level only: a call-graph SCC or an opaque-predicate proof would
// need disassembly, which this op does not do.
//
// shortcut: string-level naming, no SCC or opaque-predicate proof. Upgrade when
// a native call-graph reader can hand this op SCC membership.
func deceptionShadowState(win []byte) deceptionClass {
	c := deceptionClass{Class: "shadow-state-machine", Hits: []deceptionHit{}}
	roots := map[string]bool{}
	members := 0
	first := int64(-1)
	seen := map[string]bool{}
	for _, m := range shadowIdentRe.FindAllIndex(win, -1) {
		name := string(win[m[0]:m[1]])
		if seen[name] {
			continue
		}
		seen[name] = true
		tail := shadowSuffixRe.FindString(name)
		if tail == "" || len(name) <= len(tail) {
			continue
		}
		members++
		roots[strings.ToLower(name[:len(name)-len(tail)])] = true
		if first < 0 {
			first = int64(m[0])
		}
	}
	if members < shadowFamilyMin {
		return c
	}
	o := first
	c.Hits = append(c.Hits, deceptionHit{
		ID:     "state-family",
		Offset: &o,
		Detail: fmt.Sprintf("%d state/handler identifiers across %d roots (string-level, no call-graph SCC)", members, len(roots)),
	})
	return c
}

// decodeBase64JSON decodes an inline map payload into sm.
func decodeBase64JSON(payload string, sm *webSourceMap) error {
	raw, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, sm)
}
