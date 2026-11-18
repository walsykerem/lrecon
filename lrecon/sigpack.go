package main

import (
	"bytes"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
)

// Signature pack: fixed literal markers, matched in one pass over a bounded
// window. A hit is one mechanism (Axis "sig") and never a language claim on its
// own; settleLanguage pairs it with a disjoint witness from the symbol mangling
// classifier and lets emit() decide.
//
//go:embed sigpack.json
var sigpackJSON []byte

const (
	// sigpackSchema is the only pack layout this build understands. A pack with
	// another version is refused whole, so a rule set never half-loads.
	sigpackSchema = 1
	// maxSigScan bounds the window scanned for markers. A marker past this window
	// is not looked at, and the digest says so instead of reporting "absent".
	maxSigScan = 16 << 20
	// sigMaxHitsPerRule keeps a hostile file full of repeated markers from
	// crowding the digest; one witness per language is all a claim can use.
	sigMaxHitsPerRule = 1
)

// sigRule is one marker: a literal (hex or str, never both), where it may sit,
// and the literals that cancel it — a marker of another family in the same file
// makes this hit evidence for neither.
type sigRule struct {
	ID     string   `json:"id"`
	Lang   string   `json:"lang"`
	Str    string   `json:"str,omitempty"`
	Hex    string   `json:"hex,omitempty"`
	At     string   `json:"at,omitempty"`
	Not    []string `json:"not,omitempty"`
	Corpus string   `json:"corpus,omitempty"`
}

type sigpackFile struct {
	Schema int       `json:"schema_version"`
	Note   string    `json:"note"`
	Rules  []sigRule `json:"rules"`
}

// sigPat is one loaded rule: literal bytes plus the anti-markers that cancel it.
type sigPat struct {
	id   string
	lang string
	at   string
	lit  []byte
	not  [][]byte
}

var (
	sigOnce  sync.Once
	sigPats  []sigPat
	sigDrops map[string]int // refusal reason -> rules dropped at load
	sigErr   error
)

// loadSigpack parses the embedded pack once. Every refusal is by rule id, so the
// set of loaded rules is identical on every machine.
func loadSigpack() {
	p := sigpackFile{}
	if err := json.Unmarshal(sigpackJSON, &p); err != nil {
		sigErr = fmt.Errorf("sigpack: %v", err)
		return
	}
	if p.Schema != sigpackSchema {
		sigErr = fmt.Errorf("sigpack: schema %d, this build reads %d", p.Schema, sigpackSchema)
		return
	}
	sigDrops = map[string]int{}
	for _, r := range p.Rules {
		pat, why := compileSigRule(r)
		if why != "" {
			sigDrops[why]++
			continue
		}
		sigPats = append(sigPats, pat)
	}
	sort.Slice(sigPats, func(i, j int) bool { return sigPats[i].id < sigPats[j].id })
}

// compileSigRule turns one rule into a matcher, or names the reason it cannot be
// trusted. A literal shorter than atomLen, or one whose first four bytes carry
// fewer than three distinct values, would match half a file: it is dropped at
// load time rather than run per byte.
func compileSigRule(r sigRule) (sigPat, string) {
	if r.ID == "" || r.Lang == "" {
		return sigPat{}, "sigpack-schema"
	}
	var lit []byte
	switch {
	case r.Str != "" && r.Hex != "":
		return sigPat{}, "sigpack-schema"
	case r.Str != "":
		lit = []byte(r.Str)
	case r.Hex != "":
		b, err := hex.DecodeString(r.Hex)
		if err != nil {
			return sigPat{}, "sigpack-schema"
		}
		lit = b
	default:
		return sigPat{}, "sigpack-schema"
	}
	if r.At == "" {
		r.At = "any"
	}
	if r.At != "any" && r.At != "0" {
		return sigPat{}, "sigpack-at-unsupported"
	}
	if !strongAtom(lit) {
		return sigPat{}, "sigpack-weak-atom"
	}
	pat := sigPat{id: r.ID, lang: r.Lang, at: r.At, lit: lit}
	for _, n := range r.Not {
		if n == "" {
			continue
		}
		pat.not = append(pat.not, []byte(n))
	}
	return pat, ""
}

// atomLen is the fixed window the load-time quality gate scores.
const atomLen = 4

// strongAtom reports whether the first atomLen bytes are specific enough to be
// worth a byte-by-byte scan: at least three distinct values, and no period-1 or
// period-2 repeat (the 00 00 00 00 and abababab cases).
func strongAtom(lit []byte) bool {
	if len(lit) < atomLen {
		return false
	}
	w := lit[:atomLen]
	distinct := map[byte]bool{}
	for _, b := range w {
		distinct[b] = true
	}
	if len(distinct) < 3 {
		return false
	}
	if w[0] == w[1] && w[2] == w[3] && w[0] == w[2] {
		return false
	}
	return true
}

func init() {
	register(reader{
		format: "sigpack",
		reasons: []string{
			"sigpack-schema",
			"sigpack-weak-atom",
			"sigpack-at-unsupported",
			"sigpack-truncated",
		},
		inspect: inspectSigpack,
		post:    true,
	})
}

// inspectSigpack records one witness per language marker it actually saw. The
// window is read once; a marker beyond it is reported as not scanned.
func inspectSigpack(path string, d *Digest) {
	switch d.Kind {
	case "elf", "macho", "pe":
	default:
		return
	}
	sigOnce.Do(loadSigpack)
	if sigErr != nil {
		d.skip("sigpack-schema", sigErr.Error())
		return
	}
	for _, reason := range []string{"sigpack-schema", "sigpack-at-unsupported", "sigpack-weak-atom"} {
		if n := sigDrops[reason]; n > 0 {
			d.skip(reason, fmt.Sprintf("%d rules refused at load", n))
		}
	}
	win := head(path, maxSigScan)
	if int64(len(win)) < d.FileSize {
		d.skip("sigpack-truncated", fmt.Sprintf("markers scanned in the first %d of %d bytes", len(win), d.FileSize))
	}
	hits := matchSigpack(win)
	for _, lang := range sortedSigLangs(hits) {
		h := hits[lang][0]
		d.witness(Witness{Axis: "sig", Class: "sigpack", Value: lang, Start: h.start, End: h.end})
		d.parsed()
	}
}

type sigHit struct {
	rule  string
	start int64
	end   int64
}

// matchSigpack runs every loaded rule over the window. Anti-markers are checked
// first: a file carrying another family's marker is not evidence for this one.
func matchSigpack(win []byte) map[string][]sigHit {
	out := map[string][]sigHit{}
	for _, p := range sigPats {
		cancelled := false
		for _, n := range p.not {
			if bytes.Contains(win, n) {
				cancelled = true
				break
			}
		}
		if cancelled {
			continue
		}
		offs := sigOffsets(win, p, sigMaxHitsPerRule)
		for _, off := range offs {
			out[p.lang] = append(out[p.lang], sigHit{rule: p.id, start: int64(off), end: int64(off) + int64(len(p.lit))})
		}
	}
	for lang := range out {
		sort.Slice(out[lang], func(i, j int) bool {
			if out[lang][i].start != out[lang][j].start {
				return out[lang][i].start < out[lang][j].start
			}
			return out[lang][i].rule < out[lang][j].rule
		})
	}
	return out
}

// sigOffsets returns the distinct offsets a rule matches at, in file order.
// limit bounds the work as well as the result: matchSigpack keeps at most
// sigMaxHitsPerRule hits, so a hostile file full of one marker must not make the
// scan allocate an offset per byte.
func sigOffsets(win []byte, p sigPat, limit int) []int {
	var out []int
	for i := 0; i+len(p.lit) <= len(win) && len(out) < limit; {
		j := bytes.Index(win[i:], p.lit)
		if j < 0 {
			break
		}
		off := i + j
		if p.at == "any" || off == 0 {
			out = append(out, off)
		}
		if p.at == "0" {
			break
		}
		i = off + 1
	}
	return out
}

func sortedSigLangs(hits map[string][]sigHit) []string {
	langs := make([]string, 0, len(hits))
	for lang := range hits {
		langs = append(langs, lang)
	}
	sort.Strings(langs)
	return langs
}

// langFromFamily maps a mangling family to the language it is evidence for. A
// family is a scheme, not a language: itanium and msvc are both C++.
var langFromFamily = map[string]string{
	"itanium":     "c++",
	"msvc":        "c++",
	"rust-legacy": "rust",
	"rust-v0":     "rust",
	"swift":       "swift",
	"go":          "go",
	"objc":        "objc",
}

// settleLanguage proposes one claim per language that has a marker, and lets
// emit decide. A marker alone lands in Unknown with witness-same-mech: the pack
// never turns a single reader into a language.
func (d *Digest) settleLanguage() {
	byLang := map[string][]Witness{}
	// One witness per mechanism per language: witnessGap refuses a second one,
	// so keeping it would turn two markers into no claim at all.
	add := func(lang string, w Witness) {
		for _, have := range byLang[lang] {
			if have.Axis == w.Axis {
				return
			}
		}
		byLang[lang] = append(byLang[lang], w)
	}
	for _, w := range d.witnesses {
		switch w.Axis {
		case "sig":
			add(w.Value, w)
		case "mangling":
			lang, ok := langFromFamily[w.Value]
			if !ok {
				continue
			}
			w.Axis, w.Value = "parser", lang
			add(lang, w)
		}
	}
	if len(byLang) == 0 {
		return
	}
	langs := make([]string, 0, len(byLang))
	for lang := range byLang {
		langs = append(langs, lang)
	}
	sort.Strings(langs)
	for _, lang := range langs {
		d.emit(claimReq{Slot: "language", Value: lang, Witnesses: byLang[lang]})
	}
}
