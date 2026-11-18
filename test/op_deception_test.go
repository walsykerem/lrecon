package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func deceptionResult(t *testing.T, path string) map[string]any {
	t.Helper()
	got, err := runCheckDeception(path)
	if err != nil {
		t.Fatalf("check_deception_signals: %v", err)
	}
	return got.(map[string]any)
}

func deceptionClassOf(t *testing.T, res map[string]any, class string) deceptionClass {
	t.Helper()
	for _, c := range res["classes"].([]deceptionClass) {
		if c.Class == class {
			return c
		}
	}
	t.Fatalf("class %q not in output", class)
	return deceptionClass{}
}

func TestDeceptionCanaryCredential(t *testing.T) {
	p := writeTmp(t, "canary.bin", []byte("... __RE_CANARY__ ... REA_TRAP ... 0xFAB11BAF ..."))
	res := deceptionResult(t, p)
	c := deceptionClassOf(t, res, "canary-credential")
	if len(c.Hits) != 3 {
		t.Fatalf("canary hits = %+v, want all three markers", c.Hits)
	}
	for _, h := range c.Hits {
		if h.Offset == nil || *h.Offset < 0 {
			t.Fatalf("hit %q carries no offset", h.ID)
		}
	}
	if res["deception_risk"] != "indicators" {
		t.Fatalf("deception_risk = %v, want indicators", res["deception_risk"])
	}
}

func TestDeceptionCleanBinaryIsNone(t *testing.T) {
	p := writeTmp(t, "clean.bin", []byte("ordinary data, no decoy markers here at all"))
	res := deceptionResult(t, p)
	if res["deception_risk"] != "none" {
		t.Fatalf("deception_risk = %v, want none", res["deception_risk"])
	}
	for _, c := range res["classes"].([]deceptionClass) {
		if len(c.Hits) != 0 {
			t.Fatalf("clean file hit class %s: %+v", c.Class, c.Hits)
		}
	}
}

// A source map trailer that resolves nowhere is honey; the wrong kind of target
// answers with no hits instead of a guess.
func TestDeceptionHoneySourcemapScript(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "app.js")
	if err := os.WriteFile(script, []byte("var x=1\n//# sourceMappingURL=app.js.map\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	c := deceptionClassOf(t, deceptionResult(t, script), "honey-sourcemap")
	if len(c.Hits) != 1 || c.Hits[0].ID != "dangling-map" {
		t.Fatalf("honey hits = %+v, want one dangling-map", c.Hits)
	}
}

func TestDeceptionHoneySourcemapMap(t *testing.T) {
	dir := t.TempDir()
	mapPath := filepath.Join(dir, "bundle.js.map")
	sm := webSourceMap{
		Version: 3,
		File:    "bundle.js",
		Sources: []string{"src/genuinely-absent.ts", "src/also-absent.ts"},
	}
	raw, err := json.Marshal(sm)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mapPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	c := deceptionClassOf(t, deceptionResult(t, mapPath), "honey-sourcemap")
	if len(c.Hits) != 1 || c.Hits[0].ID != "sources-not-on-disk" {
		t.Fatalf("honey hits = %+v, want sources-not-on-disk", c.Hits)
	}
}

// A map whose sources are embedded (sourcesContent) is a reversible pair, not
// honey, even when the original files are not on disk.
func TestDeceptionEmbeddedSourcesAreNotHoney(t *testing.T) {
	dir := t.TempDir()
	mapPath := filepath.Join(dir, "bundle.js.map")
	content := "export const x = 1\n"
	sm := webSourceMap{
		Version:        3,
		File:           "bundle.js",
		Sources:        []string{"src/main.ts"},
		SourcesContent: []*string{&content},
	}
	raw, err := json.Marshal(sm)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mapPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	c := deceptionClassOf(t, deceptionResult(t, mapPath), "honey-sourcemap")
	if len(c.Hits) != 0 {
		t.Fatalf("embedded sources flagged as honey: %+v", c.Hits)
	}
}

// The honey class only applies to asar and js/ts targets; a plain binary is the
// wrong kind and yields no hits (never a guessed one).
func TestDeceptionHoneyWrongKindNoHits(t *testing.T) {
	p := writeTmp(t, "plain.bin", []byte("//# sourceMappingURL=nowhere.js.map\n"))
	c := deceptionClassOf(t, deceptionResult(t, p), "honey-sourcemap")
	if len(c.Hits) != 0 {
		t.Fatalf("wrong-kind target flagged: %+v", c.Hits)
	}
}

func TestDeceptionShadowStateMachine(t *testing.T) {
	var sb strings.Builder
	for _, root := range []string{"alpha", "beta", "gamma", "delta", "epsilon", "zeta", "eta", "theta"} {
		sb.WriteString(root)
		sb.WriteString("Handler ")
	}
	sb.WriteString("unrelatedFunction loneState x y z")
	p := writeTmp(t, "shadow.bin", []byte(sb.String()))
	c := deceptionClassOf(t, deceptionResult(t, p), "shadow-state-machine")
	if len(c.Hits) != 1 || c.Hits[0].ID != "state-family" {
		t.Fatalf("shadow hits = %+v, want one state family", c.Hits)
	}
}

func TestDeceptionShadowNeedsEightMembers(t *testing.T) {
	var sb strings.Builder
	for _, root := range []string{"alpha", "beta", "gamma"} {
		sb.WriteString(root)
		sb.WriteString("Handler ")
	}
	p := writeTmp(t, "thin.bin", []byte(sb.String()))
	c := deceptionClassOf(t, deceptionResult(t, p), "shadow-state-machine")
	if len(c.Hits) != 0 {
		t.Fatalf("three siblings flagged as a state machine: %+v", c.Hits)
	}
}

// Decoys are indicators, never a verdict: the answer must not say the analysis
// was defeated or the check bypassed.
func TestDeceptionNeverClaimsBypass(t *testing.T) {
	p := writeTmp(t, "canary.bin", []byte("__RE_CANARY__ REA_TRAP plus alphaHandler betaHandler gammaHandler deltaHandler epsilonHandler zetaHandler etaHandler thetaHandler"))
	text := strings.ToLower(toString(deceptionResult(t, p)))
	for _, bad := range []string{"bypassed", "defeated"} {
		if strings.Contains(text, bad) {
			t.Fatalf("output contains %q: %s", bad, text)
		}
	}
}

// An asar whose packed script points at a map the archive does not hold is the
// honey shape: the trailer resolves to no member, so "recovering" it yields
// nothing. writeAsarArchive is the helper asar_test.go already builds archives
// with, so no new fixture is needed.
func TestDeceptionHoneySourcemapAsar(t *testing.T) {
	p := writeAsarArchive(t, t.TempDir(), "app.asar", map[string][]byte{
		"package.json": []byte(`{"main":"index.js"}`),
		"index.js":     []byte("var x=1\n//# sourceMappingURL=index.js.map\n"),
	})
	c := deceptionClassOf(t, deceptionResult(t, p), "honey-sourcemap")
	if len(c.Hits) != 1 || c.Hits[0].ID != "dangling-map" {
		t.Fatalf("asar honey hits = %+v, want one dangling-map", c.Hits)
	}
}
