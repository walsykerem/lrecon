package main

// Evergreen 13: the verdict must follow the bytes, not what the file says about
// itself. P and Q are the same Go file: identical top-level names, identical
// helper signature, identical benign header declaration. The only difference is
// in the executable body: Q routes a trigger marker through its helper into a
// real write sink, P does not. The shipped binary scans raw bytes, so it has to
// separate the pair. Nothing here is asserted on the comment text.

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

const eg13Bin = "./lrecon"

const eg13Marker = "__RE_CANARY__"

// eg13Header is shared verbatim by both fixtures: same declared story, same
// package name, same imports, same helper name.
const eg13Header = `// Package statusline reports a single status line. Plain report helper.
// It performs no probes, plants no decoy markers and carries no canary.
package statusline

import (
	"io"
	"strings"
)

func reportStatus(w io.Writer) error {
`

// eg13HonestBody ends the helper without ever touching the marker.
const eg13HonestBody = `	line := strings.TrimSpace("ok")
	_, err := io.WriteString(w, line)
	return err
}
`

// eg13TriggerBody fulfils the same contract but its argument flow reaches the
// sink carrying the marker the tool scans for.
const eg13TriggerBody = `	line := strings.TrimSpace(eg13Token())
	_, err := io.WriteString(w, line)
	return err
}

func eg13Token() string {
	return "__RE_CANARY__"
}
`

// eg13Run executes the shipped binary on one file and returns the op result.
func eg13Run(t *testing.T, path string) map[string]any {
	t.Helper()
	cmd := exec.Command(eg13Bin, "--op", "check_deception_signals", path, "--json")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("run %v: %v (stderr=%q)", cmd.Args, err, stderr.String())
	}
	var env map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &env); err != nil {
		t.Fatalf("envelope for %s not JSON (stdout=%q stderr=%q): %v", path, stdout.String(), stderr.String(), err)
	}
	if env["op"] != "check_deception_signals" {
		t.Fatalf("envelope op = %v, want check_deception_signals", env["op"])
	}
	res, ok := env["result"].(map[string]any)
	if !ok {
		t.Fatalf("no result in envelope: %v", env)
	}
	return res
}

// eg13CanaryHits pulls the canary-credential class hits out of a result.
func eg13CanaryHits(t *testing.T, res map[string]any) []deceptionHit {
	t.Helper()
	classes, ok := res["classes"].([]any)
	if !ok {
		t.Fatalf("classes not a list: %v", res["classes"])
	}
	for _, raw := range classes {
		c, ok := raw.(map[string]any)
		if !ok || c["class"] != "canary-credential" {
			continue
		}
		list, _ := c["hits"].([]any)
		hits := make([]deceptionHit, 0, len(list))
		for _, h := range list {
			hm, ok := h.(map[string]any)
			if !ok {
				t.Fatalf("hit not an object: %v", h)
			}
			var hit deceptionHit
			hit.ID, _ = hm["id"].(string)
			hit.Detail, _ = hm["detail"].(string)
			if off, ok := hm["offset"].(float64); ok {
				o := int64(off)
				hit.Offset = &o
			}
			hits = append(hits, hit)
		}
		return hits
	}
	t.Fatalf("canary-credential class missing from result")
	return nil
}

func TestEvergreen13DeclarationBytesMismatch(t *testing.T) {
	dir := t.TempDir()
	honestPath := filepath.Join(dir, "p_statusline.go")
	triggerPath := filepath.Join(dir, "q_statusline.go")

	honest := []byte(eg13Header + eg13HonestBody)
	trigger := []byte(eg13Header + eg13TriggerBody)

	// Precondition: the shared declaration carries no marker, and both files
	// differ only in the body. Otherwise the separation below would be free.
	if bytes.Contains([]byte(eg13Header), []byte(eg13Marker)) {
		t.Fatalf("shared header unexpectedly carries the marker")
	}
	if !bytes.HasPrefix(trigger, []byte(eg13Header)) || !bytes.HasPrefix(honest, []byte(eg13Header)) {
		t.Fatalf("fixtures must share the same declared header")
	}
	if err := os.WriteFile(honestPath, honest, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(triggerPath, trigger, 0o644); err != nil {
		t.Fatal(err)
	}

	honestRes := eg13Run(t, honestPath)
	triggerRes := eg13Run(t, triggerPath)

	honestHits := eg13CanaryHits(t, honestRes)
	triggerHits := eg13CanaryHits(t, triggerRes)

	// P: benign declaration, benign bytes -> no finding.
	if honestRes["deception_risk"] != "none" {
		t.Fatalf("honest file deception_risk = %v, want none", honestRes["deception_risk"])
	}
	if len(honestHits) != 0 {
		t.Fatalf("honest file reported %d canary hits: %+v", len(honestHits), honestHits)
	}

	// Q: same declaration, different bytes -> the bytes decide.
	if triggerRes["deception_risk"] != "indicators" {
		t.Fatalf("disguised file deception_risk = %v, want indicators (declaration must not outvote the bytes)", triggerRes["deception_risk"])
	}
	if len(triggerHits) != 1 {
		t.Fatalf("disguised file canary hits = %d (%+v), want exactly 1", len(triggerHits), triggerHits)
	}
	if triggerHits[0].ID != eg13Marker {
		t.Fatalf("hit id = %q, want %q", triggerHits[0].ID, eg13Marker)
	}
	if triggerHits[0].Offset == nil {
		t.Fatalf("hit carries no offset")
	}
	wantOff := int64(bytes.Index(trigger, []byte(eg13Marker)))
	if *triggerHits[0].Offset != wantOff {
		t.Fatalf("hit offset = %d, want %d (the marker's byte offset)", *triggerHits[0].Offset, wantOff)
	}
	// The located bytes sit past the shared declaration, inside the executable
	// argument flow: the verdict is anchored to code, not to self-description.
	if wantOff <= int64(len(eg13Header)) {
		t.Fatalf("marker offset %d not past the shared header (%d)", wantOff, len(eg13Header))
	}

	// The pair is indistinguishable by name, only by bytes.
	if honestRes["deception_risk"] == triggerRes["deception_risk"] {
		t.Fatalf("verdict did not separate honest from disguised: both %v", honestRes["deception_risk"])
	}
}
