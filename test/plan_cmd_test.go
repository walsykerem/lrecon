package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// planFixture is the file each plan entry was measured on: the pointer a
// caller's kind routes to must actually be a file of that kind.
var planFixture = map[string]string{
	"macho": "testdata/fixtures/macho",
	"elf":   "testdata/fixtures/elf",
	"pe":    "testdata/fixtures/pe.exe",
}

// TestPlanOpAnswersOnItsFixture runs the op --plan recommends: the plan is only
// worth one turn if the command it fills in works and carries the envelope keys
// it promised.
func TestPlanOpAnswersOnItsFixture(t *testing.T) {
	for kind, fixture := range planFixture {
		d, err := Probe(fixture)
		if err != nil {
			t.Fatalf("%s: %v", fixture, err)
		}
		if d.Kind != kind {
			t.Fatalf("%s: kind = %q, want %q", fixture, d.Kind, kind)
		}
		p := buildPlan(d, fixture)
		res, err := runOp(p.Op, fixture)
		if err != nil {
			t.Fatalf("%s: planned op %q failed: %v", fixture, p.Op, err)
		}
		b, err := json.Marshal(map[string]any{"op": p.Op, "target": fixture, "result": res})
		if err != nil {
			t.Fatalf("%s: %v", fixture, err)
		}
		var got map[string]any
		if err := json.Unmarshal(b, &got); err != nil {
			t.Fatalf("%s: %v", fixture, err)
		}
		for _, k := range p.Envelope.Top {
			if _, ok := got[k]; !ok {
				t.Errorf("%s: envelope promises top key %q, op answer has none", fixture, k)
			}
		}
		inner, ok := got["result"].(map[string]any)
		if !ok {
			t.Fatalf("%s: op %q answered with %T, want an object", fixture, p.Op, got["result"])
		}
		for _, k := range p.Envelope.Result {
			if _, ok := inner[k]; !ok {
				t.Errorf("%s: envelope promises result key %q, op %q answer has none", fixture, k, p.Op)
			}
		}
		for _, c := range p.Next {
			name := strings.Fields(c)[2]
			if _, ok := ops[name]; !ok {
				t.Errorf("%s: next command names unregistered op %q", fixture, name)
			}
		}
	}
}

// TestPlanCLIOneCall pins the one-call contract: --plan answers kind, op and the
// filled command on stdout, and --next prints commands only.
func TestPlanCLIOneCall(t *testing.T) {
	out, rc := runCLI(t, "testdata/fixtures/macho", "--plan")
	if rc != 0 {
		t.Fatalf("--plan rc = %d, want 0: %s", rc, out)
	}
	var p plan
	if err := json.Unmarshal([]byte(out), &p); err != nil {
		t.Fatalf("--plan is not one JSON object: %v\n%s", err, out)
	}
	if p.Kind != "macho" || p.Op != "inspect_macho" {
		t.Fatalf("plan = kind %q op %q, want macho/inspect_macho", p.Kind, p.Op)
	}
	if !strings.HasPrefix(p.Cmd, "lrecon --op inspect_macho --json ") || !strings.Contains(p.Cmd, "testdata/fixtures/macho") {
		t.Fatalf("cmd = %q: target or op missing", p.Cmd)
	}
	if len(p.Next) < 2 {
		t.Fatalf("plan carries %d next commands, want 2-3", len(p.Next))
	}
	// The filled command must be paste-ready: the op it names runs on the path
	// it names.
	fields := strings.Fields(p.Cmd)
	if _, err := runOp(fields[2], fields[len(fields)-1]); err != nil {
		t.Fatalf("plan cmd %q does not run: %v", p.Cmd, err)
	}

	next, rc := runCLI(t, "testdata/fixtures/elf", "--next")
	if rc != 0 {
		t.Fatalf("--next rc = %d, want 0: %s", rc, next)
	}
	for ln := range strings.SplitSeq(strings.TrimSpace(next), "\n") {
		if !strings.HasPrefix(ln, "lrecon --op ") {
			t.Errorf("--next printed %q, want a command", ln)
		}
	}

	if out, errOut, rc := runCLIAll(t, "testdata/fixtures/macho", "--plan", "--next"); rc != 2 || !strings.Contains(errOut+out, "cannot be combined") {
		t.Fatalf("--plan --next = rc %d %q %q, want a refusal", rc, out, errOut)
	}
}
