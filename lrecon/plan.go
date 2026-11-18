package main

import (
	"encoding/json"
	"fmt"
	"strings"
)

// planFor answers the three turns a caller spends by hand today: identify the
// kind, pick the op that is worth running, then run it. One --plan call names
// the op and hands back the filled command line, so the reader does not have to
// read the 235-row inventory to guess.
//
// Only ops observed working on that kind are listed; a kind with no entry falls
// back to binary_overview, which reads any native file.
var planFor = map[string]struct {
	op   string
	next []string
}{
	"macho": {"inspect_macho", []string{"trace_dylib_resolution", "inspect_artifact", "inspect_go_binary"}},
	"elf":   {"inspect_elf_notes", []string{"inspect_native_exports", "evaluate_reconstruction_coverage"}},
	"pe":    {"inspect_pe_imports", []string{"inspect_pe_load_config", "inspect_pe_resources"}},
}

var planFallback = struct {
	op   string
	next []string
}{"binary_overview", []string{"inspect_artifact"}}

// planResultKeys are the result fields the plan promises for its own op. A test
// runs each op on its fixture and fails when one of these is missing, so the
// promise cannot drift from the answer.
var planResultKeys = map[string][]string{
	"inspect_macho":      {"kind", "format", "slices", "minos", "dylibs"},
	"inspect_elf_notes":  {"machine", "build_id", "owners", "notes"},
	"inspect_pe_imports": {"dlls", "imports", "total"},
	"binary_overview":    {"summary", "kind", "exports", "symbols"},
}

// plan is the machine answer of --plan: what the target is, which op answers it
// next, the paste-ready command, and the envelope that command prints.
type plan struct {
	Kind     string       `json:"kind"`
	Format   string       `json:"format"`
	Op       string       `json:"op"`
	Cmd      string       `json:"cmd"`
	Envelope planEnvelope `json:"envelope"`
	Next     []string     `json:"next"`
}

// planEnvelope is the shape promise: --json always answers one object with
// these top keys, and the op's result carries at least result.
type planEnvelope struct {
	Top    []string `json:"top"`
	Result []string `json:"result"`
}

func buildPlan(d Digest, path string) plan {
	step, ok := planFor[d.Kind]
	if !ok {
		step = planFallback
	}
	p := plan{
		Kind:   d.Kind,
		Format: d.Format,
		Op:     step.op,
		Cmd:    "lrecon " + opCmd(step.op, path),
		Envelope: planEnvelope{
			Top:    []string{"op", "target", "result"},
			Result: planResultKeys[step.op],
		},
	}
	for _, name := range step.next {
		if _, known := ops[name]; !known {
			continue
		}
		p.Next = append(p.Next, "lrecon "+opCmd(name, path))
	}
	return p
}

func opCmd(name, path string) string {
	return "--op " + name + " --json " + shellArg(path)
}

// shellArg quotes a path only when the shell would otherwise split or expand it.
func shellArg(s string) string {
	if s != "" && !strings.ContainsAny(s, " \t\n'\"\\$&|;<>()*?[]{}!~`") {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func printPlan(p plan) {
	b, err := json.Marshal(p)
	if err != nil {
		refuse(err.Error())
	}
	fmt.Println(string(b))
}

// printNext is --plan with the envelope and the identity dropped: only the
// commands a caller pastes next.
func printNext(p plan) {
	for _, c := range p.Next {
		fmt.Println(c)
	}
}
