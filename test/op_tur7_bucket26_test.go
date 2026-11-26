package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestTur7Bucket26CallPathDisasmHops proves trace_call_path reports the call
// chain the machine code actually contains, not a plausible one. The fixture is
// built so name similarity and call order disagree: alpha calls beta, beta
// calls delta, delta calls gamma — beta never calls gamma, so the "obvious"
// alpha,beta,gamma answer is wrong. `go tool objdump` supplies the real CALL
// targets independently of Ghidra; every hop the tool returns must be one of
// them, in order.
func TestTur7Bucket26CallPathDisasmHops(t *testing.T) {
	requireRealGhidra(t)
	dir := t.TempDir()
	src := `package main

//go:noinline
func gamma(n int) int { return n*3 + 1 }

//go:noinline
func delta(n int) int { return gamma(n) + 4 }

//go:noinline
func zeta(n int) int { return n - 7 }

//go:noinline
func beta(n int) int { return delta(n) + 2 }

//go:noinline
func alpha(n int) int { return beta(n) + zeta(n) }

func main() { println(alpha(2)) }
`
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module chain26\n\ngo 1.21\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "chain")
	build := exec.Command("go", "build", "-gcflags=all=-l", "-o", bin, ".")
	build.Dir = dir
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("fixture build failed: %v\n%s", err, out)
	}

	// directCallees reads the CALL targets of one function straight out of the
	// disassembly, keeping only the fixture's own functions.
	self := map[string]bool{"main.alpha": true, "main.beta": true, "main.delta": true, "main.gamma": true, "main.zeta": true}
	directCallees := func(fn string) []string {
		t.Helper()
		out, err := exec.Command("go", "tool", "objdump", "-s", "^"+strings.ReplaceAll(fn, ".", "\\.")+"$", bin).Output()
		if err != nil {
			t.Fatalf("go tool objdump %s: %v", fn, err)
		}
		var got []string
		for line := range strings.SplitSeq(string(out), "\n") {
			fields := strings.Fields(line)
			for i, tok := range fields {
				if (tok != "CALL" && tok != "BL") || i+1 >= len(fields) {
					continue
				}
				if target := strings.TrimSuffix(fields[i+1], "(SB)"); self[target] && !slices.Contains(got, target) {
					got = append(got, target)
				}
			}
		}
		return got
	}

	// The disassembly must agree with the fixture's trap before the tool is
	// asked anything: beta reaches gamma only through delta.
	if got := directCallees("main.beta"); !slices.Equal(got, []string{"main.delta"}) {
		t.Fatalf("fixture is not the trap it claims: main.beta calls %v, want [main.delta]", got)
	}
	if got := directCallees("main.delta"); !slices.Equal(got, []string{"main.gamma"}) {
		t.Fatalf("fixture is not the trap it claims: main.delta calls %v, want [main.gamma]", got)
	}
	if got := directCallees("main.alpha"); !slices.Contains(got, "main.beta") || slices.Contains(got, "main.gamma") {
		t.Fatalf("fixture is not the trap it claims: main.alpha calls %v, want main.beta and not main.gamma", got)
	}

	t.Setenv("LRECON_FROM", "main.alpha")
	t.Setenv("LRECON_TO", "main.gamma")
	stdout, code := runCLI(t, "--json", "--op", "trace_call_path", bin)
	if code != 0 {
		t.Fatalf("trace_call_path exit %d, want 0; output:\n%s", code, stdout)
	}
	var env struct {
		Result struct {
			From     string   `json:"from"`
			To       string   `json:"to"`
			Found    bool     `json:"found"`
			Depth    int      `json:"depth"`
			Coverage string   `json:"coverage"`
			MaxDepth int      `json:"max_depth"`
			Path     []string `json:"path"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(stdout), &env); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s", err, stdout)
	}
	r := env.Result
	want := []string{"main.alpha", "main.beta", "main.delta", "main.gamma"}
	if !r.Found || r.Coverage != "resolved-path" {
		t.Fatalf("found=%v coverage=%q, want true/resolved-path; output:\n%s", r.Found, r.Coverage, stdout)
	}
	if r.From != "main.alpha" || r.To != "main.gamma" {
		t.Fatalf("from=%q to=%q, want main.alpha -> main.gamma", r.From, r.To)
	}
	if !slices.Equal(r.Path, want) {
		t.Fatalf("path = %v, want the disassembled chain %v", r.Path, want)
	}
	if r.Depth != len(want)-1 {
		t.Fatalf("depth = %d, want %d for a %d-hop path", r.Depth, len(want)-1, len(want)-1)
	}
	if r.MaxDepth <= r.Depth {
		t.Fatalf("max_depth = %d, want a cap above the found depth %d", r.MaxDepth, r.Depth)
	}
	// Each returned hop must be a CALL the disassembly shows: a fabricated or
	// name-guessed hop cannot survive this.
	for i := 1; i < len(r.Path); i++ {
		caller, callee := r.Path[i-1], r.Path[i]
		if !slices.Contains(directCallees(caller), callee) {
			t.Fatalf("hop %d: %s -> %s is not a CALL in `go tool objdump` of %s (real callees %v)",
				i, caller, callee, caller, directCallees(caller))
		}
	}
}
