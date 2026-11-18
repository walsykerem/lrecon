package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestEvergreen14ContractTriggerBreaks: the contract route is two-way.
//
// lrecon 1.0.0 does not read skill/ at runtime: contractVersion is the compiled
// constant in types.go:43 and the enforcement point is loadDigest, main.go:632,
// which refuses any saved digest whose contract_version differs. So the only
// contract artifact a caller can hand the tool is a saved digest, and the test
// pins both directions: a current digest is a live comparison baseline, the same
// bytes with the version damaged are refused before any comparison runs. It also
// pins the finding that the skill/ references are inert prose, not input.
func TestEvergreen14ContractTriggerBreaks(t *testing.T) {
	dir := t.TempDir()
	target, err := filepath.Abs(fixtureFat)
	if err != nil {
		t.Fatal(err)
	}

	// The healthy contract copy: a digest the tool itself emits for a real
	// Mach-O target, contract_version 1.
	healthyRaw, code := runCLI(t, "--json", target)
	if code != 0 {
		t.Fatalf("--json %s exit %d, want 0:\n%s", target, code, healthyRaw)
	}
	var healthyDigest Digest
	if err := json.Unmarshal([]byte(healthyRaw), &healthyDigest); err != nil {
		t.Fatalf("digest is not JSON: %v", err)
	}
	if contractVersion != 1 || healthyDigest.ContractVersion != contractVersion {
		t.Fatalf("contract_version = const %d / digest %d, want 1/1",
			contractVersion, healthyDigest.ContractVersion)
	}
	healthy := filepath.Join(dir, "healthy.json")
	if err := os.WriteFile(healthy, []byte(healthyRaw), 0o644); err != nil {
		t.Fatal(err)
	}

	// Healthy route 1: comparing a digest with its own target is accepted and
	// reports no change (exit 0).
	out, stderr, code := runCLIAll(t, "--diff", healthy, target)
	if code != 0 {
		t.Fatalf("--diff healthy exit %d, want 0; stdout=%q stderr=%q", code, out, stderr)
	}
	if strings.TrimSpace(out) != "" {
		t.Fatalf("--diff healthy printed %q, want no changes", out)
	}

	// Healthy route 2: the digest is a live baseline, so another target is a
	// measured difference (exit 1, one line per changed field).
	other := filepath.Join(dir, "other.txt")
	if err := os.WriteFile(other, []byte("evergreen14 other target\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, stderr, code = runCLIAll(t, "--diff", healthy, other)
	if code != 1 {
		t.Fatalf("--diff healthy vs other exit %d, want 1; stdout=%q stderr=%q", code, out, stderr)
	}
	if !strings.Contains(out, "sha256 ") || !strings.Contains(out, "size ") {
		t.Fatalf("--diff healthy vs other printed %q, want sha256/size changes", out)
	}

	// Damage 1: corrupt the version string. Routing must degrade to a refusal
	// and the comparison must never run.
	damaged := strings.Replace(healthyRaw, `"contract_version":1`, `"contract_version":2`, 1)
	if damaged == healthyRaw {
		t.Fatalf("digest has no %q to damage: %s", `"contract_version":1`, healthyRaw)
	}
	damagedPath := filepath.Join(dir, "damaged-version.json")
	if err := os.WriteFile(damagedPath, []byte(damaged), 0o644); err != nil {
		t.Fatal(err)
	}
	out, stderr, code = runCLIAll(t, "--diff", damagedPath, other)
	if code != 2 {
		t.Fatalf("--diff damaged version exit %d, want 2; stdout=%q stderr=%q", code, out, stderr)
	}
	if !strings.Contains(stderr, "is contract_version 2, want 1: regenerate it with this lrecon") {
		t.Fatalf("stderr = %q, want the contract_version 2 refusal", stderr)
	}
	if strings.Contains(out, "sha256 ") {
		t.Fatalf("damaged contract still compared: %q", out)
	}

	// Damage 2: delete the trigger. A missing version reads as 0 and is refused
	// the same way, so "no version" cannot pass as "current".
	var fields map[string]any
	if err := json.Unmarshal([]byte(healthyRaw), &fields); err != nil {
		t.Fatal(err)
	}
	delete(fields, "contract_version")
	noVersionRaw, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	noVersion := filepath.Join(dir, "damaged-missing.json")
	if err := os.WriteFile(noVersion, noVersionRaw, 0o644); err != nil {
		t.Fatal(err)
	}
	out, stderr, code = runCLIAll(t, "--diff", noVersion, other)
	if code != 2 {
		t.Fatalf("--diff missing version exit %d, want 2; stdout=%q stderr=%q", code, out, stderr)
	}
	if !strings.Contains(stderr, "is contract_version 0, want 1: regenerate it with this lrecon") {
		t.Fatalf("stderr = %q, want the contract_version 0 refusal", stderr)
	}

	// Finding: the tool cannot be pointed at a copy of skill/. Corrupting every
	// contract document inside a working directory changes nothing, because the
	// contract is compiled in and the references are never opened at runtime.
	docsDir := filepath.Join(dir, "skill")
	for _, rel := range []string{"SKILL.md", filepath.Join("references", "contract.md"), filepath.Join("references", "router.md")} {
		src := filepath.Join("..", "skill", rel)
		body, err := os.ReadFile(src)
		if err != nil {
			t.Fatalf("read contract doc %s: %v", src, err)
		}
		if len(body) == 0 {
			t.Fatalf("contract doc %s is empty", src)
		}
		dst := filepath.Join(docsDir, rel)
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dst, []byte("contract_version: 999\nrouting: broken\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command(cliPath, "--json", target)
	cmd.Dir = docsDir
	var stdout, stderrBuf strings.Builder
	cmd.Stdout, cmd.Stderr = &stdout, &stderrBuf
	if err := cmd.Run(); err != nil {
		t.Fatalf("--json from damaged skill dir: %v; stderr=%q", err, stderrBuf.String())
	}
	if stdout.String() != healthyRaw {
		t.Fatalf("digest changed with damaged skill docs: got %q, want %q", stdout.String(), healthyRaw)
	}
}
