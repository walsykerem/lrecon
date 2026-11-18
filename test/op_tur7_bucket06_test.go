package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestTur7Bucket06SkillShim drives the real skill/scripts/find.sh shim. The
// shim is the only path the documented skill uses for the catalog queries the
// binary lacks, so its argv is a contract: it must honour the LRECON override,
// fall back to PATH, and every argv it builds must be accepted verbatim by the
// built CLI. A flag the binary rejects makes the skill's own entry point dead.
func TestTur7Bucket06SkillShim(t *testing.T) {
	script := tur7b06Script(t)
	dir := t.TempDir()
	stub := filepath.Join(dir, "lrecon")
	const stubBody = `#!/usr/bin/env bash
printf '%s\n' "$@" >> "$LRECON_ARGV_LOG"
if [[ "${1:-}" == "--list-ops" && "${2:-}" == "--json" ]]; then
	echo '[]'
elif [[ "${1:-}" == "--list-ops" ]]; then
	printf 'check_stub\tL\ttarget\n'
else
	echo stub
fi
`
	if err := os.WriteFile(stub, []byte(stubBody), 0o755); err != nil {
		t.Fatal(err)
	}
	basePATH := "/usr/bin:/bin:/usr/sbin:/sbin"

	// argv reads back one recorded invocation; a missing log means the stub was
	// never reached, which is itself a fact (the usage branch must not call it).
	argv := func(t *testing.T, log string) []string {
		t.Helper()
		b, err := os.ReadFile(log)
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			t.Fatal(err)
		}
		s := strings.TrimSuffix(string(b), "\n")
		if s == "" {
			return nil
		}
		return strings.Split(s, "\n")
	}
	run := func(t *testing.T, env []string, args ...string) (string, string, int) {
		t.Helper()
		cmd := exec.Command("bash", append([]string{script}, args...)...)
		cmd.Env = env
		var out, errb strings.Builder
		cmd.Stdout, cmd.Stderr = &out, &errb
		err := cmd.Run()
		if err == nil {
			return out.String(), errb.String(), 0
		}
		ee, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatalf("find.sh %v: %v", args, err)
		}
		return out.String(), errb.String(), ee.ExitCode()
	}

	// LRECON override: the shim must call exactly the binary named there, with
	// exactly these argv, for every branch it documents.
	cases := []struct {
		name string
		args []string
		want []string
	}{
		{"list-ops", []string{"--list-ops"}, []string{"--list-ops"}},
		{"compact", []string{"--list-ops", "--compact"}, []string{"--list-ops", "--json"}},
		{"find", []string{"--find", "check_"}, []string{"--list-ops"}},
		{"budget", []string{"--budget", "1234", "--", "--op", "check_deception_signals", "/tmp/none"}, []string{"--max-bytes", "1234", "--op", "check_deception_signals", "/tmp/none"}},
		{"budget-no-sep", []string{"--budget", "77", "--list-ops"}, []string{"--max-bytes", "77", "--list-ops"}},
	}
	for _, c := range cases {
		log := filepath.Join(dir, c.name+".argv")
		env := []string{"PATH=" + basePATH, "LRECON=" + stub, "LRECON_ARGV_LOG=" + log}
		if _, stderr, code := run(t, env, c.args...); code != 0 {
			t.Fatalf("LRECON override %s: exit %d, stderr %q", c.name, code, stderr)
		}
		got := argv(t, log)
		if strings.Join(got, "\x00") != strings.Join(c.want, "\x00") {
			t.Fatalf("LRECON override %s: lrecon argv %q, want %q", c.name, got, c.want)
		}
	}

	// Usage branch: an unknown command is the shim's own error, so lrecon must
	// never be invoked (no argv log at all).
	usageLog := filepath.Join(dir, "usage.argv")
	if _, _, code := run(t, []string{"PATH=" + basePATH, "LRECON=" + stub, "LRECON_ARGV_LOG=" + usageLog}, "--nope"); code != 2 {
		t.Fatalf("usage branch: exit %d, want 2", code)
	}
	if got := argv(t, usageLog); len(got) != 0 {
		t.Fatalf("usage branch invoked lrecon with %q; it must not run the binary", got)
	}

	// PATH resolution: with LRECON unset, `BIN=${LRECON:-lrecon}` must resolve
	// through PATH, not fail with "command not found".
	pathLog := filepath.Join(dir, "path.argv")
	env := []string{"PATH=" + dir + ":" + basePATH, "LRECON_ARGV_LOG=" + pathLog}
	if _, stderr, code := run(t, env, "--list-ops", "--compact"); code != 0 {
		t.Fatalf("PATH resolution: exit %d, stderr %q", code, stderr)
	}
	if got := argv(t, pathLog); strings.Join(got, "\x00") != "--list-ops\x00--json" {
		t.Fatalf("PATH resolution: lrecon argv %q, want [--list-ops --json]", got)
	}

	// Real binary: the argv the shim builds must be accepted, and its 3-column
	// projection must carry the real catalog's route and needs for this slice.
	realEnv := []string{"PATH=" + basePATH, "LRECON=" + cliPath}
	// The shim deliberately has no --json forwarding branch, so the machine
	// catalog is read from the binary directly.
	direct := exec.Command(cliPath, "--list-ops", "--json")
	var rawBuf, errBuf strings.Builder
	direct.Stdout, direct.Stderr = &rawBuf, &errBuf
	if err := direct.Run(); err != nil {
		t.Fatalf("real --list-ops --json: %v, stderr %q", err, errBuf.String())
	}
	raw := rawBuf.String()
	var catalog []struct {
		Name  string   `json:"name"`
		Route string   `json:"route"`
		Needs []string `json:"needs"`
	}
	if err := json.Unmarshal([]byte(raw), &catalog); err != nil {
		t.Fatalf("real --list-ops --json is not a JSON array: %v", err)
	}
	byName := make(map[string]int, len(catalog))
	for i, r := range catalog {
		byName[r.Name] = i
	}
	want := map[string]struct {
		route string
		needs string
	}{
		"binary_session":                         {"L", "target"},
		"build_call_path":                        {"G", "target"},
		"build_reconstruction_obligation_ledger": {"L", "target"},
		"capture_adb_screen":                     {"Y", "device"},
		"capture_browser_scenario":               {"Y", "target"},
		"capture_electron_scenario":              {"Y", "target"},
		"capture_native_ui_scenario":             {"Y", "device"},
		"capture_process_scenario":               {"Y", "target"},
		"capture_web_screenshot":                 {"Y", "target"},
		"check_deception_signals":                {"L", "target"},
		"check_runtime_evasion":                  {"L", "target"},
	}
	for name, w := range want {
		i, ok := byName[name]
		if !ok {
			t.Fatalf("real catalog lost op %q", name)
		}
		if catalog[i].Route != w.route || strings.Join(catalog[i].Needs, ",") != w.needs {
			t.Fatalf("real catalog %s: route %q needs %q, want %q %q", name, catalog[i].Route, catalog[i].Needs, w.route, w.needs)
		}
	}

	tsv, stderr, code := run(t, realEnv, "--list-ops", "--compact")
	if code != 0 {
		t.Fatalf("real --list-ops --compact via shim: exit %d, stderr %q", code, stderr)
	}
	rows := strings.Split(strings.TrimSuffix(tsv, "\n"), "\n")
	if len(rows) != len(catalog) {
		t.Fatalf("compact projection has %d rows, catalog has %d ops", len(rows), len(catalog))
	}
	seen := make(map[string]bool, len(rows))
	for _, row := range rows {
		f := strings.Split(row, "\t")
		if len(f) != 3 {
			t.Fatalf("compact row %q: want 3 tab fields, got %d", row, len(f))
		}
		i, ok := byName[f[0]]
		if !ok {
			t.Fatalf("compact row names %q, absent from --list-ops --json", f[0])
		}
		if f[1] != catalog[i].Route || f[2] != strings.Join(catalog[i].Needs, ",") {
			t.Fatalf("compact row %s: route/needs %q/%q, catalog says %q/%q", f[0], f[1], f[2], catalog[i].Route, strings.Join(catalog[i].Needs, ","))
		}
		seen[f[0]] = true
	}
	for name := range want {
		if !seen[name] {
			t.Fatalf("compact projection dropped %q", name)
		}
	}

	// The budget branch is the one that forwards arbitrary extra argv, so it is
	// where an unknown or misordered flag surfaces. Both documented spellings
	// must reach the binary and be accepted.
	for _, args := range [][]string{
		{"--budget", "4096", "--", "--list-ops"},
		{"--budget", "4096", "--", "--op", "check_deception_signals", filepath.Join(dir, "absent.bin")},
	} {
		out, stderr, code := run(t, realEnv, args...)
		bad := strings.Contains(stderr, "flag provided but not defined") || strings.Contains(stderr, "unknown flag")
		if bad {
			t.Fatalf("find.sh %q builds argv the binary rejects: %q", args, strings.TrimSpace(stderr))
		}
		if code == 0 && !strings.Contains(out, "check_deception_signals") && strings.Contains(strings.Join(args, " "), "--list-ops") {
			t.Fatalf("find.sh %q: exit 0 but no catalog text: %q", args, out)
		}
	}
}

// tur7b06Script locates the shipped shim relative to the package, so the test
// exercises the exact bytes the skill ships rather than a rewritten copy.
func tur7b06Script(t *testing.T) string {
	t.Helper()
	d, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 6; i++ {
		p := filepath.Join(d, "skill", "scripts", "find.sh")
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p
		}
		d = filepath.Dir(d)
	}
	t.Fatalf("skill/scripts/find.sh not found above %s", mustGetwd(t))
	return ""
}

func mustGetwd(t *testing.T) string {
	t.Helper()
	d, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return d
}
