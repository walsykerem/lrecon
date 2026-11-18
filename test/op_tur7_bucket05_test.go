package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// bucket05: binary_overview is route L and reads the digest, so its whole
// argument contract is one positional target and nothing else. The source
// registers needs:true and never touches a LRECON_* variable, unlike its
// neighbours on route G (LRECON_AT, LRECON_ARGS, LRECON_FROM/TO). This test
// enumerates that declared requirement from --list-ops and then asserts the
// binary honours each part of it: one target answers, zero or two targets
// refuse with arity kinds, a directory refuses as an io problem naming the
// path, and a full bag of other ops' arguments changes nothing.

type tur05ListRow struct {
	Name  string   `json:"name"`
	Route string   `json:"route"`
	Needs []string `json:"needs"`
}

// tur05Run runs the built CLI in dir with every inherited LRECON_* variable
// dropped, so an ambient argument from the caller cannot decide the answer.
func tur05Run(t *testing.T, dir string, env []string, args ...string) (string, string, int) {
	t.Helper()
	if buildErr != nil {
		t.Fatalf("go build failed: %v\n%s", buildErr, buildLog)
	}
	if cliPath == "" {
		t.Fatal("cli binary was not built")
	}
	cmd := exec.Command(cliPath, args...)
	cmd.Dir = dir
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "LRECON_") {
			cmd.Env = append(cmd.Env, kv)
		}
	}
	cmd.Env = append(cmd.Env, env...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	code := 0
	if err != nil {
		exitErr, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatalf("run %v: %v", args, err)
		}
		code = exitErr.ExitCode()
	}
	return stdout.String(), stderr.String(), code
}

// tur05Envelope decodes one machine answer and requires the fields the op
// promises: the op name, the target it answered for, and the error kind when
// it refused.
func tur05Envelope(t *testing.T, stdout string) (map[string]any, map[string]any) {
	t.Helper()
	var env map[string]any
	if err := json.Unmarshal([]byte(stdout), &env); err != nil {
		t.Fatalf("answer is not one JSON envelope: %v\n%s", err, stdout)
	}
	// A refusal carries contract_version at the envelope; a success carries it
	// inside the op's result.
	if _, refused := env["error"]; refused && env["contract_version"] != float64(contractVersion) {
		t.Fatalf("refusal contract_version = %v, want %d: %s", env["contract_version"], contractVersion, stdout)
	}
	res, _ := env["result"].(map[string]any)
	return env, res
}

func TestTur7Bucket05BinaryOverview(t *testing.T) {
	// Declared requirement, straight from the inventory the caller reads.
	out, _, rc := tur05Run(t, t.TempDir(), nil, "--list-ops", "--json")
	if rc != 0 {
		t.Fatalf("--list-ops --json rc = %d, want 0: %s", rc, out)
	}
	var rows []tur05ListRow
	if err := json.Unmarshal([]byte(out), &rows); err != nil {
		t.Fatalf("--list-ops --json is not an array of rows: %v", err)
	}
	var declared []string
	route := ""
	for _, r := range rows {
		if r.Name == "binary_overview" {
			declared, route = r.Needs, r.Route
			break
		}
	}
	if route != "L" {
		t.Fatalf("binary_overview route = %q, want L", route)
	}
	if len(declared) != 1 || declared[0] != "target" {
		t.Fatalf("binary_overview needs = %v, want exactly [target]", declared)
	}

	work := t.TempDir()
	textPath := filepath.Join(work, "note.txt")
	if err := os.WriteFile(textPath, []byte("just a plain text fixture\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	empty := t.TempDir() // no file to infer a target from

	// 1. Valid arity and argument: one regular file answers, and the digest
	// fields follow the file that was named.
	baseOut, baseErr, rc := tur05Run(t, work, nil, textPath, "--op", "binary_overview", "--json")
	if rc != 0 {
		t.Fatalf("binary_overview on a text file rc = %d, want 0: %s%s", rc, baseOut, baseErr)
	}
	env, res := tur05Envelope(t, baseOut)
	if env["op"] != "binary_overview" || env["target"] != textPath {
		t.Fatalf("envelope op/target = %v/%v, want binary_overview/%s", env["op"], env["target"], textPath)
	}
	if res["kind"] != "text" {
		t.Fatalf("text file kind = %v, want text: %s", res["kind"], baseOut)
	}
	if res["format"] != "unknown" {
		t.Fatalf("text file format = %v, want unknown", res["format"])
	}
	if res["slices"] != float64(0) || res["exports"] != float64(0) {
		t.Fatalf("text file slices/exports = %v/%v, want 0/0", res["slices"], res["exports"])
	}
	if res["contract_version"] != float64(contractVersion) {
		t.Fatalf("answer carries contract_version %v, want %d", res["contract_version"], contractVersion)
	}
	if _, ok := res["hardening"]; !ok {
		t.Fatalf("answer has no hardening key: %s", baseOut)
	}

	// 2. The answer traces the target argument: a real native file cannot
	// report the same kind as the text fixture.
	want := map[string]string{"darwin": "macho", "linux": "elf", "windows": "pe"}[runtime.GOOS]
	if want == "" {
		t.Fatalf("no native kind known for GOOS %q", runtime.GOOS)
	}
	nativeOut, nativeErr, rc := tur05Run(t, work, nil, cliPath, "--op", "binary_overview", "--json")
	if rc != 0 {
		t.Fatalf("binary_overview on a native file rc = %d, want 0: %s%s", rc, nativeOut, nativeErr)
	}
	_, nativeRes := tur05Envelope(t, nativeOut)
	if nativeRes["kind"] != want {
		t.Fatalf("native file kind = %v, want %s: %s", nativeRes["kind"], want, nativeOut)
	}

	// 3. The op declares no LRECON_* argument, so every other route's argument
	// must leave the answer byte-identical to the run without them.
	foreign := []string{
		"LRECON_AT=0xzz", "LRECON_NAME=bogus", "LRECON_ARGS=,",
		"LRECON_FROM=0x1", "LRECON_TO=0x2", "LRECON_ARCH=bogus",
	}
	withArgs, argsErr, rc := tur05Run(t, work, foreign, textPath, "--op", "binary_overview", "--json")
	if rc != 0 {
		t.Fatalf("binary_overview with foreign args rc = %d, want 0: %s%s", rc, withArgs, argsErr)
	}
	if withArgs != baseOut {
		t.Fatalf("foreign LRECON_* changed the answer:\nwithout: %s\nwith:    %s", baseOut, withArgs)
	}

	// 4. Wrong arity, zero targets: the refusal names the requirement it
	// honours (the target path), not one of the foreign arguments.
	noArgsOut, noArgsErr, rc := tur05Run(t, empty, foreign, "--op", "binary_overview", "--json")
	if rc != 2 {
		t.Fatalf("binary_overview with no target rc = %d, want 2: %s%s", rc, noArgsOut, noArgsErr)
	}
	noArgsEnv, _ := tur05Envelope(t, noArgsOut)
	if noArgsEnv["kind"] != string(kindNeedsArg) {
		t.Fatalf("no-target kind = %v, want %s: %s", noArgsEnv["kind"], kindNeedsArg, noArgsOut)
	}
	msg, _ := noArgsEnv["error"].(string)
	if !strings.Contains(msg, "needs a target path") {
		t.Fatalf("no-target refusal does not name the target requirement: %q", msg)
	}
	for _, f := range foreign {
		name := f[:strings.Index(f, "=")]
		if strings.Contains(msg, name) {
			t.Fatalf("no-target refusal blames %s, which the op never reads: %q", name, msg)
		}
	}

	// 5. Wrong arity, two targets: a different kind from case 4, and the count
	// of the offending arguments is named.
	twoOut, twoErr, rc := tur05Run(t, empty, nil, textPath, cliPath, "--op", "binary_overview", "--json")
	if rc != 2 {
		t.Fatalf("binary_overview with two targets rc = %d, want 2: %s%s", rc, twoOut, twoErr)
	}
	twoEnv, _ := tur05Envelope(t, twoOut)
	if twoEnv["kind"] != string(kindUsage) {
		t.Fatalf("two-target kind = %v, want %s: %s", twoEnv["kind"], kindUsage, twoOut)
	}
	twoMsg, _ := twoEnv["error"].(string)
	if !strings.Contains(twoMsg, "takes one target, got 2") {
		t.Fatalf("two-target refusal does not name the arity it got: %q", twoMsg)
	}

	// 6. A target of the wrong kind: the op reads one file, so a directory is
	// an io refusal that names the path it could not read.
	dirPath := filepath.Join(work, "not-a-file")
	if err := os.Mkdir(dirPath, 0o755); err != nil {
		t.Fatal(err)
	}
	dirOut, dirErr, rc := tur05Run(t, work, nil, dirPath, "--op", "binary_overview", "--json")
	if rc != 2 {
		t.Fatalf("binary_overview on a directory rc = %d, want 2: %s%s", rc, dirOut, dirErr)
	}
	dirEnv, _ := tur05Envelope(t, dirOut)
	if dirEnv["kind"] != string(kindIO) {
		t.Fatalf("directory kind = %v, want %s: %s", dirEnv["kind"], kindIO, dirOut)
	}
	if dirEnv["target"] != dirPath {
		t.Fatalf("directory refusal target = %v, want %s", dirEnv["target"], dirPath)
	}
	dirMsg, _ := dirEnv["error"].(string)
	if !strings.Contains(dirMsg, dirPath) || !strings.Contains(dirMsg, "is a directory") {
		t.Fatalf("directory refusal does not name the offending path: %q", dirMsg)
	}
}
