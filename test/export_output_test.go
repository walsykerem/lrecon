package main

import (
	"archive/zip"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// A3: an op that writes output must not pick a destination for the caller. No
// op may write beside the target, and --extract may not write into whatever
// directory the caller happens to be standing in. Both refuse with exit 2 and
// write nothing; -o DIR|FILE is the only way to get the bytes.

// outputEntries names the entries of dir so a test can prove nothing appeared.
func outputEntries(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	names := make([]string, 0, len(ents))
	for _, e := range ents {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	return names
}

func outputSame(t *testing.T, dir string, before []string) {
	t.Helper()
	after := outputEntries(t, dir)
	if strings.Join(before, "\x00") != strings.Join(after, "\x00") {
		t.Fatalf("%s changed: before %v, after %v", dir, before, after)
	}
}

// outputZip writes a one-member zip so an extracting op has something real.
func outputZip(t *testing.T, path, member, body string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create %s: %v", path, err)
	}
	zw := zip.NewWriter(f)
	w, err := zw.Create(member)
	if err != nil {
		t.Fatalf("zip entry %q: %v", member, err)
	}
	if _, err := w.Write([]byte(body)); err != nil {
		t.Fatalf("zip body: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close %s: %v", path, err)
	}
}

// TestWritingOpsNeedOutput is the A3 contract: each op that produces output
// refuses a call with no -o, says needs_arg on the machine path, and leaves the
// target's directory exactly as it found it.
func TestWritingOpsNeedOutput(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.bin")
	if err := os.WriteFile(target, []byte("plain bytes, not an archive"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"export_evidence_bundle",
		"export_environment_bundle",
		"export_web_scripts",
		"extract_firmware",
		"extract_artifact",
	} {
		before := outputEntries(t, dir)
		stdout, code := runCLI(t, "--json", "--op", name, target)
		if code != 2 {
			t.Fatalf("%s without -o: exit %d, want 2 (stdout %q)", name, code, stdout)
		}
		if !strings.Contains(stdout, "needs_arg") {
			t.Fatalf("%s without -o: stdout %q does not name needs_arg", name, stdout)
		}
		outputSame(t, dir, before)
	}
}

// TestExportEvidenceBundleOutput: -o DIR receives <name>.evidence.json, -o FILE
// is the file itself, and the target's directory only ever holds the new tree.
func TestExportEvidenceBundleOutput(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "a.bin")
	if err := os.WriteFile(target, []byte("evidence me"), 0o644); err != nil {
		t.Fatal(err)
	}

	outDir := filepath.Join(dir, "out")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if stdout, code := runCLI(t, "--op", "export_evidence_bundle", "-o", outDir, target); code != 0 {
		t.Fatalf("-o DIR: exit %d, stdout %q", code, stdout)
	}
	if _, err := os.Stat(filepath.Join(outDir, "a.bin.evidence.json")); err != nil {
		t.Fatalf("-o DIR did not receive the bundle: %v", err)
	}

	file := filepath.Join(dir, "bundle.json")
	if stdout, code := runCLI(t, "--op", "export_evidence_bundle", "-o", file, target); code != 0 {
		t.Fatalf("-o FILE: exit %d, stdout %q", code, stdout)
	}
	if _, err := os.Stat(file); err != nil {
		t.Fatalf("-o FILE did not receive the bundle: %v", err)
	}
	// Nothing beside the artifact: the target's directory holds a.bin and the
	// two destinations we named, and no target-derived bundle or tree.
	for _, name := range outputEntries(t, dir) {
		if name != "a.bin" && name != "out" && name != "bundle.json" {
			t.Fatalf("unexpected entry beside the target: %q", name)
		}
	}
}

// TestExtractNeedsOutput: --extract writes into -o DIR and nowhere else. It used
// to drop the member into the process working directory, which is the target's
// directory as often as not.
func TestExtractNeedsOutput(t *testing.T) {
	dir := t.TempDir()
	archive := filepath.Join(dir, "a.zip")
	outputZip(t, archive, "m.txt", "member body")

	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	cwdBefore := outputEntries(t, cwd)

	stderr, code := func() (string, int) {
		_, e, c := runCLIAll(t, "--extract", "m.txt", archive)
		return e, c
	}()
	if code != 2 {
		t.Fatalf("--extract without -o: exit %d, want 2 (stderr %q)", code, stderr)
	}
	if !strings.Contains(stderr, "-o") {
		t.Fatalf("--extract without -o: stderr %q does not name -o", stderr)
	}
	if _, err := os.Stat(filepath.Join(cwd, "m.txt")); !os.IsNotExist(err) {
		t.Fatalf("--extract without -o wrote m.txt into the working directory")
	}
	outputSame(t, cwd, cwdBefore)
	outputSame(t, dir, []string{"a.zip"})

	outDir := filepath.Join(dir, "out")
	if stdout, code := runCLI(t, "--extract", "m.txt", "-o", outDir, archive); code != 0 {
		t.Fatalf("--extract -o DIR: exit %d, stdout %q", code, stdout)
	}
	body, err := os.ReadFile(filepath.Join(outDir, "m.txt"))
	if err != nil || string(body) != "member body" {
		t.Fatalf("extracted member = %q, %v", body, err)
	}
	outputSame(t, dir, []string{"a.zip", "out"})
}

// TestReadOnlyOpRefusesOutput: -o on an op that prints its result would be
// silently dropped while the caller waits for a file, so it is refused.
func TestReadOnlyOpRefusesOutput(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "out.json")
	stderr, code := func() (string, int) {
		_, e, c := runCLIAll(t, "-o", dest, "--op", "list_strings", fixtureMacho)
		return e, c
	}()
	if code != 2 {
		t.Fatalf("-o on a read-only op: exit %d, want 2 (stderr %q)", code, stderr)
	}
	if !strings.Contains(stderr, "-o") {
		t.Fatalf("stderr %q does not name -o", stderr)
	}
	if _, err := os.Stat(dest); !os.IsNotExist(err) {
		t.Fatalf("-o on a read-only op wrote %s", dest)
	}
	outputSame(t, dir, nil)
}

// B9: extract_artifact on an asar writes under -o and nowhere else. The op has
// its own deadline now, but a normal archive still yields the tree.
func TestExtractArtifactAsarWritesUnderOutput(t *testing.T) {
	dir := t.TempDir()
	archive := writeAsarArchive(t, dir, "app.asar", map[string][]byte{
		"main.js":    []byte("module.exports = 1;\n"),
		"pkg/a.json": []byte("{\"a\":1}\n"),
	})
	outDir := filepath.Join(dir, "out")
	stdout, code := runCLI(t, "--op", "extract_artifact", "--json", "-o", outDir, archive)
	if code != 0 {
		t.Fatalf("extract_artifact: exit %d, stdout %q", code, stdout)
	}
	var env struct {
		Result struct {
			Kind   string `json:"kind"`
			Output string `json:"output"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(stdout), &env); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s", err, stdout)
	}
	if env.Result.Kind != "asar" || env.Result.Output != outDir {
		t.Fatalf("result = %+v, want asar -> %s", env.Result, outDir)
	}
	for _, rel := range []string{"main.js", "pkg/a.json"} {
		if _, err := os.Stat(filepath.Join(outDir, rel)); err != nil {
			t.Errorf("%s not extracted under -o: %v", rel, err)
		}
	}
	outputSame(t, dir, []string{"app.asar", "out"})
}

// TestExtractArtifactKeepsCallersDirectoryOnFailure: -o DIR is merged into, so a
// failed walk must not delete files the caller already had there. A directory
// this call created is still rolled back, so a failure leaves nothing behind.
func TestExtractArtifactKeepsCallersDirectoryOnFailure(t *testing.T) {
	dir := t.TempDir()
	archive := filepath.Join(dir, "mixed.zip")
	f, err := os.Create(archive)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	for _, m := range []struct{ name, body string }{
		{"ok.txt", "written before the failure"},
		{"../evil.txt", "escape"},
	} {
		w, err := zw.Create(m.name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(m.body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	outDir := filepath.Join(dir, "out")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(outDir, "mine.txt")
	if err := os.WriteFile(sentinel, []byte("caller data"), 0o644); err != nil {
		t.Fatal(err)
	}
	withOpOutput(t, outDir)
	if _, err := runOp("extract_artifact", archive); err == nil || !strings.Contains(err.Error(), ".. path element") {
		t.Fatalf("escaping member: error = %v, want the .. refusal", err)
	}
	if body, err := os.ReadFile(sentinel); err != nil || string(body) != "caller data" {
		t.Fatalf("failed walk deleted the caller's file: %q, %v", body, err)
	}
	if _, err := os.Stat(filepath.Join(outDir, "ok.txt")); err != nil {
		t.Fatalf("member written before the failure is gone: %v", err)
	}

	// Nothing was there before: the half-written tree is this call's own and is
	// removed, so a retry starts clean.
	fresh := filepath.Join(dir, "fresh")
	withOpOutput(t, fresh)
	if _, err := runOp("extract_artifact", archive); err == nil {
		t.Fatal("escaping member into a fresh -o dir: want an error")
	}
	if _, err := os.Stat(fresh); !os.IsNotExist(err) {
		t.Fatalf("a directory this call created survived the failure: %v", err)
	}
}
