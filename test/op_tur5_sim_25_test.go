package main

// Tur5, listed .go files: real op/helper simulations (no pass-for-passing).
// Uses the lrecon binary, the published testdata/ops.json contract and real
// parsers. Production code stays untouched; no env/ or source deletion.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestTur5OpsJSONClassForListedOps reads the published op table and checks the
// route/needs/class for the ops whose implementation files are in this lane.
// The table is the contract: a drift here is a real regression, not a fixture.
func TestTur5OpsJSONClassForListedOps(t *testing.T) {
	b, err := os.ReadFile(opTablePath)
	if err != nil {
		t.Fatalf("read %s: %v", opTablePath, err)
	}
	var table struct {
		Ops []struct {
			Name   string `json:"name"`
			Route  string `json:"route"`
			Needs  bool   `json:"needs"`
			Expect struct {
				NoArgs     string `json:"no_args"`
				WithTarget string `json:"with_target"`
			} `json:"expect"`
		} `json:"ops"`
	}
	if err := json.Unmarshal(b, &table); err != nil {
		t.Fatalf("decode %s: %v", opTablePath, err)
	}
	byName := map[string]struct {
		route              string
		needs              bool
		noArgs, withTarget string
	}{}
	for _, r := range table.Ops {
		byName[r.Name] = struct {
			route              string
			needs              bool
			noArgs, withTarget string
		}{
			r.Route, r.Needs, r.Expect.NoArgs, r.Expect.WithTarget,
		}
	}
	// (op, route, needs, no_args, with_target) from testdata/ops.json.
	want := []struct {
		name, route, noArgs, withTarget string
		needs                           bool
	}{
		{"analyze_swift_types", "L", "needs_arg", "ok", true},
		{"compare_javascript_export_shapes", "L", "needs_arg", "bad_arg", true},
		{"inspect_binary_layout", "L", "needs_arg", "ok", true},
		{"inspect_managed_native_boundaries", "L", "needs_arg", "bad_arg", true},
		{"inspect_native_dispatch_metadata", "G", "needs_arg", "skipped_ghidra", true},
		{"inspect_python_pyc", "L", "needs_arg", "bad_arg", true},
		{"extract_artifact", "L", "needs_arg", "needs_arg", true},
		{"goto_address", "L", "needs_arg", "needs_arg", true},
		{"procedure_address", "G", "needs_arg", "needs_arg", true},
		{"resolve_native_call_targets", "G", "needs_arg", "needs_arg", true},
	}
	for _, w := range want {
		got, ok := byName[w.name]
		if !ok {
			t.Errorf("%s missing from %s", w.name, opTablePath)
			continue
		}
		if got.route != w.route || got.needs != w.needs || got.noArgs != w.noArgs || got.withTarget != w.withTarget {
			t.Errorf("%s contract = %+v, want route=%s needs=%v no_args=%s with_target=%s",
				w.name, got, w.route, w.needs, w.noArgs, w.withTarget)
		}
	}
}

// TestTur5CompareJavascriptExportShapesLexerMask drives the real exportTable
// through strings/templates/comments: a fake export inside a literal must not
// change the shape, and a real arity change must still be reported.
func TestTur5CompareJavascriptExportShapesLexerMask(t *testing.T) {
	dir := t.TempDir()
	// Both files fake the same extra export in a comment, string and template;
	// the lexer masks those, so only the real export (arity 1->2) differs.
	oldSrc := "exports.real = function(a){};\n// exports.comment = function(){};\nvar s = \"exports.string = function(){};\";\nvar t = `exports.template = function(){};`;\n"
	newSrc := "exports.real = function(a,b){};\n// exports.comment = function(){};\nvar s = \"exports.string = function(){};\";\nvar t = `exports.template = function(){};`;\n"
	for name, src := range map[string]string{"old.js": oldSrc, "new.js": newSrc} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got, err := opCompareJavascriptExportShapes(dir)
	if err != nil {
		t.Fatalf("opCompareJavascriptExportShapes: %v", err)
	}
	d := got.(exportShapeDiff)
	if d.Identical || len(d.Changed) != 1 || d.Changed[0].Name != "real" ||
		d.Changed[0].From != 1 || d.Changed[0].To != 2 {
		t.Fatalf("diff = %+v, want only real 1->2 changed", d)
	}
	if len(d.Added) != 0 || len(d.Removed) != 0 {
		t.Fatalf("literal exports leaked into added/removed: %+v / %+v", d.Added, d.Removed)
	}
}

// TestTur5CompareJavascriptExportShapesFileRefusal: passing one file must be a
// caller-fixable error that says a directory of exactly two scripts is needed.
func TestTur5CompareJavascriptExportShapesFileRefusal(t *testing.T) {
	f := filepath.Join(t.TempDir(), "one.js")
	if err := os.WriteFile(f, []byte("exports.a = function(){};"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := opCompareJavascriptExportShapes(f)
	if err == nil || !strings.Contains(err.Error(), "pass a directory holding exactly two script files") {
		t.Fatalf("err = %v, want the pass-a-directory refusal", err)
	}
	if classify(err.Error()) != kindBadArg {
		t.Fatalf("classify(%q) = %q, want %q", err, classify(err.Error()), kindBadArg)
	}
}

// TestTur5ExtractSingleCreatesMissingDirRollback: a failed extraction into a
// directory this call created must remove that directory, so a hostile archive
// cannot leave a tree behind; an existing directory must be left untouched.
func TestTur5ExtractSingleCreatesMissingDirRollback(t *testing.T) {
	// A valid zip with a missing member: the call creates the destination, then
	// fails with "not in", and must roll back the directory it just created.
	src := writeZip(t, "one.zip", []zipEntry{{"a.txt", []byte("hello")}})
	base := t.TempDir()
	fresh := filepath.Join(base, "fresh")
	var d Digest
	if err := ExtractPayloadTo(src, "absent.txt", fresh, &d); err == nil {
		t.Fatal("ExtractPayloadTo(absent member) accepted")
	}
	if _, err := os.Stat(fresh); !os.IsNotExist(err) {
		t.Fatalf("failed extract left created dir %s behind: %v", fresh, err)
	}
	// A pre-existing directory must survive the same failure with its content.
	existing := filepath.Join(base, "existing")
	if err := os.MkdirAll(existing, 0o755); err != nil {
		t.Fatal(err)
	}
	seed := filepath.Join(existing, "keep.txt")
	if err := os.WriteFile(seed, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := ExtractPayloadTo(src, "absent.txt", existing, &d); err == nil {
		t.Fatal("ExtractPayloadTo(absent member) accepted")
	}
	if b, err := os.ReadFile(seed); err != nil || string(b) != "keep" {
		t.Fatalf("pre-existing content lost: %q %v", b, err)
	}
}
