package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TUR3 lane16: classify() must not label caller-fixable input errors as
// internal. compare_javascript_export_shapes with a wrong script count is
// bad_arg, like its "is one file:" neighbour in the same case block.
func TestR3L16CompareScriptCountKind(t *testing.T) {
	msg := "/some/dir holds 0 script files, want 2: put the old and the new build side by side"
	if got := classify(msg); got != kindBadArg {
		t.Fatalf("classify(%q) = %q, want %q", msg, got, kindBadArg)
	}
	// The full closed set still lands on a switchable kind.
	for _, k := range kindList {
		if k == "" {
			t.Fatal("empty kind in kindList")
		}
	}
}

func TestR3L16CompareJavascriptExportShapesRealDir(t *testing.T) {
	dir := t.TempDir()
	oldSrc := "exports.foo = function(a,b){}; exports.bar = function(x){};\n"
	newSrc := "exports.foo = function(a,b,c){}; exports.baz = function(){};\n"
	for name, src := range map[string]string{"old.js": oldSrc, "new.js": newSrc} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got, err := opCompareJavascriptExportShapes(dir)
	if err != nil {
		t.Fatal(err)
	}
	d, ok := got.(exportShapeDiff)
	if !ok {
		t.Fatalf("result type %T, want exportShapeDiff", got)
	}
	if d.Identical || len(d.Changed) != 1 || d.Changed[0].Name != "foo" ||
		d.Changed[0].From != 2 || d.Changed[0].To != 3 {
		t.Fatalf("changed = %+v, want foo 2->3", d.Changed)
	}
	if len(d.Added) != 1 || d.Added[0].Name != "baz" ||
		len(d.Removed) != 1 || d.Removed[0].Name != "bar" {
		t.Fatalf("added=%+v removed=%+v, want baz/bar", d.Added, d.Removed)
	}
}

func TestR3L16CompareJavascriptExportShapesWrongDirKind(t *testing.T) {
	_, err := opCompareJavascriptExportShapes(t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "want 2") {
		t.Fatalf("err = %v, want a want-2 refusal", err)
	}
	if got := classify(err.Error()); got != kindBadArg {
		t.Fatalf("classify(%q) = %q, want %q", err, got, kindBadArg)
	}
}

func TestR3L16InspectAndroidPackageRefusal(t *testing.T) {
	got, err := runOp("inspect_android_package", "/Users/keremurhan/kalitetest/test1")
	if err != nil {
		t.Fatal(err)
	}
	s, ok := got.(*skip)
	if !ok || !strings.Contains(s.Reason, "not an Android package") {
		t.Fatalf("result = %+v, want a skipped:<reason> for a Mach-O", got)
	}
}

func TestR3L16ReasonRegistryStable(t *testing.T) {
	if !registeredReason("pyc-version-unverified") {
		t.Fatal("pyc-version-unverified not registered")
	}
	if registeredReason("not-a-real-reason") {
		t.Fatal("unknown reason registered")
	}
	if fieldOf("dex-bad-map") != "dex" {
		t.Fatalf("fieldOf = %q, want dex", fieldOf("dex-bad-map"))
	}
}

// A real 4096-byte block of zeros must measure as plain, not packed: the
// entropy is computed from the bytes read, not from the file's size or name.
func TestR3L16ByteEntropyUniformBlock(t *testing.T) {
	p := filepath.Join(t.TempDir(), "zeros.bin")
	if err := os.WriteFile(p, make([]byte, 4096), 0o644); err != nil {
		t.Fatal(err)
	}
	f := fields(t, run(t, "inspect_byte_entropy", p))
	if f["blocks"] != float64(1) || f["block_bytes"] != float64(4096) {
		t.Fatalf("blocks/block_bytes = %v/%v, want 1/4096", f["blocks"], f["block_bytes"])
	}
	if f["mean"] != float64(0) || f["min"] != float64(0) || f["max"] != float64(0) {
		t.Fatalf("mean/min/max = %v/%v/%v, want 0/0/0", f["mean"], f["min"], f["max"])
	}
	if f["plain_blocks"] != float64(1) || f["packed_blocks"] != float64(0) {
		t.Fatalf("plain/packed = %v/%v, want 1/0", f["plain_blocks"], f["packed_blocks"])
	}
}

// Two imports naming the same spec are one (kind,spec) edge; the deduped
// dependency map is keyed by the bundle's basename.
func TestR3L16AnalyzeWebBundleDedupe(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "bundle.js")
	src := "import a from \"./a.js\";\nimport { b } from \"./a.js\";\nimport(\"./b.js\");\n"
	if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	f := fields(t, run(t, "analyze_web_bundle", p))
	if f["modules"] != float64(2) {
		t.Fatalf("modules = %v, want 2 (deduped)", f["modules"])
	}
	graph, ok := f["graph"].(map[string]any)
	if !ok {
		t.Fatalf("graph = %T, want an object", f["graph"])
	}
	deps := numList(t, graph["bundle.js"])
	if len(deps) != 2 || deps[0] != "./a.js" || deps[1] != "./b.js" {
		t.Fatalf("deps = %v, want [./a.js ./b.js]", deps)
	}
	seen := 0
	for _, e := range f["edges"].([]any) {
		if e.(map[string]any)["spec"] == "./a.js" {
			seen++
		}
	}
	if seen != 1 {
		t.Fatalf("spec ./a.js seen %d times, want 1 after dedupe", seen)
	}
}

// A claim window past EOF is an honest per-claim error, not a silent mismatch.
func TestR3L16VerifyReconstructionOutOfRangeClaim(t *testing.T) {
	target := writeTemp(t, "small.bin", []byte("abcd"))
	job := metaTestArg(t, map[string]any{
		"file": target,
		"claims": []any{
			map[string]any{"offset": 100, "length": 4, "expect": "deadbeef"},
		},
	})
	m := metaMustRun(t, "verify_reconstruction", job)
	if m["verified"] != false || m["mismatched"] != float64(1) || m["total"] != float64(1) {
		t.Fatalf("verify result = %+v, want total=1 mismatched=1 verified=false", m)
	}
	claims, ok := m["claims"].([]any)
	if !ok || len(claims) != 1 {
		t.Fatalf("claims = %+v", m["claims"])
	}
	c := claims[0].(map[string]any)
	if !strings.Contains(c["error"].(string), "outside the 4-byte file") {
		t.Fatalf("claim error = %v, want an out-of-range refusal", c["error"])
	}
}
