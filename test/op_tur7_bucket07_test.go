package main

// Bucket 07: the compare_* family is a comparison, not an echo. Three laws, each
// on a field-level dimension: identical inputs give an empty diff, two inputs
// differing in exactly one dimension move only that dimension, and swapping the
// two inputs mirrors the diff instead of repeating it.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func tur7b07SHA(body string) string {
	sum := sha256.Sum256([]byte(body))
	return hex.EncodeToString(sum[:])
}

// tur7b07Digest writes a saved digest so two sides can differ in exactly one
// contract field. A phrase-matching tool cannot produce the field names or the
// before/after values these digests pin.
func tur7b07Digest(t *testing.T, name string, mutate func(d map[string]any)) string {
	t.Helper()
	d := map[string]any{
		"contract_version": contractVersion,
		"kind":             "application",
		"format":           "macho",
		"minos":            "12.0",
		"toolchain":        "go1.22",
		"mobile_package":   "com.example.app",
		"mobile_sdk":       "ios-16.0",
		"target": map[string]any{
			"size":        4096,
			"file_sha256": strings.Repeat("a", 64),
			"hash_scope":  "whole-file",
			"hash_bytes":  4096,
			"gitoid":      strings.Repeat("b", 40),
		},
	}
	if mutate != nil {
		mutate(d)
	}
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	return writeTemp(t, name, b)
}

// tur7b07Ones returns the single change object of a diff, failing when the diff
// does not hold exactly one change.
func tur7b07One(t *testing.T, m map[string]any, wantPath string) map[string]any {
	t.Helper()
	changes, _ := m["changes"].([]any)
	if len(changes) != 1 {
		t.Fatalf("changes = %v, want exactly one (the changed dimension)", m["changes"])
	}
	ch, _ := changes[0].(map[string]any)
	if got := fmt.Sprint(ch["path"]); wantPath != "" && got != wantPath {
		t.Fatalf("change path = %q, want %q", got, wantPath)
	}
	return ch
}

func tur7b07Empty(t *testing.T, key string, m map[string]any) {
	t.Helper()
	switch v := m[key].(type) {
	case nil:
	case []any:
		if len(v) != 0 {
			t.Fatalf("%s = %v, want an empty diff", key, v)
		}
	case string:
		if v != "" && v != "[]" && v != "null" {
			t.Fatalf("%s = %q, want an empty diff", key, v)
		}
	default:
		t.Fatalf("%s = %v, want an empty diff", key, v)
	}
}

func TestTur7Bucket07Antisymmetry(t *testing.T) {
	t.Run("compare_bundles member bytes", func(t *testing.T) {
		old := a13Zip(t, "old.zip", map[string]string{"app.js": "A", "keep.txt": "K"})
		new := a13Zip(t, "new.zip", map[string]string{"app.js": "B", "keep.txt": "K"})
		job := func(a, b string) map[string]any {
			return metaMustRun(t, "compare_bundles", metaTestArg(t, map[string]any{"old": a, "new": b}))
		}

		same := job(old, old)
		if !metaBool(t, same, "identical") || metaNum(t, same, "count") != 0 {
			t.Fatalf("same bundle vs itself: identical = %v count = %d, want true/0",
				same["identical"], metaNum(t, same, "count"))
		}
		tur7b07Empty(t, "changes", same)

		fwd := job(old, new)
		if metaBool(t, fwd, "identical") {
			t.Fatal("identical = true although app.js bytes changed")
		}
		if n := metaNum(t, fwd, "count"); n != 1 {
			t.Fatalf("count = %d, want 1: only app.js differs", n)
		}
		if metaNum(t, fwd, "added") != 0 || metaNum(t, fwd, "removed") != 0 || metaNum(t, fwd, "changed") != 1 {
			t.Fatalf("added/removed/changed = %d/%d/%d, want 0/0/1",
				metaNum(t, fwd, "added"), metaNum(t, fwd, "removed"), metaNum(t, fwd, "changed"))
		}
		ch := tur7b07One(t, fwd, "")
		if ch["name"] != "app.js" || ch["change"] != "changed" {
			t.Fatalf("change = %v, want app.js changed", ch)
		}
		if ch["old_sha256"] != tur7b07SHA("A") || ch["new_sha256"] != tur7b07SHA("B") {
			t.Fatalf("shas = %v -> %v, want hash(A) -> hash(B)", ch["old_sha256"], ch["new_sha256"])
		}

		rev := job(new, old)
		rch := tur7b07One(t, rev, "")
		if rch["old_sha256"] != ch["new_sha256"] || rch["new_sha256"] != ch["old_sha256"] {
			t.Fatalf("swapped shas = %v -> %v, want the mirror of %v -> %v",
				rch["old_sha256"], rch["new_sha256"], ch["old_sha256"], ch["new_sha256"])
		}
	})

	t.Run("compare_bundles member presence", func(t *testing.T) {
		with := a13Zip(t, "with.zip", map[string]string{"app.js": "A", "extra.txt": "E"})
		without := a13Zip(t, "without.zip", map[string]string{"app.js": "A"})
		fwd := metaMustRun(t, "compare_bundles", metaTestArg(t, map[string]any{"old": with, "new": without}))
		if metaNum(t, fwd, "removed") != 1 || metaNum(t, fwd, "added") != 0 || metaNum(t, fwd, "changed") != 0 {
			t.Fatalf("added/removed/changed = %d/%d/%d, want 0/1/0",
				metaNum(t, fwd, "added"), metaNum(t, fwd, "removed"), metaNum(t, fwd, "changed"))
		}
		ch := tur7b07One(t, fwd, "")
		if ch["name"] != "extra.txt" || ch["change"] != "removed" || ch["old_sha256"] != tur7b07SHA("E") {
			t.Fatalf("change = %v, want extra.txt removed with its old hash", ch)
		}

		rev := metaMustRun(t, "compare_bundles", metaTestArg(t, map[string]any{"old": without, "new": with}))
		rch := tur7b07One(t, rev, "")
		if metaNum(t, rev, "added") != 1 || metaNum(t, rev, "removed") != 0 {
			t.Fatalf("swapped added/removed = %d/%d, want 1/0",
				metaNum(t, rev, "added"), metaNum(t, rev, "removed"))
		}
		if rch["name"] != ch["name"] || rch["change"] != "added" || rch["new_sha256"] != ch["old_sha256"] {
			t.Fatalf("swapped change = %v, want extra.txt added with the same hash", rch)
		}
	})

	t.Run("compare_artifacts one digest field", func(t *testing.T) {
		base := tur7b07Digest(t, "base.json", nil)
		tool := tur7b07Digest(t, "tool.json", func(d map[string]any) { d["toolchain"] = "go1.23" })
		job := func(a, b string) map[string]any {
			return metaMustRun(t, "compare_artifacts", metaTestArg(t, map[string]any{"old": a, "new": b}))
		}

		same := job(base, base)
		if !metaBool(t, same, "identical") || metaNum(t, same, "count") != 0 {
			t.Fatalf("same digest vs itself: identical = %v count = %d, want true/0",
				same["identical"], metaNum(t, same, "count"))
		}
		tur7b07Empty(t, "changes", same)

		fwd := job(base, tool)
		if metaBool(t, fwd, "identical") {
			t.Fatal("identical = true although toolchain changed")
		}
		ch := tur7b07One(t, fwd, "toolchain")
		if ch["before"] != "go1.22" || ch["after"] != "go1.23" {
			t.Fatalf("change = %v, want toolchain go1.22 -> go1.23", ch)
		}

		rev := job(tool, base)
		rch := tur7b07One(t, rev, "toolchain")
		if rch["before"] != ch["after"] || rch["after"] != ch["before"] {
			t.Fatalf("swapped change = %v, want the mirror of %v", rch, ch)
		}
	})

	t.Run("compare_application_versions release vs build", func(t *testing.T) {
		buildA := tur7b07Digest(t, "buildA.json", nil)
		// Same package metadata, different bytes and toolchain: a rebuild.
		buildB := tur7b07Digest(t, "buildB.json", func(d map[string]any) {
			d["toolchain"] = "go1.23"
			d["target"] = map[string]any{
				"size": 5000, "file_sha256": strings.Repeat("c", 64),
				"hash_scope": "whole-file", "hash_bytes": 5000, "gitoid": strings.Repeat("d", 40),
			}
		})
		// New package version on top of the rebuild.
		release := tur7b07Digest(t, "release.json", func(d map[string]any) {
			d["toolchain"] = "go1.23"
			d["mobile_package"] = "com.example.app2"
			d["target"] = map[string]any{
				"size": 6000, "file_sha256": strings.Repeat("e", 64),
				"hash_scope": "whole-file", "hash_bytes": 6000, "gitoid": strings.Repeat("f", 40),
			}
		})
		job := func(a, b string) map[string]any {
			return metaMustRun(t, "compare_application_versions", metaTestArg(t, map[string]any{"old": a, "new": b}))
		}

		same := job(buildA, buildA)
		if got := metaStr(t, same, "verdict"); got != "same bytes" {
			t.Fatalf("verdict = %q, want \"same bytes\"", got)
		}
		if !metaBool(t, same, "same_release") || metaNum(t, same, "count") != 0 {
			t.Fatalf("same release = %v count = %d, want true/0", same["same_release"], metaNum(t, same, "count"))
		}

		rebuild := job(buildA, buildB)
		if metaNum(t, rebuild, "count") != 0 {
			t.Fatalf("count = %d for a rebuild, want 0: build detail is not an application change",
				metaNum(t, rebuild, "count"))
		}
		tur7b07Empty(t, "changes", rebuild)
		tur7b07Empty(t, "identity_changed", rebuild)
		if got := metaStr(t, rebuild, "verdict"); got != "same application identity, different build" {
			t.Fatalf("verdict = %q for a rebuild", got)
		}
		if metaBool(t, rebuild, "same_release") {
			t.Fatal("same_release = true although the bytes differ")
		}

		bump := job(buildA, release)
		ch := tur7b07One(t, bump, "mobile_package")
		if ch["before"] != "com.example.app" || ch["after"] != "com.example.app2" {
			t.Fatalf("change = %v, want the package rename", ch)
		}
		if got := fmt.Sprint(bump["identity_changed"]); got != "[mobile_package]" {
			t.Fatalf("identity_changed = %v, want [mobile_package]", bump["identity_changed"])
		}
		if got := metaStr(t, bump, "verdict"); got != "application identity changed: mobile_package" {
			t.Fatalf("verdict = %q", got)
		}

		rev := job(release, buildA)
		rch := tur7b07One(t, rev, "mobile_package")
		if rch["before"] != ch["after"] || rch["after"] != ch["before"] {
			t.Fatalf("swapped change = %v, want the mirror of %v", rch, ch)
		}
		if fmt.Sprint(rev["identity_changed"]) != fmt.Sprint(bump["identity_changed"]) {
			t.Fatalf("swapped identity_changed = %v, want %v",
				rev["identity_changed"], bump["identity_changed"])
		}
	})

	t.Run("compare_javascript_export_shapes arity", func(t *testing.T) {
		write := func(dir, a, b string) {
			for name, body := range map[string]string{"a.js": a, "b.js": b} {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
					t.Fatal(err)
				}
			}
		}
		oldSrc := "exports.alpha = function (x, y) {};\nexports.beta = function (q) {};\n"
		newSrc := "exports.alpha = function (x, y, z) {};\nexports.beta = function (q) {};\n"

		fwdDir := t.TempDir()
		write(fwdDir, oldSrc, newSrc)
		fwd := metaMustRun(t, "compare_javascript_export_shapes", fwdDir)
		if metaBool(t, fwd, "identical") {
			t.Fatal("identical = true although alpha gained a parameter")
		}
		changed, _ := fwd["changed"].([]any)
		if len(changed) != 1 || metaNum(t, fwd, "same") != 1 {
			t.Fatalf("changed = %v same = %d, want one arity change and beta unchanged",
				fwd["changed"], metaNum(t, fwd, "same"))
		}
		ch, _ := changed[0].(map[string]any)
		if ch["name"] != "alpha" || metaNum(t, ch, "from") != 2 || metaNum(t, ch, "to") != 3 {
			t.Fatalf("changed = %v, want alpha 2 -> 3", changed)
		}
		tur7b07Empty(t, "added", fwd)
		tur7b07Empty(t, "removed", fwd)

		revDir := t.TempDir()
		write(revDir, newSrc, oldSrc)
		rev := metaMustRun(t, "compare_javascript_export_shapes", revDir)
		rchanged, _ := rev["changed"].([]any)
		if len(rchanged) != 1 {
			t.Fatalf("swapped changed = %v, want one arity change", rev["changed"])
		}
		rch, _ := rchanged[0].(map[string]any)
		if rch["name"] != ch["name"] || metaNum(t, rch, "from") != 3 || metaNum(t, rch, "to") != 2 {
			t.Fatalf("swapped changed = %v, want alpha 3 -> 2", rchanged)
		}

		sameDir := t.TempDir()
		write(sameDir, oldSrc, oldSrc)
		same := metaMustRun(t, "compare_javascript_export_shapes", sameDir)
		if !metaBool(t, same, "identical") || metaNum(t, same, "same") != 2 {
			t.Fatalf("same table twice: identical = %v same = %d, want true/2",
				same["identical"], metaNum(t, same, "same"))
		}
		tur7b07Empty(t, "changed", same)
	})
}
