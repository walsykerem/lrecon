package main

import (
	"os"
	"path/filepath"
	"testing"
)

// A selector whose file half does not exist is a missing file, not a missing
// argument: the caller did pass <file>#<class>.
func TestInspectAndroidClassMissingFileWithSelectorIsIO(t *testing.T) {
	_, err := ops["inspect_android_class"].run("/nonexistent-xyz#com.foo.Bar")
	if err == nil {
		t.Fatal("a missing dex must refuse")
	}
	if got := classify(err.Error()); got != kindIO {
		t.Fatalf("kind = %s, want %s: %v", got, kindIO, err)
	}
}

func TestInspectAndroidClassMissingSelectorIsNeedsArg(t *testing.T) {
	_, err := ops["inspect_android_class"].run("/nonexistent-xyz")
	if err == nil {
		t.Fatal("a call with no selector must refuse")
	}
	if got := classify(err.Error()); got != kindNeedsArg {
		t.Fatalf("kind = %s, want %s: %v", got, kindNeedsArg, err)
	}
}

// A '#' inside a file that exists is part of its name, never a selector split.
func TestInspectAndroidClassHashInExistingNameIsNotASelector(t *testing.T) {
	p := filepath.Join(t.TempDir(), "a#b.dex")
	if err := os.WriteFile(p, dexFile(), 0o644); err != nil {
		t.Fatalf("write dex: %v", err)
	}
	_, err := ops["inspect_android_class"].run(p)
	if err == nil {
		t.Fatal("a dex with no selector must refuse")
	}
	if got := classify(err.Error()); got != kindNeedsArg {
		t.Fatalf("kind = %s, want %s: %v", got, kindNeedsArg, err)
	}
}

func TestInspectAndroidClassSelectorMissIsBadArg(t *testing.T) {
	p := writeZip(t, "miss.apk", []zipEntry{{name: "classes.dex", data: dexFile()}})
	_, err := ops["inspect_android_class"].run(p + "#com.example.Nope")
	if err == nil {
		t.Fatal("a name the dex does not carry must refuse")
	}
	if got := classify(err.Error()); got != kindBadArg {
		t.Fatalf("kind = %s, want %s: %v", got, kindBadArg, err)
	}
}
