package main

import "testing"

// inspect_android_method shares the selector split with inspect_android_class,
// so a missing file half must answer io here too.
func TestInspectAndroidMethodMissingFileWithSelectorIsIO(t *testing.T) {
	_, err := ops["inspect_android_method"].run("/nonexistent-xyz#com.foo.Bar")
	if err == nil {
		t.Fatal("a missing dex must refuse")
	}
	if got := classify(err.Error()); got != kindIO {
		t.Fatalf("kind = %s, want %s: %v", got, kindIO, err)
	}
}

func TestInspectAndroidMethodMissingSelectorIsNeedsArg(t *testing.T) {
	_, err := ops["inspect_android_method"].run("/nonexistent-xyz")
	if err == nil {
		t.Fatal("a call with no selector must refuse")
	}
	if got := classify(err.Error()); got != kindNeedsArg {
		t.Fatalf("kind = %s, want %s: %v", got, kindNeedsArg, err)
	}
}
