package main

import (
	"encoding/json"
	"testing"
)

// TestSearchStringsCoverage pins the coverage envelope of search_strings.
// skipped must be the corpus strings the search did not match, so
// matched + skipped == strings, and skipped must never exceed the corpus.
// The envelope used to read skipped as strings - rows printed, which counted
// the matched-but-unprinted hits as skipped too: on the elf fixture it read
// 5584 of 5684 strings skipped while 4519 strings matched.
func TestSearchStringsCoverage(t *testing.T) {
	t.Setenv("LRECON_QUERY", "e")
	const path = "testdata/fixtures/elf"
	res, err := ops["search_strings"].run(path)
	if err != nil {
		t.Fatal(err)
	}
	m, ok := res.(map[string]any)
	if !ok {
		t.Fatalf("search_strings result = %T, want map", res)
	}
	corpus := covNum(t, m["strings"])
	matched := covNum(t, m["matched"])
	listed := covNum(t, m["listed"])
	if corpus <= 0 || matched <= 0 || listed <= 0 {
		t.Fatalf("empty measurement: strings %d matched %d listed %d", corpus, matched, listed)
	}
	if matched > corpus {
		t.Fatalf("matched %d > strings %d", matched, corpus)
	}
	if got := covNum(t, m["shown"]); got != matched {
		t.Fatalf("shown %d, want the accounted strings %d", got, matched)
	}

	env, ok := withCoverage(map[string]any{"op": "search_strings", "target": path, "result": res}).(map[string]any)
	if !ok {
		t.Fatal("withCoverage did not return a map")
	}
	cov, ok := env["coverage"].(map[string]any)
	if !ok {
		t.Fatalf("coverage = %v, want a map", env["coverage"])
	}
	skipped := covNum(t, cov["skipped"])
	parsed := covNum(t, cov["parsed"])
	if parsed <= 0 {
		t.Fatalf("coverage.parsed = %d, want a real count", parsed)
	}
	if skipped <= 0 {
		t.Fatalf("coverage.skipped = %d, want a real count", skipped)
	}
	if matched+skipped != corpus {
		t.Errorf("coverage.skipped = %d: matched %d + skipped %d != strings %d", skipped, matched, skipped, corpus)
	}
	if skipped > corpus {
		t.Errorf("coverage.skipped = %d > strings %d", skipped, corpus)
	}
}

// covNum reads a count from a map that may hold an int or a decoded JSON number.
func covNum(t *testing.T, v any) int {
	t.Helper()
	switch x := v.(type) {
	case int:
		return x
	case float64:
		return int(x)
	case json.Number:
		n, err := x.Int64()
		if err != nil {
			t.Fatalf("number %v: %v", x, err)
		}
		return int(n)
	}
	t.Fatalf("number %v (%T), want int or json.Number", v, v)
	return 0
}
