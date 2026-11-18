package main

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"testing"
)

func TestOpModesShapes(t *testing.T) {
	answer, err := decodeNumbers(map[string]any{
		"op":     "list_strings",
		"target": "t",
		"result": map[string]any{
			"strings": 3,
			"shown":   2,
			"rows": []any{
				map[string]any{"address": 1, "ascii": true},
				map[string]any{"address": 2, "ascii": true},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	got, err := aggregate(answer, opModes{countOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	// The fixture lists 2 of 3 strings: the answer must say so. The old
	// assertion expected only count/op/target, which is the cap state the
	// count-only envelope is supposed to keep (F6).
	if !reflect.DeepEqual(got, map[string]any{"count": 2, "op": "list_strings", "target": "t", "total": 3, "truncated": true}) {
		t.Fatalf("count-only = %#v", got)
	}

	// G3: a count-only answer must keep the truncation state, or "count":100
	// cannot be told apart from "exactly 100 records". count stays the listed
	// rows; total and truncated ride along.
	cut, err := decodeNumbers(map[string]any{
		"op":     "list_strings",
		"target": "t",
		"result": map[string]any{
			"total":     101,
			"shown":     1,
			"truncated": true,
			"rows":      []any{map[string]any{"address": 1}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err = aggregate(cut, opModes{countOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	if m, _ := got.(map[string]any); m["count"] != 1 || fmt.Sprint(m["total"]) != "101" || m["truncated"] != true {
		t.Fatalf("count-only dropped the cap state: %#v", got)
	}

	got, err = aggregate(answer, opModes{by: "ascii"})
	if err != nil {
		t.Fatal(err)
	}
	groups := got.(map[string]any)["result"].(map[string]any)["rows"].([]any)
	if len(groups) != 1 || groups[0].(map[string]any)["count"] != 2 {
		t.Fatalf("group = %#v", groups)
	}

	got, err = aggregate(answer, opModes{fields: "address", top: 1})
	if err != nil {
		t.Fatal(err)
	}
	rows := got.(map[string]any)["result"].(map[string]any)["rows"].([]any)
	if len(rows) != 1 || len(rows[0].(map[string]any)) != 1 {
		t.Fatalf("projection = %#v", rows)
	}

	cov := withCoverage(answer).(map[string]any)
	c, _ := cov["coverage"].(map[string]any)
	// The answer listed 2 of 3 strings, so the scan is not complete: the old
	// assertion demanded partial=false here, which was this defect.
	if c["parsed"] != 2 || c["skipped"] != 1 || cov["partial"] != true {
		t.Fatalf("coverage = %#v", cov)
	}

	pretty, _ := encodeJSON(answer, false)
	compact, _ := encodeJSON(answer, true)
	var a, b any
	if err := json.Unmarshal(pretty, &a); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(compact, &b); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a, b) || len(compact) >= len(pretty) {
		t.Fatal("compact is not the same data, smaller")
	}
}

// searchBytesAnswer is a real capped scan: the Mach-O fixture has far more
// 0x00 bytes than the 100-row cap, so hits is the true total and shown the list.
func searchBytesAnswer(t *testing.T) map[string]any {
	t.Helper()
	t.Setenv("LRECON_PATTERN", "00")
	v, err := runOp("search_bytes", "testdata/fixtures/macho")
	if err != nil {
		t.Fatal(err)
	}
	answer, err := decodeNumbers(map[string]any{"op": "search_bytes", "target": "testdata/fixtures/macho", "result": v})
	if err != nil {
		t.Fatal(err)
	}
	return answer.(map[string]any)
}

// TestCoverageAccountsCappedScan pins F1: hits=30842 with 100 listed used to
// report coverage skipped:0 partial:false, a complete-scan claim the op never
// made.
func TestCoverageAccountsCappedScan(t *testing.T) {
	answer := searchBytesAnswer(t)
	res := answer["result"].(map[string]any)
	hits, _ := jsonInt(res["hits"])
	shown, _ := jsonInt(res["shown"])
	if hits <= shown {
		t.Fatalf("fixture did not trip the 100-row cap: hits %d shown %d", hits, shown)
	}
	cov := withCoverage(answer).(map[string]any)
	c, _ := cov["coverage"].(map[string]any)
	if c["parsed"] != shown || c["skipped"] != hits-shown || c["unknown"] != 0 || cov["partial"] != true {
		t.Fatalf("coverage = %#v partial %v, want parsed %d skipped %d partial true", c, cov["partial"], shown, hits-shown)
	}
}

// TestCountOnlyKeepsCapState pins F6: an answer that names its true total in an
// op-native key must carry that cap state through --count-only and through the
// answer-size cap. The real Mach-O lists far more strings than the 100-row cap.
func TestCountOnlyKeepsCapState(t *testing.T) {
	v, err := runOp("list_strings", "testdata/fixtures/macho")
	if err != nil {
		t.Fatal(err)
	}
	answer, _ := decodeNumbers(map[string]any{"op": "list_strings", "target": "testdata/fixtures/macho", "result": v})
	res := answer.(map[string]any)["result"].(map[string]any)
	total, _ := jsonInt(res["total"])
	shown, _ := jsonInt(res["shown"])
	if total <= shown {
		t.Fatalf("fixture did not trip the 100-string cap: total %d shown %d", total, shown)
	}
	got, err := aggregate(answer, opModes{countOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	m := got.(map[string]any)
	if m["count"] != shown || m["total"] != total || m["truncated"] != true {
		t.Fatalf("count-only = %#v, want count %d total %d truncated true", m, shown, total)
	}
	t.Setenv("LRECON_ANSWER_CAP_BYTES", "64")
	spilled := capAnswer(m)
	if dst, _ := spilled["written_to"].(string); dst != "" {
		defer os.Remove(dst)
	}
	if spilled["total"] != total || spilled["truncated"] != true {
		t.Fatalf("spilled count-only = %#v, want total %d truncated true", spilled, total)
	}
}

// TestCapStateReadsOpTotals pins the shared F6 helper on the search_bytes shape:
// hits is the total, shown the capped list, so dropped keys still mean capped.
func TestCapStateReadsOpTotals(t *testing.T) {
	if total, known, truncated := capState(map[string]any{"hits": 30842, "shown": 100}, 100); !known || total != 30842 || !truncated {
		t.Fatalf("capState = %d %v %v, want 30842 true true", total, known, truncated)
	}
	if _, known, _ := capState(map[string]any{"rows": []any{1, 2}}, 2); known {
		t.Fatal("capState invented a total for an answer that named none")
	}
}

// TestByCoveragePrintedRecords pins the --by + --coverage defect: a grouped
// answer used to report parsed=<group count> and leak the internal
// _printed_records key into the JSON envelope. The real record count must win,
// and the marker must never reach the caller.
func TestByCoveragePrintedRecords(t *testing.T) {
	v, err := runOp("list_strings", "testdata/fixtures/macho")
	if err != nil {
		t.Fatal(err)
	}
	answer, err := decodeNumbers(map[string]any{"op": "list_strings", "target": "testdata/fixtures/macho", "result": v})
	if err != nil {
		t.Fatal(err)
	}
	// Sanity: the fixture's record count is the number the grouped answer must
	// report, independent of how many groups --by collapses it into.
	shown, _ := jsonInt(answer.(map[string]any)["result"].(map[string]any)["shown"])
	if shown != 100 {
		t.Fatalf("fixture changed: list_strings shown %d, want 100", shown)
	}

	got, err := aggregate(answer, opModes{by: "ascii", coverage: true})
	if err != nil {
		t.Fatal(err)
	}
	env := withCoverage(got).(map[string]any)
	b, err := encodeJSON(env, false)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	if _, leaked := doc[printedMarker]; leaked {
		t.Fatalf("%s leaked into the JSON envelope: %v", printedMarker, doc)
	}
	cov, _ := doc["coverage"].(map[string]any)
	parsed, _ := jsonInt(cov["parsed"])
	if parsed != shown {
		t.Fatalf("coverage.parsed = %d, want %d records (not the group count)", parsed, shown)
	}
}
