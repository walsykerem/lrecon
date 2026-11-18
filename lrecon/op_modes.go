package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"sort"
	"strings"
)

// opModes are the opt-in answer shapers: compact JSON, aggregation over a
// record array, and the coverage envelope. Zero value means "shipped output".
type opModes struct {
	compact   bool
	countOnly bool
	top       int
	by        string
	fields    string
	coverage  bool
}

func (m opModes) aggregate() bool {
	return m.countOnly || m.by != "" || m.fields != "" || m.top > 0
}

// encodeJSON is the one JSON writer: --compact drops the indentation, which is
// the whole saving (whitespace, not data).
func encodeJSON(v any, compact bool) ([]byte, error) {
	if compact {
		return json.Marshal(v)
	}
	return json.MarshalIndent(v, "", "  ")
}

// decodeNumbers re-reads a value as plain JSON so aggregation can walk records
// without knowing their Go types. UseNumber keeps wide addresses exact.
func decodeNumbers(v any) (any, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var out any
	if err := dec.Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}

// covUnit names the records an op counts: the table it prints and the keys
// that carry the count of that same table over the whole scan. Only the op
// knows which of its counts matches its own table - list_strings publishes the
// corpus size beside the rows it listed, and the corpus is not a record count.
type covUnit struct {
	table  string
	totals []string
}

// covUnits maps an op to the records it counts.
var covUnits = map[string]covUnit{
	"list_strings":       {table: "rows", totals: []string{"total", "strings"}},
	"search_strings":     {table: "matches", totals: []string{"matched"}},
	"search_bytes":       {table: "matches", totals: []string{"hits"}},
	"list_names":         {table: "sample", totals: []string{"names"}},
	"list_procedures":    {table: "sample", totals: []string{"functions"}},
	"get_call_graph":     {table: "sample", totals: []string{"functions"}},
	"analyze_web_bundle": {table: "edges", totals: []string{"count"}},
}

// tableKeys are the answer keys that hold a record table when the op names none.
var tableKeys = []string{"rows", "imports", "dlls", "names", "functions", "instructions", "refs"}

// countKeys are the answer keys that count records. "strings" is not one of
// them: it counts the corpus an op searched, not the records it listed.
var countKeys = []string{"count", "hits", "matched", "imports", "names", "functions", "blocks", "devices", "features", "findings", "groups", "segments", "files", "entries", "items", "records", "scrubbed", "duplicate_groups", "modules", "addresses", "symbols"}

// printedMarker carries the number of records a grouped answer printed from
// the shaper to the coverage envelope. It is internal: withCoverage reads it
// and drops it again.
const printedMarker = "_printed_records"

// tableOf finds the record table of an answer: the one the op names, else the
// canonical key, else the biggest array the answer holds. One table means one
// record kind: an answer that holds sections and imports has two kinds, and
// counting them together reports records that do not exist.
func tableOf(m map[string]any, op string) (string, []any, bool) {
	if u, ok := covUnits[op]; ok {
		if rows, ok := m[u.table].([]any); ok {
			return u.table, rows, true
		}
	}
	for _, key := range tableKeys {
		if rows, ok := m[key].([]any); ok {
			return key, rows, true
		}
	}
	return longestArray(m)
}

// longestArray finds the biggest array a map holds. An answer that names no
// table still holds one kind of record, and the biggest array is it. Ties go
// to the first key in order, so the answer does not change from run to run.
func longestArray(m map[string]any) (string, []any, bool) {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	name := ""
	var rows []any
	for _, key := range keys {
		l, ok := m[key].([]any)
		if !ok {
			continue
		}
		if name == "" || len(l) > len(rows) {
			name, rows = key, l
		}
	}
	return name, rows, name != ""
}

// unitTotal finds the count that covers the same records as the table the
// answer prints. Ops publish several counts - a corpus size, a match count, a
// group count - and only the op knows which one counts its own table, so the
// pair comes from the table when the op is listed and from the answer's own
// "total" otherwise. An answer that names no count leaves the total unknown:
// skipped stays null and the answer says partial, rather than claim a scan it
// cannot account for.
func unitTotal(res map[string]any, op string, printed int) (int, bool) {
	if u, ok := covUnits[op]; ok {
		for _, key := range u.totals {
			if n, ok := jsonInt(res[key]); ok {
				return n, true
			}
		}
	}
	if n, ok := jsonInt(res["total"]); ok {
		return n, true
	}
	// The answer counts its own table: a count that equals the number of rows
	// printed is that table's count, not another kind's.
	for _, key := range countKeys {
		if n, ok := jsonInt(res[key]); ok && n == printed {
			return n, true
		}
	}
	return 0, false
}

// capFlag reads the op's own "this answer was cut" flags.
func capFlag(res map[string]any) bool {
	for _, key := range []string{"truncated", "strings_truncated"} {
		if b, ok := res[key].(bool); ok && b {
			return true
		}
	}
	// A partial scan is a cut answer even when the row cap never fired.
	if b, ok := res["scanned_whole"].(bool); ok && !b {
		return true
	}
	return false
}

// unitState reads the cap state of the table the answer prints: how many
// records the op found over the whole scan, how many it printed, and whether
// it cut anything.
func unitState(res map[string]any, op string, printed int) (total int, known, truncated bool) {
	total, known = unitTotal(res, op, printed)
	truncated = capFlag(res) || (known && total > printed)
	return total, known, truncated
}

// unitName names the table an op counts.
func unitName(op string) string {
	if u, ok := covUnits[op]; ok {
		return u.table
	}
	return ""
}

// recordArray finds the array an answer carries and a way to put a shorter one
// back in its place: top-level for --list-ops, under "result" for --op. It
// also names the table, so the coverage envelope counts the records the
// shaper worked on.
func recordArray(v any) ([]any, func([]any) any, string) {
	if rows, ok := v.([]any); ok {
		return rows, func(r []any) any { return r }, ""
	}
	outer, ok := v.(map[string]any)
	if !ok {
		return nil, nil, ""
	}
	op := opName(v)
	inner, _ := outer["result"].(map[string]any)
	if name, rows, ok := tableOf(inner, op); ok {
		return rows, func(r []any) any {
			out := map[string]any{}
			maps.Copy(out, inner)
			out[name] = r
			wrapped := map[string]any{}
			maps.Copy(wrapped, outer)
			wrapped["result"] = out
			return wrapped
		}, name
	}
	if name, rows, ok := tableOf(outer, op); ok {
		return rows, func(r []any) any {
			out := map[string]any{}
			maps.Copy(out, outer)
			out[name] = r
			return out
		}, name
	}
	return nil, nil, ""
}

// opName reads the op an answer came from.
func opName(v any) string {
	if outer, ok := v.(map[string]any); ok {
		op, _ := outer["op"].(string)
		return op
	}
	return ""
}

// aggregate applies at most one shaper, in precedence order: count-only, group
// (--by [--top N]), projection (--fields), then a plain --top N prefix.
func aggregate(v any, m opModes) (any, error) {
	rows, rebuild, _ := recordArray(v)
	if rows == nil {
		return nil, errors.New("this answer carries no record array; --count-only, --top, --by and --fields need rows")
	}
	op := opName(v)
	switch {
	case m.countOnly:
		out := map[string]any{"count": len(rows)}
		if outer, ok := v.(map[string]any); ok {
			for _, k := range []string{"op", "target"} {
				if val, ok := outer[k]; ok {
					out[k] = val
				}
			}
			// A capped record array must not read as the whole table: carry the
			// truncation state and total, or 100 rows and 10000 look alike. The
			// total is the one that counts this table, not another kind.
			fields, _ := outer["result"].(map[string]any)
			if fields == nil {
				fields = outer
			}
			total, known, truncated := unitState(fields, op, len(rows))
			if known {
				out["total"] = total
			}
			if truncated {
				out["truncated"] = true
			}
		}
		return out, nil
	case m.by != "":
		grouped, records, err := groupRows(rows, m.by, m.top)
		if err != nil {
			return nil, err
		}
		out, ok := rebuild(grouped).(map[string]any)
		if !ok {
			return rebuild(grouped), nil
		}
		if m.coverage {
			// The rows are groups now: the printed records are the group
			// counts. withCoverage reads this and drops it again.
			out[printedMarker] = records
		}
		return out, nil
	case m.fields != "":
		projected, err := projectRows(rows, m.fields)
		if err != nil {
			return nil, err
		}
		if m.top > 0 && m.top < len(projected) {
			projected = projected[:m.top]
		}
		return rebuild(projected), nil
	case m.top > 0 && m.top < len(rows):
		return rebuild(rows[:m.top]), nil
	}
	return v, nil
}

// groupRows counts each distinct value of field, biggest group first. --top
// keeps the first N groups and nothing else, so the answer is a table, not a
// sample of rows.
//
// A row without the field lands in a group of its own: dropping it would make
// the group counts smaller than the table they came from. A field no row
// carries is refused, because an empty table beside the answer's own total is
// a contradiction, not an answer.
func groupRows(rows []any, field string, top int) ([]any, int, error) {
	counts := map[string]int{}
	values := map[string]any{}
	keys := make([]string, 0, len(rows))
	found := false
	for _, row := range rows {
		m, ok := row.(map[string]any)
		if !ok {
			return nil, 0, fmt.Errorf("--by %s: this answer has rows that are not objects", field)
		}
		val, has := m[field]
		found = found || has
		key := fmt.Sprint(val)
		if _, seen := counts[key]; !seen {
			keys = append(keys, key)
		}
		counts[key]++
		values[key] = val
	}
	if !found {
		return nil, 0, fmt.Errorf("--by %s: this answer has no %s field (it has %s)", field, field, strings.Join(fieldNames(rows), ", "))
	}
	sort.Slice(keys, func(i, j int) bool {
		if counts[keys[i]] != counts[keys[j]] {
			return counts[keys[i]] > counts[keys[j]]
		}
		return keys[i] < keys[j]
	})
	if top > 0 && top < len(keys) {
		keys = keys[:top]
	}
	out := make([]any, 0, len(keys))
	for _, k := range keys {
		out = append(out, map[string]any{"value": values[k], "count": counts[k]})
	}
	return out, len(rows), nil
}

// projectRows keeps only the named fields, in the caller's order: a row that
// carries one number does not need the other twelve. A field no row carries is
// refused, and so is a row that would come out empty: an empty object says
// nothing and hides the mistake.
func projectRows(rows []any, fields string) ([]any, error) {
	names := splitComma(fields)
	out := make([]any, 0, len(rows))
	have := map[string]bool{}
	empty := 0
	for _, row := range rows {
		m, ok := row.(map[string]any)
		if !ok {
			out = append(out, row)
			continue
		}
		p := map[string]any{}
		for _, name := range names {
			if val, ok := m[name]; ok {
				p[name] = val
				have[name] = true
			}
		}
		if len(p) == 0 {
			empty++
		}
		out = append(out, p)
	}
	if len(have) == 0 {
		return nil, fmt.Errorf("--fields %s: this answer has no %s field (it has %s)", fields, fields, strings.Join(fieldNames(rows), ", "))
	}
	if empty > 0 {
		return nil, fmt.Errorf("--fields %s: %d of %d rows carry none of these fields", fields, empty, len(rows))
	}
	return out, nil
}

// fieldNames lists the fields the rows carry, so a refusal can name what the
// caller could have asked for.
func fieldNames(rows []any) []string {
	set := map[string]bool{}
	for _, row := range rows {
		m, ok := row.(map[string]any)
		if !ok {
			continue
		}
		for k := range m {
			set[k] = true
		}
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	if len(out) > 12 {
		out = out[:12]
	}
	return out
}

func splitComma(s string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == ',' {
			if f := trimSpace(s[start:i]); f != "" {
				out = append(out, f)
			}
			start = i + 1
		}
	}
	return out
}

func trimSpace(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\t') {
		s = s[:len(s)-1]
	}
	return s
}

// withCoverage adds the envelope the digest already publishes: parsed, skipped,
// unknown and partial. It is opt-in because it costs ~35 tokens on every
// answer, which is more than a count-only answer.
func withCoverage(v any) any {
	// Coverage is counted on the JSON form: an op builds typed slices, and the
	// record walker only sees []any.
	d, err := decodeNumbers(v)
	if err != nil {
		return v
	}
	outer, ok := d.(map[string]any)
	if !ok {
		return v
	}
	res := outer["result"]
	// A skipped count is only a fact when the op reported the total it found:
	// 0 on an op that never counted units would claim a complete scan.
	cov := map[string]any{"parsed": recordsIn(res), "skipped": nil, "unknown": nil}
	// A grouped answer carries the real record count on a marker so coverage
	// counts records, not the groups --by replaced them with. Consume it before
	// the copy so the internal key never reaches the JSON caller.
	if n, ok := jsonInt(outer[printedMarker]); ok {
		cov["parsed"] = n
		delete(outer, printedMarker)
	}
	partial := partialOf(res)
	if m, ok := res.(map[string]any); ok {
		shown := recordsIn(m)
		if n, ok := jsonInt(m["shown"]); ok {
			shown = n
		}
		total, known, truncated := capState(m, shown)
		if known {
			cov["skipped"] = max(total-shown, 0)
			cov["unknown"] = 0
		}
		if n := lenList(m["skipped"]); n > 0 {
			cov["skipped"] = n
		}
		if n := lenList(m["unknown"]); n > 0 {
			cov["unknown"] = n
		}
		partial = partial || truncated
	}
	if cov["skipped"] == nil || cov["unknown"] == nil {
		// The op did not account for its full input: say so instead of publishing
		// skipped:0, which reads as "nothing was skipped".
		partial = true
	}
	out := map[string]any{}
	maps.Copy(out, outer)
	out["coverage"] = cov
	out["partial"] = partial
	return out
}

func partialOf(res any) bool {
	m, ok := res.(map[string]any)
	if !ok {
		return false
	}
	if b, ok := m["truncated"].(bool); ok {
		return b
	}
	_, ok = m["partial"]
	return ok
}

// capState reads an op's own cap report: how many units it found, how many it
// listed, and whether it says it cut any. Ops name the total differently
// (total, hits, strings, imports), so every reader goes through here instead of
// knowing one op's keys.
func capState(m map[string]any, shown int) (total int, known, truncated bool) {
	for _, key := range []string{"total", "hits", "strings", "imports"} {
		if n, ok := jsonInt(m[key]); ok {
			total, known = n, true
			break
		}
	}
	if b, ok := m["truncated"].(bool); ok && b {
		truncated = true
	}
	// A partial scan is a cut answer even when the row cap never fired.
	if b, ok := m["scanned_whole"].(bool); ok && !b {
		truncated = true
	}
	if !known {
		return shown, false, truncated
	}
	return total, true, truncated || total > shown
}

func jsonInt(v any) (int, bool) {
	switch x := v.(type) {
	case json.Number:
		n, err := x.Int64()
		return int(n), err == nil
	case float64:
		return int(x), true
	case int:
		return x, true
	}
	return 0, false
}

func lenList(v any) int {
	if l, ok := v.([]any); ok {
		return len(l)
	}
	return 0
}

// modeConflict names the combinations the modes cannot answer together.
func modeConflict(m opModes) error {
	if m.countOnly && (m.by != "" || m.fields != "") {
		return errors.New("--count-only cannot be combined with --by or --fields: it drops the rows they read")
	}
	if m.by != "" && m.fields != "" {
		return errors.New("--by and --fields cannot be combined: grouping replaces the rows projection would cut")
	}
	if m.top < 0 {
		return errors.New("--top needs a positive record count")
	}
	return nil
}
