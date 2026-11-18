package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

func init() {
	registerOp(op{
		name:  "compare_process_captures",
		route: "L",
		desc:  "join two capture JSONs by symbol and diff their value arrays (target = \"first.json,second.json\")",
		needs: true,
		run:   compareProcessCaptures,
	})
}

type rtSymbolChange struct {
	Symbol string   `json:"symbol"`
	First  []string `json:"first"`
	Second []string `json:"second"`
}

type rtCaptureDiff struct {
	OnlyInFirst  []string         `json:"only_in_first"`
	OnlyInSecond []string         `json:"only_in_second"`
	Changed      []rtSymbolChange `json:"changed"`
	Unchanged    int              `json:"unchanged"`
}

// compareProcessCaptures is §y y17: symbols joined by name, values compared
// element by element, and both sides kept in the report so a changed row is
// readable without reopening either capture. Counts stay in the arrays: a
// multiset of symbols alone cannot produce a "changed" set.
func compareProcessCaptures(target string) (any, error) {
	parts := strings.Split(target, ",")
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
		return nil, fmt.Errorf("target must be two capture files: \"first.json,second.json\"")
	}
	first, err := rtReadCapture(strings.TrimSpace(parts[0]))
	if err != nil {
		return nil, err
	}
	second, err := rtReadCapture(strings.TrimSpace(parts[1]))
	if err != nil {
		return nil, err
	}
	res := rtCaptureDiff{OnlyInFirst: []string{}, OnlyInSecond: []string{}, Changed: []rtSymbolChange{}}
	for sym, a := range first {
		b, ok := second[sym]
		if !ok {
			res.OnlyInFirst = append(res.OnlyInFirst, sym)
			continue
		}
		if rtSameValues(a, b) {
			res.Unchanged++
			continue
		}
		res.Changed = append(res.Changed, rtSymbolChange{Symbol: sym, First: a, Second: b})
	}
	for sym := range second {
		if _, ok := first[sym]; !ok {
			res.OnlyInSecond = append(res.OnlyInSecond, sym)
		}
	}
	sort.Strings(res.OnlyInFirst)
	sort.Strings(res.OnlyInSecond)
	sort.Slice(res.Changed, func(i, j int) bool { return res.Changed[i].Symbol < res.Changed[j].Symbol })
	return res, nil
}

func rtReadCapture(path string) (map[string][]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var raw map[string][]json.Number
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, fmt.Errorf("%s is not a {symbol: [values]} capture: %w", path, err)
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("%s has no symbols", path)
	}
	out := make(map[string][]string, len(raw))
	for sym, vals := range raw {
		strs := make([]string, len(vals))
		for i, v := range vals {
			strs[i] = v.String()
		}
		out[sym] = strs
	}
	return out, nil
}

func rtSameValues(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
