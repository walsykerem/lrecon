package main

import "strings"

// final.md 88: search_strings.
func init() {
	registerOp(op{
		name:  "search_strings",
		route: "L",
		desc:  "case-insensitive substring search over the ASCII and UTF-16LE strings, query from LRECON_QUERY",
		needs: true,
		run: func(path string) (any, error) {
			query, err := nativeEnvHint("LRECON_QUERY", "a substring to look for in the binary's strings")
			if err != nil {
				return nil, err
			}
			abs, err := absTarget(path)
			if err != nil {
				return nil, err
			}
			return searchStringsAnswer(abs, query, 50000, 100, nativeScanCap)
		},
	})
}

// searchStringsAnswer is the op body with its three caps named: `keep` strings
// retained for reporting, `matchCap` matches returned, and the scan budget.
// `truncated` is matchCap, not the scan: matched counts every hit in the
// scanned prefix, so matched > len(matches) means the answer is a prefix.
// `strings_truncated` is the inner keep cut (total > retained): it says the
// string list is a prefix, but matched is still counted over all scanned
// strings. A test sets all three small and asserts each flag separately.
//
// `shown` counts the corpus strings the search accounted for (the ones that
// matched), not the rows it printed: the coverage envelope reads total-shown
// as skipped, so this makes skipped the corpus strings that did not match.
// It used to carry the printed row count, and total minus that count called
// the matched-but-unprinted hits skipped too: measured on the elf fixture,
// skipped read 5584 of 5684 strings while 4519 strings matched. `listed` is the
// printed row count, so the number moved here is not lost.
func searchStringsAnswer(path, query string, keep, matchCap int, scanCap uint64) (any, error) {
	all, matches, matched, total, scanned, err := nativeStringsSearch(path, 4, keep, matchCap, scanCap, strings.ToLower(query))
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"query":             query,
		"strings":           total,
		"strings_scanned":   len(all),
		"strings_truncated": total > len(all),
		"matched":           matched,
		"shown":             matched,
		"listed":            len(matches),
		"truncated":         matched > len(matches),
		"scanned":           scanned,
		"scanned_whole":     scanned < scanCap,
		"matches":           matches,
	}, nil
}
