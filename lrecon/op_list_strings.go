package main

import "unicode/utf8"

// listStringsValueMax caps one reported string. The scanner may find a 10 KB
// blob as one "string"; the op answer is a sample, not a dump, and the full
// length stays in `len` so the cap is visible rather than silent (final.md 405).
const listStringsValueMax = 512

// listStringsValueNotice is where a shortened value also flips `truncated`. A
// Go binary carries a few KB of table-like printable bytes; cutting those at
// 512 is routine and `strings_truncated` already says so. A value past 4 KiB is
// a glued blob, the case final.md 405 measured, and the answer says out loud
// that it is not the whole value.
const listStringsValueNotice = 4 << 10

// final.md 71: list_strings.
func init() {
	registerOp(op{
		name:  "list_strings",
		route: "L",
		needs: true,
		desc:  "printable ASCII and UTF-16LE strings in the data sections, with address and file offset",
		run: func(path string) (any, error) {
			return listStringsAnswer(path, nativeRowsCap, nativeScanCap)
		},
	})
}

// listStringsAnswer builds the answer for a given row cap and scan budget, so a
// test can drive both caps without a 64 MB fixture. `truncated` means the answer
// is not the whole list: it is true when the row cap hid rows and when a row's
// value was cut at listStringsValueMax. `strings_truncated` names the value cut
// alone, so a reader can tell a short list from a long string.
func listStringsAnswer(path string, keep int, scanCap uint64) (any, error) {
	hits, total, scanned, err := nativeStringsScan(path, 4, keep, scanCap)
	if err != nil {
		return nil, err
	}
	valuesCut, blobCut := capValues(hits)
	return map[string]any{
		// total is the same count as strings under the generic key a shaper
		// (--count-only) can carry: strings stays the op-native name.
		"strings":           total,
		"total":             total,
		"shown":             len(hits),
		"truncated":         total > len(hits) || blobCut,
		"strings_truncated": valuesCut,
		"scanned":           scanned,
		"scanned_whole":     scanned < scanCap,
		"rows":              hits,
	}, nil
}

// capValues cuts every over-long row in place. It reports whether any row was
// cut, and whether one was long enough to flip `truncated` too. `len` keeps the
// original length so a caller can tell 512 of 10001 from a genuinely 512-byte
// string.
func capValues(hits []stringHit) (cut, blobCut bool) {
	for i := range hits {
		n := len(hits[i].Value)
		if n <= listStringsValueMax {
			continue
		}
		hits[i].Value = capValue(hits[i].Value, listStringsValueMax)
		cut = true
		if n > listStringsValueNotice {
			blobCut = true
		}
	}
	return cut, blobCut
}

// capValue cuts on a rune boundary and marks the cut, so the answer stays valid
// UTF-8 even for a decoded UTF-16LE string.
func capValue(s string, max int) string {
	if len(s) <= max {
		return s
	}
	for max > 0 && !utf8.RuneStart(s[max]) {
		max--
	}
	return s[:max] + "…"
}
