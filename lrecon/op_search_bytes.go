package main

// final.md 86: search_bytes.
func init() {
	registerOp(op{
		name:  "search_bytes",
		route: "L",
		desc:  "find a byte pattern from LRECON_PATTERN such as \"48 8b ?? c3\" across the file-backed sections",
		needs: true,
		run: func(path string) (any, error) {
			raw, err := nativeEnvHint("LRECON_PATTERN", "a byte pattern such as 48 8b ?? c3")
			if err != nil {
				return nil, err
			}
			pat, mask, err := parseBytePattern(raw)
			if err != nil {
				return nil, err
			}
			abs, err := absTarget(path)
			if err != nil {
				return nil, err
			}
			hits, total, scanned, err := searchPattern(abs, pat, mask, 100)
			if err != nil {
				return nil, err
			}
			// hits counts every match in the scanned prefix; scanned_whole says
			// whether that prefix is the whole file-backed data (see list_strings).
			return map[string]any{
				"pattern":       raw,
				"normalized":    nativePatternString(pat, mask),
				"length":        len(pat),
				"hits":          total,
				"shown":         len(hits),
				"scanned":       scanned,
				"scanned_whole": scanned < nativeScanCap,
				"matches":       hits,
			}, nil
		},
	})
}
