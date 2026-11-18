package main

import "fmt"

// final.md 87: search_procedures.
func init() {
	registerOp(op{
		name:  "search_procedures",
		route: "G",
		desc:  "case-insensitive name search over functions using LRECON_PATTERN (ghidra headless)",
		needs: true,
		run: func(path string) (any, error) {
			pattern, err := nativeEnvHint("LRECON_PATTERN", "a substring of a function name")
			if err != nil {
				// The refusal stays needs_arg (the argument is missing), but a
				// broken engine path rides along so the caller is not sent
				// hunting for the pattern on a machine that has no Ghidra.
				if s := ghidraGate(path); s != nil {
					return nil, fmt.Errorf("%v (Ghidra: %s)", err, s.Reason)
				}
				return nil, err
			}
			if s := ghidraGate(path); s != nil {
				return s, nil
			}
			return ghidraOp(path, "search_procedures", pattern)
		},
	})
}
