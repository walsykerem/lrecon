package main

// final.md 50: compare_functions.
func init() {
	registerOp(op{
		name:  "compare_functions",
		route: "G",
		desc:  "decompile LRECON_FROM and LRECON_TO and score their shared pseudocode lines (ghidra headless)",
		needs: true,
		run: func(path string) (any, error) {
			from, to, err := nativePair()
			if err != nil {
				return nil, err
			}
			return ghidraOp(path, "compare_functions", from, to)
		},
	})
}
