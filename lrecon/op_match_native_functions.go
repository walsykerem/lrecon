package main

// final.md 72: match_native_functions.
func init() {
	registerOp(op{
		name:  "match_native_functions",
		route: "G",
		desc:  "group functions with byte-identical bodies (exact match; FunctionID database not used) (ghidra headless)",
		needs: true,
		run: func(path string) (any, error) {
			return ghidraOp(path, "match_native_functions")
		},
	})
}
