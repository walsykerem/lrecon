package main

// final.md 47: analyze_function.
func init() {
	registerOp(op{
		name:  "analyze_function",
		route: "G",
		desc:  "decompile one function named by LRECON_NAME or LRECON_AT with its signature and line count (ghidra headless)",
		needs: true,
		run: func(path string) (any, error) {
			if sk := ghidraGate(path); sk != nil {
				return sk, nil
			}
			ref, err := nativeRef()
			if err != nil {
				return nil, err
			}
			return ghidraOp(path, "analyze_function", ref)
		},
	})
}
