package main

// final.md 84: resolve_containing_procedure.
func init() {
	registerOp(op{
		name:  "resolve_containing_procedure",
		route: "G",
		desc:  "the function containing LRECON_AT with the offset into it (ghidra headless)",
		needs: true,
		run: func(path string) (any, error) {
			if nativeEnv("LRECON_AT") != "" {
				if s := ghidraGate(path); s != nil {
					return s, nil
				}
			}
			at, err := nativeHexArg()
			if err != nil {
				return nil, err
			}
			return ghidraOp(path, "resolve_containing_procedure", at)
		},
	})
}
