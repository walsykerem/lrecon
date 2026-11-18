package main

// final.md: read_function_instructions.
func init() {
	registerOp(op{
		name:  "read_function_instructions",
		route: "G",
		desc:  "run the read_function_instructions item for the function named by LRECON_NAME or LRECON_AT (ghidra headless)",
		needs: true,
		run: func(path string) (any, error) {
			if nativeEnv("LRECON_AT") != "" || nativeEnv("LRECON_NAME") != "" {
				if s := ghidraGate(path); s != nil {
					return s, nil
				}
			}
			ref, err := nativeRef()
			if err != nil {
				return nil, err
			}
			return ghidraOp(path, "read_function_instructions", ref)
		},
	})
}
