package main

// final.md 57: find_xrefs_to_name.
func init() {
	registerOp(op{
		name:  "find_xrefs_to_name",
		route: "G",
		desc:  "every reference to the symbol named by LRECON_NAME, with the function that makes it (ghidra headless)",
		needs: true,
		run: func(path string) (any, error) {
			name, err := nativeEnvHint("LRECON_NAME", "a symbol name")
			if err != nil {
				return nil, err
			}
			return ghidraOp(path, "find_xrefs_to_name", name)
		},
	})
}
