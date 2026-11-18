package main

// final.md 61: inspect_address_context.
func init() {
	registerOp(op{
		name:  "inspect_address_context",
		route: "G",
		desc:  "block, function, symbol and instruction at LRECON_AT (ghidra headless)",
		needs: true,
		run: func(path string) (any, error) {
			at, err := nativeHexArg()
			if err != nil {
				return nil, err
			}
			return ghidraOp(path, "inspect_address_context", at)
		},
	})
}
