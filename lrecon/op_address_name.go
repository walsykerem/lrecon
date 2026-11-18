package main

// final.md 45: address_name.
func init() {
	registerOp(op{
		name:  "address_name",
		route: "G",
		desc:  "name the symbol, function and memory block at LRECON_AT (ghidra headless)",
		needs: true,
		run: func(path string) (any, error) {
			at, err := nativeHexArg()
			if err != nil {
				return nil, err
			}
			return ghidraOp(path, "address_name", at)
		},
	})
}
