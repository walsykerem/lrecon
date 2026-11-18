package main

// final.md: procedure_address.
func init() {
	registerOp(op{
		name:  "procedure_address",
		route: "G",
		desc:  "run the procedure_address item for the function named by LRECON_NAME or LRECON_AT (ghidra headless)",
		needs: true,
		run: func(path string) (any, error) {
			ref, err := nativeRef()
			if err != nil {
				return nil, err
			}
			return ghidraOp(path, "procedure_address", ref)
		},
	})
}
