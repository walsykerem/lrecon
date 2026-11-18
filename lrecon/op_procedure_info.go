package main

// final.md: procedure_info.
func init() {
	registerOp(op{
		name:  "procedure_info",
		route: "G",
		desc:  "run the procedure_info item for the function named by LRECON_NAME or LRECON_AT (ghidra headless)",
		needs: true,
		run: func(path string) (any, error) {
			ref, err := nativeRef()
			if err != nil {
				return nil, err
			}
			return ghidraOp(path, "procedure_info", ref)
		},
	})
}
