package main

// final.md: procedure_pseudo_code.
func init() {
	registerOp(op{
		name:  "procedure_pseudo_code",
		route: "G",
		desc:  "run the procedure_pseudo_code item for the function named by LRECON_NAME or LRECON_AT (ghidra headless)",
		needs: true,
		run: func(path string) (any, error) {
			ref, err := nativeRef()
			if err != nil {
				return nil, err
			}
			return ghidraOp(path, "procedure_pseudo_code", ref)
		},
	})
}
