package main

// final.md: procedure_callers.
func init() {
	registerOp(op{
		name:  "procedure_callers",
		route: "G",
		desc:  "run the procedure_callers item for the function named by LRECON_NAME or LRECON_AT (ghidra headless)",
		needs: true,
		run: func(path string) (any, error) {
			ref, err := nativeRef()
			if err != nil {
				return nil, err
			}
			return ghidraOp(path, "procedure_callers", ref)
		},
	})
}
