package main

// final.md 63: inspect_native_data_type.
func init() {
	registerOp(op{
		name:  "inspect_native_data_type",
		route: "G",
		desc:  "look up the data type named by LRECON_NAME in the program's type manager (ghidra headless)",
		needs: true,
		run: func(path string) (any, error) {
			name, err := nativeEnvHint("LRECON_NAME", "a data type name, e.g. _EXCEPTION_RECORD")
			if err != nil {
				return nil, err
			}
			return ghidraOp(path, "inspect_native_data_type", name)
		},
	})
}
