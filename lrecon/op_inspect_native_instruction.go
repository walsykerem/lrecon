package main

// final.md 65: inspect_native_instruction.
func init() {
	registerOp(op{
		name:  "inspect_native_instruction",
		route: "G",
		desc:  "the instruction at LRECON_AT with its p-code, length and flow type (ghidra headless)",
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
			return ghidraOp(path, "inspect_native_instruction", at)
		},
	})
}
