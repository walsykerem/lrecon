package main

// final.md 85: resolve_native_call_targets.
func init() {
	registerOp(op{
		name:  "resolve_native_call_targets",
		route: "G",
		desc:  "the flows and references leaving the instruction at LRECON_AT (ghidra headless)",
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
			return ghidraOp(path, "resolve_native_call_targets", at)
		},
	})
}
