package main

// final.md 89: trace_call_path.
func init() {
	registerOp(op{
		name:  "trace_call_path",
		route: "G",
		desc:  "bounded breadth-first trace from LRECON_FROM to LRECON_TO reporting depth and path (ghidra headless)",
		needs: true,
		run: func(path string) (any, error) {
			if s := ghidraGate(path); s != nil {
				return s, nil
			}
			from, to, err := nativePair()
			if err != nil {
				return nil, err
			}
			return ghidraOp(path, "trace_call_path", from, to)
		},
	})
}
