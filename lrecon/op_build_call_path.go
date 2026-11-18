package main

// final.md 49: build_call_path.
func init() {
	registerOp(op{
		name:  "build_call_path",
		route: "G",
		desc:  "breadth-first call path from LRECON_FROM to LRECON_TO with depth and visited count (ghidra headless)",
		needs: true,
		run: func(path string) (any, error) {
			if sk := ghidraGate(path); sk != nil {
				return sk, nil
			}
			from, to, err := nativePair()
			if err != nil {
				return nil, err
			}
			return ghidraOp(path, "build_call_path", from, to)
		},
	})
}
