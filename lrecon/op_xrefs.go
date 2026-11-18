package main

// final.md 90: xrefs.
func init() {
	registerOp(op{
		name:  "xrefs",
		route: "G",
		desc:  "references to and from LRECON_AT (or the symbol named by LRECON_NAME) (ghidra headless)",
		needs: true,
		run: func(path string) (any, error) {
			if s := ghidraGate(path); s != nil {
				return s, nil
			}
			ref, err := nativeRef()
			if err != nil {
				return nil, err
			}
			return ghidraOp(path, "xrefs", ref)
		},
	})
}
