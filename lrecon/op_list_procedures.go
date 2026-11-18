package main

// final.md 69: list_procedures.
func init() {
	registerOp(op{
		name:  "list_procedures",
		route: "G",
		desc:  "function count, external count and a bounded name/entry/size sample (ghidra headless)",
		needs: true,
		run: func(path string) (any, error) {
			return ghidraOp(path, "list_procedures")
		},
	})
}
