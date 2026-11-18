package main

// final.md 58: get_call_graph.
func init() {
	registerOp(op{
		name:  "get_call_graph",
		route: "G",
		desc:  "function and call-edge counts with a bounded edge sample (ghidra headless)",
		needs: true,
		run: func(path string) (any, error) {
			return ghidraOp(path, "get_call_graph")
		},
	})
}
