package main

// final.md 70: list_segments.
func init() {
	registerOp(op{
		name:  "list_segments",
		route: "G",
		desc:  "every memory block with start, end, permissions and total bytes (ghidra headless)",
		needs: true,
		run: func(path string) (any, error) {
			return ghidraOp(path, "list_segments")
		},
	})
}
