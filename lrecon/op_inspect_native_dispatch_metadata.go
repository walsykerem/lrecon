package main

// final.md 64: inspect_native_dispatch_metadata.
func init() {
	registerOp(op{
		name:  "inspect_native_dispatch_metadata",
		route: "G",
		desc:  "Objective-C and libdispatch bridge symbols with their call sites (ghidra headless)",
		needs: true,
		run: func(path string) (any, error) {
			return ghidraOp(path, "inspect_native_dispatch_metadata")
		},
	})
}
