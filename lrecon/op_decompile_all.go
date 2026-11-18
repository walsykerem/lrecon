package main

// final.md 55: decompile_all. Native images go through ghidra; a managed
// assembly (kind pe-dotnet) is metadata plus IL, which ghidra cannot import as
// machine code, so it is disassembled from the MethodDef bodies instead. The
// managed/bytecode guard for every other route-G item stays in ghidraOp.
func init() {
	registerOp(op{
		name:  "decompile_all",
		route: "G",
		desc:  "decompile every non-external function within a time budget and report the counts plus samples (ghidra headless; IL for a managed assembly)",
		needs: true,
		run: func(path string) (any, error) {
			if d, err := Probe(path); err == nil && d.Kind == "pe-dotnet" {
				return decompileManaged(path)
			}
			return ghidraOp(path, "decompile_all")
		},
	})
}
